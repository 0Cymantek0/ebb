package restore

// Rebuild-driver tests (Foundation §12.5 last paragraphs): the open
// operation's reconstruction phase through the fake-runner seam — happy
// path, action failure, timeout, missing tool, declined approval, F36
// protected-change detection (files kept), cancellation, resume
// skipping succeeded actions, and the strict reader's handling of the
// definition extension.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/platform"
)

// fakeRunner implements ActionRunner: it records call order and defers
// to an injectable behavior; the default behavior creates every
// declared output (a benign "install") and reports success.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	fn    func(def actions.Definition) (actions.Result, error)
}

func (r *fakeRunner) Run(ctx context.Context, def actions.Definition, wsRoot string, appr actions.Approver, capture actions.OutputSink) (actions.Result, error) {
	r.mu.Lock()
	r.calls = append(r.calls, def.ID)
	fn := r.fn
	r.mu.Unlock()
	if fn != nil {
		return fn(def)
	}
	for _, out := range def.Outputs {
		p := filepath.Join(wsRoot, filepath.FromSlash(out))
		if err := os.MkdirAll(p, 0o755); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
		if err := os.WriteFile(filepath.Join(p, "built.txt"), []byte("rebuilt\n"), 0o644); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
	}
	return actions.Result{ExitCode: 0}, nil
}

func (r *fakeRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// rebuildFixture builds the standard fixture with an executable
// definition on the recipe group (argv[0] must resolve on PATH: the
// pre-pass pins the tool identity even though the fake never execs).
func rebuildFixture(t *testing.T, argv ...string) *fixture {
	t.Helper()
	return buildFixture(t, fixtureSpec{recipeGroup: true, defArgv: argv})
}

// newRebuildOpener wires an opener with the rebuild seams: the fake
// runner, a REAL approvalstore document in the fixture parent, and a
// resolver that records every pending approval exactly as pinned.
func newRebuildOpener(f *fixture, runner ActionRunner, decline bool) (*Opener, *approvalstore.FileApprover) {
	f.t.Helper()
	store := approvalstore.New(filepath.Join(f.parent, "approvals.json"))
	resolver := func(ctx context.Context, pending []PendingApproval) error {
		if decline {
			return errors.New("declined in test")
		}
		for _, p := range pending {
			if _, err := store.Approve(p.Def, p.Tool, p.InputDigests, "test"); err != nil {
				return err
			}
		}
		return nil
	}
	o, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner: runner, Approver: store, Approve: resolver,
	})
	if err != nil {
		f.t.Fatalf("New: %v", err)
	}
	return o, store
}

func rebuildDest(f *fixture) string { return filepath.Join(f.parent, "restored") }

func assertPhase(t *testing.T, f *fixture, opID domain.OperationID, want string) {
	t.Helper()
	op, err := f.cat.GetOperation(opID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Phase != want {
		t.Fatalf("operation phase = %q, want %q (last error: %q)", op.Phase, want, op.LastError)
	}
}

// ---- happy path -----------------------------------------------------------

func TestRebuildHappyPathReachesDone(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{}
	o, _ := newRebuildOpener(f, runner, false)

	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	if err != nil {
		t.Fatalf("open with rebuild: %v", err)
	}
	if res.Phase != catalog.PhaseDone {
		t.Fatalf("phase = %q, want DONE", res.Phase)
	}
	if runner.callCount() != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.callCount())
	}
	// The action's output exists at the final destination.
	if b, err := os.ReadFile(filepath.Join(dest, "node_modules", "built.txt")); err != nil || string(b) != "rebuilt\n" {
		t.Fatalf("rebuild output missing: %q %v", b, err)
	}
	// Preserved files intact.
	if b, err := os.ReadFile(filepath.Join(dest, "a.txt")); err != nil || string(b) != "alpha\n" {
		t.Fatalf("protected file damaged by the rebuild: %q %v", b, err)
	}
	// Journal: op DONE, one succeeded action_run, snapshot still pinned.
	assertPhase(t, f, res.OperationID, catalog.PhaseDone)
	runs, err := f.cat.ListActionRuns(res.OperationID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("action runs = %v (%v), want 1", runs, err)
	}
	if runs[0].ActionID != "node-dependencies" || runs[0].Status != catalog.ActionRunSucceeded {
		t.Fatalf("action run row = %+v", runs[0])
	}
	snap, err := f.cat.GetSnapshot(f.snapID)
	if err != nil || !snap.Pinned {
		t.Fatalf("snapshot must stay pinned (I07): %+v %v", snap, err)
	}
	if len(res.Actions) != 1 || res.Actions[0].Status != ActionSucceeded {
		t.Fatalf("result actions = %+v", res.Actions)
	}
}

// ---- failures land at REBUILD_FAILED, files intact -------------------------

func assertRebuildFailure(t *testing.T, f *fixture, dest string, err error, wantReasonSub string) (Result, *ErrRebuildFailed) {
	t.Helper()
	var rb *ErrRebuildFailed
	if !errors.As(err, &rb) {
		t.Fatalf("err = %v, want *ErrRebuildFailed", err)
	}
	if rb.Code() != CodeRebuildFailed {
		t.Fatalf("code = %s", rb.Code())
	}
	if wantReasonSub != "" && !strings.Contains(err.Error(), wantReasonSub) {
		t.Fatalf("error %q lacks %q", err, wantReasonSub)
	}
	// Preserved files are intact and published (I08): the failure never
	// removes the recovered files.
	if b, rerr := os.ReadFile(filepath.Join(dest, "a.txt")); rerr != nil || string(b) != "alpha\n" {
		t.Fatalf("recovered files not intact after failure: %q %v", b, rerr)
	}
	res := Result{}
	return res, rb
}

func TestRebuildActionFailureLandsRebuildFailed(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 7, OutputExcerpt: "boom"}, nil
	}}
	o, _ := newRebuildOpener(f, runner, false)

	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	if err == nil {
		t.Fatal("failing action must fail the open")
	}
	assertRebuildFailure(t, f, dest, err, "exited 7")
	if res.Phase != catalog.PhaseRebuildFailed {
		t.Fatalf("result phase = %q, want REBUILD_FAILED", res.Phase)
	}
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)
	runs, rerr := f.cat.ListActionRuns(res.OperationID)
	if rerr != nil || len(runs) != 1 || runs[0].Status != catalog.ActionRunFailed || runs[0].ExitCode != 7 {
		t.Fatalf("action runs = %+v (%v)", runs, rerr)
	}
}

func TestRebuildTimeoutLandsRebuildFailed(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: -1}, &actions.ErrTimeout{ActionID: def.ID, Timeout: 30 * time.Second}
	}}
	o, _ := newRebuildOpener(f, runner, false)

	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	assertRebuildFailure(t, f, dest, err, "timeout")
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)
}

func TestRebuildMissingToolIsPreciseRequirement(t *testing.T) {
	f := rebuildFixture(t, "ebb-no-such-tool-xyz", "install")
	dest := rebuildDest(f)
	runner := &fakeRunner{}
	o, _ := newRebuildOpener(f, runner, false)

	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	assertRebuildFailure(t, f, dest, err, "not resolvable")
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)
	if runner.callCount() != 0 {
		t.Fatalf("nothing may run when the tool is missing; calls = %d", runner.callCount())
	}
	if !strings.Contains(err.Error(), "ebb-no-such-tool-xyz") {
		t.Fatalf("failure must name the missing tool: %v", err)
	}
}

func TestRebuildDeclinedApprovalNeverRuns(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{}
	o, _ := newRebuildOpener(f, runner, true) // resolver declines

	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	assertRebuildFailure(t, f, dest, err, "approval declined")
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)
	if runner.callCount() != 0 {
		t.Fatalf("declined approval must never execute; calls = %d", runner.callCount())
	}
}

func TestRebuildNonInteractiveWithoutResolverBlocks(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{}
	store := approvalstore.New(filepath.Join(f.parent, "approvals.json"))
	o, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner: runner, Approver: store, Approve: nil, // non-interactive
	})
	if err != nil {
		t.Fatal(err)
	}
	res, oerr := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	assertRebuildFailure(t, f, dest, oerr, "no approval resolver")
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)
	if runner.callCount() != 0 {
		t.Fatalf("unresolved approval must never execute; calls = %d", runner.callCount())
	}
}

func TestRebuildCancellationLandsRebuildFailed(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: -1}, context.Canceled
	}}
	o, _ := newRebuildOpener(f, runner, false)

	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	var rb *ErrRebuildFailed
	if !errors.As(err, &rb) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrRebuildFailed wrapping context.Canceled (exit 130 semantics)", err)
	}
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)
	op, _ := f.cat.GetOperation(res.OperationID)
	if !strings.Contains(op.LastError, "cancelled") {
		t.Fatalf("journal must record the cancel reason: %q", op.LastError)
	}
	runs, _ := f.cat.ListActionRuns(res.OperationID)
	if len(runs) != 1 || runs[0].Status != catalog.ActionRunCancelled {
		t.Fatalf("cancelled run must be journaled: %+v", runs)
	}
}

// ---- F36 ------------------------------------------------------------------

func TestRebuildF36ProtectedChangeDetectedFilesKept(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		// The approved action "succeeds" but tramples a protected file
		// OUTSIDE its declared outputs (F36).
		if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("trampled\n"), 0o644); err != nil {
			return actions.Result{}, err
		}
		return actions.Result{ExitCode: 0}, nil
	}}
	o, _ := newRebuildOpener(f, runner, false)

	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	var rb *ErrRebuildFailed
	if !errors.As(err, &rb) {
		t.Fatalf("err = %v, want ErrRebuildFailed", err)
	}
	var pc *ErrProtectedChanged
	if !errors.As(err, &pc) || !strings.Contains(pc.Error(), "a.txt") {
		t.Fatalf("the protected change must be reported with the entry: %v", err)
	}
	if pc.Code() != CodeProtectedChanged {
		t.Fatalf("code = %s", pc.Code())
	}
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)
	// The NEW file content is kept (possible user work, §12.5): Ebb
	// never reverts or removes it.
	if b, rerr := os.ReadFile(filepath.Join(dest, "a.txt")); rerr != nil || string(b) != "trampled\n" {
		t.Fatalf("F36 must keep the new bytes untouched: %q %v", b, rerr)
	}
	snap, _ := f.cat.GetSnapshot(f.snapID)
	if !snap.Pinned {
		t.Fatal("snapshot must stay pinned after F36 (I07)")
	}
}

// ---- resume ----------------------------------------------------------------

func TestResumeRebuildRunsOnlyUnsucceededActions(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	// Phase 1: the action succeeds (journaled, outputs materialized as
	// any successful action must) but F36 fails the rebuild because a
	// protected file changed.
	runner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		_ = os.WriteFile(filepath.Join(dest, "a.txt"), []byte("trampled\n"), 0o644)
		for _, out := range def.Outputs {
			if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(out)), 0o755); err != nil {
				return actions.Result{ExitCode: -1}, err
			}
		}
		return actions.Result{ExitCode: 0}, nil
	}}
	o, _ := newRebuildOpener(f, runner, false)
	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	var phase1 *ErrRebuildFailed
	if !errors.As(err, &phase1) {
		t.Fatalf("phase 1 err = %v, want ErrRebuildFailed", err)
	}
	assertPhase(t, f, res.OperationID, catalog.PhaseRebuildFailed)

	// The user resolves the change (restores the protected bytes).
	if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Phase 2: resume. The succeeded action must NOT re-run (the runner
	// now FAILS if called — proof by contradiction).
	strict := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 99}, nil
	}}
	o2, _ := newRebuildOpener(f, strict, false)
	rres, rerr := o2.ResumeRebuild(context.Background(), f.vault, res.OperationID)
	if rerr != nil {
		t.Fatalf("resume must complete without re-running the succeeded action: %v", rerr)
	}
	if rres.Phase != catalog.PhaseDone {
		t.Fatalf("resume phase = %q, want DONE", rres.Phase)
	}
	if strict.callCount() != 0 {
		t.Fatalf("a succeeded action was re-run: %d calls", strict.callCount())
	}
	assertPhase(t, f, res.OperationID, catalog.PhaseDone)
	runs, _ := f.cat.ListActionRuns(res.OperationID)
	if len(runs) != 1 || runs[0].Status != catalog.ActionRunSucceeded {
		t.Fatalf("action runs after resume = %+v, want the single original success", runs)
	}
	if len(rres.Actions) != 1 || !rres.Actions[0].Skipped || rres.Actions[0].Status != ActionSkipped {
		t.Fatalf("resume report must mark the skipped action: %+v", rres.Actions)
	}
}

func TestResumeRebuildFailedThenSucceedsAfterFix(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	dest := rebuildDest(f)
	runner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 7}, nil
	}}
	o, _ := newRebuildOpener(f, runner, false)
	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	var failed1 *ErrRebuildFailed
	if !errors.As(err, &failed1) {
		t.Fatalf("err = %v", err)
	}

	// Fix the action; resume re-runs it (no successful run journaled).
	fixed := &fakeRunner{}
	o2, _ := newRebuildOpener(f, fixed, false)
	rres, rerr := o2.ResumeRebuild(context.Background(), f.vault, res.OperationID)
	if rerr != nil {
		t.Fatalf("resume: %v", rerr)
	}
	if rres.Phase != catalog.PhaseDone || fixed.callCount() != 1 {
		t.Fatalf("resume phase = %q calls = %d", rres.Phase, fixed.callCount())
	}
	if b, err := os.ReadFile(filepath.Join(dest, "node_modules", "built.txt")); err != nil {
		t.Fatalf("rebuild output missing after resume: %v", err)
	} else if string(b) != "rebuilt\n" {
		t.Fatalf("unexpected output %q", b)
	}
	runs, _ := f.cat.ListActionRuns(res.OperationID)
	if len(runs) != 2 || runs[0].Status != catalog.ActionRunFailed || runs[1].Status != catalog.ActionRunSucceeded {
		t.Fatalf("one row per attempt: %+v", runs)
	}
}

func TestResumeRebuildRejectsWrongPhaseAndMissingDest(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	o, _ := newRebuildOpener(f, &fakeRunner{}, false)

	// A DONE operation is not resumable.
	dest := rebuildDest(f)
	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ResumeRebuild(context.Background(), f.vault, res.OperationID); err == nil ||
		!strings.Contains(err.Error(), "--resume applies to") {
		t.Fatalf("resuming a DONE op must be refused: %v", err)
	}

	// A REBUILD_FAILED op whose destination vanished is a usage error.
	f2 := rebuildFixture(t, "go", "version")
	failRunner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 7}, nil
	}}
	o2, _ := newRebuildOpener(f2, failRunner, false)
	dest2 := rebuildDest(f2)
	res2, err := o2.Open(context.Background(), f2.vault, f2.snapID, Options{Destination: dest2})
	var failed2 *ErrRebuildFailed
	if !errors.As(err, &failed2) {
		t.Fatalf("err = %v", err)
	}
	if err := os.RemoveAll(dest2); err != nil {
		t.Fatal(err)
	}
	if _, err := o2.ResumeRebuild(context.Background(), f2.vault, res2.OperationID); err == nil ||
		!strings.Contains(err.Error(), "not a published directory") {
		t.Fatalf("resume without the published destination must be refused: %v", err)
	}
}

func TestCancelRebuild(t *testing.T) {
	f := rebuildFixture(t, "go", "version")
	runner := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 7}, nil
	}}
	o, _ := newRebuildOpener(f, runner, false)
	dest := rebuildDest(f)
	res, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	var failed2 *ErrRebuildFailed
	if !errors.As(err, &failed2) {
		t.Fatalf("err = %v", err)
	}
	if _, cerr := o.CancelRebuild(res.OperationID); cerr != nil {
		t.Fatalf("cancel: %v", cerr)
	}
	assertPhase(t, f, res.OperationID, catalog.PhaseCanceled)
	// Terminal: the workspace is unblocked (no active operations).
	active, aerr := f.cat.ActiveOperations(f.wsID)
	if aerr != nil || len(active) != 0 {
		t.Fatalf("active operations after cancel = %v (%v)", active, aerr)
	}
	// Published files stay.
	if _, rerr := os.Stat(filepath.Join(dest, "a.txt")); rerr != nil {
		t.Fatalf("published files must survive a cancel: %v", rerr)
	}
	// A done/canceled op cannot be canceled twice.
	if _, cerr := o.CancelRebuild(res.OperationID); cerr == nil {
		t.Fatal("double cancel must be refused")
	}
}

// ---- DAG ordering + definition reading ------------------------------------

func TestTopoOrderDeterministic(t *testing.T) {
	defs := []actions.Definition{
		{ID: "b", Argv: []string{"go"}, Outputs: []string{"out-b"}, Network: actions.NetworkNone, Timeout: time.Second, DependsOn: []string{"c"}},
		{ID: "a", Argv: []string{"go"}, Outputs: []string{"out-a"}, Network: actions.NetworkNone, Timeout: time.Second},
		{ID: "c", Argv: []string{"go"}, Outputs: []string{"out-c"}, Network: actions.NetworkNone, Timeout: time.Second, DependsOn: []string{"a"}},
	}
	if err := actions.ValidateGraph(defs); err != nil {
		t.Fatalf("graph: %v", err)
	}
	var order []string
	for _, d := range topoOrder(defs) {
		order = append(order, d.ID)
	}
	// Dependencies before dependents; lexicographic among the ready.
	if strings.Join(order, ",") != "a,c,b" {
		t.Fatalf("topo order = %v, want a,c,b", order)
	}

	// A cycle is rejected by the graph validation the driver re-runs
	// (c -> x -> b -> c).
	cyclic := []actions.Definition{
		{ID: "a", Argv: []string{"go"}, Outputs: []string{"out-a"}, Network: actions.NetworkNone, Timeout: time.Second},
		{ID: "b", Argv: []string{"go"}, Outputs: []string{"out-b"}, Network: actions.NetworkNone, Timeout: time.Second, DependsOn: []string{"c"}},
		{ID: "c", Argv: []string{"go"}, Outputs: []string{"out-c"}, Network: actions.NetworkNone, Timeout: time.Second, DependsOn: []string{"x"}},
		{ID: "x", Argv: []string{"go"}, Outputs: []string{"out-x"}, Network: actions.NetworkNone, Timeout: time.Second, DependsOn: []string{"b"}},
	}
	if err := actions.ValidateGraph(cyclic); err == nil {
		t.Fatal("cycle must be rejected")
	}
}

func TestRebuildDefinitionsFromManifest(t *testing.T) {
	parseManifest := func(f *fixture) manifestDoc {
		t.Helper()
		var m manifestDoc
		if err := decodeStrict(f.manifestBytes, &m); err != nil {
			t.Fatalf("parse fixture manifest: %v", err)
		}
		return m
	}
	// Legacy manifest without the extension: hint-only.
	fLegacy := buildFixture(t, fixtureSpec{recipeGroup: true})
	defs, err := rebuildDefinitions(parseManifest(fLegacy))
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 0 {
		t.Fatalf("legacy manifest must yield no executable definitions: %+v", defs)
	}
	if hints := rebuildHints(parseManifest(fLegacy)); len(hints) != 1 {
		t.Fatalf("legacy manifest must still report the hint: %+v", hints)
	}

	// Manifest with the extension: exact wire form round-trips.
	f := rebuildFixture(t, "go", "version")
	defs, err = rebuildDefinitions(parseManifest(f))
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 1 {
		t.Fatalf("defs = %+v", defs)
	}
	d := defs[0]
	if d.ID != "node-dependencies" || strings.Join(d.Argv, " ") != "go version" ||
		d.WorkingRoot != "." || d.Timeout != 30*time.Second ||
		len(d.Outputs) != 1 || d.Outputs[0] != "node_modules" || len(d.Inputs) != 1 {
		t.Fatalf("definition wire form drifted: %+v", d)
	}
}

func TestRebuildStrictReaderRejectsUnknownDefinitionField(t *testing.T) {
	f := buildFixture(t, fixtureSpec{recipeGroup: true, defArgv: []string{"go", "version"}, extraDefField: true})
	dest := rebuildDest(f)
	o, _ := newRebuildOpener(f, &fakeRunner{}, false)
	_, err := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	var ver *ErrVerification
	if !errors.As(err, &ver) {
		t.Fatalf("err = %v, want ErrVerification from strict parsing", err)
	}
	if !strings.Contains(err.Error(), "unexpected") {
		t.Fatalf("strict reader must name the unknown field: %v", err)
	}
}
