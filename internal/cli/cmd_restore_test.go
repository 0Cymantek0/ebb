// cmd_restore_test.go drives `ebb restore` end to end through the Deps
// seam: a real `ebb trim` produces the sealed record, then the restore
// command replays it through the fake runner — covering dispatch, the
// §17.2 envelope shape, exit codes, --dry-run no-effects, --strategy
// validation, drift reconciliation and the branch-mismatch refusal
// wording.

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/actions"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/restore"
)

// newRestoreHarness builds the e-harness with the fake action runner
// seam installed for `ebb restore`.
func newRestoreHarness(t *testing.T) (*eHarness, *gRunner) {
	t.Helper()
	h := newEHarness(t)
	r := &gRunner{}
	h.deps.NewActionRunner = func() restore.ActionRunner { return r }
	return h, r
}

// trimCliws runs a real trim of the deps group and returns the trim op.
func trimCliws(t *testing.T, h *eHarness) catalog.Operation {
	t.Helper()
	if code, _, stderr := h.run("trim", "--groups", "deps", "--yes", h.wsRoot); code != ExitOK {
		t.Fatalf("trim code = %d, stderr = %s", code, stderr)
	}
	var best *catalog.Operation
	for _, op := range operationsOf(t, h.cat()) {
		op := op
		if op.Kind == catalog.OpKindTrim && op.Phase == catalog.PhaseTrimDone {
			if best == nil || op.UpdatedAt > best.UpdatedAt {
				best = &op
			}
		}
	}
	if best == nil {
		t.Fatal("no completed trim operation recorded")
	}
	return *best
}

func TestRestoreReplaysTrimmedGroups(t *testing.T) {
	h, runner := newRestoreHarness(t)
	trim := trimCliws(t, h)
	// The trim removed the group's outputs from the live root.
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("trim left node_modules behind: %v", err)
	}

	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("restore code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if got := envString(t, env, "outcome"); got != "ok" {
		t.Fatalf("outcome = %q", got)
	}
	if got := envString(t, env, "phase"); got != catalog.PhaseRestoreDone {
		t.Fatalf("phase = %q, want %s", got, catalog.PhaseRestoreDone)
	}
	if got := envString(t, env, "operation_id"); got == "" {
		t.Fatal("envelope lacks the restore operation id")
	}
	details, _ := env["details"].(map[string]any)
	if details == nil {
		t.Fatalf("envelope lacks details: %v", env)
	}
	for _, key := range []string{"workspace", "root", "trim_operation_id", "groups", "protected_gate"} {
		if _, ok := details[key]; !ok {
			t.Fatalf("details lacks %q: %v", key, details)
		}
	}
	if details["trim_operation_id"] != string(trim.ID) {
		t.Fatalf("details trim op = %v, want %s", details["trim_operation_id"], trim.ID)
	}
	groups, _ := details["groups"].([]any)
	if len(groups) != 1 {
		t.Fatalf("groups = %v", groups)
	}
	g := groups[0].(map[string]any)
	if g["id"] != "deps" || g["command"] == nil {
		t.Fatalf("group details malformed: %v", g)
	}
	if details["protected_gate"] != "passed" {
		t.Fatalf("protected gate outcome = %v", details["protected_gate"])
	}
	if runner.count() != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.count())
	}
	// The recipe recreated the outputs; protected files are untouched.
	if b, err := os.ReadFile(filepath.Join(h.wsRoot, "node_modules", "built.txt")); err != nil || string(b) != "rebuilt\n" {
		t.Fatalf("recipe output missing: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(h.wsRoot, "notes.md")); err != nil || !strings.Contains(string(b), "private notes") {
		t.Fatalf("protected file damaged: %v", err)
	}
	// The restore op is journaled DONE and terminal.
	var restoreOp *catalog.Operation
	for _, op := range operationsOf(t, h.cat()) {
		op := op
		if op.Kind == catalog.OpKindRestore {
			restoreOp = &op
		}
	}
	if restoreOp == nil || restoreOp.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("restore op = %+v", restoreOp)
	}
}

func TestRestoreRecipeFailureExitsSixAndRerunResumes(t *testing.T) {
	h, _ := newRestoreHarness(t)
	trimCliws(t, h)
	h.deps.NewActionRunner = func() restore.ActionRunner { return &failOnceRunner{} }
	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitRebuildFailed {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if got := envString(t, env, "outcome"); got != "rebuild-failed" {
		t.Fatalf("outcome = %q", got)
	}
	if got := envString(t, env, "phase"); got != catalog.PhaseRestoreFailed {
		t.Fatalf("phase = %q", got)
	}
	errs := strings.Join(stringList(env["errors"]), " ")
	if !strings.Contains(errs, "resumable") {
		t.Fatalf("exit-6 wording must name the resumable path: %v", errs)
	}
	// The rerun resumes (partial outputs exist but the FAILED op keeps
	// the already-restored gate honest) and completes.
	h.deps.NewActionRunner = func() restore.ActionRunner { return &gRunner{} }
	code2, _, stderr2 := h.run("restore", h.wsRoot)
	if code2 != ExitOK {
		t.Fatalf("rerun code = %d, stderr = %s", code2, stderr2)
	}
}

// failOnceRunner fails its first execution and succeeds on later ones.
type failOnceRunner struct {
	gRunner
	failed bool
}

func (r *failOnceRunner) Run(ctx context.Context, def actions.Definition, wsRoot string, appr actions.Approver, capture actions.OutputSink) (actions.Result, error) {
	if !r.failed {
		r.failed = true
		// Leave a partial output behind (the crash-ish reality).
		_ = os.MkdirAll(filepath.Join(wsRoot, "node_modules"), 0o755)
		return actions.Result{ExitCode: 3, OutputExcerpt: "--- stderr ---\nEPERM"}, nil
	}
	return r.gRunner.Run(ctx, def, wsRoot, appr, capture)
}

func TestRestoreNothingRecordedIsHonestBlock(t *testing.T) {
	h, _ := newRestoreHarness(t)
	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if got := envString(t, env, "outcome"); got != "blocked" {
		t.Fatalf("outcome = %q", got)
	}
	errs := strings.Join(stringList(env["errors"]), " ")
	if !strings.Contains(errs, "no recorded cleanup") {
		t.Fatalf("error wording must be honest about the missing record: %v", errs)
	}
}

func TestRestoreAlreadyRestoredRefusesRedundancy(t *testing.T) {
	h, _ := newRestoreHarness(t)
	trimCliws(t, h)
	if code, _, stderr := h.run("restore", h.wsRoot); code != ExitOK {
		t.Fatalf("first restore code = %d, stderr = %s", code, stderr)
	}
	code, _, stderr := h.run("restore", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("second restore code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "already carries every recorded group's outputs") {
		t.Fatalf("already-restored wording missing: %s", stderr)
	}
}

func TestRestoreStrategyValidation(t *testing.T) {
	h, _ := newRestoreHarness(t)
	trimCliws(t, h)
	code, _, stderr := h.run("restore", "--strategy", "bogus", h.wsRoot)
	if code != ExitUsage {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "merge, current, baseline") {
		t.Fatalf("usage wording: %s", stderr)
	}
}

func TestRestoreDriftRequiresStrategyNonInteractively(t *testing.T) {
	h, _ := newRestoreHarness(t)
	trimCliws(t, h)
	// Wednesday: the developer adds a dependency.
	pkg := filepath.Join(h.wsRoot, "package.json")
	if err := os.WriteFile(pkg, []byte(`{"name":"cliws","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0","chalk":"5.0.0"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	errs := strings.Join(stringList(env["errors"]), " ")
	if !strings.Contains(errs, "drifted") || !strings.Contains(errs, "--strategy") {
		t.Fatalf("strategy-required wording missing: %v", errs)
	}
	if !strings.Contains(errs, "package.json") {
		t.Fatalf("drift table must name the drifted input: %v", errs)
	}
}

func TestRestoreMergeStrategyUnionsAndBacksUp(t *testing.T) {
	h, runner := newRestoreHarness(t)
	trimCliws(t, h)
	pkg := filepath.Join(h.wsRoot, "package.json")
	live := []byte(`{"name":"cliws","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0","chalk":"5.0.0"}}` + "\n")
	if err := os.WriteFile(pkg, live, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("restore", "--strategy", "merge", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("merge code = %d, stderr = %s", code, stderr)
	}
	// The unioned manifest keeps the live chalk AND the recorded
	// (trim-time) left-pad declaration; a backup preserves the pre-merge
	// live bytes.
	b, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if jerr := json.Unmarshal(b, &doc); jerr != nil {
		t.Fatalf("unioned package.json unparseable: %s", b)
	}
	deps := doc["dependencies"].(map[string]any)
	if deps["chalk"] != "5.0.0" {
		t.Fatalf("live-only addition lost: %s", b)
	}
	backups, _ := filepath.Glob(pkg + ".bak-drift-*")
	if len(backups) != 1 {
		t.Fatalf("expected one drift backup, got %v", backups)
	}
	if runner.count() != 1 {
		t.Fatalf("runner calls = %d", runner.count())
	}
	if !strings.Contains(stderr, "merge") && !strings.Contains(stderr, "restored workspace") {
		t.Fatalf("human report missing: %s", stderr)
	}
}

func TestRestoreDryRunHasNoEffects(t *testing.T) {
	h, runner := newRestoreHarness(t)
	trimCliws(t, h)
	code, stdout, stderr := h.run("restore", "--dry-run", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("dry-run code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if got := envString(t, env, "outcome"); got != "dry-run" {
		t.Fatalf("outcome = %q", got)
	}
	if runner.count() != 0 {
		t.Fatalf("dry run executed recipes")
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("dry run created outputs: %v", err)
	}
	for _, op := range operationsOf(t, h.cat()) {
		if op.Kind == catalog.OpKindRestore {
			t.Fatalf("dry run journaled a restore operation: %+v", op)
		}
	}
	details, _ := env["details"].(map[string]any)
	if details == nil || details["dry_run"] != true {
		t.Fatalf("details must carry dry_run: %v", details)
	}
	// The human (non-json) preview names the dry run.
	if code2, _, stderr2 := h.run("restore", "--dry-run", h.wsRoot); code2 != ExitOK || !strings.Contains(stderr2, "dry run") {
		t.Fatalf("human dry-run report: code=%d stderr=%s", code2, stderr2)
	}
}

func TestRestoreBranchMismatchRefusalWording(t *testing.T) {
	h, _ := newRestoreHarness(t)
	// The trim records the Git context through the (overridable) seam.
	recorded := domain.GitObservation{IsRepo: true, HeadBranch: "feature-payments",
		HeadCommit: "9a8f3b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a"}
	h.deps.ObserveGit = func(ctx context.Context, root string) (domain.GitObservation, error) {
		return recorded, nil
	}
	trimCliws(t, h)
	// The workspace moved to main: the live observation diverges.
	live := domain.GitObservation{IsRepo: true, HeadBranch: "main",
		HeadCommit: "4c11e7a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3"}
	h.deps.ObserveGit = liveObserve(live)

	code, _, stderr := h.run("restore", h.wsRoot) // non-interactive
	if code != ExitBlocked {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"feature-payments", "main", "never auto-decides"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("branch-mismatch wording lacks %q:\n%s", want, stderr)
		}
	}
}

func TestRestoreBranchMismatchInteractiveSwitchBack(t *testing.T) {
	h, runner := newRestoreHarness(t)
	recorded := domain.GitObservation{IsRepo: true, HeadBranch: "feature-payments",
		HeadCommit: "9a8f3b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a"}
	h.deps.ObserveGit = liveObserve(recorded)
	trimCliws(t, h)
	h.deps.ObserveGit = liveObserve(domain.GitObservation{IsRepo: true, HeadBranch: "main"})

	h.tty = true
	h.lines = []string{"1"} // switch back first
	code, _, stderr := h.run("restore", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("switch-back choice code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "git switch feature-payments") {
		t.Fatalf("the exact git switch command must be printed: %s", stderr)
	}
	if runner.count() != 0 {
		t.Fatalf("nothing may run on the switch-back choice")
	}
}

func TestRestoreInteractiveStrategyMenu(t *testing.T) {
	h, _ := newRestoreHarness(t)
	trimCliws(t, h)
	if err := os.WriteFile(filepath.Join(h.wsRoot, "package.json"),
		[]byte(`{"name":"cliws","dependencies":{"left-pad":"2.0.0"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.tty = true
	h.lines = []string{"3"} // revert to baseline
	code, _, stderr := h.run("restore", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("baseline menu choice code = %d, stderr = %s", code, stderr)
	}
	pkg, err := os.ReadFile(filepath.Join(h.wsRoot, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The baseline reverts package.json to the frozen trim-time bytes.
	frozen := `{"name":"cliws","version":"1.0.0","private":true}` + "\n"
	if string(pkg) != frozen {
		t.Fatalf("baseline did not restore the frozen manifest: %q", pkg)
	}
}

// liveObserve wraps one fixed observation as the ObserveGit seam.
func liveObserve(obs domain.GitObservation) func(ctx context.Context, root string) (domain.GitObservation, error) {
	return func(ctx context.Context, root string) (domain.GitObservation, error) {
		return obs, nil
	}
}

// stringList coerces an envelope JSON array field to strings.
func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---- Wave 1 restore review regressions ------------------------------------

// TestRestoreJSONOnTerminalNeverPrompts pins F6: `--json` is machine
// mode, so even on a terminal the branch mismatch refuses with its
// typed error instead of dropping a scripted consumer into a menu.
func TestRestoreJSONOnTerminalNeverPrompts(t *testing.T) {
	h, runner := newRestoreHarness(t)
	recorded := domain.GitObservation{IsRepo: true, HeadBranch: "feature-payments",
		HeadCommit: "9a8f3b2c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a"}
	h.deps.ObserveGit = liveObserve(recorded)
	trimCliws(t, h)
	h.deps.ObserveGit = liveObserve(domain.GitObservation{IsRepo: true, HeadBranch: "main"})

	// A terminal is attached AND --json is set: no menu may appear.
	h.tty = true
	h.lines = nil // nothing queued: a menu read would fail the test later
	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if strings.Contains(stderr, "Select:") || strings.Contains(stderr, "Branch mismatch:") {
		t.Fatalf("--json must not render an interactive menu:\n%s", stderr)
	}
	env := envelopeOf(t, stdout)
	errs := strings.Join(stringList(env["errors"]), " ")
	if !strings.Contains(errs, restore.CodeBranchMismatch) {
		t.Fatalf("envelope must carry the typed mismatch code %s: %v", restore.CodeBranchMismatch, errs)
	}
	if !strings.Contains(errs, "feature-payments") || !strings.Contains(errs, "main") {
		t.Fatalf("mismatch must name both branches: %v", errs)
	}
	if runner.count() != 0 {
		t.Fatalf("nothing may run on a refused mismatch")
	}
}

// partialFailRunner fails its first execution (leaving a partial output
// tree behind, the RESTORE_FAILED reality) and succeeds on later ones.
type partialFailRunner struct {
	gRunner
	failed bool
}

func (r *partialFailRunner) Run(ctx context.Context, def actions.Definition, wsRoot string, appr actions.Approver, capture actions.OutputSink) (actions.Result, error) {
	if !r.failed {
		r.failed = true
		if err := os.MkdirAll(filepath.Join(wsRoot, "node_modules"), 0o755); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
		if err := os.WriteFile(filepath.Join(wsRoot, "node_modules", "partial.txt"), []byte("partial"), 0o644); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
		return actions.Result{ExitCode: 3, OutputExcerpt: "--- stderr ---\nEPERM"}, nil
	}
	return r.gRunner.Run(ctx, def, wsRoot, appr, capture)
}

// TestRestoreHeadlessRefusalUnwedgesDeadRowForLaterTrim pins F3's driver
// ordering end to end: a restore that failed (RESTORE_FAILED), then a
// headless rerun over drift with no --strategy (exit 3,
// ErrStrategyRequired — no operation opened) STILL supersedes the dead
// row, so a following trim proceeds instead of answering ErrOpInProgress
// forever.
func TestRestoreHeadlessRefusalUnwedgesDeadRowForLaterTrim(t *testing.T) {
	h, _ := newRestoreHarness(t)
	trimCliws(t, h)

	// A failed restore leaves the dead row plus partial outputs.
	h.deps.NewActionRunner = func() restore.ActionRunner { return &partialFailRunner{} }
	if code, _, stderr := h.run("restore", h.wsRoot); code != ExitRebuildFailed {
		t.Fatalf("first restore code = %d, stderr = %s", code, stderr)
	}
	var deadOp *catalog.Operation
	for _, op := range operationsOf(t, h.cat()) {
		op := op
		if op.Kind == catalog.OpKindRestore && op.Phase == catalog.PhaseRestoreFailed {
			deadOp = &op
		}
	}
	if deadOp == nil {
		t.Fatal("no RESTORE_FAILED row recorded")
	}

	// Wednesday drift + headless rerun without --strategy: blocked (3)
	// with the strategy error — and the dead row superseded anyway.
	if err := os.WriteFile(filepath.Join(h.wsRoot, "package.json"),
		[]byte(`{"name":"cliws","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0","chalk":"5.0.0"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := h.run("restore", "--json", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("headless rerun code = %d, want blocked (3)", code)
	}
	env := envelopeOf(t, stdout)
	if errs := strings.Join(stringList(env["errors"]), " "); !strings.Contains(errs, restore.CodeStrategyRequired) {
		t.Fatalf("expected the strategy-required blocker: %v", errs)
	}
	fresh, gerr := h.cat().GetOperation(deadOp.ID)
	if gerr != nil || fresh.Phase != catalog.PhaseCanceled {
		t.Fatalf("dead row must be superseded despite the refusal: phase=%s err=%v", fresh.Phase, gerr)
	}

	// The workspace is un-wedged: a later trim proceeds.
	if code, _, stderr := h.run("trim", "--groups", "deps", "--yes", h.wsRoot); code != ExitOK {
		t.Fatalf("trim after the un-wedging rerun must proceed: code=%d stderr=%s", code, stderr)
	}
}
