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

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/restore"
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
	// Wave-5 (D4): the drifted input makes the trim-time approval stale,
	// and merge runs the recreate_live argv — a DIFFERENT command than
	// the approved one. The replay therefore asks for a fresh approval
	// interactively (headless refuses; the approvalstore contract) and
	// the queued "yes" records it before the recipe runs.
	h.tty = true
	h.lines = []string{"yes"}
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
	// Wave-5 (D4): after the baseline strategy choice, the drifted input
	// digests make the trim-time approval stale — the approval prompt
	// follows the strategy menu and the queued "yes" re-approves.
	h.lines = []string{"3", "yes"} // revert to baseline, then re-approve
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

// ---- wave-5 D3/D5 CLI-surface regressions ---------------------------------

// TestReclaimTrimRecordsRestoreApproval (wave-5 D3): a trim performed
// through reclaim's trim stage records the REAL approval behind its
// consent — the same approvalstore `ebb restore` verifies — so a later
// restore replays the exact recipe silently, headless, with no
// re-approval (the D033 no-re-prompt property survives reclaim).
func TestReclaimTrimRecordsRestoreApproval(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("reclaim", "--target", "1", "--yes", h.wsRoot); code != ExitOK {
		t.Fatalf("reclaim code = %d, stderr = %s", code, stderr)
	}
	// Direct evidence: the state dir's approval store pins the deps
	// action, recorded by the --yes flag.
	raw, err := os.ReadFile(filepath.Join(h.stateDir, approvalsFile))
	if err != nil {
		t.Fatalf("approval store document: %v", err)
	}
	var doc struct {
		Approvals []struct {
			ActionID   string `json:"action_id"`
			ApprovedBy string `json:"approved_by"`
		} `json:"approvals"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("approval store parse: %v", err)
	}
	found := false
	for _, a := range doc.Approvals {
		if a.ActionID != "deps" {
			continue
		}
		found = true
		if a.ApprovedBy != "flag:--yes" {
			t.Errorf("approved_by = %q, want flag:--yes", a.ApprovedBy)
		}
	}
	if !found {
		t.Fatalf("reclaim's trim recorded NO approval for deps: %s", raw)
	}

	// Restore replays silently: headless (no tty), no flags — an exact
	// match must never reach the approval resolver.
	r := &gRunner{}
	h.deps.NewActionRunner = func() restore.ActionRunner { return r }
	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("restore after reclaim code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if got := envString(t, env, "outcome"); got != "ok" {
		t.Fatalf("outcome = %q (stderr %s)", got, stderr)
	}
	if r.count() != 1 {
		t.Fatalf("runner calls = %d, want 1", r.count())
	}
}

// legacyPending builds one legacy-marked pending approval (the shape the
// driver's pre-pass emits for an action synthesized from a trim manifest
// without frozen definitions).
func legacyPending() restore.PendingApproval {
	return restore.PendingApproval{
		Def: actions.Definition{
			ID:          "deps",
			Argv:        []string{"pnpm", "install", "--frozen-lockfile"},
			WorkingRoot: ".",
			Inputs:      []string{"package.json", "pnpm-lock.yaml"},
			Outputs:     []string{"node_modules"},
		},
		Cause:  &actions.ErrApprovalRequired{ActionID: "deps"},
		Legacy: true,
	}
}

// TestRestoreLegacyHeadlessRefusalNamesLegacyApprove (wave-5 D5): a
// non-terminal asked to approve a legacy-manifest action refuses with
// the EBB_E_LEGACY_TRIM_MANIFEST disclosure (command, root, inputs,
// outputs; historical approval identity unavailable) and names the
// --legacy-approve flag — NOT open's --yes, which restore does not have.
func TestRestoreLegacyHeadlessRefusalNamesLegacyApprove(t *testing.T) {
	baseCalled := false
	base := func(ctx context.Context, pending []restore.PendingApproval) error {
		baseCalled = true
		return nil
	}
	deps := Deps{StdinIsTerminal: func() bool { return false }}
	resolver := restoreLegacyApprovalResolver(deps, Streams{Err: &strings.Builder{}}, false, base)

	err := resolver(context.Background(), []restore.PendingApproval{legacyPending()})
	if err == nil {
		t.Fatal("headless legacy consent must refuse (D5)")
	}
	if baseCalled {
		t.Fatal("the grouped resolver must not run for a refused legacy consent")
	}
	msg := err.Error()
	for _, want := range []string{
		restore.CodeLegacyManifest,
		"--legacy-approve",
		"historical approval identity is unavailable",
		"pnpm install --frozen-lockfile",
		"package.json", "pnpm-lock.yaml",
		"node_modules",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("headless refusal lacks %q:\n%s", want, msg)
		}
	}
	if code := classifyExitCode(err); code != ExitBlocked {
		t.Errorf("exit code = %d, want blocked (3)", code)
	}
}

// TestRestoreLegacyResolverDisclosesBeforeConfirm (wave-5 D5): on a
// terminal the legacy disclosure prints BEFORE the grouped confirm, and
// non-legacy pendings bypass the banner entirely; --legacy-approve
// headless prints the banner and resolves without a refusal.
func TestRestoreLegacyResolverDisclosesBeforeConfirm(t *testing.T) {
	newBase := func(called *bool) restore.ApprovalResolver {
		return func(ctx context.Context, pending []restore.PendingApproval) error {
			*called = true
			return nil
		}
	}

	// (a) Interactive: banner, then the grouped resolver.
	called := false
	errb := &strings.Builder{}
	deps := Deps{StdinIsTerminal: func() bool { return true }}
	resolver := restoreLegacyApprovalResolver(deps, Streams{Err: errb}, false, newBase(&called))
	if err := resolver(context.Background(), []restore.PendingApproval{legacyPending()}); err != nil {
		t.Fatalf("interactive legacy consent must reach the confirm: %v", err)
	}
	if !called {
		t.Fatal("the grouped resolver must run after the disclosure")
	}
	if msg := errb.String(); !strings.Contains(msg, "legacy recovery attempt") ||
		!strings.Contains(msg, "freshly approved NOW") ||
		!strings.Contains(msg, "not the previously-approved actions") ||
		!strings.Contains(msg, "pnpm install --frozen-lockfile") {
		t.Errorf("disclosure banner incomplete:\n%s", msg)
	}

	// (b) Exact-shape pendings without the legacy marker bypass the
	// banner entirely (open's resolver handles them untouched).
	called2, errb2 := false, &strings.Builder{}
	resolver2 := restoreLegacyApprovalResolver(deps, Streams{Err: errb2}, false, newBase(&called2))
	fresh := legacyPending()
	fresh.Legacy = false
	if err := resolver2(context.Background(), []restore.PendingApproval{fresh}); err != nil {
		t.Fatalf("non-legacy pending: %v", err)
	}
	if !called2 || errb2.String() != "" {
		t.Errorf("non-legacy pendings must bypass the legacy banner (called=%v stderr=%q)", called2, errb2.String())
	}

	// (c) --legacy-approve headless: consent recorded, banner printed.
	called3, errb3 := false, &strings.Builder{}
	depsHeadless := Deps{StdinIsTerminal: func() bool { return false }}
	resolver3 := restoreLegacyApprovalResolver(depsHeadless, Streams{Err: errb3}, true, newBase(&called3))
	if err := resolver3(context.Background(), []restore.PendingApproval{legacyPending()}); err != nil {
		t.Fatalf("consented headless legacy replay must resolve: %v", err)
	}
	if !called3 {
		t.Fatal("the grouped resolver must record the consented legacy approval")
	}
	if msg := errb3.String(); !strings.Contains(msg, "legacy recovery attempt") {
		t.Errorf("consented headless legacy replay must print the honest label:\n%s", msg)
	}
}
