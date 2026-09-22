// wave_g_open_test.go drives the rebuild-execution wiring of `ebb open`
// end to end through the Deps seam: the fake-runner seam executing the
// frozen manifest definitions, the approval prompt / --yes / drift
// matrix, exit-6 classification, --resume skipping succeeded actions,
// and --cancel unblocking the workspace.

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/restore"
)

// gRunner is the fake actions runner: it records calls, defers to an
// injectable behavior, and by default materializes every declared
// output (a benign "install") with success.
type gRunner struct {
	mu    sync.Mutex
	calls []string
	fn    func(def actions.Definition) (actions.Result, error)
}

func (r *gRunner) Run(ctx context.Context, def actions.Definition, wsRoot string, appr actions.Approver, capture actions.OutputSink) (actions.Result, error) {
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

func (r *gRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// gCustomEbbfile declares a custom-command regenerate group whose argv
// resolves on every test machine ("go"); the fake runner executes it.
const gCustomEbbfile = `version = 1

[workspace]
name = "cliws"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "build"
adapter = "custom"
root = "."
outputs = ["generated"]
inputs = ["package.json"]
network = "allowed"
command = ["go", "version"]
`

// newGHarness builds the e-harness with the custom-command workspace:
// the Ebbfile is rewritten over the pnpm fixture and the group's output
// tree exists (so the group actually has omitted members at capture).
func newGHarness(t *testing.T) *eHarness {
	t.Helper()
	h := newEHarness(t)
	files := map[string]string{
		"Ebbfile.toml":          gCustomEbbfile,
		"generated/artifact.js": "// generated content omitted at capture\n",
	}
	for rel, content := range files {
		p := filepath.Join(h.wsRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// withRunner installs the fake runner seam.
func withRunner(h *eHarness, r *gRunner) {
	h.deps.NewActionRunner = func() restore.ActionRunner { return r }
}

// parkG parks the custom workspace and returns the park snapshot id.
func parkG(t *testing.T, h *eHarness) domain.SnapshotID {
	t.Helper()
	if code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatalf("park code = %d, stderr = %s", code, stderr)
	}
	for _, s := range snapshotsOf(t, h) {
		if s.Kind == catalog.SnapshotKindPark {
			return s.ID
		}
	}
	t.Fatal("no park snapshot")
	return ""
}

func gDest(t *testing.T) string {
	return filepath.Join(t.TempDir(), "restored")
}

func mustParkManifestCarryDefinition(t *testing.T, h *eHarness) {
	t.Helper()
	// The frozen manifest inside the payload must carry the definition
	// extension (the exact captured argv the open will run).
	for _, s := range snapshotsOf(t, h) {
		if s.Kind != catalog.SnapshotKindPark || s.PayloadBackendID == "" {
			continue
		}
		snap := h.store.snaps[s.PayloadBackendID]
		if snap == nil {
			t.Fatal("payload snapshot missing from the fake store")
		}
		for path, b := range snap.files {
			if strings.HasSuffix(path, "/manifest.json") {
				if !strings.Contains(string(b), `"definition"`) ||
					!strings.Contains(string(b), `"go"`) || !strings.Contains(string(b), `"version"`) {
					t.Fatalf("frozen manifest lacks the definition extension:\n%s", b)
				}
				return
			}
		}
	}
	t.Fatal("no manifest.json found in the payload")
}

func TestOpenRebuildRunsFrozenDefinitionAndExitsZero(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	mustParkManifestCarryDefinition(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	h.tty = false // --yes non-interactive path

	dest := gDest(t)
	code, stdout, stderr := h.run("open", "cliws", "--to", dest, "--yes")
	if code != ExitOK {
		t.Fatalf("open code = %d, stderr = %s", code, stderr)
	}
	if runner.count() != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.count())
	}
	// The action's output exists at the destination; protected files too.
	if b, err := os.ReadFile(filepath.Join(dest, "generated", "built.txt")); err != nil || string(b) != "rebuilt\n" {
		t.Fatalf("rebuild output missing: %q %v", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "notes.md")); err != nil || !strings.Contains(string(b), "private notes") {
		t.Fatalf("protected file damaged: %v", err)
	}
	// The op is DONE and the action run journaled.
	cat := h.cat()
	var opID domain.OperationID
	for _, op := range operationsOf(t, cat) {
		if op.Kind == catalog.OpKindOpen {
			opID = op.ID
		}
	}
	if opID == "" {
		t.Fatal("no open operation found")
	}
	op, err := cat.GetOperation(opID)
	if err != nil || op.Phase != catalog.PhaseDone {
		t.Fatalf("open op phase: %v %q, want DONE", err, op.Phase)
	}
	runs, err := cat.ListActionRuns(opID)
	if err != nil || len(runs) != 1 || runs[0].Status != catalog.ActionRunSucceeded {
		t.Fatalf("action runs = %+v (%v)", runs, err)
	}
	// The approval was durably recorded (approvalstore in the state dir).
	store := approvalstore.New(filepath.Join(h.stateDir, approvalsFile))
	list, err := store.List()
	if err != nil || len(list) != 1 || list[0].ActionID != "build" {
		t.Fatalf("approvals = %+v (%v)", list, err)
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, stdout)
}

func TestOpenRebuildInteractivePromptListsActions(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	h.tty = true
	h.lines = []string{"yes"}

	dest := gDest(t)
	code, _, stderr := h.run("open", "cliws", "--to", dest)
	if code != ExitOK {
		t.Fatalf("open code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"reconstruction actions will run",
		"go version",
		"outputs: generated",
		"inputs: package.json",
		"network: allowed",
		"sha256",
		"Approve these actions?",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("prompt lacks %q:\n%s", want, stderr)
		}
	}
}

func TestOpenRebuildDeclinedPromptExitsSix(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	h.tty = true
	h.lines = []string{"no"}

	dest := gDest(t)
	code, _, stderr := h.run("open", "cliws", "--to", dest)
	if code != ExitRebuildFailed {
		t.Fatalf("code = %d, want 6", code)
	}
	if !strings.Contains(stderr, "EBB_E_APPROVAL_DECLINED") {
		t.Errorf("stderr must name the declined approval:\n%s", stderr)
	}
	if runner.count() != 0 {
		t.Fatalf("declined approval must never execute; calls = %d", runner.count())
	}
	// Files intact at the destination; op REBUILD_FAILED (resumable).
	if b, err := os.ReadFile(filepath.Join(dest, "notes.md")); err != nil || !strings.Contains(string(b), "private notes") {
		t.Fatalf("recovered files not intact: %v", err)
	}
	for _, op := range operationsOf(t, h.cat()) {
		if op.Kind == catalog.OpKindOpen && op.Phase != catalog.PhaseRebuildFailed {
			t.Fatalf("open op phase = %q, want REBUILD_FAILED", op.Phase)
		}
	}
}

func TestOpenRebuildNonInteractiveWithoutYesBlocks(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	h.tty = false

	code, _, stderr := h.run("open", "cliws", "--to", gDest(t))
	if code != ExitRebuildFailed {
		t.Fatalf("code = %d, want 6", code)
	}
	if !strings.Contains(stderr, "EBB_E_APPROVAL_REQUIRED") {
		t.Errorf("stderr must name the missing approval:\n%s", stderr)
	}
	if runner.count() != 0 {
		t.Fatalf("nothing may run without an approval; calls = %d", runner.count())
	}
}

// recordDriftedApproval writes an approval for the SAME action id with a
// DIFFERENT argv, so the frozen definition's exact approval is stale.
func recordDriftedApproval(t *testing.T, h *eHarness) {
	t.Helper()
	tool, err := actions.ResolveTool("go")
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{}
	if b, rerr := os.ReadFile(filepath.Join(h.wsRoot, "package.json")); rerr != nil {
		t.Fatal(rerr)
	} else {
		digests["package.json"] = digestOf(b)
	}
	store := approvalstore.New(filepath.Join(h.stateDir, approvalsFile))
	drifted := actions.Definition{
		ID: "build", Argv: []string{"go", "env"}, WorkingRoot: ".",
		Inputs: []string{"package.json"}, Outputs: []string{"generated"},
		Network: actions.NetworkAllowed, Timeout: customActionTimeout,
	}
	if _, aerr := store.Approve(drifted, tool, digests, "test-drift"); aerr != nil {
		t.Fatal(aerr)
	}
}

func TestOpenRebuildDriftBlocksNonInteractiveEvenWithYes(t *testing.T) {
	h := newGHarness(t)
	recordDriftedApproval(t, h) // before the park removes the root
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	h.tty = false

	code, _, stderr := h.run("open", "cliws", "--to", gDest(t), "--yes")
	if code != ExitRebuildFailed {
		t.Fatalf("code = %d, want 6 (drift blocks even with --yes)", code)
	}
	if !strings.Contains(stderr, "EBB_E_APPROVAL_DRIFT") {
		t.Errorf("stderr must name the drift:\n%s", stderr)
	}
	if runner.count() != 0 {
		t.Fatalf("drifted approval must never execute; calls = %d", runner.count())
	}
}

func TestOpenRebuildDriftRepromptsInteractively(t *testing.T) {
	h := newGHarness(t)
	recordDriftedApproval(t, h) // before the park removes the root
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	h.tty = true
	h.lines = []string{"yes"}

	dest := gDest(t)
	code, _, stderr := h.run("open", "cliws", "--to", dest, "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "approval drift") || !strings.Contains(stderr, "argv digest") {
		t.Errorf("the re-prompt must show the drift lines:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(dest, "generated", "built.txt")); err != nil {
		t.Fatalf("rebuild did not run after re-approval: %v", err)
	}
}

func TestOpenRebuildRecordedApprovalReusedWithoutPrompt(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)

	// First open records the approval (--yes, non-interactive).
	dest1 := gDest(t)
	if code, _, stderr := h.run("open", "cliws", "--to", dest1, "--yes"); code != ExitOK {
		t.Fatalf("first open code = %d, stderr = %s", code, stderr)
	}
	first := runner.count()

	// Park again at the live destination (the standard re-park cycle),
	// then open with NO --yes and NO terminal: the recorded approval
	// matches exactly and must be reused silently (§5.2).
	h.resetSignalContext()
	if code, _, stderr := h.run("park", "--assert-writers-stopped", dest1); code != ExitOK {
		t.Fatalf("re-park code = %d, stderr = %s", code, stderr)
	}
	h.tty = false
	dest2 := gDest(t)
	code, _, stderr := h.run("open", "cliws", "--to", dest2)
	if code != ExitOK {
		t.Fatalf("second open code = %d, stderr = %s", code, stderr)
	}
	if got := runner.count(); got != first+1 {
		t.Fatalf("runner calls = %d, want %d (approval reused, action re-run once)", got, first+1)
	}
	if strings.Contains(stderr, "Approve these actions?") {
		t.Errorf("an exactly-matching recorded approval must not re-prompt:\n%s", stderr)
	}
}

func TestOpenRebuildFailureExit6ThenResumeSucceeds(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 7, OutputExcerpt: "install failed"}, nil
	}}
	withRunner(h, runner)
	h.tty = false

	dest := gDest(t)
	code, _, stderr := h.run("open", "cliws", "--to", dest, "--yes")
	if code != ExitRebuildFailed {
		t.Fatalf("code = %d, want 6, stderr = %s", code, stderr)
	}
	for _, want := range []string{"EBB_E_REBUILD_FAILED", "build", "--resume"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("exit-6 message lacks %q:\n%s", want, stderr)
		}
	}
	// Files intact; a failed run row is journaled.
	if _, err := os.Stat(filepath.Join(dest, "notes.md")); err != nil {
		t.Fatalf("recovered files not intact: %v", err)
	}
	var opID domain.OperationID
	for _, op := range operationsOf(t, h.cat()) {
		if op.Kind == catalog.OpKindOpen {
			opID = op.ID
		}
	}
	runs, _ := h.cat().ListActionRuns(opID)
	if len(runs) != 1 || runs[0].Status != catalog.ActionRunFailed {
		t.Fatalf("failed attempt must be journaled: %+v", runs)
	}

	// Fix the action; --resume re-runs it and completes DONE.
	runner.fn = nil
	h.resetSignalContext()
	code, _, stderr = h.run("open", "--resume", string(opID))
	if code != ExitOK {
		t.Fatalf("resume code = %d, stderr = %s", code, stderr)
	}
	op, err := h.cat().GetOperation(opID)
	if err != nil || op.Phase != catalog.PhaseDone {
		t.Fatalf("resumed op phase: %v %q, want DONE", err, op.Phase)
	}
	if _, err := os.Stat(filepath.Join(dest, "generated", "built.txt")); err != nil {
		t.Fatalf("rebuild output missing after resume: %v", err)
	}
	runs, _ = h.cat().ListActionRuns(opID)
	if len(runs) != 2 || runs[1].Status != catalog.ActionRunSucceeded {
		t.Fatalf("one row per attempt: %+v", runs)
	}
}

func TestOpenCancelUnblocksWorkspace(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 7}, nil
	}}
	withRunner(h, runner)
	h.tty = false

	dest := gDest(t)
	if code, _, _ := h.run("open", "cliws", "--to", dest, "--yes"); code != ExitRebuildFailed {
		t.Fatalf("code = %d, want 6", code)
	}
	// The REBUILD_FAILED op blocks a new park on the workspace.
	h.resetSignalContext()
	if code, _, _ := h.run("park", "--assert-writers-stopped", dest); code != ExitBlocked {
		t.Fatalf("park over an unresolved rebuild must block, got %d", code)
	}

	// Cancel by workspace name; files stay, snapshot stays pinned.
	h.resetSignalContext()
	code, _, stderr := h.run("open", "--cancel", "cliws")
	if code != ExitOK {
		t.Fatalf("cancel code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dest, "notes.md")); err != nil {
		t.Fatalf("published files must survive the cancel: %v", err)
	}
	// The workspace is unblocked: a fresh park succeeds.
	h.resetSignalContext()
	if code, _, stderr := h.run("park", "--assert-writers-stopped", dest); code != ExitOK {
		t.Fatalf("park after cancel code = %d, stderr = %s", code, stderr)
	}
}

func TestClassifyRebuildFailureExitSix(t *testing.T) {
	err := &restore.ErrRebuildFailed{OperationID: "op", FailedActions: []string{"a"}, Reason: "action failed"}
	if got := classifyExitCode(err); got != ExitRebuildFailed {
		t.Fatalf("classifyExitCode = %d, want 6", got)
	}
	// A cancellation inside the rebuild keeps exit-130 semantics.
	cancelled := &restore.ErrRebuildFailed{OperationID: "op", Reason: "cancelled", Err: context.Canceled}
	if got := classifyExitCode(cancelled); got != ExitCancelled {
		t.Fatalf("classifyExitCode(cancelled rebuild) = %d, want 130", got)
	}
}

// operationsOf lists every operation row of the harness catalog (test
// observation only).
func operationsOf(t *testing.T, c *catalog.Catalog) []catalog.Operation {
	t.Helper()
	ops, err := c.ListOperations("")
	if err != nil {
		t.Fatalf("list operations: %v", err)
	}
	return ops
}

// digestOf is the test's own sha256 over bytes.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestOpenFilesOnlyCompletesDone pins the §17.2 files-only contract
// explicitly: exit 0, no runner needed, operation DONE (nothing
// outstanding), reconstruction reported as skipped.
func TestOpenFilesOnlyCompletesDone(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	withRunner(h, &gRunner{fn: func(actions.Definition) (actions.Result, error) {
		t.Error("files-only must never execute actions")
		return actions.Result{}, errors.New("must not run")
	}})
	h.tty = false

	dest := gDest(t)
	code, _, stderr := h.run("open", "cliws", "--to", dest, "--files-only")
	if code != ExitOK {
		t.Fatalf("files-only code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dest, "generated")); !os.IsNotExist(err) {
		t.Fatalf("files-only must not reconstruct: %v", err)
	}
	for _, op := range operationsOf(t, h.cat()) {
		if op.Kind == catalog.OpKindOpen && op.Phase != catalog.PhaseDone {
			t.Fatalf("files-only open phase = %q, want DONE", op.Phase)
		}
	}
	if !strings.Contains(stderr, "no reconstruction actions ran") {
		t.Errorf("files-only report must say reconstruction was skipped:\n%s", stderr)
	}
}
