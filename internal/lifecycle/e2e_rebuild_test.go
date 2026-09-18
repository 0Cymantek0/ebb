package lifecycle

// Scenario 5 of the real-restic acceptance suite: park -> open WITH
// rebuild execution (Foundation §12.5 last paragraphs). The manifest
// freezes an EXACT action definition (a tiny Go helper built for the
// test, mirroring the actions run-test pattern), the REAL actions.Runner
// executes it as a real subprocess at the final destination through the
// real restic vault, the F36 protected-file gate passes, the operation
// reaches DONE, and the attempt is journaled in action_runs. A
// failing-action variant pins the failure posture: REBUILD_FAILED,
// files intact, snapshot pinned (the CLI maps the typed error to exit 6
// — asserted in the cli suite; this package cannot import internal/cli).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"ebb/internal/actions"
	"ebb/internal/actions/approvalstore"
	"ebb/internal/catalog"
	"ebb/internal/platform"
	"ebb/internal/policy"
	"ebb/internal/restore"
)

// e2eRebuildHelperSource is the single-file source of the e2e action
// helper (kept in its own tiny module so the build cannot depend on this
// repository's module graph). Modes:
//
//	emit <path> <text>   create parent dirs, write text
//	fail                 exit with code 7
const e2eRebuildHelperSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: helper <mode> [args...]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "emit":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "emit wants path and text")
			os.Exit(1)
		}
		if err := os.MkdirAll(filepath.Dir(os.Args[2]), 0o755); err != nil {
			fail(err)
		}
		if err := os.WriteFile(os.Args[2], []byte(os.Args[3]), 0o644); err != nil {
			fail(err)
		}
	case "fail":
		os.Exit(7)
	default:
		fail(fmt.Errorf("unknown mode %q", os.Args[1]))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "helper:", err)
	os.Exit(1)
}
`

var (
	e2eHelperOnce sync.Once
	e2eHelperPath string
	e2eHelperErr  error
)

// e2eRebuildHelper compiles the tiny action helper once per test binary
// (real compiled binary, never a shell — shell detection never fires).
func e2eRebuildHelper(t *testing.T) string {
	t.Helper()
	e2eHelperOnce.Do(func() {
		dir := t.TempDir()
		src := filepath.Join(dir, "src")
		if err := os.MkdirAll(src, 0o755); err != nil {
			e2eHelperErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(e2eRebuildHelperSource), 0o644); err != nil {
			e2eHelperErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module ebb-e2e-rebuild-helper\n\ngo 1.27\n"), 0o644); err != nil {
			e2eHelperErr = err
			return
		}
		exe := filepath.Join(dir, "helper")
		if runtime.GOOS == "windows" {
			exe += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", exe, ".")
		cmd.Dir = src
		if out, err := cmd.CombinedOutput(); err != nil {
			e2eHelperErr = fmt.Errorf("go build helper: %w\n%s", err, out)
			return
		}
		e2eHelperPath = exe
	})
	if e2eHelperErr != nil {
		t.Fatalf("build e2e helper: %v", e2eHelperErr)
	}
	return e2eHelperPath
}

// e2eRebuildOpener wires a rebuild-capable opener over the real restic
// store: the REAL actions.Runner, a REAL approvalstore document, and the
// auto-recording approval resolver (the --yes shape: record every
// pending approval exactly as pinned — the drift matrix is covered by
// the cli/restore suites).
func (e *e2eEnv) e2eRebuildOpener(approveDir string) *restore.Opener {
	e.t.Helper()
	store := approvalstore.New(filepath.Join(approveDir, "approvals.json"))
	resolver := func(ctx context.Context, pending []restore.PendingApproval) error {
		for _, p := range pending {
			if _, err := store.Approve(p.Def, p.Tool, p.InputDigests, "e2e-acceptance"); err != nil {
				return err
			}
		}
		return nil
	}
	o, err := restore.New(restore.Dependencies{
		Store: e.store, Cat: e.newCat(), Probe: platform.New(),
		CreateLink: platform.CreateLink,
		Runner:     actions.New(), Approver: store, Approve: resolver,
	})
	if err != nil {
		e.t.Fatalf("new rebuild opener: %v", err)
	}
	return o
}

// e2eBuildRebuildWorkspace creates the rebuild fixture: a custom-command
// regenerate group whose recorded definition is the tiny helper. mode
// "emit" makes the action succeed; "fail" makes it exit 7.
func (e *e2eEnv) e2eBuildRebuildWorkspace(t *testing.T, helper, mode string) (string, policy.Policy, actions.Definition) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "ws-rebuild")
	argv := []string{helper, "emit", "gen/built.txt", "rebuilt by the e2e action"}
	if mode == "fail" {
		argv = []string{helper, "fail"}
	}
	quoted := make([]string, 0, len(argv))
	for _, a := range argv {
		quoted = append(quoted, fmt.Sprintf("%q", a))
	}
	polTOML := fmt.Sprintf(`
version = 1

[workspace]
name = "e2e-rebuild"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "gen"
adapter = "custom"
root = "."
outputs = ["gen"]
inputs = ["package.json"]
network = "allowed"
command = [%s]
`, strings.Join(quoted, ", "))
	e2eWriteFile(t, filepath.Join(root, "Ebbfile.toml"), []byte(polTOML))
	e2eWriteFile(t, filepath.Join(root, "package.json"), []byte(`{"name":"e2e-rebuild"}`+"\n"))
	e2eWriteFile(t, filepath.Join(root, "notes.md"), []byte("notes that must survive the rebuild\n"))
	e2eWriteFile(t, filepath.Join(root, "gen", "old.js"), []byte("// generated content omitted at capture\n"))

	pol, err := policy.Parse([]byte(polTOML))
	if err != nil {
		t.Fatalf("parse Ebbfile: %v", err)
	}
	def := actions.Definition{
		ID:          "gen",
		Argv:        argv,
		WorkingRoot: ".",
		Inputs:      []string{"package.json"},
		Outputs:     []string{"gen"},
		Network:     actions.NetworkAllowed,
		Timeout:     time.Minute,
	}
	if err := def.Validate(); err != nil {
		t.Fatalf("e2e definition: %v", err)
	}
	return root, pol, def
}

// TestE2EResticParkOpenRebuild is the rebuild-execution acceptance.
func TestE2EResticParkOpenRebuild(t *testing.T) {
	e := newE2EEnv(t)
	helper := e2eRebuildHelper(t)

	t.Run("rebuild executes at the final destination and completes DONE", func(t *testing.T) {
		root, pol, def := e.e2eBuildRebuildWorkspace(t, helper, "emit")
		ws := newWSID()
		ctx, cancel := e.opCtx()
		defer cancel()
		res, err := e.coord(nil).Park(ctx, e.vault, root, CaptureOptions{
			WorkspaceName:   "e2e-rebuild",
			WorkspaceID:     ws,
			Policy:          pol,
			Park:            true,
			WriterAssertion: "e2e-acceptance: writers asserted stopped",
			ActionDefs:      []actions.Definition{def},
		})
		if err != nil {
			t.Fatalf("park with action defs: %v", err)
		}
		mustLstatErrNotExist(t, root)

		destParent := t.TempDir()
		dest := filepath.Join(destParent, "ws-rebuild-restored")
		ores, oerr := e.e2eRebuildOpener(destParent).Open(ctx, e.rvault(), res.Snapshot.SnapshotID,
			restore.Options{Destination: dest})
		if oerr != nil {
			t.Fatalf("open with rebuild through the real backend: %v", oerr)
		}
		// The real subprocess wrote the declared output at the FINAL path.
		if b, rerr := os.ReadFile(filepath.Join(dest, "gen", "built.txt")); rerr != nil || string(b) != "rebuilt by the e2e action" {
			t.Fatalf("rebuild output wrong: %q (%v)", b, rerr)
		}
		// Protected preserved file intact (F36 passed).
		if b, rerr := os.ReadFile(filepath.Join(dest, "notes.md")); rerr != nil || string(b) != "notes that must survive the rebuild\n" {
			t.Fatalf("protected file damaged: %q (%v)", b, rerr)
		}
		if ores.Phase != catalog.PhaseDone {
			t.Fatalf("open phase = %q, want DONE", ores.Phase)
		}
		op, gerr := e.newCat().GetOperation(ores.OperationID)
		if gerr != nil || op.Phase != catalog.PhaseDone {
			t.Fatalf("open op phase: %v %q, want DONE", gerr, op.Phase)
		}
		runs, rerr := e.newCat().ListActionRuns(ores.OperationID)
		if rerr != nil || len(runs) != 1 || runs[0].Status != catalog.ActionRunSucceeded || runs[0].ActionID != "gen" {
			t.Fatalf("action runs = %+v (%v)", runs, rerr)
		}
		if snap, serr := e.newCat().GetSnapshot(res.Snapshot.SnapshotID); serr != nil || !snap.Pinned {
			t.Fatalf("snapshot must stay pinned after the rebuild (I07): %+v (%v)", snap, serr)
		}
		e2eNoScratch(t, destParent, "rebuild destination parent")
	})

	t.Run("failing action lands REBUILD_FAILED with files intact", func(t *testing.T) {
		root, pol, def := e.e2eBuildRebuildWorkspace(t, helper, "fail")
		ws := newWSID()
		ctx, cancel := e.opCtx()
		defer cancel()
		res, err := e.coord(nil).Park(ctx, e.vault, root, CaptureOptions{
			WorkspaceName:   "e2e-rebuild",
			WorkspaceID:     ws,
			Policy:          pol,
			Park:            true,
			WriterAssertion: "e2e-acceptance: writers asserted stopped",
			ActionDefs:      []actions.Definition{def},
		})
		if err != nil {
			t.Fatalf("park: %v", err)
		}

		destParent := t.TempDir()
		dest := filepath.Join(destParent, "ws-rebuild-failed")
		_, oerr := e.e2eRebuildOpener(destParent).Open(ctx, e.rvault(), res.Snapshot.SnapshotID,
			restore.Options{Destination: dest})
		var rb *restore.ErrRebuildFailed
		if !errors.As(oerr, &rb) {
			t.Fatalf("open err = %v, want *restore.ErrRebuildFailed (the cli maps it to exit 6)", oerr)
		}
		if len(rb.FailedActions) != 1 || rb.FailedActions[0] != "gen" {
			t.Fatalf("failed actions = %v, want [gen]", rb.FailedActions)
		}
		// Files intact: the recovered preserved set stays published, the
		// failed group's output does not exist, the snapshot stays pinned.
		if b, rerr := os.ReadFile(filepath.Join(dest, "notes.md")); rerr != nil || string(b) != "notes that must survive the rebuild\n" {
			t.Fatalf("recovered files not intact after the failed rebuild: %q (%v)", b, rerr)
		}
		if _, serr := os.Lstat(filepath.Join(dest, "gen")); !os.IsNotExist(serr) {
			t.Errorf("the failing action must not have produced its output: %v", serr)
		}
		cat := e.newCat()
		active, aerr := cat.ActiveOperations(ws)
		if aerr != nil || len(active) != 1 || active[0].Phase != catalog.PhaseRebuildFailed {
			t.Fatalf("active ops after failure = %+v (%v), want one REBUILD_FAILED", active, aerr)
		}
		runs, rerr := cat.ListActionRuns(active[0].ID)
		if rerr != nil || len(runs) != 1 || runs[0].Status != catalog.ActionRunFailed || runs[0].ExitCode != 7 {
			t.Fatalf("failed attempt must be journaled: %+v (%v)", runs, rerr)
		}
		if snap, serr := cat.GetSnapshot(res.Snapshot.SnapshotID); serr != nil || !snap.Pinned {
			t.Fatalf("snapshot must stay pinned after the failed rebuild: %+v (%v)", snap, serr)
		}
	})
}
