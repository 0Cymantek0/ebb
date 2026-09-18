package actions_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/actions"
	"ebb/internal/actions/approvalstore"
)

// These tests wire the Runner to the real JSON FileApprover store to
// prove the approval lifecycle end to end: nothing runs unapproved, an
// approval unblocks exactly the pinned resolution, and a changed input
// file blocks the next run.

func TestRunnerWithFileApproverLifecycle(t *testing.T) {
	ws := t.TempDir()
	writeFileT(t, filepath.Join(ws, "in.txt"), "input v1")
	def := actions.Definition{
		ID:      "emit-action",
		Argv:    []string{helperExe, "emit", "out/stamp.txt", "written"},
		Inputs:  []string{"in.txt"},
		Outputs: []string{"out/stamp.txt"},
		Network: actions.NetworkNone,
		Timeout: 30 * time.Second,
	}
	store := approvalstore.New(filepath.Join(t.TempDir(), "approvals.json"))
	runner := actions.New()

	// 1. No approval recorded: refusal, no execution, no auto-approval.
	_, err := runner.Run(context.Background(), def, ws, store, nil)
	var req *actions.ErrApprovalRequired
	if !errors.As(err, &req) {
		t.Fatalf("expected *ErrApprovalRequired, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "out")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("unapproved action executed")
	}
	list, err := store.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("run must not record approvals itself: %v %v", list, err)
	}

	// 2. Explicit local approval unblocks the run.
	tool, err := actions.ResolveTool(def.Argv[0])
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{"in.txt": mustDigest(t, filepath.Join(ws, "in.txt"))}
	if _, err := store.Approve(def, tool, digests, "alice"); err != nil {
		t.Fatal(err)
	}
	res, err := runner.Run(context.Background(), def, ws, store, nil)
	if err != nil {
		t.Fatalf("approved run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, excerpt %q", res.ExitCode, res.OutputExcerpt)
	}

	// 3. A changed input file blocks the next run: the approval pinned
	// the old digest (Foundation §7.3 input pinning).
	writeFileT(t, filepath.Join(ws, "in.txt"), "input v2 -- tampered")
	_, err = runner.Run(context.Background(), def, ws, store, nil)
	var stale *actions.ErrApprovalStale
	if !errors.As(err, &stale) {
		t.Fatalf("expected *ErrApprovalStale after input change, got: %v", err)
	}
	found := false
	for _, line := range stale.Diff {
		if strings.Contains(line, `input "in.txt"`) && strings.Contains(line, "digest changed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale diff must name the changed input, got: %v", stale.Diff)
	}
}

func TestRunnerWithFileApproverToolSwapBlocked(t *testing.T) {
	ws := t.TempDir()
	writeFileT(t, filepath.Join(ws, "in.txt"), "input v1")
	def := actions.Definition{
		ID:      "emit-action",
		Argv:    []string{helperExe, "emit", "out/stamp.txt", "written"},
		Inputs:  []string{"in.txt"},
		Outputs: []string{"out/stamp.txt"},
		Network: actions.NetworkNone,
		Timeout: 30 * time.Second,
	}
	store := approvalstore.New(filepath.Join(t.TempDir(), "approvals.json"))

	// Approve while argv[0] points at the helper...
	tool, err := actions.ResolveTool(def.Argv[0])
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{"in.txt": mustDigest(t, filepath.Join(ws, "in.txt"))}
	if _, err := store.Approve(def, tool, digests, "alice"); err != nil {
		t.Fatal(err)
	}

	// ...then swap the definition to a different tool with the same
	// inputs. The approval is stale on argv digest and tool identity.
	def.Argv = []string{"git", "--version"}
	def.Outputs = []string{"out/stamp.txt"}
	_, err = actions.New().Run(context.Background(), def, ws, store, nil)
	var stale *actions.ErrApprovalStale
	if !errors.As(err, &stale) {
		t.Fatalf("expected *ErrApprovalStale after tool swap, got: %v", err)
	}
	var sawArgv, sawTool bool
	for _, line := range stale.Diff {
		if strings.Contains(line, "argv digest") {
			sawArgv = true
		}
		if strings.Contains(line, "tool path") || strings.Contains(line, "tool sha256") {
			sawTool = true
		}
	}
	if !sawArgv || !sawTool {
		t.Fatalf("diff must name argv and tool drift, got: %v", stale.Diff)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "out")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("stale action executed")
	}
}

func mustDigest(t *testing.T, path string) string {
	t.Helper()
	d, err := actions.DigestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
