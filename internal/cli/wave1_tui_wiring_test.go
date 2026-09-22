package cli

// Wave 1 integration wiring tests: the D032 bare-invocation picker on
// `ebb open` (PickWorkspace seam -> tui.Select in production).

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/cli/tui"
)

// TestOpenBarePickerOpensChosenWorkspace drives a bare `ebb open` on a
// terminal-shaped stdin through the picker seam: the picked parked
// workspace opens at its ORIGINAL root (the park op's journaled source
// root — the row itself is unbound). The rebuild then honestly blocks
// (the e-harness has no pnpm), which is exit 6 with files intact.
func TestOpenBarePickerOpensChosenWorkspace(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatalf("park code = %d, stderr = %s", code, stderr)
	}
	h.tty = true
	var gotRows []WorkspaceChoice
	h.deps.PickWorkspace = func(ctx context.Context, title string, rows []WorkspaceChoice, out io.Writer) (int, error) {
		gotRows = rows
		return 0, nil
	}
	code, stdout, stderr := h.run("open")
	if code != ExitRebuildFailed {
		t.Fatalf("bare open code = %d (want %d: rebuild blocked without pnpm), stdout = %s, stderr = %s",
			code, ExitRebuildFailed, stdout, stderr)
	}
	if len(gotRows) != 1 || gotRows[0].Name != "cliws" || gotRows[0].Right != "parked" {
		t.Fatalf("picker rows = %+v", gotRows)
	}
	if !strings.Contains(gotRows[0].Detail, "original:") || !strings.Contains(gotRows[0].Detail, h.wsRoot) {
		t.Fatalf("picker detail lacks the original root: %+v", gotRows[0])
	}
	// Files published at the original root before the rebuild blocked.
	if b, err := os.ReadFile(filepath.Join(h.wsRoot, "notes.md")); err != nil || !strings.Contains(string(b), "private notes") {
		t.Fatalf("notes.md not restored at the original root: %v", err)
	}
}

// TestOpenBarePickerCancelExits130 pins the cancel contract: the picker's
// ErrCanceled maps to exit 130 and nothing is restored.
func TestOpenBarePickerCancelExits130(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatalf("park code = %d, stderr = %s", code, stderr)
	}
	h.tty = true
	h.deps.PickWorkspace = func(ctx context.Context, title string, rows []WorkspaceChoice, out io.Writer) (int, error) {
		return -1, tui.ErrCanceled
	}
	code, _, stderr := h.run("open")
	if code != ExitCancelled {
		t.Fatalf("cancel code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "canceled") {
		t.Errorf("stderr lacks cancel note:\n%s", stderr)
	}
}

// TestOpenBarePickerFailureDegradesBlocked pins the degrade path: a picker
// that cannot run (unsupported terminal) is an honest blocked exit with
// guidance, never a hang or a silent non-interactive open.
func TestOpenBarePickerFailureDegradesBlocked(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatalf("park code = %d, stderr = %s", code, stderr)
	}
	h.tty = true
	h.deps.PickWorkspace = func(ctx context.Context, title string, rows []WorkspaceChoice, out io.Writer) (int, error) {
		return -1, errors.New("no usable terminal")
	}
	code, _, stderr := h.run("open")
	if code != ExitBlocked {
		t.Fatalf("degrade code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "pass a workspace name") {
		t.Errorf("stderr lacks guidance:\n%s", stderr)
	}
}

// TestOpenBareNoParkedWorkspacesBlocked pins the empty-catalog case.
func TestOpenBareNoParkedWorkspacesBlocked(t *testing.T) {
	h := newEHarness(t)
	h.tty = true
	called := false
	h.deps.PickWorkspace = func(ctx context.Context, title string, rows []WorkspaceChoice, out io.Writer) (int, error) {
		called = true
		return 0, nil
	}
	code, _, stderr := h.run("open")
	if code != ExitBlocked {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if called {
		t.Errorf("picker was invoked with no parked workspaces")
	}
	if !strings.Contains(stderr, "no parked workspaces") {
		t.Errorf("stderr lacks honest empty message:\n%s", stderr)
	}
}
