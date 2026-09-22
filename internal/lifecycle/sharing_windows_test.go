//go:build windows

package lifecycle

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"golang.org/x/sys/windows"
)

// TestSharingViolationBlockedThenResumeRemoval: the Windows handle-block
// contract (Foundation §12.3). The test process itself holds a handle
// WITHOUT FILE_SHARE_DELETE on a file inside the quarantine (opened via
// native CreateFile at the exact walk point — Go's os.Open always shares
// delete, which is why a real park can still remove around Go handles).
// The walk must block with BlockSharingViolation, stay REMOVAL_BLOCKED,
// retain everything — and after the handle closes, ResumeRemoval on a
// FRESH coordinator completes the park. Never schedule-on-reboot, never
// kill.
func TestSharingViolationBlockedThenResumeRemoval(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	var held windows.Handle
	haveHandle := false
	h.probe.onProbeFile = func(path string) {
		// Arm only inside the quarantine: during capture/revalidation the
		// same relative path is probed in the LIVE root, where an open
		// handle would block the quarantine rename itself.
		if haveHandle || !strings.Contains(filepath.ToSlash(path), quarantinePrefix) {
			return
		}
		if !strings.HasSuffix(filepath.ToSlash(path), "vendor/dist/gen.js") {
			return
		}
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return
		}
		hh, err := windows.CreateFile(p, windows.GENERIC_READ,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, // deliberately NO FILE_SHARE_DELETE
			nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Logf("CreateFile for the violation fixture failed: %v", err)
			return
		}
		held, haveHandle = hh, true
	}

	_, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws))
	if err == nil {
		t.Fatal("park unexpectedly succeeded despite the held handle")
	}
	var blocked *ErrRemovalBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("expected ErrRemovalBlocked, got %v", err)
	}
	if blocked.Code != BlockSharingViolation {
		t.Fatalf("expected block code %s, got %s (%v)", BlockSharingViolation, blocked.Code, err)
	}
	if !haveHandle {
		t.Fatal("violation fixture was never armed (probe hook missed)")
	}
	ops, _ := h.coord().cat.ActiveOperations(ws)
	if len(ops) != 1 || ops[0].Phase != catalog.PhaseRemovalBlocked {
		t.Fatalf("expected one REMOVAL_BLOCKED op, got %+v", ops)
	}
	op := ops[0]

	// The user resolves the blocker (closes the handle), then explicitly
	// resumes on a fresh coordinator.
	if err := windows.CloseHandle(held); err != nil {
		t.Fatalf("CloseHandle: %v", err)
	}
	rep, rerr := h.coord().ResumeRemoval(context.Background(), h.vault, op.ID)
	if rerr != nil {
		t.Fatalf("ResumeRemoval: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseAfter != catalog.PhaseDone {
		t.Errorf("phase after resume = %q, want DONE", rep.PhaseAfter)
	}
	mustLstatErrNotExist(t, root)
	if w, err := h.coord().cat.GetWorkspace(ws); err != nil || w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace not parked after resumed removal: %+v err=%v", w, err)
	}
}

// compile-time: the report's removal-blocked path stays reachable on this
// build (guard against accidental dead-code elimination in refactors).
var _ = domain.KindFile
