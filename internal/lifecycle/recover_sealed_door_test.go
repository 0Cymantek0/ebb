package lifecycle

// Acceptance-gate coverage for the SEALED --resume-removal door (Wave 4
// gauntlet bug B). The door exists because a park whose quarantine
// rename was blocked sits in SEALED (the rename never ran, so no later
// phase committed) while its park-time error advises --resume-removal —
// which until the door refused exactly that phase. The full blocked->
// resume->DONE flow is Windows-only (the repro needs a handle that pins
// the root's rename; see recover_sealed_door_windows_test.go); these
// portable tests pin the gate's refusals, which are pure durable-state
// decisions.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// sealedOpFor crafts a durable SEALED operation row of the given kind
// with the given last_error, exactly the shape a crash after seal (no
// error) or a blocked tail (error recorded, phase never advanced)
// leaves. It never touches the filesystem beyond the catalog.
func sealedOpFor(t *testing.T, h *harness, ws domain.WorkspaceID, root, kind, lastError string) domain.OperationID {
	t.Helper()
	if err := h.coord().cat.EnsureWorkspace(ws, "door-ws"); err != nil {
		t.Fatal(err)
	}
	opID, err := h.coord().cat.BeginOperation(ws, kind, root, "ident", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.coord().cat.AdvanceOperation(opID, catalog.PhasePlanned, catalog.PhaseSealed); err != nil {
		t.Fatal(err)
	}
	if lastError != "" {
		if err := h.coord().cat.FailOperation(opID, catalog.PhaseSealed, lastError); err != nil {
			t.Fatal(err)
		}
	}
	return opID
}

// TestSealedResumeDoorRefusesCrashAfterSeal: a SEALED park with NO
// recorded failure (the plain crash-after-seal state) has no blocked
// removal to resume; the door refuses and keeps the report-only
// discipline (plain Recover + --cancel govern that state).
func TestSealedResumeDoorRefusesCrashAfterSeal(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("door-a")
	opID := sealedOpFor(t, h, ws, root, catalog.OpKindPark, "")

	rep, err := h.coord().ResumeRemoval(context.Background(), h.vault, opID)
	if err == nil {
		t.Fatalf("resume of a crash-after-seal SEALED op must refuse (report %+v)", rep)
	}
	var mismatch *ErrJournalMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected ErrJournalMismatch, got %v", err)
	}
	for _, want := range []string{"no recorded failure", "--cancel"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal text lacks %q (must name the action that works in this state): %v", want, err)
		}
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseSealed {
		t.Errorf("phase changed by the refusal: %s", got)
	}
}

// TestSealedResumeDoorRefusesNonParkKind: a SEALED row of a kind whose
// vocabulary has no park tail is refused by name.
func TestSealedResumeDoorRefusesNonParkKind(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("door-b")
	opID := sealedOpFor(t, h, ws, root, catalog.OpKindTrim, "blocked: simulated")

	_, err := h.coord().ResumeRemoval(context.Background(), h.vault, opID)
	if err == nil {
		t.Fatal("resume of a non-park SEALED op must refuse")
	}
	if !strings.Contains(err.Error(), "applies to a park") {
		t.Errorf("refusal text should name the park restriction: %v", err)
	}
}

// TestSealedResumeDoorRefusesWhenSiblingExists: a SEALED park WITH a
// recorded failure but with the quarantine sibling present is the F5
// crash window (the rename DID commit) — the door refuses and routes to
// plain Recover, which adopts the sibling by native identity.
func TestSealedResumeDoorRefusesWhenSiblingExists(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("door-c")
	opID := sealedOpFor(t, h, ws, root, catalog.OpKindPark,
		"lifecycle: removal blocked at "+root+" (EBB_E_SHARING_VIOLATION)")
	quar := quarantinePath(filepath.Dir(root), opID)
	if err := os.MkdirAll(quar, 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := h.coord().ResumeRemoval(context.Background(), h.vault, opID)
	if err == nil {
		t.Fatal("resume with a quarantine sibling present must refuse (F5 adoption governs)")
	}
	for _, want := range []string{"quarantine sibling", "already renamed the root"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal text lacks %q: %v", want, err)
		}
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseSealed {
		t.Errorf("phase changed by the refusal: %s", got)
	}
	if _, err := os.Lstat(quar); err != nil {
		t.Errorf("the sibling must never be touched by the refusal: %v", err)
	}
}
