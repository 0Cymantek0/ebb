//go:build windows

package lifecycle

// The SEALED-blocked recovery door, end to end on Windows (Wave 4
// gauntlet bug B). The fault injection is the REAL bug-A mechanism, not
// a synthetic hook: the test process's own working directory is moved
// INTO the workspace root, and a process cwd is an open handle without
// FILE_SHARE_DELETE — the exact pin the gauntlet measured
// (20260921T194516Z, EBB_E_SHARING_VIOLATION on the §12.2 step-7
// rename). The park must fail blocked while staying SEALED (the rename
// never ran, so no later phase exists), and — after the holder is
// released (the cwd moves out, the user's remedy) — the door
// (`--resume-removal`) must revalidate and complete to DONE, where
// plain Recover stays report-only.
//
// HAZARD: this test changes the PROCESS working directory; it saves and
// restores it and must never run in parallel.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
)

func TestSealedQuarantineBlockedByCwdThenResumeDoor(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	saved, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Bug A's pin: the process cwd sits on the root itself.
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir into the workspace root: %v", err)
	}
	defer func() {
		if err := os.Chdir(saved); err != nil {
			t.Fatalf("restore cwd %s: %v", saved, err)
		}
	}()

	_, err = h.coord().Park(context.Background(), h.vault, root, parkOpts(ws))
	if err == nil {
		t.Fatal("park unexpectedly succeeded despite the cwd pinning the root")
	}
	var blocked *ErrRemovalBlocked
	if !errors.As(err, &blocked) || blocked.Code != BlockSharingViolation {
		t.Fatalf("expected a sharing-violation removal block, got %v", err)
	}
	if blocked.OperationID == "" {
		t.Fatal("the blocker must carry the operation id (the CLI renders the runnable recovery command)")
	}
	if !strings.Contains(err.Error(), "working directory is inside the workspace") {
		t.Errorf("the blocker must name the cwd holder explicitly:\n%v", err)
	}

	// The durable state: still SEALED (the rename never ran), the tail
	// attempt recorded in last_error, the root intact, no sibling.
	ops, _ := h.coord().cat.ActiveOperations(ws)
	if len(ops) != 1 || ops[0].Phase != catalog.PhaseSealed {
		t.Fatalf("expected one SEALED op after the blocked rename, got %+v", ops)
	}
	opID := ops[0].ID
	if ops[0].LastError == "" {
		t.Fatal("the blocked tail must be recorded in last_error (the door's durable evidence)")
	}
	mustExist(t, root)
	if _, qerr := os.Lstat(quarantinePath(filepath.Dir(root), opID)); !os.IsNotExist(qerr) {
		t.Fatalf("no quarantine sibling may exist (the rename never ran): %v", qerr)
	}

	// The user releases the holder (cd out), then asks for the report
	// first: plain Recover is REPORT-ONLY here and names the door.
	if err := os.Chdir(h.base); err != nil {
		t.Fatalf("chdir out of the workspace: %v", err)
	}
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("plain recover of SEALED must report, not fail: %v", rerr)
	}
	if rep.PhaseAfter != catalog.PhaseSealed {
		t.Fatalf("plain recover changed the phase: %s", rep.PhaseAfter)
	}
	mustExist(t, root)
	if !strings.Contains(rep.NextAction, "--resume-removal") {
		t.Errorf("the report's next action must name the working door: %q", rep.NextAction)
	}

	// The door: revalidate (§12.4 do-not-assume) then quarantine+remove.
	rep, rerr = h.coord().ResumeRemoval(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("resume through the SEALED door: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseBefore != catalog.PhaseSealed || rep.PhaseAfter != catalog.PhaseDone {
		t.Fatalf("phases %s -> %s, want SEALED -> DONE", rep.PhaseBefore, rep.PhaseAfter)
	}
	mustLstatErrNotExist(t, root)
	if got := h.phaseOf(t, opID); got != catalog.PhaseDone {
		t.Errorf("durable phase after resume = %s, want DONE", got)
	}
	if w, werr := h.coord().cat.GetWorkspace(ws); werr != nil || w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace after resume = %+v (%v), want parked", w, werr)
	}
	// The retained pair stays pinned (I07): snapshots recorded for the ws.
	snaps, serr := h.coord().cat.ListSnapshots(ws)
	if serr != nil || len(snaps) == 0 {
		t.Errorf("retained snapshots after resume: %+v (%v)", snaps, serr)
	}
}

// TestSealedQuarantineBlockedDoorRefusesChangedSource: the door's
// revalidation gate. A blocked-tail SEALED op whose source changed
// after the seal must FAIL CLOSED through the door — ErrSourceChanged,
// phase still SEALED, root intact — and the report must advise the
// cancel+recapture route, never a retry of the resume.
func TestSealedQuarantineBlockedDoorRefusesChangedSource(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	saved, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir into the workspace root: %v", err)
	}
	defer func() {
		if err := os.Chdir(saved); err != nil {
			t.Fatalf("restore cwd %s: %v", saved, err)
		}
	}()

	if _, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws)); !errors.As(err, new(*ErrRemovalBlocked)) {
		t.Fatalf("expected the blocked park, got %v", err)
	}
	ops, _ := h.coord().cat.ActiveOperations(ws)
	if len(ops) != 1 || ops[0].Phase != catalog.PhaseSealed {
		t.Fatalf("expected one SEALED op, got %+v", ops)
	}
	opID := ops[0].ID

	// Release the pin, then change the source: the door must revalidate
	// and refuse — deletion is NOT assumed to remain authorized.
	if err := os.Chdir(h.base); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(root, "notes.md")
	if err := os.WriteFile(notes, []byte(fixtureNotes+"changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, rerr := h.coord().ResumeRemoval(context.Background(), h.vault, opID)
	if !errors.As(rerr, new(*ErrSourceChanged)) {
		t.Fatalf("expected ErrSourceChanged through the door, got %v (report %+v)", rerr, rep)
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseSealed {
		t.Errorf("phase after the refused resume = %s, want SEALED", got)
	}
	mustExist(t, notes)
	if !strings.Contains(rep.NextAction, "--cancel") || strings.Contains(rep.NextAction, "ResumeRemoval") {
		t.Errorf("next action must route to cancel+recapture, not a resume retry: %q", rep.NextAction)
	}
}
