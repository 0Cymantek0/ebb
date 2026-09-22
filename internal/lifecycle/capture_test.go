package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// TestSnapshotRoundTrip: a plain capture (§12.2 steps 1-5, terminal DONE)
// leaves the source byte-identical (checked by the TEST's own digest
// walk, never the scanner under test), records a pinned P/S pair and a
// terminal operation. The fixture's deep directories exercise the
// directory-shorthand selection path — coverage must still account for
// every captured descendant and readback every preserved file (§11.4).
func TestSnapshotRoundTrip(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	before := digestTree(t, root)

	res, err := h.coord().Snapshot(context.Background(), h.vault, root, snapshotOpts(ws))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	after := digestTree(t, root)
	requireSameTree(t, before, after)

	if res.BackendIDs[0] == "" || res.BackendIDs[1] == "" {
		t.Errorf("expected payload+seal backend ids, got %v", res.BackendIDs)
	}
	c := h.coord()
	snaps, err := c.cat.ListSnapshots(ws)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("ListSnapshots = %d (err %v), want 1", len(snaps), err)
	}
	s := snaps[0]
	if !s.Pinned {
		t.Error("snapshot not pinned (I07)")
	}
	if s.Kind != catalog.SnapshotKindSnapshot {
		t.Errorf("snapshot kind = %q, want %q", s.Kind, catalog.SnapshotKindSnapshot)
	}
	if s.PayloadBackendID != res.BackendIDs[0] || s.SealBackendID != res.BackendIDs[1] {
		t.Errorf("catalog P/S (%s/%s) != result ids (%v)", s.PayloadBackendID, s.SealBackendID, res.BackendIDs)
	}

	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseDone {
		t.Errorf("operation phase = %q, want DONE", got)
	}
	if n := activeCount(t, c, ws); n != 0 {
		t.Errorf("active operations after DONE = %d, want 0", n)
	}
	// Scratch (op dir, seal dir, journal) is cleaned up after completion.
	parent := filepath.Dir(root)
	des, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-") {
			t.Errorf("scratch object %s left behind", d.Name())
		}
	}
}

// TestSnapshotCoverageFailure: a store that lost one tree record (Ls
// hides an entry) fails §11.4 coverage; the payload is retained unsealed
// and pinned (§11.3), the operation is CANCELED, and the local op dir is
// KEPT as the clean manifest copy.
func TestSnapshotCoverageFailure(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	h.store.hideInLs["/ws/node_modules/.pnpm/x@1.0/index.js"] = true

	_, err := h.coord().Snapshot(context.Background(), h.vault, root, snapshotOpts(ws))
	var verr *ErrVerification
	if !errors.As(err, &verr) || verr.Check != "coverage" {
		t.Fatalf("expected ErrVerification{coverage}, got %v", err)
	}
	if !errors.Is(err, errPayloadIncomplete) {
		t.Errorf("error must state the §11.3 retention rule; got %v", err)
	}

	c := h.coord()
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseCanceled {
		t.Errorf("phase = %q, want CANCELED", got)
	}
	snaps, _ := c.cat.ListSnapshots(ws)
	if len(snaps) != 1 {
		t.Fatalf("unsealed payload row not recorded; snapshots = %d", len(snaps))
	}
	s := snaps[0]
	if !s.Pinned || s.SealBackendID != "" {
		t.Errorf("unsealed retention wrong: pinned=%v seal=%q", s.Pinned, s.SealBackendID)
	}
	// Source untouched, op dir kept.
	mustExist(t, filepath.Join(root, "package.json"))
	opDir := filepath.Join(filepath.Dir(root), opDirName(domain.OperationID(opID)))
	mustExist(t, filepath.Join(opDir, manifestName))
}

// TestSnapshotReadbackFailure: a store that returns wrong bytes on dump
// fails §11.4 readback with the same retention contract as coverage.
func TestSnapshotReadbackFailure(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	h.store.corruptDump["/ws/notes.md"] = true

	_, err := h.coord().Snapshot(context.Background(), h.vault, root, snapshotOpts(ws))
	var verr *ErrVerification
	if !errors.As(err, &verr) || verr.Check != "readback" {
		t.Fatalf("expected ErrVerification{readback}, got %v", err)
	}
	if !errors.Is(err, errPayloadIncomplete) {
		t.Errorf("error must state the §11.3 retention rule; got %v", err)
	}
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseCanceled {
		t.Errorf("phase = %q, want CANCELED", got)
	}
	mustExist(t, filepath.Join(root, "notes.md"))
}

// TestBeginOperationActiveBlocksSecond (F37): a workspace with an active
// operation refuses a second one until the first is reconciled. The
// interrupted op is canceled by Recover, then a fresh capture binds the
// same workspace id.
func TestBeginOperationActiveBlocksSecond(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	h.store.failNthSnapshot = 1 // payload capture fails; op stays CAPTURING
	if _, err := h.coord().Snapshot(context.Background(), h.vault, root, snapshotOpts(ws)); err == nil {
		t.Fatal("expected capture failure")
	}
	c := h.coord()
	if n := activeCount(t, c, ws); n != 1 {
		t.Fatalf("active ops = %d, want 1", n)
	}

	_, err := h.coord().Snapshot(context.Background(), h.vault, root, snapshotOpts(ws))
	var inprog *ErrOpInProgress
	if !errors.As(err, &inprog) {
		t.Fatalf("expected ErrOpInProgress, got %v", err)
	}
	if len(inprog.Operations) != 1 {
		t.Errorf("ErrOpInProgress should name the blocking op, got %v", inprog.Operations)
	}

	// Reconcile with Recover (fresh coordinator = new process), then the
	// same workspace accepts a new capture.
	opID := domain.OperationID(inprog.Operations[0])
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("recover: %v", rerr)
	}
	if rep.PhaseAfter != catalog.PhaseCanceled {
		t.Errorf("phase after recover = %q, want CANCELED", rep.PhaseAfter)
	}
	if _, err := h.coord().Snapshot(context.Background(), h.vault, root, snapshotOpts(ws)); err != nil {
		t.Fatalf("fresh capture after cancel: %v", err)
	}
}
