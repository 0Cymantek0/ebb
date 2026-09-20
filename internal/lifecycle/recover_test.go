package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// TestRecoverPayloadCommittedSealsAndStops: a crash during the seal
// capture (hook) leaves the op PAYLOAD_COMMITTED with P recorded. A
// fresh coordinator's Recover re-verifies P from P's own retained
// documents, seals it, commits SEALED — and STOPS: removal is never
// assumed authorized by recovery (§12.4).
func TestRecoverPayloadCommittedSealsAndStops(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	before := digestTree(t, root)

	sealCrashed := false
	h.store.onSnapshot = func(tags map[string]string) error {
		if tags["ebb-kind"] == "seal" && !sealCrashed {
			sealCrashed = true // crash only the first attempt; Recover's retry succeeds
			return errors.New("fault injection: seal capture crashed")
		}
		return nil
	}
	_, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws))
	if err == nil || !strings.Contains(err.Error(), "seal capture failed") {
		t.Fatalf("expected seal capture failure, got %v", err)
	}
	c := h.coord()
	// The op row itself must be PAYLOAD_COMMITTED with P recorded.
	ops, err := c.cat.ActiveOperations(ws)
	if err != nil || len(ops) != 1 {
		t.Fatalf("active ops = %d (err %v), want 1", len(ops), err)
	}
	op := ops[0]
	if op.Phase != catalog.PhasePayloadCommitted {
		t.Fatalf("phase = %q, want PAYLOAD_COMMITTED", op.Phase)
	}
	if op.PayloadSnap == "" {
		t.Fatal("payload backend id not recorded on the op row")
	}

	rep, rerr := h.coord().Recover(context.Background(), h.vault, op.ID)
	if rerr != nil {
		t.Fatalf("recover: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseAfter != catalog.PhaseSealed {
		t.Errorf("phase after recover = %q, want SEALED", rep.PhaseAfter)
	}
	if rep.PhaseBefore != catalog.PhasePayloadCommitted {
		t.Errorf("phase before = %q", rep.PhaseBefore)
	}
	if !strings.Contains(rep.NextAction, "not assumed authorized") {
		t.Errorf("next action should state removal is not assumed authorized: %q", rep.NextAction)
	}
	// Removal did NOT run: source intact, no quarantine.
	requireSameTree(t, before, digestTree(t, root))
	parent := filepath.Dir(root)
	des, _ := os.ReadDir(parent)
	for _, d := range des {
		if strings.HasPrefix(d.Name(), quarantinePrefix) {
			t.Errorf("quarantine created during recovery: %s", d.Name())
		}
	}
	// The seal now exists in the catalog and the snapshot is pinned.
	after, err := c.cat.GetOperation(op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SealSnap == "" {
		t.Error("seal backend id not recorded after recovery seal")
	}
}

// TestRecoverSealedReportsOnly: SEALED is report-only territory. With a
// changed source the report names the mismatch; with a matching source
// the report confirms the match — and in BOTH cases removal never runs.
func TestRecoverSealedReportsOnly(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	// Variant A: source changed after seal → report the mismatch.
	armed, mutated := false, false
	h.store.onSnapshot = func(tags map[string]string) error {
		if tags["ebb-kind"] == "seal" {
			armed = true
		}
		return nil
	}
	h.probe.onRootIdentity = func(p string) (domain.RootIdentity, error, bool) {
		if armed && !mutated && p == root {
			mutated = true
			_ = os.WriteFile(filepath.Join(root, "notes.md"), []byte(fixtureNotes+"late\n"), 0o644)
		}
		return domain.RootIdentity{}, nil, false
	}
	if _, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws)); !errors.As(err, new(*ErrSourceChanged)) {
		t.Fatalf("expected ErrSourceChanged, got %v", err)
	}
	ops, _ := h.coord().cat.ActiveOperations(ws)
	if len(ops) != 1 || ops[0].Phase != catalog.PhaseSealed {
		t.Fatalf("expected one SEALED op, got %+v", ops)
	}
	op := ops[0]

	rep, rerr := h.coord().Recover(context.Background(), h.vault, op.ID)
	if rerr != nil {
		t.Fatalf("recover (changed) should report, not fail: %v", rerr)
	}
	if rep.PhaseAfter != catalog.PhaseSealed {
		t.Errorf("phase changed during SEALED recovery: %q", rep.PhaseAfter)
	}
	if len(rep.Remaining) == 0 || !strings.Contains(rep.Remaining[0], "sealed inventory") {
		t.Errorf("report should name the source mismatch, got %+v", rep.Remaining)
	}
	mustExist(t, filepath.Join(root, "notes.md"))

	// Variant B: the user reverts the change; Recover now revalidates to
	// an exact match — reports it, keeps SEALED, and still never removes.
	_ = os.WriteFile(filepath.Join(root, "notes.md"), []byte(fixtureNotes), 0o644)
	rep2, rerr2 := h.coord().Recover(context.Background(), h.vault, op.ID)
	if rerr2 != nil {
		t.Fatalf("recover (unchanged): %v", rerr2)
	}
	if rep2.PhaseAfter != catalog.PhaseSealed {
		t.Errorf("phase changed during SEALED recovery: %q", rep2.PhaseAfter)
	}
	if len(rep2.Actions) == 0 || !strings.Contains(rep2.Actions[0], "exact match") {
		t.Errorf("report should confirm the exact match, got %+v", rep2.Actions)
	}
	mustExist(t, filepath.Join(root, "notes.md"))
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
}

// TestJournalTornFinalLine: a crash mid-append leaves a torn final line;
// readJournal truncates at the last complete record and lastRemoved is
// correct.
func TestJournalTornFinalLine(t *testing.T) {
	dir := t.TempDir()
	opID := domain.OperationID(domain.NewID())
	path := journalPath(dir, opID)
	good := []byte(`{"time":"t1","step":"begin","detail":"park"}` + "\n" +
		`{"time":"t2","step":"removed","path":"a/b.js","removed":1}` + "\n" +
		`{"time":"t3","step":"removed","path":"a/c.js","removed":2}` + "\n")
	torn := []byte(`{"time":"t4","step":"remo`)
	if err := os.WriteFile(path, append(append([]byte{}, good...), torn...), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := readJournal(dir, opID)
	if err != nil {
		t.Fatalf("readJournal: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("records = %d, want 3 (torn line dropped)", len(recs))
	}
	last, n := lastRemoved(recs)
	if last != "a/c.js" || n != 2 {
		t.Errorf("lastRemoved = %q/%d, want a/c.js/2", last, n)
	}
}

// TestStrictDocumentReparse: every retained document loader rejects
// unknown fields (the manifest.go comment's DisallowUnknownFields
// promise) and trailing data.
func TestStrictDocumentReparse(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		into any
	}{
		{"manifest", `{"schema_version":1,"evil_field":true}`, new(manifestDoc)},
		{"receipt", `{"schema_version":1,"evil":1}`, new(receiptDoc)},
		{"trim-plan", `{"schema_version":1,"evil":[]}`, new(trimPlanDoc)},
		{"inventory-record", `{"root":"main","path":"a","kind":"file","route":"preserve","evil":1}`, new(inventoryRecord)},
	}
	for _, tc := range cases {
		if err := decodeStrictJSON([]byte(tc.doc), tc.into); err == nil {
			t.Errorf("%s: unknown field accepted", tc.name)
		}
	}
	if err := decodeStrictJSON([]byte(`{"schema_version":1} {}`), new(receiptDoc)); err == nil {
		t.Error("trailing data accepted")
	}
	// A well-formed record still parses and round-trips its group token.
	rec := inventoryRecord{Group: "deps"}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var back inventoryRecord
	if err := decodeStrictJSON(b, &back); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	if back.Group != "deps" {
		t.Errorf("group token lost: %+v", back)
	}
}

// ---- dead restore operations (Wave 1 restore review F3) --------------------
//
// RESTORE_FAILED/RESTORE_RUNNING are deliberately non-terminal (rerun-as-
// resume), but nothing could ever close them: Recover was report-only
// with "no lifecycle action required" guidance, and --cancel refused
// restore phases — a restore that can never complete bricked the
// workspace against every destructive operation.

// deadRestoreOpFor opens a restore-kind operation walked to the given
// dead phase, exactly the durable state a crash (RESTORE_RUNNING) or a
// failed execution (RESTORE_FAILED) leaves.
func deadRestoreOpFor(t *testing.T, h *harness, ws domain.WorkspaceID, root, phase string) domain.OperationID {
	t.Helper()
	if err := capsuleCat(t, h).EnsureWorkspace(ws, "dead-restore-ws"); err != nil {
		t.Fatal(err)
	}
	opID, err := capsuleCat(t, h).BeginOperation(ws, catalog.OpKindRestore, root, "", "")
	if err != nil {
		t.Fatal(err)
	}
	steps := map[string][][2]string{
		catalog.PhaseRestoreRunning: {
			{catalog.PhasePlanned, catalog.PhaseRestorePlanning},
			{catalog.PhaseRestorePlanning, catalog.PhaseRestoreRunning},
		},
		catalog.PhaseRestoreFailed: {
			{catalog.PhasePlanned, catalog.PhaseRestorePlanning},
			{catalog.PhaseRestorePlanning, catalog.PhaseRestoreRunning},
			{catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed},
		},
		catalog.PhaseRestoreDone: {
			{catalog.PhasePlanned, catalog.PhaseRestorePlanning},
			{catalog.PhaseRestorePlanning, catalog.PhaseRestoreRunning},
			{catalog.PhaseRestoreRunning, catalog.PhaseRestoreDone},
		},
	}[phase]
	for _, s := range steps {
		if err := capsuleCat(t, h).AdvanceOperation(opID, s[0], s[1]); err != nil {
			t.Fatal(err)
		}
	}
	return opID
}

// TestCancelDeadRestoreClosesAndUnblocksTrim proves the F3 escape hatch
// at the lifecycle seam: a RESTORE_FAILED restore op closes idempotently
// to CANCELED, and a trim of the same workspace then proceeds (before
// F3 the row answered every later destructive op with ErrOpInProgress).
func TestCancelDeadRestoreClosesAndUnblocksTrim(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("f3-ws")
	opID := deadRestoreOpFor(t, h, ws, root, catalog.PhaseRestoreFailed)

	// The bug's shape, pinned first: while the dead row is active, the
	// workspace refuses destructive work.
	blockedOpts := trimOpts(t, ws, "deps")
	blockedOpts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, blockedOpts); err == nil {
		t.Fatal("a dead restore row must block the workspace's destructive operations")
	} else {
		var inProgress *ErrOpInProgress
		if !errors.As(err, &inProgress) {
			t.Fatalf("expected ErrOpInProgress, got %v", err)
		}
	}

	rep, err := h.coord().CancelOperation(context.Background(), h.vault, opID)
	if err != nil {
		t.Fatalf("cancel on RESTORE_FAILED: %v", err)
	}
	if rep.PhaseAfter != catalog.PhaseCanceled {
		t.Fatalf("phase after cancel = %s, want CANCELED", rep.PhaseAfter)
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseCanceled {
		t.Fatalf("durable phase = %s, want CANCELED", got)
	}
	if active, err := capsuleCat(t, h).ActiveOperations(ws); err != nil || len(active) != 0 {
		t.Fatalf("active ops after cancel = %v (%v)", active, err)
	}
	canceled, stays := false, false
	for _, r := range rep.Remaining {
		if strings.Contains(r, "stays in place") {
			canceled = true
		}
		if strings.Contains(r, "pinned") {
			stays = true
		}
	}
	if !canceled || !stays {
		t.Fatalf("cancel report must keep the never-undo / I07 contract: %+v", rep.Remaining)
	}

	// Idempotent rerun: already CANCELED, no refusal.
	rep, err = h.coord().CancelOperation(context.Background(), h.vault, opID)
	if err != nil || rep.PhaseAfter != catalog.PhaseCanceled {
		t.Fatalf("idempotent cancel rerun: %v (report %+v)", err, rep)
	}

	// The unblocked workspace: a real trim now proceeds.
	opts := trimOpts(t, ws, "deps")
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("trim after cancel must proceed: %v", err)
	}
}

// TestCancelRestoreDoneRefusedAndReportOnlyRecover pins F3's boundaries:
// RESTORE_DONE is terminal-uncancelable, plain Recover on a dead restore
// is report-only (naming both the rerun and --cancel), and a kind/phase
// vocabulary mismatch is refused as journal divergence.
func TestCancelRestoreDoneRefusedAndReportOnlyRecover(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("f3-done-ws")

	doneOp := deadRestoreOpFor(t, h, ws, root, catalog.PhaseRestoreDone)
	if _, err := h.coord().CancelOperation(context.Background(), h.vault, doneOp); err == nil {
		t.Fatal("cancel accepted a RESTORE_DONE operation — terminal phases must stay uncancelable")
	} else {
		var jm *ErrJournalMismatch
		if !errors.As(err, &jm) {
			t.Fatalf("restore-done refusal is not ErrJournalMismatch: %v", err)
		}
	}
	if got := h.phaseOf(t, doneOp); got != catalog.PhaseRestoreDone {
		t.Fatalf("refused cancel changed the phase: %s", got)
	}

	deadOp := deadRestoreOpFor(t, h, ws, root, catalog.PhaseRestoreFailed)
	rep, err := h.coord().Recover(context.Background(), h.vault, deadOp)
	if err != nil {
		t.Fatalf("plain recover on a dead restore must report, not fail: %v", err)
	}
	if rep.PhaseAfter != catalog.PhaseRestoreFailed {
		t.Fatalf("plain recover changed the phase: %s", rep.PhaseAfter)
	}
	if !strings.Contains(rep.NextAction, "ebb restore") || !strings.Contains(rep.NextAction, "--cancel") {
		t.Fatalf("next action must name both exits (rerun + cancel): %q", rep.NextAction)
	}

	// A restore phase on a NON-restore kind row is journal divergence,
	// never silently reported or closed.
	parkWS := newWSID()
	if err := capsuleCat(t, h).EnsureWorkspace(parkWS, "mismatch-ws"); err != nil {
		t.Fatal(err)
	}
	mismatchOp, err := capsuleCat(t, h).BeginOperation(parkWS, catalog.OpKindPark, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range [][2]string{
		{catalog.PhasePlanned, catalog.PhaseRestorePlanning},
		{catalog.PhaseRestorePlanning, catalog.PhaseRestoreRunning},
	} {
		if err := capsuleCat(t, h).AdvanceOperation(mismatchOp, s[0], s[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.coord().Recover(context.Background(), h.vault, mismatchOp); err == nil {
		t.Fatal("plain recover accepted a park-kind row in a RESTORE_* phase — vocabulary mismatch must refuse")
	}
}
