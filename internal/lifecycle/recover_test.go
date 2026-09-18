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
