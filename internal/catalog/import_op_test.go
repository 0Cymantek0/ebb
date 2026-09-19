package catalog

import (
	"errors"
	"testing"
	"time"

	"ebb/internal/domain"
)

// TestImportOperationWalksPhasesToDone mirrors the export precedent: the
// op begins at the generic PLANNED phase, moves onto the import
// vocabulary before touching anything, walks the CAS happy path to DONE
// and disappears from the active set.
func TestImportOperationWalksPhasesToDone(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "import-done")
	opID, err := c.BeginOperation(ws, OpKindImport, "", "", "")
	if err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}
	steps := [][2]string{
		{PhasePlanned, PhaseImportPlanned},
		{PhaseImportPlanned, PhaseImportCopying},
		{PhaseImportCopying, PhaseImportVerifying},
		{PhaseImportVerifying, PhaseDone},
	}
	for _, s := range steps {
		if err := c.AdvanceOperation(opID, s[0], s[1]); err != nil {
			t.Fatalf("advance %s->%s: %v", s[0], s[1], err)
		}
	}

	op, err := c.GetOperation(opID)
	if err != nil {
		t.Fatalf("GetOperation: %v", err)
	}
	if op.Kind != OpKindImport {
		t.Fatalf("kind: got %s, want %s", op.Kind, OpKindImport)
	}
	if op.Phase != PhaseDone {
		t.Fatalf("phase: got %s, want %s", op.Phase, PhaseDone)
	}
	if op.Generation != int64(len(steps)+1) {
		t.Fatalf("generation: got %d, want %d", op.Generation, len(steps)+1)
	}
	if op.WorkspaceID != ws {
		t.Fatalf("workspace: got %s, want %s", op.WorkspaceID, ws)
	}

	active, err := c.ActiveOperations(ws)
	if err != nil {
		t.Fatalf("ActiveOperations: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("active ops after DONE: got %d, want 0", len(active))
	}
	// Replaying the last step against the terminal row is a conflict.
	if err := c.AdvanceOperation(opID, PhaseImportVerifying, PhaseDone); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale advance after DONE: got %v, want ErrCASConflict", err)
	}
}

// TestImportOperationCancelPath closes a failed import from its last
// durable phase: FailOperation records the error without a transition,
// then one CAS advance moves to CANCELED (exit-130 semantics) and the
// row leaves the active set.
func TestImportOperationCancelPath(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "import-cancel")
	opID, err := c.BeginOperation(ws, OpKindImport, "", "", "")
	if err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}
	for _, s := range [][2]string{
		{PhasePlanned, PhaseImportPlanned},
		{PhaseImportPlanned, PhaseImportCopying},
	} {
		if err := c.AdvanceOperation(opID, s[0], s[1]); err != nil {
			t.Fatalf("advance %s->%s: %v", s[0], s[1], err)
		}
	}
	const failMsg = "destination vault rejected payload"
	if err := c.FailOperation(opID, PhaseImportCopying, failMsg); err != nil {
		t.Fatalf("FailOperation: %v", err)
	}
	op, err := c.GetOperation(opID)
	if err != nil {
		t.Fatalf("GetOperation after fail: %v", err)
	}
	if op.Phase != PhaseImportCopying || op.LastError != failMsg {
		t.Fatalf("FailOperation changed more than last_error: %+v", op)
	}
	if err := c.AdvanceOperation(opID, PhaseImportCopying, PhaseCanceled); err != nil {
		t.Fatalf("advance to CANCELED: %v", err)
	}

	op, err = c.GetOperation(opID)
	if err != nil {
		t.Fatalf("GetOperation after cancel: %v", err)
	}
	if op.Phase != PhaseCanceled {
		t.Fatalf("phase: got %s, want %s", op.Phase, PhaseCanceled)
	}
	if op.Generation != 4 {
		t.Fatalf("generation: got %d, want 4", op.Generation)
	}
	active, err := c.ActiveOperations(ws)
	if err != nil {
		t.Fatalf("ActiveOperations: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("active ops after CANCELED: got %d, want 0", len(active))
	}
}

// TestImportPhaseVocabularyClosed pins the vocabulary edges: the three
// import phases are accepted in both CAS positions, a typo'd phase is
// refused in either position, and BeginOperation rejects a kind outside
// validOpKinds.
func TestImportPhaseVocabularyClosed(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "import-vocab")
	opID, err := c.BeginOperation(ws, OpKindImport, "", "", "")
	if err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}
	for _, p := range []string{PhaseImportPlanned, PhaseImportCopying, PhaseImportVerifying} {
		if !validPhases[p] {
			t.Fatalf("phase %s missing from validPhases", p)
		}
	}
	if !validOpKinds[OpKindImport] {
		t.Fatal("OpKindImport missing from validOpKinds")
	}
	// Accepted in the to-position (from-position acceptance is exercised
	// by every step of the walks above).
	if err := c.AdvanceOperation(opID, PhasePlanned, PhaseImportPlanned); err != nil {
		t.Fatalf("advance PLANNED->IMPORT_PLANNED: %v", err)
	}
	// A typo'd phase is refused in both positions.
	if err := c.AdvanceOperation(opID, "IMPORT_VERIFIED", PhaseImportCopying); err == nil {
		t.Fatal("typo'd from-phase accepted")
	}
	if err := c.AdvanceOperation(opID, PhaseImportPlanned, "IMPORT_VERIFING"); err == nil {
		t.Fatal("typo'd to-phase accepted")
	}
	// FailOperation also validates against the closed vocabulary.
	if err := c.FailOperation(opID, "IMPORT_COPYNG", "x"); err == nil {
		t.Fatal("typo'd FailOperation phase accepted")
	}
	// A kind outside the vocabulary is refused at BeginOperation.
	if _, err := c.BeginOperation(ws, "ingest", "", "", ""); err == nil {
		t.Fatal("invalid operation kind accepted")
	}
}

// TestImportDiscoveredSnapshotNeverOverwritesWitness covers the merge
// contract (Wave J review J4): re-importing a discovered snapshot id is
// COMPARED, never merged. An exact re-import is a benign duplicate (nil
// error, the row and its pin audit completely untouched); a candidate
// claiming different witness-bearing fields (payload/seal backend ids,
// vault, digests, kind) is refused with *ErrWitnessDivergence while the
// existing row — the D017/D020 tamper witness — stays exactly as it was.
func TestImportDiscoveredSnapshotNeverOverwritesWitness(t *testing.T) {
	c := open(t)
	vaultA := domain.VaultID(domain.NewID())
	vaultB := domain.VaultID(domain.NewID())
	if err := c.RegisterVault(Vault{ID: vaultA, Path: `D:\vaults\a`, RepoID: "repo-a"}); err != nil {
		t.Fatalf("RegisterVault A: %v", err)
	}
	if err := c.RegisterVault(Vault{ID: vaultB, Path: `D:\vaults\b`, RepoID: "repo-b"}); err != nil {
		t.Fatalf("RegisterVault B: %v", err)
	}

	wsID := domain.WorkspaceID(domain.NewID())
	const snapID = domain.SnapshotID("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	s := Snapshot{
		ID:               snapID,
		PayloadBackendID: "payload-a",
		SealBackendID:    "seal-a",
		VaultID:          vaultA,
		ManifestDigest:   "manifest-a",
		InventoryDigest:  "inventory-a",
		Kind:             SnapshotKindPark,
		CreatedAt:        domain.FormatTime(time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)),
	}
	if err := c.ImportDiscoveredSnapshot(wsID, "capsule-proj", s); err != nil {
		t.Fatalf("ImportDiscoveredSnapshot: %v", err)
	}
	got, err := c.GetSnapshot(snapID)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if got.VaultID != vaultA || got.PayloadBackendID != "payload-a" || got.SealBackendID != "seal-a" ||
		got.ManifestDigest != "manifest-a" || got.InventoryDigest != "inventory-a" {
		t.Fatalf("initial discovered facts: %+v", got)
	}
	if !got.Pinned || !contains(got.PinReasons, PinReasonCreation) {
		t.Fatalf("initially imported snapshot not pinned: %+v", got)
	}

	// A pin taken between imports must survive every re-import untouched.
	if err := c.Pin(snapID, "audit-hold"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	before, err := c.GetSnapshot(snapID)
	if err != nil {
		t.Fatalf("GetSnapshot after pin: %v", err)
	}

	// Benign duplicate: the exact same discovered facts re-imported
	// (discovery running twice over an intact catalog). No error, and
	// the row is bit-for-bit what it was.
	if err := c.ImportDiscoveredSnapshot(wsID, "capsule-proj", s); err != nil {
		t.Fatalf("benign duplicate re-import refused: %v", err)
	}
	got, err = c.GetSnapshot(snapID)
	if err != nil {
		t.Fatalf("GetSnapshot after benign re-import: %v", err)
	}
	if !sameRow(got, before) {
		t.Fatalf("benign duplicate re-import disturbed the row: before %+v, after %+v", before, got)
	}

	// Divergence: the same logical id discovered with DIFFERENT
	// witness-bearing facts (a minted pair, D023's post-loss threat)
	// must be refused with the row untouched.
	s.VaultID = vaultB
	s.PayloadBackendID = "payload-b"
	s.SealBackendID = "seal-b"
	s.ManifestDigest = "manifest-b"
	s.InventoryDigest = "inventory-b"
	s.Kind = SnapshotKindSnapshot
	err = c.ImportDiscoveredSnapshot(wsID, "capsule-proj", s)
	if err == nil {
		t.Fatal("divergent re-import was accepted — the witness was re-anchorable")
	}
	var div *ErrWitnessDivergence
	if !errors.As(err, &div) {
		t.Fatalf("divergent re-import error is not ErrWitnessDivergence: %v", err)
	}
	wantFields := map[string]bool{
		"payload_backend_id": true, "seal_backend_id": true, "vault_id": true,
		"manifest_digest": true, "inventory_digest": true, "kind": true,
	}
	if len(div.Fields) != len(wantFields) {
		t.Fatalf("divergence fields = %v, want exactly %v", div.Fields, wantFields)
	}
	for _, f := range div.Fields {
		if !wantFields[f] {
			t.Fatalf("unexpected divergence field %q (all: %v)", f, div.Fields)
		}
	}
	if len(div.Reasons()) != len(wantFields) {
		t.Fatalf("reasons = %v, want one per diverging field", div.Reasons())
	}

	// The intact row is EXACTLY what it was — nothing was overwritten.
	got, err = c.GetSnapshot(snapID)
	if err != nil {
		t.Fatalf("GetSnapshot after divergent re-import: %v", err)
	}
	if !sameRow(got, before) {
		t.Fatalf("divergent re-import disturbed the row: before %+v, after %+v", before, got)
	}
	if got.VaultID != vaultA || got.PayloadBackendID != "payload-a" || got.ManifestDigest != "manifest-a" {
		t.Fatalf("witness re-anchored to vault-derived values: %+v", got)
	}

	// The row was never duplicated, and vault membership still follows
	// the untouched row's own vault_id.
	snaps, err := c.ListSnapshots(wsID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("re-import duplicated snapshot: got %d rows", len(snaps))
	}
	forB, err := c.WorkspacesForVault(vaultB)
	if err != nil {
		t.Fatalf("WorkspacesForVault B: %v", err)
	}
	if len(forB) != 0 {
		t.Fatalf("divergent candidate changed vault membership: %v", forB)
	}
}

// sameRow compares two snapshot rows including the pin-audit slice
// (Snapshot embeds a []string, so == is not available).
func sameRow(a, b Snapshot) bool {
	if a.ID != b.ID || a.WorkspaceID != b.WorkspaceID || a.CreatedAt != b.CreatedAt ||
		a.PayloadBackendID != b.PayloadBackendID || a.SealBackendID != b.SealBackendID ||
		a.VaultID != b.VaultID || a.ManifestDigest != b.ManifestDigest ||
		a.InventoryDigest != b.InventoryDigest || a.Kind != b.Kind || a.Pinned != b.Pinned {
		return false
	}
	if len(a.PinReasons) != len(b.PinReasons) {
		return false
	}
	for i := range a.PinReasons {
		if a.PinReasons[i] != b.PinReasons[i] {
			return false
		}
	}
	return true
}
