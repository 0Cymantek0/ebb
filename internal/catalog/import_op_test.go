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

// TestImportDiscoveredSnapshotRefreshesVaultAndFacts covers the capsule
// re-import shape (Foundation §15.3): registering the same discovered
// snapshot id into a different destination vault refreshes vault_id and
// the discovered backend facts while the pinned state and the pin audit
// list stay exactly as they were.
func TestImportDiscoveredSnapshotRefreshesVaultAndFacts(t *testing.T) {
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

	// A pin taken between imports must survive the re-import untouched.
	if err := c.Pin(snapID, "audit-hold"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	before, err := c.GetSnapshot(snapID)
	if err != nil {
		t.Fatalf("GetSnapshot after pin: %v", err)
	}

	// Re-import the same id into a different destination vault with
	// refreshed backend ids and digests.
	s.VaultID = vaultB
	s.PayloadBackendID = "payload-b"
	s.SealBackendID = "seal-b"
	s.ManifestDigest = "manifest-b"
	s.InventoryDigest = "inventory-b"
	if err := c.ImportDiscoveredSnapshot(wsID, "capsule-proj", s); err != nil {
		t.Fatalf("re-import: %v", err)
	}

	got, err = c.GetSnapshot(snapID)
	if err != nil {
		t.Fatalf("GetSnapshot after re-import: %v", err)
	}
	if got.VaultID != vaultB {
		t.Fatalf("re-import did not refresh vault_id: got %s, want %s", got.VaultID, vaultB)
	}
	if got.PayloadBackendID != "payload-b" || got.SealBackendID != "seal-b" {
		t.Fatalf("re-import did not refresh backend ids: %+v", got)
	}
	if got.ManifestDigest != "manifest-b" || got.InventoryDigest != "inventory-b" {
		t.Fatalf("re-import did not refresh digests: %+v", got)
	}
	if !got.Pinned {
		t.Fatal("re-import disturbed pinned state")
	}
	if len(got.PinReasons) != len(before.PinReasons) {
		t.Fatalf("re-import changed the pin audit list: before %v, after %v", before.PinReasons, got.PinReasons)
	}
	for i, r := range before.PinReasons {
		if got.PinReasons[i] != r {
			t.Fatalf("re-import changed the pin audit list: before %v, after %v", before.PinReasons, got.PinReasons)
		}
	}

	// The row was refreshed, never duplicated.
	snaps, err := c.ListSnapshots(wsID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("re-import duplicated snapshot: got %d rows", len(snaps))
	}
	// Vault membership follows the refreshed vault_id.
	forA, err := c.WorkspacesForVault(vaultA)
	if err != nil {
		t.Fatalf("WorkspacesForVault A: %v", err)
	}
	if len(forA) != 0 {
		t.Fatalf("stale vault membership for A: %v", forA)
	}
	forB, err := c.WorkspacesForVault(vaultB)
	if err != nil {
		t.Fatalf("WorkspacesForVault B: %v", err)
	}
	if len(forB) != 1 || forB[0] != wsID {
		t.Fatalf("vault membership after refresh: got %v, want [%s]", forB, wsID)
	}
}
