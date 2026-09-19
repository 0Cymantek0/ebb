//go:build security_poc

package catalog

// Wave J adversarial security PoC (catalog merge semantics). Opt-in via
// -tags security_poc; the default suite stays green.

import (
	"strings"
	"testing"

	"ebb/internal/domain"
)

// J4 — ImportDiscoveredSnapshot's ON CONFLICT DO UPDATE silently
// OVERWRITES the witness-bearing fields (payload/seal backend ids,
// manifest/inventory digests, kind) of an EXISTING snapshot row with
// values re-derived from the vault. Those digests are exactly the
// D017/D020 tamper witness (loadSeal binds a retained receipt to the
// catalog row's seal-time digests). On the `ebb init --rebuild-catalog
// --force-rebuild` merge path (rebuild_catalog.go calls this method for
// EVERY discovered pair, counting duplicates but never comparing), a
// vault-password attacker who minted a diverging pair for a known
// logical snapshot id gets the intact catalog's witness swapped for the
// minted pair's values — after which open/verify/forget validate
// against the attacker's digests. No mismatch is reported and nothing
// is marked suspicious; only the duplicates counter moves.
func TestJ4_ForcedMergeReplacesWitnessDigestsOfExistingRow(t *testing.T) {
	c := open(t)
	ws := domain.WorkspaceID(domain.NewID())
	if err := c.EnsureWorkspace(ws, "victim"); err != nil {
		t.Fatal(err)
	}
	snapID := domain.SnapshotID(domain.NewID())
	genuine := Snapshot{
		ID: snapID, WorkspaceID: ws, CreatedAt: "2026-09-01T00:00:00Z",
		PayloadBackendID: "p-genuine-0000000000000000000000000000000000000000000000000000000000",
		SealBackendID:    "s-genuine-0000000000000000000000000000000000000000000000000000000000",
		ManifestDigest:   strings.Repeat("a", 64),
		InventoryDigest:  strings.Repeat("b", 64),
		Kind:             SnapshotKindPark,
	}
	if _, err := c.RecordSnapshot(genuine); err != nil {
		t.Fatal(err)
	}

	// The minted pair the rebuild discovers in the vault: same LOGICAL id,
	// different backend payloads and digests (requires vault-password
	// minting power — D023's accepted post-loss threat; the point is what
	// the MERGE does to the intact catalog's independent witness).
	minted := Snapshot{
		ID: snapID, WorkspaceID: ws, CreatedAt: "2026-09-01T00:00:00Z",
		PayloadBackendID: "p-minted-00000000000000000000000000000000000000000000000000000000000",
		SealBackendID:    "s-minted-00000000000000000000000000000000000000000000000000000000000",
		ManifestDigest:   strings.Repeat("c", 64),
		InventoryDigest:  strings.Repeat("d", 64),
		Kind:             SnapshotKindSnapshot,
	}
	if err := c.ImportDiscoveredSnapshot(ws, "victim", minted); err != nil {
		t.Fatalf("J4 harness: ImportDiscoveredSnapshot refused: %v", err)
	}

	got, err := c.GetSnapshot(snapID)
	if err != nil {
		t.Fatal(err)
	}
	// What the merge honestly preserves: pinned state and the pin audit.
	if !got.Pinned {
		t.Error("J4: merge dropped the pinned flag (a REAL drop the comment promises never happens)")
	}
	if len(got.PinReasons) == 0 || got.PinReasons[0] != PinReasonCreation {
		t.Errorf("J4: pin audit = %v (creation reason lost)", got.PinReasons)
	}
	// The defect: the D017 witness was silently re-anchored.
	if got.ManifestDigest == genuine.ManifestDigest && got.PayloadBackendID == genuine.PayloadBackendID {
		t.Fatal("J4: merge did NOT overwrite the row — the ON CONFLICT shape changed; re-review")
	}
	t.Errorf("J4 CONFIRMED: the forced-merge import replaced the existing row's witness fields — "+
		"payload %s -> %s, manifest digest %s -> %s, kind %s -> %s — with vault-derived values, "+
		"with no mismatch reported and nothing marked suspicious; the catalog's seal-time digests "+
		"(D017/D020's tamper witness for open/verify/forget) now describe the minted pair",
		genuine.PayloadBackendID, got.PayloadBackendID,
		genuine.ManifestDigest[:12]+"…", got.ManifestDigest[:12]+"…",
		genuine.Kind, got.Kind)
}
