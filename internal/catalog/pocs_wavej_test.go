//go:build security_poc

package catalog

// Wave J adversarial security PoC (catalog merge semantics). Opt-in via
// -tags security_poc; the default suite stays green.

import (
	"errors"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// J4 — post-fix contract (wave C/F/G convention: the PoC flips to assert
// the fixed behavior and stays as the regression guard).
// ImportDiscoveredSnapshot's conflict handling COMPARES the
// witness-bearing fields (payload/seal backend ids, vault binding,
// manifest/inventory digests, kind) instead of overwriting them. An
// exact match is a benign duplicate; a divergent candidate returns
// *ErrWitnessDivergence with the existing row — the D017/D020 tamper
// witness — completely untouched, for the caller to surface as a
// suspicious finding. Rebuild-from-catalog-LOSS is unaffected (no row
// exists to conflict).
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
	err := c.ImportDiscoveredSnapshot(ws, "victim", minted)
	if err == nil {
		t.Fatal("J4: the divergent merge was ACCEPTED — the witness is re-anchorable; fix regressed")
	}
	var div *ErrWitnessDivergence
	if !errors.As(err, &div) {
		t.Fatalf("J4: divergent import error is not ErrWitnessDivergence: %v", err)
	}
	for _, want := range []string{"payload_backend_id", "seal_backend_id", "manifest_digest", "inventory_digest", "kind"} {
		found := false
		for _, f := range div.Fields {
			if f == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("J4: divergence report omits field %q (fields: %v)", want, div.Fields)
		}
	}

	got, err := c.GetSnapshot(snapID)
	if err != nil {
		t.Fatal(err)
	}
	// The intact witness survives bit-for-bit: pinned state, pin audit,
	// backend ids, digests and kind all describe the GENUINE pair.
	if !got.Pinned {
		t.Error("J4: merge dropped the pinned flag")
	}
	if len(got.PinReasons) == 0 || got.PinReasons[0] != PinReasonCreation {
		t.Errorf("J4: pin audit = %v (creation reason lost)", got.PinReasons)
	}
	if got.ManifestDigest != genuine.ManifestDigest || got.InventoryDigest != genuine.InventoryDigest {
		t.Errorf("J4: seal-time digests overwritten: got %s/%s, want the genuine %s/%s",
			got.ManifestDigest[:12]+"…", got.InventoryDigest[:12]+"…",
			genuine.ManifestDigest[:12]+"…", genuine.InventoryDigest[:12]+"…")
	}
	if got.PayloadBackendID != genuine.PayloadBackendID || got.SealBackendID != genuine.SealBackendID {
		t.Errorf("J4: backend ids overwritten: got %s/%s, want the genuine pair",
			got.PayloadBackendID, got.SealBackendID)
	}
	if got.Kind != genuine.Kind {
		t.Errorf("J4: kind overwritten: got %s, want %s", got.Kind, genuine.Kind)
	}

	// The benign twin (exact re-import) still passes as a duplicate.
	if err := c.ImportDiscoveredSnapshot(ws, "victim", genuine); err != nil {
		t.Errorf("J4: benign duplicate re-import refused: %v", err)
	}
}
