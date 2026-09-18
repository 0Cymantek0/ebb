//go:build security_poc

// Wave F adversarial security PoCs (restore package, in-package so the
// fixture/fakeStore seams are reachable). Opt-in via -tags security_poc
// (Wave C precedent).
//
// F4  Seal-receipt forgery passes: the receipt's manifest/inventory
//
//	digests are checked against the PAYLOAD's bytes and against each
//	other, but NEVER against the digests the CATALOG recorded at seal
//	time (catalog.Snapshot.ManifestDigest/InventoryDigest are
//	write-only). An attacker who can write the vault (knowing the
//	vault password, e.g. a malicious peer of a shared/synced vault)
//	rewrites P and S to a self-consistent pair carrying content the
//	original seal never covered; open() publishes it as "verified".
package restore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"ebb/internal/domain"
)

// TestPoCForgedSealReceiptPublishesUnsealedContent: build a legitimate
// fixture (real scan, correct digests, catalog row), then swap BOTH the
// payload documents and the receipt for attacker-authored, internally
// consistent bytes that inject a file the original capture never
// contained. loadSeal + loadDocuments + the oracle all pass; the catalog
// row's seal-time digests disagree and are never consulted.
func TestPoCForgedSealReceiptPublishesUnsealedContent(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})

	// ---- the attacker's additions ----------------------------------
	injected := "/renderer/pwned.txt"
	injectedData := []byte("content the original seal never covered\n")
	injectedDigest := digestBytes(injectedData)

	// All tampering happens under one short lock; open() below takes the
	// store lock itself (holding it across open would deadlock).
	f.store.mu.Lock()

	// 1) Payload tree gains the injected file.
	f.store.snaps[f.payloadID].files[injected] = injectedData

	// 2) Payload inventory.jsonl gains a consistent preserve entry
	// (re-sorted: restore's parseInventory enforces canonical order).
	opInv := "/" + f.opDirName + "/" + inventoryName
	invBytes := append([]byte(nil), f.store.snaps[f.payloadID].files[opInv]...)
	hostile := domain.Entry{
		Root:        domain.RootMain,
		Path:        "pwned.txt",
		Kind:        domain.KindFile,
		LogicalSize: int64(len(injectedData)),
		Digest:      injectedDigest,
		Ownership:   domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary,
		Route:       domain.RoutePreserve,
	}
	var recs []domain.Entry
	for _, l := range splitLines(invBytes) {
		if l == "" {
			continue
		}
		var r inventoryRecord
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		recs = append(recs, r.Entry)
	}
	recs = append(recs, hostile)
	sort.Slice(recs, func(i, j int) bool { return recs[i].Path < recs[j].Path })
	var rebuilt []byte
	for _, e := range recs {
		line, err := json.Marshal(inventoryRecord{Entry: e})
		if err != nil {
			t.Fatal(err)
		}
		rebuilt = append(rebuilt, append(line, '\n')...)
	}
	invBytes = rebuilt
	f.store.snaps[f.payloadID].files[opInv] = invBytes
	// NOTE: parseInventory (restore's own reader) VALIDATES entries, so
	// the injected record must be a legitimate-looking path — which it
	// is: "pwned.txt" is a perfectly valid root-relative path. The
	// forgery does not need traversal; it needs content the seal never
	// covered.

	// 3) Manifest digest+count patched to the new inventory.
	opMan := "/" + f.opDirName + "/" + manifestName
	manBytes := f.store.snaps[f.payloadID].files[opMan]
	var doc map[string]any
	if err := json.Unmarshal(manBytes, &doc); err != nil {
		t.Fatal(err)
	}
	inv, _ := doc["inventory"].(map[string]any)
	inv["digest"] = digestBytes(invBytes)
	inv["count"] = len(recs)
	nb, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.store.snaps[f.payloadID].files[opMan] = append(nb, '\n')

	// 4) The seal's receipt is rewritten with matching digests.
	newReceipt, err := json.MarshalIndent(receiptDoc{
		SchemaVersion:    schemaVersionCurrent,
		SnapshotID:       string(f.snapID),
		WorkspaceID:      string(f.wsID),
		BackendRepoID:    "fake-repo-id",
		PayloadBackendID: f.payloadID,
		ManifestDigest:   digestBytes(append(nb, '\n')),
		InventoryDigest:  digestBytes(invBytes),
		RequiredFeatures: []string{},
		Verification: receiptVerification{
			Checks: []string{"coverage-complete", "payload-readback-complete"},
			Scope:  "single-owned-root",
			Time:   domain.FormatTime(time.Now()),
			ToolVersions: map[string]string{
				"ebb": "0.1.0-dev", "backend": "restic 0.19.1"},
		},
		OperationID: string(f.opID),
		Retention:   "pinned",
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	sealPath := "/" + sealPrefix + string(f.opID) + "/" + receiptName
	f.store.snaps[f.sealID].files[sealPath] = append(newReceipt, '\n')
	f.store.mu.Unlock()

	// The catalog row still carries the ORIGINAL seal-time digests and
	// disagrees with the forged receipt — nothing reads them.
	snapRow, err := f.cat.GetSnapshot(f.snapID)
	if err != nil {
		t.Fatal(err)
	}
	if snapRow.InventoryDigest == digestBytes(invBytes) {
		t.Fatal("setup error: catalog digest unexpectedly matches the forgery")
	}

	// ---- open() with the forged vault --------------------------------
	dest := filepath.Join(f.parent, "restored")
	res, oerr := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if oerr != nil {
		t.Fatalf("F4 NOT confirmed: open rejected the forged pair: %v", oerr)
	}
	if _, serr := os.Lstat(filepath.Join(dest, "pwned.txt")); serr != nil {
		t.Fatalf("unexpected: injected file was not published (%v); result %+v", serr, res)
	}
	t.Errorf("F4 CONFIRMED: open() published attacker-injected content as a verified restore (phase FILES_READY, %d entries) while the catalog's seal-time inventory digest %s disagreed with the receipt's %s — a one-line cross-check (receipt.ManifestDigest == snap.ManifestDigest && receipt.InventoryDigest == snap.InventoryDigest) would have refused it",
		res.EntriesRestored, snapRow.InventoryDigest, digestBytes(invBytes))
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
