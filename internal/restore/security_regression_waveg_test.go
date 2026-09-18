package restore

// Regression tests for the Wave G security fixes (F4, Wave F review
// finding, lab/security-review/wave-F/FINDINGS.md). Default suite: the
// hardened behavior is continuously protected; the security_poc-tagged
// twin demonstrates the original forgery.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// forgeSelfConsistentPair rewrites P and S into an attacker-authored,
// internally self-consistent pair (exactly what an attacker with vault
// write access can produce): the payload tree gains an injected file,
// the inventory gains a consistent preserve record, the manifest's
// digest+count follow, and the seal receipt is rewritten to match. The
// CATALOG row keeps the original seal-time digests — the witness.
func forgeSelfConsistentPair(t *testing.T, f *fixture) (injectedRel, injectedDigest string) {
	t.Helper()
	injectedRel = "pwned.txt"
	injectedData := []byte("content the original seal never covered\n")
	injectedDigest = digestBytes(injectedData)

	f.store.mu.Lock()
	defer f.store.mu.Unlock()

	// 1) Payload tree gains the injected file.
	f.store.snaps[f.payloadID].files["/"+f.wsPrefix+"/"+injectedRel] = injectedData

	// 2) Inventory gains a consistent preserve record (canonical order:
	// restore's parseInventory enforces it).
	opInv := "/" + f.opDirName + "/" + inventoryName
	invBytes := f.store.snaps[f.payloadID].files[opInv]
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
	recs = append(recs, domain.Entry{
		Root:        domain.RootMain,
		Path:        injectedRel,
		Kind:        domain.KindFile,
		LogicalSize: int64(len(injectedData)),
		Digest:      injectedDigest,
		Ownership:   domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary,
		Route:       domain.RoutePreserve,
	})
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
	return injectedRel, injectedDigest
}

// TestSealDigestCrossCheckRefusesForgedPair (F4, end to end): a forged,
// internally self-consistent P+S pair whose digests disagree with the
// catalog row's seal-time digests must be REFUSED before any staging or
// publishing; nothing from the forgery reaches the destination.
func TestSealDigestCrossCheckRefusesForgedPair(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	injectedRel, _ := forgeSelfConsistentPair(t, f)

	// The catalog row still carries the ORIGINAL seal-time digests.
	snapRow, err := f.cat.GetSnapshot(f.snapID)
	if err != nil {
		t.Fatal(err)
	}
	if snapRow.ManifestDigest == "" || snapRow.InventoryDigest == "" {
		t.Fatal("setup error: fixture catalog row lacks seal-time digests")
	}

	dest := filepath.Join(f.parent, "restored")
	_, oerr := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if oerr == nil {
		t.Fatalf("open accepted the forged pair (catalog digests never consulted?)")
	}
	var sei *ErrSealInvalid
	if !errors.As(oerr, &sei) {
		t.Fatalf("refusal is not a typed ErrSealInvalid: %v", oerr)
	}
	joined := joinStrings(sei.Details)
	if !containsAll(joined, "seal-time", "tampering") {
		t.Fatalf("refusal does not name the witness disagreement: %v", sei.Details)
	}
	// Nothing published: no destination, no staging leftovers, and the
	// injected file exists only inside the (fake) vault, never on disk
	// at the destination.
	if _, serr := os.Lstat(dest); serr == nil {
		t.Fatalf("destination %s was created by the refused open", dest)
	}
	assertNoStageDirs(t, f.parent)
	if _, serr := os.Lstat(filepath.Join(dest, injectedRel)); serr == nil {
		t.Fatalf("injected file %s was published", injectedRel)
	}
	// The catalog row was not modified by the refusal (witness intact).
	after, err := f.cat.GetSnapshot(f.snapID)
	if err != nil {
		t.Fatal(err)
	}
	if after.ManifestDigest != snapRow.ManifestDigest || after.InventoryDigest != snapRow.InventoryDigest {
		t.Fatalf("catalog seal-time digests changed during the refusal: %+v", after)
	}
}

// TestSealDigestCrossCheckRefusesLegacyRow (F4): a catalog row without
// seal-time digests cannot witness anything and must refuse (D017
// posture — the same rule lifecycle applies to retained documents).
func TestSealDigestCrossCheckRefusesLegacyRow(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	// Wipe the row's digests (models a pre-D017 catalog): the discovery
	// import path refreshes digests without touching the pin state.
	if err := f.cat.ImportDiscoveredSnapshot(f.wsID, f.wsPrefix, catalog.Snapshot{
		ID: f.snapID, WorkspaceID: f.wsID,
		PayloadBackendID: f.payloadID, SealBackendID: f.sealID,
		ManifestDigest: "", InventoryDigest: "",
		Kind: catalog.SnapshotKindPark,
	}); err != nil {
		t.Fatalf("blank seal-time digests: %v", err)
	}

	dest := filepath.Join(f.parent, "restored")
	_, oerr := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if oerr == nil {
		t.Fatalf("open accepted a seal with no catalog witness digests")
	}
	var sei *ErrSealInvalid
	if !errors.As(oerr, &sei) {
		t.Fatalf("refusal is not a typed ErrSealInvalid: %v", oerr)
	}
	if !containsAll(joinStrings(sei.Details), "legacy") {
		t.Fatalf("refusal does not name the legacy-row cause: %v", sei.Details)
	}
	if _, serr := os.Lstat(dest); serr == nil {
		t.Fatalf("destination %s was created by the refused open", dest)
	}
	assertNoStageDirs(t, f.parent)
}

// TestSealDigestCrossCheckLegitimateRowStillOpens (F4 guard): the
// cross-check must not refuse a legitimate seal — the fixture's row
// records exactly the receipt's digests and open still round-trips.
func TestSealDigestCrossCheckLegitimateRowStillOpens(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")
	if _, oerr := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true}); oerr != nil {
		t.Fatalf("legitimate seal refused by the digest cross-check: %v", oerr)
	}
	if _, serr := os.Lstat(filepath.Join(dest, "a.txt")); serr != nil {
		t.Fatalf("legitimate open did not publish: %v", serr)
	}
}

func joinStrings(ss []string) string {
	out := ""
	for _, s := range ss {
		out += s + "\n"
	}
	return out
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

// splitLines splits b on newlines (blank lines kept out).
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
