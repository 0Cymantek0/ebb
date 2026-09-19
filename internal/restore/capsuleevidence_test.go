package restore

// Tests for LoadCapsuleEvidence — the §15.3 capsule-import evidence
// loader: verify and load a payload's retained evidence with NO
// lifecycle seal receipt and NO catalog row. The only inputs are the
// payload's backend id and the two digests a capsule's embedded
// destination seal declares; everything else must be re-derived from
// the payload's own bytes (I12 — never trust a claimed digest). Every
// fault case asserts the TYPED error (*ErrVerification with concrete
// detail lines), not just a non-nil error. Fixtures are written with
// exact-byte writers (writeFile), never heredocs (Wave G lesson), and
// shape cases match exact path ELEMENTS, never loose suffixes.

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// asDocVerification asserts err is a *ErrVerification with Check
// "documents" and returns it for detail inspection.
func asDocVerification(t *testing.T, err error) *ErrVerification {
	t.Helper()
	var ve *ErrVerification
	if !errors.As(err, &ve) {
		t.Fatalf("error %v (%T) is not *ErrVerification", err, err)
	}
	if ve.Check != "documents" {
		t.Fatalf("ErrVerification.Check = %q, want %q", ve.Check, "documents")
	}
	if len(ve.Details) == 0 {
		t.Fatal("ErrVerification carries no detail lines")
	}
	return ve
}

// Happy path over the real fixture payload: identities come from the
// payload's own manifest, the retained set and preserved counts are
// re-derived from the accounting document, the tree prefixes match the
// frozen manifest, and Receipt is the ZERO value (no lifecycle receipt
// exists on this path — callers must not cite one).
func TestLoadCapsuleEvidenceHappyPath(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	ev, err := LoadCapsuleEvidence(context.Background(), f.store, f.vault,
		f.payloadID, f.manifestDigest, f.inventoryDigest)
	if err != nil {
		t.Fatalf("LoadCapsuleEvidence: %v", err)
	}

	if ev.SnapshotID != f.snapID {
		t.Fatalf("SnapshotID = %s, want the manifest's %s", ev.SnapshotID, f.snapID)
	}
	if ev.WorkspaceID != f.wsID {
		t.Fatalf("WorkspaceID = %s, want the manifest's %s", ev.WorkspaceID, f.wsID)
	}
	if !reflect.DeepEqual(ev.Receipt, ReceiptFacts{}) {
		t.Fatalf("Receipt = %+v, want the zero value (no lifecycle receipt on the capsule path)", ev.Receipt)
	}

	// Manifest facts: digests are the ones re-computed over the dumped
	// bytes; the kind is derived from the frozen contract (the fixture
	// freezes stopped-writers-asserted → park).
	if ev.Manifest.ManifestDigest != f.manifestDigest {
		t.Fatalf("Manifest.ManifestDigest = %s, want %s", ev.Manifest.ManifestDigest, f.manifestDigest)
	}
	if ev.Manifest.InventoryDigest != f.inventoryDigest {
		t.Fatalf("Manifest.InventoryDigest = %s, want %s", ev.Manifest.InventoryDigest, f.inventoryDigest)
	}
	if ev.Manifest.Kind != catalog.SnapshotKindPark {
		t.Fatalf("Manifest.Kind = %q, want %q", ev.Manifest.Kind, catalog.SnapshotKindPark)
	}
	if ev.Manifest.InventoryPath != inventoryName {
		t.Fatalf("Manifest.InventoryPath = %q, want %q", ev.Manifest.InventoryPath, inventoryName)
	}
	if ev.Manifest.InventoryCount != int64(len(f.entries)) {
		t.Fatalf("Manifest.InventoryCount = %d, want %d", ev.Manifest.InventoryCount, len(f.entries))
	}
	if ev.Manifest.ManifestBytes != int64(len(f.manifestBytes)) {
		t.Fatalf("Manifest.ManifestBytes = %d, want %d", ev.Manifest.ManifestBytes, len(f.manifestBytes))
	}

	// Retained set: the fixture scans every entry as preserve, so the
	// re-derived set must equal the fixture's scan element-for-element
	// (canonical order on both sides).
	var want []domain.Entry
	for _, e := range f.entries {
		if e.Route == domain.RoutePreserve {
			want = append(want, e)
		}
	}
	if len(ev.Retained) != len(want) {
		t.Fatalf("Retained has %d entries, want %d", len(ev.Retained), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(ev.Retained[i], want[i]) {
			t.Fatalf("Retained[%d] = %+v, want %+v", i, ev.Retained[i], want[i])
		}
	}
	if ev.PreservedEntries != int64(len(want)) {
		t.Fatalf("PreservedEntries = %d, want %d", ev.PreservedEntries, len(want))
	}
	if ev.PreservedBytes != f.preservedBytes() {
		t.Fatalf("PreservedBytes = %d, want %d", ev.PreservedBytes, f.preservedBytes())
	}

	// Tree prefixes: the workspace name (main-root backend prefix) and
	// the located op dir.
	if ev.WsPrefix != f.wsPrefix {
		t.Fatalf("WsPrefix = %q, want %q", ev.WsPrefix, f.wsPrefix)
	}
	if ev.OpDirName != f.opDirName {
		t.Fatalf("OpDirName = %q, want %q", ev.OpDirName, f.opDirName)
	}
}

// A manifest digest that does not match the payload's actual bytes is
// the core I12 refusal, with the discovery wording family naming both
// digests.
func TestLoadCapsuleEvidenceManifestDigestMismatch(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	wrong := digestBytes([]byte("not the frozen manifest bytes"))
	_, err := LoadCapsuleEvidence(context.Background(), f.store, f.vault,
		f.payloadID, wrong, f.inventoryDigest)
	ve := asDocVerification(t, err)
	joined := strings.Join(ve.Details, "; ")
	for _, want := range []string{
		"manifest.json: digest ",
		"destination seal declares " + wrong,
		"the payload does not match its seal",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("details %q do not contain %q", joined, want)
		}
	}
}

// The accounting document is gated by its own declared digest.
func TestLoadCapsuleEvidenceInventoryDigestMismatch(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	wrong := digestBytes([]byte("not the frozen inventory bytes"))
	_, err := LoadCapsuleEvidence(context.Background(), f.store, f.vault,
		f.payloadID, f.manifestDigest, wrong)
	ve := asDocVerification(t, err)
	joined := strings.Join(ve.Details, "; ")
	for _, want := range []string{
		"inventory.jsonl: digest ",
		"destination seal declares " + wrong,
		"the payload does not match its seal",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("details %q do not contain %q", joined, want)
		}
	}
}

// A snapshot whose tree carries no .ebb-op-<32hex>/manifest.json node
// (exact path elements: a plain directory, and an .ebb-op- dir whose
// suffix is not 32-hex, are both non-matches) is not a payload shape
// and is refused regardless of the claimed digests.
func TestLoadCapsuleEvidenceRejectsNonPayloadShape(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	// Exact-byte fixture writers only (never heredocs).
	writeFile(t, filepath.Join(f.parent, "foreign", manifestName), f.manifestBytes)
	writeFile(t, filepath.Join(f.parent, ".ebb-op-not-a-valid-id", manifestName), f.manifestBytes)
	ref, err := f.store.Snapshot(context.Background(), f.vault.RepoDir, f.parent,
		[]string{"foreign", ".ebb-op-not-a-valid-id"}, f.vault.Passfile, nil)
	if err != nil {
		t.Fatalf("foreign snapshot: %v", err)
	}
	_, err = LoadCapsuleEvidence(context.Background(), f.store, f.vault,
		ref.BackendID, f.manifestDigest, f.inventoryDigest)
	ve := asDocVerification(t, err)
	if !strings.Contains(strings.Join(ve.Details, "; "), "not an Ebb payload shape") {
		t.Fatalf("details %q do not name the payload shape refusal", strings.Join(ve.Details, "; "))
	}
}

// Tampered manifest bytes whose digest the seal actually declares (the
// claim is consistent with the bytes): the digest gate passes, but
// strict parsing refuses — a well-formed digest over garbage bytes is
// not evidence.
func TestLoadCapsuleEvidenceTamperedManifestFailsStrictParse(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	garbage := []byte("this is not a manifest\n")
	f.store.dumpTamper["/"+f.opDirName+"/"+manifestName] = func([]byte) []byte {
		return append([]byte(nil), garbage...)
	}
	_, err := LoadCapsuleEvidence(context.Background(), f.store, f.vault,
		f.payloadID, digestBytes(garbage), f.inventoryDigest)
	ve := asDocVerification(t, err)
	if !strings.Contains(strings.Join(ve.Details, "; "), "failed strict parsing") {
		t.Fatalf("details %q do not name the strict-parse refusal", strings.Join(ve.Details, "; "))
	}
}

// Empty declared digests cannot verify anything and refuse up front
// (mirroring the receipt-side emptiness refusal of the discovery path).
func TestLoadCapsuleEvidenceEmptyDigestClaimsRefused(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	_, err := LoadCapsuleEvidence(context.Background(), f.store, f.vault,
		f.payloadID, "", "")
	ve := asDocVerification(t, err)
	if !strings.Contains(strings.Join(ve.Details, "; "),
		"destination seal carries an empty manifest/inventory digest") {
		t.Fatalf("details %q do not name the empty-claim refusal", strings.Join(ve.Details, "; "))
	}
}

// A payload backend id that is not a full 64-hex id refuses with the
// discovery path's wording (capsule import never resolves ambiguity).
func TestLoadCapsuleEvidenceRefusesNonFullBackendID(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	_, err := LoadCapsuleEvidence(context.Background(), f.store, f.vault,
		f.payloadID[:8], f.manifestDigest, f.inventoryDigest)
	ve := asDocVerification(t, err)
	if !strings.Contains(strings.Join(ve.Details, "; "), "not a full 64-hex backend id") {
		t.Fatalf("details %q do not name the backend-id shape refusal", strings.Join(ve.Details, "; "))
	}
}

// Shared-core gate on the DISCOVERY side: a (self-consistent) receipt
// whose operation id names an op dir the payload tree does not carry is
// refused as suspicious, and only the genuine pair is adopted. This
// pins the requireOpDir contract that keeps DiscoverVault's receipt
// binding while the core locates the op dir by tree shape.
func TestDiscoverVaultRefusesReceiptNamingWrongOpDir(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	ctx := context.Background()

	otherOp := domain.OperationID(domain.NewID())
	receipt := receiptDoc{
		SchemaVersion:    schemaVersionCurrent,
		SnapshotID:       string(f.snapID),
		WorkspaceID:      string(f.wsID),
		BackendRepoID:    "fake-repo-id",
		PayloadBackendID: f.payloadID,
		ManifestDigest:   f.manifestDigest,
		InventoryDigest:  f.inventoryDigest,
		RequiredFeatures: []string{},
		Verification: receiptVerification{
			Checks:       []string{"coverage-complete", "payload-readback-complete"},
			Scope:        "single-owned-root",
			Time:         domain.FormatTime(time.Now()),
			ToolVersions: map[string]string{"ebb": "fixture"},
		},
		OperationID: string(otherOp),
		Retention:   "pinned",
	}
	rb, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rb = append(rb, '\n')
	sealDirName := sealPrefix + string(otherOp)
	writeFile(t, filepath.Join(f.parent, sealDirName, receiptName), rb)
	if _, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent,
		[]string{sealDirName}, f.vault.Passfile, map[string]string{"ebb-kind": "seal"}); err != nil {
		t.Fatalf("plant mismatched seal: %v", err)
	}

	disc, derr := DiscoverVault(ctx, f.store, f.vault, "fake-repo-id")
	if derr != nil {
		t.Fatalf("DiscoverVault: %v", derr)
	}
	if len(disc.Pairs) != 1 {
		t.Fatalf("adopted pairs = %d, want exactly the genuine one (pairs %+v, suspicious %+v)",
			len(disc.Pairs), disc.Pairs, disc.Suspicious)
	}
	if disc.Pairs[0].SealBackendID != f.sealID || disc.Pairs[0].PayloadBackendID != f.payloadID {
		t.Fatalf("adopted pair = %s/%s, want the genuine %s/%s",
			disc.Pairs[0].SealBackendID, disc.Pairs[0].PayloadBackendID, f.sealID, f.payloadID)
	}
	if len(disc.Suspicious) != 1 {
		t.Fatalf("suspicious findings = %+v, want exactly the mismatched seal", disc.Suspicious)
	}
	joined := strings.Join(disc.Suspicious[0].Reasons, "; ")
	if !strings.Contains(joined, "but the receipt names") {
		t.Fatalf("suspicious reasons %q do not name the op-dir mismatch", joined)
	}
}

// Task-3 regression: LoadRetainedEvidence also fills Manifest.Kind from
// the frozen contract (additive; existing callers unaffected).
func TestLoadRetainedEvidenceFillsManifestKind(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	snap, err := f.cat.GetSnapshot(f.snapID)
	if err != nil {
		t.Fatalf("get snapshot row: %v", err)
	}
	ev, err := LoadRetainedEvidence(context.Background(), f.store, f.vault, f.snapID, snap)
	if err != nil {
		t.Fatalf("LoadRetainedEvidence: %v", err)
	}
	if ev.Manifest.Kind != catalog.SnapshotKindPark {
		t.Fatalf("Manifest.Kind = %q, want %q (fixture freezes stopped-writers-asserted)",
			ev.Manifest.Kind, catalog.SnapshotKindPark)
	}
}
