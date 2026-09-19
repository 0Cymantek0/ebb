package capsule

// import_test.go — the default-suite tests for the §15.3 import
// protocol over the fake capsule store (importfake_test.go): the happy
// path end to end, the typed refusals at every gate (unlock, structure,
// classification, seal provenance, evidence digests, trim kind,
// headroom, duplicate gate, silent copy skip), the step-12 rollback
// hygiene (List-verified forget of what the import created), and the
// golden pin of the local import receipt against lifecycle's own §16.4
// writer. Exact-byte writers only — never heredocs.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/platform"
	"ebb/internal/policy"
	"ebb/internal/restore"
)

// runImport drives one Import against the fixture with the standard
// seams (injected FreeSpace so the real disk never gates the test).
func (fx *importFixture) runImport(mut func(*ImportParams)) (ImportResult, error) {
	fx.t.Helper()
	fx.store.resetCalls()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	params := ImportParams{
		Store:        fx.store,
		CapsulePath:  fx.capsulePath,
		Passphrase:   fxCapsulePass,
		DestRepoDir:  fx.dstRepoDir,
		DestPassfile: fx.dstPassfile,
		DestRepoID:   fx.dstRepoID,
		OperationID:  fx.impOpID,
		FreeSpace:    func(string) (int64, error) { return 1 << 40, nil },
		EbbVersion:   "test-version",
	}
	if mut != nil {
		mut(&params)
	}
	return Import(ctx, params)
}

func newImportOpID(t *testing.T) domain.OperationID {
	t.Helper()
	id, err := domain.ParseID(string(domain.NewID()))
	if err != nil {
		t.Fatal(err)
	}
	return domain.OperationID(id)
}

// assertNoImportScratch asserts the owned working dir is gone.
func assertNoImportScratch(t *testing.T, fx *importFixture) {
	t.Helper()
	des, err := os.ReadDir(filepath.Dir(fx.dstRepoDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-import-") {
			t.Errorf("import scratch dir %s left behind", d.Name())
		}
	}
}

func TestImportHappyPath(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	seedIDs := fx.store.snapIDs(fx.dstRepoDir)

	var phases []string
	var knownArgs []string
	res, err := fx.runImport(func(p *ImportParams) {
		p.Phase = func(step string) error {
			phases = append(phases, step)
			return nil
		}
		p.Known = func(snapshotID, manifestDigest string) (bool, error) {
			knownArgs = []string{snapshotID, manifestDigest}
			return false, nil
		}
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	t.Run("result facts", func(t *testing.T) {
		if res.AlreadyKnown {
			t.Error("AlreadyKnown = true on a fresh import")
		}
		if res.LogicalSnapshotID != fx.snapID {
			t.Errorf("LogicalSnapshotID = %s, want the manifest's %s", res.LogicalSnapshotID, fx.snapID)
		}
		if res.WorkspaceID != fx.wsID {
			t.Errorf("WorkspaceID = %s, want %s", res.WorkspaceID, fx.wsID)
		}
		if res.WorkspaceName != fx.wsPrefix {
			t.Errorf("WorkspaceName = %q, want the main-root backend prefix %q", res.WorkspaceName, fx.wsPrefix)
		}
		if res.Kind != catalog.SnapshotKindPark {
			t.Errorf("Kind = %q, want %q", res.Kind, catalog.SnapshotKindPark)
		}
		if res.CreatedAt != "2026-09-18T12:00:00Z" {
			t.Errorf("CreatedAt = %q", res.CreatedAt)
		}
		if res.ManifestDigest != fx.manifestDigest || res.InventoryDigest != fx.inventoryDigest {
			t.Errorf("digests = %s/%s, want the re-derived %s/%s",
				res.ManifestDigest, res.InventoryDigest, fx.manifestDigest, fx.inventoryDigest)
		}
		if res.CapsuleRepoID != "fake-capsule-repo-1" {
			t.Errorf("CapsuleRepoID = %s", res.CapsuleRepoID)
		}
		if res.RepoBytes <= 0 {
			t.Errorf("RepoBytes = %d, want the container-declared repository size", res.RepoBytes)
		}
		if res.PreservedEntries != 2 || res.PreservedBytes <= 0 {
			t.Errorf("preserved = %d entries / %d bytes", res.PreservedEntries, res.PreservedBytes)
		}
		if res.DestinationPayload == "" || res.DestinationPayload == fx.payloadID {
			t.Errorf("DestinationPayload = %q, want a DISCOVERED new id (ids change on copy; capsule held %s)",
				res.DestinationPayload, fx.payloadID)
		}
		if res.DestinationSeal == "" {
			t.Error("DestinationSeal is empty")
		}
		want := []string{checkCoverage, checkPayloadReadback, checkSealReadback, checkContainer}
		if !reflect.DeepEqual(res.Checks, want) {
			t.Errorf("Checks = %v, want %v", res.Checks, want)
		}
		if knownArgs == nil || knownArgs[0] != string(fx.snapID) || knownArgs[1] != fx.manifestDigest {
			t.Errorf("Known args = %v, want (%s, %s)", knownArgs, fx.snapID, fx.manifestDigest)
		}
		wantPhases := []string{PhaseExtracting, PhaseCopying, PhaseVerifying}
		if strings.Join(phases, ",") != strings.Join(wantPhases, ",") {
			t.Errorf("phases = %v, want %v", phases, wantPhases)
		}
	})

	t.Run("destination vault state", func(t *testing.T) {
		ids := fx.store.snapIDs(fx.dstRepoDir)
		if len(ids) != len(seedIDs)+2 {
			t.Fatalf("destination holds %d snapshots, want seed + payload + seal (%d)", len(ids), len(seedIDs)+2)
		}
		if tags := fx.store.snapTags(fx.dstRepoDir, res.DestinationPayload); tags["ebb-kind"] != "payload" {
			t.Errorf("destination payload tags = %v", tags)
		}
		tags := fx.store.snapTags(fx.dstRepoDir, res.DestinationSeal)
		// The seal carries the CAPTURE's operation id (the payload's
		// frozen op dir id, fx.expOpID) — not the import's transport op
		// id — so every lifecycle-shaped receipt consumer agrees.
		if tags["ebb-kind"] != "seal" || tags["ebb-op"] != string(fx.expOpID) || tags["ws"] != string(fx.wsID) {
			t.Errorf("destination seal tags = %v", tags)
		}
		for _, id := range seedIDs {
			if id == res.DestinationPayload || id == res.DestinationSeal {
				t.Error("a pre-existing snapshot was reused as an import artifact")
			}
		}
	})

	t.Run("local seal receipt wire form", func(t *testing.T) {
		// The receipt lives under .ebb-seal-<CAPTURE op id> (fx.expOpID).
		raw, err := fx.store.dumpFrom(fx.dstRepoDir, fx.dstPassfile, res.DestinationSeal,
			"/"+sealDirPrefix+string(fx.expOpID)+"/"+sealDocName)
		if err != nil {
			t.Fatalf("dump import receipt: %v", err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("receipt is not JSON: %v", err)
		}
		assertJSONField(t, doc, "schema_version", "1")
		assertJSONField(t, doc, "snapshot_id", `"`+string(fx.snapID)+`"`)
		assertJSONField(t, doc, "workspace_id", `"`+string(fx.wsID)+`"`)
		assertJSONField(t, doc, "backend_repo_id", `"`+fx.dstRepoID+`"`)
		assertJSONField(t, doc, "payload_backend_id", `"`+res.DestinationPayload+`"`)
		assertJSONField(t, doc, "manifest_digest", `"`+fx.manifestDigest+`"`)
		assertJSONField(t, doc, "inventory_digest", `"`+fx.inventoryDigest+`"`)
		assertJSONField(t, doc, "operation_id", `"`+string(fx.expOpID)+`"`)
		assertJSONField(t, doc, "retention", `"pinned"`)
		if string(doc["required_features"]) != "[]" {
			t.Errorf("required_features = %s, want []", doc["required_features"])
		}
		var ver map[string]json.RawMessage
		if err := json.Unmarshal(doc["verification"], &ver); err != nil {
			t.Fatalf("verification block: %v", err)
		}
		var checks []string
		if err := json.Unmarshal(ver["checks"], &checks); err != nil {
			t.Fatal(err)
		}
		wantChecks := []string{checkCoverage, checkPayloadReadback, checkSealReadback, checkContainer}
		if !reflect.DeepEqual(checks, wantChecks) {
			t.Errorf("verification.checks = %v, want %v", checks, wantChecks)
		}
		assertJSONField(t, ver, "scope", `"capsule-import"`)
		if _, err := time.Parse(time.RFC3339Nano, strings.Trim(string(ver["time"]), `"`)); err != nil {
			t.Errorf("verification.time %s is not RFC3339: %v", ver["time"], err)
		}
		var tools map[string]string
		if err := json.Unmarshal(ver["tool_versions"], &tools); err != nil {
			t.Fatal(err)
		}
		wantTools := map[string]string{"ebb-capsule": ProducerEbb, "ebb": "test-version"}
		if !reflect.DeepEqual(tools, wantTools) {
			t.Errorf("tool_versions = %v, want %v", tools, wantTools)
		}
	})

	assertNoImportScratch(t, fx)
}

func assertJSONField(t *testing.T, doc map[string]json.RawMessage, key, want string) {
	t.Helper()
	got, ok := doc[key]
	if !ok {
		t.Fatalf("receipt field %q missing (have %v)", key, keysOf(doc))
	}
	if strings.TrimSpace(string(got)) != want {
		t.Errorf("receipt field %q = %s, want %s", key, got, want)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestImportPairLoadsThroughProductEvidencePath — the e2e lesson made
// cheap: after a fake Import, the product's own verification path
// (restore.LoadRetainedEvidence — `ebb verify`'s loader, including the
// D017 catalog-row digest witness and the I13 op-dir re-derivation from
// the RECEIPT's operation id) must accept the imported pair over a
// hand-built catalog row built from the import result alone. This is
// the default-suite reproducer for the seal op-id bug: when the local
// seal recorded the IMPORT's op id, loadDocuments looked for the
// payload's frozen documents under .ebb-op-<import op id> and the dump
// refused.
func TestImportPairLoadsThroughProductEvidencePath(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	res, err := fx.runImport(nil)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	// The row exactly what the CLI registers after a real import.
	row := catalog.Snapshot{
		ID:               res.LogicalSnapshotID,
		WorkspaceID:      res.WorkspaceID,
		PayloadBackendID: res.DestinationPayload,
		SealBackendID:    res.DestinationSeal,
		ManifestDigest:   res.ManifestDigest,
		InventoryDigest:  res.InventoryDigest,
		Kind:             res.Kind,
		CreatedAt:        res.CreatedAt,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ev, err := restore.LoadRetainedEvidence(ctx, fx.store,
		restore.VaultRef{RepoDir: fx.dstRepoDir, Passfile: fx.dstPassfile},
		res.LogicalSnapshotID, row)
	if err != nil {
		t.Fatalf("LoadRetainedEvidence over the imported pair (the ebb verify path): %v", err)
	}
	// The re-loaded evidence agrees with the capsule-side derivation on
	// every fact both establish, and the receipt names the CAPTURE's op
	// id (the payload's frozen op dir — fx.expOpID), never the import's.
	if ev.Manifest.ManifestDigest != fx.manifestDigest || ev.Manifest.InventoryDigest != fx.inventoryDigest {
		t.Errorf("re-loaded digests = %s/%s, want the fixture's %s/%s",
			ev.Manifest.ManifestDigest, ev.Manifest.InventoryDigest, fx.manifestDigest, fx.inventoryDigest)
	}
	if ev.PreservedEntries != res.PreservedEntries || ev.PreservedBytes != res.PreservedBytes {
		t.Errorf("re-loaded preserved = %d/%d, want the import's %d/%d",
			ev.PreservedEntries, ev.PreservedBytes, res.PreservedEntries, res.PreservedBytes)
	}
	if ev.WsPrefix != fx.wsPrefix || ev.OpDirName != fx.opDir {
		t.Errorf("re-loaded prefixes = %q/%q, want %q/%q", ev.WsPrefix, ev.OpDirName, fx.wsPrefix, fx.opDir)
	}
	if ev.Receipt.OperationID != string(fx.expOpID) {
		t.Errorf("receipt operation_id = %q, want the CAPTURE's %q (the payload's frozen op dir id)",
			ev.Receipt.OperationID, fx.expOpID)
	}
	if ev.Receipt.Scope != importScope {
		t.Errorf("receipt scope = %q, want %q (the import's provenance)", ev.Receipt.Scope, importScope)
	}
}

// TestImportIdentifiedHookContract — the identity-adoption hook fires
// ONCE, after capsule verification and the trim gate, BEFORE the Known
// duplicate gate and any destination-vault mutation, carrying the
// payload's own logical identity; an error aborts with zero
// destination-vault calls.
func TestImportIdentifiedHookContract(t *testing.T) {
	t.Run("fires once after verification, before Known, with verified identity", func(t *testing.T) {
		impOp := newImportOpID(t)
		fx := buildImportFixture(t, impOp, capsuleSpec{})
		var calls []string // ordered hook trace: "identified" then "known"
		res, err := fx.runImport(func(p *ImportParams) {
			p.Identified = func(id ImportIdentity) error {
				calls = append(calls, "identified")
				if id.SnapshotID != string(fx.snapID) || id.WorkspaceID != string(fx.wsID) {
					t.Errorf("Identified ids = %s/%s, want the manifest's %s/%s",
						id.SnapshotID, id.WorkspaceID, fx.snapID, fx.wsID)
				}
				if id.WorkspaceName != fx.wsPrefix || id.Kind != catalog.SnapshotKindPark {
					t.Errorf("Identified name/kind = %q/%q, want %q/%q",
						id.WorkspaceName, id.Kind, fx.wsPrefix, catalog.SnapshotKindPark)
				}
				if id.ManifestDigest != fx.manifestDigest {
					t.Errorf("Identified manifest digest = %s, want the re-derived %s", id.ManifestDigest, fx.manifestDigest)
				}
				return nil
			}
			p.Known = func(snapshotID, manifestDigest string) (bool, error) {
				calls = append(calls, "known")
				return false, nil
			}
		})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if res.AlreadyKnown {
			t.Fatal("AlreadyKnown = true despite the Known gate's miss")
		}
		if strings.Join(calls, ",") != "identified,known" {
			t.Errorf("hook order = %v, want identified before known", calls)
		}
	})

	t.Run("already-known path fires Identified exactly once too", func(t *testing.T) {
		impOp := newImportOpID(t)
		fx := buildImportFixture(t, impOp, capsuleSpec{})
		var identified, known int
		_, err := fx.runImport(func(p *ImportParams) {
			p.Identified = func(ImportIdentity) error { identified++; return nil }
			p.Known = func(string, string) (bool, error) { known++; return true, nil }
		})
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		if identified != 1 || known != 1 {
			t.Errorf("identified/known calls = %d/%d, want 1/1", identified, known)
		}
	})

	t.Run("error aborts with zero vault mutations", func(t *testing.T) {
		impOp := newImportOpID(t)
		fx := buildImportFixture(t, impOp, capsuleSpec{})
		hookErr := errors.New("catalog: workspace row refused")
		_, err := fx.runImport(func(p *ImportParams) {
			p.Identified = func(ImportIdentity) error { return hookErr }
			p.Known = func(string, string) (bool, error) {
				t.Error("Known fired despite the Identified refusal")
				return false, nil
			}
		})
		if err == nil || !strings.Contains(err.Error(), "identity hook refused") {
			t.Fatalf("err = %v, want the identity-hook refusal", err)
		}
		if !errors.Is(err, hookErr) {
			t.Errorf("the hook's own error must surface wrapped, not swallowed: %v", err)
		}
		if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
			t.Errorf("destination vault was contacted: %v", calls)
		}
		if ids := fx.store.snapIDs(fx.dstRepoDir); len(ids) != 1 {
			t.Errorf("destination holds %d snapshots after the refusal, want only the seed", len(ids))
		}
		assertNoImportScratch(t, fx)
	})
}

// TestImportParamsValidation — caller mistakes refuse before anything is
// created (the validateParams mirror).
func TestImportParamsValidation(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	base := func() ImportParams {
		return ImportParams{
			Store: fx.store, CapsulePath: fx.capsulePath, Passphrase: fxCapsulePass,
			DestRepoDir: fx.dstRepoDir, DestPassfile: fx.dstPassfile, DestRepoID: fx.dstRepoID,
			OperationID: impOp,
		}
	}
	cases := []struct {
		name string
		mut  func(*ImportParams)
	}{
		{"no store", func(p *ImportParams) { p.Store = nil }},
		{"no capsule path", func(p *ImportParams) { p.CapsulePath = "" }},
		{"no passphrase", func(p *ImportParams) { p.Passphrase = "" }},
		{"no dest repo dir", func(p *ImportParams) { p.DestRepoDir = "" }},
		{"no dest passfile", func(p *ImportParams) { p.DestPassfile = "" }},
		{"no dest repo id", func(p *ImportParams) { p.DestRepoID = "" }},
		{"no operation id", func(p *ImportParams) { p.OperationID = "" }},
		{"missing capsule file", func(p *ImportParams) { p.CapsulePath = filepath.Join(t.TempDir(), "absent.ebb") }},
		{"capsule is a directory", func(p *ImportParams) { p.CapsulePath = t.TempDir() }},
		{"dest repo dir missing", func(p *ImportParams) { p.DestRepoDir = filepath.Join(t.TempDir(), "absent-vault") }},
	}
	fx.store.resetCalls()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.mut(&p)
			_, err := Import(context.Background(), p)
			if !IsInvalidParams(err) {
				t.Fatalf("err = %v, want ErrInvalidParams", err)
			}
		})
	}
	if len(fx.store.calls) != 0 {
		t.Errorf("store was called during param validation: %v", fx.store.calls)
	}
}

// TestImportWrongPassphrase — the store's auth failure is re-typed to
// name the capsule; the capsule file is untouched and the destination
// vault was never contacted.
func TestImportWrongPassphrase(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	before, _ := os.ReadFile(fx.capsulePath)

	_, err := fx.runImport(func(p *ImportParams) { p.Passphrase = "not-the-recovery-secret" })
	var unlock *ErrCapsuleUnlock
	if !errors.As(err, &unlock) {
		t.Fatalf("err = %v, want ErrCapsuleUnlock", err)
	}
	if unlock.Path != fx.capsulePath {
		t.Errorf("unlock error names %q, want the capsule path", unlock.Path)
	}
	var se *domain.StoreError
	if !errors.As(err, &se) || se.Class != domain.StoreErrAuth {
		t.Errorf("underlying error class = %v, want store auth", err)
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted: %v", calls)
	}
	after, _ := os.ReadFile(fx.capsulePath)
	if string(before) != string(after) {
		t.Error("the capsule file was modified")
	}
	assertNoImportScratch(t, fx)
}

// TestImportNotACapsule — structural container failures wrap into the
// typed ErrNotACapsule naming the file.
func TestImportNotACapsule(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	garbage := filepath.Join(t.TempDir(), "garbage.ebb")
	fxWriteFile(t, garbage, []byte("definitely not a zip container"))
	fx.capsulePath = garbage

	_, err := fx.runImport(nil)
	var na *ErrNotACapsule
	if !errors.As(err, &na) {
		t.Fatalf("err = %v, want ErrNotACapsule", err)
	}
	if na.Path != garbage || len(na.Details) == 0 {
		t.Errorf("ErrNotACapsule = %+v", na)
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted: %v", calls)
	}
}

// TestImportClassifyRefusals — the fresh-capsule-repository contract:
// exactly one payload + one seal; anything else refuses listing ids.
func TestImportClassifyRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec capsuleSpec
		want string
	}{
		{"two payloads", capsuleSpec{twoPayloads: true}, "2 ebb-kind=payload snapshots"},
		{"untagged snapshot", capsuleSpec{untaggedExtra: true}, "without an ebb-kind tag"},
		{"no seal snapshot", capsuleSpec{noSealSnap: true}, "no ebb-kind=seal snapshot"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			impOp := newImportOpID(t)
			fx := buildImportFixture(t, impOp, tc.spec)
			_, err := fx.runImport(nil)
			var na *ErrNotACapsule
			if !errors.As(err, &na) {
				t.Fatalf("err = %v, want ErrNotACapsule", err)
			}
			if !strings.Contains(na.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", na.Error(), tc.want)
			}
			if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
				t.Errorf("destination vault was contacted: %v", calls)
			}
		})
	}
}

// TestImportSealFromAnotherRepo — a destination seal minted for a
// different repository refuses (D023 discipline: never accept a seal
// whose repository binding does not match the material in hand).
func TestImportSealFromAnotherRepo(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{sealRepoID: "some-other-repo"})
	_, err := fx.runImport(nil)
	var ve *ErrVerification
	if !errors.As(err, &ve) || ve.Check != "capsule-seal" {
		t.Fatalf("err = %v, want ErrVerification{capsule-seal}", err)
	}
	if !strings.Contains(strings.Join(ve.Details, "; "), "some-other-repo") {
		t.Errorf("details %v do not name the foreign repository", ve.Details)
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted: %v", calls)
	}
}

// TestImportDigestMismatch — the core I12 refusal: the payload's own
// manifest bytes do not hash to the digest the capsule seal declares
// (a repository file was modified inside the capsule). Nothing was
// mutated in the destination.
func TestImportDigestMismatch(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{lieManifestDgst: true})
	_, err := fx.runImport(nil)
	var ve *ErrVerification
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ErrVerification", err)
	}
	if ve.Check != "capsule-documents" {
		t.Fatalf("Check = %q, want %q", ve.Check, "capsule-documents")
	}
	joined := strings.Join(ve.Details, "; ")
	for _, want := range []string{"manifest.json: digest ", "destination seal declares"} {
		if !strings.Contains(joined, want) {
			t.Errorf("details %q do not contain %q", joined, want)
		}
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted: %v", calls)
	}
	assertNoImportScratch(t, fx)
}

// TestImportMissingAccountingDoc — the op dir lacking the accounting
// document the manifest names refuses on the evidence path.
func TestImportMissingAccountingDoc(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{noAccountingDoc: true})
	_, err := fx.runImport(nil)
	var ve *ErrVerification
	if !errors.As(err, &ve) || ve.Check != "capsule-documents" {
		t.Fatalf("err = %v, want ErrVerification{capsule-documents}", err)
	}
	if !strings.Contains(strings.Join(ve.Details, "; "), "inventory.jsonl") {
		t.Errorf("details %v do not name the missing accounting document", ve.Details)
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted: %v", calls)
	}
}

// TestImportTrimCapsule — a trim capsule's authoritative material is a
// removal plan; the typed blocked error refuses before any vault
// mutation, naming the logical identities.
func TestImportTrimCapsule(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{trim: true})
	_, err := fx.runImport(nil)
	var tc *ErrTrimCapsule
	if !errors.As(err, &tc) {
		t.Fatalf("err = %v, want ErrTrimCapsule", err)
	}
	if tc.SnapshotID != string(fx.snapID) || tc.WorkspaceID != string(fx.wsID) {
		t.Errorf("ErrTrimCapsule identities = %s/%s", tc.SnapshotID, tc.WorkspaceID)
	}
	if !strings.Contains(tc.Error(), "removal plan") {
		t.Errorf("error %q does not explain the trim refusal", tc.Error())
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted: %v", calls)
	}
}

// TestImportSealReplicationMismatch — the payload's manifest identities
// must BE what the capsule seal certifies (the loader leaves this
// comparison to the caller by contract).
func TestImportSealReplicationMismatch(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{wrongWsInSeal: true})
	_, err := fx.runImport(nil)
	var ve *ErrVerification
	if !errors.As(err, &ve) || ve.Check != "capsule-seal" {
		t.Fatalf("err = %v, want ErrVerification{capsule-seal}", err)
	}
	if !strings.Contains(strings.Join(ve.Details, "; "), "workspace") {
		t.Errorf("details %v do not name the workspace disagreement", ve.Details)
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted: %v", calls)
	}
}

// TestImportDuplicateGateAlreadyKnown — a Known hit returns the facts
// WITHOUT any destination-vault call (the gate fires after capsule
// verification, before the first vault mutation).
func TestImportDuplicateGateAlreadyKnown(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	res, err := fx.runImport(func(p *ImportParams) {
		p.Known = func(snapshotID, manifestDigest string) (bool, error) {
			if snapshotID != string(fx.snapID) || manifestDigest != fx.manifestDigest {
				t.Errorf("Known args = %s/%s", snapshotID, manifestDigest)
			}
			return true, nil
		}
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !res.AlreadyKnown {
		t.Fatal("AlreadyKnown = false")
	}
	if res.DestinationPayload != "" || res.DestinationSeal != "" {
		t.Errorf("destination ids = %s/%s, want none (no mutation)", res.DestinationPayload, res.DestinationSeal)
	}
	if res.LogicalSnapshotID != fx.snapID || res.ManifestDigest != fx.manifestDigest {
		t.Errorf("facts not filled: %+v", res)
	}
	if calls := fx.store.callsOn(fx.dstRepoDir); len(calls) > 0 {
		t.Errorf("destination vault was contacted after the duplicate gate: %v", calls)
	}
	assertNoImportScratch(t, fx)
}

// TestImportSilentCopySkip — restic copy can skip silently (probe C10):
// a copy that creates nothing refuses as unprovable, with no rollback
// needed (nothing was created).
func TestImportSilentCopySkip(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	fx.store.copyNoOp = true
	_, err := fx.runImport(nil)
	var ci *ErrCopyIntegrity
	if !errors.As(err, &ci) {
		t.Fatalf("err = %v, want ErrCopyIntegrity", err)
	}
	if !strings.Contains(ci.Error(), "skip silently") {
		t.Errorf("error %q does not name the silent skip", ci.Error())
	}
	if len(fx.store.forgetIDs) > 0 {
		t.Errorf("forget was called for a copy that created nothing: %v", fx.store.forgetIDs)
	}
}

// TestImportPostCopyReadbackFailureRollsBack — a §11.4 gate failure
// AFTER the copy forgets the created payload, List-verified gone, and
// reports the verification cause (never hides the leak path).
func TestImportPostCopyReadbackFailureRollsBack(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	seedIDs := fx.store.snapIDs(fx.dstRepoDir)
	// Serve different bytes for one retained workspace file from the
	// destination dump (the capsule-side evidence path never reads
	// workspace files, so the fault lands exactly at step 10).
	fx.store.dumpTamper["/"+fx.wsPrefix+"/a.txt"] = func(b []byte) []byte {
		return append(append([]byte(nil), b...), []byte("tampered")...)
	}

	_, err := fx.runImport(nil)
	var ve *ErrVerification
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ErrVerification", err)
	}
	if ve.Check != "destination-readback" {
		t.Fatalf("Check = %q, want destination-readback", ve.Check)
	}
	if strings.Contains(ve.Error(), "ROLLBACK") {
		t.Errorf("clean rollback should not add rollback noise: %v", err)
	}
	if len(fx.store.forgetIDs) != 1 {
		t.Fatalf("forget calls = %v, want exactly one", fx.store.forgetIDs)
	}
	forgotten := fx.store.forgetIDs[0]
	if len(forgotten) != 1 {
		t.Fatalf("forgot %v, want exactly the copied payload", forgotten)
	}
	left := fx.store.snapIDs(fx.dstRepoDir)
	if !reflect.DeepEqual(left, seedIDs) {
		t.Errorf("destination holds %v after rollback, want the seed set %v", left, seedIDs)
	}
	assertNoImportScratch(t, fx)
}

// TestImportSealReadbackMismatchRollsBack — a receipt that does not
// read back byte-exact refuses, and BOTH artifacts the import created
// (payload + seal snapshot) are forgotten List-verified. The tamper key
// is the seal's tree path, whose dir embeds the CAPTURE's op id.
func TestImportSealReadbackMismatchRollsBack(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	seedIDs := fx.store.snapIDs(fx.dstRepoDir)
	// The tamper is scoped to the DESTINATION repository: after the
	// capture-op-id fix the local seal's tree path equals the capsule's
	// embedded seal path (.ebb-seal-<capture op id>/receipt.json), so a
	// repo-wide tamper would also corrupt the capsule-side seal read.
	fx.store.tamperDumpIn(fx.dstRepoDir, "/"+sealDirPrefix+string(fx.expOpID)+"/"+sealDocName,
		func(b []byte) []byte { return append([]byte("not the receipt: "), b...) })

	_, err := fx.runImport(nil)
	var ve *ErrVerification
	if !errors.As(err, &ve) || ve.Check != checkSealReadback {
		t.Fatalf("err = %v, want ErrVerification{%s}", err, checkSealReadback)
	}
	if len(fx.store.forgetIDs) != 1 {
		t.Fatalf("forget calls = %v, want exactly one", fx.store.forgetIDs)
	}
	if len(fx.store.forgetIDs[0]) != 2 {
		t.Fatalf("forgot %v, want the payload AND the seal snapshot", fx.store.forgetIDs[0])
	}
	left := fx.store.snapIDs(fx.dstRepoDir)
	if !reflect.DeepEqual(left, seedIDs) {
		t.Errorf("destination holds %v after rollback, want the seed set %v", left, seedIDs)
	}
}

// TestImportFailedRollbackReportsLeak — when the forget itself fails,
// the leaked backend ids are appended to the returned error honestly.
func TestImportFailedRollbackReportsLeak(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	fx.store.dumpTamper["/"+fx.wsPrefix+"/a.txt"] = func(b []byte) []byte { return []byte("changed") }
	fx.store.forgetErr = errors.New("vault locked")

	_, err := fx.runImport(nil)
	if err == nil || !strings.Contains(err.Error(), "ROLLBACK FAILED") {
		t.Fatalf("err = %v, want an honest rollback-failure report", err)
	}
}

// TestImportSpacePreflightRefusal — the §15.3 headroom gate fires
// BEFORE extraction with both numbers in the error and no backend call.
func TestImportSpacePreflightRefusal(t *testing.T) {
	impOp := newImportOpID(t)
	fx := buildImportFixture(t, impOp, capsuleSpec{})
	check, err := verifyPackage(fx.capsulePath)
	if err != nil {
		t.Fatalf("verifyPackage: %v", err)
	}
	free := check.ExportDoc.RepoBytes // need 2x; free == 1x

	res, err := fx.runImport(func(p *ImportParams) {
		p.FreeSpace = func(string) (int64, error) { return free, nil }
	})
	var sp *ErrImportSpace
	if !errors.As(err, &sp) {
		t.Fatalf("err = %v, want ErrImportSpace", err)
	}
	if sp.FreeBytes != free || sp.NeedBytes != 2*check.ExportDoc.RepoBytes || sp.RepoBytes != check.ExportDoc.RepoBytes {
		t.Errorf("ErrImportSpace numbers = free %d / need %d / repo %d", sp.FreeBytes, sp.NeedBytes, sp.RepoBytes)
	}
	if !strings.Contains(sp.Error(), fmt.Sprintf("%d bytes free", free)) ||
		!strings.Contains(sp.Error(), fmt.Sprintf("approximately %d needed", 2*check.ExportDoc.RepoBytes)) {
		t.Errorf("error %q does not carry both numbers", sp.Error())
	}
	_ = res
	if len(fx.store.calls) != 0 {
		t.Errorf("store was contacted despite the headroom refusal: %v", fx.store.calls)
	}
	assertNoImportScratch(t, fx)
}

// TestImportReceiptFieldNamesMatchLifecycleWriter — the golden pin of
// the LOCAL strict writer against lifecycle's own §16.4 receipt: a real
// lifecycle capture (fake store, real catalog + probe) produces a
// receipt whose JSON field names must equal both the literal frozen
// list below and what capsule's import receipt emits. A schema rename
// in either place fails HERE.
func TestImportReceiptFieldNamesMatchLifecycleWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	base := t.TempDir()
	store := newImportFakeStore()
	passfile := filepath.Join(base, "vault.pass")
	fxWriteFile(t, passfile, []byte("golden-vault-pass"))
	vaultDir := filepath.Join(base, "vault")
	if err := store.Init(ctx, vaultDir, passfile); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Open(filepath.Join(base, "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cat.Close()
	coord, err := lifecycle.New(lifecycle.Dependencies{Store: store, Cat: cat, Probe: platform.New()})
	if err != nil {
		t.Fatal(err)
	}
	wsRoot := filepath.Join(base, "golden-ws")
	fxWriteFile(t, filepath.Join(wsRoot, "a.txt"), []byte("golden fixture content\n"))
	res, err := coord.Snapshot(ctx, lifecycle.VaultRef{RepoDir: vaultDir, Passfile: passfile},
		wsRoot, lifecycle.CaptureOptions{WorkspaceName: "golden", Policy: policy.Default("golden")})
	if err != nil {
		t.Fatalf("real lifecycle capture over the fake store: %v", err)
	}

	// The receipt lifecycle itself wrote (from the seal snapshot).
	sealID := res.BackendIDs[1]
	raw := dumpReceipt(t, store, vaultDir, passfile, sealID)
	lifeTop := topLevelKeys(t, raw, "lifecycle receipt")
	lifeVer := nestedKeys(t, raw, "verification", "lifecycle receipt")

	// What capsule's import writer emits for the same wire form.
	mine, err := marshalImportReceipt(buildImportReceipt(
		restore.Evidence{
			SnapshotID:  domain.SnapshotID(domain.NewID()),
			WorkspaceID: domain.WorkspaceID(domain.NewID()),
			Manifest: restore.ManifestFacts{
				ManifestDigest:  strings.Repeat("0a", 32),
				InventoryDigest: strings.Repeat("0b", 32),
			},
		}, "repo-id", "payload-id", string(newImportOpID(t)),
		time.Now(), []string{checkCoverage}, "golden"))
	if err != nil {
		t.Fatal(err)
	}
	mineTop := topLevelKeys(t, mine, "import receipt")
	mineVer := nestedKeys(t, mine, "verification", "import receipt")

	// The literal frozen field list (§16.4): a rename anywhere fails.
	wantTop := []string{
		"schema_version", "snapshot_id", "workspace_id", "backend_repo_id",
		"payload_backend_id", "manifest_digest", "inventory_digest",
		"required_features", "verification", "operation_id", "retention",
	}
	wantVer := []string{"checks", "scope", "time", "tool_versions"}
	assertKeySet(t, lifeTop, wantTop, "lifecycle receipt top level")
	assertKeySet(t, mineTop, wantTop, "import receipt top level")
	assertKeySet(t, lifeVer, wantVer, "lifecycle receipt verification")
	assertKeySet(t, mineVer, wantVer, "import receipt verification")
}

func dumpReceipt(t *testing.T, store *importFakeStore, repoDir, passfile, sealID string) []byte {
	t.Helper()
	ls, err := store.Ls(context.Background(), repoDir, passfile, sealID)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ls {
		if e.Kind == domain.KindFile && strings.HasSuffix(e.Path, "/"+sealDocName) {
			raw, derr := store.dumpFrom(repoDir, passfile, sealID, e.Path)
			if derr != nil {
				t.Fatal(derr)
			}
			return raw
		}
	}
	t.Fatalf("no receipt node in seal snapshot %s", sealID)
	return nil
}

func topLevelKeys(t *testing.T, raw []byte, what string) []string {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not a JSON object: %v", what, err)
	}
	out := make([]string, 0, len(doc))
	for k := range doc {
		out = append(out, k)
	}
	return out
}

func nestedKeys(t *testing.T, raw []byte, field, what string) []string {
	t.Helper()
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not a JSON object: %v", what, err)
	}
	block, ok := doc[field]
	if !ok {
		t.Fatalf("%s has no %q block", what, field)
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(block, &inner); err != nil {
		t.Fatalf("%s %q block is not an object: %v", what, field, err)
	}
	out := make([]string, 0, len(inner))
	for k := range inner {
		out = append(out, k)
	}
	return out
}

func assertKeySet(t *testing.T, got, want []string, what string) {
	t.Helper()
	sorted := append([]string(nil), got...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j] < sorted[i] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	wantSorted := append([]string(nil), want...)
	for i := 0; i < len(wantSorted); i++ {
		for j := i + 1; j < len(wantSorted); j++ {
			if wantSorted[j] < wantSorted[i] {
				wantSorted[i], wantSorted[j] = wantSorted[j], wantSorted[i]
			}
		}
	}
	if strings.Join(sorted, ",") != strings.Join(wantSorted, ",") {
		t.Errorf("%s keys = %v, want exactly %v", what, sorted, wantSorted)
	}
}

// TestCapsuleFreeSpaceProbe — the default FreeSpace seam reports a sane
// quota-aware number for an existing directory and errors for a missing
// path (Windows/Linux build-tagged implementations).
func TestCapsuleFreeSpaceProbe(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		t.Skipf("no native free-space probe on %s", runtime.GOOS)
	}
	free, err := capsuleFreeSpace(t.TempDir())
	if err != nil {
		t.Fatalf("capsuleFreeSpace: %v", err)
	}
	if free <= 0 || free > 1<<50 {
		t.Errorf("free = %d, want a sane positive number", free)
	}
	if _, err := capsuleFreeSpace(filepath.Join(t.TempDir(), "absent-child")); err == nil {
		t.Error("a nonexistent path should not probe successfully")
	}
}
