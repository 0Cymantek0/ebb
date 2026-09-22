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

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/platform"
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
	// A pre-D017 catalog row (no seal-time digests) is CONSTRUCTED at
	// creation via the fixture spec — the J4 witness-preserving merge
	// rightly refuses to blank a witnessed row by re-importing over it.
	f := buildFixture(t, fixtureSpec{legacyNoDigests: true})

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

// ---- G2: a journaled success is only trusted when reality agrees ------

// TestResumeForgedSucceededRunWithAbsentOutputsIsReRun (Wave G review
// finding G2, default-suite twin of the tagged PoC): a "succeeded"
// action_runs row forged by a catalog-write attacker must NOT make
// --resume skip the action while its declared outputs are absent — the
// action is re-run (consult reality, not journals).
func TestResumeForgedSucceededRunWithAbsentOutputsIsReRun(t *testing.T) {
	f := buildFixture(t, fixtureSpec{recipeGroup: true, defArgv: []string{"go", "version"}})
	dest := filepath.Join(f.parent, "opened")
	failing := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		return actions.Result{ExitCode: 1}, nil // fails, creates no output
	}}
	o, _ := newRebuildOpener(f, failing, false)
	res, oerr := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest})
	if oerr == nil || res.Phase != catalog.PhaseRebuildFailed {
		t.Fatalf("first open should land at REBUILD_FAILED (fixture problem): %v (phase %s)", oerr, res.Phase)
	}
	opID := res.OperationID

	// The attacker (catalog write) forges a successful run.
	runID, rerr := f.cat.StartActionRun(opID, "node-dependencies")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if ferr := f.cat.FinishActionRun(runID, catalog.ActionRunSucceeded, 0, "forged by catalog-write attacker"); ferr != nil {
		t.Fatal(ferr)
	}

	// Resume with a runner that succeeds and materializes its outputs.
	retry := &fakeRunner{}
	store := approvalstore.New(filepath.Join(f.parent, "approvals.json"))
	o2, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner: retry, Approver: store, Approve: func(ctx context.Context, pending []PendingApproval) error {
			for _, p := range pending {
				if _, aerr := store.Approve(p.Def, p.Tool, p.InputDigests, "test"); aerr != nil {
					return aerr
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res2, rerr := o2.ResumeRebuild(context.Background(), f.vault, opID)
	if rerr != nil || res2.Phase != catalog.PhaseDone {
		t.Fatalf("resume must re-run the forged-skipped action to completion: %v (phase %s)", rerr, res2.Phase)
	}
	for _, a := range res2.Actions {
		if a.ID == "node-dependencies" && a.Skipped {
			t.Fatal("the action was skipped on a forged row while its outputs were absent")
		}
	}
	if len(retry.calls) == 0 {
		t.Fatal("the runner never executed: the forged row was trusted over reality")
	}
	if _, serr := os.Stat(filepath.Join(dest, "node_modules")); serr != nil {
		t.Fatalf("re-run action did not materialize its output: %v", serr)
	}
}

// ---- G3: the open-side I06 vault-overlap preflight ---------------------

// TestOpenRefusesDestinationInsideVaultRepository (Wave G review finding
// G3, default-suite twin of the tagged PoC): a destination inside the
// vault repository — staging sibling included — is refused BEFORE any
// side effect, with the typed ErrVaultOverlap.
func TestOpenRefusesDestinationInsideVaultRepository(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	if err := os.MkdirAll(f.vault.RepoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(f.vault.RepoDir, "restored-ws")
	o, err := New(Dependencies{Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink})
	if err != nil {
		t.Fatal(err)
	}
	_, oerr := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest, FilesOnly: true})
	var overlap *ErrVaultOverlap
	if !errors.As(oerr, &overlap) {
		t.Fatalf("open into the vault repository must fail with ErrVaultOverlap, got %v", oerr)
	}
	if _, serr := os.Lstat(dest); serr == nil {
		t.Fatalf("something was published at %s despite the overlap refusal", dest)
	}
	des, _ := os.ReadDir(f.vault.RepoDir)
	for _, de := range des {
		if strings.HasPrefix(de.Name(), stagePrefix) {
			t.Fatalf("staging leftover %s inside the vault repository despite the refusal", de.Name())
		}
	}
}

// TestCheckVaultOverlapDirections covers every direction of the overlap
// rule as a unit: clean layout passes; destination inside the repo,
// destination containing the repo, and destination containing the
// passfile are each refused.
func TestCheckVaultOverlapDirections(t *testing.T) {
	base := t.TempDir()
	repo := filepath.Join(base, "vault", "repo")
	pass := filepath.Join(base, "vault", "pass.txt")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pass, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	v := VaultRef{RepoDir: repo, Passfile: pass}

	if err := checkVaultOverlap(filepath.Join(base, "ws"), v); err != nil {
		t.Fatalf("clean layout must pass: %v", err)
	}
	var overlap *ErrVaultOverlap
	if err := checkVaultOverlap(filepath.Join(repo, "ws"), v); !errors.As(err, &overlap) {
		t.Fatalf("dest inside repo: want ErrVaultOverlap, got %v", err)
	}
	outer := filepath.Join(base, "outer")
	if err := os.MkdirAll(filepath.Join(outer, "vault", "repo"), 0o700); err != nil {
		t.Fatal(err)
	}
	v2 := VaultRef{RepoDir: filepath.Join(outer, "vault", "repo"), Passfile: pass}
	if err := checkVaultOverlap(outer, v2); !errors.As(err, &overlap) {
		t.Fatalf("dest containing repo: want ErrVaultOverlap, got %v", err)
	}
	if err := checkVaultOverlap(base, VaultRef{RepoDir: filepath.Join(base, "other-repo"), Passfile: pass}); !errors.As(err, &overlap) {
		t.Fatalf("dest containing passfile: want ErrVaultOverlap, got %v", err)
	}
}
