package lifecycle

// Scenario: acceptance gate F39 against the REAL restic backend —
// park → simulated CATALOG LOSS (catalog.db deleted; the vault and its
// secret remain) → rebuild through restore.DiscoverVault +
// catalog.ImportDiscoveredSnapshot (the exact seam `ebb init
// --rebuild-catalog` drives) → the rebuilt rows are asserted equal to
// the pre-loss rows (modulo pin audit) → an open round trip runs
// against the REBUILT catalog, proving the re-derived digests are valid
// D017 witnesses (loadSeal cross-checks the receipt against the row) →
// a forged seal snapshot planted in the vault with a mismatching digest
// is refused as suspicious → a seal forgotten out from under a payload
// leaves it unsealed-and-pinned (§11.3).

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/policy"
	"ebb/internal/restore"
)

// loseCatalog closes every catalog handle the env opened and deletes
// the database file: the F39 loss simulation. Later newCat/coord calls
// recreate an empty catalog exactly like a fresh CLI session would.
func (e *e2eEnv) loseCatalog(t *testing.T) {
	e.t.Helper()
	for _, cat := range e.opened {
		if err := cat.Close(); err != nil {
			t.Fatalf("close catalog handle before loss simulation: %v", err)
		}
	}
	e.opened = nil
	if err := os.Remove(e.catPath); err != nil {
		t.Fatalf("delete catalog.db: %v", err)
	}
}

// rebuildFromVault mirrors the CLI's `ebb init --rebuild-catalog` flow
// over this env: repository id, vault row (lifecycle's own derivation),
// discovery, additive imports. Returns the discovery report.
func (e *e2eEnv) rebuildFromVault(t *testing.T) *restore.VaultDiscovery {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	repoID, err := e.store.RepoID(ctx, e.vault.RepoDir, e.vault.Passfile)
	if err != nil {
		t.Fatalf("repo id: %v", err)
	}
	disc, derr := restore.DiscoverVault(ctx, e.store, e.rvault(), repoID)
	if derr != nil {
		t.Fatalf("discover vault: %v", derr)
	}
	cat := e.newCat()
	// The vault row id MUST be lifecycle's own derivation (the test sits
	// in this package, so the authoritative function is used directly).
	vaultRowID := (&Coordinator{}).vaultIDFor(repoID, e.vault)
	if err := cat.RegisterVault(catalog.Vault{ID: vaultRowID, Path: e.vault.RepoDir, RepoID: repoID}); err != nil {
		t.Fatalf("register vault row: %v", err)
	}
	discovered := "discovered:" + time.Now().UTC().Format("2006-01-02")
	for _, p := range disc.Pairs {
		if err := cat.ImportDiscoveredSnapshot(p.WorkspaceID, p.WorkspaceName, catalog.Snapshot{
			ID: p.SnapshotID, CreatedAt: p.CreatedAt,
			PayloadBackendID: p.PayloadBackendID, SealBackendID: p.SealBackendID,
			VaultID: vaultRowID, ManifestDigest: p.ManifestDigest,
			InventoryDigest: p.InventoryDigest, Kind: p.Kind,
			PinReasons: []string{discovered},
		}); err != nil {
			t.Fatalf("import discovered snapshot %s: %v", p.SnapshotID, err)
		}
	}
	for _, u := range disc.Unsealed {
		if err := cat.ImportDiscoveredSnapshot(u.WorkspaceID, u.WorkspaceName, catalog.Snapshot{
			ID: u.SnapshotID, CreatedAt: u.CreatedAt,
			PayloadBackendID: u.PayloadBackendID,
			VaultID:          vaultRowID, ManifestDigest: u.ManifestDigest,
			InventoryDigest: u.InventoryDigest, Kind: u.Kind,
			PinReasons: []string{discovered + ":unsealed"},
		}); err != nil {
			t.Fatalf("record unsealed payload %s: %v", u.PayloadBackendID, err)
		}
	}
	return disc
}

func TestE2EResticCatalogRebuildAfterLoss(t *testing.T) {
	e := newE2EEnv(t)
	root := e.buildMainWorkspace(t)
	ws := newWSID()
	pol, err := policy.Parse([]byte(e2eMainPolicyTOML))
	if err != nil {
		t.Fatalf("parse Ebbfile: %v", err)
	}
	before := e2eWalkTree(t, root)
	wantPreserved := map[string]e2eNode{}
	for p, n := range before {
		if !e2eIsGenOmitted(p) {
			wantPreserved[p] = n
		}
	}

	// Park through the real backend; snapshot the pre-loss row.
	ctx, cancel := e.opCtx()
	defer cancel()
	if _, perr := e.coord(nil).Park(ctx, e.vault, root, CaptureOptions{
		WorkspaceName:   "e2e-main",
		WorkspaceID:     ws,
		Policy:          pol,
		Park:            true,
		WriterAssertion: "e2e-acceptance: writers asserted stopped",
	}); perr != nil {
		t.Fatalf("park: %v", perr)
	}
	preLossCat := e.newCat()
	preRows, err := preLossCat.ListSnapshots(ws)
	if err != nil || len(preRows) != 1 {
		t.Fatalf("pre-loss snapshot rows = %+v (%v)", preRows, err)
	}
	pre := preRows[0]
	if pre.Kind != catalog.SnapshotKindPark || !pre.Pinned {
		t.Fatalf("pre-loss row = %+v, want pinned park kind", pre)
	}

	// ---- catalog loss ---------------------------------------------------
	e.loseCatalog(t)

	// ---- rebuild --------------------------------------------------------
	disc := e.rebuildFromVault(t)
	if len(disc.Pairs) != 1 || len(disc.Unsealed) != 0 || len(disc.Suspicious) != 0 {
		t.Fatalf("discovery = %+v", disc)
	}
	pair := disc.Pairs[0]
	if pair.Kind != catalog.SnapshotKindPark {
		t.Errorf("derived kind = %s, want park (stopped-writers-asserted contract)", pair.Kind)
	}
	// §16.5: the reconstructed workspace is UNBOUND with the payload tree
	// prefix as its name — never a guessed live/parked.
	if pair.WorkspaceName != "ws-main" {
		t.Errorf("workspace name = %q, want the payload tree prefix ws-main", pair.WorkspaceName)
	}
	cat := e.newCat()
	w, err := cat.GetWorkspace(ws)
	if err != nil || w.Status != catalog.WorkspaceUnbound || w.RootPath != "" {
		t.Fatalf("rebuilt workspace = %+v (%v)", w, err)
	}
	rows, err := cat.ListSnapshots(ws)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rebuilt rows = %+v (%v)", rows, err)
	}
	got := rows[0]
	if got.ID != pre.ID || got.PayloadBackendID != pre.PayloadBackendID ||
		got.SealBackendID != pre.SealBackendID ||
		got.ManifestDigest != pre.ManifestDigest || got.InventoryDigest != pre.InventoryDigest {
		t.Errorf("rebuilt row %+v differs from pre-loss %+v", got, pre)
	}
	if !got.Pinned {
		t.Error("rebuilt snapshot not pinned (I07: discovery must assume obligation)")
	}
	foundDiscovered := false
	for _, r := range got.PinReasons {
		if strings.HasPrefix(r, "discovered:") {
			foundDiscovered = true
		}
	}
	if !foundDiscovered {
		t.Errorf("pin reasons = %v, want discovered:<date>", got.PinReasons)
	}

	// The rebuilt row is a VALID D017 witness: verify's evidence loader
	// (which cross-checks the receipt against the row's seal-time
	// digests) runs clean over it.
	ev, everr := restore.LoadRetainedEvidence(context.Background(), e.store, e.rvault(), got.ID, got)
	if everr != nil {
		t.Fatalf("retained evidence over the rebuilt row: %v", everr)
	}
	if ev.Manifest.ManifestDigest != pre.ManifestDigest || ev.PreservedEntries == 0 {
		t.Errorf("evidence = %+v", ev.Manifest)
	}

	// ---- open round trip against the REBUILT catalog --------------------
	dest := filepath.Join(t.TempDir(), "ws-main-restored")
	ores, oerr := e.opener().Open(context.Background(), e.rvault(), got.ID, restore.Options{
		Destination: dest, FilesOnly: true,
	})
	if oerr != nil {
		t.Fatalf("open after rebuild: %v", oerr)
	}
	if ores.WorkspaceID != ws || ores.SnapshotID != got.ID {
		t.Errorf("open result identity = %+v", ores)
	}
	e2eSameTree(t, wantPreserved, e2eWalkTree(t, dest))
}

// TestE2EResticRebuildRefusesForgedSeal: a second seal-shaped snapshot
// planted in the vault with a receipt whose manifest digest does not
// match the payload's actual bytes (what a vault-password attacker can
// mint) is refused as suspicious; the genuine pair is still adopted and
// the logical snapshot id appears exactly once.
func TestE2EResticRebuildRefusesForgedSeal(t *testing.T) {
	e := newE2EEnv(t)
	root := e.buildMainWorkspace(t)
	ws := newWSID()
	pol, err := policy.Parse([]byte(e2eMainPolicyTOML))
	if err != nil {
		t.Fatalf("parse Ebbfile: %v", err)
	}
	ctx, cancel := e.opCtx()
	defer cancel()
	parkRes, perr := e.coord(nil).Park(ctx, e.vault, root, CaptureOptions{
		WorkspaceName:   "e2e-main",
		WorkspaceID:     ws,
		Policy:          pol,
		Park:            true,
		WriterAssertion: "e2e-acceptance: writers asserted stopped",
	})
	if perr != nil {
		t.Fatalf("park: %v", perr)
	}

	// Plant the forged seal: the REAL receipt bytes with one digest
	// nibble flipped, captured as a fresh tagged seal snapshot (this is
	// exactly the write capability a vault-password attacker has).
	realSeal := parkRes.Snapshot.BackendIDs[1]
	ls, err := e.store.Ls(ctx, e.vault.RepoDir, e.vault.Passfile, realSeal)
	if err != nil {
		t.Fatalf("ls real seal: %v", err)
	}
	var receiptPath string
	for _, n := range ls {
		if n.Kind == domain.KindFile && strings.HasSuffix(n.Path, "/receipt.json") {
			receiptPath = n.Path
		}
	}
	if receiptPath == "" {
		t.Fatal("no receipt node in the real seal")
	}
	raw, err := e.store.DumpFile(ctx, e.vault.RepoDir, e.vault.Passfile, realSeal, receiptPath)
	if err != nil {
		t.Fatalf("dump real receipt: %v", err)
	}
	// The forged tree reuses the ORIGINAL op id (extracted from the real
	// receipt path) so the shape gate passes and the DIGEST gate is what
	// must refuse it; forgeReceipt then breaks the digest binding.
	opID := strings.TrimPrefix(filepath.Base(filepath.Dir(receiptPath)), ".ebb-seal-")
	forgeParent := t.TempDir()
	forgeDir := filepath.Join(forgeParent, ".ebb-seal-"+opID)
	if err := os.MkdirAll(forgeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	forgedBytes, ferr := forgeReceipt(raw)
	if ferr != nil {
		t.Fatal(ferr)
	}
	if err := os.WriteFile(filepath.Join(forgeDir, "receipt.json"), forgedBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Snapshot(ctx, e.vault.RepoDir, forgeParent,
		[]string{".ebb-seal-" + opID}, e.vault.Passfile,
		map[string]string{"ebb-op": opID, "ebb-kind": "seal", "ws": string(ws)}); err != nil {
		t.Fatalf("plant forged seal: %v", err)
	}

	e.loseCatalog(t)
	disc := e.rebuildFromVault(t)

	if len(disc.Pairs) != 1 {
		t.Fatalf("adopted pairs = %d, want exactly the genuine one (suspicious = %+v)", len(disc.Pairs), disc.Suspicious)
	}
	if disc.Pairs[0].SealBackendID != realSeal {
		t.Errorf("adopted seal = %s, want the genuine %s", disc.Pairs[0].SealBackendID, realSeal)
	}
	if len(disc.Suspicious) != 1 {
		t.Fatalf("suspicious = %+v, want the forged seal", disc.Suspicious)
	}
	joined := strings.Join(disc.Suspicious[0].Reasons, "; ")
	if !strings.Contains(joined, "does not match its seal") {
		t.Errorf("suspicious reasons = %q, want the digest mismatch", joined)
	}
	// The forged seal is RETAINED in the vault (repair mode; never
	// deleted by discovery).
	refs, err := e.store.List(ctx, e.vault.RepoDir, e.vault.Passfile)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, r := range refs {
		if r.Tags["ebb-kind"] == "seal" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("seal snapshots in vault = %d, want 2 (forged one retained)", count)
	}
}

// TestE2EResticRebuildUnsealedPayload: with the seal snapshot genuinely
// absent from the vault (forgotten out from under the payload — crash
// window, external interference, or a partial §16.6 flow), discovery
// records the payload unsealed-and-pinned from its own manifest (§11.3
// incomplete operation, not garbage): the row has no seal id, stays
// pinned, and no pair is adopted.
func TestE2EResticRebuildUnsealedPayload(t *testing.T) {
	e := newE2EEnv(t)
	root := e.buildMainWorkspace(t)
	ws := newWSID()
	pol, err := policy.Parse([]byte(e2eMainPolicyTOML))
	if err != nil {
		t.Fatalf("parse Ebbfile: %v", err)
	}
	ctx, cancel := e.opCtx()
	defer cancel()
	parkRes, perr := e.coord(nil).Park(ctx, e.vault, root, CaptureOptions{
		WorkspaceName:   "e2e-main",
		WorkspaceID:     ws,
		Policy:          pol,
		Park:            true,
		WriterAssertion: "e2e-acceptance: writers asserted stopped",
	})
	if perr != nil {
		t.Fatalf("park: %v", perr)
	}

	// Remove the seal snapshot from the vault (verified by List, per the
	// forget discipline — restic forget of a missing id is silent).
	sealID := parkRes.Snapshot.BackendIDs[1]
	if err := e.store.Forget(ctx, e.vault.RepoDir, e.vault.Passfile, []string{sealID}); err != nil {
		t.Fatalf("forget seal: %v", err)
	}
	refs, err := e.store.List(ctx, e.vault.RepoDir, e.vault.Passfile)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.BackendID == sealID {
			t.Fatal("seal still present after forget")
		}
	}

	e.loseCatalog(t)
	disc := e.rebuildFromVault(t)
	if len(disc.Pairs) != 0 {
		t.Fatalf("adopted pairs = %+v, want none (no seal exists)", disc.Pairs)
	}
	if len(disc.Unsealed) != 1 {
		t.Fatalf("unsealed = %+v, want the orphaned payload", disc.Unsealed)
	}
	u := disc.Unsealed[0]
	if u.PayloadBackendID != parkRes.Snapshot.BackendIDs[0] || u.Kind != catalog.SnapshotKindPark {
		t.Errorf("unsealed record = %+v", u)
	}

	// Catalog shape: pinned, NO seal backend id (the shape forget refuses
	// and open-selection skips), workspace UNBOUND.
	cat := e.newCat()
	w, err := cat.GetWorkspace(ws)
	if err != nil || w.Status != catalog.WorkspaceUnbound {
		t.Fatalf("workspace = %+v (%v)", w, err)
	}
	rows, err := cat.ListSnapshots(ws)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v (%v)", rows, err)
	}
	r := rows[0]
	if !r.Pinned || r.SealBackendID != "" || r.PayloadBackendID != u.PayloadBackendID {
		t.Errorf("unsealed row = %+v, want pinned with empty seal id", r)
	}
	if r.ManifestDigest != u.ManifestDigest {
		t.Errorf("row digest %s != computed %s", r.ManifestDigest, u.ManifestDigest)
	}
}

// forgeReceipt flips the manifest digest inside the real receipt bytes
// (64 'f' hex chars) so the forged seal names the REAL payload with a
// wrong binding — the digest re-derivation must catch exactly this.
func forgeReceipt(raw []byte) ([]byte, error) {
	var m struct {
		ManifestDigest string `json:"manifest_digest"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.ManifestDigest == "" {
		return nil, errors.New("receipt carries no manifest digest")
	}
	return []byte(strings.Replace(string(raw), m.ManifestDigest, strings.Repeat("f", 64), 1)), nil
}
