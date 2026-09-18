// wave_h_test.go: `ebb init --rebuild-catalog` over the eHarness
// fake-store world (acceptance gate F39): park → simulated catalog loss
// (delete catalog.db in the state dir) → rebuild → status/open round
// trip, the non-empty-catalog refusal + forced merge, the no-vault
// blocker, and the tampered-seal refusal posture (suspicious pair not
// adopted; payload kept unsealed-and-pinned; forget refuses it).

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/vault"
)

// parkH parks the harness workspace with the flag writer assertion and
// returns the pre-loss snapshot row (read through a promptly closed
// handle so the file can be deleted right after).
func parkH(t *testing.T, h *eHarness) catalog.Snapshot {
	t.Helper()
	code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("park code = %d, stderr = %s", code, stderr)
	}
	cat, err := catalog.Open(filepath.Join(h.stateDir, vault.CatalogFile))
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	defer cat.Close()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces = %+v (%v)", wss, err)
	}
	snaps, err := cat.ListSnapshots(wss[0].ID)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snapshots = %+v (%v)", snaps, err)
	}
	return snaps[0]
}

// loseCatalog closes nothing (each Main invocation closed its session)
// and deletes the catalog file: the F39 loss simulation.
func loseCatalog(t *testing.T, h *eHarness) {
	t.Helper()
	if err := os.Remove(filepath.Join(h.stateDir, vault.CatalogFile)); err != nil {
		t.Fatalf("delete catalog.db: %v", err)
	}
}

// rebuildEnvelope decodes the rebuild details from a --json run.
func rebuildEnvelope(t *testing.T, stdout string) map[string]any {
	t.Helper()
	env := envelopeOf(t, stdout)
	det, ok := env["details"].(map[string]any)
	if !ok {
		t.Fatalf("details = %#v", env["details"])
	}
	return det
}

func TestInitRebuildCatalogAfterLoss(t *testing.T) {
	h := newEHarness(t)
	pre := parkH(t, h)
	loseCatalog(t, h)

	code, stdout, stderr := h.run("init", "--rebuild-catalog", "--json")
	if code != ExitOK {
		t.Fatalf("rebuild code = %d, stderr = %s", code, stderr)
	}
	det := rebuildEnvelope(t, stdout)
	if env := envelopeOf(t, stdout); env["outcome"] != "ok" {
		t.Fatalf("outcome = %v", env["outcome"])
	}
	wss := det["workspaces"].([]any)
	if len(wss) != 1 {
		t.Fatalf("workspaces = %v", wss)
	}
	w := wss[0].(map[string]any)
	if w["status"] != "UNBOUND" || w["name"] != "cliws" {
		t.Errorf("rebuilt workspace row = %v (name/status)", w)
	}
	if got := det["snapshots_adopted"].(float64); got != 1 {
		t.Errorf("snapshots_adopted = %v, want 1", got)
	}

	// The rebuilt row is a full D017 witness: same logical id, backend
	// pair and digests as before the loss; pinned with a discovered:
	// reason; workspace UNBOUND with no root (never a guessed status).
	cat := h.cat()
	ws, err := cat.GetWorkspace(domain.WorkspaceID(w["id"].(string)))
	if err != nil || ws.Status != catalog.WorkspaceUnbound || ws.RootPath != "" {
		t.Fatalf("workspace row = %+v (%v)", ws, err)
	}
	snaps, err := cat.ListSnapshots(ws.ID)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snapshots = %+v (%v)", snaps, err)
	}
	got := snaps[0]
	if got.ID != pre.ID || got.SealBackendID != pre.SealBackendID ||
		got.PayloadBackendID != pre.PayloadBackendID ||
		got.ManifestDigest != pre.ManifestDigest || got.InventoryDigest != pre.InventoryDigest {
		t.Errorf("rebuilt row %+v differs from pre-loss %+v", got, pre)
	}
	if !got.Pinned || got.Kind != catalog.SnapshotKindPark {
		t.Errorf("rebuilt row pinned/kind = %v/%s", got.Pinned, got.Kind)
	}
	foundDiscovered := false
	for _, r := range got.PinReasons {
		if strings.HasPrefix(r, "discovered:") {
			foundDiscovered = true
		}
	}
	if !foundDiscovered {
		t.Errorf("pin reasons = %v, want a discovered:<date> entry", got.PinReasons)
	}

	// The product WORKS after a rebuild: status lists the UNBOUND
	// workspace; open selects per D011 and restores to a named
	// destination (UNBOUND has no root path, so --to is required).
	code, _, stderr = h.run("status")
	if code != ExitOK || !strings.Contains(stderr, "UNBOUND") || !strings.Contains(stderr, "cliws") {
		t.Fatalf("status code = %d stderr = %s", code, stderr)
	}
	// open without --to is a usage error from UNBOUND state (checked
	// before the successful open occupies the path).
	code, _, stderr = h.run("open", "cliws", "--files-only")
	if code != ExitUsage || !strings.Contains(stderr, CodeOpenNoDestination) {
		t.Fatalf("open without --to code = %d stderr = %s", code, stderr)
	}
	code, _, stderr = h.run("open", "cliws", "--to", h.wsRoot, "--files-only")
	if code != ExitOK {
		t.Fatalf("open after rebuild code = %d, stderr = %s", code, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(h.wsRoot, "notes.md")); err != nil || !strings.Contains(string(b), "private notes") {
		t.Fatalf("restored notes.md missing/damaged: %v", err)
	}
}

func TestInitRebuildRefusesNonEmptyCatalogThenForcedMerge(t *testing.T) {
	h := newEHarness(t)
	parkH(t, h) // catalog intact and non-empty

	code, _, stderr := h.run("init", "--rebuild-catalog")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeRebuildNeedsForce, "--force-rebuild")

	code, stdout, stderr := h.run("init", "--rebuild-catalog", "--force-rebuild", "--json")
	if code != ExitOK {
		t.Fatalf("forced rebuild code = %d, stderr = %s", code, stderr)
	}
	det := rebuildEnvelope(t, stdout)
	if got := det["duplicates"].(float64); got != 1 {
		t.Errorf("duplicates = %v, want 1 (merge-discover reports, never drops)", got)
	}
	// The workspace row was NOT re-guessed: still live with its root.
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces = %+v (%v)", wss, err)
	}
	if wss[0].Status != catalog.WorkspaceParked || wss[0].RootPath != "" {
		t.Errorf("forced merge overwrote workspace identity: %+v", wss[0])
	}
}

func TestInitRebuildNeedsVault(t *testing.T) {
	h := newEHarness(t)
	if err := os.Remove(filepath.Join(h.stateDir, vault.RegistryFile)); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("init", "--rebuild-catalog")
	if code != ExitVault {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitVault, stderr)
	}
	assertBlocker(t, stderr, CodeNoVault, "`ebb init`")
}

func TestInitRebuildFlagsDiscipline(t *testing.T) {
	h := newEHarness(t)
	// --force-rebuild without --rebuild-catalog is a usage mistake.
	if code, _, _ := h.run("init", "--force-rebuild"); code != ExitUsage {
		t.Fatalf("force without rebuild code = %d, want %d", code, ExitUsage)
	}
}

// TestInitRebuildTamperedSealRefusedNotAdopted: a seal whose receipt
// digests do not match the payload's actual document bytes (the D017
// tamper shape) is refused as suspicious; the payload stays as an
// unsealed-and-pinned row (§11.3) that forget refuses and open never
// selects. Nothing is deleted from the vault.
func TestInitRebuildTamperedSealRefusedNotAdopted(t *testing.T) {
	h := newEHarness(t)
	pre := parkH(t, h)

	// Tamper: flip one manifest-digest nibble inside the stored receipt.
	tampered := 0
	for id, snap := range h.store.snaps {
		if h.store.tags[id]["ebb-kind"] != "seal" {
			continue
		}
		for path, raw := range snap.files {
			if strings.HasSuffix(path, "/receipt.json") {
				forged := strings.Replace(string(raw), pre.ManifestDigest[:8], "00000000", 1)
				if forged == string(raw) {
					t.Fatalf("receipt tamper no-op:\n%s", raw)
				}
				snap.files[path] = []byte(forged)
				tampered++
			}
		}
	}
	if tampered != 1 {
		t.Fatalf("tampered %d receipts, want 1", tampered)
	}
	loseCatalog(t, h)

	code, stdout, stderr := h.run("init", "--rebuild-catalog", "--json")
	if code != ExitOK {
		t.Fatalf("rebuild code = %d, stderr = %s", code, stderr)
	}
	det := rebuildEnvelope(t, stdout)
	if got := det["snapshots_adopted"].(float64); got != 0 {
		t.Errorf("snapshots_adopted = %v, want 0 (tampered pair must not be adopted)", got)
	}
	if sus := det["suspicious_refused"].([]any); len(sus) != 1 {
		t.Fatalf("suspicious = %v", sus)
	} else if reasons := sus[0].(map[string]any)["reasons"].([]any); len(reasons) == 0 {
		t.Error("suspicious finding carries no reasons")
	}
	if un := det["unsealed_payloads"].([]any); len(un) != 1 {
		t.Fatalf("unsealed = %v, want the payload kept unsealed-and-pinned", un)
	}

	// The payload row exists, is pinned, has NO seal id, and neither
	// forget nor open-selection will touch it.
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces = %+v (%v)", wss, err)
	}
	if wss[0].Status != catalog.WorkspaceUnbound {
		t.Errorf("workspace status = %s, want UNBOUND", wss[0].Status)
	}
	snaps, err := cat.ListSnapshots(wss[0].ID)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snapshots = %+v (%v)", snaps, err)
	}
	s := snaps[0]
	if !s.Pinned || s.SealBackendID != "" {
		t.Errorf("unsealed row = %+v, want pinned with empty seal id", s)
	}
	code, _, stderr = h.run("forget", string(s.ID), "--yes")
	if code != ExitBlocked || !strings.Contains(stderr, CodeForgetUnsealed) {
		t.Fatalf("forget unsealed code = %d stderr = %s", code, stderr)
	}
	code, _, stderr = h.run("open", "cliws", "--to", filepath.Join(t.TempDir(), "x"), "--files-only")
	if code != ExitBlocked || !strings.Contains(stderr, CodeOpenUnknownTarget) {
		t.Fatalf("open unsealed code = %d stderr = %s", code, stderr)
	}
	// The vault still holds every backend snapshot (retain, never delete).
	if len(h.store.snaps) != 2 {
		t.Errorf("backend snapshots = %d, want 2 (payload+seal retained)", len(h.store.snaps))
	}
}

// ---- doctor: the F39 hint ---------------------------------------------

// TestDoctorCatalogCheck exercises the catalog/vault-registry hint
// directly (cheap local reads only — the check never touches a backend).
func TestDoctorCatalogCheck(t *testing.T) {
	// Missing catalog, no vaults: healthy fresh install, no hint.
	dir := t.TempDir()
	if c := catalogCheck(dir); c.Status != "pass" {
		t.Errorf("empty state check = %+v, want pass", c)
	}

	// Missing catalog + registered vault: the F39 signature.
	reg := filepath.Join(dir, vault.RegistryFile)
	if _, err := vault.New(reg).Register("main", filepath.Join(dir, "repo"), ""); err != nil {
		t.Fatal(err)
	}
	c := catalogCheck(dir)
	if c.Status != "warn" || !strings.Contains(c.Detail, "ebb init --rebuild-catalog") {
		t.Errorf("missing-catalog hint = %+v", c)
	}

	// Catalog with rows + vault: pass with counts.
	cat, err := catalog.Open(filepath.Join(dir, vault.CatalogFile))
	if err != nil {
		t.Fatal(err)
	}
	wsID := domain.WorkspaceID(domain.NewID())
	if err := cat.UpsertWorkspace(catalog.Workspace{ID: wsID, Name: "drcat", CreatedAt: "2026-09-19T00:00:00Z", Status: catalog.WorkspaceLive, RootPath: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.RecordSnapshot(catalog.Snapshot{WorkspaceID: wsID, Kind: catalog.SnapshotKindSnapshot}); err != nil {
		t.Fatal(err)
	}
	if err := cat.Close(); err != nil {
		t.Fatal(err)
	}
	if c := catalogCheck(dir); c.Status != "pass" || !strings.Contains(c.Detail, "1 snapshot") {
		t.Errorf("populated-catalog check = %+v", c)
	}
}
