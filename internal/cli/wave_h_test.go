// wave_h_test.go: `ebb init --rebuild-catalog` over the eHarness
// fake-store world (acceptance gate F39): park → simulated catalog loss
// (delete catalog.db in the state dir) → rebuild → status/open round
// trip, the non-empty-catalog refusal + forced merge, the no-vault
// blocker, and the tampered-seal refusal posture (suspicious pair not
// adopted; payload kept unsealed-and-pinned; forget refuses it).

package cli

import (
	"context"
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

	// The product WORKS after a rebuild: the catalog lists the UNBOUND
	// workspace (direct read; `ebb status` is the stats dashboard since
	// Wave 3); open selects per D011 and restores to a named
	// destination (UNBOUND has no root path, so --to is required).
	if w := h.workspaceRowOf("cliws"); w.Status != catalog.WorkspaceUnbound {
		t.Fatalf("rebuilt workspace status = %s, want UNBOUND", w.Status)
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

	// A catalog holding ONLY docker_images freeze rows is NOT a lost
	// catalog (W2-4 regression: the heuristic used to fire on
	// workspaces==0 alone and point at --rebuild-catalog, which can
	// never reconstruct freeze records). The rows are reported present.
	fdir := t.TempDir()
	if _, err := vault.New(filepath.Join(fdir, vault.RegistryFile)).Register("main", filepath.Join(fdir, "repo"), ""); err != nil {
		t.Fatal(err)
	}
	fcat, err := catalog.Open(filepath.Join(fdir, vault.CatalogFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fcat.RecordDockerImage(catalog.DockerImage{
		ImageID:    "sha256:" + strings.Repeat("ab", 32),
		SnapshotID: strings.Repeat("c", 64),
		Filename:   "docker-image-frozen.tar",
		SHA256:     strings.Repeat("d", 64),
		Bytes:      4096,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fcat.Close(); err != nil {
		t.Fatal(err)
	}
	c = catalogCheck(fdir)
	if c.Status != "pass" || strings.Contains(c.Detail, "catalog was lost") {
		t.Errorf("freeze-only catalog check = %+v, want pass without the lost-catalog warning", c)
	}
	if !strings.Contains(c.Detail, "frozen docker image") {
		t.Errorf("freeze-only detail does not report the freeze rows: %+v", c)
	}
}

// TestInitRebuildReportsFreezeSnapshotsNotRebuildable: after a catalog
// loss, a freeze-tagged vault snapshot (ebb:v1 + op:freeze, the tags
// `ebb freeze`'s BackupStdin writes) must be retained and honestly
// reported — classified by name, never reconstructed into docker_images
// rows (the freeze record's image id, digest and filename live only in
// the lost catalog), never silently counted as unrecognized (W2-4).
func TestInitRebuildReportsFreezeSnapshotsNotRebuildable(t *testing.T) {
	h := newEHarness(t)
	parkH(t, h)

	// A freeze blob in the same vault. The tree bytes are irrelevant —
	// only the tags classify it; they mirror encodeTags' output around
	// the freezer's op/image tags. (The blob gets its own fixture dir:
	// the park above removed the workspace root.)
	freezeSrc := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(freezeSrc, []byte("pretend docker-save stream\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	freezeTags := map[string]string{"ebb": "v1", "op": "freeze", "image": "sha256_frozenimage"}
	ref, err := h.store.Snapshot(context.Background(), "", filepath.Dir(freezeSrc),
		[]string{filepath.Base(freezeSrc)}, "", freezeTags)
	if err != nil {
		t.Fatalf("freeze blob snapshot: %v", err)
	}
	loseCatalog(t, h)

	code, stdout, stderr := h.run("init", "--rebuild-catalog", "--json")
	if code != ExitOK {
		t.Fatalf("rebuild code = %d, stderr = %s", code, stderr)
	}
	det := rebuildEnvelope(t, stdout)
	if got := det["snapshots_adopted"].(float64); got != 1 {
		t.Errorf("snapshots_adopted = %v, want 1 (the park pair only)", got)
	}
	if got := det["freeze_images_retained"].(float64); got != 1 {
		t.Errorf("freeze_images_retained = %v, want 1", got)
	}
	if got := det["unrecognized_snapshots"].(float64); got != 0 {
		t.Errorf("unrecognized_snapshots = %v, want 0 (the freeze blob is classified, not unknown)", got)
	}

	// Nothing was fabricated: the rebuilt catalog holds the workspace
	// pair but ZERO docker_images rows.
	ct, err := h.cat().Counts()
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if ct.DockerImages != 0 {
		t.Errorf("rebuilt catalog fabricated %d docker_images row(s)", ct.DockerImages)
	}
	// And the blob itself is retained untouched in the vault.
	if _, ok := h.store.snaps[ref.BackendID]; !ok {
		t.Fatal("the freeze blob was deleted from the vault")
	}
}

// TestRenderRebuildHumanNamesFreezeLimits pins the report wording: the
// freeze line must say retained + not rebuildable + the true follow-up
// command, never a command that does not exist.
func TestRenderRebuildHumanNamesFreezeLimits(t *testing.T) {
	d := rebuildDetails{FreezeImagesRetained: 2, NextStep: rebuildNextStep(rebuildDetails{FreezeImagesRetained: 2})}
	out := renderRebuildHuman(d)
	for _, want := range []string{
		"2 frozen docker-image snapshot(s) retained in the vault",
		"cannot be rebuilt from the snapshots",
		"`ebb freeze <image-id>`",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rebuild report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--list") {
		t.Errorf("rebuild report points at a nonexistent list command:\n%s", out)
	}
	next := rebuildNextStep(d)
	if !strings.Contains(next, "freeze records are not rebuildable") {
		t.Errorf("next step lacks the honest freeze note: %s", next)
	}
}
