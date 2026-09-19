// wave_j_regression_test.go — default-suite regressions for the Wave J
// security fixes (lab/security-review/wave-J/FINDINGS.md): the crashed
// capsule-transport operations are closable with `recover --cancel`
// (J1/J1b), the export's one-time passphrase survives post-publication
// bookkeeping failures as a warning on a success (J2), a failed import
// registration rolls the copied pair back List-verified instead of
// orphaning it (J3), a forced rebuild surfaces a divergent pair as a
// suspicious finding without touching the intact row (J4), and forget's
// last-recovery-copy guard covers UNBOUND workspaces (J8).
//
// The fault helpers (jStore, jLockCatalog) live here untagged so both
// this suite and the security_poc PoCs drive the same interpositions.

package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/vault"

	_ "modernc.org/sqlite"
)

// jStore wraps the Wave H disk-backed fake store with a DumpFile hook,
// so a test can interpose at an exact backend call without modifying the
// shared harness. Every other method (including the capsule Copy seam)
// is promoted from *hStore.
type jStore struct {
	*hStore
	onDumpFile func(repoDir, snapID, path string)
}

func (s *jStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	if s.onDumpFile != nil {
		s.onDumpFile(repoDir, snapID, path)
	}
	return s.hStore.DumpFile(ctx, repoDir, passfile, snapID, path)
}

// jLockCatalog takes an EXCLUSIVE sqlite transaction on the catalog file
// through a second connection and holds it until release. Every write on
// the session's own connection then fails deterministically after its
// busy_timeout — the controlled "catalog just broke" failure the J2/J3
// orderings need, without corrupting anything.
func jLockCatalog(t *testing.T, path string) (release func()) {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(500)")
	if err != nil {
		t.Fatalf("J lock: open: %v", err)
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatalf("J lock: conn: %v", err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN EXCLUSIVE"); err != nil {
		t.Fatalf("J lock: begin exclusive: %v", err)
	}
	return func() {
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		_ = conn.Close()
		_ = db.Close()
	}
}

// ---- J1/J1b: recover --cancel closes a crashed export op + releases pin --

// TestRecoverCancelClosesCrashedExportAndReleasesPin simulates the
// durable state a hard crash mid-export leaves (op active at
// EXPORT_COPYING with the duration pin taken) and proves the escape
// hatch: `ebb recover <op> --cancel` closes the op to CANCELED,
// releases the duration pin AUDIT-ONLY (the snapshot keeps its own
// pinned state, I07), and unblocks the workspace for new captures —
// with no manual catalog surgery.
func TestRecoverCancelClosesCrashedExportAndReleasesPin(t *testing.T) {
	h := newHHarness(t)
	snap := h.captureSnapshot(t)

	// The crash state: the journal row is active at EXPORT_COPYING and
	// the export's duration pin was taken.
	cat := h.cat()
	opID, err := cat.BeginOperation(snap.WorkspaceID, catalog.OpKindExport, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]string{
		{catalog.PhasePlanned, catalog.PhaseExportPlanned},
		{catalog.PhaseExportPlanned, catalog.PhaseExportCopying},
	} {
		if err := cat.AdvanceOperation(opID, step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := cat.Pin(snap.ID, "export:"+string(opID)); err != nil {
		t.Fatal(err)
	}

	// Plain recover is report-only and advises the closing verb.
	code, stdout, stderr := h.run("recover", string(opID), "--json")
	if code != ExitOK {
		t.Fatalf("plain recover exit = %d: %s %s", code, stdout, stderr)
	}
	det := envelopeOf(t, stdout)["details"].(map[string]any)
	if det["phase_after"] != catalog.PhaseExportCopying {
		t.Fatalf("plain recover changed the phase: %v", det["phase_after"])
	}
	if na, _ := det["next_action"].(string); !strings.Contains(na, "--cancel") {
		t.Fatalf("plain recover next_action = %q, want --cancel advice", na)
	}

	// The cancel closes the op and releases the pin audit-only.
	code, stdout, stderr = h.run("recover", string(opID), "--cancel")
	if code != ExitOK {
		t.Fatalf("recover --cancel exit = %d: %s %s", code, stdout, stderr)
	}
	cat2 := h.cat()
	op, err := cat2.GetOperation(opID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Phase != catalog.PhaseCanceled {
		t.Fatalf("op phase = %s, want CANCELED", op.Phase)
	}
	if active, err := cat2.ActiveOperations(""); err != nil || len(active) != 0 {
		t.Fatalf("active ops after cancel = %v (%v), want none", active, err)
	}
	fresh, err := cat2.GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	sawRelease := false
	for _, r := range fresh.PinReasons {
		if r == "unpin:export:"+string(opID) {
			sawRelease = true
		}
	}
	if !sawRelease {
		t.Fatalf("duration pin not released by cancel (audit: %v)", fresh.PinReasons)
	}
	if !fresh.Pinned {
		t.Error("cancel dropped the snapshot's own pinned flag (I07 violation)")
	}

	// The workspace accepts new captures again (the F37 block is gone).
	code, _, stderr = h.run("snapshot", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("a new snapshot was refused after cancel (code %d): %s", code, stderr)
	}

	// The close is idempotent (a crash between the CAS commit and the
	// report must not brick the verb).
	code, _, _ = h.run("recover", string(opID), "--cancel")
	if code != ExitOK {
		t.Fatalf("idempotent cancel rerun failed (code %d)", code)
	}
}

// ---- J2: export bookkeeping failure after publish = warning on success --

// TestExportBookkeepingFailureAfterPublishIsWarningWithPassphrase locks
// the catalog exactly after the transport's last catalog-free stretch
// begins (the extracted-seal re-read): the capsule still publishes, and
// the failing bookkeeping (replica row, pin release, DONE close) must
// surface as WARNINGS on a SUCCESS — with the one-time passphrase
// already displayed, never destroyed, and never in the JSON envelope.
func TestExportBookkeepingFailureAfterPublishIsWarningWithPassphrase(t *testing.T) {
	h := newHHarness(t)
	js := &jStore{hStore: h.store}
	h.deps.NewStore = func() (domain.SnapshotStore, func(), error) { return js, func() {}, nil }
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "capsule.ebb")
	catPath := filepath.Join(h.stateDir, vault.CatalogFile)

	unlock := func() {}
	armed := true
	js.onDumpFile = func(repoDir, _, path string) {
		if armed && strings.HasSuffix(filepath.ToSlash(repoDir), "/extracted") && strings.Contains(path, ".ebb-seal-") {
			armed = false
			unlock = jLockCatalog(t, catPath)
		}
	}
	defer func() { unlock() }()

	code, stdout, stderr := h.run("export", "--json", string(snap.ID), "--output", out)
	unlock()
	if code != ExitOK {
		t.Fatalf("export exit = %d after a post-publication bookkeeping failure, want 0 (warning on success): %s %s", code, stdout, stderr)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("capsule missing at the final path: %v", err)
	}
	if _, err := os.Stat(out + ".partial"); err == nil {
		t.Error("a .partial coexists with the published capsule")
	}

	// The passphrase was displayed exactly once, terminal-only.
	if !strings.Contains(stderr, "CAPSULE PASSPHRASE") {
		t.Fatalf("stderr lacks the passphrase block:\n%s", stderr)
	}
	secret := passphraseOfBlock(stderr)
	if secret == "" {
		t.Fatal("no passphrase parsed from the block")
	}
	if strings.Contains(stdout, secret) {
		t.Fatal("the passphrase leaked into the JSON envelope")
	}
	if strings.Count(stderr, secret) != 1 {
		t.Errorf("passphrase printed %d times, want 1", strings.Count(stderr, secret))
	}

	// Success outcome carrying warnings that disclose the complete
	// capsule at the final path.
	env := envelopeOf(t, stdout)
	if env["outcome"] != "ok" {
		t.Fatalf("envelope outcome = %v, want ok", env["outcome"])
	}
	warnings, _ := env["warnings"].([]any)
	disclosed := false
	for _, w := range warnings {
		if ws, _ := w.(string); strings.Contains(ws, "COMPLETE capsule") && strings.Contains(ws, out) {
			disclosed = true
		}
	}
	if !disclosed {
		t.Fatalf("no warning discloses the complete capsule at %s (warnings: %v)", out, warnings)
	}

	// The warned-about leftovers reconcile with the cancel verb.
	cat := h.cat()
	ops := exportOpsOf(t, cat, snap.WorkspaceID)
	if len(ops) != 1 || ops[0].Phase != catalog.PhaseExportVerifying {
		t.Fatalf("export ops = %+v, want one active at EXPORT_VERIFYING", ops)
	}
	if code, _, _ = h.run("recover", string(ops[0].ID), "--cancel"); code != ExitOK {
		t.Fatalf("recover --cancel failed (code %d)", code)
	}
	if active, _ := h.cat().ActiveOperations(""); len(active) != 0 {
		t.Fatalf("active ops after cancel: %v", active)
	}
}

// ---- J3: import registration failure rolls the copied pair back ---------

// TestImportRegistrationFailureRollsBackCopiedPair locks the catalog at
// the import transport's last backend call (the local seal's readback):
// the transport has copied the payload+seal pair, and the CLI-side
// registration then fails — the pair must be forgotten and List-verified
// gone (no orphans), the failure must say so, and after closing the
// stuck op the rerun copies one fresh pair into the clean vault.
func TestImportRegistrationFailureRollsBackCopiedPair(t *testing.T) {
	capPath, secret, snap := exportCapsuleOf(t)
	ih := newImportHarness(t)
	js := &jStore{hStore: ih.store}
	ih.deps.NewStore = func() (domain.SnapshotStore, func(), error) { return js, func() {}, nil }
	t.Setenv(EnvCapsulePassword, secret)

	catPath := filepath.Join(ih.stateDir, vault.CatalogFile)
	unlock := func() {}
	armed := true
	js.onDumpFile = func(repoDir, _, path string) {
		if armed && repoDir == ih.destRepo && strings.Contains(path, ".ebb-seal-") && strings.HasSuffix(path, "/receipt.json") {
			armed = false
			unlock = jLockCatalog(t, catPath)
		}
	}
	defer func() { unlock() }()

	code, stdout, stderr := ih.run("import", "--json", capPath)
	unlock()
	if code == ExitOK {
		t.Fatalf("import succeeded despite the locked catalog: %s", stdout)
	}
	if leaked := ih.destSnaps(t); len(leaked) != 0 {
		t.Fatalf("destination vault holds %d orphaned snapshot(s) after the failed registration: %v", len(leaked), leaked)
	}
	if !strings.Contains(stdout+stderr, "rolled back") {
		t.Errorf("the failure does not report the rollback: %s %s", stdout, stderr)
	}
	if _, err := ih.cat().GetSnapshot(snap.ID); err == nil {
		t.Fatal("a snapshot row exists despite the failed registration")
	}
	ops := importOpsOf(t, ih.cat())
	if len(ops) != 1 {
		t.Fatalf("import ops = %+v, want one", ops)
	}

	// Close the stuck op, then the rerun copies exactly one fresh pair.
	if code, stdout, _ = ih.run("recover", string(ops[0].ID), "--cancel"); code != ExitOK {
		t.Fatalf("recover --cancel failed (code %d): %s", code, stdout)
	}
	code, stdout, stderr = ih.run("import", "--json", capPath)
	if code != ExitOK {
		t.Fatalf("rerun failed (code %d): %s %s", code, stdout, stderr)
	}
	if got := ih.destSnaps(t); len(got) != 2 {
		t.Fatalf("rerun left %d backend snapshots, want exactly one pair (2): %v", len(got), got)
	}
	if _, err := ih.cat().GetSnapshot(snap.ID); err != nil {
		t.Fatalf("rerun did not register the snapshot: %v", err)
	}
}

// ---- J4: forced rebuild with a divergent pair -> suspicious finding ------

// TestForcedRebuildDivergentPairIsSuspiciousRowUntouched plants a catalog
// row claiming a logical snapshot id with FORGED backend ids (the
// vault-password attacker's minted pair, D023's post-loss threat), then
// runs the forced rebuild over the intact catalog: the genuine pair
// discovered in the vault conflicts with the planted row's witness
// fields, the rebuild must surface the divergence as a SUSPICIOUS
// finding, and the existing row must stay byte-for-byte untouched
// (never re-anchored to the vault-derived values).
func TestForcedRebuildDivergentPairIsSuspiciousRowUntouched(t *testing.T) {
	h := newEHarness(t)
	genuine := parkH(t, h) // the real P/S pair + the intact row
	loseCatalog(t, h)

	// Plant the forged row for the SAME logical id before the rebuild:
	// different backend ids, different digests, different kind.
	forged := catalog.Snapshot{
		ID:               genuine.ID,
		WorkspaceID:      genuine.WorkspaceID,
		CreatedAt:        genuine.CreatedAt,
		PayloadBackendID: "forged-payload-00000000000000000000000000000",
		SealBackendID:    "forged-seal-00000000000000000000000000000000",
		ManifestDigest:   strings.Repeat("c", 64),
		InventoryDigest:  strings.Repeat("d", 64),
		Kind:             catalog.SnapshotKindSnapshot,
	}
	pc, err := catalog.Open(filepath.Join(h.stateDir, vault.CatalogFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.ImportDiscoveredSnapshot(genuine.WorkspaceID, "cliws", forged); err != nil {
		t.Fatalf("plant forged row: %v", err)
	}
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	planted, err := h.cat().GetSnapshot(genuine.ID)
	if err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := h.run("init", "--rebuild-catalog", "--force-rebuild", "--json")
	if code != ExitOK {
		t.Fatalf("forced rebuild failed (code %d): %s %s", code, stdout, stderr)
	}
	det := rebuildEnvelope(t, stdout)

	// The divergence is a FINDING, not a walk failure, and the pair was
	// not adopted or counted as a duplicate.
	susp, _ := det["suspicious_refused"].([]any)
	if len(susp) != 1 {
		t.Fatalf("suspicious_refused = %v, want the one divergent pair", susp)
	}
	s := susp[0].(map[string]any)
	if s["snapshot_id"] != string(genuine.ID) {
		t.Errorf("suspicious entry names snapshot %v, want %s", s["snapshot_id"], genuine.ID)
	}
	reasons, _ := s["reasons"].([]any)
	joined := ""
	for _, r := range reasons {
		joined += fmt.Sprint(r)
	}
	if !strings.Contains(joined, "witness divergence") || !strings.Contains(joined, "payload_backend_id") {
		t.Errorf("suspicious reasons do not name the divergence and field: %v", reasons)
	}
	if det["snapshots_adopted"] != float64(0) {
		t.Errorf("snapshots_adopted = %v, want 0 (the divergent pair is not adopted)", det["snapshots_adopted"])
	}
	if det["duplicates"] != float64(0) {
		t.Errorf("duplicates = %v, want 0 (a divergent pair is not a duplicate)", det["duplicates"])
	}

	// The existing row is untouched: still the forged witness values,
	// exactly as planted (nothing was re-anchored to the vault's genuine
	// pair — which is the point: overwriting would have swapped the
	// witness to whichever side spoke last).
	after, err := h.cat().GetSnapshot(genuine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.PayloadBackendID != planted.PayloadBackendID ||
		after.SealBackendID != planted.SealBackendID ||
		after.ManifestDigest != planted.ManifestDigest ||
		after.InventoryDigest != planted.InventoryDigest ||
		after.Kind != planted.Kind {
		t.Fatalf("the existing row was modified by the forced rebuild:\nplanted %+v\nafter  %+v", planted, after)
	}
	if !after.Pinned {
		t.Error("the existing row lost its pinned flag")
	}

	// The genuine pair itself stays in the vault, retained (the backend
	// was not touched by a catalog rebuild).
	if len(h.store.snaps) < 2 {
		t.Fatalf("backend snapshots = %d, want the genuine pair retained", len(h.store.snaps))
	}
}

// ---- J8: forget sole-UNBOUND refuses without the acknowledgement ---------

// TestForgetSoleUnboundSnapshotRequiresAcknowledgement rebuilds the
// catalog after a park + catalog loss (the workspace comes back UNBOUND
// — no local root) and proves the last-recovery-copy guard fires for
// that status too: plain --yes refuses with the same typed code as the
// parked twin; only --last-of-parked releases the pair.
func TestForgetSoleUnboundSnapshotRequiresAcknowledgement(t *testing.T) {
	h := newEHarness(t)
	snap := parkH(t, h)
	loseCatalog(t, h)

	code, stdout, stderr := h.run("init", "--rebuild-catalog", "--json")
	if code != ExitOK {
		t.Fatalf("rebuild failed (code %d): %s %s", code, stdout, stderr)
	}
	wss, err := h.cat().ListWorkspaces()
	if err != nil || len(wss) != 1 || wss[0].Status != catalog.WorkspaceUnbound {
		t.Fatalf("workspaces = %+v (%v), want one UNBOUND", wss, err)
	}

	before := len(h.store.snaps)
	code, stdout, stderr = h.run("forget", string(snap.ID), "--yes")
	if code != ExitBlocked || !strings.Contains(stdout+stderr, CodeForgetLastOfParked) {
		t.Fatalf("sole-UNBOUND forget under plain --yes was not refused (code %d): %s %s", code, stdout, stderr)
	}
	if got := len(h.store.snaps); got != before {
		t.Fatalf("the refused forget mutated the backend (%d -> %d)", before, got)
	}

	code, stdout, stderr = h.run("forget", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("the acknowledged forget failed (code %d): %s %s", code, stdout, stderr)
	}
	if after := len(h.store.snaps); after != before-2 {
		t.Fatalf("backend snapshots %d -> %d, want the pair forgotten (before-2)", before, after)
	}
}
