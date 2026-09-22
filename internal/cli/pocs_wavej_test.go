//go:build security_poc

package cli

// Wave J adversarial security PoCs (CLI export/import journal + failure
// ordering, forget's last-recovery-copy guard). Opt-in via -tags
// security_poc; the default suite stays green. Each test drives the
// REAL command path through the existing Wave H/I harnesses (real
// catalog, real platform probe, disk-backed fake store) and asserts the
// specific misbehavior.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// ---- helpers ------------------------------------------------------------
// jStore and jLockCatalog live untagged in wave_j_regression_test.go so
// this suite and the default regressions drive the same interpositions.

// ---- J1 (post-fix contract): a crashed export (or import) in an
// EXPORT_*/IMPORT_* phase is closable by `ebb recover <op> --cancel`
// (the capsule transports own no removal authority, so cancel-after-
// crash is always safe); plain recover stays report-only and names that
// verb; gc's refusal names the verb that works for the kind; and the
// workspace is unblocked afterwards.
func TestJ1_CrashedExportOperationUnrecoverableAndBlocksWorkspaceAndGc(t *testing.T) {
	h := newHHarness(t)
	snap := h.captureSnapshot(t)

	// The durable state a hard crash mid-copy leaves (power loss / kill
	// during the ~15 s export): the op row is active at EXPORT_COPYING.
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

	// (a) gc is blocked globally — and its advice names the verb that
	// actually closes this kind's phases.
	code, stdout, stderr := h.run("gc", "main", "--json")
	if code != ExitBlocked {
		t.Fatalf("J1: gc exit = %d, want %d (stdout %s stderr %s)", code, ExitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout+stderr, "ebb recover "+string(opID)+" --cancel") {
		t.Errorf("J1: gc refusal does not direct at `recover --cancel` for a capsule-transport op (message: %s %s)", stdout, stderr)
	}

	// (b) plain recover: report-only, phase unchanged, exit 0 — and it
	// advises the closing verb.
	code, stdout, stderr = h.run("recover", string(opID), "--json")
	if code != ExitOK {
		t.Fatalf("J1: plain recover exit = %d (%s %s)", code, stdout, stderr)
	}
	env := envelopeOf(t, stdout)
	det, _ := env["details"].(map[string]any)
	if det == nil || det["phase_after"] != catalog.PhaseExportCopying {
		t.Errorf("J1: recover phase_after = %v (details %v) — want the phase UNCHANGED at %s (report-only)",
			det["phase_after"], det, catalog.PhaseExportCopying)
	}
	if na, _ := det["next_action"].(string); !strings.Contains(na, "--cancel") {
		t.Errorf("J1: recover next_action = %q — want it to advise `--cancel`", na)
	}

	// (c) the explicit cancel verb closes the crashed transport op.
	code, stdout, stderr = h.run("recover", string(opID), "--cancel")
	if code != ExitOK {
		t.Fatalf("J1: --cancel failed (code %d): %s %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout+stderr, catalog.PhaseCanceled) {
		t.Errorf("J1: cancel report does not name CANCELED: %s %s", stdout, stderr)
	}

	// (d) the workspace accepts new operations again.
	code, stdout, stderr = h.run("snapshot", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("J1: a new snapshot was refused after cancel (code %d): %s %s", code, stdout, stderr)
	}

	// (e) the op is closed — terminal CANCELED, no longer active.
	cat2 := h.cat()
	op, err := cat2.GetOperation(opID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Phase != catalog.PhaseCanceled {
		t.Fatalf("J1: op phase = %s, want %s", op.Phase, catalog.PhaseCanceled)
	}
	if active, err := cat2.ActiveOperations(""); err != nil || len(active) != 0 {
		t.Fatalf("J1: active ops after cancel = %v (%v), want none", active, err)
	}

	// (f) cancel is idempotent: a rerun reports already-canceled, exit 0.
	code, _, _ = h.run("recover", string(opID), "--cancel")
	if code != ExitOK {
		t.Fatalf("J1: idempotent cancel rerun failed (code %d)", code)
	}
}

// J1b (post-fix contract) — a transient catalog write failure during an
// otherwise normal export (an exclusive lock, i.e. any SQLITE_BUSY-class
// window, taken at the backend copy) still fails the transport honestly
// (nothing was published), but the resulting stuck-active op is now
// closable with `recover --cancel`, which ALSO releases the stale
// duration pin audit-only — no manual catalog surgery, no permanent pin.
func TestJ1b_TransientCatalogErrorLeavesUnrecoverableOpAndStalePin(t *testing.T) {
	h := newHHarness(t)
	js := &jStore{hStore: h.store}
	h.deps.NewStore = func() (domain.SnapshotStore, func(), error) { return js, func() {}, nil }
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "capsule.ebb")
	catPath := filepath.Join(h.stateDir, vault.CatalogFile)

	// Lock when the backend copy starts: the op row is already active at
	// EXPORT_COPYING (pin taken, both journal advances committed) and
	// the next catalog writes — the phase advance to EXPORT_VERIFYING,
	// releasePin's audit, and failClose's CAS close — deterministically
	// fail.
	unlock := func() {}
	armed := true
	js.hStore.onCopy = func(src, dst string, ids []string) error {
		if armed {
			armed = false
			unlock = jLockCatalog(t, catPath)
		}
		return nil
	}
	defer func() { unlock() }()

	code, stdout, _ := h.run("export", "--json", string(snap.ID), "--output", out)
	unlock()
	if code == ExitOK {
		t.Fatalf("J1b: export succeeded despite the locked catalog: %s", stdout)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("J1b: a capsule was published despite the locked catalog (pre-publication failure expected)")
	}
	cat := h.cat()
	ops := exportOpsOf(t, cat, snap.WorkspaceID)
	if len(ops) != 1 {
		t.Fatalf("J1b: export ops = %+v, want exactly one", ops)
	}
	if ops[0].Phase != catalog.PhaseExportCopying && ops[0].Phase != catalog.PhaseExportVerifying {
		t.Fatalf("J1b: stuck phase = %s, want an active EXPORT_* phase", ops[0].Phase)
	}
	if act, _ := cat.ActiveOperations(""); len(act) == 0 {
		t.Error("J1b: the failed export's op is not active (J1-class block absent)")
	}
	fresh, err := cat.GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	pinTaken, pinReleased := false, false
	for _, r := range fresh.PinReasons {
		if strings.HasPrefix(r, "pin:export:"+string(ops[0].ID)) {
			pinTaken = true
		}
		if strings.HasPrefix(r, "unpin:export:"+string(ops[0].ID)) {
			pinReleased = true
		}
	}
	if !pinTaken || pinReleased {
		t.Fatalf("J1b: duration-pin audit = %v (taken=%v released=%v) — pin state not the claimed stale shape", fresh.PinReasons, pinTaken, pinReleased)
	}

	// The fix: the J1 escape hatch closes the op AND releases the stale
	// duration pin (audit-only; the snapshot stays pinned by creation).
	code, stdout, _ = h.run("recover", string(ops[0].ID), "--cancel")
	if code != ExitOK {
		t.Fatalf("J1b: --cancel could not close the crashed export op: %s", stdout)
	}
	cat2 := h.cat()
	op, err := cat2.GetOperation(ops[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if op.Phase != catalog.PhaseCanceled {
		t.Fatalf("J1b: op phase after cancel = %s, want CANCELED", op.Phase)
	}
	fresh, err = cat2.GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	pinReleased = false
	for _, r := range fresh.PinReasons {
		if strings.HasPrefix(r, "unpin:export:"+string(ops[0].ID)) {
			pinReleased = true
		}
	}
	if !pinReleased {
		t.Fatalf("J1b: the stale duration pin was not released by cancel (audit: %v)", fresh.PinReasons)
	}
	if !fresh.Pinned {
		t.Error("J1b: cancel dropped the snapshot's own pinned flag — cancel must never release recovery obligations (I07)")
	}
}

// ---- J2 (post-fix contract): the passphrase prints IMMEDIATELY after
// the publish rename and BEFORE any fallible bookkeeping, so a
// post-publication bookkeeping failure (replicas row / DONE close)
// degrades to a WARNING on a SUCCESS outcome — the capsule exists at
// its final path, its secret was displayed, and the warning discloses
// both plus how to reconcile the operation.
func TestJ2_ExportPublishesThenLosesPassphraseOnBookkeepingFailure(t *testing.T) {
	h := newHHarness(t)
	js := &jStore{hStore: h.store}
	h.deps.NewStore = func() (domain.SnapshotStore, func(), error) { return js, func() {}, nil }
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "capsule.ebb")
	catPath := filepath.Join(h.stateDir, vault.CatalogFile)

	// Lock the catalog exactly when verifyExtractedRepo re-reads the
	// extracted seal: everything capsule.Export still has to do (publish)
	// is catalog-free, so the transport SUCCEEDS and the next catalog call
	// (RecordReplica, after publication) deterministically fails.
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
	unlock() // free the catalog before asserting on durable state
	if code != ExitOK {
		t.Fatalf("J2: export FAILED after publication (code %d) — post-publication bookkeeping must be a warning on success: %s %s", code, stdout, stderr)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("J2: capsule NOT published at %s: %v", out, err)
	}
	if _, err := os.Stat(out + ".partial"); err == nil {
		t.Error("J2: a .partial also exists — unexpected double artifact")
	}

	// The one-time secret WAS displayed (exactly once, terminal only).
	if !strings.Contains(stderr, "CAPSULE PASSPHRASE") {
		t.Errorf("J2: the passphrase block was NOT shown on the terminal:\n%s", stderr)
	}
	secret := passphraseOfBlock(stderr)
	if secret == "" {
		t.Fatal("J2: no passphrase line found in the block")
	}
	if strings.Contains(stdout, secret) {
		t.Fatal("J2: THE CAPSULE PASSPHRASE LEAKED INTO THE JSON ENVELOPE")
	}
	if strings.Count(stderr, secret) != 1 {
		t.Errorf("J2: passphrase printed %d times in stderr, want exactly 1", strings.Count(stderr, secret))
	}

	// The envelope is a SUCCESS with warnings that disclose the complete
	// capsule at the final path and name the reconciliation verb.
	env := envelopeOf(t, stdout)
	if env["outcome"] != "ok" {
		t.Fatalf("J2: envelope outcome = %v, want ok", env["outcome"])
	}
	warned := false
	for _, w := range env["warnings"].([]any) {
		ws, _ := w.(string)
		if strings.Contains(ws, "COMPLETE capsule") && strings.Contains(ws, out) {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("J2: no warning discloses the complete capsule at %s (warnings: %v)", out, env["warnings"])
	}

	// The stuck bits the warnings name are reconcilable with the J1
	// verb: the op (still active — its DONE close failed) closes and
	// the unreleased pin audit is released.
	cat := h.cat()
	ops := exportOpsOf(t, cat, snap.WorkspaceID)
	if len(ops) != 1 || ops[0].Phase != catalog.PhaseExportVerifying {
		t.Fatalf("J2: export ops = %+v, want one active at EXPORT_VERIFYING (DONE close failed)", ops)
	}
	code, stdout, _ = h.run("recover", string(ops[0].ID), "--cancel")
	if code != ExitOK {
		t.Fatalf("J2: recover --cancel could not close the bookkeeping-failed export op: %s", stdout)
	}
	fresh, err := h.cat().GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	for _, r := range fresh.PinReasons {
		if strings.HasPrefix(r, "unpin:export:"+string(ops[0].ID)) {
			released = true
		}
	}
	if !released {
		t.Errorf("J2: the export pin was not released by cancel (audit: %v)", fresh.PinReasons)
	}
	if !fresh.Pinned {
		t.Error("J2: the source snapshot lost its own pinned flag")
	}
}

// ---- J3 (post-fix contract): a CLI-side registration failure after a
// successful import transport rolls the copied payload+seal pair back
// through the transport's List-verified forget (no orphans), reports
// the rollback, and the rerun copies FRESH into a clean vault (after
// the stuck op is closed with the J1 verb) instead of accumulating a
// second pair.
func TestJ3_ImportRegistrationFailureOrphansVaultSnapshots(t *testing.T) {
	capPath, secret, snap := exportCapsuleOf(t)
	ih := newImportHarness(t) // re-sets vault.EnvPassword for the destination world
	js := &jStore{hStore: ih.store}
	ih.deps.NewStore = func() (domain.SnapshotStore, func(), error) { return js, func() {}, nil }
	t.Setenv(EnvCapsulePassword, secret)

	if n := len(ih.destSnaps(t)); n != 0 {
		t.Fatalf("J3 harness: destination vault not empty at start (%d)", n)
	}

	catPath := filepath.Join(ih.stateDir, vault.CatalogFile)
	unlock := func() {}
	armed := true
	js.onDumpFile = func(repoDir, _, path string) {
		// The import seal's byte-exact readback is the LAST backend call
		// of the transport; lock the catalog exactly there so the transport
		// completes and only the CLI-side registration fails.
		if armed && repoDir == ih.destRepo && strings.Contains(path, ".ebb-seal-") && strings.HasSuffix(path, "/receipt.json") {
			armed = false
			unlock = jLockCatalog(t, catPath)
		}
	}
	defer func() { unlock() }()

	code, stdout, stderr := ih.run("import", "--json", capPath)
	unlock() // free the catalog before asserting on durable state
	if code == ExitOK {
		t.Fatalf("J3: import SUCCEEDED despite the locked catalog (registration failures stay failures): %s", stdout)
	}

	// The copied pair was rolled back, List-verified gone: NO orphans.
	if leaked := ih.destSnaps(t); len(leaked) != 0 {
		t.Fatalf("J3: destination vault holds %d snapshot(s) after the rolled-back import, want 0: %v", len(leaked), leaked)
	}
	if !strings.Contains(stdout+stderr, "rolled back") {
		t.Errorf("J3: the failure does not report the rollback: %s %s", stdout, stderr)
	}
	cat := ih.cat()
	if _, err := cat.GetSnapshot(snap.ID); err == nil {
		t.Fatalf("J3: a snapshot row exists despite the failed registration")
	}
	ops := importOpsOf(t, cat)
	if len(ops) != 1 {
		t.Fatalf("J3: import ops = %+v, want exactly one", ops)
	}
	if act, _ := cat.ActiveOperations(""); len(act) == 0 {
		t.Error("J3: the failed import's operation is not active (the locked catalog also broke failClose)")
	}

	// Close the stuck op with the J1 verb, then rerun: the vault is
	// clean, so the rerun copies exactly one fresh pair — not a second
	// copy beside the orphaned one.
	code, stdout, _ = ih.run("recover", string(ops[0].ID), "--cancel")
	if code != ExitOK {
		t.Fatalf("J3: recover --cancel could not close the failed import op: %s", stdout)
	}
	code, stdout, stderr = ih.run("import", "--json", capPath)
	if code != ExitOK {
		t.Fatalf("J3: the rerun failed (code %d): %s %s", code, stdout, stderr)
	}
	if got := ih.destSnaps(t); len(got) != 2 {
		t.Fatalf("J3: rerun left %d backend snapshots, want exactly the one fresh pair (2): %v", len(got), got)
	}
	if _, err := ih.cat().GetSnapshot(snap.ID); err != nil {
		t.Fatalf("J3: the rerun did not register the snapshot row: %v", err)
	}
}

// ---- J8 (post-fix contract): forget's last-recovery-copy guard covers
// BOTH statuses that have no local root. The SAME sole snapshot, after
// catalog loss + rebuild (workspace UNBOUND — no root, no local copy),
// refuses under plain --yes exactly like the PARKED twin, and releases
// only with the explicit --last-of-parked acknowledgement.
func TestJ8_ForgetLastCopyGuardSkipsUnboundWorkspaces(t *testing.T) {
	h := newEHarness(t)
	snap := parkH(t, h)

	// Twin A: the sole snapshot of a PARKED workspace refuses without the
	// explicit acknowledgement.
	code, _, stderr := h.run("forget", string(snap.ID), "--yes")
	if code != ExitBlocked || !strings.Contains(stderr, CodeForgetLastOfParked) {
		t.Fatalf("J8 harness: parked sole-snapshot forget was not blocked (code %d, stderr %s)", code, stderr)
	}

	// Twin B: the SAME sole snapshot after catalog loss + rebuild — the
	// workspace comes back UNBOUND (no root, no local copy) and the guard
	// fires for it too now.
	loseCatalog(t, h)
	code, stdout, stderr := h.run("init", "--rebuild-catalog", "--json")
	if code != ExitOK {
		t.Fatalf("J8 harness: rebuild failed (%d): %s %s", code, stdout, stderr)
	}
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("J8 harness: workspaces = %+v (%v)", wss, err)
	}
	if wss[0].Status != catalog.WorkspaceUnbound {
		t.Fatalf("J8 harness: rebuilt workspace status = %s, want UNBOUND", wss[0].Status)
	}

	before := len(h.store.snaps)
	code, stdout, stderr = h.run("forget", string(snap.ID), "--yes")
	if code != ExitBlocked || !strings.Contains(stdout+stderr, CodeForgetLastOfParked) {
		t.Fatalf("J8: the UNBOUND sole-snapshot forget was NOT refused (code %d): %s %s", code, stdout, stderr)
	}
	if got := len(h.store.snaps); got != before {
		t.Fatalf("J8: backend snapshots changed by the refused forget (%d -> %d)", before, got)
	}

	// With the explicit acknowledgement the deliberate release proceeds.
	code, stdout, stderr = h.run("forget", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("J8: the acknowledged forget failed (code %d): %s %s", code, stdout, stderr)
	}
	after := len(h.store.snaps)
	if after != before-2 {
		t.Fatalf("J8: backend snapshots %d -> %d, want the P/S pair gone (before-2)", before, after)
	}
}
