//go:build security_poc

package cli

// Wave J adversarial security PoCs (CLI export/import journal + failure
// ordering, forget's last-recovery-copy guard). Opt-in via -tags
// security_poc; the default suite stays green. Each test drives the
// REAL command path through the existing Wave H/I harnesses (real
// catalog, real platform probe, disk-backed fake store) and asserts the
// specific misbehavior.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/vault"

	_ "modernc.org/sqlite"
)

// ---- helpers ------------------------------------------------------------

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
// busy_timeout (5 s per call) — the controlled "catalog just broke"
// failure the J2/J3 orderings need, without corrupting anything.
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

// ---- J1: a crashed export (or import) in an EXPORT_*/IMPORT_* phase is
// unresolvable by every recovery verb, blocks the workspace and gc, and
// gc's refusal actively misdirects the user to `ebb recover <op>` which
// reports "nothing reconciled".
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

	// (a) gc is blocked globally — and its advice is wrong for this kind.
	code, stdout, stderr := h.run("gc", "main", "--json")
	if code != ExitBlocked {
		t.Fatalf("J1: gc exit = %d, want %d (stdout %s stderr %s)", code, ExitBlocked, stdout, stderr)
	}
	if !strings.Contains(stdout+stderr, "ebb recover "+string(opID)) {
		t.Errorf("J1: gc refusal does not direct at recover (message: %s %s)", stdout, stderr)
	}

	// (b) plain recover: report-only, phase unchanged, exit 0.
	code, stdout, stderr = h.run("recover", string(opID), "--json")
	if code != ExitOK {
		t.Logf("J1: plain recover exit = %d (%s %s)", code, stdout, stderr)
	}
	env := envelopeOf(t, stdout)
	det, _ := env["details"].(map[string]any)
	if det == nil || det["phase_after"] != catalog.PhaseExportCopying {
		t.Errorf("J1: recover phase_after = %v (details %v) — want the phase UNCHANGED at %s",
			det["phase_after"], det, catalog.PhaseExportCopying)
	}
	if na, _ := det["next_action"].(string); !strings.Contains(na, "no lifecycle action required") {
		t.Logf("J1: recover next_action = %q", na)
	}

	// (c) the explicit cancel verb refuses the phase outright.
	code, stdout, stderr = h.run("recover", string(opID), "--cancel")
	if code == ExitOK {
		t.Fatalf("J1: --cancel SUCCEEDED — the stuck op WAS closable; finding stale. stdout %s", stdout)
	}
	if !strings.Contains(stdout+stderr, "cancel applies to phases") {
		t.Logf("J1: --cancel refusal wording: %s %s", stdout, stderr)
	}

	// (d) the workspace is bricked for every future capture.
	code, stdout, stderr = h.run("snapshot", h.wsRoot)
	if code == ExitOK {
		t.Fatalf("J1: a new snapshot SUCCEEDED with the dead export op active — finding stale")
	}
	if !strings.Contains(stdout+stderr, string(opID)) {
		t.Errorf("J1: snapshot refusal does not name the blocking op: %s %s", stdout, stderr)
	}

	// (e) the op is still active afterwards — nothing above closed it.
	cat2 := h.cat()
	active, err := cat2.ActiveOperations("")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, op := range active {
		if op.ID == opID {
			found = op.Phase == catalog.PhaseExportCopying
		}
	}
	if !found {
		t.Fatalf("J1: op %s not active at %s — something closed it; finding stale (active=%v)", opID, catalog.PhaseExportCopying, active)
	}
	t.Errorf("J1 CONFIRMED: a crashed export at %s cannot be closed by ANY verb — plain recover reports "+
		"'nothing reconciled', --cancel refuses the phase, the workspace refuses new captures, gc is blocked "+
		"globally — until manual catalog surgery; gc's refusal even directs the user at the recover command "+
		"that cannot help", catalog.PhaseExportCopying)
}

// J1b — the same unrecoverable active-op state is reachable WITHOUT a
// crash: a transient catalog write failure during an otherwise normal
// export (here: an exclusive lock, i.e. any SQLITE_BUSY-class window,
// taken at the backend copy) makes the post-transport bookkeeping
// (RecordReplica / failClose's CAS close) fail, leaving the op ACTIVE
// at EXPORT_COPYING and the duration pin pin:export:<op> taken but
// never released (releasePin's error is swallowed by design).
func TestJ1b_TransientCatalogErrorLeavesUnrecoverableOpAndStalePin(t *testing.T) {
	h := newHHarness(t)
	js := &jStore{hStore: h.store}
	h.deps.NewStore = func() (domain.SnapshotStore, func(), error) { return js, func() {}, nil }
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "capsule.ebb")
	catPath := filepath.Join(h.stateDir, vault.CatalogFile)

	// Lock when the backend copy starts: the op row is already active at
	// EXPORT_COPYING (pin taken, both journal advances committed) and the
	// next catalog writes — releasePin's audit, RecordReplica, and
	// failClose's CAS close — deterministically fail.
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
	// And the stuck op again admits no recovery verb.
	code, stdout, _ = h.run("recover", string(ops[0].ID), "--cancel")
	if code == ExitOK {
		t.Fatalf("J1b: --cancel closed the EXPORT_PLANNED op — finding stale: %s", stdout)
	}
	t.Errorf("J1b CONFIRMED: one transient catalog write failure (busy lock) during a normal export left the "+
		"operation ACTIVE at %s with the duration pin %s taken but never released; no recovery verb closes it "+
		"(plain recover reports 'nothing reconciled', --cancel refuses the phase) — the same manual-surgery "+
		"dead end as a hard crash, reachable in ordinary operation", ops[0].Phase, "pin:export:"+string(ops[0].ID))
}

// ---- J2: post-publication bookkeeping failures destroy the one-time
// capsule passphrase. capsule.Export has already PUBLISHED (final name,
// no partial) when RecordReplica runs; its failure walks failClose,
// returns an error, and the passphrase print — the only place the
// crypto/rand secret ever appears — is never reached. The user is left
// with a complete, final-named capsule that can never be opened.
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
	if code == ExitOK {
		t.Fatalf("J2: export SUCCEEDED despite the locked catalog — ordering changed; stdout %s", stdout)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("J2: capsule NOT published at %s — the failure preceded publication; ordering changed: %v", out, err)
	}
	if _, err := os.Stat(out + ".partial"); err == nil {
		t.Error("J2: a .partial also exists — unexpected double artifact")
	}
	if strings.Contains(stderr, "CAPSULE PASSPHRASE") || strings.Contains(stdout, "CAPSULE PASSPHRASE") {
		t.Errorf("J2: the passphrase block WAS shown — finding stale")
	}
	t.Errorf("J2 CONFIRMED: the export FAILED after publication (capsule exists at the FINAL path %s) and the "+
		"one-time passphrase was never displayed — a complete capsule whose crypto/rand secret is now "+
		"unrecoverable, an error report that does not disclose that, no replicas row, and (§15.2) not the "+
		"'identifiable partial artifact' a failed export is supposed to leave", out)
}

// ---- J3: a CLI-side registration failure after a successful import
// transport leaves the copied payload+seal ORPHANED in the destination
// vault (no rollback, no rows, op stuck active) and a rerun would copy
// AGAIN.
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
		t.Fatalf("J3: import SUCCEEDED despite the locked catalog — ordering changed; stdout %s", stdout)
	}

	// The vault holds the copied pair with NO catalog row: orphaned.
	leaked := ih.destSnaps(t)
	if len(leaked) != 2 {
		t.Fatalf("J3: destination vault holds %d snapshots, want exactly the leaked pair (2): %v", len(leaked), leaked)
	}
	cat := ih.cat()
	if _, err := cat.GetSnapshot(snap.ID); err == nil {
		t.Fatalf("J3: a snapshot row exists despite the failed registration — finding stale")
	}
	ops := importOpsOf(t, cat)
	if len(ops) != 1 {
		t.Fatalf("J3: import ops = %+v, want exactly one", ops)
	}
	if ops[0].Phase != catalog.PhaseImportVerifying {
		t.Logf("J3: stuck phase = %s (want %s)", ops[0].Phase, catalog.PhaseImportVerifying)
	}
	if act, _ := cat.ActiveOperations(""); len(act) == 0 {
		t.Error("J3: the failed import's operation is not active — J1-class block absent")
	}
	if strings.Contains(stdout+stderr, "ROLLBACK") {
		t.Error("J3: a rollback was reported — the transport's rollback fired after all; finding stale")
	}
	t.Errorf("J3 CONFIRMED: the import failed AFTER the transport succeeded — payload %s and seal %s remain "+
		"in the destination vault with no catalog row, no rollback was attempted (the transport's "+
		"List-verified rollback only covers transport errors), the operation is stuck active at %s, and a "+
		"rerun (Known gate: no row) would copy the pair a SECOND time",
		leaked[0], leaked[1], ops[0].Phase)
}

// ---- J8: forget's last-recovery-copy guard covers PARKED workspaces
// only. The SAME sole snapshot, once its workspace is UNBOUND (the
// catalog-rebuild / import state, where no local root exists either),
// forgets under plain --yes with no --last-of-parked acknowledgement.
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
	// no longer applies.
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
	if code != ExitOK {
		t.Fatalf("J8 CONFIRMED-negative: the UNBOUND sole-snapshot forget was refused (code %d): %s %s — finding stale", code, stdout, stderr)
	}
	after := len(h.store.snaps)
	if after != before-2 {
		t.Fatalf("J8: backend snapshots %d -> %d, want the P/S pair gone (before-2)", before, after)
	}
	t.Errorf("J8 CONFIRMED: forgetting the ONLY snapshot of the UNBOUND workspace %q required no "+
		"--last-of-parked acknowledgement (plain --yes, exit 0, P/S pair gone) while the identical "+
		"sole-snapshot forget of the PARKED twin refuses with %s — the guard protects exactly one of the "+
		"two statuses that have no local root", wss[0].Name, CodeForgetLastOfParked)
}
