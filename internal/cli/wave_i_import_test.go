// wave_i_import_test.go drives `ebb import` and `ebb inspect
// <capsule>` end to end through the Deps seam. The capsule fixture is
// produced by a REAL `ebb export` in a source world (the wave H
// harness), then imported into a SECOND world: its own state
// dir/catalog/registry and its own destination vault, so the capsule's
// logical snapshot id is genuinely unregistered — the fresh-import
// shape. The real-restic product-level acceptance lives in
// internal/capsule/e2e_reSTORic_test.go; this file pins the CLI
// contract: exit codes, envelope shape, passphrase non-exposure, the
// durable rows (workspace/snapshot/vault/replica/operation), the
// idempotent rerun, the same-id-different-digest refusal, dry-run
// touch-nothing behavior, and inspect's public/verified capsule modes.

package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/capsule"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/platform"
	"ebb/internal/restore"
	"ebb/internal/vault"
)

// ---- the import world ------------------------------------------------
//
// iHarness is a second harness world that shares only the capsule FILE
// with the export world: fresh catalog (nothing registered), fresh
// registry with one initialized destination vault "dest" (the disk-
// backed fake store's auth contract: keys/hkey == the vault password).

type iHarness struct {
	t        *testing.T
	stateDir string
	destRepo string
	store    *hStore
	deps     Deps
}

func newImportHarness(t *testing.T) *iHarness {
	t.Helper()
	base := t.TempDir()
	h := &iHarness{
		t:        t,
		stateDir: filepath.Join(base, "state"),
		destRepo: filepath.Join(base, "dest-vault"),
		store:    newHStore(),
	}
	if err := os.MkdirAll(h.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(vault.EnvPassword, "iworld-vault-secret")
	if err := os.MkdirAll(h.destRepo, 0o700); err != nil {
		t.Fatal(err)
	}
	pwFile := filepath.Join(base, "dest-pass")
	if err := os.WriteFile(pwFile, []byte("iworld-vault-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.store.Init(context.Background(), h.destRepo, pwFile); err != nil {
		t.Fatalf("init destination vault: %v", err)
	}
	if _, err := vault.New(filepath.Join(h.stateDir, vault.RegistryFile)).Register("dest", h.destRepo, ""); err != nil {
		t.Fatal(err)
	}

	deps := RealDeps()
	deps.StateDir = func() (string, error) { return h.stateDir, nil }
	deps.OpenCatalog = catalog.Open
	deps.NewStore = func() (domain.SnapshotStore, func(), error) { return h.store, func() {}, nil }
	deps.NewLifecycle = lifecycle.New
	deps.NewRestoreOp = restore.New
	deps.NewProbe = platform.New
	deps.StdinIsTerminal = func() bool { return false }
	deps.ReadLine = func() (string, error) { return "", fmt.Errorf("no tty") }
	deps.NewSignalContext = func() (context.Context, func()) { return context.Background(), func() {} }
	h.deps = deps
	return h
}

func (h *iHarness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var out, errb strings.Builder
	code := Main(args, Streams{Out: &out, Err: &errb}, h.deps)
	return code, out.String(), errb.String()
}

func (h *iHarness) cat() *catalog.Catalog {
	h.t.Helper()
	c, err := catalog.Open(filepath.Join(h.stateDir, vault.CatalogFile))
	if err != nil {
		h.t.Fatalf("open catalog: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

// destRepoID resolves the destination vault's backend identity (the
// same probe cmdImport runs inside the vault closure).
func (h *iHarness) destRepoID(t *testing.T) string {
	t.Helper()
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("iworld-vault-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := h.store.RepoID(context.Background(), h.destRepo, pwFile)
	if err != nil {
		t.Fatalf("dest RepoID: %v", err)
	}
	return id
}

// destSnaps lists the destination vault's backend snapshot ids.
func (h *iHarness) destSnaps(t *testing.T) []string {
	t.Helper()
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("iworld-vault-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	refs, err := h.store.List(context.Background(), h.destRepo, pwFile)
	if err != nil {
		t.Fatalf("dest List: %v", err)
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.BackendID)
	}
	return ids
}

// exportCapsuleOf produces one real capsule in the export world and
// returns its path, its passphrase (captured from the terminal block)
// and the source snapshot's FULL row — the logical workspace id an
// import must ADOPT travels in it.
func exportCapsuleOf(t *testing.T) (path, passphrase string, snap catalog.Snapshot) {
	t.Helper()
	h := newHHarness(t)
	snap = h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "capsule.ebb")
	code, _, stderr := h.run("export", string(snap.ID), "--output", out)
	if code != ExitOK {
		t.Fatalf("fixture export failed (%d): %s", code, stderr)
	}
	secret := passphraseOfBlock(stderr)
	if secret == "" {
		t.Fatal("no passphrase in the export terminal block")
	}
	return out, secret, snap
}

// exportCapsule is exportCapsuleOf with the snapshot id spelled out.
func exportCapsule(t *testing.T) (path, passphrase, snapID string) {
	p, s, snap := exportCapsuleOf(t)
	return p, s, string(snap.ID)
}

// importOpsOf returns the import-kind operation rows across all
// workspaces.
func importOpsOf(t *testing.T, cat *catalog.Catalog) []catalog.Operation {
	t.Helper()
	all, err := cat.ListOperations("")
	if err != nil {
		t.Fatalf("list operations: %v", err)
	}
	var out []catalog.Operation
	for _, op := range all {
		if op.Kind == catalog.OpKindImport {
			out = append(out, op)
		}
	}
	return out
}

// ---- tests ---------------------------------------------------------------

func TestImportHappyPathCLI(t *testing.T) {
	capPath, secret, snap := exportCapsuleOf(t)
	snapID := string(snap.ID)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, secret)

	code, stdout, stderr := h.run("import", "--json", capPath)
	if code != ExitOK {
		t.Fatalf("import code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || envString(t, env, "command") != "import" {
		t.Errorf("outcome/command = %v/%v", env["outcome"], env["command"])
	}
	if envString(t, env, "snapshot_id") != snapID {
		t.Errorf("envelope snapshot_id = %v, want the capsule's logical id %s", env["snapshot_id"], snapID)
	}
	if envString(t, env, "operation_id") == "" || envString(t, env, "workspace_id") == "" {
		t.Errorf("operation_id/workspace_id missing: %v / %v", env["operation_id"], env["workspace_id"])
	}
	for _, want := range []string{"registered", "pinned-by-creation", "import-never-implies-forget"} {
		if !mustCondition(env, want) {
			t.Errorf("conditions missing %q: %v", want, env["conditions"])
		}
	}
	if ws, _ := env["warnings"].([]any); len(ws) == 0 || !strings.Contains(fmt.Sprint(ws), "UNTRUSTED") {
		t.Errorf("warnings lack the §13.3 trust line: %v", env["warnings"])
	}
	det := env["details"].(map[string]any)
	if det["already_known"] != nil && det["already_known"] != false {
		t.Errorf("already_known = %v on a fresh import", det["already_known"])
	}
	if det["vault"] != "dest" || det["destination_payload_id"] == "" || det["destination_seal_id"] == "" {
		t.Errorf("details vault/destination ids = %v / %v / %v", det["vault"], det["destination_payload_id"], det["destination_seal_id"])
	}
	// Identity adoption: the one reported workspace id IS the capsule's
	// logical id, and the redundant report-only twin field is gone.
	if det["workspace_id"] != string(snap.WorkspaceID) {
		t.Errorf("details workspace_id = %v, want the ADOPTED capsule id %s", det["workspace_id"], snap.WorkspaceID)
	}
	if det["capsule_workspace_id"] != nil {
		t.Errorf("the redundant capsule_workspace_id field survives: %v", det["capsule_workspace_id"])
	}
	if det["passphrase"] != nil {
		t.Error("details carries a passphrase field")
	}

	// Passphrase non-exposure: the secret never appears in ANY output.
	if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
		t.Fatal("THE CAPSULE PASSPHRASE LEAKED INTO THE IMPORT OUTPUT")
	}

	// Durable rows: one UNBOUND workspace named after the manifest's
	// main-root prefix and carrying the CAPSULE'S LOGICAL ID (identity
	// adoption — §16.1), the pinned snapshot bound to the destination
	// vault row, the replica receipt, one DONE import operation.
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces = %v (%v)", wss, err)
	}
	if wss[0].Status != catalog.WorkspaceUnbound || wss[0].RootPath != "" {
		t.Errorf("imported workspace not UNBOUND: %+v", wss[0])
	}
	if wss[0].ID != snap.WorkspaceID {
		t.Errorf("workspace id = %s, want the ADOPTED capsule logical id %s", wss[0].ID, snap.WorkspaceID)
	}
	if wss[0].Name != "ws" {
		t.Errorf("workspace name = %q, want the manifest prefix %q", wss[0].Name, "ws")
	}
	snapRow, err := cat.GetSnapshot(domain.SnapshotID(snapID))
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if !snapRow.Pinned {
		t.Error("imported snapshot not pinned")
	}
	if snapRow.WorkspaceID != wss[0].ID {
		t.Errorf("snapshot workspace = %s, want the adopted %s", snapRow.WorkspaceID, wss[0].ID)
	}
	if snapRow.PayloadBackendID != det["destination_payload_id"] || snapRow.SealBackendID != det["destination_seal_id"] {
		t.Errorf("snapshot backend ids = %s/%s, want %v/%v",
			snapRow.PayloadBackendID, snapRow.SealBackendID, det["destination_payload_id"], det["destination_seal_id"])
	}
	wantVaultRow := lifecycle.VaultIDFor(h.destRepoID(t), h.destRepo)
	if snapRow.VaultID != wantVaultRow {
		t.Errorf("snapshot vault = %s, want %s", snapRow.VaultID, wantVaultRow)
	}
	if _, verr := cat.GetVault(wantVaultRow); verr != nil {
		t.Errorf("catalog vault row missing: %v", verr)
	}
	reps, err := cat.ListReplicas(snapRow.ID)
	if err != nil || len(reps) != 1 {
		t.Fatalf("replicas = %v (%v)", reps, err)
	}
	if reps[0].Path != capPath || reps[0].VaultID != "" || !strings.HasPrefix(reps[0].Scope, "capsule-import:") {
		t.Errorf("replica row = %+v", reps[0])
	}
	iops := importOpsOf(t, cat)
	if len(iops) != 1 || iops[0].Phase != catalog.PhaseDone {
		t.Fatalf("import ops = %+v, want one DONE", iops)
	}
	if iops[0].WorkspaceID != wss[0].ID {
		t.Errorf("import op workspace = %s, want %s", iops[0].WorkspaceID, wss[0].ID)
	}

	// Destination vault holds exactly the payload + the new local seal.
	ids := h.destSnaps(t)
	if len(ids) != 2 {
		t.Errorf("destination vault holds %d snapshots (%v), want exactly payload+seal", len(ids), ids)
	}

	// No import scratch beside the destination repo.
	des, _ := os.ReadDir(filepath.Dir(h.destRepo))
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-import-") {
			t.Errorf("import scratch dir %s left behind", d.Name())
		}
	}
}

// TestImportAdoptsIdentityAcrossSnapshots — the §16.1 identity
// continuity contract: importing capsules of TWO DIFFERENT snapshots
// from the SAME producer workspace must register them under ONE
// workspace row (the capsule's logical id — never a locally minted
// fork), so `ebb open <name>` can select the latest of the group.
func TestImportAdoptsIdentityAcrossSnapshots(t *testing.T) {
	// One producer world, two captures of one workspace (same root ⇒
	// same logical workspace id), exported into two capsules.
	h := newHHarness(t)
	snap1 := h.captureSnapshot(t)
	snap2 := h.captureSnapshot(t)
	if snap1.WorkspaceID != snap2.WorkspaceID {
		t.Fatalf("fixture wiring: two captures of one workspace produced ids %s and %s",
			snap1.WorkspaceID, snap2.WorkspaceID)
	}
	exportOne := func(snap catalog.Snapshot) (path, secret string) {
		t.Helper()
		out := filepath.Join(h.outDir, string(snap.ID)+".ebb")
		code, _, stderr := h.run("export", string(snap.ID), "--output", out)
		if code != ExitOK {
			t.Fatalf("fixture export of %s failed (%d): %s", snap.ID, code, stderr)
		}
		secret = passphraseOfBlock(stderr)
		if secret == "" {
			t.Fatal("no passphrase in the export terminal block")
		}
		return out, secret
	}
	cap1, secret1 := exportOne(snap1)
	cap2, secret2 := exportOne(snap2)

	// Both capsules into ONE destination world.
	ih := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, secret1)
	if code, _, stderr := ih.run("import", cap1); code != ExitOK {
		t.Fatalf("first import (%d): %s", code, stderr)
	}
	t.Setenv(EnvCapsulePassword, secret2)
	code, stdout, stderr := ih.run("import", "--json", cap2)
	if code != ExitOK {
		t.Fatalf("second import (%d): %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	det := env["details"].(map[string]any)
	if det["workspace_id"] != string(snap1.WorkspaceID) {
		t.Errorf("second import reports workspace_id %v, want the ADOPTED %s",
			det["workspace_id"], snap1.WorkspaceID)
	}

	// ONE workspace row carrying the capsule's logical id; TWO snapshot
	// rows under it, both pinned; two DONE import operations.
	cat := ih.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces after both imports = %v (%v), want exactly ONE", wss, err)
	}
	if wss[0].ID != snap1.WorkspaceID {
		t.Errorf("workspace id = %s, want the capsule's logical %s (identity continuity)", wss[0].ID, snap1.WorkspaceID)
	}
	if wss[0].Status != catalog.WorkspaceUnbound || wss[0].Name != "ws" {
		t.Errorf("adopted workspace row = %+v, want UNBOUND named %q", wss[0], "ws")
	}
	snaps, err := cat.ListSnapshots(snap1.WorkspaceID)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("snapshots under the adopted workspace = %v (%v), want both %s and %s",
			snaps, err, snap1.ID, snap2.ID)
	}
	gotIDs := map[domain.SnapshotID]bool{}
	for _, s := range snaps {
		if !s.Pinned {
			t.Errorf("snapshot %s is not pinned", s.ID)
		}
		gotIDs[s.ID] = true
	}
	if !gotIDs[snap1.ID] || !gotIDs[snap2.ID] {
		t.Errorf("registered snapshot ids = %v, want both capsule ids", gotIDs)
	}
	iops := importOpsOf(t, cat)
	if len(iops) != 2 {
		t.Fatalf("import ops = %d, want one journal per import", len(iops))
	}
	for _, op := range iops {
		if op.WorkspaceID != snap1.WorkspaceID || op.Phase != catalog.PhaseDone {
			t.Errorf("import op = %+v, want DONE under the adopted workspace", op)
		}
	}

	// The destination vault holds both pairs (2 payloads + 2 seals).
	if ids := ih.destSnaps(t); len(ids) != 4 {
		t.Errorf("destination vault holds %d snapshots (%v), want 4 (two payloads + two seals)", len(ids), ids)
	}
}

func TestImportIdempotentRerunAlreadyKnown(t *testing.T) {
	capPath, secret, _ := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, secret)

	if code, _, stderr := h.run("import", capPath); code != ExitOK {
		t.Fatalf("first import (%d): %s", code, stderr)
	}
	cat := h.cat()
	snapBefore := len(importOpsOf(t, cat))
	destBefore := len(h.destSnaps(t))

	code, stdout, stderr := h.run("import", "--json", capPath)
	if code != ExitOK {
		t.Fatalf("rerun code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || !mustCondition(env, "already-known") {
		t.Errorf("rerun outcome/conditions = %v / %v", env["outcome"], env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["already_known"] != true {
		t.Errorf("details already_known = %v, want true", det["already_known"])
	}
	if det["destination_payload_id"] != nil {
		t.Errorf("rerun reports a destination payload id: %v", det["destination_payload_id"])
	}

	// No second registration: same workspace/snapshot/replica counts,
	// no new operation, nothing added to the destination vault.
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces after rerun = %v (%v)", wss, err)
	}
	reps, err := cat.ListReplicas("")
	if err != nil || len(reps) != 1 {
		t.Fatalf("replicas after rerun = %v (%v)", reps, err)
	}
	if got := len(importOpsOf(t, cat)); got != snapBefore {
		t.Errorf("import ops after rerun = %d, want %d (no journal for a known snapshot)", got, snapBefore)
	}
	if got := len(h.destSnaps(t)); got != destBefore {
		t.Errorf("destination snapshots after rerun = %d, want %d", got, destBefore)
	}

	// Human mode states the idempotent outcome.
	code, _, stderr = h.run("import", capPath)
	if code != ExitOK || !strings.Contains(stderr, "already registered") || !strings.Contains(stderr, "nothing to do") {
		t.Errorf("human rerun: code=%d stderr=%s", code, stderr)
	}
}

func TestImportSameIDDifferentDigestRefused(t *testing.T) {
	capPath, secret, snapID := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, secret)

	// Manufacture the conflict: the capsule's logical id already
	// registered with a DIFFERENT manifest digest.
	cat := h.cat()
	wsID := domain.WorkspaceID(domain.NewID())
	if err := cat.UpsertWorkspace(catalog.Workspace{ID: wsID, Name: "conflict", Status: catalog.WorkspaceLive}); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.RecordSnapshot(catalog.Snapshot{
		ID: domain.SnapshotID(snapID), WorkspaceID: wsID,
		PayloadBackendID: "p", SealBackendID: "s",
		ManifestDigest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Kind:           catalog.SnapshotKindPark,
	}); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := h.run("import", "--json", capPath)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want 3", code)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "blocked" {
		t.Errorf("outcome = %v", env["outcome"])
	}
	errs := jsonOf(t, env)
	for _, want := range []string{CodeImportIDConflict, "different content", "refusing to overwrite"} {
		if !strings.Contains(errs, want) {
			t.Errorf("error lacks %q: %s", want, errs)
		}
	}

	// Nothing registered: no import operation, no replica, no
	// destination-vault mutation (the gate fires before the copy).
	if got := len(importOpsOf(t, cat)); got != 0 {
		t.Errorf("import ops = %d, want 0", got)
	}
	if reps, err := cat.ListReplicas(""); err != nil || len(reps) != 0 {
		t.Errorf("replicas = %v (%v)", reps, err)
	}
	if ids := h.destSnaps(t); len(ids) != 0 {
		t.Errorf("destination vault mutated: %v", ids)
	}
}

func TestImportWrongVaultName(t *testing.T) {
	capPath, secret, _ := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, secret) // so ONLY the vault error can fire

	code, stdout, _ := h.run("import", "--json", "--vault", "nope", capPath)
	if code != ExitUsage {
		t.Fatalf("code = %d, want 2", code)
	}
	if errs := jsonOf(t, envelopeOf(t, stdout)); !strings.Contains(errs, "no vault named") {
		t.Errorf("error lacks the unknown-vault wording: %s", errs)
	}
}

func TestImportMissingFile(t *testing.T) {
	h := newImportHarness(t)
	missing := filepath.Join(t.TempDir(), "nope.ebb")
	// No capsule password and no terminal: the file argument check must
	// still win (exit 2, not the passphrase block).
	code, _, stderr := h.run("import", "--json", missing)
	if code != ExitUsage {
		t.Fatalf("code = %d, want 2 (%s)", code, stderr)
	}
}

func TestImportNotACapsule(t *testing.T) {
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, "whatever")
	garbage := filepath.Join(t.TempDir(), "garbage.ebb")
	if err := os.WriteFile(garbage, []byte("not a capsule at all\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := h.run("import", "--json", garbage)
	if code != ExitUsage {
		t.Fatalf("code = %d, want 2", code)
	}
	if errs := jsonOf(t, envelopeOf(t, stdout)); !strings.Contains(errs, capsule.CodeNotACapsule) {
		t.Errorf("error lacks %s: %s", capsule.CodeNotACapsule, errs)
	}
}

func TestImportNoPassphraseSource(t *testing.T) {
	capPath, _, _ := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, "") // unset: env wins only when non-empty

	code, stdout, _ := h.run("import", "--json", capPath)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want 3", code)
	}
	errs := jsonOf(t, envelopeOf(t, stdout))
	for _, want := range []string{CodeImportPassphrase, EnvCapsulePassword, "terminal"} {
		if !strings.Contains(errs, want) {
			t.Errorf("error lacks %q: %s", want, errs)
		}
	}
	// Nothing was journaled or registered.
	cat := h.cat()
	if got := len(importOpsOf(t, cat)); got != 0 {
		t.Errorf("import ops = %d, want 0", got)
	}
	if ids := h.destSnaps(t); len(ids) != 0 {
		t.Errorf("destination vault mutated: %v", ids)
	}
}

func TestImportPassphrasePromptOnTerminal(t *testing.T) {
	capPath, secret, snapID := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, "")
	h.deps.StdinIsTerminal = func() bool { return true }
	var prompted bool
	h.deps.ReadLine = func() (string, error) {
		prompted = true
		return secret, nil
	}

	code, _, stderr := h.run("import", capPath)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !prompted || !strings.Contains(stderr, "capsule passphrase:") {
		t.Errorf("prompt not shown (prompted=%v):\n%s", prompted, stderr)
	}
	// The typed secret is the env-provided passphrase; it must not leak
	// into any report line.
	if strings.Count(stderr, secret) != 0 {
		t.Error("the passphrase appears in the import report")
	}
	cat := h.cat()
	if _, err := cat.GetSnapshot(domain.SnapshotID(snapID)); err != nil {
		t.Errorf("registered snapshot missing: %v", err)
	}
}

func TestImportDryRunTouchesNothing(t *testing.T) {
	capPath, _, _ := exportCapsule(t)
	h := newImportHarness(t)
	// No capsule password (dry-run must not need it) AND no vault
	// password: the dry-run plan never unlocks anything.
	t.Setenv(EnvCapsulePassword, "")
	t.Setenv(vault.EnvPassword, "")

	code, stdout, stderr := h.run("import", "--json", "--dry-run", capPath)
	if code != ExitOK {
		t.Fatalf("dry-run code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || !mustCondition(env, "dry-run") {
		t.Errorf("outcome/conditions = %v / %v", env["outcome"], env["conditions"])
	}
	det := env["details"].(map[string]any)
	for _, k := range []string{"repo_bytes", "repo_entries", "capsule_bytes", "container_version", "backend_family"} {
		if det[k] == nil || det[k] == float64(0) {
			t.Errorf("dry-run details lack %s: %v", k, det[k])
		}
	}
	if det["headroom_known"] != true || det["free_bytes"] == float64(0) {
		t.Errorf("dry-run headroom = %v / %v", det["headroom_known"], det["free_bytes"])
	}
	for _, k := range []string{"operation_id", "destination_payload_id", "destination_seal_id", "snapshot_id"} {
		if det[k] != nil && det[k] != "" {
			t.Errorf("dry-run details leak %s = %v", k, det[k])
		}
	}

	// No catalog rows, no vault calls (the vault password is gone; an
	// unlock attempt would have failed the command), no scratch.
	cat := h.cat()
	if ct, err := cat.Counts(); err != nil || ct.Workspaces != 0 || ct.Snapshots != 0 {
		t.Errorf("catalog counts = %d/%d (%v), want 0/0", ct.Workspaces, ct.Snapshots, err)
	}
	if got := len(importOpsOf(t, cat)); got != 0 {
		t.Errorf("import ops = %d, want 0", got)
	}
	if ids := h.destSnaps(t); len(ids) != 0 {
		t.Errorf("destination vault mutated by the dry-run: %v", ids)
	}
	des, _ := os.ReadDir(filepath.Dir(h.destRepo))
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-import-") {
			t.Errorf("dry-run left scratch dir %s", d.Name())
		}
	}

	// Human mode explains the boundary.
	code, _, stderr = h.run("import", "--dry-run", capPath)
	if code != ExitOK || !strings.Contains(stderr, "unlock happens at import") {
		t.Errorf("human dry-run: code=%d stderr=%s", code, stderr)
	}
}

func TestImportUnlockFailure(t *testing.T) {
	capPath, _, _ := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, "definitely-the-wrong-secret")

	code, stdout, _ := h.run("import", "--json", capPath)
	if code != ExitVault {
		t.Fatalf("code = %d, want 7", code)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "vault-unavailable" {
		t.Errorf("outcome = %v", env["outcome"])
	}
	if errs := jsonOf(t, env); !strings.Contains(errs, capsule.CodeCapsuleUnlock) {
		t.Errorf("error lacks %s: %s", capsule.CodeCapsuleUnlock, errs)
	}
	// Nothing registered; the capsule file is untouched.
	cat := h.cat()
	if ct, err := cat.Counts(); err != nil || ct.Workspaces != 0 || ct.Snapshots != 0 {
		t.Errorf("catalog counts = %d/%d (%v), want 0/0", ct.Workspaces, ct.Snapshots, err)
	}
	if ids := h.destSnaps(t); len(ids) != 0 {
		t.Errorf("destination vault mutated by a failed unlock: %v", ids)
	}
}

// TestImportCopyFailureClosesOperation pins the lazy journal's
// failClose discipline: a copy failure AFTER the journal opened leaves
// the operation CANCELED with its last durable phase recorded, no
// snapshot registered, and the destination vault empty.
func TestImportCopyFailureClosesOperation(t *testing.T) {
	capPath, secret, snapID := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, secret)
	h.store.onCopy = func(src, dst string, ids []string) error {
		return fmt.Errorf("simulated backend copy failure")
	}

	code, stdout, _ := h.run("import", "--json", capPath)
	if code != ExitCaptureVerify {
		t.Fatalf("code = %d, want 4", code)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "verification-failed" {
		t.Errorf("outcome = %v", env["outcome"])
	}
	if envString(t, env, "operation_id") == "" {
		t.Error("failure envelope lacks the journaled operation id")
	}

	cat := h.cat()
	iops := importOpsOf(t, cat)
	if len(iops) != 1 || iops[0].Phase != catalog.PhaseCanceled {
		t.Fatalf("import ops = %+v, want one CANCELED", iops)
	}
	if iops[0].LastError == "" {
		t.Error("CANCELED operation carries no last_error")
	}
	// The adopted workspace row remains (UNBOUND, named from the
	// capsule's manifest — the audit trail of the failed attempt; the
	// journal never names a snapshot), but nothing else registered.
	if _, err := cat.GetSnapshot(domain.SnapshotID(snapID)); err == nil {
		t.Error("a snapshot row was registered from a failed import")
	}
	if reps, err := cat.ListReplicas(""); err != nil || len(reps) != 0 {
		t.Errorf("replicas = %v (%v)", reps, err)
	}
	if ids := h.destSnaps(t); len(ids) != 0 {
		t.Errorf("destination vault holds import artifacts after a failed copy: %v", ids)
	}
	des, _ := os.ReadDir(filepath.Dir(h.destRepo))
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-import-") {
			t.Errorf("import scratch dir %s left behind", d.Name())
		}
	}
}

// TestImportExitClassifications pins the CLI-owned mapping of the
// capsule package's typed import failures onto §17.5 exit codes (the
// headroom and trim refusals are disk/kind-dependent and covered
// end-to-end in internal/capsule; their CLASSIFICATION is this layer's
// contract).
func TestImportExitClassifications(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want int
		name string
	}{
		{&capsule.ErrCapsuleUnlock{Path: "c.ebb"}, ExitVault, "wrong capsule passphrase"},
		{&capsule.ErrNotACapsule{Path: "c.ebb"}, ExitUsage, "not a capsule"},
		{&capsule.ErrImportSpace{Volume: "v", FreeBytes: 1, NeedBytes: 2, RepoBytes: 1}, ExitBlocked, "headroom"},
		{&capsule.ErrTrimCapsule{Path: "c.ebb"}, ExitBlocked, "trim capsule"},
		{&capsule.ErrCopyIntegrity{}, ExitCaptureVerify, "unprovable copy"},
		{capsule.ErrInvalidParams("x"), ExitUsage, "invalid params"},
		{&capsule.ErrVerification{Check: "capsule-seal"}, ExitCaptureVerify, "failed check"},
		{fmt.Errorf("wrapped: %w", &capsule.ErrImportSpace{Volume: "v"}), ExitBlocked, "wrapped headroom"},
	} {
		if got := classifyExitCode(tc.err); got != tc.want {
			t.Errorf("%s: classifyExitCode = %d, want %d", tc.name, got, tc.want)
		}
	}
	// The typed errors carry their §5.5 codes through codedMessage.
	msg := codedWithSafeAction(fmt.Errorf("x: %w", &capsule.ErrCapsuleUnlock{Path: "c.ebb"}))
	if !strings.Contains(msg, capsule.CodeCapsuleUnlock) {
		t.Errorf("coded message lacks the stable code: %s", msg)
	}
}

func TestInspectCapsulePublicOnly(t *testing.T) {
	capPath, _, _ := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, "") // public facts only

	code, stdout, stderr := h.run("inspect", "--json", capPath)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || !mustCondition(env, "capsule-public-metadata") {
		t.Errorf("outcome/conditions = %v / %v", env["outcome"], env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["verified"] != false {
		t.Errorf("verified = %v, want false without the env var", det["verified"])
	}
	if det["container_version"] != float64(1) || det["backend_family"] != "restic" {
		t.Errorf("public facts = %v / %v", det["container_version"], det["backend_family"])
	}
	if !strings.Contains(det["producer"].(string), "ebb") || det["repo_bytes"] == float64(0) || det["repo_entries"] == float64(0) {
		t.Errorf("public facts incomplete: %v", det)
	}
	fi, err := os.Stat(capPath)
	if err != nil {
		t.Fatal(err)
	}
	if det["capsule_bytes"] != float64(fi.Size()) {
		t.Errorf("capsule_bytes = %v, want %d", det["capsule_bytes"], fi.Size())
	}
	// Human mode carries the verification hint (json mode suppresses
	// the human report, so check it on its own invocation).
	code, _, stderr = h.run("inspect", capPath)
	if code != ExitOK || !strings.Contains(stderr, EnvCapsulePassword) {
		t.Errorf("human report lacks the env-var hint: code=%d\n%s", code, stderr)
	}
	// Zero registrations, vault untouched.
	cat := h.cat()
	if ct, cerr := cat.Counts(); cerr != nil || ct.Workspaces != 0 || ct.Snapshots != 0 {
		t.Errorf("catalog counts = %d/%d (%v), want 0/0", ct.Workspaces, ct.Snapshots, cerr)
	}
	if ids := h.destSnaps(t); len(ids) != 0 {
		t.Errorf("destination vault mutated by inspect: %v", ids)
	}
}

func TestInspectCapsuleVerifiedRegistersNothing(t *testing.T) {
	capPath, secret, snapID := exportCapsule(t)
	h := newImportHarness(t)
	t.Setenv(EnvCapsulePassword, secret)

	code, stdout, stderr := h.run("inspect", "--json", capPath)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if !mustCondition(env, "capsule-verified") || !mustCondition(env, "nothing-registered") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["verified"] != true {
		t.Fatalf("verified = %v", det["verified"])
	}
	if det["snapshot_id"] != snapID {
		t.Errorf("snapshot_id = %v, want %s", det["snapshot_id"], snapID)
	}
	if det["workspace"] != "ws" || det["kind"] == "" || det["manifest_digest"] == "" {
		t.Errorf("verified facts incomplete: %v", det)
	}
	if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
		t.Error("THE CAPSULE PASSPHRASE LEAKED INTO THE INSPECT OUTPUT")
	}

	// ZERO registrations: no workspace, no snapshot, no replica, no
	// operation, no destination-vault mutation (staging was private).
	cat := h.cat()
	if ct, err := cat.Counts(); err != nil || ct.Workspaces != 0 || ct.Snapshots != 0 {
		t.Errorf("catalog counts = %d/%d (%v), want 0/0", ct.Workspaces, ct.Snapshots, err)
	}
	if got := len(importOpsOf(t, cat)); got != 0 {
		t.Errorf("import ops = %d, want 0", got)
	}
	if ids := h.destSnaps(t); len(ids) != 0 {
		t.Errorf("destination vault mutated by verified inspect: %v", ids)
	}
}

func TestInspectNotACapsuleFile(t *testing.T) {
	h := newImportHarness(t)
	garbage := filepath.Join(t.TempDir(), "garbage.ebb")
	if err := os.WriteFile(garbage, []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := h.run("inspect", "--json", garbage)
	if code != ExitUsage {
		t.Fatalf("code = %d, want 2", code)
	}
	if errs := jsonOf(t, envelopeOf(t, stdout)); !strings.Contains(errs, capsule.CodeNotACapsule) {
		t.Errorf("error lacks %s: %s", capsule.CodeNotACapsule, errs)
	}
}

func TestImportDispatchWiring(t *testing.T) {
	h := newImportHarness(t)
	capPath, _, _ := exportCapsule(t)

	// The usage summary names the command.
	code, _, stderr := h.run("help")
	if code != ExitOK || !strings.Contains(stderr, "import <file>") {
		t.Errorf("usage lacks the import command: code=%d\n%s", code, stderr)
	}
	// Unknown flag: exit 2 (also proves the flag set is wired).
	if code, _, _ := h.run("import", "--bogus", capPath); code != ExitUsage {
		t.Errorf("unknown flag code = %d, want 2", code)
	}
	// No positional: exit 2.
	if code, _, _ := h.run("import"); code != ExitUsage {
		t.Errorf("missing argument code = %d, want 2", code)
	}
	// A directory argument is not a capsule file.
	if code, _, _ := h.run("import", h.stateDir); code != ExitUsage {
		t.Errorf("directory argument code = %d, want 2", code)
	}
	// The workspace-root inspect mode still works (no session needed).
	if code, _, _ := h.run("inspect", h.stateDir); code == ExitUsage {
		t.Error("directory inspect broke")
	}
}
