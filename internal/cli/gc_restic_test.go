// gc_restic_test.go: `ebb gc` end to end against the REAL restic binary
// (the Wave E/D013 real-backend discipline — the fake-store tests cannot
// see physical reclamation, lock typing or the forget→gc→verify data
// safety chain). Skips with a reason when restic is not usable.
//
// The regression contract under test (Wave H gate): FORGET→GC must never
// release a PINNED snapshot's data. Two snapshots share one blob family
// and each holds a unique family; forgetting the first and running gc
// must physically shrink the vault while the survivor still reads back
// fully (`ebb verify --content` = every preserved byte re-read and
// digest-checked through the backend).

package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	resticstore "github.com/0Cymantek0/ebb/internal/storage/restic"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// gcTestPassword is the repository password shared by the env source
// (EBB_VAULT_PASSWORD — how the CLI unlocks the vault) and the test's
// own passfile for direct store access.
const gcTestPassword = "gc-restic-suite-password"

// gcResticEnv is the real-stack gc harness: one real restic repository
// registered as the default vault, the real catalog under a temp state
// dir, and the full production Deps except that NewStore returns the
// test's already-opened store (so the private cache dir cleanup is
// owned once).
type gcResticEnv struct {
	t        *testing.T
	store    *resticstore.Store
	deps     Deps
	stateDir string
	wsRoot   string
	repoDir  string
	passfile string
}

func newGcResticEnv(t *testing.T) *gcResticEnv {
	t.Helper()
	bin := os.Getenv("EBB_TEST_RESTIC_BIN")
	if bin == "" {
		bin = "restic"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("restic binary %q not usable on this machine (%v); real-backend gc suite skipped", bin, err)
	}
	store := resticstore.New(path)
	t.Cleanup(store.Close)

	base := t.TempDir()
	e := &gcResticEnv{
		t: t, store: store,
		stateDir: filepath.Join(base, "state"),
		wsRoot:   filepath.Join(base, "gcws"),
		repoDir:  filepath.Join(base, "vault"),
		passfile: filepath.Join(base, "repo.pass"),
	}
	if err := os.MkdirAll(e.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.wsRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.passfile, []byte(gcTestPassword), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Init(ctx, e.repoDir, e.passfile); err != nil {
		t.Fatalf("restic init: %v", err)
	}

	// The vault's unlock secret comes from the env source, so it must be
	// the SAME password the repository was initialized with.
	t.Setenv(vault.EnvPassword, gcTestPassword)
	if _, err := vault.New(filepath.Join(e.stateDir, vault.RegistryFile)).Register("main", e.repoDir, ""); err != nil {
		t.Fatal(err)
	}

	deps := RealDeps()
	deps.StateDir = func() (string, error) { return e.stateDir, nil }
	deps.OpenCatalog = catalog.Open
	deps.NewStore = func() (domain.SnapshotStore, func(), error) { return e.store, func() {}, nil }
	e.deps = deps
	return e
}

func (e *gcResticEnv) run(args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb strings.Builder
	code := Main(args, Streams{Out: &out, Err: &errb}, e.deps)
	return code, out.String(), errb.String()
}

func (e *gcResticEnv) cat() *catalog.Catalog {
	e.t.Helper()
	c, err := catalog.Open(filepath.Join(e.stateDir, vault.CatalogFile))
	if err != nil {
		e.t.Fatalf("open catalog: %v", err)
	}
	e.t.Cleanup(func() { c.Close() })
	return c
}

// gcLcg returns n deterministic incompressible bytes.
func gcLcg(n int, seed uint32) []byte {
	out := make([]byte, n)
	next := seed
	for i := range out {
		next = next*1664525 + 1013904223
		out[i] = byte(next >> 23)
	}
	return out
}

func gcWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func gcRepoSize(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			if fi, ierr := d.Info(); ierr == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return total
}

func gcBackendIDs(t *testing.T, e *gcResticEnv) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	refs, err := e.store.List(ctx, e.repoDir, e.passfile)
	if err != nil {
		t.Fatalf("restic list: %v", err)
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.BackendID)
	}
	return ids
}

// TestGcResticForgetGcVerifySurvivor is the Wave H gate: the physical
// loop closes (forget → gc → vault shrinks) and a PINNED survivor's
// data is never released (verify --content reads every byte back).
func TestGcResticForgetGcVerifySurvivor(t *testing.T) {
	e := newGcResticEnv(t)

	// Two logical snapshots: shared content plus a unique family each.
	gcWrite(t, filepath.Join(e.wsRoot, "shared.bin"), gcLcg(1<<20, 1))
	gcWrite(t, filepath.Join(e.wsRoot, "unique-1.bin"), gcLcg(1<<20, 2))
	if code, _, stderr := e.run("snapshot", e.wsRoot); code != ExitOK {
		t.Fatalf("snapshot 1 code = %d, stderr = %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(e.wsRoot, "unique-1.bin")); err != nil {
		t.Fatal(err)
	}
	gcWrite(t, filepath.Join(e.wsRoot, "unique-2.bin"), gcLcg(1<<20, 3))
	if code, _, stderr := e.run("snapshot", e.wsRoot); code != ExitOK {
		t.Fatalf("snapshot 2 code = %d, stderr = %s", code, stderr)
	}

	cat := e.cat()
	wsList, err := cat.ListWorkspaces()
	if err != nil || len(wsList) != 1 {
		t.Fatalf("workspaces = %v (%v)", wsList, err)
	}
	snaps, err := cat.ListSnapshots(wsList[0].ID)
	if err != nil || len(snaps) != 2 {
		t.Fatalf("snapshots = %v (%v)", snaps, err)
	}
	first, survivor := snaps[0], snaps[1]

	// Forget the first snapshot (the shared chunks stay referenced by
	// the survivor; unique-1's bytes become unreferenced).
	sizeBeforeForget := gcRepoSize(t, e.repoDir)
	if code, _, stderr := e.run("forget", string(first.ID), "--yes"); code != ExitOK {
		t.Fatalf("forget code = %d, stderr = %s", code, stderr)
	}

	idsBeforeGc := gcBackendIDs(t, e)

	// ---- gc --dry-run: eligibility + estimate, NO mutation -------------
	sizeBeforeDry := gcRepoSize(t, e.repoDir)
	code, stdout, stderr := e.run("gc", "--json", "--dry-run", "main")
	if code != ExitOK {
		t.Fatalf("gc --dry-run code = %d, stderr = %s", code, stderr)
	}
	if got := gcRepoSize(t, e.repoDir); got != sizeBeforeDry {
		t.Fatalf("gc --dry-run mutated the repository: %d -> %d", sizeBeforeDry, got)
	}
	envDry := envelopeOf(t, stdout)
	if !mustCondition(envDry, "dry-run") {
		t.Errorf("dry-run conditions = %v", envDry["conditions"])
	}
	detDry := envDry["details"].(map[string]any)
	if est, _ := detDry["reclaimable_estimate_bytes"].(float64); est <= 0 {
		t.Errorf("dry-run reclaim estimate = %v, want > 0 (1 MiB of forgotten-only data)", detDry["reclaimable_estimate_bytes"])
	}

	// ---- gc: the physical loop closes ----------------------------------
	code, stdout, stderr = e.run("gc", "--json", "main")
	if code != ExitOK {
		t.Fatalf("gc code = %d, stderr = %s", code, stderr)
	}
	envReal := envelopeOf(t, stdout)
	if !mustCondition(envReal, "pruned") || !mustCondition(envReal, "snapshots-verified-unchanged") {
		t.Errorf("gc conditions = %v", envReal["conditions"])
	}
	detReal := envReal["details"].(map[string]any)
	if freed, _ := detReal["freed_observed"].(float64); freed <= 0 {
		t.Fatalf("freed_observed = %v, want > 0 (details: %v)", detReal["freed_observed"], detReal)
	}
	sizeAfterGc := gcRepoSize(t, e.repoDir)
	if sizeAfterGc >= sizeBeforeForget {
		t.Errorf("vault did not physically shrink vs before-forget: %d -> %d", sizeBeforeForget, sizeAfterGc)
	}
	t.Logf("gc freed %.2f MiB walked (vault %d -> %d bytes; estimate %.0f)",
		float64(sizeBeforeForget-sizeAfterGc)/(1<<20), sizeBeforeForget, sizeAfterGc, detReal["reclaimable_estimate_bytes"].(float64))

	// Workspace/snapshot sets intact: survivor pinned and present; the
	// gc itself did not touch any backend snapshot (set identical).
	if idsAfter := gcBackendIDs(t, e); len(idsAfter) != len(idsBeforeGc) {
		t.Fatalf("gc changed the backend snapshot set: %v -> %v", idsBeforeGc, idsAfter)
	}
	got, err := cat.GetSnapshot(survivor.ID)
	if err != nil || !got.Pinned {
		t.Fatalf("survivor row damaged by gc: %+v (%v)", got, err)
	}
	if detReal["retained_snapshots"].(float64) != 1 || detReal["pinned_snapshots"].(float64) != 1 {
		t.Errorf("retained/pinned = %v/%v, want 1/1", detReal["retained_snapshots"], detReal["pinned_snapshots"])
	}

	// ---- THE regression: the survivor still reads back fully ------------
	// verify --content re-reads every preserved byte through the backend
	// and digest-checks it — proof gc released nothing the pinned
	// survivor references (the shared chunks must still exist).
	if code, _, stderr := e.run("verify", string(survivor.ID), "--content"); code != ExitOK {
		t.Fatalf("post-gc verify --content code = %d, stderr = %s", code, stderr)
	}
	assertNoSecrets(t, stdout)
	assertNoSecrets(t, stderr)
}

// TestGcResticRefusedWhileOperationActive: the eligibility gate must
// hold against a REAL durable active operation even though the vault is
// reachable and prunable (F38: a capture must never race a prune).
func TestGcResticRefusedWhileOperationActive(t *testing.T) {
	e := newGcResticEnv(t)
	gcWrite(t, filepath.Join(e.wsRoot, "a.bin"), gcLcg(64<<10, 7))
	if code, _, stderr := e.run("snapshot", e.wsRoot); code != ExitOK {
		t.Fatalf("snapshot code = %d, stderr = %s", code, stderr)
	}
	cat := e.cat()
	wsList, _ := cat.ListWorkspaces()
	opID, err := cat.BeginOperation(wsList[0].ID, catalog.OpKindOpen, "/dest", "", "")
	if err != nil {
		t.Fatal(err)
	}

	code, _, stderr := e.run("gc", "main")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeGcActiveOperation, string(opID))
}

// TestGcResticCleanNoOpOnEmptyVault: a fresh vault with no snapshots is
// a valid nothing-to-reclaim result (exit 0), and prune never runs.
func TestGcResticCleanNoOpOnEmptyVault(t *testing.T) {
	e := newGcResticEnv(t)
	if ids := gcBackendIDs(t, e); len(ids) != 0 {
		t.Fatalf("fresh vault holds snapshots: %v", ids)
	}
	code, _, stderr := e.run("gc", "main")
	if code != ExitOK {
		t.Fatalf("empty-vault gc code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "nothing to reclaim") {
		t.Errorf("stderr = %s", stderr)
	}
	if ids := gcBackendIDs(t, e); len(ids) != 0 {
		t.Errorf("empty vault changed: %v", ids)
	}
}
