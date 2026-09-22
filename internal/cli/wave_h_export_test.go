// wave_h_export_test.go drives `ebb export` end to end through the Deps
// seam: a temp state directory, the REAL catalog, the REAL platform
// probe, a DISK-BACKED repo-scoped fake store implementing the capsule
// copy seam (with fault hooks), and a registered vault unlocked via
// EBB_VAULT_PASSWORD. The real-restic product-level acceptance lives in
// internal/capsule/e2e_reSTORic_test.go; this file pins the CLI
// contract: exit codes, envelope shape, pin/journal/replicas durable
// state, passphrase display rules, dry-run, and the refusals.

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/lifecycle"
	"github.com/0Cymantek0/ebb/internal/platform"
	"github.com/0Cymantek0/ebb/internal/restore"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// ---- hStore: disk-backed repo-scoped fake with the copy seam ------------
//
// The capsule exporter walks, packages and re-opens the destination
// repository as a real directory tree, so the fake must keep every
// repository ON DISK: <repoDir>/config (repo id), <repoDir>/keys/hkey
// (the password — standing in for the encrypted key file) and
// <repoDir>/snaps/<id>/{meta.json,blobs/<n>}. An extracted copy of a
// repository then works with no extra machinery, exactly like restic.

type hSnapMeta struct {
	Tags  map[string]string `json:"tags"`
	Files []hSnapFile       `json:"files"`
	Dirs  []string          `json:"dirs"`
}

type hSnapFile struct {
	TreePath string `json:"tree_path"`
	Blob     string `json:"blob"`
	Size     int64  `json:"size"`
}

type hStore struct {
	mu  sync.Mutex
	seq int
	// Fault hooks (nil = healthy).
	onCopy     func(src, dst string, ids []string) error
	onCopyDone func(dst string)
}

func newHStore() *hStore { return &hStore{} }

type hRepoConfig struct {
	ID string `json:"id"`
}

func hReadConfig(repoDir string) (hRepoConfig, error) {
	b, err := os.ReadFile(filepath.Join(repoDir, "config"))
	if err != nil {
		return hRepoConfig{}, err
	}
	var c hRepoConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return hRepoConfig{}, err
	}
	return c, nil
}

func (s *hStore) auth(repoDir, passfile string) error {
	key, err := os.ReadFile(filepath.Join(repoDir, "keys", "hkey"))
	if err != nil {
		return &domain.StoreError{Class: domain.StoreErrRepo, Err: fmt.Errorf("hStore: no repository at %s", repoDir)}
	}
	pw, rerr := os.ReadFile(passfile)
	if rerr != nil || string(pw) != string(key) {
		return &domain.StoreError{Class: domain.StoreErrAuth, Err: fmt.Errorf("hStore: wrong password for %s", repoDir)}
	}
	return nil
}

func (s *hStore) Init(ctx context.Context, dir, passfile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := os.Stat(filepath.Join(dir, "config")); err == nil {
		return &domain.StoreError{Class: domain.StoreErrRepo, Err: fmt.Errorf("hStore: %s already initialized", dir)}
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "snaps"), 0o700); err != nil {
		return err
	}
	pw, _ := os.ReadFile(passfile)
	if err := os.WriteFile(filepath.Join(dir, "keys", "hkey"), pw, 0o600); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte("hrepo:" + dir))
	raw, _ := json.Marshal(hRepoConfig{ID: hex.EncodeToString(sum[:16])})
	return os.WriteFile(filepath.Join(dir, "config"), raw, 0o600)
}

func (s *hStore) RepoID(ctx context.Context, dir, passfile string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.auth(dir, passfile); err != nil {
		return "", err
	}
	c, err := hReadConfig(dir)
	if err != nil {
		return "", &domain.StoreError{Class: domain.StoreErrRepo, Err: err}
	}
	return c.ID, nil
}

func (s *hStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.auth(repoDir, passfile); err != nil {
		return domain.SnapshotRef{}, err
	}
	s.seq++
	sum := sha256.Sum256(fmt.Appendf(nil, "hstore-snap-%d", s.seq))
	id := hex.EncodeToString(sum[:])
	meta := hSnapMeta{Tags: map[string]string{}}
	for k, v := range tags {
		meta.Tags[k] = v
	}
	snapDir := filepath.Join(repoDir, "snaps", id)
	if err := os.MkdirAll(filepath.Join(snapDir, "blobs"), 0o700); err != nil {
		return domain.SnapshotRef{}, err
	}
	files := map[string][]byte{}
	dirs := map[string]bool{}
	if err := hWalkInto(files, dirs, baseDir, relPaths); err != nil {
		return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrSource, Err: err}
	}
	n := 0
	for p := range dirs {
		meta.Dirs = append(meta.Dirs, p)
	}
	for p := range files {
		n++
		blob := fmt.Sprintf("b%06d", n)
		if err := os.WriteFile(filepath.Join(snapDir, "blobs", blob), files[p], 0o600); err != nil {
			return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrSource, Err: err}
		}
		meta.Files = append(meta.Files, hSnapFile{TreePath: p, Blob: blob, Size: int64(len(files[p]))})
	}
	raw, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(snapDir, "meta.json"), raw, 0o600); err != nil {
		return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrSource, Err: err}
	}
	return domain.SnapshotRef{BackendID: id, ShortID: id[:8], Time: "2026-09-19T00:00:00Z", Paths: relPaths, Tags: meta.Tags}, nil
}

// hWalkInto records the listed baseDir-relative paths as tree paths.
func hWalkInto(files map[string][]byte, dirs map[string]bool, baseDir string, relPaths []string) error {
	addAncestors := func(treePath string) {
		segs := strings.Split(strings.TrimPrefix(treePath, "/"), "/")
		for i := 1; i < len(segs); i++ {
			dirs["/"+strings.Join(segs[:i], "/")] = true
		}
	}
	var walk func(rel string) error
	walk = func(rel string) error {
		abs := filepath.Join(baseDir, filepath.FromSlash(rel))
		fi, err := os.Lstat(abs)
		if err != nil {
			return err
		}
		treePath := "/" + rel
		switch {
		case fi.Mode().IsRegular():
			b, err := os.ReadFile(abs)
			if err != nil {
				return err
			}
			addAncestors(treePath)
			files[treePath] = b
		case fi.IsDir():
			addAncestors(treePath)
			dirs[treePath] = true
			des, err := os.ReadDir(abs)
			if err != nil {
				return err
			}
			for _, de := range des {
				if err := walk(rel + "/" + de.Name()); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("hStore: unsupported object %s (%s)", abs, fi.Mode())
		}
		return nil
	}
	for _, rel := range relPaths {
		if err := walk(rel); err != nil {
			return err
		}
	}
	return nil
}

func (s *hStore) readMeta(repoDir, snapID string) (hSnapMeta, error) {
	raw, err := os.ReadFile(filepath.Join(repoDir, "snaps", snapID, "meta.json"))
	if err != nil {
		return hSnapMeta{}, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("hStore: no snapshot %s in %s", snapID, repoDir)}
	}
	var m hSnapMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return hSnapMeta{}, &domain.StoreError{Class: domain.StoreErrUnknown, Err: err}
	}
	return m, nil
}

func (s *hStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.auth(repoDir, passfile); err != nil {
		return nil, err
	}
	des, err := os.ReadDir(filepath.Join(repoDir, "snaps"))
	if err != nil {
		return nil, &domain.StoreError{Class: domain.StoreErrRepo, Err: err}
	}
	var out []domain.SnapshotRef
	for _, de := range des {
		m, merr := s.readMeta(repoDir, de.Name())
		if merr != nil {
			continue
		}
		out = append(out, domain.SnapshotRef{BackendID: de.Name(), ShortID: de.Name()[:8], Time: "2026-09-19T00:00:00Z", Tags: m.Tags})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BackendID < out[j].BackendID })
	return out, nil
}

func (s *hStore) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.auth(repoDir, passfile); err != nil {
		return nil, err
	}
	m, err := s.readMeta(repoDir, snapID)
	if err != nil {
		return nil, err
	}
	var out []domain.TreeEntry
	for _, d := range m.Dirs {
		out = append(out, domain.TreeEntry{Path: d, Kind: domain.KindDir})
	}
	for _, f := range m.Files {
		out = append(out, domain.TreeEntry{Path: f.TreePath, Kind: domain.KindFile, Size: f.Size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s *hStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.auth(repoDir, passfile); err != nil {
		return nil, err
	}
	m, err := s.readMeta(repoDir, snapID)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for _, f := range m.Files {
		if f.TreePath == path {
			return os.ReadFile(filepath.Join(repoDir, "snaps", snapID, "blobs", f.Blob))
		}
	}
	return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("hStore: %s not in %s", path, snapID)}
}

func (s *hStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	return &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("hStore: restore not needed by the export tests")}
}

func (s *hStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.auth(repoDir, passfile); err != nil {
		return err
	}
	for _, id := range snapIDs {
		if err := os.RemoveAll(filepath.Join(repoDir, "snaps", id)); err != nil {
			return err
		}
	}
	return nil
}

// Copy mirrors the probe-verified restic semantics: snapshot ids CHANGE
// on copy, tags are preserved, and the copy lands in the destination
// repository's own on-disk snapshot space.
func (s *hStore) Copy(ctx context.Context, srcRepoDir, srcPassfile, dstRepoDir, dstPassfile string, snapIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.auth(srcRepoDir, srcPassfile); err != nil {
		return err
	}
	if err := s.auth(dstRepoDir, dstPassfile); err != nil {
		return err
	}
	if s.onCopy != nil {
		if err := s.onCopy(srcRepoDir, dstRepoDir, snapIDs); err != nil {
			return &domain.StoreError{Class: domain.StoreErrSource, Err: err}
		}
	}
	for _, id := range snapIDs {
		if _, err := os.Stat(filepath.Join(srcRepoDir, "snaps", id)); err != nil {
			// restic exits 0 with an Ignoring line; the adapter converts
			// that — mirror the typed failure here.
			return &domain.StoreError{Class: domain.StoreErrSource, Err: fmt.Errorf("hStore: copy: Ignoring %q: not in the source repository", id)}
		}
		s.seq++
		sum := sha256.Sum256(fmt.Appendf(nil, "hstore-copy-%d", s.seq))
		if err := os.MkdirAll(filepath.Join(dstRepoDir, "snaps"), 0o700); err != nil {
			return err
		}
		if err := copyTree(filepath.Join(srcRepoDir, "snaps", id), filepath.Join(dstRepoDir, "snaps", hex.EncodeToString(sum[:]))); err != nil {
			return &domain.StoreError{Class: domain.StoreErrSource, Err: err}
		}
	}
	if s.onCopyDone != nil {
		s.onCopyDone(dstRepoDir)
	}
	return nil
}

// copyTree is a plain recursive directory copy (test double).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, p)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		return os.WriteFile(target, b, 0o600)
	})
}

// ---- harness ------------------------------------------------------------

type hHarness struct {
	t        *testing.T
	stateDir string
	wsRoot   string
	outDir   string
	store    *hStore
	deps     Deps
}

func newHHarness(t *testing.T) *hHarness {
	t.Helper()
	base := t.TempDir()
	h := &hHarness{
		t:        t,
		stateDir: filepath.Join(base, "state"),
		wsRoot:   filepath.Join(base, "ws"),
		outDir:   filepath.Join(base, "out"),
		store:    newHStore(),
	}
	if err := os.MkdirAll(h.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(h.outDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for rel, content := range map[string]string{
		"README.md":     "# export cli fixture\n",
		"notes.md":      "private notes\n",
		"src/main.go":   "package main\n\nfunc main() { println(\"x\") }\n",
		"assets/b.bin":  strings.Repeat("blob ", 400),
		"docs/deep.txt": "nested file\n",
	} {
		p := filepath.Join(h.wsRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv(vault.EnvPassword, "hexport-test-secret")
	repoDir := filepath.Join(base, "vault")
	if err := os.MkdirAll(repoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.New(filepath.Join(h.stateDir, vault.RegistryFile)).Register("main", repoDir, ""); err != nil {
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

func (h *hHarness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var out, errb strings.Builder
	code := Main(args, Streams{Out: &out, Err: &errb}, h.deps)
	return code, out.String(), errb.String()
}

func (h *hHarness) cat() *catalog.Catalog {
	h.t.Helper()
	c, err := catalog.Open(filepath.Join(h.stateDir, vault.CatalogFile))
	if err != nil {
		h.t.Fatalf("open catalog: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

// capture runs one `ebb snapshot` through the harness world and returns
// the retained snapshot row (kind "snapshot", sealed, pinned).
func (h *hHarness) captureSnapshot(t *testing.T) catalog.Snapshot {
	t.Helper()
	code, _, stderr := h.run("snapshot", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("fixture snapshot failed (%d): %s", code, stderr)
	}
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces = %v (%v)", wss, err)
	}
	snaps, err := cat.ListSnapshots(wss[0].ID)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("snapshots = %v (%v)", snaps, err)
	}
	return snaps[len(snaps)-1] // creation order; the newest is the one just made
}

// exportOpsOf returns the workspace's export-kind operation rows.
func exportOpsOf(t *testing.T, cat *catalog.Catalog, ws domain.WorkspaceID) []catalog.Operation {
	t.Helper()
	all, err := cat.ListOperations(ws)
	if err != nil {
		t.Fatalf("list operations: %v", err)
	}
	var out []catalog.Operation
	for _, op := range all {
		if op.Kind == catalog.OpKindExport {
			out = append(out, op)
		}
	}
	return out
}

// ---- tests ---------------------------------------------------------------

func TestExportHappyPathCLI(t *testing.T) {
	h := newHHarness(t)
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "capsule.ebb")

	code, stdout, stderr := h.run("export", "--json", string(snap.ID), "--output", out)
	if code != ExitOK {
		t.Fatalf("export code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || envString(t, env, "command") != "export" {
		t.Errorf("outcome/command = %v/%v", env["outcome"], env["command"])
	}
	for _, want := range []string{"independent-encryption-domain", "source-stays-pinned", "verified-before-publication"} {
		if !mustCondition(env, want) {
			t.Errorf("conditions missing %q: %v", want, env["conditions"])
		}
	}
	det := env["details"].(map[string]any)
	if det["output_path"] != out {
		t.Errorf("details output_path = %v", det["output_path"])
	}
	if det["passphrase"] != "displayed on terminal only; not recorded in machine output" {
		t.Errorf("details passphrase = %v", det["passphrase"])
	}

	// Passphrase display contract: the secret appears ONCE on the
	// terminal (stderr), NEVER in the machine stdout.
	if !strings.Contains(stderr, "CAPSULE PASSPHRASE") {
		t.Errorf("stderr lacks the marked passphrase block:\n%s", stderr)
	}
	secret := passphraseOfBlock(stderr)
	if secret == "" {
		t.Fatal("no passphrase line found in the block")
	}
	if strings.Contains(stdout, secret) {
		t.Fatal("THE CAPSULE PASSPHRASE LEAKED INTO THE JSON ENVELOPE")
	}
	if strings.Count(stderr, secret) != 1 {
		t.Errorf("passphrase printed %d times in stderr, want exactly 1", strings.Count(stderr, secret))
	}

	// Publication shape: capsule exists, no partial, no workdir.
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("capsule missing: %v", err)
	}
	des, _ := os.ReadDir(h.outDir)
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-") || strings.HasSuffix(d.Name(), ".partial") {
			t.Errorf("scratch artifact %s left behind", d.Name())
		}
	}

	// Durable state: op DONE, replica recorded, pin audit shows the
	// export pin taken AND released while the snapshot stays pinned.
	cat := h.cat()
	fresh, err := cat.GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.Pinned {
		t.Error("source snapshot lost its pin")
	}
	sawPin, sawRelease := false, false
	for _, r := range fresh.PinReasons {
		if strings.HasPrefix(r, "pin:export:") {
			sawPin = true
		}
		if strings.HasPrefix(r, "unpin:export:") {
			sawRelease = true
		}
	}
	if !sawPin || !sawRelease {
		t.Errorf("pin audit = %v (want both the export pin and its release)", fresh.PinReasons)
	}
	eops := exportOpsOf(t, cat, fresh.WorkspaceID)
	if len(eops) != 1 || eops[0].Phase != catalog.PhaseDone {
		t.Errorf("export ops = %+v, want one DONE", eops)
	}
	reps, err := cat.ListReplicas(fresh.ID)
	if err != nil || len(reps) != 1 {
		t.Fatalf("replicas = %v (%v)", reps, err)
	}
	if reps[0].Path != out || reps[0].VaultID != "" || !strings.Contains(reps[0].Scope, "capsule-export:") {
		t.Errorf("replica row = %+v", reps[0])
	}
}

func passphraseOfBlock(stderr string) string {
	lines := strings.Split(stderr, "\n")
	for i, l := range lines {
		if strings.Contains(l, "CAPSULE PASSPHRASE") && i+1 < len(lines) {
			cand := strings.TrimSpace(lines[i+1])
			if cand != "" && !strings.HasPrefix(cand, "Store") {
				return cand
			}
		}
	}
	return ""
}

func TestExportHumanModePassphraseOnStderr(t *testing.T) {
	h := newHHarness(t)
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "human.ebb")
	code, stdout, stderr := h.run("export", string(snap.ID), "--output", out)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("human mode wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "CAPSULE PASSPHRASE") {
		t.Error("human mode lacks the passphrase block")
	}
}

func TestExportDryRun(t *testing.T) {
	h := newHHarness(t)
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "dry.ebb")

	code, stdout, stderr := h.run("export", "--json", "--dry-run", string(snap.ID), "--output", out)
	if code != ExitOK {
		t.Fatalf("dry-run code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || !mustCondition(env, "dry-run") {
		t.Errorf("dry-run outcome/conditions = %v / %v", env["outcome"], env["conditions"])
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("dry-run created the capsule")
	}
	if _, err := os.Stat(out + ".partial"); err == nil {
		t.Error("dry-run created a partial")
	}
	des, _ := os.ReadDir(h.outDir)
	if len(des) != 0 {
		t.Errorf("dry-run left artifacts: %v", des)
	}
	cat := h.cat()
	if eops := exportOpsOf(t, cat, snap.WorkspaceID); len(eops) != 0 {
		t.Errorf("dry-run journaled an export operation: %+v", eops)
	}
	// The plain-text mode explains the size honestly.
	code, _, stderr = h.run("export", "--dry-run", string(snap.ID), "--output", out)
	if code != ExitOK || !strings.Contains(stderr, "unknown before the copy") {
		t.Errorf("human dry-run: code=%d stderr=%s", code, stderr)
	}
}

func TestExportRefusals(t *testing.T) {
	h := newHHarness(t)

	t.Run("trim kind", func(t *testing.T) {
		// Manufacture a sealed trim-kind row directly.
		cat := h.cat()
		ws := h.captureSnapshot(t)
		trimID, err := cat.RecordSnapshot(catalog.Snapshot{
			ID: domain.SnapshotID(domain.NewID()), WorkspaceID: ws.WorkspaceID,
			PayloadBackendID: "p", SealBackendID: "s", Kind: catalog.SnapshotKindTrim,
		})
		if err != nil {
			t.Fatal(err)
		}
		code, stdout, _ := h.run("export", "--json", string(trimID), "--output", filepath.Join(h.outDir, "t.ebb"))
		if code != ExitBlocked {
			t.Fatalf("code = %d, want 3", code)
		}
		if !strings.Contains(jsonOf(t, envelopeOf(t, stdout)), CodeExportNotExportable) {
			t.Errorf("error lacks %s", CodeExportNotExportable)
		}
	})
	t.Run("unknown id", func(t *testing.T) {
		code, _, stderr := h.run("export", string(domain.NewID()), "--output", filepath.Join(h.outDir, "u.ebb"))
		if code != ExitUsage {
			t.Fatalf("code = %d (%s), want 2", code, stderr)
		}
	})
	t.Run("missing output flag", func(t *testing.T) {
		snap := h.captureSnapshot(t)
		code, _, _ := h.run("export", string(snap.ID))
		if code != ExitUsage {
			t.Fatalf("code = %d, want 2", code)
		}
	})
	t.Run("occupied output", func(t *testing.T) {
		snap := h.captureSnapshot(t)
		out := filepath.Join(h.outDir, "occupied.ebb")
		os.WriteFile(out, []byte("precious"), 0o600)
		code, stdout, _ := h.run("export", "--json", string(snap.ID), "--output", out)
		if code != ExitBlocked {
			t.Fatalf("code = %d, want 3", code)
		}
		if !strings.Contains(jsonOf(t, envelopeOf(t, stdout)), CodeExportOutputOccupied) {
			t.Errorf("error lacks %s", CodeExportOutputOccupied)
		}
		if b, _ := os.ReadFile(out); string(b) != "precious" {
			t.Error("occupied file was modified")
		}
	})
	t.Run("stale partial", func(t *testing.T) {
		snap := h.captureSnapshot(t)
		out := filepath.Join(h.outDir, "stale.ebb")
		// A recognizable partial: a capsule-shaped zip with the
		// identification document (crash-leftover shape).
		if code, _, stderr := h.run("export", string(snap.ID), "--output", out+".tmp"); code != ExitOK {
			t.Fatalf("seed export: %s", stderr)
		}
		b, _ := os.ReadFile(out + ".tmp")
		os.WriteFile(out+".partial", b, 0o600)
		os.Remove(out + ".tmp")
		code, stdout, _ := h.run("export", "--json", string(snap.ID), "--output", out)
		if code != ExitBlocked {
			t.Fatalf("code = %d, want 3", code)
		}
		if !strings.Contains(jsonOf(t, envelopeOf(t, stdout)), CodeExportPartialStale) {
			t.Errorf("error lacks %s", CodeExportPartialStale)
		}
	})
}

func jsonOf(t *testing.T, env map[string]any) string {
	t.Helper()
	b, err := json.Marshal(env["errors"])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExportCopyFailurePreservesSource(t *testing.T) {
	h := newHHarness(t)
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "failed.ebb")

	h.store.onCopy = func(src, dst string, ids []string) error {
		return fmt.Errorf("simulated backend copy failure")
	}
	code, stdout, _ := h.run("export", "--json", string(snap.ID), "--output", out)
	if code != ExitCaptureVerify {
		t.Fatalf("code = %d, want 4 (capture/integrity class for a failed copy)", code)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "verification-failed" {
		t.Errorf("outcome = %v", env["outcome"])
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("capsule published from a failed export")
	}
	des, _ := os.ReadDir(h.outDir)
	if len(des) != 0 {
		t.Errorf("failure left artifacts: %v", des)
	}
	// Source intact: still pinned, op closed CANCELED.
	cat := h.cat()
	fresh, err := cat.GetSnapshot(snap.ID)
	if err != nil || !fresh.Pinned {
		t.Fatalf("source pin lost: %+v (%v)", fresh, err)
	}
	if eops := exportOpsOf(t, cat, fresh.WorkspaceID); len(eops) != 1 || eops[0].Phase != catalog.PhaseCanceled {
		t.Errorf("export ops = %+v, want one CANCELED", eops)
	}
}

func TestExportTamperedCopyCaughtByVerification(t *testing.T) {
	h := newHHarness(t)
	snap := h.captureSnapshot(t)
	out := filepath.Join(h.outDir, "tampered.ebb")

	// Tamper "mid-export": the copy-done hook flips one byte of one
	// payload blob in the destination repo — same length, different
	// digest — the readback gate must fail the named check and publish
	// nothing.
	h.store.onCopyDone = func(dst string) {
		filepath.WalkDir(filepath.Join(dst, "snaps"), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, "b000001") {
				return nil
			}
			b, _ := os.ReadFile(p)
			if len(b) > 0 {
				b[0] ^= 0x20
				_ = os.WriteFile(p, b, 0o600)
			}
			return nil
		})
	}

	code, stdout, _ := h.run("export", "--json", string(snap.ID), "--output", out)
	if code != ExitCaptureVerify {
		t.Fatalf("code = %d, want 4", code)
	}
	if !strings.Contains(stdout, "destination-readback") && !strings.Contains(stdout, "destination-coverage") {
		t.Errorf("tamper not caught by a named destination check:\n%s", stdout)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("capsule published despite tampering")
	}
	des, _ := os.ReadDir(h.outDir)
	if len(des) != 0 {
		t.Errorf("failure left artifacts: %v", des)
	}
}
