// wave_e_test.go drives the Wave E command wiring end to end through the
// Deps seam: a temp state directory, the REAL catalog, the REAL platform
// probe (wrapped for fault injection), an in-memory filesystem-backed
// fake store, a registered vault unlocked via EBB_VAULT_PASSWORD, and
// controllable terminal/signal seams. Fixture SETUP writes plain files;
// the code under test never runs project code (Foundation §18.4).

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/platform"
	"ebb/internal/restore"
	"ebb/internal/vault"
)

// ---- eFakeStore: in-memory tree store over real fixture files ---------

type eFakeSnap struct {
	files map[string][]byte
	dirs  map[string]bool
	links map[string]string
}

type eFakeStore struct {
	mu         sync.Mutex
	next       int
	snaps      map[string]*eFakeSnap
	tags       map[string]map[string]string
	onSnapshot func(tags map[string]string) error
}

func newEFakeStore() *eFakeStore {
	return &eFakeStore{snaps: map[string]*eFakeSnap{}, tags: map[string]map[string]string{}}
}

func (s *eFakeStore) Init(ctx context.Context, dir, passfile string) error { return nil }

func (s *eFakeStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	return "ecli-fake-repo", nil
}

func (s *eFakeStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.onSnapshot != nil {
		if err := s.onSnapshot(tags); err != nil {
			return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrUnknown, Err: err}
		}
	}
	s.next++
	sum := sha256.Sum256(fmt.Appendf(nil, "ecli-snap-%d", s.next))
	id := hex.EncodeToString(sum[:])
	snap := &eFakeSnap{files: map[string][]byte{}, dirs: map[string]bool{}, links: map[string]string{}}
	for _, rel := range relPaths {
		if err := eWalkInto(snap, baseDir, filepath.ToSlash(rel)); err != nil {
			return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrSource, Err: err}
		}
	}
	s.snaps[id] = snap
	cp := map[string]string{}
	for k, v := range tags {
		cp[k] = v
	}
	s.tags[id] = cp
	return domain.SnapshotRef{BackendID: id, ShortID: id[:8], Time: "2026-09-18T00:00:00Z", Paths: relPaths, Tags: cp}, nil
}

// eWalkInto records one listed baseDir-relative path (and, for
// directories, its whole subtree) in tree-path form, materializing
// ancestor directories the way the real backend does.
func eWalkInto(snap *eFakeSnap, baseDir, rel string) error {
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
		eAddAncestors(snap, treePath)
		snap.files[treePath] = b
	case fi.IsDir():
		eAddAncestors(snap, treePath)
		snap.dirs[treePath] = true
		des, err := os.ReadDir(abs)
		if err != nil {
			return err
		}
		for _, de := range des {
			if err := eWalkInto(snap, baseDir, rel+"/"+de.Name()); err != nil {
				return err
			}
		}
	case fi.Mode()&os.ModeSymlink != 0, fi.Mode()&os.ModeIrregular != 0:
		t, err := os.Readlink(abs)
		if err != nil {
			return err
		}
		eAddAncestors(snap, treePath)
		snap.links[treePath] = t
	default:
		return fmt.Errorf("eFakeStore: unsupported object %s (%s)", abs, fi.Mode())
	}
	return nil
}

func eAddAncestors(snap *eFakeSnap, treePath string) {
	segs := strings.Split(strings.TrimPrefix(treePath, "/"), "/")
	for i := 1; i < len(segs); i++ {
		snap.dirs["/"+strings.Join(segs[:i], "/")] = true
	}
}

func (s *eFakeStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.snaps))
	for id := range s.snaps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]domain.SnapshotRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, domain.SnapshotRef{BackendID: id, ShortID: id[:8], Time: "2026-09-18T00:00:00Z", Tags: s.tags[id]})
	}
	return out, nil
}

func (s *eFakeStore) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.snaps[snapID]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("eFakeStore: no snapshot %s", snapID)}
	}
	var out []domain.TreeEntry
	for p := range snap.dirs {
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindDir})
	}
	for p, b := range snap.files {
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindFile, Size: int64(len(b))})
	}
	for p, t := range snap.links {
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindSymlink, LinkTarget: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s *eFakeStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.snaps[snapID]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("eFakeStore: no snapshot %s", snapID)}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	b, ok := snap.files[path]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("eFakeStore: %s not in snapshot %s", path, snapID)}
	}
	return append([]byte(nil), b...), nil
}

// Restore materializes the subtree under dest at its full tree path
// (restic --target semantics: subtree /cliws lands at dest/cliws).
func (s *eFakeStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	s.mu.Lock()
	snap, ok := s.snaps[snapID]
	s.mu.Unlock()
	if !ok {
		return &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("eFakeStore: no snapshot %s", snapID)}
	}
	sub := strings.TrimPrefix(subtree, "/")
	under := func(p string) bool {
		t := strings.TrimPrefix(p, "/")
		return sub == "" || t == sub || strings.HasPrefix(t, sub+"/")
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	var dirs, files, links []string
	for p := range snap.dirs {
		if under(p) {
			dirs = append(dirs, p)
		}
	}
	for p := range snap.files {
		if under(p) {
			files = append(files, p)
		}
	}
	for p := range snap.links {
		if under(p) {
			links = append(links, p)
		}
	}
	sort.Strings(dirs)
	sort.Strings(files)
	sort.Strings(links)
	for _, p := range dirs {
		if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(p)), 0o700); err != nil {
			return err
		}
	}
	for _, p := range files {
		abs := filepath.Join(dest, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(abs, snap.files[p], 0o600); err != nil {
			return err
		}
	}
	for _, p := range links {
		if err := os.Symlink(snap.links[p], filepath.Join(dest, filepath.FromSlash(p))); err != nil {
			if runtime.GOOS != "windows" {
				return &domain.StoreError{Class: domain.StoreErrSource, Err: err}
			}
			// Junction fallback (unprivileged on Windows).
			if out, cerr := runMklinkJ(filepath.Join(dest, filepath.FromSlash(p)), snap.links[p]); cerr != nil {
				return &domain.StoreError{Class: domain.StoreErrSource,
					Err: fmt.Errorf("mklink /J %s: %v (%s)", p, cerr, out)}
			}
		}
	}
	return nil
}

func (s *eFakeStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range snapIDs {
		delete(s.snaps, id)
		delete(s.tags, id)
	}
	return nil
}

// ---- probe wrapper (fault injection around the REAL probe) -----------

type eProbe struct {
	inner       domain.PlatformProbe
	onProbeFile func(path string)
}

func (p *eProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	return p.inner.RootIdentity(path)
}
func (p *eProbe) VolumeUsage(path string) (domain.VolumeUsage, error) {
	return p.inner.VolumeUsage(path)
}
func (p *eProbe) ProbeFile(path string) (domain.FileFacts, error) {
	if p.onProbeFile != nil {
		p.onProbeFile(path)
	}
	return p.inner.ProbeFile(path)
}

// OpenDirVerified forwards to the native verified-descent seam when the
// inner probe provides it (the production probe does).
func (p *eProbe) OpenDirVerified(path, expectedIdentity string) (domain.IdentifiedDir, error) {
	vp, ok := p.inner.(domain.VerifiedDirProbe)
	if !ok {
		return nil, fmt.Errorf("eProbe: inner probe lacks verified dir descent")
	}
	return vp.OpenDirVerified(path, expectedIdentity)
}

// ---- harness -----------------------------------------------------------

type eHarness struct {
	t        *testing.T
	stateDir string
	wsRoot   string
	store    *eFakeStore
	probe    *eProbe
	deps     Deps

	// signal context control
	ctx       context.Context
	cancelSig context.CancelFunc

	// terminal control
	tty   bool
	lines []string
}

// runMklinkJ creates a junction via the unprivileged Windows mklink
// (test-fixture privilege; the code under test never does this).
func runMklinkJ(link, target string) (string, error) {
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// newEHarness builds a disposable world: state dir, fixture workspace
// (Ebbfile declaring the deps group), registered vault, env password.
func newEHarness(t *testing.T) *eHarness {
	t.Helper()
	base := t.TempDir()
	h := &eHarness{
		t:        t,
		stateDir: filepath.Join(base, "state"),
		wsRoot:   filepath.Join(base, "cliws"),
		store:    newEFakeStore(),
	}
	h.probe = &eProbe{inner: platform.New()}
	h.ctx, h.cancelSig = context.WithCancel(context.Background())

	if err := os.MkdirAll(h.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.writeFixture()

	// Register the default vault; the password comes from the env source
	// (CI/tests never touch a real credential store).
	t.Setenv(vault.EnvPassword, "ecli-test-secret")
	repoDir := filepath.Join(base, "vault")
	if _, err := vault.New(filepath.Join(h.stateDir, vault.RegistryFile)).Register("main", repoDir, "ecli-fake-repo"); err != nil {
		t.Fatal(err)
	}

	deps := RealDeps()
	deps.StateDir = func() (string, error) { return h.stateDir, nil }
	deps.OpenCatalog = catalog.Open
	deps.NewStore = func() (domain.SnapshotStore, func(), error) { return h.store, func() {}, nil }
	deps.NewLifecycle = lifecycle.New
	deps.NewRestoreOp = restore.New
	deps.NewProbe = func() domain.PlatformProbe { return h.probe }
	deps.StdinIsTerminal = func() bool { return h.tty }
	deps.ReadLine = func() (string, error) {
		if len(h.lines) == 0 {
			return "", fmt.Errorf("no queued line")
		}
		line := h.lines[0]
		h.lines = h.lines[1:]
		return line, nil
	}
	// The returned stop mirrors signal.NotifyContext semantics: it
	// RELEASES the handler without canceling; the test cancels
	// explicitly via cancelSig (a stop that canceled would poison
	// later runs in the same harness).
	deps.NewSignalContext = func() (context.Context, func()) { return h.ctx, func() {} }
	h.deps = deps
	return h
}

// resetSignalContext mints a fresh signal context (a real process gets a
// fresh one per invocation; a canceled harness context must not poison
// the next run).
func (h *eHarness) resetSignalContext() {
	h.ctx, h.cancelSig = context.WithCancel(context.Background())
}

// writeFixture writes the canonical workspace: preserved material plus a
// regenerable node_modules declared by the Ebbfile.
func (h *eHarness) writeFixture() {
	h.t.Helper()
	files := map[string]string{
		"Ebbfile.toml": `version = 1

[workspace]
name = "cliws"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "deps"
adapter = "pnpm"
root = "."
outputs = ["node_modules"]
inputs = ["package.json", "pnpm-lock.yaml"]
network = "allowed"
`,
		"package.json":                       `{"name":"cliws","version":"1.0.0","private":true}` + "\n",
		"pnpm-lock.yaml":                     "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad: 1.3.0\n",
		"notes.md":                           "private notes that must survive everything\n",
		".env":                               "SECRET_TOKEN=ecli-do-not-print\n",
		"src/main.go":                        "package main\n\nfunc main() { println(\"cliws\") }\n",
		"node_modules/.package-lock.json":    `{"lockfileVersion":3}`,
		"node_modules/left-pad/package.json": "{\n  \"name\": \"left-pad\",\n  \"version\": \"1.3.0\"\n}\n",
		"node_modules/left-pad/index.js":     "module.exports = () => 1;\n",
	}
	for rel, content := range files {
		p := filepath.Join(h.wsRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
}

// run executes one CLI invocation against the harness world.
func (h *eHarness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var out, errb strings.Builder
	code := Main(args, Streams{Out: &out, Err: &errb}, h.deps)
	return code, out.String(), errb.String()
}

// cat opens the harness catalog directly (test observation only).
func (h *eHarness) cat() *catalog.Catalog {
	h.t.Helper()
	c, err := catalog.Open(filepath.Join(h.stateDir, vault.CatalogFile))
	if err != nil {
		h.t.Fatalf("open catalog: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

// envelope decodes the JSON envelope from a --json run.
func envelopeOf(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout)
	}
	return env
}

func envString(t *testing.T, env map[string]any, key string) string {
	t.Helper()
	v, ok := env[key].(string)
	if !ok {
		t.Fatalf("envelope field %q missing or not a string: %v", key, env[key])
	}
	return v
}

func mustCondition(env map[string]any, substr string) bool {
	list, _ := env["conditions"].([]any)
	for _, c := range list {
		if s, ok := c.(string); ok && strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
