package lifecycle

// Test harness (Foundation §16.7: "native adapters can be replaced in
// tests with deterministic fault-injection implementations").
//
//   - fakeStore: a filesystem-backed content-tree store. Snapshot copies
//     the listed baseDir-relative paths into <repo>/snap/<id>/ and hands
//     out opaque hex ids; Ls walks the copy (dirs included, like restic
//     ls --json); DumpFile returns copied bytes. Fault knobs: fail the
//     Nth Snapshot, hide a tree path from Ls, corrupt a DumpFile, and an
//     OnSnapshot hook (fired with the capture tags — tests arm source
//     mutations "after seal" from it).
//   - wrapProbe: fault injection around the REAL platform probe (truth
//     matters for identity/volume). Hooks: override/observe RootIdentity,
//     observe ProbeFile (fired per entry during scans and the removal
//     walk — tests cancel contexts or open handles at exact sequence
//     points from it).
//
// The harness builds: temp base dir with vault repo + passfile + catalog
// (real modernc SQLite, DSN pragmas per Learnings), and a Coordinator
// factory that opens a FRESH catalog handle per call — the new-process
// simulation Recover must survive.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/platform"
	"ebb/internal/policy"
)

// ---- fakeStore ---------------------------------------------------------

type fakeStore struct {
	// failNthSnapshot (1-based) makes that Snapshot call fail with a
	// source-class error (an unmarked incomplete snapshot, Learnings
	// restic Q4a shape).
	failNthSnapshot int
	// onSnapshot is fired at the top of every Snapshot call with its
	// tags; a non-nil error aborts the capture before anything is
	// stored.
	onSnapshot func(tags map[string]string) error
	// hideInLs marks tree paths Ls pretends not to contain.
	hideInLs map[string]bool
	// corruptDump marks tree paths whose DumpFile bytes are altered.
	corruptDump map[string]bool

	mu      sync.Mutex
	calls   int
	failSet bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{hideInLs: map[string]bool{}, corruptDump: map[string]bool{}}
}

func (f *fakeStore) Init(ctx context.Context, dir, passfile string) error {
	if _, err := os.Lstat(dir); err == nil {
		return &domain.StoreError{Class: domain.StoreErrRepo, Err: errors.New("repo already initialized")}
	}
	return os.MkdirAll(dir, 0o700)
}

func (f *fakeStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	return "fakerepo-" + digestBytes([]byte("repo:" + filepath.Clean(mustAbs(repoDir))))[:16], nil
}

func (f *fakeStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	f.mu.Lock()
	f.calls++
	nth := f.calls
	f.mu.Unlock()
	if f.onSnapshot != nil {
		if err := f.onSnapshot(tags); err != nil {
			return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrUnknown, Err: err}
		}
	}
	if f.failNthSnapshot != 0 && f.failNthSnapshot == nth {
		return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrSource,
			Err: errors.New("fake store: source read error (incomplete snapshot left behind)")}
	}
	id := fmt.Sprintf("%064x", nth)
	dir := filepath.Join(repoDir, "snap", id)
	for _, rel := range relPaths {
		src := filepath.Join(baseDir, filepath.FromSlash(rel))
		if err := copyIntoTree(src, filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			return domain.SnapshotRef{}, &domain.StoreError{Class: domain.StoreErrSource, Err: err}
		}
	}
	// Tags live outside the snapshot tree so they never pollute Ls.
	tagDir := filepath.Join(repoDir, "tags")
	if err := os.MkdirAll(tagDir, 0o700); err != nil {
		return domain.SnapshotRef{}, err
	}
	tb, _ := json.Marshal(tags)
	if err := os.WriteFile(filepath.Join(tagDir, id+".json"), tb, 0o600); err != nil {
		return domain.SnapshotRef{}, err
	}
	cp := map[string]string{}
	for k, v := range tags {
		cp[k] = v
	}
	return domain.SnapshotRef{BackendID: id, ShortID: id[:8], Time: "2026-01-01T00:00:00Z", Paths: append([]string(nil), relPaths...), Tags: cp}, nil
}

func (f *fakeStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	entries, err := os.ReadDir(filepath.Join(repoDir, "snap"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []domain.SnapshotRef
	for _, e := range entries {
		tb, err := os.ReadFile(filepath.Join(repoDir, "tags", e.Name()+".json"))
		if err != nil {
			return nil, err
		}
		var tags map[string]string
		if err := json.Unmarshal(tb, &tags); err != nil {
			return nil, err
		}
		out = append(out, domain.SnapshotRef{BackendID: e.Name(), ShortID: e.Name()[:8], Tags: tags})
	}
	return out, nil
}

func (f *fakeStore) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	root := filepath.Join(repoDir, "snap", snapID)
	if _, err := os.Lstat(root); err != nil {
		return nil, &domain.StoreError{Class: domain.StoreErrRepo, Err: fmt.Errorf("fake store: no snapshot %s", snapID)}
	}
	var out []domain.TreeEntry
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		treePath := "/" + filepath.ToSlash(rel)
		if f.hideInLs[treePath] {
			// Hidden node: its descendants remain (the knob simulates a
			// store that lost one record, not a subtree).
			return nil
		}
		kind := domain.KindFile
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if info.IsDir() {
			kind = domain.KindDir
		}
		out = append(out, domain.TreeEntry{Path: treePath, Kind: kind, Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (f *fakeStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	rel := strings.TrimPrefix(filepath.FromSlash(path), string(filepath.Separator))
	b, err := os.ReadFile(filepath.Join(repoDir, "snap", snapID, rel))
	if err != nil {
		return nil, &domain.StoreError{Class: domain.StoreErrRepo, Err: err}
	}
	if f.corruptDump[path] {
		b = append(b, []byte("corrupted-by-fault-injection")...)
	}
	return b, nil
}

func (f *fakeStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	return errors.New("fake store: restore not supported in lifecycle tests")
}

func (f *fakeStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	for _, id := range snapIDs {
		if err := os.RemoveAll(filepath.Join(repoDir, "snap", id)); err != nil {
			return err
		}
	}
	return nil
}

// copyIntoTree copies a file or a whole directory tree (byte-exact).
func copyIntoTree(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		b, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	}
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

// ---- wrapProbe ---------------------------------------------------------

// wrapProbe wraps the real native probe with observation/override hooks.
// The real probe stays the truth source; the wrapper only injects faults
// at exact sequence points.
type wrapProbe struct {
	// Embedding the INTERFACE (not a concrete probe) keeps optional
	// capabilities like VerifiedDirProbe promoted through the wrapper —
	// a concrete-method wrapper silently drops them and falls the
	// scanner back to path-based descent (Wave E e2e finding).
	domain.PlatformProbe
	// onRootIdentity may answer (handled=true) or just observe.
	onRootIdentity func(path string) (domain.RootIdentity, error, bool)
	// onProbeFile observes every ProbeFile call.
	onProbeFile func(path string)
}

func (w *wrapProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	if w.onRootIdentity != nil {
		if id, err, handled := w.onRootIdentity(path); handled {
			return id, err
		}
	}
	return w.PlatformProbe.RootIdentity(path)
}

func (w *wrapProbe) ProbeFile(path string) (domain.FileFacts, error) {
	if w.onProbeFile != nil {
		w.onProbeFile(path)
	}
	return w.PlatformProbe.ProbeFile(path)
}

// ---- harness -----------------------------------------------------------

type harness struct {
	t       *testing.T
	base    string
	vault   VaultRef
	store   *fakeStore
	probe   *wrapProbe
	catPath string

	opened []*catalog.Catalog
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	base := t.TempDir()
	h := &harness{
		t:       t,
		base:    base,
		store:   newFakeStore(),
		probe:   &wrapProbe{PlatformProbe: platform.New()},
		catPath: filepath.Join(base, "catalog.db"),
	}
	h.vault = VaultRef{
		RepoDir:  filepath.Join(base, "vault"),
		Passfile: filepath.Join(base, "vault.pass"),
	}
	if err := os.MkdirAll(h.vault.RepoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.vault.Passfile, []byte("harness-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// t.TempDir cleanup on Windows cannot delete the catalog while a
	// pooled connection holds it; close every handle the harness opened.
	t.Cleanup(func() {
		for _, cat := range h.opened {
			_ = cat.Close()
		}
	})
	return h
}

// coord builds a Coordinator over a FRESH catalog handle (new-process
// simulation: no in-memory carryover is possible).
func (h *harness) coord() *Coordinator {
	h.t.Helper()
	cat, err := catalog.Open(h.catPath)
	if err != nil {
		h.t.Fatalf("open catalog: %v", err)
	}
	h.opened = append(h.opened, cat)
	c, err := New(Dependencies{Store: h.store, Cat: cat, Probe: h.probe})
	if err != nil {
		h.t.Fatalf("new coordinator: %v", err)
	}
	return c
}

// workspace creates a fixture workspace root under the harness base.
func (h *harness) workspace(name string) string {
	root := filepath.Join(h.base, "work", name)
	writeStdFixture(h.t, root)
	return root
}

func newWSID() domain.WorkspaceID {
	return domain.WorkspaceID(domain.NewID())
}

func snapshotOpts(ws domain.WorkspaceID) CaptureOptions {
	return CaptureOptions{WorkspaceName: "fixture", WorkspaceID: ws, Policy: policy.Default("fixture")}
}

func parkOpts(ws domain.WorkspaceID) CaptureOptions {
	o := snapshotOpts(ws)
	o.Park = true
	o.WriterAssertion = "harness-assert-writers-stopped"
	return o
}

// stdFixture is the canonical test tree. node_modules (deep, plain) and
// vendor/dist exercise directory-shorthand capture; vendor retains a
// file outside the group output.
const (
	fixturePackageJSON = `{"name":"fixture","version":"1.0.0"}` + "\n"
	fixtureLock        = "lockfileVersion: 6.0\n\nimporters:\n  .:\n    dependencies:\n      x: 1.0.0\n"
	fixtureNotes       = "private notes that must never be removed\n"
	fixtureAjs         = "module a;\nexport const a = 1;\n"
	fixtureXjs         = "module x;\nexport const x = 1;\n"
	fixtureGen         = "// generated output\n"
	fixtureLicense     = "MIT-style license text\n"
)

func writeStdFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"package.json":                      fixturePackageJSON,
		"pnpm-lock.yaml":                    fixtureLock,
		"notes.md":                          fixtureNotes,
		"node_modules/a.js":                 fixtureAjs,
		"node_modules/.pnpm/x@1.0/index.js": fixtureXjs,
		"vendor/dist/gen.js":                fixtureGen,
		"vendor/LICENSE.txt":                fixtureLicense,
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// trimPolicyTOML declares one pnpm group over the standard fixture.
const trimPolicyTOML = `
version = 1

[workspace]
name = "fixture"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "deps"
adapter = "pnpm"
root = "."
outputs = ["node_modules", "vendor/dist"]
inputs = ["package.json", "pnpm-lock.yaml"]
network = "allowed"
`

func trimPolicy(t *testing.T) policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(trimPolicyTOML))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func trimOpts(t *testing.T, ws domain.WorkspaceID, groups ...string) CaptureOptions {
	t.Helper()
	o := snapshotOpts(ws)
	o.Policy = trimPolicy(t)
	o.DoTrim = groups
	return o
}

// ---- assertions -------------------------------------------------------

// digestTree is the TEST's own independent walk (never the scanner under
// test): every file's sha256 and dir markers, keyed by slash-relative
// path.
func digestTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			out[rel] = "<dir>"
			return nil
		}
		f, oerr := os.Open(p)
		if oerr != nil {
			return oerr
		}
		h := sha256.New()
		_, cerr := io.Copy(h, f)
		f.Close()
		if cerr != nil {
			return cerr
		}
		out[rel] = hex.EncodeToString(h.Sum(nil))
		return nil
	})
	if err != nil {
		t.Fatalf("digest walk %s: %v", root, err)
	}
	return out
}

func requireSameTree(t *testing.T, before, after map[string]string) {
	t.Helper()
	for path, want := range before {
		got, ok := after[path]
		if !ok {
			t.Errorf("source entry %s disappeared (source must be untouched)", path)
			continue
		}
		if got != want {
			t.Errorf("source entry %s changed", path)
		}
	}
	for path := range after {
		if _, ok := before[path]; !ok {
			t.Errorf("source entry %s appeared unexpectedly", path)
		}
	}
}

func mustLstatErrNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Errorf("expected %s to be gone, stat err = %v", path, err)
	}
}

func mustExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("expected %s to exist: %v", path, err)
	}
}

// opIDOf resolves the operation id of a workspace's most recent snapshot
// through the backend tags (the same discovery binding Recover relies
// on). Terminal operations are not returned by ActiveOperations.
func (h *harness) opIDOf(t *testing.T, ws domain.WorkspaceID) domain.OperationID {
	t.Helper()
	c := h.coord()
	snaps, err := c.cat.ListSnapshots(ws)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("no snapshots for %s (err %v)", ws, err)
	}
	payload := snaps[len(snaps)-1].PayloadBackendID
	refs, err := h.store.List(context.Background(), h.vault.RepoDir, h.vault.Passfile)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if r.BackendID == payload {
			if op := r.Tags["ebb-op"]; op != "" {
				return domain.OperationID(op)
			}
		}
	}
	t.Fatal("no ebb-op tag found on payload snapshot")
	return ""
}

// phaseOf reads an operation's current phase straight from the journal.
func (h *harness) phaseOf(t *testing.T, opID domain.OperationID) string {
	c := h.coord()
	op, err := c.cat.GetOperation(opID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	return op.Phase
}

func activeCount(t *testing.T, c *Coordinator, ws domain.WorkspaceID) int {
	t.Helper()
	ops, err := c.cat.ActiveOperations(ws)
	if err != nil {
		t.Fatal(err)
	}
	return len(ops)
}
