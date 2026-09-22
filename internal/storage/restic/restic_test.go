package resticstore

// Conformance tests against the real restic binary (0.19.1 pinned in
// the environment). Every test skips with a clear message when restic
// is not on PATH. Fixtures are built under t.TempDir() and cleaned by
// the testing framework; the store's private restic cache dir is
// removed via t.Cleanup(Close).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// ---- helpers -------------------------------------------------------

func newStore(t *testing.T) *Store {
	t.Helper()
	path, err := exec.LookPath("restic")
	if err != nil {
		t.Skipf("restic binary not on PATH: %v", err)
	}
	s := New(path)
	t.Cleanup(s.Close)
	return s
}

func newRepo(t *testing.T, s *Store) (repoDir, passfile string) {
	t.Helper()
	return newRepoWithPassword(t, s, "ebb-test-password-7f3a")
}

func newRepoWithPassword(t *testing.T, s *Store, password string) (repoDir, passfile string) {
	t.Helper()
	base := t.TempDir()
	repoDir = filepath.Join(base, "repo")
	passfile = filepath.Join(base, "pw")
	if err := os.WriteFile(passfile, []byte(password), 0o600); err != nil {
		t.Fatalf("passfile: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.Init(ctx, repoDir, passfile); err != nil {
		t.Fatalf("init: %v", err)
	}
	return repoDir, passfile
}

func errClass(t *testing.T, err error) domain.StoreErrorClass {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var se *domain.StoreError
	if !errors.As(err, &se) {
		t.Fatalf("error does not wrap *domain.StoreError: %v", err)
	}
	return se.Class
}

func sha256Bytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// nodeSpec is one oracle entry, derived from the fixture by the test
// itself (independent of all restic output).
type nodeSpec struct {
	kind domain.EntryKind
	size int64
}

// fixture is the D003 capture layout: parent/ { ws/ workspace, opd/
// metadata dir } plus a junction pointing OUTSIDE the fixture (into a
// separate temp root).
type fixture struct {
	parent      string
	ws, opd     string
	outside     string
	hasJunction bool
	oracle      map[string]nodeSpec // "ws/..." | "opd/..." -> spec
	digests     map[string]string   // files only
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		parent:  t.TempDir(),
		outside: t.TempDir(), // deliberately a different temp root
		oracle:  map[string]nodeSpec{},
		digests: map[string]string{},
	}
	f.ws = filepath.Join(f.parent, "ws")
	f.opd = filepath.Join(f.parent, "opd")
	for _, d := range []string{filepath.Join(f.ws, "sub"), filepath.Join(f.ws, "emptydir"), f.opd} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	write := func(rel string, content []byte) {
		t.Helper()
		abs := filepath.Join(f.parent, filepath.FromSlash(rel))
		if err := os.WriteFile(abs, content, 0o644); err != nil {
			t.Fatalf("write %s: %v", abs, err)
		}
	}

	write("ws/regular.txt", []byte("hello ebb\n"))
	// >1KiB deterministic content, not trivially compressible.
	big := make([]byte, 8192)
	next := uint32(0x9E3779B9)
	for i := range big {
		next = next*1664525 + 1013904223
		big[i] = byte(next >> 23)
	}
	write("ws/big.bin", big)
	write("ws/notes spaces ünïcode ☃.txt", []byte("unicode round trip ✓\n"))
	write("ws/empty.txt", nil)
	write("ws/unselected.txt", []byte("must NOT appear in exact selection\n"))
	write("ws/sub/inner.txt", []byte("nested\n"))
	write("opd/manifest.json", []byte(`{"schema":1,"op":"fixture"}`))

	// Hardlink pair: two names, one file object.
	hardA := filepath.Join(f.ws, "hard_a.txt")
	if err := os.WriteFile(hardA, []byte("hardlinked payload\n"), 0o644); err != nil {
		t.Fatalf("hard_a: %v", err)
	}
	if err := os.Link(hardA, filepath.Join(f.ws, "hard_b.txt")); err != nil {
		t.Fatalf("hardlink pair: %v", err)
	}

	// A file inside the junction target proves restic does not follow
	// the junction.
	if err := os.WriteFile(filepath.Join(f.outside, "outsider.txt"), []byte("outside content\n"), 0o644); err != nil {
		t.Fatalf("outsider: %v", err)
	}
	// Junction via mklink /J (no privilege needed; probe fixture_cmd).
	link := filepath.Join(f.ws, "junction-out")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, f.outside).CombinedOutput()
	if err != nil {
		t.Logf("mklink /J failed (%v: %s); junction assertions will be skipped", err, out)
	} else if fi, lerr := os.Lstat(link); lerr != nil || fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) == 0 {
		t.Logf("junction %s did not materialize as a reparse point; junction assertions will be skipped", link)
	} else {
		f.hasJunction = true
	}

	// Build the oracle and digest set independently of restic.
	for _, root := range []string{"ws", "opd"} {
		base := filepath.Join(f.parent, root)
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(f.parent, p)
			rel = filepath.ToSlash(rel)
			info, serr := os.Lstat(p)
			if serr != nil {
				return serr
			}
			switch {
			case info.Mode().IsRegular():
				f.oracle[rel] = nodeSpec{kind: domain.KindFile, size: info.Size()}
				content, rerr := os.ReadFile(p)
				if rerr != nil {
					return rerr
				}
				f.digests[rel] = sha256Bytes(content)
			case info.IsDir():
				f.oracle[rel] = nodeSpec{kind: domain.KindDir}
			case info.Mode()&fs.ModeSymlink != 0:
				f.oracle[rel] = nodeSpec{kind: domain.KindSymlink}
			case info.Mode()&fs.ModeIrregular != 0: // junction on Go/Windows
				f.oracle[rel] = nodeSpec{kind: domain.KindSymlink} // restic types junctions as symlink
			default:
				t.Fatalf("oracle: unmodeled fixture object %s (%s)", rel, info.Mode())
			}
			return nil
		})
		if err != nil {
			t.Fatalf("oracle walk %s: %v", base, err)
		}
	}
	return f
}

// selected returns the exact-file selection (Foundation §11.2 forbids
// dir shorthand for selected files; emptydir is listed precisely
// because it is genuinely empty).
func (f *fixture) selected(withJunction bool) []string {
	rel := []string{
		"ws/regular.txt", "ws/big.bin", "ws/notes spaces ünïcode ☃.txt",
		"ws/empty.txt", "ws/sub/inner.txt", "ws/emptydir",
		"ws/hard_a.txt", "ws/hard_b.txt",
		"opd/manifest.json",
	}
	if withJunction && f.hasJunction {
		rel = append(rel, "ws/junction-out")
	}
	return rel
}

// expectedTree computes the exact snapshot-tree set for a selection:
// every selected entry plus its ancestor directories, in restic tree
// path form (/ws/...).
func expectedTree(rel []string, oracle map[string]nodeSpec) map[string]nodeSpec {
	out := map[string]nodeSpec{}
	for _, r := range rel {
		spec, ok := oracle[r]
		if !ok {
			continue // junction when junction creation was unavailable
		}
		segs := strings.Split(r, "/")
		for i := 1; i < len(segs); i++ {
			out["/"+strings.Join(segs[:i], "/")] = nodeSpec{kind: domain.KindDir}
		}
		out["/"+r] = spec
	}
	return out
}

func entriesByPath(entries []domain.TreeEntry) map[string]domain.TreeEntry {
	m := make(map[string]domain.TreeEntry, len(entries))
	for _, e := range entries {
		m[e.Path] = e
	}
	return m
}

func diffSets(t *testing.T, got map[string]domain.TreeEntry, want map[string]nodeSpec) {
	t.Helper()
	var missing, extra []string
	for p, spec := range want {
		e, ok := got[p]
		if !ok {
			missing = append(missing, p)
			continue
		}
		if e.Kind != spec.kind {
			t.Errorf("%s: kind %q want %q", p, e.Kind, spec.kind)
		}
		if spec.kind == domain.KindFile && e.Size != spec.size {
			t.Errorf("%s: size %d want %d", p, e.Size, spec.size)
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			extra = append(extra, p)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("missing from snapshot tree: %v", missing)
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		t.Errorf("unexpected entries in snapshot tree: %v", extra)
	}
}

// snap is the canonical Snapshot call for a fixture.
func snap(t *testing.T, s *Store, f *fixture, repoDir, passfile string, rel []string, tag string) domain.SnapshotRef {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ref, err := s.Snapshot(ctx, repoDir, f.parent, rel, passfile, map[string]string{"op": tag})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	return ref
}

func lsOK(t *testing.T, s *Store, repoDir, passfile, id string) []domain.TreeEntry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	entries, err := s.Ls(ctx, repoDir, passfile, id)
	if err != nil {
		t.Fatalf("Ls(%s): %v", id, err)
	}
	return entries
}

// ---- tests ---------------------------------------------------------

func TestInitAndRepoID(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, err := s.RepoID(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("RepoID: %v", err)
	}
	if !isHexID(id, 64) {
		t.Fatalf("RepoID = %q, want 64 hex chars", id)
	}
	again, err := s.RepoID(ctx, repoDir, passfile)
	if err != nil || again != id {
		t.Fatalf("RepoID not stable: %q vs %q (%v)", id, again, err)
	}

	// Pinned live: re-init fails with "config file already exists"
	// (exit 1) and is reported as a repo-class error.
	if err := s.Init(ctx, repoDir, passfile); err == nil {
		t.Fatal("re-init of an existing repository must fail")
	} else if c := errClass(t, err); c != domain.StoreErrRepo {
		t.Fatalf("re-init class = %q want repo (%v)", c, err)
	}

	// Wrong password: exit 12 → auth.
	badPW := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(badPW, []byte("definitely-wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RepoID(ctx, repoDir, badPW); err == nil {
		t.Fatal("wrong password must fail")
	} else if c := errClass(t, err); c != domain.StoreErrAuth {
		t.Fatalf("wrong password class = %q want auth (%v)", c, err)
	}

	// Missing repository: exit 10 → repo.
	if _, err := s.RepoID(ctx, filepath.Join(t.TempDir(), "nope"), passfile); err == nil {
		t.Fatal("missing repo must fail")
	} else if c := errClass(t, err); c != domain.StoreErrRepo {
		t.Fatalf("missing repo class = %q want repo (%v)", c, err)
	}
}

func TestListEmptyRepo(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	refs, err := s.List(ctx, repoDir, passfile)
	// Pinned live: `snapshots --json` on an empty repo prints `[]` and
	// exits 0 — an empty list is not an error.
	if err != nil {
		t.Fatalf("List on empty repo: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("empty repo listed %d snapshots", len(refs))
	}
}

func TestSnapshotFullTreeCapture(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)

	ref := snap(t, s, f, repoDir, passfile, []string{"ws", "opd"}, "full-tree")
	if !isHexID(ref.BackendID, 64) || len(ref.ShortID) != 8 {
		t.Fatalf("ref = %+v", ref)
	}
	entries := entriesByPath(lsOK(t, s, repoDir, passfile, ref.BackendID))

	// D003 pin: tree prefixes are exactly /ws and /opd — no synthetic
	// /C/... ancestor chain (which would drag ACLs back on restore).
	for p := range entries {
		if !strings.HasPrefix(p, "/ws") && !strings.HasPrefix(p, "/opd") {
			t.Errorf("tree path %s outside the manifest bijection prefixes", p)
		}
	}
	// Full oracle coverage: every fixture node (incl. recursion through
	// the listed nonempty dirs, which IS the intent in this mode), keyed
	// in tree-path form.
	want := make(map[string]nodeSpec, len(f.oracle))
	for rel, spec := range f.oracle {
		want["/"+rel] = spec
	}
	diffSets(t, entries, want)

	// Junction pin: stored as a symlink node, NOT followed.
	if f.hasJunction {
		e, ok := entries["/ws/junction-out"]
		if !ok {
			t.Fatal("junction missing from snapshot tree")
		}
		if e.Kind != domain.KindSymlink {
			t.Errorf("junction kind = %q want symlink", e.Kind)
		}
		for p := range entries {
			if strings.HasPrefix(p, "/ws/junction-out/") {
				t.Errorf("restic followed the junction: %s in tree", p)
			}
		}
	}
	// Empty dir pin.
	if e := entries["/ws/emptydir"]; e.Kind != domain.KindDir {
		t.Errorf("empty dir kind = %q want dir", e.Kind)
	}
	// Hardlink pin: both names present as independent file nodes of
	// identical size (restic does not group hardlinks).
	a, b := entries["/ws/hard_a.txt"], entries["/ws/hard_b.txt"]
	if a.Kind != domain.KindFile || b.Kind != domain.KindFile || a.Size != b.Size || a.Size == 0 {
		t.Errorf("hardlink pair nodes = %+v / %+v", a, b)
	}
}

func TestSnapshotExactSelection(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)

	sel := f.selected(true)
	ref := snap(t, s, f, repoDir, passfile, sel, "exact")
	if ref.BackendID == "" {
		t.Fatal("no snapshot id")
	}
	entries := entriesByPath(lsOK(t, s, repoDir, passfile, ref.BackendID))

	// EXACT coverage: selected entries + ancestor dirs, nothing else —
	// in particular the unselected neighbor is absent (Foundation
	// §11.2: listing a nonempty dir would recurse into it; the adapter
	// lists files individually instead).
	diffSets(t, entries, expectedTree(sel, f.oracle))
	if _, ok := entries["/ws/unselected.txt"]; ok {
		t.Error("unselected neighbor leaked into exact-selection snapshot")
	}

	// DumpFile readback: digests equal the independent fixture oracle.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, rel := range []string{"ws/big.bin", "ws/notes spaces ünïcode ☃.txt", "ws/regular.txt", "ws/empty.txt", "ws/hard_a.txt"} {
		got, err := s.DumpFile(ctx, repoDir, passfile, ref.BackendID, "/"+rel)
		if err != nil {
			t.Fatalf("DumpFile(%s): %v", rel, err)
		}
		if d := sha256Bytes(got); d != f.digests[rel] {
			t.Errorf("DumpFile(%s) digest %s want %s", rel, d, f.digests[rel])
		}
	}
	// Pin: an empty stored file dumps zero bytes with exit 0.
	if got, _ := s.DumpFile(ctx, repoDir, passfile, ref.BackendID, "/ws/empty.txt"); len(got) != 0 {
		t.Errorf("empty file dump = %d bytes", len(got))
	}
	// Pin (probe Q6): dumping a reparse-point node is refused by restic
	// and surfaces as a usage error.
	if f.hasJunction {
		if _, err := s.DumpFile(ctx, repoDir, passfile, ref.BackendID, "/ws/junction-out"); err == nil {
			t.Error("dumping a junction node must fail")
		} else if c := errClass(t, err); c != domain.StoreErrUsage {
			t.Errorf("junction dump class = %q want usage (%v)", c, err)
		}
	}
	// A path absent from the snapshot is a usage error, not silent data.
	if _, err := s.DumpFile(ctx, repoDir, passfile, ref.BackendID, "/ws/unselected.txt"); err == nil {
		t.Error("dumping an unselected path must fail")
	}

	// List: tags round-trip; the paths field is the native absolute
	// form restic records (cwd-resolved) — truthful, distinct from the
	// tree bijection.
	refs, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var listed *domain.SnapshotRef
	for i := range refs {
		if refs[i].BackendID == ref.BackendID {
			listed = &refs[i]
		}
	}
	if listed == nil {
		t.Fatal("snapshot missing from List")
	}
	if listed.Tags["op"] != "exact" || listed.Tags["ebb"] != "v1" {
		t.Errorf("tags = %v", listed.Tags)
	}
	for _, p := range listed.Paths {
		if !filepath.IsAbs(p) {
			t.Errorf("snapshots --json paths field lost native absolute form: %q", p)
		}
	}
}

// TestSnapshotUnreadableSource pins the most dangerous restic behavior
// (probe Q4a): with a denied source file the backup still CREATES a
// snapshot (exit 3, stderr error records, no marker anywhere). The
// adapter must return StoreErrSource, and the orphaned snapshot must
// be visible via List — callers must never use it as a capture.
func TestSnapshotUnreadableSource(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)

	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	denied := filepath.Join(f.ws, "regular.txt")
	if out, err := exec.Command("icacls", denied, "/deny", user+":R").CombinedOutput(); err != nil {
		t.Skipf("cannot apply icacls deny on this machine (%v: %s); unreadable-source pin skipped", err, out)
	}
	// Undo the deny BEFORE t.TempDir cleanup runs (LIFO order).
	t.Cleanup(func() {
		out, err := exec.Command("icacls", denied, "/remove:d", user).CombinedOutput()
		if err != nil {
			t.Logf("icacls /remove:d failed (%v: %s); trying /reset", err, out)
			_ = exec.Command("icacls", denied, "/reset").Run()
		}
	})

	sel := f.selected(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := s.Snapshot(ctx, repoDir, f.parent, sel, passfile, map[string]string{"op": "deny"})
	if err == nil {
		t.Fatal("snapshot with an unreadable source file must fail")
	}
	if c := errClass(t, err); c != domain.StoreErrSource {
		t.Fatalf("unreadable source class = %q want source (%v)", c, err)
	}
	if !strings.Contains(err.Error(), "INCOMPLETE snapshot") {
		t.Errorf("error must name the orphaned incomplete snapshot id: %v", err)
	}

	// The incomplete snapshot exists in the repository, unmarked.
	refs, lerr := s.List(ctx, repoDir, passfile)
	if lerr != nil {
		t.Fatalf("List: %v", lerr)
	}
	found := 0
	for _, r := range refs {
		if r.Tags["op"] == "deny" {
			found++
			entries := entriesByPath(lsOK(t, s, repoDir, passfile, r.BackendID))
			if _, ok := entries["/ws/regular.txt"]; ok {
				t.Error("denied file unexpectedly present in incomplete snapshot")
			}
			if _, ok := entries["/ws/empty.txt"]; !ok {
				t.Error("readable sibling missing from incomplete snapshot")
			}
		}
	}
	if found == 0 {
		t.Fatal("incomplete snapshot not visible via List (behavior regressed: restic no longer stores it)")
	}
}

func TestSnapshotRepoAndAuthErrors(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)

	// Missing repository: exit 10 → repo. Note the passfile itself is
	// valid; only the repo dir is absent.
	pw := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pw, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := s.Snapshot(ctx, filepath.Join(t.TempDir(), "no-repo"), f.parent, []string{"ws"}, pw, nil)
	if c := errClass(t, err); c != domain.StoreErrRepo {
		t.Fatalf("missing repo class = %q want repo (%v)", c, err)
	}

	// Wrong password: exit 12 → auth.
	repoDir, _ := newRepo(t, s)
	badPW := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(badPW, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Snapshot(ctx, repoDir, f.parent, []string{"ws"}, badPW, nil); err == nil {
		t.Fatal("wrong password must fail")
	} else if c := errClass(t, err); c != domain.StoreErrAuth {
		t.Fatalf("wrong password class = %q want auth (%v)", c, err)
	}
}

// TestMixedAbsRelRejectedClientSide proves rejection happens before
// any restic subprocess: the repo directory does not exist, so a
// StoreErrRepo answer would mean restic actually ran.
func TestMixedAbsRelRejectedClientSide(t *testing.T) {
	s := newStore(t)
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	missingRepo := filepath.Join(t.TempDir(), "no-repo")
	cases := [][]string{
		{"ws/ok.txt", `C:\elsewhere\x.txt`},
		{"ws/ok.txt", "C:/elsewhere/x.txt"},
		{`ws\backslash.txt`},
		{"/ws/leading-slash.txt"},
		nil,
	}
	for _, rel := range cases {
		_, err := s.Snapshot(ctx, missingRepo, f.parent, rel, "unused", nil)
		if err == nil {
			t.Fatalf("rel %q must be rejected", rel)
		}
		if c := errClass(t, err); c != domain.StoreErrUsage {
			t.Fatalf("rel %q class = %q want usage (client-side rejection before restic runs): %v", rel, c, err)
		}
	}
}

func TestForgetRemovesExactlyOne(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)

	refA := snap(t, s, f, repoDir, passfile, []string{"ws/regular.txt"}, "forget-a")
	refB := snap(t, s, f, repoDir, passfile, []string{"ws/big.bin"}, "forget-b")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.Forget(ctx, repoDir, passfile, []string{refA.BackendID}); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	refs, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, r := range refs {
		if r.BackendID == refA.BackendID {
			t.Error("forgotten snapshot still listed")
		}
	}
	if len(refs) != 1 || refs[0].BackendID != refB.BackendID {
		t.Fatalf("exactly refB must remain: %+v", refs)
	}
	if _, err := s.Ls(ctx, repoDir, passfile, refA.BackendID); err == nil {
		t.Error("ls of a forgotten snapshot must fail")
	}

	// Pinned live: restic's own forget of a nonexistent id exits 0 as a
	// silent no-op; the adapter must refuse it.
	err = s.Forget(ctx, repoDir, passfile, []string{refA.BackendID})
	if err == nil {
		t.Fatal("forget of a nonexistent id must be refused, not silently accepted")
	}
	if c := errClass(t, err); c != domain.StoreErrUsage {
		t.Fatalf("nonexistent forget id class = %q want usage (%v)", c, err)
	}
}

func TestRestoreRoundTrip(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)

	// Selection WITHOUT the junction: a clean restore must exit 0
	// (pinned live); the junction case has its own classification test.
	sel := f.selected(false)
	ref := snap(t, s, f, repoDir, passfile, sel, "restore")
	dest := filepath.Join(t.TempDir(), "out")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.Restore(ctx, repoDir, passfile, ref.BackendID, "", dest); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Byte-identical round trip for every regular file in the
	// selection, judged by the independent fixture digests.
	restored := 0
	err := filepath.WalkDir(dest, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		rel, _ := filepath.Rel(dest, p)
		rel = filepath.ToSlash(rel) // dest/ws/x.txt → ws/x.txt
		want, ok := f.digests[rel]
		if !ok {
			return fmt.Errorf("restored file %s is not part of the selection", rel)
		}
		content, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if sha256Bytes(content) != want {
			t.Errorf("restored %s digest mismatch", rel)
		}
		restored++
		return nil
	})
	if err != nil {
		t.Fatalf("restored tree walk: %v", err)
	}
	files := 0
	for _, rel := range sel {
		if f.oracle[rel].kind == domain.KindFile {
			files++
		}
	}
	if restored != files {
		t.Fatalf("restored %d regular files want %d", restored, files)
	}
	// Empty dir restored as a dir.
	if fi, err := os.Stat(filepath.Join(dest, "ws", "emptydir")); err != nil || !fi.IsDir() {
		t.Errorf("empty dir not restored: %v", err)
	}
}

func TestRestoreNonZeroClassification(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)
	if !f.hasJunction {
		t.Skip("junction fixture unavailable on this machine")
	}

	ref := snap(t, s, f, repoDir, passfile, f.selected(true), "restore-junction")
	dest := filepath.Join(t.TempDir(), "out")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err := s.Restore(ctx, repoDir, passfile, ref.BackendID, "", dest)
	if err == nil {
		// Environment can create symlinks (admin/Developer Mode); the
		// probe machine cannot — both outcomes are acceptable, only
		// silent partial failure is not.
		t.Skip("junction restore succeeded on this privileged environment")
	}
	// Pin (probe Q7): restic exits 1 because junction materialization
	// needs SeCreateSymbolicLinkPrivilege; the adapter classifies the
	// missing entry as a content failure (StoreErrSource) instead of
	// silently accepting a partial restore.
	if c := errClass(t, err); c != domain.StoreErrSource {
		t.Fatalf("junction restore class = %q want source (%v)", c, err)
	}
	if !strings.Contains(err.Error(), "materialize") {
		t.Errorf("error should report the missing entry: %v", err)
	}
	if _, serr := os.Lstat(filepath.Join(dest, "ws", "junction-out")); serr == nil {
		t.Log("junction unexpectedly materialized; restic error came from another cause")
	}
}

func TestDumpFileContextCancellation(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)
	ref := snap(t, s, f, repoDir, passfile, []string{"ws/regular.txt"}, "cancel")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.DumpFile(ctx, repoDir, passfile, ref.BackendID, "/ws/regular.txt")
	if err == nil {
		t.Fatal("canceled context must abort the dump")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("error should carry context cancellation: %v", err)
	}
}

// compile-time interface check.
var _ domain.SnapshotStore = (*Store)(nil)
var _ domain.TreeTarDumper = (*Store)(nil) // streaming whole-tree readback seam (D007 shape)
