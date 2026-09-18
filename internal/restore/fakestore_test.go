package restore

// fakeStore is an in-memory/tree SnapshotStore backed by real temp-dir
// fixtures (Foundation §16.7: "native adapters can be replaced in tests
// with deterministic fault-injection implementations"). Snapshot READS a
// real directory tree into memory (exactly what the capture side fed
// the backend); DumpFile/Restore serve those bytes back. The tree-path
// shapes mirror the D003 layout: "/<wsprefix>/..." and "/.ebb-op-
// <opID>/..." nodes with forward slashes.
//
// Fault knobs (all optional):
//
//   - dumpTamper:  rewrite bytes served for one tree path
//   - restoreDrop: silently skip one tree path during Restore (the E10
//     dropped-file fault)
//   - restoreCorrupt: write different content for one tree path
//   - lsHide:      hide one node from Ls
//   - restoreErr:  fail Restore after creating dest + one file
//     ("fails mid-way")
//   - restoreHook: arbitrary callback at the top of Restore and
//     RestoreExcluding (used to create a racing destination occupant
//     between preflight and publish — F35)
//   - RestoreExcluding (Wave F): the exclusion-based staging path; it
//     records the excludes it received and never creates excluded
//     link nodes (the restore layer recreates those natively).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"ebb/internal/domain"
)

type fakeLink struct {
	target   string // recreation form: what os.Symlink / mklink /J receive
	junction bool   // recreate via junction (unprivileged Windows)
}

type fakeSnap struct {
	id    string
	files map[string][]byte
	dirs  map[string]bool
	links map[string]fakeLink
}

type fakeStore struct {
	mu    sync.Mutex
	next  int
	snaps map[string]*fakeSnap

	dumpTamper     map[string]func([]byte) []byte
	restoreDrop    map[string]bool
	restoreCorrupt map[string]string
	lsHide         map[string]bool
	restoreErr     error
	restoreHook    func() error

	// excludeCalls records every excludes list passed to
	// RestoreExcluding (the restore layer's exclusion contract).
	excludeCalls [][]string
	// linksMaterialized records link paths the STORE created itself
	// (RestoreExcluding must never see link paths — they are excluded;
	// this records the negative evidence).
	linksMaterialized []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		snaps:          map[string]*fakeSnap{},
		dumpTamper:     map[string]func([]byte) []byte{},
		restoreDrop:    map[string]bool{},
		restoreCorrupt: map[string]string{},
		lsHide:         map[string]bool{},
	}
}

func (s *fakeStore) newID() string {
	s.next++
	sum := sha256.Sum256(fmt.Appendf(nil, "fake-snap-%d", s.next))
	return hex.EncodeToString(sum[:])
}

func (s *fakeStore) Init(ctx context.Context, dir, passfile string) error { return nil }

func (s *fakeStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	return "fake-repo-id", nil
}

// Snapshot reads the listed relative paths under baseDir into a new
// in-memory snapshot, mirroring the cwd-relative D003 capture layout.
func (s *fakeStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := &fakeSnap{
		id:    s.newID(),
		files: map[string][]byte{},
		dirs:  map[string]bool{},
		links: map[string]fakeLink{},
	}
	for _, rel := range relPaths {
		if err := s.walkInto(snap, baseDir, filepath.ToSlash(rel)); err != nil {
			return domain.SnapshotRef{}, err
		}
	}
	s.snaps[snap.id] = snap
	return domain.SnapshotRef{BackendID: snap.id, ShortID: snap.id[:8], Time: "2026-09-18T00:00:00Z", Paths: relPaths, Tags: tags}, nil
}

func (s *fakeStore) walkInto(snap *fakeSnap, baseDir, rel string) error {
	abs := filepath.Join(baseDir, filepath.FromSlash(rel))
	fi, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	switch {
	case fi.Mode().IsRegular():
		b, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		snap.files["/"+rel] = b
	case fi.IsDir():
		snap.dirs["/"+rel] = true
		des, err := os.ReadDir(abs)
		if err != nil {
			return err
		}
		for _, de := range des {
			if err := s.walkInto(snap, baseDir, rel+"/"+de.Name()); err != nil {
				return err
			}
		}
	case fi.Mode()&os.ModeSymlink != 0:
		t, err := os.Readlink(abs)
		if err != nil {
			return err
		}
		snap.links["/"+rel] = fakeLink{target: t}
	case fi.Mode()&os.ModeIrregular != 0:
		// Junction / reparse directory (Windows): record the link text,
		// never descend.
		t, err := os.Readlink(abs)
		if err != nil {
			return err
		}
		snap.links["/"+rel] = fakeLink{target: t, junction: true}
	default:
		return fmt.Errorf("fakeStore: unsupported object %s (%s)", abs, fi.Mode())
	}
	return nil
}

func (s *fakeStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var refs []domain.SnapshotRef
	for _, id := range s.sortedIDs() {
		refs = append(refs, domain.SnapshotRef{BackendID: id, ShortID: id[:8], Time: "2026-09-18T00:00:00Z"})
	}
	return refs, nil
}

func (s *fakeStore) sortedIDs() []string {
	ids := make([]string, 0, len(s.snaps))
	for id := range s.snaps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Ls lists one snapshot's tree nodes. All link flavors surface as
// KindSymlink, mirroring the backend's tree typing (lifecycle's
// treeKindOf).
func (s *fakeStore) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.snaps[snapID]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("fakeStore: snapshot %q not found", snapID)}
	}
	var out []domain.TreeEntry
	for p := range snap.dirs {
		if s.lsHide[p] {
			continue
		}
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindDir})
	}
	for p, b := range snap.files {
		if s.lsHide[p] {
			continue
		}
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindFile, Size: int64(len(b))})
	}
	for p, l := range snap.links {
		if s.lsHide[p] {
			continue
		}
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindSymlink, LinkTarget: l.target})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s *fakeStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap, ok := s.snaps[snapID]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("fakeStore: snapshot %q not found", snapID)}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	b, ok := snap.files[path]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("fakeStore: %q not found in snapshot %s", path, snapID)}
	}
	if f := s.dumpTamper[path]; f != nil {
		b = f(b)
	}
	return append([]byte(nil), b...), nil
}

// Restore materializes the snapshot subtree under dest, recreating the
// tree structure below the included prefix (restic --target/--include
// semantics: the workspace tree lands at dest/<prefix>).
func (s *fakeStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	s.mu.Lock()
	snap, ok := s.snaps[snapID]
	s.mu.Unlock()
	if !ok {
		return &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("fakeStore: snapshot %q not found", snapID)}
	}
	if s.restoreHook != nil {
		if err := s.restoreHook(); err != nil {
			return err
		}
	}
	sub := strings.TrimPrefix(subtree, "/")
	under := func(p string) bool {
		trimmed := strings.TrimPrefix(p, "/")
		if sub == "" {
			return true
		}
		return trimmed == sub || strings.HasPrefix(trimmed, sub+"/")
	}

	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	if s.restoreErr != nil {
		// "Fails mid-way": dest exists, one file landed, then failure.
		var first string
		for _, p := range s.sortedFileKeys(snap) {
			if under(p) {
				first = p
				break
			}
		}
		if first != "" {
			_ = os.MkdirAll(filepath.Join(dest, filepath.FromSlash(filepath.Dir(first))), 0o700)
			_ = os.WriteFile(filepath.Join(dest, filepath.FromSlash(first)), snap.files[first], 0o600)
		}
		return s.restoreErr
	}

	for p := range snap.dirs {
		if !under(p) {
			continue
		}
		if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(p)), 0o700); err != nil {
			return err
		}
	}
	for _, p := range s.sortedFileKeys(snap) {
		if !under(p) {
			continue
		}
		if s.restoreDrop[p] {
			continue // the silent E10 drop
		}
		content := snap.files[p]
		if repl, ok := s.restoreCorrupt[p]; ok {
			content = []byte(repl)
		}
		abs := filepath.Join(dest, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(abs, content, 0o600); err != nil {
			return err
		}
	}
	for _, p := range s.sortedLinkKeys(snap) {
		if !under(p) {
			continue
		}
		if s.restoreDrop[p] {
			continue
		}
		if err := createLink(filepath.Join(dest, filepath.FromSlash(p)), snap.links[p]); err != nil {
			return err
		}
	}
	return nil
}

// RestoreExcluding models the restic exclusion contract (Wave F):
// materialize the FULL snapshot tree into dest, skipping exactly the
// listed snapshot-relative paths (leading-slash-free) AND their
// subtrees (restic prunes descent of an excluded directory). Link
// nodes that were NOT excluded are created by the store itself —
// mirroring real restic, which attempts (and, unprivileged, fails on)
// every link node it is not told to skip. The exclusion calls are
// recorded so tests can assert exactly what the restore layer asked
// the backend to skip.
func (s *fakeStore) RestoreExcluding(ctx context.Context, repoDir, passfile, snapID, dest string, excludes []string) error {
	s.mu.Lock()
	snap, ok := s.snaps[snapID]
	s.excludeCalls = append(s.excludeCalls, append([]string(nil), excludes...))
	s.mu.Unlock()
	if !ok {
		return &domain.StoreError{Class: domain.StoreErrUsage, Err: fmt.Errorf("fakeStore: snapshot %q not found", snapID)}
	}
	if s.restoreHook != nil {
		if err := s.restoreHook(); err != nil {
			return err
		}
	}
	excluded := map[string]bool{}
	for _, ex := range excludes {
		excluded["/"+ex] = true
	}
	pruned := func(p string) bool { // p is a "/a/b" tree path
		for cur := p; ; {
			if excluded[cur] {
				return true
			}
			cur = path.Dir(cur)
			if cur == "/" || cur == "." {
				return false
			}
		}
	}

	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	if s.restoreErr != nil {
		var first string
		for _, p := range s.sortedFileKeys(snap) {
			if !pruned(p) {
				first = p
				break
			}
		}
		if first != "" {
			_ = os.MkdirAll(filepath.Join(dest, filepath.FromSlash(filepath.Dir(first))), 0o700)
			_ = os.WriteFile(filepath.Join(dest, filepath.FromSlash(first)), snap.files[first], 0o600)
		}
		return s.restoreErr
	}

	for p := range snap.dirs {
		if pruned(p) {
			continue
		}
		if err := os.MkdirAll(filepath.Join(dest, filepath.FromSlash(p)), 0o700); err != nil {
			return err
		}
	}
	for _, p := range s.sortedFileKeys(snap) {
		if pruned(p) {
			continue
		}
		if s.restoreDrop[p] {
			continue // the silent E10 drop
		}
		content := snap.files[p]
		if repl, ok := s.restoreCorrupt[p]; ok {
			content = []byte(repl)
		}
		abs := filepath.Join(dest, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(abs, content, 0o600); err != nil {
			return err
		}
	}
	for _, p := range s.sortedLinkKeys(snap) {
		if pruned(p) {
			continue
		}
		s.mu.Lock()
		s.linksMaterialized = append(s.linksMaterialized, p)
		s.mu.Unlock()
		if err := createLink(filepath.Join(dest, filepath.FromSlash(p)), snap.links[p]); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeStore) sortedFileKeys(snap *fakeSnap) []string {
	keys := make([]string, 0, len(snap.files))
	for p := range snap.files {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	return keys
}

func (s *fakeStore) sortedLinkKeys(snap *fakeSnap) []string {
	keys := make([]string, 0, len(snap.links))
	for p := range snap.links {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	return keys
}

func (s *fakeStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, id := range snapIDs {
		delete(s.snaps, id)
	}
	return nil
}

// createLink recreates one link fixture: a real symlink where the
// platform allows it, otherwise a junction via the unprivileged
// `cmd /c mklink /J` (Windows). A backend that cannot recreate the link
// reports a content failure, mirroring restic's classification.
func createLink(linkPath string, l fakeLink) error {
	if !l.junction {
		if err := os.Symlink(l.target, linkPath); err == nil {
			return nil
		} else if runtime.GOOS != "windows" {
			return &domain.StoreError{Class: domain.StoreErrSource, Err: err}
		}
	}
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", linkPath, l.target).CombinedOutput(); err == nil {
			return nil
		} else {
			return &domain.StoreError{Class: domain.StoreErrSource,
				Err: fmt.Errorf("mklink /J %s %s: %v (%s)", linkPath, l.target, err, strings.TrimSpace(string(out)))}
		}
	}
	return &domain.StoreError{Class: domain.StoreErrSource,
		Err: fmt.Errorf("cannot recreate link %s on %s", linkPath, runtime.GOOS)}
}
