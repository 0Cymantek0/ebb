package lifecycle

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ebb/internal/domain"
)

// Verification (Foundation §11.4). Two independent checks gate every
// seal: COVERAGE (the snapshot tree contains exactly the expected
// entries — names, kinds, root mapping, sizes; nothing extra under the
// declared prefixes, I04) and READBACK (every authoritative preserved
// byte is decrypted/decompressed through the backend and compared to the
// independent inventory digest — never to a backend chunk id, I12).
//
// The manifest prefix bijection (§11.2/D003): a root listed as the
// relative entry "<ws>/f1" from cwd = parent appears at tree path
// "/<ws>/f1". The bijection is confirmed against the actual listing,
// never derived by stripping drive letters or matching basenames.

// expectedNode is one expected snapshot-tree node, in tree-normalized
// form (junctions/mount points appear as symlink nodes in the backend
// tree — restic types all reparse links as "symlink").
type expectedNode struct {
	Kind domain.EntryKind // KindSymlink for every link flavor
	Size int64
}

// treeKindOf normalizes an inventory kind to the backend-tree kind.
func treeKindOf(k domain.EntryKind) domain.EntryKind {
	switch k {
	case domain.KindJunction, domain.KindMountPoint:
		return domain.KindSymlink
	default:
		return k
	}
}

// addExpectedPath adds path ("/<prefix>/[...]") and all its ancestor
// directories (below the prefix root) to the expected tree.
func addExpectedPath(m map[string]expectedNode, path string, node expectedNode) {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := 1; i < len(segs); i++ {
		m["/"+strings.Join(segs[:i], "/")] = expectedNode{Kind: domain.KindDir}
	}
	m[path] = node
}

// verifyCoverage compares the snapshot listing against the expected tree
// exactly (Foundation §11.4 "Coverage"). Failures: missing expected
// entries, unexpected entries (including anything outside the two
// declared prefixes — I04), kind mismatches, file size mismatches.
func verifyCoverage(ls []domain.TreeEntry, expected map[string]expectedNode, prefixes []string) error {
	prefixSet := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		prefixSet["/"+p] = true
	}
	var details []string
	seen := make(map[string]bool, len(ls))
	for _, e := range ls {
		if !underAnyPrefix(e.Path, prefixSet) {
			details = append(details, fmt.Sprintf("unexpected tree entry %q (outside declared prefixes %v; I04)", e.Path, prefixes))
			continue
		}
		if seen[e.Path] {
			details = append(details, fmt.Sprintf("duplicate tree entry %q", e.Path))
			continue
		}
		seen[e.Path] = true
		want, ok := expected[e.Path]
		if !ok {
			details = append(details, fmt.Sprintf("unexpected tree entry %q not in the capture selection (I04)", e.Path))
			continue
		}
		if e.Kind != want.Kind {
			details = append(details, fmt.Sprintf("%s: tree kind %q, expected %q", e.Path, e.Kind, want.Kind))
			continue
		}
		if want.Kind == domain.KindFile && e.Size != want.Size {
			details = append(details, fmt.Sprintf("%s: tree size %d, expected %d", e.Path, e.Size, want.Size))
		}
	}
	for path, want := range expected {
		if !seen[path] {
			details = append(details, fmt.Sprintf("expected %s (%s) missing from snapshot tree", path, want.Kind))
		}
	}
	if len(details) > 0 {
		sort.Strings(details)
		return &ErrVerification{Check: "coverage", Details: details}
	}
	return nil
}

func underAnyPrefix(path string, prefixes map[string]bool) bool {
	// path is "/<first-seg>/..." or "/<first-seg>"; the bijection is by
	// complete first segment.
	trimmed := strings.TrimPrefix(path, "/")
	first := trimmed
	if i := strings.IndexByte(trimmed, '/'); i >= 0 {
		first = trimmed[:i]
	}
	return prefixes["/"+first]
}

// readbackFile is one file to deep-read through the backend.
type readbackFile struct {
	// SnapPath is the tree path ("/<prefix>/..."); Digest is the
	// independent inventory digest to compare against.
	SnapPath string
	Digest   string
}

// verifyReadback dumps every listed file through the backend, hashes the
// returned bytes and compares to the independent digest (Foundation
// §11.4 "Readback"). A truncated or missing dump fails (the store
// already checks producer exit status; I12). The files map may be large;
// entries are processed one at a time, never buffered wholesale.
func verifyReadback(ctx context.Context, store domain.SnapshotStore, repoDir, passfile, snapID string, files []readbackFile) error {
	var details []string
	for _, f := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		got, err := store.DumpFile(ctx, repoDir, passfile, snapID, f.SnapPath)
		if err != nil {
			details = append(details, fmt.Sprintf("dump %s: %v", f.SnapPath, err))
			continue
		}
		h := sha256.Sum256(got)
		if hex := fmt.Sprintf("%x", h); hex != f.Digest {
			details = append(details, fmt.Sprintf("%s: readback digest %s, expected %s", f.SnapPath, hex, f.Digest))
		}
	}
	if len(details) > 0 {
		sort.Strings(details) // deterministic failure text
		return &ErrVerification{Check: "readback", Details: details}
	}
	return nil
}

// expectedTreeAndReadback derives the §11.4 coverage expectation and
// readback set for the entries that actually end up in a capture under one
// backend prefix. It mirrors buildSelection's listing rules exactly:
//
//   - a preserved file with a digest is always captured (listed itself or
//     inside a shorthand-listed ancestor directory);
//   - every preserved link is listed individually;
//   - a preserved directory is in the tree when it is empty (listed as a
//     genuine empty dir) or has any in-tree descendant (restic
//     materializes ancestor nodes of listed children); a directory whose
//     only descendants are omitted or unhashed entries is NOT in the tree;
//   - omitted entries and blocking kinds are never in the tree.
//
// Recover reuses this to rebuild the evidence for re-verifying P from P's
// own retained inventory — the same rules must reconstruct the same tree
// expectation or a re-verification would be vacuous.
func expectedTreeAndReadback(entries []domain.Entry, prefix string) (map[string]expectedNode, []readbackFile) {
	expected := make(map[string]expectedNode, len(entries))
	var readback []readbackFile

	hasChild := make(map[string]bool, len(entries))
	for _, e := range entries {
		if p := parentSlash(e.Path); p != "" {
			hasChild[p] = true
		}
	}
	// Canonical order sorts every descendant after its ancestors, so a
	// reverse scan has seen each entry's whole subtree before the entry;
	// in-tree-ness propagates to the immediate parent as it is decided.
	childInTree := make(map[string]bool, len(entries))
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Route != domain.RoutePreserve {
			continue
		}
		inTree := false
		switch e.Kind {
		case domain.KindFile:
			inTree = e.Digest != ""
		case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
			inTree = true
		case domain.KindDir:
			inTree = !hasChild[e.Path] || childInTree[e.Path]
		}
		if !inTree {
			continue
		}
		if p := parentSlash(e.Path); p != "" {
			childInTree[p] = true
		}
		treePath := "/" + prefix + "/" + e.Path
		addExpectedPath(expected, treePath, expectedNode{Kind: treeKindOf(e.Kind), Size: e.LogicalSize})
		if e.Kind == domain.KindFile {
			readback = append(readback, readbackFile{SnapPath: treePath, Digest: e.Digest})
		}
	}
	return expected, readback
}

// parentSlash returns the parent of a root-relative slash path, "" for a
// top-level path (its parent is the root itself, which is not an entry).
func parentSlash(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

// ---- exported expected-tree derivation (§11.4) -------------------------
//
// ExpectedTreeFor is the thin exported window onto expectedTreeAndReadback
// for callers outside this package that re-derive capture evidence from a
// retained inventory (`ebb verify`): sharing the exact rules is the point
// — a re-verification that disagreed with the capture's own derivation
// would be vacuous (Learnings, Wave D).

// ExpectedNode is one expected snapshot-tree node in tree-normalized form
// (junctions/mount points appear as symlink nodes in the backend tree).
type ExpectedNode struct {
	Kind domain.EntryKind
	Size int64
}

// ReadbackFile is one file whose authoritative preserved bytes must be
// deep-read through the backend and compared to the independent digest.
type ReadbackFile struct {
	// SnapPath is the tree path ("/<prefix>/..."); Digest is the
	// independent inventory digest to compare against.
	SnapPath string
	Digest   string
}

// ExpectedTreeFor derives the §11.4 coverage expectation and readback set
// for the entries a capture under prefix placed in the snapshot tree. It
// is pure: no I/O, no clocks; the same entries and prefix always yield
// the same expectation.
func ExpectedTreeFor(entries []domain.Entry, prefix string) (map[string]ExpectedNode, []ReadbackFile) {
	expected, readback := expectedTreeAndReadback(entries, prefix)
	out := make(map[string]ExpectedNode, len(expected))
	for p, n := range expected {
		out[p] = ExpectedNode{Kind: n.Kind, Size: n.Size}
	}
	files := make([]ReadbackFile, len(readback))
	for i, f := range readback {
		files[i] = ReadbackFile{SnapPath: f.SnapPath, Digest: f.Digest}
	}
	return out, files
}

// walkLocalTree returns every file (path relative to root, forward
// slashes, plus size and digest) under dir. Used to (a) enumerate the op
// dir's expected tree for coverage, and (b) build readback sets for
// trim's recipe-input copies.
func walkLocalTree(dir string) (map[string]fileFact, error) {
	out := map[string]fileFact{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		info, serr := d.Info()
		if serr != nil {
			return serr
		}
		switch {
		case info.Mode().IsRegular():
			dig, derr := digestFile(p)
			if derr != nil {
				return derr
			}
			out[rel] = fileFact{Kind: domain.KindFile, Size: info.Size(), Digest: dig}
		case info.IsDir():
			out[rel] = fileFact{Kind: domain.KindDir}
		default:
			// The op dir is Ebb-authored and never contains links; an
			// unexpected object here is a bug, not a survivable case.
			return fmt.Errorf("unexpected non-regular object in op dir: %s (%s)", p, info.Mode())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type fileFact struct {
	Kind   domain.EntryKind
	Size   int64
	Digest string
}

// digestFile streams one local file through SHA-256 (bounded memory).
func digestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
