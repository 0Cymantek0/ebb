package lifecycle

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
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

// verifyReadback deep-reads every listed file through the backend and
// compares to the independent digest (Foundation §11.4 "Readback").
//
// Transport selection: when the store implements domain.TreeTarDumper
// (the real restic backend), the whole snapshot tree is consumed as ONE
// streaming tar archive — §14.3 "avoid one subprocess per file"; park
// latency then scales with bytes, not file count. Otherwise (every fake)
// the original per-file DumpFile loop runs unchanged. The two transports
// verify the SAME readback set against the SAME digests, fail the same
// named check ("readback") on the same conditions (dump/transport
// failure, digest mismatch, expected file missing, truncated stream,
// non-zero producer exit, cancellation), and are held equivalent by
// TestE2EResticTarReadbackEquivalence (real backend).
func verifyReadback(ctx context.Context, store domain.SnapshotStore, repoDir, passfile, snapID string, files []readbackFile) error {
	if dumper, ok := store.(domain.TreeTarDumper); ok {
		return verifyReadbackTar(ctx, dumper, repoDir, passfile, snapID, files)
	}
	return verifyReadbackPerFile(ctx, store, repoDir, passfile, snapID, files)
}

// verifyReadbackPerFile is the original §11.4 readback loop: one
// DumpFile subprocess per expected file. The files map may be large;
// entries are processed one at a time, never buffered wholesale.
func verifyReadbackPerFile(ctx context.Context, store domain.SnapshotStore, repoDir, passfile, snapID string, files []readbackFile) error {
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

// maxTarTrailingZeros bounds the all-zero padding that may follow the tar
// end-of-archive marker: restic 0.19.1 writes exactly two zero blocks and
// a parser may stop one block early, so ≤1024 zero bytes are legal tail
// (lab/restic-probe/tar-dump). Anything longer or nonzero is malformed.
const maxTarTrailingZeros = 1024

// verifyReadbackTar is the streaming whole-tree §11.4 readback: ONE
// `dump --archive tar` subprocess for the entire snapshot (workspace
// prefix AND op-dir prefix), hashed member by member with bounded memory.
//
// Equivalence contract with verifyReadbackPerFile (this is a TRANSPORT
// change only — no gate may be weaker or stricter):
//
//   - only REGULAR members are content-hashed; dir and link members
//     (junctions/symlinks) are skipped — their fidelity is coverage's
//     check, unchanged (verifyCoverage runs first at every call site,
//     over the same immutable snapshot);
//   - each expected file must appear with the exact independent digest;
//     a missing expected file fails exactly as a failed per-file dump
//     does;
//   - regular members OUTSIDE the expected readback set are ignored: the
//     per-file transport cannot observe extras either, and extras are
//     coverage's gate (I04) — a stricter rule here would not be
//     equivalent. The one parser-hardening exception §11.4 explicitly
//     demands is DUPLICATE names: a duplicated expected member fails;
//   - truncation fails twice over, as §11.4 requires: the tar parser's
//     unexpected EOF at read time AND the producer-exit/complete-
//     consumption gates in the stream's Close (probe: a killed producer
//     leaves a clean EOF, exit 1, empty stderr — either gate alone is
//     blind to a case the other catches).
func verifyReadbackTar(ctx context.Context, dumper domain.TreeTarDumper, repoDir, passfile, snapID string, files []readbackFile) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(files) == 0 {
		// The per-file loop runs zero subprocesses for an empty set.
		return nil
	}
	expected := make(map[string]string, len(files)) // tree path -> digest
	for _, f := range files {
		expected[f.SnapPath] = f.Digest
	}
	seen := make(map[string]bool, len(files))

	stream, err := dumper.DumpTreeTar(ctx, repoDir, passfile, snapID, "/")
	if err != nil {
		// Same shape as a failing first DumpFile: a named-check failure,
		// not an infra error (the per-file loop turns dump errors into
		// readback details too).
		return &ErrVerification{Check: "readback", Details: []string{
			fmt.Sprintf("tar dump transport: %v", err)}}
	}
	var details []string

	tr := tar.NewReader(stream)
	for {
		if cerr := ctx.Err(); cerr != nil {
			_ = stream.Close()
			return cerr
		}
		hdr, nerr := tr.Next()
		if nerr == io.EOF {
			break // clean end of archive
		}
		if nerr != nil {
			details = append(details, fmt.Sprintf(
				"tar dump stream ended before the end-of-archive marker (truncated or malformed archive): %v", nerr))
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue // dirs/links/etc: content fidelity is coverage's job
		}
		// Probe-pinned member form: snapshot-rooted WITHOUT the leading
		// slash ("ws/f.txt", ".ebb-op-…/manifest.json"); directory
		// members carry a trailing slash ("ws/") — normalized away here
		// for robustness (restic never gives regular members one).
		path := "/" + strings.Trim(strings.TrimPrefix(hdr.Name, "/"), "/")
		want, ok := expected[path]
		if !ok {
			continue // extras are coverage's gate (I04), not readback's
		}
		if seen[path] {
			details = append(details, fmt.Sprintf(
				"%s: duplicate tar member (Foundation §11.4 rejects duplicate names)", path))
			continue
		}
		seen[path] = true
		h := sha256.New()
		if _, cerr := io.Copy(h, tr); cerr != nil {
			details = append(details, fmt.Sprintf(
				"%s: reading tar member content failed (truncated stream?): %v", path, cerr))
			continue
		}
		if hex := fmt.Sprintf("%x", h.Sum(nil)); hex != want {
			details = append(details, fmt.Sprintf("%s: readback digest %s, expected %s", path, hex, want))
		}
	}

	// Drain past the end-of-archive marker to the producer's EOF: only
	// zero padding may follow (≤ maxTarTrailingZeros). This is the
	// parser-completion half of §11.4's "fully consumed" requirement; the
	// producer-exit half is enforced by Close below.
	trailing, allZero := drainTarTail(stream)
	if !allZero || trailing > maxTarTrailingZeros {
		details = append(details, fmt.Sprintf(
			"tar dump stream carries %d bytes (all-zero: %v) after the end-of-archive marker; only zero padding up to %d bytes is legal",
			trailing, allZero, maxTarTrailingZeros))
	}
	for _, f := range files {
		if !seen[f.SnapPath] {
			details = append(details, fmt.Sprintf(
				"expected %s missing from the tar dump", f.SnapPath))
		}
	}
	if cerr := stream.Close(); cerr != nil {
		details = append(details, fmt.Sprintf("tar dump stream closed dirty: %v", cerr))
	}
	if len(details) > 0 {
		sort.Strings(details) // deterministic failure text
		return &ErrVerification{Check: "readback", Details: details}
	}
	return nil
}

// drainTarTail reads the stream through EOF and reports how many bytes
// followed and whether they were all zero. A read error before EOF is
// reported as a nonzero tail (the stream did not end cleanly).
func drainTarTail(stream io.Reader) (int64, bool) {
	var n int64
	allZero := true
	buf := make([]byte, 4096)
	for {
		m, err := stream.Read(buf)
		for i := 0; i < m; i++ {
			if buf[i] != 0 {
				allZero = false
			}
		}
		n += int64(m)
		if err == io.EOF {
			return n, allZero
		}
		if err != nil {
			return n, false
		}
	}
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

// VerifyCoverage is the exported §11.4 coverage gate behind
// `ebb verify` and the capsule exporter: the SAME exact-match comparison
// the capture itself ran (missing/unexpected/duplicate nodes, kind and
// size mismatches, prefix gating — I04). Sharing it is what keeps a
// re-verification from being stricter or laxer than the original gate.
// The returned error is nil or *ErrVerification{Check: "coverage"}.
func VerifyCoverage(ls []domain.TreeEntry, expected map[string]ExpectedNode, prefixes []string) error {
	want := make(map[string]expectedNode, len(expected))
	for p, n := range expected {
		want[p] = expectedNode{Kind: n.Kind, Size: n.Size}
	}
	return verifyCoverage(ls, want, prefixes)
}

// VerifyReadback is the exported §11.4 readback executor behind
// `ebb verify --content`: the SAME transport verifyPayload (capture) and
// reverifyPayload (crash recovery) run, over sets derived by the same
// pure functions. Crash-recovery re-verification and verify must derive
// identical evidence — sharing the executor is what keeps the transports
// and failure classes identical (Learnings, Wave D reimplementation-drift
// warning). The returned error is either a raw context error (cancelled)
// or *ErrVerification{Check: "readback"}; infra failures surface as
// readback details, exactly as the per-file loop always reported them.
func VerifyReadback(ctx context.Context, store domain.SnapshotStore, repoDir, passfile, snapID string, files []ReadbackFile) error {
	rb := make([]readbackFile, len(files))
	for i, f := range files {
		rb[i] = readbackFile{SnapPath: f.SnapPath, Digest: f.Digest}
	}
	return verifyReadback(ctx, store, repoDir, passfile, snapID, rb)
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
