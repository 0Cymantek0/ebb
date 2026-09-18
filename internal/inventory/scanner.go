// Package inventory implements Ebb's discovery pass (Foundation §8): a
// metadata-first, no-follow walk over one capture root producing the
// canonical entry stream, hardlink grouping, issue observations and the
// complete-accounting summary.
//
// The scanner consumes domain.PlatformProbe only. Platform-specific facts
// (reparse classification, allocation, file identity, streams) arrive
// through that seam so tests can substitute deterministic fakes and
// inject faults (Foundation §16.7). The scanner never decides that
// content is disposable: every entry leaves with RoutePreserve, and
// omission is a policy/planner decision (Foundation §6.4 I02).
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"ebb/internal/domain"
)

// Default bounds (Foundation §8.3: exceeding a bound is a reported
// blocker, never silent truncation).
const (
	DefaultMaxEntries int64 = 2_000_000
	DefaultMaxDepth   int   = 128

	// hashBufSize is the reused I/O buffer for streaming digests; file
	// contents are never fully buffered (bounded memory).
	hashBufSize = 1 << 20 // 1 MiB

	// hardlinkPrefix namespaces scanner-assigned hardlink group ids.
	hardlinkPrefix = "hl:"

	// evidenceScan is the base classification evidence for scanner output.
	evidenceScan = "inventory.scan"
)

// Stable ScanIssue codes emitted by this package.
const (
	// IssueBoundaryLink marks junctions, mount points and other reparse
	// boundaries that were recorded but never descended into.
	IssueBoundaryLink = "EBB_SCAN_BOUNDARY_LINK"
	// IssueSpecialFile marks FIFOs, sockets, devices and unrecognized
	// kinds: ephemeral state that blocks destructive operations.
	IssueSpecialFile = "EBB_SCAN_SPECIAL_FILE"
	// IssueHardlinkOutside marks files whose link count exceeds the
	// in-root references seen: aliases outside the root keep the bytes
	// alive, so they are not exclusively reclaimable.
	IssueHardlinkOutside = "EBB_SCAN_HARDLINK_OUTSIDE"
	// IssueADSPresent marks files carrying named data streams. The v1
	// backend loses them, so destructive operations must block.
	IssueADSPresent = "EBB_SCAN_ADS_PRESENT"
	// IssuePlaceholderSuspect marks files that look like cloud
	// placeholders (logical size > 0, zero allocation, not sparse). They
	// are never opened for hashing.
	IssuePlaceholderSuspect = "EBB_SCAN_PLACEHOLDER_SUSPECT"
	// IssueNonrepresentableName marks names that are not valid UTF-8;
	// they stay in inventory but block destructive capability (§8.2).
	IssueNonrepresentableName = "EBB_SCAN_NONREPRESENTABLE_NAME"
)

// Options controls one scan. The zero value selects the defaults.
type Options struct {
	// MaxEntries caps the number of recorded entries; 0 selects
	// DefaultMaxEntries. Exceeding it fails the scan with the exact
	// position of the first unrecorded entry.
	MaxEntries int64
	// MaxDepth caps entry depth below the root (direct children are
	// depth 1); 0 selects DefaultMaxDepth.
	MaxDepth int
	// Hash digests preserved regular files (SHA-256, streamed) during
	// the scan. false defers digesting to the capture pass: entry sizes
	// are still set but Digest stays empty.
	Hash bool
}

// Result is the outcome of one scan. Err non-nil means the scan is
// incomplete and the result is fatal to any destructive plan (I12);
// Entries still carries everything recorded before the failure so the
// caller can decide how to proceed.
type Result struct {
	Root    domain.Root
	Entries []domain.Entry // canonical (root, path) order
	Summary domain.InventorySummary
	Err     error
}

// incompleteError marks a scan that could not finish. It always wraps
// domain.ErrScanIncomplete and, when there is one, the immediate cause
// (e.g. context.Canceled), so errors.Is distinguishes both.
type incompleteError struct {
	msg   string
	cause error
}

func (e *incompleteError) Error() string {
	if e.cause == nil {
		return "inventory: " + e.msg + ": " + domain.ErrScanIncomplete.Error()
	}
	return "inventory: " + e.msg + ": " + e.cause.Error() + ": " + domain.ErrScanIncomplete.Error()
}

func (e *incompleteError) Unwrap() []error {
	if e.cause == nil {
		return []error{domain.ErrScanIncomplete}
	}
	return []error{domain.ErrScanIncomplete, e.cause}
}

// Scan walks rootPath without following links and returns the inventory
// for that root. The root identity is resolved once via the probe before
// any walking; a missing or unidentifiable root fails before entries are
// produced. See the package comment for the classification contract.
func Scan(ctx context.Context, probe domain.PlatformProbe, rootPath string, opts Options) Result {
	if opts.MaxEntries == 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.MaxDepth == 0 {
		opts.MaxDepth = DefaultMaxDepth
	}
	if probe == nil {
		return Result{Err: &incompleteError{msg: "nil platform probe"}}
	}
	if opts.MaxEntries < 0 || opts.MaxDepth < 0 {
		return Result{Err: &incompleteError{msg: fmt.Sprintf("negative bounds (max entries %d, max depth %d)", opts.MaxEntries, opts.MaxDepth)}}
	}
	if rootPath == "" {
		return Result{Err: &incompleteError{msg: "empty root path"}}
	}
	if ctx == nil {
		return Result{Err: &incompleteError{msg: "nil context"}}
	}
	if err := ctx.Err(); err != nil {
		return Result{Err: &incompleteError{msg: "canceled before start", cause: err}}
	}

	rootAbs := filepath.Clean(mustAbs(rootPath))
	ident, err := probe.RootIdentity(rootAbs)
	if err != nil {
		return Result{Err: &incompleteError{msg: fmt.Sprintf("root identity for %q", rootAbs), cause: err}}
	}
	root := domain.Root{
		ID:        domain.RootMain,
		Path:      rootAbs,
		Identity:  ident,
		Ownership: domain.OwnershipOwned,
	}

	s := &scanner{
		ctx:      ctx,
		probe:    probe,
		rootAbs:  rootAbs,
		opts:     opts,
		groups:   make(map[string]*hlGroup),
		excl:     make(map[string]int64),
		blocking: make(map[string]struct{}),
	}
	s.walk("", 0)
	return s.finalize(root)
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

// hlGroup accumulates the in-root names sharing one file identity.
type hlGroup struct {
	idxs     []int // indices into scanner.entries (walk order)
	maxNlink int64
}

// entryMeta carries per-entry facts needed by the accounting pass; it is
// parallel to scanner.entries in walk order (before canonical sorting).
type entryMeta struct {
	seg      string // top-level path segment (ExclReclaimable key)
	blocking bool   // outcome is "blocking", not "preserved"
	excl     int64  // exclusive bytes for unshared files; -1 = not eligible
	alloc    *int64 // allocation for hardlink-group members
}

type scanner struct {
	ctx     context.Context
	probe   domain.PlatformProbe
	rootAbs string
	opts    Options

	entries        []domain.Entry
	meta           []entryMeta
	issues         []domain.ScanIssue
	groups         map[string]*hlGroup
	blocking       map[string]struct{}
	excl           map[string]int64
	preserved      int64
	preservedBytes int64
	nEntries       int64
	hashBuf        []byte
	err            error
}

// walk enumerates one directory's children at depth+1 and recurses into
// real subdirectories only. rel is "" for the root itself.
func (s *scanner) walk(rel string, depth int) bool {
	des, err := os.ReadDir(s.abs(rel))
	if err != nil {
		s.fail(fmt.Sprintf("reading directory %q", s.relOrRoot(rel)), err)
		return false
	}
	if len(des) > 0 && depth+1 > s.opts.MaxDepth {
		s.fail(fmt.Sprintf("depth bound exceeded at %q (max depth %d)", joinRel(rel, des[0].Name()), s.opts.MaxDepth), nil)
		return false
	}
	for _, de := range des {
		if err := s.ctx.Err(); err != nil {
			s.fail(fmt.Sprintf("canceled at %q", s.relOrRoot(rel)), err)
			return false
		}
		childRel := joinRel(rel, de.Name())
		if s.nEntries >= s.opts.MaxEntries {
			s.fail(fmt.Sprintf("entry budget exceeded at %q (max entries %d)", childRel, s.opts.MaxEntries), nil)
			return false
		}
		facts, err := s.probe.ProbeFile(s.abs(childRel))
		if err != nil {
			s.fail(fmt.Sprintf("probing %q", childRel), err)
			return false
		}
		kind, ok := s.emit(childRel, de.Name(), de, facts)
		if !ok {
			return false
		}
		if kind == domain.KindDir && !s.walk(childRel, depth+1) {
			return false
		}
	}
	return true
}

// emit classifies one child, records the entry and its accounting meta,
// and reports whether the walk can continue.
func (s *scanner) emit(rel, name string, de os.DirEntry, facts domain.FileFacts) (domain.EntryKind, bool) {
	kind := facts.Kind
	if kind == "" {
		kind = kindFromDirEntry(de)
	}
	if facts.LogicalSize < 0 {
		s.fail(fmt.Sprintf("probe reported negative logical size for %q", rel), nil)
		return kind, false
	}
	if facts.AllocatedSize != nil && *facts.AllocatedSize < 0 {
		s.fail(fmt.Sprintf("probe reported negative allocated size for %q", rel), nil)
		return kind, false
	}

	e := domain.Entry{
		Root:        domain.RootMain,
		Path:        rel,
		Kind:        kind,
		Route:       domain.RoutePreserve,
		Ownership:   domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary,
		Evidence:    []string{evidenceScan},
	}
	m := entryMeta{seg: topSegment(rel), excl: -1}
	blocking := false

	// A name the durable records cannot represent losslessly must block
	// destructive capability, not disappear (Foundation §8.2).
	if !nameRepresentable(name) {
		blocking = true
		s.addIssue(rel, IssueNonrepresentableName, "name is not valid UTF-8; blocks destructive capability")
		e.Evidence = append(e.Evidence, evidenceScan+":"+IssueNonrepresentableName)
	}

	switch kind {
	case domain.KindFile:
		e.LogicalSize = facts.LogicalSize
		e.AllocatedSize = facts.AllocatedSize
		// Placeholder heuristic: content reported but nothing allocated
		// and no sparse flag (modern OneDrive placeholders report exact
		// logical size with zero on-disk allocation; see
		// lab/platform-probe Q8). AllocatedSize==nil means the platform
		// cannot observe allocation and says nothing either way.
		placeholder := facts.Placeholder || (!facts.Sparse &&
			facts.AllocatedSize != nil && *facts.AllocatedSize == 0 &&
			facts.LogicalSize > 0)
		if placeholder {
			blocking = true
			s.addIssue(rel, IssuePlaceholderSuspect, fmt.Sprintf(
				"logical size %d with zero allocation and no sparse flag; cloud placeholder suspected; never opened for hashing", facts.LogicalSize))
			e.Evidence = append(e.Evidence, evidenceScan+":"+IssuePlaceholderSuspect)
		}
		if len(facts.Streams) > 0 {
			blocking = true
			s.addIssue(rel, IssueADSPresent, streamsNote(facts.Streams))
			e.Evidence = append(e.Evidence, evidenceScan+":"+IssueADSPresent)
		}
		if facts.LinkCount > 1 {
			// Multiple names share this content: mutation is shared.
			e.Ownership = domain.OwnershipShared
			if facts.FileIdentity != "" {
				g := s.groups[facts.FileIdentity]
				if g == nil {
					g = &hlGroup{}
					s.groups[facts.FileIdentity] = g
				}
				g.idxs = append(g.idxs, len(s.entries))
				if facts.LinkCount > g.maxNlink {
					g.maxNlink = facts.LinkCount
				}
				m.alloc = facts.AllocatedSize
			}
			// Without an identity the sharing cannot be attributed:
			// excluded from ExclReclaimable (report unknown, §14.1).
		} else if facts.LinkCount == 1 && !blocking && facts.AllocatedSize != nil {
			m.excl = *facts.AllocatedSize
		}
		if s.opts.Hash && !placeholder {
			if err := s.ctx.Err(); err != nil {
				s.fail(fmt.Sprintf("canceled before hashing %q", rel), err)
				return kind, false
			}
			digest, err := s.digestFile(s.abs(rel))
			if err != nil {
				s.fail(fmt.Sprintf("hashing %q", rel), err)
				return kind, false
			}
			e.Digest = digest
		}

	case domain.KindDir:
		// Directory metadata is captured, but sizes stay zero.

	case domain.KindSymlink:
		e.Ownership = domain.OwnershipReferenceOnly
		e.LinkTarget = facts.LinkTarget

	case domain.KindJunction, domain.KindMountPoint, domain.KindOtherReparse:
		e.Ownership = domain.OwnershipReferenceOnly
		e.LinkTarget = facts.LinkTarget
		s.addIssue(rel, IssueBoundaryLink, boundaryNote(kind, facts.LinkTarget))
		e.Evidence = append(e.Evidence, evidenceScan+":"+IssueBoundaryLink)
		if kind == domain.KindOtherReparse {
			// Unrecognized reparse objects are not DestructiveSafe (§10.2).
			blocking = true
			s.addIssue(rel, IssueSpecialFile, fmt.Sprintf("unrecognized reparse point (tag %q); blocks destructive operations", facts.ReparseTag))
			e.Evidence = append(e.Evidence, evidenceScan+":"+IssueSpecialFile)
		}

	case domain.KindFIFO, domain.KindSocket, domain.KindDevice:
		blocking = true
		s.addIssue(rel, IssueSpecialFile, fmt.Sprintf("%s is ephemeral state, not file content; blocks destructive operations", kind))
		e.Evidence = append(e.Evidence, evidenceScan+":"+IssueSpecialFile)

	default:
		blocking = true
		s.addIssue(rel, IssueSpecialFile, fmt.Sprintf("probe reported unrecognized kind %q; blocks destructive operations", kind))
		e.Evidence = append(e.Evidence, evidenceScan+":"+IssueSpecialFile)
	}

	m.blocking = blocking
	if blocking {
		s.blocking[rel] = struct{}{}
	} else {
		s.preserved++
		if kind == domain.KindFile {
			s.preservedBytes += facts.LogicalSize
		}
	}
	s.entries = append(s.entries, e)
	s.meta = append(s.meta, m)
	s.nEntries++
	return kind, true
}

// finalize assigns hardlink groups, closes the accounting, sorts every
// output deterministically and validates the canonical stream.
func (s *scanner) finalize(root domain.Root) Result {
	s.assignHardlinkGroups()

	for i := range s.meta {
		if m := s.meta[i]; !m.blocking && m.excl >= 0 {
			s.excl[m.seg] += m.excl
		}
	}

	domain.SortEntries(s.entries)
	sort.Slice(s.issues, func(i, j int) bool {
		if s.issues[i].Path != s.issues[j].Path {
			return s.issues[i].Path < s.issues[j].Path
		}
		return s.issues[i].Code < s.issues[j].Code
	})
	blocking := make([]string, 0, len(s.blocking))
	for p := range s.blocking {
		blocking = append(blocking, p)
	}
	sort.Strings(blocking)

	if err := domain.CheckSortedAndUnique(s.entries); err != nil {
		s.fail("canonical order violation", err)
	}

	summary := domain.InventorySummary{
		TotalEntries:   int64(len(s.entries)),
		Preserved:      s.preserved,
		OmittedByRoute: map[domain.Route]int64{},
		Blocking:       blocking,
		PreservedBytes: s.preservedBytes,
		Issues:         s.issues,
	}
	if len(s.excl) > 0 {
		summary.ExclReclaimable = s.excl
	}
	if s.err == nil && !summary.Complete() {
		s.fail("accounting mismatch: every entry needs exactly one outcome", nil)
	}

	return Result{Root: root, Entries: s.entries, Summary: summary, Err: s.err}
}

// assignHardlinkGroups gives every in-root hardlink group a stable id
// derived from the file identity, records outside-root sharing, and
// attributes each group's allocation exactly once — and only when the
// group is fully in-root, unblocked and inside one top-level segment
// (Foundation §14.1: never guess attribution, never double-count).
func (s *scanner) assignHardlinkGroups() {
	if len(s.groups) == 0 {
		return
	}
	idents := make([]string, 0, len(s.groups))
	for id := range s.groups {
		idents = append(idents, id)
	}
	sort.Strings(idents)

	for _, id := range idents {
		g := s.groups[id]
		sum := sha256.Sum256([]byte(id))
		gid := hardlinkPrefix + hex.EncodeToString(sum[:])[:8]

		singleSeg, allAlloc, anyBlocking := true, true, false
		seg := s.meta[g.idxs[0]].seg
		for _, idx := range g.idxs {
			s.entries[idx].HardlinkGroup = gid
			m := s.meta[idx]
			if m.seg != seg {
				singleSeg = false
			}
			if m.alloc == nil {
				allAlloc = false
			}
			if m.blocking {
				anyBlocking = true
			}
		}
		if g.maxNlink > int64(len(g.idxs)) {
			for _, idx := range g.idxs {
				s.addIssue(s.entries[idx].Path, IssueHardlinkOutside, fmt.Sprintf(
					"link count %d exceeds %d in-root references; aliases outside the root keep these bytes alive",
					g.maxNlink, len(g.idxs)))
			}
			continue
		}
		if singleSeg && allAlloc && !anyBlocking {
			// All aliases report the same physical allocation; count it once.
			s.excl[seg] += *s.meta[g.idxs[0]].alloc
		}
	}
}

// digestFile streams the file through SHA-256 with the shared 1 MiB
// buffer; contents are never fully buffered.
func (s *scanner) digestFile(abs string) (string, error) {
	f, err := os.Open(abs)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if s.hashBuf == nil {
		s.hashBuf = make([]byte, hashBufSize)
	}
	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, s.hashBuf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *scanner) addIssue(path, code, note string) {
	s.issues = append(s.issues, domain.ScanIssue{Path: path, Code: code, Note: note})
}

// fail records the first fatal scan error; later failures are dropped.
func (s *scanner) fail(msg string, cause error) {
	if s.err == nil {
		s.err = &incompleteError{msg: msg, cause: cause}
	}
}

// abs maps a root-relative slash path to an absolute native path.
func (s *scanner) abs(rel string) string {
	if rel == "" {
		return s.rootAbs
	}
	return filepath.Join(s.rootAbs, filepath.FromSlash(rel))
}

func (s *scanner) relOrRoot(rel string) string {
	if rel == "" {
		return s.rootAbs
	}
	return rel
}

func joinRel(rel, name string) string {
	if rel == "" {
		return name
	}
	return rel + "/" + name
}

// topSegment returns the path prefix before the first '/', or the whole
// path for top-level files — the ExclReclaimable reporting key.
func topSegment(rel string) string {
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		return rel[:i]
	}
	return rel
}

// kindFromDirEntry is the fallback classifier when the probe reports no
// Kind. It must not be the primary source: raw modes cannot distinguish
// junctions from other reparse points (lab/platform-probe Q1).
func kindFromDirEntry(de os.DirEntry) domain.EntryKind {
	mode := de.Type()
	switch {
	case mode.IsDir():
		return domain.KindDir
	case mode&os.ModeSymlink != 0:
		return domain.KindSymlink
	case mode&os.ModeIrregular != 0:
		return domain.KindOtherReparse
	case mode&os.ModeNamedPipe != 0:
		return domain.KindFIFO
	case mode&os.ModeSocket != 0:
		return domain.KindSocket
	case mode&os.ModeDevice != 0:
		return domain.KindDevice
	default:
		return domain.KindFile
	}
}

// nameRepresentable reports whether an on-disk name can travel through
// Ebb's UTF-8 records unchanged.
func nameRepresentable(name string) bool {
	return utf8.ValidString(name)
}

func streamsNote(ss []domain.NamedStream) string {
	var b strings.Builder
	b.WriteString("named data streams present (lost by the v1 backend; destructive operations blocked):")
	for _, st := range ss {
		fmt.Fprintf(&b, " :%s(%d bytes)", st.Name, st.Size)
	}
	return b.String()
}

func boundaryNote(kind domain.EntryKind, target string) string {
	if target == "" {
		return fmt.Sprintf("%s boundary: recorded, never descended (target unavailable)", kind)
	}
	return fmt.Sprintf("%s boundary: recorded, never descended (target %q)", kind, target)
}
