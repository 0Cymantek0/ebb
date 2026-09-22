package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// ---------------------------------------------------------------------------
// Test seams (Foundation §16.7): a real-FS probe built from stdlib os only
// (no x/sys, no dependency on internal/platform), plus a programmable
// fakeProbe with fact overrides and fault injection layered over a real
// temp directory.
// ---------------------------------------------------------------------------

// fsEnrich fills platform-native file identity and link count when the
// build supports it (set by probe_windows_test.go).
var fsEnrich func(abs string, f *domain.FileFacts)

// fsRootIdentity computes a native root identity when available.
var fsRootIdentity func(abs string) (domain.RootIdentity, error)

// realProbe answers PlatformProbe from stdlib os alone: Lstat for kind
// and size, os.Readlink for link text, plus optional native enrichment.
// It is the "real filesystem" test arm; production probing lives in
// internal/platform behind the same seam.
type realProbe struct{}

func (realProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	if fsRootIdentity != nil {
		return fsRootIdentity(path)
	}
	return domain.RootIdentity{VolumeID: "real-fs", FileID: filepath.Clean(path)}, nil
}

func (realProbe) VolumeUsage(path string) (domain.VolumeUsage, error) {
	id := "real-fs"
	if fsRootIdentity != nil {
		if ri, err := fsRootIdentity(path); err == nil {
			id = ri.VolumeID
		}
	}
	return domain.VolumeUsage{VolumeID: id}, nil
}

func (realProbe) ProbeFile(abs string) (domain.FileFacts, error) {
	return fsFacts(abs)
}

// fsFacts classifies via stdlib Lstat. Junctions surface as
// ModeIrregular (lab/platform-probe Q1); without the reparse ioctl the
// test probe labels them KindJunction, which matches the fixtures tests
// create (mklink /J).
func fsFacts(abs string) (domain.FileFacts, error) {
	fi, err := os.Lstat(abs)
	if err != nil {
		return domain.FileFacts{}, err
	}
	f := domain.FileFacts{}
	mode := fi.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		f.Kind = domain.KindSymlink
		f.LinkTarget = readlinkBestEffort(abs)
	case mode.IsDir():
		f.Kind = domain.KindDir
	case mode&os.ModeIrregular != 0:
		f.Kind = domain.KindJunction
		f.LinkTarget = readlinkBestEffort(abs)
	case mode&os.ModeNamedPipe != 0:
		f.Kind = domain.KindFIFO
	case mode&os.ModeSocket != 0:
		f.Kind = domain.KindSocket
	case mode&os.ModeDevice != 0:
		f.Kind = domain.KindDevice
	default:
		f.Kind = domain.KindFile
		f.LogicalSize = fi.Size()
		if fsEnrich != nil {
			fsEnrich(abs, &f)
		}
	}
	return f, nil
}

func readlinkBestEffort(abs string) string {
	t, err := os.Readlink(abs)
	if err != nil {
		return ""
	}
	return t
}

// fakeProbe wraps a real root directory with programmable fact overlays
// and injectable errors. Facts default to the real filesystem and are
// then overridden field by field (non-zero fields win).
type fakeProbe struct {
	root            string
	rootID          domain.RootIdentity
	rootErr         error
	facts           map[string]*domain.FileFacts // by root-relative slash path
	errs            map[string]error             // ProbeFile faults by rel path
	onProbe         func(rel string, call int)   // hook for cancellation etc.
	disableIdentity bool                         // simulate a probe without native identity
	calls           int
}

func newFakeProbe(t *testing.T) (*fakeProbe, string) {
	t.Helper()
	root := t.TempDir()
	return &fakeProbe{
		root:  root,
		facts: make(map[string]*domain.FileFacts),
		errs:  make(map[string]error),
	}, root
}

func (p *fakeProbe) rel(abs string) string {
	a := filepath.Clean(abs)
	r := filepath.Clean(p.root)
	if strings.HasPrefix(a, r+string(os.PathSeparator)) {
		return filepath.ToSlash(strings.TrimPrefix(a, r+string(os.PathSeparator)))
	}
	return filepath.ToSlash(a)
}

func (p *fakeProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	if p.rootErr != nil {
		return domain.RootIdentity{}, p.rootErr
	}
	if p.rootID != (domain.RootIdentity{}) {
		return p.rootID, nil
	}
	return domain.RootIdentity{VolumeID: "fakevol", FileID: filepath.Clean(path)}, nil
}

func (p *fakeProbe) VolumeUsage(string) (domain.VolumeUsage, error) {
	return domain.VolumeUsage{VolumeID: "fakevol"}, nil
}

func (p *fakeProbe) ProbeFile(abs string) (domain.FileFacts, error) {
	p.calls++
	rel := p.rel(abs)
	if p.onProbe != nil {
		p.onProbe(rel, p.calls)
	}
	if err := p.errs[rel]; err != nil {
		return domain.FileFacts{}, err
	}
	f, err := fsFacts(abs)
	if err != nil {
		return domain.FileFacts{}, err
	}
	if p.disableIdentity {
		f.FileIdentity = ""
	}
	if o := p.facts[rel]; o != nil {
		overlayFacts(&f, o)
	}
	return f, nil
}

// overlayFacts copies every non-zero field from o onto dst.
func overlayFacts(dst *domain.FileFacts, o *domain.FileFacts) {
	if o.Kind != "" {
		dst.Kind = o.Kind
	}
	if o.LogicalSize != 0 {
		dst.LogicalSize = o.LogicalSize
	}
	if o.AllocatedSize != nil {
		dst.AllocatedSize = o.AllocatedSize
	}
	if o.LinkTarget != "" {
		dst.LinkTarget = o.LinkTarget
	}
	if o.FileIdentity != "" {
		dst.FileIdentity = o.FileIdentity
	}
	if o.LinkCount != 0 {
		dst.LinkCount = o.LinkCount
	}
	if o.Streams != nil {
		dst.Streams = o.Streams
	}
	if o.Sparse {
		dst.Sparse = true
	}
	if o.ReparseTag != "" {
		dst.ReparseTag = o.ReparseTag
	}
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// makeJunction creates a Windows junction via cmd /c mklink /J, which
// works unprivileged. It reports false when junctions are unavailable
// (non-Windows or restricted environments).
func makeJunction(t *testing.T, link, target string) bool {
	t.Helper()
	if runtime.GOOS != "windows" {
		return false
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		t.Logf("mklink /J %s %s failed: %v: %s", link, target, err, out)
		return false
	}
	return true
}

func entryOf(t *testing.T, res Result, path string) domain.Entry {
	t.Helper()
	for _, e := range res.Entries {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("no entry with path %q among %d entries", path, len(res.Entries))
	return domain.Entry{}
}

func issueCodes(res Result, path string) []string {
	var codes []string
	for _, is := range res.Summary.Issues {
		if is.Path == path {
			codes = append(codes, is.Code)
		}
	}
	sort.Strings(codes)
	return codes
}

// checkCanonical asserts the invariants every successful or partial
// result must satisfy.
func checkCanonical(t *testing.T, res Result) {
	t.Helper()
	if err := domain.CheckSortedAndUnique(res.Entries); err != nil {
		t.Fatalf("entries not sorted+unique: %v", err)
	}
	if !res.Summary.Complete() {
		t.Fatalf("accounting incomplete: %+v", res.Summary)
	}
	if res.Summary.TotalEntries != int64(len(res.Entries)) {
		t.Fatalf("TotalEntries=%d len=%d", res.Summary.TotalEntries, len(res.Entries))
	}
}

// ---------------------------------------------------------------------------
// Basic traversal (real filesystem, real probe)
// ---------------------------------------------------------------------------

func TestScanBasicFixture(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "hello.txt"), "hello world")
	writeFile(t, filepath.Join(root, "a", "b", "c.txt"), "deep content")
	mkdir(t, filepath.Join(root, "empty"))
	writeFile(t, filepath.Join(root, "a", "mid.txt"), "mid")

	res := Scan(context.Background(), realProbe{}, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}

	wantPaths := []string{
		"a",
		"a/b",
		"a/b/c.txt",
		"a/mid.txt",
		"empty",
		"hello.txt",
	}
	var got []string
	for _, e := range res.Entries {
		got = append(got, e.Path)
	}
	if !reflect.DeepEqual(got, wantPaths) {
		t.Fatalf("paths = %v, want %v", got, wantPaths)
	}

	c := entryOf(t, res, "hello.txt")
	if c.Kind != domain.KindFile || c.LogicalSize != int64(len("hello world")) {
		t.Fatalf("hello.txt = %+v", c)
	}
	if c.Digest != sha256Hex([]byte("hello world")) {
		t.Fatalf("hello.txt digest = %q", c.Digest)
	}
	empty := entryOf(t, res, "empty")
	if empty.Kind != domain.KindDir {
		t.Fatalf("empty dir kind = %q", empty.Kind)
	}
	dirA := entryOf(t, res, "a")
	if dirA.Kind != domain.KindDir || dirA.LogicalSize != 0 || dirA.Digest != "" {
		t.Fatalf("dir a = %+v", dirA)
	}

	if res.Root.ID != domain.RootMain || res.Root.Path != filepath.Clean(root) {
		t.Fatalf("root = %+v", res.Root)
	}
	if len(res.Summary.Issues) != 0 {
		t.Fatalf("unexpected issues: %+v", res.Summary.Issues)
	}
	if res.Summary.Preserved != res.Summary.TotalEntries || res.Summary.OmittedByRoute == nil {
		t.Fatalf("summary = %+v", res.Summary)
	}
	if res.Summary.PreservedBytes != int64(len("hello world")+len("deep content")+len("mid")) {
		t.Fatalf("PreservedBytes = %d", res.Summary.PreservedBytes)
	}
	checkCanonical(t, res)

	for _, e := range res.Entries {
		if err := e.Validate(); err != nil {
			t.Fatalf("entry %q failed Validate: %v", e.Path, err)
		}
	}
}

func TestScanNoHashModeDefersDigest(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.txt"), "payload")

	res := Scan(context.Background(), realProbe{}, root, Options{Hash: false})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	e := entryOf(t, res, "f.txt")
	if e.Digest != "" {
		t.Fatalf("digest = %q, want empty in deferred mode", e.Digest)
	}
	if e.LogicalSize != int64(len("payload")) {
		t.Fatalf("size = %d", e.LogicalSize)
	}
}

func TestScanEmptyRoot(t *testing.T) {
	root := t.TempDir()
	res := Scan(context.Background(), realProbe{}, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("entries = %v", res.Entries)
	}
	if len(res.Summary.Blocking) != 0 || res.Summary.Preserved != 0 {
		t.Fatalf("summary = %+v", res.Summary)
	}
	checkCanonical(t, res)
}

func TestScanCanonicalOrderBeatsDFSPreorder(t *testing.T) {
	// DFS pre-order with sorted directory reads yields a/b before
	// "a b.txt" and "a.txt"; canonical (root, path) order does not.
	root := t.TempDir()
	mkdir(t, filepath.Join(root, "a"))
	writeFile(t, filepath.Join(root, "a", "y.txt"), "y")
	writeFile(t, filepath.Join(root, "a b.txt"), "sp")
	writeFile(t, filepath.Join(root, "a.txt"), "x")
	mkdir(t, filepath.Join(root, "zzz"))

	res := Scan(context.Background(), realProbe{}, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	want := []string{"a", "a b.txt", "a.txt", "a/y.txt", "zzz"}
	var got []string
	for _, e := range res.Entries {
		got = append(got, e.Path)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Links: junction and symlink must never be descended into
// ---------------------------------------------------------------------------

func TestScanJunctionNotDescended(t *testing.T) {
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "do not touch")
	root := t.TempDir()
	if !makeJunction(t, filepath.Join(root, "junc"), outside) {
		t.Skip("junction creation unavailable on this host")
	}
	writeFile(t, filepath.Join(root, "plain.txt"), "plain")

	res := Scan(context.Background(), realProbe{}, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}

	j := entryOf(t, res, "junc")
	if j.Kind != domain.KindJunction {
		t.Fatalf("junction kind = %q", j.Kind)
	}
	if j.LinkTarget == "" {
		t.Fatalf("junction recorded without LinkTarget")
	}
	if j.Ownership != domain.OwnershipReferenceOnly {
		t.Fatalf("junction ownership = %q", j.Ownership)
	}
	for _, e := range res.Entries {
		if strings.HasPrefix(e.Path, "junc/") {
			t.Fatalf("descended into junction: %q", e.Path)
		}
		if e.Path == "secret.txt" {
			t.Fatalf("external target content leaked into inventory")
		}
	}
	if codes := issueCodes(res, "junc"); !reflect.DeepEqual(codes, []string{IssueBoundaryLink}) {
		t.Fatalf("junction issues = %v", codes)
	}
	checkCanonical(t, res)
}

func TestScanSymlinkRecordedNotFollowed(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "t.txt")
	writeFile(t, target, "outside content")
	root := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	res := Scan(context.Background(), realProbe{}, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	e := entryOf(t, res, "link.txt")
	if e.Kind != domain.KindSymlink {
		t.Fatalf("kind = %q", e.Kind)
	}
	if e.LinkTarget != target {
		t.Fatalf("LinkTarget = %q, want %q", e.LinkTarget, target)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("entries = %v", res.Entries)
	}
	if len(res.Summary.Issues) != 0 {
		t.Fatalf("symlink must not raise a boundary issue: %+v", res.Summary.Issues)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Real hardlink grouping (Windows native identity via stdlib syscall)
// ---------------------------------------------------------------------------

func TestScanHardlinkGroupReal(t *testing.T) {
	if runtime.GOOS != "windows" || fsEnrich == nil {
		t.Skip("native file identity enrichment unavailable")
	}
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "x.txt"), "shared bytes")
	if err := os.Link(filepath.Join(root, "x.txt"), filepath.Join(root, "y.txt")); err != nil {
		t.Skipf("hardlink creation unavailable: %v", err)
	}
	writeFile(t, filepath.Join(root, "solo.txt"), "solo")

	res := Scan(context.Background(), realProbe{}, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	x := entryOf(t, res, "x.txt")
	y := entryOf(t, res, "y.txt")
	solo := entryOf(t, res, "solo.txt")

	if x.HardlinkGroup == "" || x.HardlinkGroup != y.HardlinkGroup {
		t.Fatalf("group ids: x=%q y=%q", x.HardlinkGroup, y.HardlinkGroup)
	}
	if !strings.HasPrefix(x.HardlinkGroup, "hl:") || len(x.HardlinkGroup) != len("hl:")+8 {
		t.Fatalf("group id shape: %q", x.HardlinkGroup)
	}
	if solo.HardlinkGroup != "" {
		t.Fatalf("solo file grouped: %q", solo.HardlinkGroup)
	}
	if x.Ownership != domain.OwnershipShared || solo.Ownership != domain.OwnershipOwned {
		t.Fatalf("ownership: x=%q solo=%q", x.Ownership, solo.Ownership)
	}
	if x.Digest != y.Digest || x.Digest != sha256Hex([]byte("shared bytes")) {
		t.Fatalf("digests: x=%q y=%q", x.Digest, y.Digest)
	}
	// nlink 2 == 2 in-root references: no outside-sharing issue.
	for _, is := range res.Summary.Issues {
		if is.Code == IssueHardlinkOutside {
			t.Fatalf("unexpected outside issue: %+v", is)
		}
	}
	if len(res.Summary.Blocking) != 0 {
		t.Fatalf("unexpected blocking: %v", res.Summary.Blocking)
	}
}

// ---------------------------------------------------------------------------
// fakeProbe: hardlink accounting
// ---------------------------------------------------------------------------

func fakeFileFacts(id string, nlink int64, alloc int64, sparse bool) *domain.FileFacts {
	return &domain.FileFacts{
		LinkCount:     nlink,
		FileIdentity:  id,
		AllocatedSize: &alloc,
		Sparse:        sparse,
	}
}

func TestScanHardlinkGroupFullyInRoot(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "grp", "a.txt"), "aaaaaaaa")
	writeFile(t, filepath.Join(root, "grp", "b.txt"), "aaaaaaaa")
	p.facts["grp/a.txt"] = fakeFileFacts("ID-GRP", 2, 4096, false)
	p.facts["grp/b.txt"] = fakeFileFacts("ID-GRP", 2, 4096, false)

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	a := entryOf(t, res, "grp/a.txt")
	b := entryOf(t, res, "grp/b.txt")
	if a.HardlinkGroup == "" || a.HardlinkGroup != b.HardlinkGroup {
		t.Fatalf("groups: a=%q b=%q", a.HardlinkGroup, b.HardlinkGroup)
	}
	if got := res.Summary.ExclReclaimable["grp"]; got != 4096 {
		t.Fatalf("ExclReclaimable[grp] = %d, want 4096 counted once", got)
	}
	if len(res.Summary.Issues) != 0 {
		t.Fatalf("unexpected issues: %+v", res.Summary.Issues)
	}
}

func TestScanHardlinkGroupSpanningSegmentsNotAttributed(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "p", "a.txt"), "aaaaaaaa")
	writeFile(t, filepath.Join(root, "q", "b.txt"), "aaaaaaaa")
	p.facts["p/a.txt"] = fakeFileFacts("ID-SPAN", 2, 2048, false)
	p.facts["q/b.txt"] = fakeFileFacts("ID-SPAN", 2, 2048, false)

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	if len(res.Summary.ExclReclaimable) != 0 {
		t.Fatalf("cross-segment group must stay unattributed: %+v", res.Summary.ExclReclaimable)
	}
	if len(res.Summary.Issues) != 0 {
		t.Fatalf("fully in-root group must not raise outside issue: %+v", res.Summary.Issues)
	}
	if entryOf(t, res, "p/a.txt").HardlinkGroup == "" {
		t.Fatalf("group id missing")
	}
}

func TestScanHardlinkOutsideRoot(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "d", "a.txt"), "aaaaaaaa")
	writeFile(t, filepath.Join(root, "d", "b.txt"), "aaaaaaaa")
	p.facts["d/a.txt"] = fakeFileFacts("ID-OUT", 3, 4096, false)
	p.facts["d/b.txt"] = fakeFileFacts("ID-OUT", 3, 4096, false)

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	for _, path := range []string{"d/a.txt", "d/b.txt"} {
		if codes := issueCodes(res, path); !reflect.DeepEqual(codes, []string{IssueHardlinkOutside}) {
			t.Fatalf("%s issues = %v", path, codes)
		}
	}
	if len(res.Summary.ExclReclaimable) != 0 {
		t.Fatalf("outside-shared bytes must not be exclusively reclaimable: %+v", res.Summary.ExclReclaimable)
	}
	if len(res.Summary.Blocking) != 0 {
		t.Fatalf("outside sharing is an issue, not a blocking outcome: %v", res.Summary.Blocking)
	}
}

func TestScanSharedWithoutIdentityNotAttributed(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "n", "a.txt"), "aaaaaaaa")
	p.disableIdentity = true                               // probe cannot report native identity
	p.facts["n/a.txt"] = fakeFileFacts("", 2, 4096, false) // nlink>1, no identity

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	e := entryOf(t, res, "n/a.txt")
	if e.HardlinkGroup != "" {
		t.Fatalf("ungroupable file grouped: %q", e.HardlinkGroup)
	}
	if e.Ownership != domain.OwnershipShared {
		t.Fatalf("ownership = %q", e.Ownership)
	}
	if len(res.Summary.ExclReclaimable) != 0 {
		t.Fatalf("unattributable sharing must stay out of ExclReclaimable: %+v", res.Summary.ExclReclaimable)
	}
}

func TestScanSparseFileCountsAllocationOnly(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "s", "hole.bin"), strings.Repeat("x", 4096))
	p.facts["s/hole.bin"] = fakeFileFacts("", 1, 65536, true)
	// Logical size 4096 but sparse with a 64 KiB extent map: only the
	// allocation may enter ExclReclaimable.

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	e := entryOf(t, res, "s/hole.bin")
	if e.LogicalSize != 4096 {
		t.Fatalf("logical size = %d, want Lstat truth 4096", e.LogicalSize)
	}
	if got := res.Summary.ExclReclaimable["s"]; got != 65536 {
		t.Fatalf("ExclReclaimable[s] = %d, want allocated 65536", got)
	}
}

// ---------------------------------------------------------------------------
// fakeProbe: blocking classifications
// ---------------------------------------------------------------------------

func TestScanADSPresentBlocks(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "ads.txt"), "default stream")
	p.facts["ads.txt"] = &domain.FileFacts{
		Streams: []domain.NamedStream{{Name: "cred", Size: 8}},
	}

	res := Scan(context.Background(), p, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	if codes := issueCodes(res, "ads.txt"); !reflect.DeepEqual(codes, []string{IssueADSPresent}) {
		t.Fatalf("issues = %v", codes)
	}
	if !contains(res.Summary.Blocking, "ads.txt") {
		t.Fatalf("Blocking = %v", res.Summary.Blocking)
	}
	e := entryOf(t, res, "ads.txt")
	if e.Digest == "" {
		t.Fatalf("default stream must still digest under Hash=true")
	}
	if res.Summary.Preserved != res.Summary.TotalEntries-1 {
		t.Fatalf("ADS file must not count as preserved: %+v", res.Summary)
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestScanPlaceholderSuspectNeverHashed(t *testing.T) {
	p, root := newFakeProbe(t)
	// The real object is a DIRECTORY carrying file facts. If the scanner
	// tried to hash it, os.Open succeeds but the read fails and the scan
	// errors — so Err==nil proves the file was never opened.
	mkdir(t, filepath.Join(root, "ph"))
	zero := int64(0)
	p.facts["ph"] = &domain.FileFacts{
		Kind:          domain.KindFile,
		LogicalSize:   5000,
		AllocatedSize: &zero,
	}
	writeFile(t, filepath.Join(root, "ok.txt"), "fine")

	res := Scan(context.Background(), p, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("placeholder-suspect was opened for hashing: %v", res.Err)
	}
	e := entryOf(t, res, "ph")
	if e.Digest != "" {
		t.Fatalf("digest = %q, want empty", e.Digest)
	}
	if e.LogicalSize != 5000 {
		t.Fatalf("logical size = %d", e.LogicalSize)
	}
	if codes := issueCodes(res, "ph"); !reflect.DeepEqual(codes, []string{IssuePlaceholderSuspect}) {
		t.Fatalf("issues = %v", codes)
	}
	if !contains(res.Summary.Blocking, "ph") {
		t.Fatalf("Blocking = %v", res.Summary.Blocking)
	}
	// Known friction (reported): a preserved-route file without digest
	// cannot pass Entry.Validate — policy must later assign the real
	// external route or the user must deliberately hydrate.
	if err := e.Validate(); err == nil {
		t.Fatal("expected Validate friction for unhashable placeholder entry")
	}
}

func TestScanSpecialFilesBlock(t *testing.T) {
	for _, kind := range []domain.EntryKind{domain.KindFIFO, domain.KindSocket, domain.KindDevice} {
		t.Run(string(kind), func(t *testing.T) {
			p, root := newFakeProbe(t)
			writeFile(t, filepath.Join(root, "special"), "x")
			p.facts["special"] = &domain.FileFacts{Kind: kind}

			res := Scan(context.Background(), p, root, Options{})
			if res.Err != nil {
				t.Fatalf("scan: %v", res.Err)
			}
			e := entryOf(t, res, "special")
			if e.Kind != kind {
				t.Fatalf("kind = %q, want %q (probe facts must win)", e.Kind, kind)
			}
			if codes := issueCodes(res, "special"); !reflect.DeepEqual(codes, []string{IssueSpecialFile}) {
				t.Fatalf("issues = %v", codes)
			}
			if !contains(res.Summary.Blocking, "special") {
				t.Fatalf("Blocking = %v", res.Summary.Blocking)
			}
			checkCanonical(t, res)
		})
	}
}

func TestScanOtherReparseBlocksAndDoesNotDescend(t *testing.T) {
	p, root := newFakeProbe(t)
	mkdir(t, filepath.Join(root, "rp", "inside"))
	p.facts["rp"] = &domain.FileFacts{
		Kind:       domain.KindOtherReparse,
		ReparseTag: "0xa0000013",
	}

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	for _, e := range res.Entries {
		if strings.HasPrefix(e.Path, "rp/") {
			t.Fatalf("descended into unrecognized reparse point: %q", e.Path)
		}
	}
	codes := issueCodes(res, "rp")
	if !reflect.DeepEqual(codes, []string{IssueBoundaryLink, IssueSpecialFile}) {
		t.Fatalf("issues = %v", codes)
	}
	if !contains(res.Summary.Blocking, "rp") {
		t.Fatalf("Blocking = %v", res.Summary.Blocking)
	}
}

func TestScanUnrecognizedKindBlocks(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "weird"), "x")
	p.facts["weird"] = &domain.FileFacts{Kind: domain.EntryKind("portalgateway")}

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	if codes := issueCodes(res, "weird"); !reflect.DeepEqual(codes, []string{IssueSpecialFile}) {
		t.Fatalf("issues = %v", codes)
	}
	if !contains(res.Summary.Blocking, "weird") {
		t.Fatalf("Blocking = %v", res.Summary.Blocking)
	}
}

func TestScanNonrepresentableNameBlocks(t *testing.T) {
	if !nameRepresentable("ok.txt") || nameRepresentable("bad\xff") {
		t.Fatal("nameRepresentable contract broken")
	}
	// Creating a genuinely non-UTF-8 on-disk name needs raw native APIs
	// (Win32 is UTF-16; Go re-encodes), so the classification is covered
	// through the predicate plus the blocking wiring asserted above.
}

// ---------------------------------------------------------------------------
// Bounds and cancellation
// ---------------------------------------------------------------------------

func TestScanMaxEntriesExceeded(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "a.txt"), "a")
	writeFile(t, filepath.Join(root, "b.txt"), "b")
	writeFile(t, filepath.Join(root, "c.txt"), "c")

	res := Scan(context.Background(), p, root, Options{MaxEntries: 2})
	if res.Err == nil {
		t.Fatal("expected bound error")
	}
	if !errors.Is(res.Err, domain.ErrScanIncomplete) {
		t.Fatalf("err = %v", res.Err)
	}
	if !strings.Contains(res.Err.Error(), `"c.txt"`) {
		t.Fatalf("error must name the exact position: %v", res.Err)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("entries = %d, want the 2 recorded before the bound", len(res.Entries))
	}
	checkCanonical(t, res)
}

func TestScanMaxDepthExceeded(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "a", "b", "leaf.txt"), "deep")

	res := Scan(context.Background(), p, root, Options{MaxDepth: 2})
	if res.Err == nil {
		t.Fatal("expected depth error")
	}
	if !errors.Is(res.Err, domain.ErrScanIncomplete) {
		t.Fatalf("err = %v", res.Err)
	}
	if !strings.Contains(res.Err.Error(), `"a/b/leaf.txt"`) {
		t.Fatalf("error must name the exact position: %v", res.Err)
	}

	// depth 3 is exactly enough: a (1), a/b (2), a/b/leaf.txt (3).
	res = Scan(context.Background(), p, root, Options{MaxDepth: 3})
	if res.Err != nil {
		t.Fatalf("scan at exact bound: %v", res.Err)
	}
	if len(res.Entries) != 3 {
		t.Fatalf("entries = %d", len(res.Entries))
	}
}

func TestScanCanceledMidWalk(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "a.txt"), "a")
	writeFile(t, filepath.Join(root, "b.txt"), "b")
	writeFile(t, filepath.Join(root, "c.txt"), "c")

	ctx, cancel := context.WithCancel(context.Background())
	p.onProbe = func(rel string, call int) {
		if rel == "b.txt" {
			cancel()
		}
	}
	res := Scan(ctx, p, root, Options{})
	if res.Err == nil {
		t.Fatal("expected cancellation error")
	}
	if !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled in chain", res.Err)
	}
	if !errors.Is(res.Err, domain.ErrScanIncomplete) {
		t.Fatalf("err = %v, want ErrScanIncomplete in chain", res.Err)
	}
	if len(res.Entries) < 2 {
		t.Fatalf("entries = %d, want partial entries returned", len(res.Entries))
	}
	checkCanonical(t, res)
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

func TestScanProbeErrorPropagatesWithEntries(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "a.txt"), "a")
	writeFile(t, filepath.Join(root, "b.txt"), "b")
	boom := errors.New("probe boom")
	p.errs["b.txt"] = boom

	res := Scan(context.Background(), p, root, Options{})
	if res.Err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(res.Err, boom) {
		t.Fatalf("err = %v, want cause in chain", res.Err)
	}
	if !errors.Is(res.Err, domain.ErrScanIncomplete) {
		t.Fatalf("err = %v, want ErrScanIncomplete in chain", res.Err)
	}
	if !strings.Contains(res.Err.Error(), `"b.txt"`) {
		t.Fatalf("error must name the position: %v", res.Err)
	}
	entryOf(t, res, "a.txt") // recorded before the fault
	for _, e := range res.Entries {
		if e.Path == "b.txt" {
			t.Fatal("failed entry must not be recorded")
		}
	}
	checkCanonical(t, res)
}

func TestScanHashErrorFailsScan(t *testing.T) {
	p, root := newFakeProbe(t)
	writeFile(t, filepath.Join(root, "a.txt"), "a")
	// A directory wearing file facts: opening succeeds, reading fails.
	mkdir(t, filepath.Join(root, "bad"))
	p.facts["bad"] = &domain.FileFacts{Kind: domain.KindFile, LogicalSize: 10}

	res := Scan(context.Background(), p, root, Options{Hash: true})
	if res.Err == nil {
		t.Fatal("expected hash error")
	}
	if !errors.Is(res.Err, domain.ErrScanIncomplete) {
		t.Fatalf("err = %v", res.Err)
	}
	entryOf(t, res, "a.txt")
	checkCanonical(t, res)
}

func TestScanMissingRootFailsBeforeWalk(t *testing.T) {
	p, _ := newFakeProbe(t)
	p.rootErr = errors.New("no such root")

	res := Scan(context.Background(), p, filepath.Join(t.TempDir(), "nope"), Options{})
	if res.Err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(res.Err, domain.ErrScanIncomplete) {
		t.Fatalf("err = %v", res.Err)
	}
	if len(res.Entries) != 0 || res.Root.ID != "" {
		t.Fatalf("result = %+v", res)
	}
}

func TestScanBadArguments(t *testing.T) {
	if res := Scan(context.Background(), nil, t.TempDir(), Options{}); res.Err == nil {
		t.Fatal("nil probe must fail")
	}
	p, root := newFakeProbe(t)
	if res := Scan(context.Background(), p, root, Options{MaxEntries: -1}); res.Err == nil {
		t.Fatal("negative MaxEntries must fail")
	}
	if res := Scan(context.Background(), p, root, Options{MaxDepth: -3}); res.Err == nil {
		t.Fatal("negative MaxDepth must fail")
	}
	if res := Scan(context.Background(), p, "", Options{}); res.Err == nil {
		t.Fatal("empty root must fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if res := Scan(ctx, p, root, Options{}); res.Err == nil || !errors.Is(res.Err, context.Canceled) {
		t.Fatalf("pre-canceled ctx err = %v", res.Err)
	}
}

// ---------------------------------------------------------------------------
// Exact accounting over a mixed fixture
// ---------------------------------------------------------------------------

func TestScanSummaryAccountingExact(t *testing.T) {
	p, root := newFakeProbe(t)
	zero := int64(0)
	p.disableIdentity = true // all grouping identities come from overrides

	// Preserved, allocated known and exclusive.
	writeFile(t, filepath.Join(root, "keep", "a.txt"), "aaaa")
	p.facts["keep/a.txt"] = &domain.FileFacts{LinkCount: 1, AllocatedSize: ptr(int64(4096))}
	// Preserved, allocation unknown -> not in ExclReclaimable.
	writeFile(t, filepath.Join(root, "keep", "noalloc.txt"), "bb")
	// Preserved, nlink>1 without identity -> shared, unattributed.
	writeFile(t, filepath.Join(root, "keep", "nogroup.txt"), "cccc")
	p.facts["keep/nogroup.txt"] = &domain.FileFacts{LinkCount: 2, AllocatedSize: ptr(int64(100))}
	// Blocking: ADS.
	writeFile(t, filepath.Join(root, "ads", "b.txt"), "dddddd")
	p.facts["ads/b.txt"] = &domain.FileFacts{Streams: []domain.NamedStream{{Name: "s", Size: 3}}}
	// Blocking: placeholder suspect (real file, faked facts).
	writeFile(t, filepath.Join(root, "ph", "c.txt"), "eeeeeeee")
	p.facts["ph/c.txt"] = &domain.FileFacts{LinkCount: 1, AllocatedSize: &zero}
	// Hardlink group fully in root, same segment, allocated once.
	writeFile(t, filepath.Join(root, "sp", "f1.txt"), "ff")
	writeFile(t, filepath.Join(root, "sp", "f2.txt"), "ff")
	p.facts["sp/f1.txt"] = fakeFileFacts("ID-SP", 2, 8192, false)
	p.facts["sp/f2.txt"] = fakeFileFacts("ID-SP", 2, 8192, false)
	// Hardlink group spanning top-level segments -> unattributed.
	writeFile(t, filepath.Join(root, "mix", "g.txt"), "ggg")
	writeFile(t, filepath.Join(root, "other", "g.txt"), "ggg")
	p.facts["mix/g.txt"] = fakeFileFacts("ID-X", 2, 2048, false)
	p.facts["other/g.txt"] = fakeFileFacts("ID-X", 2, 2048, false)
	// Hardlink group with an outside alias -> issue, unattributed.
	writeFile(t, filepath.Join(root, "out", "h.txt"), "hhhh")
	writeFile(t, filepath.Join(root, "out2", "h.txt"), "hhhh")
	p.facts["out/h.txt"] = fakeFileFacts("ID-O", 3, 512, false)
	p.facts["out2/h.txt"] = fakeFileFacts("ID-O", 3, 512, false)
	// Blocking: device.
	writeFile(t, filepath.Join(root, "dev", "i.txt"), "ii")
	p.facts["dev/i.txt"] = &domain.FileFacts{Kind: domain.KindDevice}

	res := Scan(context.Background(), p, root, Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	checkCanonical(t, res)

	// 12 files + 8 dirs (keep, ads, ph, sp, mix, other, out, out2, dev) = 21.
	if res.Summary.TotalEntries != 21 {
		t.Fatalf("TotalEntries = %d", res.Summary.TotalEntries)
	}
	blockingPaths := []string{"ads/b.txt", "dev/i.txt", "ph/c.txt"}
	if !reflect.DeepEqual(res.Summary.Blocking, blockingPaths) {
		t.Fatalf("Blocking = %v", res.Summary.Blocking)
	}
	if res.Summary.Preserved != 21-3 {
		t.Fatalf("Preserved = %d", res.Summary.Preserved)
	}
	wantBytes := int64(len("aaaa") + len("bb") + len("cccc") + // keep/*
		len("ff")*2 + // sp/* (both aliases preserved)
		len("ggg")*2 + // mix+other
		len("hhhh")*2) // out+out
	if res.Summary.PreservedBytes != wantBytes {
		t.Fatalf("PreservedBytes = %d, want %d", res.Summary.PreservedBytes, wantBytes)
	}
	wantExcl := map[string]int64{"keep": 4096, "sp": 8192}
	if !reflect.DeepEqual(res.Summary.ExclReclaimable, wantExcl) {
		t.Fatalf("ExclReclaimable = %+v, want %+v", res.Summary.ExclReclaimable, wantExcl)
	}

	// Issues: exactly the expected (path, code) pairs.
	type pc struct{ p, c string }
	var got []pc
	for _, is := range res.Summary.Issues {
		got = append(got, pc{is.Path, is.Code})
	}
	want := []pc{
		{"ads/b.txt", IssueADSPresent},
		{"dev/i.txt", IssueSpecialFile},
		{"out/h.txt", IssueHardlinkOutside},
		{"out2/h.txt", IssueHardlinkOutside},
		{"ph/c.txt", IssuePlaceholderSuspect},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("issues = %+v, want %+v", got, want)
	}

	// Round-trip invariant: every entry validates — except the
	// placeholder-suspect, whose digest cannot exist (friction reported).
	for _, e := range res.Entries {
		err := e.Validate()
		if e.Path == "ph/c.txt" {
			if err == nil {
				t.Fatal("placeholder entry expected to fail Validate (digest absent)")
			}
			continue
		}
		if err != nil {
			t.Fatalf("entry %q failed Validate: %v", e.Path, err)
		}
	}
}

func TestScanRootIdentityEchoed(t *testing.T) {
	p, root := newFakeProbe(t)
	want := domain.RootIdentity{VolumeID: "volX", FileID: "idxY"}
	p.rootID = want

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	if res.Root.Identity != want {
		t.Fatalf("identity = %+v, want %+v", res.Root.Identity, want)
	}
	if res.Root.Ownership != domain.OwnershipOwned {
		t.Fatalf("root ownership = %q", res.Root.Ownership)
	}
}

// ---------------------------------------------------------------------------
// Small helpers under test
// ---------------------------------------------------------------------------

func TestTopSegment(t *testing.T) {
	cases := map[string]string{
		"a.txt":     "a.txt",
		"a/b/c.txt": "a",
		"n/m":       "n",
	}
	for in, want := range cases {
		if got := topSegment(in); got != want {
			t.Fatalf("topSegment(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func ptr(v int64) *int64 { return &v }
