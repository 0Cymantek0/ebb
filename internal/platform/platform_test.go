package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"ebb/internal/domain"
)

// Cross-platform contract tests. Windows-specific capability tests
// (junctions, streams, sparse, case heuristic, placeholders, long
// paths, Restart Manager) live in platform_windows_test.go.

// TestNewReturnsProbe checks the constructor wires the native probe
// behind the frozen domain seam.
func TestNewReturnsProbe(t *testing.T) {
	var p domain.PlatformProbe = New()
	if p == nil {
		t.Fatal("New() returned nil")
	}
}

// TestProbeFileRegularFile verifies the ordinary-file facts every
// platform must produce.
func TestProbeFileRegularFile(t *testing.T) {
	dir := t.TempDir()
	p := writeFixtureFile(t, dir, "file.txt", "hello world")

	facts, err := New().ProbeFile(p)
	if err != nil {
		t.Fatalf("ProbeFile: %v", err)
	}
	if facts.Kind != domain.KindFile {
		t.Errorf("Kind = %q, want %q", facts.Kind, domain.KindFile)
	}
	if facts.LogicalSize != int64(len("hello world")) {
		t.Errorf("LogicalSize = %d, want %d", facts.LogicalSize, len("hello world"))
	}
	if facts.LinkTarget != "" {
		t.Errorf("LinkTarget = %q, want empty for a regular file", facts.LinkTarget)
	}
	if facts.Sparse {
		t.Error("Sparse = true for a freshly written file")
	}
	if len(facts.Streams) != 0 {
		t.Errorf("Streams = %v, want none for a fresh file", facts.Streams)
	}
	if facts.FileIdentity == "" {
		t.Error("FileIdentity empty — identity is observable on this platform")
	}
	if facts.AllocatedSize == nil {
		t.Error("AllocatedSize nil — allocation is observable on this platform")
	} else if *facts.AllocatedSize < 0 {
		t.Errorf("AllocatedSize = %d, negative", *facts.AllocatedSize)
	}
}

// TestProbeFileDir verifies directory classification without descent.
func TestProbeFileDir(t *testing.T) {
	dir := t.TempDir()
	sub := makeDir(t, dir, "sub")

	facts, err := New().ProbeFile(sub)
	if err != nil {
		t.Fatalf("ProbeFile: %v", err)
	}
	if facts.Kind != domain.KindDir {
		t.Errorf("Kind = %q, want %q", facts.Kind, domain.KindDir)
	}
	if facts.LogicalSize != 0 {
		t.Errorf("LogicalSize = %d, want 0 for a directory", facts.LogicalSize)
	}
}

// TestProbeFileSymlink checks no-follow classification and the literal
// link text (skipped where symlink creation is privileged).
func TestProbeFileSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeFixtureFile(t, dir, "target.txt", "t")
	link := makeSymlink(t, dir, "link.txt", target)

	facts, err := New().ProbeFile(link)
	if err != nil {
		t.Fatalf("ProbeFile: %v", err)
	}
	if facts.Kind != domain.KindSymlink {
		t.Errorf("Kind = %q, want %q", facts.Kind, domain.KindSymlink)
	}
	if facts.LinkTarget != target {
		t.Errorf("LinkTarget = %q, want %q", facts.LinkTarget, target)
	}
}

// TestProbeFileMissingPath checks the error path.
func TestProbeFileMissingPath(t *testing.T) {
	_, err := New().ProbeFile(filepath.Join(t.TempDir(), "nope.txt"))
	if err == nil {
		t.Fatal("ProbeFile on a missing path returned nil error")
	}
	if !os.IsNotExist(err) {
		t.Errorf("error = %v, want a not-exist class", err)
	}
}

// TestHardlinkPairIdentity is the hardlink-grouping foundation: both
// names must report the same identity and LinkCount 2 (Foundation
// §10.2, probe Q2).
func TestHardlinkPairIdentity(t *testing.T) {
	dir := t.TempDir()
	a, b := makeHardlinkPair(t, dir)
	probe := New()

	fa, err := probe.ProbeFile(a)
	if err != nil {
		t.Fatalf("ProbeFile(a): %v", err)
	}
	fb, err := probe.ProbeFile(b)
	if err != nil {
		t.Fatalf("ProbeFile(b): %v", err)
	}
	if fa.FileIdentity == "" {
		t.Fatal("FileIdentity empty on hardlink a")
	}
	if fa.FileIdentity != fb.FileIdentity {
		t.Errorf("hardlink pair identities differ: %q vs %q", fa.FileIdentity, fb.FileIdentity)
	}
	if fa.LinkCount != 2 || fb.LinkCount != 2 {
		t.Errorf("LinkCount = (%d, %d), want (2, 2)", fa.LinkCount, fb.LinkCount)
	}

	ia, err := probe.RootIdentity(a)
	if err != nil {
		t.Fatalf("RootIdentity(a): %v", err)
	}
	ib, err := probe.RootIdentity(b)
	if err != nil {
		t.Fatalf("RootIdentity(b): %v", err)
	}
	if ia != ib {
		t.Errorf("RootIdentity differs across hardlink pair: %v vs %v", ia, ib)
	}
}

// TestRootIdentityStableAcrossRename is the quarantine-revalidation
// foundation: identity must survive rename of files and directories
// (Foundation §12.2, probe Q2). On Windows this also exercises the
// FileIdInfo alignment rule — errno 998 here would fail this test.
func TestRootIdentityStableAcrossRename(t *testing.T) {
	dir := t.TempDir()
	probe := New()

	file := writeFixtureFile(t, dir, "before.txt", "rename me")
	before, err := probe.RootIdentity(file)
	if err != nil {
		t.Fatalf("RootIdentity(before): %v", err)
	}
	renamed := filepath.Join(dir, "after.txt")
	if err := os.Rename(file, renamed); err != nil {
		t.Fatalf("rename file: %v", err)
	}
	after, err := probe.RootIdentity(renamed)
	if err != nil {
		t.Fatalf("RootIdentity(after): %v", err)
	}
	if before != after {
		t.Errorf("file identity changed across rename: %v -> %v", before, after)
	}

	d1 := makeDir(t, dir, "d1")
	dbefore, err := probe.RootIdentity(d1)
	if err != nil {
		t.Fatalf("RootIdentity(dir): %v", err)
	}
	d2 := filepath.Join(dir, "d2")
	if err := os.Rename(d1, d2); err != nil {
		t.Fatalf("rename dir: %v", err)
	}
	dafter, err := probe.RootIdentity(d2)
	if err != nil {
		t.Fatalf("RootIdentity(dir after): %v", err)
	}
	if dbefore != dafter {
		t.Errorf("dir identity changed across rename: %v -> %v", dbefore, dafter)
	}
}

// TestDistinctFilesHaveDistinctIdentity guards against identity
// collapsing to something path-derived.
func TestDistinctFilesHaveDistinctIdentity(t *testing.T) {
	dir := t.TempDir()
	probe := New()
	a := writeFixtureFile(t, dir, "a.txt", "one")
	b := writeFixtureFile(t, dir, "b.txt", "two")

	ia, err := probe.RootIdentity(a)
	if err != nil {
		t.Fatalf("RootIdentity(a): %v", err)
	}
	ib, err := probe.RootIdentity(b)
	if err != nil {
		t.Fatalf("RootIdentity(b): %v", err)
	}
	if ia == ib {
		t.Errorf("distinct files share identity %v", ia)
	}
}

// TestVolumeUsage checks the accounting inputs are populated and
// self-consistent (quota-aware free never exceeds total; probe Q6).
func TestVolumeUsage(t *testing.T) {
	u, err := New().VolumeUsage(t.TempDir())
	if err != nil {
		t.Fatalf("VolumeUsage: %v", err)
	}
	if u.Total <= 0 {
		t.Errorf("Total = %d, want > 0", u.Total)
	}
	if u.FreeToCaller <= 0 {
		t.Errorf("FreeToCaller = %d, want > 0", u.FreeToCaller)
	}
	if u.VolumeFree < 0 {
		t.Errorf("VolumeFree = %d, negative", u.VolumeFree)
	}
	if u.FreeToCaller > u.Total {
		t.Errorf("FreeToCaller %d > Total %d", u.FreeToCaller, u.Total)
	}
	if u.VolumeID == "" {
		t.Error("VolumeID empty")
	}
}

// TestNewWriterInspectorContract checks the capability fact per OS:
// a real inspector on Windows, ErrUnsupported elsewhere.
func TestNewWriterInspectorContract(t *testing.T) {
	insp, err := NewWriterInspector()
	switch runtime.GOOS {
	case "windows":
		if err != nil {
			t.Fatalf("NewWriterInspector: %v", err)
		}
		if insp == nil {
			t.Fatal("NewWriterInspector returned nil inspector with nil error")
		}
	default:
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("NewWriterInspector error = %v, want ErrUnsupported", err)
		}
	}
}
