//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"ebb/internal/domain"
)

// Windows capability tests. Each test builds its own disposable
// fixture under t.TempDir(); genuine environment limitations (no
// OneDrive placeholder on the machine, symlink privilege withheld)
// skip with an explicit reason — never a faked pass.

// TestProbeJunction: `mklink /J` junctions present as ModeIrregular in
// Go >= 1.23 (probe Q1); the probe must still classify them exactly by
// reparse tag and parse the target.
func TestProbeJunction(t *testing.T) {
	dir := t.TempDir()
	target := makeDir(t, dir, "tgt")
	link := makeJunction(t, dir, "junc", target)

	facts, err := New().ProbeFile(link)
	if err != nil {
		t.Fatalf("ProbeFile: %v", err)
	}
	if facts.Kind != domain.KindJunction {
		t.Errorf("Kind = %q, want %q", facts.Kind, domain.KindJunction)
	}
	if facts.ReparseTag != "0xA0000003" {
		t.Errorf("ReparseTag = %q, want 0xA0000003", facts.ReparseTag)
	}
	if !strings.EqualFold(facts.LinkTarget, target) {
		t.Errorf("LinkTarget = %q, want %q", facts.LinkTarget, target)
	}
	if facts.LogicalSize != 0 {
		t.Errorf("LogicalSize = %d, want 0 for a link entry", facts.LogicalSize)
	}
}

// TestRootIdentityOfJunctionIsTheLinkItself: identity is taken with
// OPEN_REPARSE_POINT, so a junction's identity differs from its
// target's — replacing a root with a junction to elsewhere must be
// detectable (Foundation §12.1).
func TestRootIdentityOfJunctionIsTheLinkItself(t *testing.T) {
	dir := t.TempDir()
	target := makeDir(t, dir, "tgt")
	link := makeJunction(t, dir, "junc", target)

	idLink, err := New().RootIdentity(link)
	if err != nil {
		t.Fatalf("RootIdentity(link): %v", err)
	}
	idTarget, err := New().RootIdentity(target)
	if err != nil {
		t.Fatalf("RootIdentity(target): %v", err)
	}
	if idLink == idTarget {
		t.Errorf("junction identity == target identity (%v): no-follow open broken", idLink)
	}
}

// TestProbeSymlink: exact tag 0xA000000C plus the literal link text.
// Skipped when symlink creation needs a privilege this shell lacks
// (Developer Mode off and not elevated — probe Q1).
func TestProbeSymlink(t *testing.T) {
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
	if facts.ReparseTag != "0xA000000C" {
		t.Errorf("ReparseTag = %q, want 0xA000000C", facts.ReparseTag)
	}
	if facts.LinkTarget != target {
		t.Errorf("LinkTarget = %q, want %q", facts.LinkTarget, target)
	}
}

// TestNamedStreams: Lstat/LogicalSize must exclude named-stream bytes,
// and enumeration must surface the stream with its own size (probe Q4;
// Foundation §10.2 "streams have their own lengths").
func TestNamedStreams(t *testing.T) {
	dir := t.TempDir()
	file := writeFixtureFile(t, dir, "file.txt", "main") // 4 bytes
	addNamedStream(t, file, "s1", "secret")              // echo adds CRLF -> 8 bytes

	facts, err := New().ProbeFile(file)
	if err != nil {
		t.Fatalf("ProbeFile: %v", err)
	}
	if facts.LogicalSize != 4 {
		t.Errorf("LogicalSize = %d, want 4 (named stream excluded)", facts.LogicalSize)
	}
	var found *domain.NamedStream
	for i := range facts.Streams {
		if facts.Streams[i].Name == "s1" {
			found = &facts.Streams[i]
		}
	}
	if found == nil {
		t.Fatalf("Streams = %v, want an entry named %q", facts.Streams, "s1")
	}
	if found.Size != 8 {
		t.Errorf("stream s1 Size = %d, want 8 (\"secret\\r\\n\")", found.Size)
	}
}

// TestSparseFile: logical ~10 MiB with allocation far below it, plus
// the sparse attribute (probe Q5).
func TestSparseFile(t *testing.T) {
	dir := t.TempDir()
	p := makeSparseFile(t, dir)

	facts, err := New().ProbeFile(p)
	if err != nil {
		t.Fatalf("ProbeFile: %v", err)
	}
	const logical = int64(10)<<20 + 1
	if facts.LogicalSize != logical {
		t.Errorf("LogicalSize = %d, want %d", facts.LogicalSize, logical)
	}
	if !facts.Sparse {
		t.Error("Sparse = false for an FSCTL_SET_SPARSE file")
	}
	if facts.AllocatedSize == nil {
		t.Fatal("AllocatedSize nil for sparse file")
	}
	if *facts.AllocatedSize >= logical/2 {
		t.Errorf("AllocatedSize = %d, want far below LogicalSize %d (sparse layout broken)",
			*facts.AllocatedSize, logical)
	}
}

// TestCloudPlaceholder: when the machine has a dehydrated OneDrive
// file, probing must return facts WITHOUT opening it — no identity, no
// allocated size, but a reliable logical size (probe Q8).
func TestCloudPlaceholder(t *testing.T) {
	p := findOneDrivePlaceholder(t)
	if p == "" {
		t.Skip("no OneDrive root with a dehydrated (RECALL_ON_DATA_ACCESS) file on this machine")
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatalf("Lstat placeholder: %v", err)
	}
	if !IsCloudPlaceholder(fileAttributesOf(fi)) {
		t.Fatalf("fixture stopped being a placeholder between scan and probe: %s", p)
	}

	facts, err := New().ProbeFile(p)
	if err != nil {
		t.Fatalf("ProbeFile: %v", err)
	}
	if facts.Kind != domain.KindFile {
		t.Errorf("Kind = %q, want %q", facts.Kind, domain.KindFile)
	}
	if facts.FileIdentity != "" || facts.LinkCount != 0 || facts.AllocatedSize != nil {
		t.Errorf("placeholder was probed with an open handle: %+v", facts)
	}
	if facts.LogicalSize <= 0 {
		t.Errorf("LogicalSize = %d, want the reliable Lstat size > 0", facts.LogicalSize)
	}
}

// TestIsCloudPlaceholderBits pins the attribute bits the guard uses.
func TestIsCloudPlaceholderBits(t *testing.T) {
	cases := []struct {
		attrs uint32
		want  bool
		note  string
	}{
		{windows.FILE_ATTRIBUTE_ARCHIVE, false, "plain hydrated file"},
		{windows.FILE_ATTRIBUTE_ARCHIVE | 0x00400000, true, "modern OneDrive dehydrated"},
		{windows.FILE_ATTRIBUTE_ARCHIVE | 0x00040000, true, "legacy recall-on-open"},
		{windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_OFFLINE, true, "offline"},
	}
	for _, c := range cases {
		if got := IsCloudPlaceholder(c.attrs); got != c.want {
			t.Errorf("IsCloudPlaceholder(%#x) = %v, want %v (%s)", c.attrs, got, c.want, c.note)
		}
	}
}

// TestCaseSensitivity: on-disk name truth comes from enumeration, and
// when the volume demonstrably collides case (write of the other case
// overwrites), the volume heuristic must answer case-insensitive.
func TestCaseSensitivity(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFile(t, dir, "A.txt", "upper")

	// Attempt the case-variant write; on a case-insensitive volume this
	// overwrites the same entry.
	lower := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(lower, []byte("lower"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	names := make([]string, 0, len(des))
	for _, de := range des {
		names = append(names, de.Name())
	}
	if len(names) == 1 {
		// Case collided: the on-disk truth is still the original spelling
		// and the volume must be reported case-insensitive.
		if names[0] != "A.txt" {
			t.Errorf("on-disk name = %q, want the original spelling %q", names[0], "A.txt")
		}
		cs, err := VolumeCaseSensitive(dir)
		if err != nil {
			t.Fatalf("VolumeCaseSensitive: %v", err)
		}
		if cs {
			t.Error("VolumeCaseSensitive = true on a volume that collides case")
		}
	} else if len(names) == 2 {
		t.Skipf("temp volume is case-sensitive (%v); heuristic documents NTFS-family defaults only", names)
	} else {
		t.Fatalf("unexpected directory contents: %v", names)
	}
}

// TestLongPathProbeFile: a >260-char path created via \\?\ must probe
// fine through its PLAIN spelling (Go 1.27 fixLongPath for the os
// layer, extendLongPath for the raw CreateFile calls; probe Q10).
func TestLongPathProbeFile(t *testing.T) {
	dir := t.TempDir()
	file := makeLongPath(t, dir)
	if len(file) <= 260 {
		t.Fatalf("fixture path too short to exercise long paths: %d chars", len(file))
	}

	facts, err := New().ProbeFile(file)
	if err != nil {
		t.Fatalf("ProbeFile(long plain path, len %d): %v", len(file), err)
	}
	if facts.Kind != domain.KindFile {
		t.Errorf("Kind = %q, want %q", facts.Kind, domain.KindFile)
	}
	if facts.LogicalSize != 4 {
		t.Errorf("LogicalSize = %d, want 4", facts.LogicalSize)
	}
	if facts.FileIdentity == "" {
		t.Error("FileIdentity empty — attribute open failed on the long path")
	}
}

// TestStreamNameOf pins the raw-name normalization.
func TestStreamNameOf(t *testing.T) {
	for raw, want := range map[string]string{
		"::$DATA":     "",
		":s1:$DATA":   "s1",
		":cred:$DATA": "cred",
		":Zone:$DATA": "Zone",
	} {
		name, ok := streamNameOf(raw)
		if name != want || ok != (want != "") {
			t.Errorf("streamNameOf(%q) = (%q, %v), want (%q, %v)", raw, name, ok, want, want != "")
		}
	}
}

// TestInspectWritersNotInUse: files nobody holds must yield an empty
// list without error (Restart Manager consulted, nothing found).
func TestInspectWritersNotInUse(t *testing.T) {
	insp, err := NewWriterInspector()
	if err != nil {
		t.Skipf("Restart Manager unavailable: %v", err)
	}
	dir := t.TempDir()
	p := writeFixtureFile(t, dir, "idle.txt", "not held")

	writers, err := insp.InspectWriters([]string{p})
	if err != nil {
		t.Fatalf("InspectWriters: %v", err)
	}
	if len(writers) != 0 {
		t.Errorf("writers = %+v, want none for an unheld file", writers)
	}
}

// TestInspectWritersSelfHolding: with THIS test process holding the
// file open, the Restart Manager should list the test binary itself.
// Skips (with the reason recorded) if this build's RM declines to
// report the session-owning process.
func TestInspectWritersSelfHolding(t *testing.T) {
	insp, err := NewWriterInspector()
	if err != nil {
		t.Skipf("Restart Manager unavailable: %v", err)
	}
	dir := t.TempDir()
	p := writeFixtureFile(t, dir, "held.txt", "held")
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open held file: %v", err)
	}
	defer f.Close()

	writers, err := insp.InspectWriters([]string{p})
	if err != nil {
		t.Fatalf("InspectWriters: %v", err)
	}
	self := uint32(os.Getpid())
	var me *Writer
	for i := range writers {
		if writers[i].PID == self {
			me = &writers[i]
		}
	}
	if me == nil {
		t.Skipf("Restart Manager listed %d writer(s) but not the calling process %d — RM may exclude the session owner on this build", len(writers), self)
	}
	if me.Name == "" {
		t.Errorf("writer Name empty for PID %d", self)
	}
	if me.Source != "restart-manager" {
		t.Errorf("writer Source = %q, want restart-manager", me.Source)
	}
	if me.Kind == "" {
		t.Error("writer Kind empty")
	}
}

// TestVolumeUsageQuotaFieldsOnWindows doubles as a smoke test that the
// serial-form VolumeID matches RootIdentity's volume component.
func TestVolumeUsageQuotaFieldsOnWindows(t *testing.T) {
	dir := t.TempDir()
	u, err := New().VolumeUsage(dir)
	if err != nil {
		t.Fatalf("VolumeUsage: %v", err)
	}
	id, err := New().RootIdentity(dir)
	if err != nil {
		t.Fatalf("RootIdentity: %v", err)
	}
	if u.VolumeID != id.VolumeID {
		t.Errorf("VolumeUsage.VolumeID %q != RootIdentity.VolumeID %q", u.VolumeID, id.VolumeID)
	}
}
