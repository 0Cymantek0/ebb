package resticstore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ebb/internal/domain"
)

func TestValidateRelPaths(t *testing.T) {
	ok := func(t *testing.T, in, want []string) {
		t.Helper()
		got, err := ValidateRelPaths(in)
		if err != nil {
			t.Fatalf("ValidateRelPaths(%q) unexpected error: %v", in, err)
		}
		if len(got) != len(want) {
			t.Fatalf("got %q want %q", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("got %q want %q", got, want)
			}
		}
	}
	bad := func(t *testing.T, in []string, wantClass domain.StoreErrorClass, note string) {
		t.Helper()
		_, err := ValidateRelPaths(in)
		if err == nil {
			t.Fatalf("%s: expected error for %q", note, in)
		}
		var se *domain.StoreError
		if !errors.As(err, &se) {
			t.Fatalf("%s: error is not *domain.StoreError: %v", note, err)
		}
		if se.Class != wantClass {
			t.Fatalf("%s: class %q want %q (%v)", note, se.Class, wantClass, err)
		}
	}

	ok(t, []string{"ws", "opd"}, []string{"ws", "opd"})
	ok(t, []string{"ws/a.txt", "opd/manifest.json"}, []string{"ws/a.txt", "opd/manifest.json"})
	ok(t, []string{"./opd/manifest.json"}, []string{"opd/manifest.json"}) // D003 ./ form
	ok(t, []string{"ws/notes spaces ünïcode ☃.txt"}, []string{"ws/notes spaces ünïcode ☃.txt"})

	bad(t, nil, domain.StoreErrUsage, "empty list")
	bad(t, []string{""}, domain.StoreErrUsage, "empty entry")
	bad(t, []string{"ws/a.txt", `C:\elsewhere\a.txt`}, domain.StoreErrUsage, "mixed abs backslash")
	bad(t, []string{"ws/a.txt", "C:/elsewhere/a.txt"}, domain.StoreErrUsage, "mixed abs forward")
	bad(t, []string{"/ws/a.txt"}, domain.StoreErrUsage, "leading slash")
	bad(t, []string{`\\server\share\a`}, domain.StoreErrUsage, "UNC")
	bad(t, []string{`\\?\C:\x`}, domain.StoreErrUsage, "device prefix")
	bad(t, []string{`ws\sub\a.txt`}, domain.StoreErrUsage, "backslash separator")
	bad(t, []string{"ws/../opd/a"}, domain.StoreErrUsage, "dotdot escape")
	bad(t, []string{"ws//a.txt"}, domain.StoreErrUsage, "empty segment")
	bad(t, []string{"ws/a\x00b"}, domain.StoreErrUsage, "NUL inside entry")
	bad(t, []string{"ws/a.txt", "ws/a.txt"}, domain.StoreErrUsage, "duplicate")
}

func TestWriteListFileTrailingNUL(t *testing.T) {
	dir := t.TempDir()
	rel := []string{"ws/a.txt", "ws/notes spaces ünïcode ☃.txt", "opd"}
	f, err := writeListFile(dir, rel)
	if err != nil {
		t.Fatalf("writeListFile: %v", err)
	}
	raw, err := os.ReadFile(f)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	want := "ws/a.txt\x00ws/notes spaces ünïcode ☃.txt\x00opd\x00"
	if string(raw) != want {
		t.Fatalf("list bytes = %q want %q", raw, want)
	}
	if !strings.HasSuffix(string(raw), "\x00") {
		t.Fatal("trailing NUL missing")
	}
	// Newline must never appear: it is not a separator for restic.
	if strings.Contains(string(raw), "\n") {
		t.Fatal("newline leaked into raw list")
	}
	// Round-trip: splitting on NUL minus trailing empty reproduces entries.
	parts := strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	if len(parts) != len(rel) {
		t.Fatalf("round trip got %d parts want %d", len(parts), len(rel))
	}
}

func TestParseLsKindMapping(t *testing.T) {
	ndjson := `{"time":"...","tree":"...","hostname":"ebb","id":"abc","short_id":"abc","message_type":"snapshot","struct_type":"snapshot"}` + "\n" +
		`{"message_type":"node","struct_type":"node","name":"a.txt","type":"file","path":"/ws/a.txt","size":14,"mode":438,"permissions":"-rw-rw-rw-","mtime":"2026-09-18T11:50:33.9148095+05:30"}` + "\n" +
		`{"message_type":"node","struct_type":"node","name":"ws","type":"dir","path":"/ws","mode":2147484159,"permissions":"drwxrwxrwx","mtime":"..."}` + "\n" +
		`{"message_type":"node","struct_type":"node","name":"junction-out","type":"symlink","path":"/ws/junction-out","mode":134218166,"permissions":"Lrw-rw-rw-","mtime":"..."}` + "\n" +
		`{"message_type":"node","struct_type":"node","name":"p","type":"fifo","path":"/ws/p","mtime":"..."}` + "\n" +
		`{"message_type":"node","struct_type":"node","name":"s","type":"socket","path":"/ws/s","mtime":"..."}` + "\n" +
		`{"message_type":"node","struct_type":"node","name":"d","type":"dev","path":"/ws/d","mtime":"..."}` + "\n" +
		`{"message_type":"node","struct_type":"node","name":"weird","type":"irregular","path":"/ws/weird","mtime":"..."}` + "\n"
	entries, err := parseLs([]byte(ndjson))
	if err != nil {
		t.Fatalf("parseLs: %v", err)
	}
	byPath := map[string]domain.TreeEntry{}
	for _, e := range entries {
		byPath[e.Path] = e
	}
	if len(entries) != 7 {
		t.Fatalf("got %d entries want 7 (header skipped)", len(entries))
	}
	cases := []struct {
		path string
		kind domain.EntryKind
		mode string
	}{
		{"/ws/a.txt", domain.KindFile, "-rw-rw-rw-"},
		{"/ws", domain.KindDir, "drwxrwxrwx"},
		{"/ws/junction-out", domain.KindSymlink, "Lrw-rw-rw-"},
		{"/ws/p", domain.KindFIFO, ""},
		{"/ws/s", domain.KindSocket, ""},
		{"/ws/d", domain.KindDevice, ""},
		{"/ws/weird", domain.KindOtherReparse, "type:irregular"},
	}
	for _, c := range cases {
		e, ok := byPath[c.path]
		if !ok {
			t.Fatalf("missing entry %s", c.path)
		}
		if e.Kind != c.kind {
			t.Errorf("%s kind = %q want %q", c.path, e.Kind, c.kind)
		}
		if c.mode != "" && e.Mode != c.mode {
			t.Errorf("%s mode = %q want %q", c.path, e.Mode, c.mode)
		}
	}
	if byPath["/ws/a.txt"].Size != 14 {
		t.Errorf("file size = %d want 14", byPath["/ws/a.txt"].Size)
	}
	// restic 0.19.1 exposes no linktarget in ls --json.
	if byPath["/ws/junction-out"].LinkTarget != "" {
		t.Errorf("unexpected link target %q", byPath["/ws/junction-out"].LinkTarget)
	}
}

func TestParseSnapshotsEmptyAndTags(t *testing.T) {
	refs, err := parseSnapshots([]byte("[]\n"))
	if err != nil {
		t.Fatalf("empty repo parse: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("empty repo gave %d refs", len(refs))
	}
	one := `[{"id":"dcacecd7f1d0b287a084cb32009a2a13eeaa75b5cb391b1ff06772cc94a7cf45","short_id":"dcacecd7","time":"2026-09-18T13:13:49.0697397+05:30","paths":["C:\\x\\ws"],"tags":["ebb:v1","op:exact"]}]`
	refs, err = parseSnapshots([]byte(one))
	if err != nil {
		t.Fatalf("one snapshot parse: %v", err)
	}
	if len(refs) != 1 || refs[0].BackendID != "dcacecd7f1d0b287a084cb32009a2a13eeaa75b5cb391b1ff06772cc94a7cf45" {
		t.Fatalf("refs = %+v", refs)
	}
	if refs[0].Tags["ebb"] != "v1" || refs[0].Tags["op"] != "exact" {
		t.Fatalf("tags = %+v", refs[0].Tags)
	}
}

func TestParseRepoID(t *testing.T) {
	id, err := parseRepoID([]byte("{\n  \"version\": 2,\n  \"id\": \"b0e21037b8f931ce6d4a6a652a3d935db8b1204870aa7b22a3c9043fcbef2e7a\",\n  \"chunker_polynomial\": \"394f73319f26ab\"\n}\n"))
	if err != nil {
		t.Fatalf("parseRepoID: %v", err)
	}
	if !isHexID(id, 64) {
		t.Fatalf("id = %q", id)
	}
	if _, err := parseRepoID([]byte("garbage")); err == nil {
		t.Fatal("expected error for garbage config")
	}
}

func TestEncodeTagsDeterministic(t *testing.T) {
	args, m, err := encodeTags(map[string]string{"zz": "1", "aa": "2"})
	if err != nil {
		t.Fatalf("encodeTags: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "--tag ebb:v1 --tag ") {
		t.Fatalf("base tag must come first: %q", joined)
	}
	if strings.Index(joined, "aa:2") > strings.Index(joined, "zz:1") {
		t.Fatalf("keys must be sorted: %q", joined)
	}
	if m["ebb"] != "v1" || m["aa"] != "2" || m["zz"] != "1" {
		t.Fatalf("decoded map = %v", m)
	}
	if _, _, err := encodeTags(map[string]string{"bad key": "x"}); err == nil {
		t.Fatal("expected error for tag key with space")
	}
	if _, _, err := encodeTags(map[string]string{"k": "with space"}); err == nil {
		t.Fatal("expected error for tag value with space")
	}
}

func TestScanStderrMixedForms(t *testing.T) {
	// Mixed plain-text warning + NDJSON error/exit_error records, as
	// restic emits on a denied source (probe Q4a). The decoded message
	// is: open \\?\C:\x\secret.txt: Access is denied.
	stderr := []byte("C:\\x\\nope.txt does not exist, skipping\n" +
		`{"message_type":"error","error":{"message":"open \\\\?\\C:\\x\\secret.txt: Access is denied."},"during":"archival","item":"C:\\x\\secret.txt"}` + "\n" +
		`{"message_type":"exit_error","code":3,"message":"Warning: at least one source file could not be read"}` + "\n")
	sc := scanStderr(stderr)
	if len(sc.errRecords) != 1 || !strings.Contains(sc.errRecords[0], "Access is denied") {
		t.Fatalf("errRecords = %v", sc.errRecords)
	}
	if sc.exitCode != 3 {
		t.Fatalf("exitCode = %d want 3", sc.exitCode)
	}
	if classForFailure(0, stderr) != domain.StoreErrSource {
		t.Fatal("exit_error code 3 must classify as source even when process exit was 0")
	}
	if classForFailure(12, []byte(`{"message_type":"exit_error","code":12,"message":"..."}`)) != domain.StoreErrAuth {
		t.Fatal("code 12 must be auth")
	}
}

func TestExcerptBoundsToLimit(t *testing.T) {
	big := strings.Repeat("x", stderrExcerptLimit+100)
	got := excerpt([]byte(big), stderrExcerptLimit)
	if len(got) > stderrExcerptLimit+64 { // marker allowance
		t.Fatalf("excerpt too long: %d", len(got))
	}
	if !strings.HasPrefix(got, "…[truncated]") {
		t.Fatalf("missing truncation marker")
	}
}

func TestNormalizeDumpPath(t *testing.T) {
	if p, err := normalizeDumpPath("ws/a.txt"); err != nil || p != "/ws/a.txt" {
		t.Fatalf("got %q %v", p, err)
	}
	if p, err := normalizeDumpPath("/ws/a.txt"); err != nil || p != "/ws/a.txt" {
		t.Fatalf("got %q %v", p, err)
	}
	if _, err := normalizeDumpPath(`ws\a.txt`); err == nil {
		t.Fatal("backslash must be rejected")
	}
	if _, err := normalizeDumpPath("/ws/../x"); err == nil {
		t.Fatal("dotdot must be rejected")
	}
}

func TestIsSnapshotID(t *testing.T) {
	if !isSnapshotID("dcacecd7") || !isSnapshotID(strings.Repeat("a", 64)) {
		t.Fatal("valid ids rejected")
	}
	for _, bad := range []string{"", "short", "DCACECD7", strings.Repeat("g", 64), "z"} {
		if isSnapshotID(bad) {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// ---- New binary resolution (W2-7) ---------------------------------------
//
// The doc contract says "" and bare names resolve through PATH. The old
// implementation called filepath.Abs directly, so a bare name silently
// selected <cwd>\restic — the cwd-hijack trap. These tests pin the
// closed trap: the PATH copy wins over a decoy in the working directory,
// absolute paths pass through unchanged, and a bare name PATH cannot
// resolve surfaces as a typed error at command time (never a cwd copy).

// fakeBinSuffix is the executable suffix LookPath needs on this GOOS.
func fakeBinSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// chdirTest changes the working directory for the rest of the test and
// restores it (LIFO) before the temp dirs are removed.
func chdirTest(t *testing.T, dir string) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Errorf("restore working dir: %v", err)
		}
	})
}

func TestNewBareNameResolvesThroughPATHNotCWD(t *testing.T) {
	name := "ebb-fake-restic-probe"
	// Windows quirk: exec.LookPath consults the CURRENT directory before
	// PATH unless NoDefaultCurrentDirectoryInExePath is set — pin it off
	// so the PATH copy is the only legal answer the resolver may pick.
	t.Setenv("NoDefaultCurrentDirectoryInExePath", "1")
	// The PATH copy.
	pathDir := t.TempDir()
	pathCopy := filepath.Join(pathDir, name+fakeBinSuffix())
	if err := os.WriteFile(pathCopy, []byte("path copy\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// The decoy in the working directory: the pre-fix behavior
	// (filepath.Abs of the bare name) would have selected exactly this.
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, name+fakeBinSuffix()), []byte("decoy\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	chdirTest(t, cwd)

	s := New(name)
	t.Cleanup(s.Close)
	if s.binary != pathCopy {
		t.Fatalf("New(%q) resolved %q; want the PATH copy %q (the cwd decoy must lose)", name, s.binary, pathCopy)
	}
}

func TestNewEmptyNameBehavesLikeBareRestic(t *testing.T) {
	want, err := exec.LookPath("restic")
	if err != nil {
		t.Skipf("restic not on PATH: %v", err)
	}
	s := New("")
	t.Cleanup(s.Close)
	if s.binary != want {
		t.Fatalf("New(\"\") resolved %q; want the PATH restic %q", s.binary, want)
	}
}

func TestNewAbsolutePathUnchanged(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "some-restic"+fakeBinSuffix())
	if err := os.WriteFile(bin, []byte("x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := New(bin)
	t.Cleanup(s.Close)
	if s.binary != bin {
		t.Fatalf("New(absolute) = %q; want %q unchanged", s.binary, bin)
	}
}

func TestNewUnresolvableBareNameFailsTypedAtCommandTime(t *testing.T) {
	s := New("ebb-no-such-restic-binary")
	t.Cleanup(s.Close)
	if filepath.IsAbs(s.binary) {
		t.Fatalf("an unresolvable bare name must stay bare (got %q) — absolutizing it would select a cwd copy", s.binary)
	}
	// The honest failure surface: the first command reports a typed
	// StoreError, not a cwd-hijacked subprocess run.
	_, err := s.RepoID(context.Background(), "whatever-repo", "whatever-passfile")
	var se *domain.StoreError
	if !errors.As(err, &se) {
		t.Fatalf("RepoID error is not *domain.StoreError: %v", err)
	}
	if !strings.Contains(err.Error(), "executable") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("error does not name the missing binary: %v", err)
	}
}
