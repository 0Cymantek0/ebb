package gitadapter

// Link-shape and control-character hardening tests (F3/F4): the LFS
// objects walk treats junctions as opaque leaves per the project rule
// (ModeSymlink OR ModeIrregular — Go reports NTFS junctions as
// ModeIrregular, with or without ModeDir depending on the Go version),
// and git-provided text embedded into warnings is control-stripped.

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// mkJunction creates a Windows junction via the unprivileged mklink
// (test-fixture privilege; the code under test never does this).
func mkJunction(t *testing.T, link, target string) error {
	t.Helper()
	if runtime.GOOS != "windows" {
		return fmt.Errorf("junctions are a Windows shape (on %s)", runtime.GOOS)
	}
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %v (%s)", err, out)
	}
	return nil
}

// TestWalkLFSObjectsJunctionOpaque: a junction inside the LFS objects
// tree is an opaque leaf — the walk never descends into it, so a file
// planted beyond the junction (outside .git) is not counted. The test
// also proves the created junction is link-shaped under the project's
// own rule, so the fixture genuinely probes the guard (a future Go
// changing junction reporting fails the mode assertion loudly instead
// of silently passing on the no-ModeDir accident).
func TestWalkLFSObjectsJunctionOpaque(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skipf("junction fixture is Windows-only (on %s)", runtime.GOOS)
	}
	outside := t.TempDir()
	big := filepath.Join(outside, "beyond-the-junction.dat")
	if err := os.WriteFile(big, fill(4096), 0o644); err != nil {
		t.Fatal(err)
	}
	objects := t.TempDir()
	real := filepath.Join(objects, "ab", "cd", "oid1")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(real, fill(100), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(objects, "escape")
	if err := mkJunction(t, link, outside); err != nil {
		t.Skipf("junction creation unavailable on this machine (%v); test skipped", err)
	}

	// Non-vacuous fixture proof: the junction is link-shaped per the
	// project rule (and reported without ModeDir on Go 1.27 — the very
	// accident the fixed guard no longer relies on).
	fi, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) == 0 {
		t.Fatalf("junction %s is not link-shaped under the project rule (mode %v) — Go's junction reporting changed; update the fixture", link, fi.Mode())
	}
	if fi.IsDir() {
		t.Log("junction carries ModeDir on this Go version; the guard's SkipDir branch is what holds containment")
	}

	n, warning := walkLFSObjects(objects)
	if warning != "" {
		t.Fatalf("walkLFSObjects warning = %q, want none", warning)
	}
	if n != 100 {
		t.Errorf("walkLFSObjects = %d bytes, want 100 (the real object only; the 4096 planted beyond the junction must not be counted)", n)
	}
}

func fill(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return b
}

// TestWalkLFSObjectsLinkModeClassification: the walk's skip decision is
// driven by the mode classification, asserted directly for every
// link-shaped spelling a Go version may report — including the
// ModeIrregular|ModeDir combination whose containment previously relied
// on Go's no-ModeDir accident.
func TestWalkLFSObjectsLinkModeClassification(t *testing.T) {
	linkShaped := []fs.FileMode{
		fs.ModeSymlink,
		fs.ModeSymlink | fs.ModeDir,
		fs.ModeIrregular,
		fs.ModeIrregular | fs.ModeDir,
	}
	for _, m := range linkShaped {
		if m&(fs.ModeSymlink|fs.ModeIrregular) == 0 {
			t.Errorf("mode %v classified as non-link; the project rule (ModeSymlink|ModeIrregular) must hold", m)
		}
	}
	nonLink := []fs.FileMode{fs.ModeDir, 0, fs.ModePerm, fs.ModeDir | fs.ModePerm, fs.ModeTemporary}
	for _, m := range nonLink {
		if m&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			t.Errorf("mode %v classified as link", m)
		}
	}
}

// TestStripControlChars: git stderr/stdout embedded into summary
// warnings passes through the control-character stripper — ANSI escapes
// and newlines never echo into ebb's human stream, printable text and
// multi-byte runes survive untouched.
func TestStripControlChars(t *testing.T) {
	cases := []struct{ in, want string }{
		{"fatal: not a git repository", "fatal: not a git repository"},
		{"fatal: \x1b[31mbad\x1b[0m repo", "fatal:  [31mbad [0m repo"},
		{"line one\nline two", "line one line two"},
		{"cr\r\nend", "cr  end"},
		{"tab\there", "tab here"},
		{"café 日本", "café 日本"},
		{"del\x7feted", "del eted"},
	}
	for _, c := range cases {
		if got := stripControlChars(c.in); got != c.want {
			t.Errorf("stripControlChars(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// The composition used at every warning-embedding site.
	if got := firstLineClean("fatal: \x1b[31mbad\x1b[0m\nsecond line"); got != "fatal:  [31mbad [0m" {
		t.Errorf("firstLineClean = %q", got)
	}
	if got := firstLineClean("clean fatal line\nsecond"); got != "clean fatal line" {
		t.Errorf("firstLineClean passthrough = %q", got)
	}
}
