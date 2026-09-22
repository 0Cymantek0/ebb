//go:build windows

package platform

// Link-creation tests (Wave F). The load-bearing assertion is that
// CreateJunction works UNPRIVILEGED on this machine — the exact
// capability the unprivileged-open acceptance gap needed — and that the
// created object round-trips through BOTH observation routes the system
// relies on: os.Readlink (the oracle probe's text source) and this
// package's own probe classification (capture's LinkTarget source).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// assertJunctionRoundTrip asserts path is a junction whose literal link
// text equals wantText on both observation routes.
func assertJunctionRoundTrip(t *testing.T, path, wantText string) {
	t.Helper()
	got, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("Readlink(%s): %v", path, err)
	}
	if got != wantText {
		t.Fatalf("os.Readlink round trip = %q, want exactly %q", got, wantText)
	}
	facts, err := newNativeProbe().ProbeFile(path)
	if err != nil {
		t.Fatalf("probe classify(%s): %v", path, err)
	}
	if facts.Kind != domain.KindJunction {
		t.Fatalf("probe kind = %q, want junction (facts %+v)", facts.Kind, facts)
	}
	if facts.LinkTarget != wantText {
		t.Fatalf("probe LinkTarget = %q, want exactly %q", facts.LinkTarget, wantText)
	}
}

// TestCreateJunctionUnprivileged is THE capability pin: creating a
// junction via FSCTL_SET_REPARSE_POINT must succeed without elevation
// (the test process is the ordinary unprivileged dev shell), and the
// result must be byte-indistinguishable from a mklink /J junction as
// far as the system's two observation routes see it.
func TestCreateJunctionUnprivileged(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "junction-target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "inside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "jl")
	if err := CreateJunction(link, target); err != nil {
		t.Fatalf("CreateJunction must work unprivileged: %v", err)
	}
	assertJunctionRoundTrip(t, link, target)

	// The junction resolves like a directory (the object class works,
	// not just the metadata).
	if _, err := os.ReadDir(link); err != nil {
		t.Fatalf("junction must resolve as a directory: %v", err)
	}
	// A mklink /J junction created next to it reads back IDENTICALLY.
	peer := makeJunction(t, dir, "mklink-peer", target)
	if a, b := mustReadlink(t, link), mustReadlink(t, peer); a != b {
		t.Fatalf("CreateJunction text %q differs from mklink /J text %q", a, b)
	}
}

// TestCreateJunctionNestedAndMissingTarget covers a junction below the
// tree root (the restore staging shape) and a target that does not
// exist (junctions may dangle; capture must never have required the
// target, restore must not either).
func TestCreateJunctionNestedAndMissingTarget(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "deep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "gone") // deliberately absent
	link := filepath.Join(nested, "jl")
	if err := CreateJunction(link, target); err != nil {
		t.Fatalf("CreateJunction to an absent target: %v", err)
	}
	assertJunctionRoundTrip(t, link, target)
}

// TestCreateJunctionRejectsRelativeTarget: junction substitute names are
// absolute by definition; a retained relative text is a data error and
// must be refused, not guessed at.
func TestCreateJunctionRejectsRelativeTarget(t *testing.T) {
	dir := t.TempDir()
	err := CreateJunction(filepath.Join(dir, "jl"), "relative/target")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v, want a refusal naming the absolute-target requirement", err)
	}
	if _, serr := os.Lstat(filepath.Join(dir, "jl")); !os.IsNotExist(serr) {
		t.Fatalf("a refused junction must leave no directory behind (%v)", serr)
	}
}

// TestCreateSymlinkRoundTripOrPrivilege pins both real outcomes of true
// symlink creation on this machine: success (privileged env) with exact
// text round-trip, or the typed privilege refusal (unprivileged env).
func TestCreateSymlinkRoundTripOrPrivilege(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "sym-target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sl")
	err := CreateSymlink(link, target)
	if err == nil {
		got, rerr := os.Readlink(link)
		if rerr != nil || got != target {
			t.Fatalf("symlink text = %q (%v), want exactly %q", got, rerr, target)
		}
		facts, perr := newNativeProbe().ProbeFile(link)
		if perr != nil || facts.Kind != domain.KindSymlink || facts.LinkTarget != target {
			t.Fatalf("probe facts = %+v (%v), want symlink with the exact target", facts, perr)
		}
		return
	}
	var perr *LinkPrivilegeError
	if !errors.As(err, &perr) {
		t.Fatalf("unprivileged symlink failure must be the typed privilege error, got %v", err)
	}
	if !perr.LinkPrivilegeBlocked() {
		t.Fatal("LinkPrivilegeBlocked() must report true")
	}
	if !strings.Contains(err.Error(), "SeCreateSymbolicLinkPrivilege") {
		t.Fatalf("error must name the capability: %v", err)
	}
	if _, serr := os.Lstat(link); !os.IsNotExist(serr) {
		t.Fatalf("a refused symlink must leave nothing behind (%v)", serr)
	}
}

// TestCreateLinkDispatch routes inventory kinds to the right creator and
// refuses non-link kinds.
func TestCreateLinkDispatch(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "tgt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	jl := filepath.Join(dir, "j")
	if err := CreateLink(domain.KindJunction, jl, target); err != nil {
		t.Fatalf("CreateLink(junction): %v", err)
	}
	assertJunctionRoundTrip(t, jl, target)
	if err := CreateLink(domain.KindDir, filepath.Join(dir, "x"), target); err == nil ||
		!strings.Contains(err.Error(), "unsupported link kind") {
		t.Fatalf("err = %v, want unsupported-kind refusal", err)
	}
}

// TestJunctionNames covers the substitute/print mapping as a pure
// function, including the volume-mount-point and UNC spellings that
// cannot be exercised live in tests.
func TestJunctionNames(t *testing.T) {
	cases := []struct {
		target     string
		substitute string
	}{
		{`C:\work`, `\??\C:\work`},
		{`\\server\share\dir`, `\??\UNC\server\share\dir`},
		{`Volume{4a1f0e8e-...}\`, `\??\Volume{4a1f0e8e-...}\`},
		{`\\?\Volume{4a1f0e8e-...}\`, `\??\Volume{4a1f0e8e-...}\`},
	}
	for _, tc := range cases {
		sub, print, err := junctionNames(tc.target)
		if err != nil {
			t.Fatalf("junctionNames(%q): %v", tc.target, err)
		}
		if sub != tc.substitute {
			t.Errorf("junctionNames(%q) substitute = %q, want %q", tc.target, sub, tc.substitute)
		}
		if print != tc.target {
			t.Errorf("junctionNames(%q) print = %q, want the target verbatim", tc.target, print)
		}
	}
	for _, bad := range []string{"", "relative", "also/relative"} {
		if _, _, err := junctionNames(bad); err == nil {
			t.Errorf("junctionNames(%q) must be refused", bad)
		}
	}
}

// TestMountPointReparseBufferLayout pins the buffer arithmetic against
// the fsutil-verified layout of a live mklink /J junction (substitute
// 132 bytes, print 124 bytes → ReparseDataLength 0x10c, print offset
// 134).
func TestMountPointReparseBufferLayout(t *testing.T) {
	sub := `\??\` + strings.Repeat("a", 62)
	print := strings.Repeat("b", 62)
	buf, err := mountPointReparseBuffer(sub, print)
	if err != nil {
		t.Fatalf("mountPointReparseBuffer: %v", err)
	}
	if got := len(buf); got != 16+134+124+2 { // header + sub + NUL + print + NUL
		t.Fatalf("buffer length = %d, want %d", got, 16+134+124+2)
	}
	if got := le16(t, buf[4:6]); got != 0x10c {
		t.Fatalf("ReparseDataLength = %#x, want 0x10c (the live mklink value)", got)
	}
	if got := le32(t, buf[0:4]); got != 0xA0000003 {
		t.Fatalf("ReparseTag = %#x, want the mount-point tag", got)
	}
	if got := le16(t, buf[10:12]); got != 132 {
		t.Fatalf("SubstituteNameLength = %d, want 132", got)
	}
	if got := le16(t, buf[12:14]); got != 134 {
		t.Fatalf("PrintNameOffset = %d, want 134 (NUL separator)", got)
	}
	if got := le16(t, buf[14:16]); got != 124 {
		t.Fatalf("PrintNameLength = %d, want 124", got)
	}
}

func mustReadlink(t *testing.T, path string) string {
	t.Helper()
	s, err := os.Readlink(path)
	if err != nil {
		t.Fatalf("Readlink(%s): %v", path, err)
	}
	return s
}

func le16(t *testing.T, b []byte) uint16 {
	t.Helper()
	return uint16(b[0]) | uint16(b[1])<<8
}

func le32(t *testing.T, b []byte) uint32 {
	t.Helper()
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
