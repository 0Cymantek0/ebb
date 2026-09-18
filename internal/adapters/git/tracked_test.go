package gitadapter

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestTrackedFilesExactSet verifies the exact-set contract on a fixture
// repository with tracked, untracked and ignored files (Deliverable 1
// acceptance).
func TestTrackedFilesExactSet(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initRepo(t, dir)

	writeAndCommit(t, dir, "src/main.go", "package main\n\nfunc main() {}\n")
	writeAndCommit(t, dir, "docs/guide.md", "# guide\n")
	writeRepoFile(t, dir, ".gitignore", "ignored.txt\n")
	commitAll(t, dir, "add gitignore") // .gitignore itself is tracked

	// Neither of these may appear in the tracked set.
	writeRepoFile(t, dir, "untracked.txt", "untracked\n")
	writeRepoFile(t, dir, "ignored.txt", "ignored\n")

	got, err := TrackedFiles(t.Context(), dir)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	want := map[string]bool{
		".gitignore":    true,
		"src/main.go":   true,
		"docs/guide.md": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tracked set = %v, want %v", got, want)
	}
}

// TestTrackedFilesQuotedPaths covers paths git renders C-style-quoted
// (non-ASCII bytes via the default core.quotePath). Windows forbids
// '"', '\' and control bytes in filenames, so those escape forms are
// exercised directly by TestUnquoteGitPath instead.
func TestTrackedFilesQuotedPaths(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initRepo(t, dir)

	writeRepoFile(t, dir, "data/héllo.txt", "accented\n") // quoted: bytes > 0x7f
	writeRepoFile(t, dir, "plain.txt", "plain\n")
	commitAll(t, dir, "add quoted names")

	got, err := TrackedFiles(t.Context(), dir)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if !got["data/héllo.txt"] {
		t.Errorf("tracked set lacks quoted path %q (got %v)", "data/héllo.txt", got)
	}
	if !got["plain.txt"] {
		t.Errorf("tracked set lacks %q (got %v)", "plain.txt", got)
	}
}

// TestTrackedFilesGitlink verifies gitlink (mode 160000) index entries
// count as tracked: a submodule mount point must not be ommissible. The
// gitlink is fabricated via update-index --cacheinfo, which needs no
// actual submodule clone.
func TestTrackedFilesGitlink(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	initRepo(t, dir)
	writeAndCommit(t, dir, "README.md", "x\n")

	sha := strings.TrimSpace(runGit(t, dir, "rev-parse", "HEAD"))
	runGit(t, dir, "update-index", "--add", "--cacheinfo", "160000,"+sha+",vendor/inner")

	got, err := TrackedFiles(t.Context(), dir)
	if err != nil {
		t.Fatalf("TrackedFiles: %v", err)
	}
	if !got["vendor/inner"] {
		t.Fatalf("gitlink vendor/inner not tracked (got %v)", got)
	}
	if !got["README.md"] {
		t.Fatalf("README.md not tracked (got %v)", got)
	}
}

// TestTrackedFilesNotARepository verifies the non-repo observation: an
// empty set and a nil error, never a failure.
func TestTrackedFilesNotARepository(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "loose.txt"), []byte("no repo here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := TrackedFiles(t.Context(), dir)
	if err != nil {
		t.Fatalf("TrackedFiles on non-repo: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("non-repo tracked set = %v, want empty", got)
	}
}

// TestUnquoteGitPath unit-tests the C-style decoder against git's
// quoting rules (see quote_c_style in git's quote.c).
func TestUnquoteGitPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{`plain.txt`, "plain.txt"},
		{`"plain-but-quoted.txt"`, "plain-but-quoted.txt"},
		{`"we\"ird.txt"`, `we"ird.txt`},
		{`"back\\slash.txt"`, `back\slash.txt`},
		{`"data/h\303\251llo.txt"`, "data/héllo.txt"}, // UTF-8 é = C3 A9
		{`"tab\tname.txt"`, "tab\tname.txt"},
		{`"bell\aand\nlines"`, "bell\aand\nlines"},
		{`"cr\rcode"`, "cr\r" + "code"},           // \r escape: "cr", CR, "code"
		{`"trailing-escape\"`, "trailing-escape"}, // dangling escape: stop
	}
	for _, tt := range tests {
		if got := unquoteGitPath(tt.in); got != tt.want {
			t.Errorf("unquoteGitPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
