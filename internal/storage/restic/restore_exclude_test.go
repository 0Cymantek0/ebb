package resticstore

// Tests for the exclusion-based restore path (Wave F): the pure
// pattern builder, and the live conformance pin that restoring with
// every link node excluded exits 0 on an unprivileged Windows machine
// (restic never attempts reparse materialization for excluded nodes).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/domain"
)

func TestExcludePattern(t *testing.T) {
	// Literal paths pass through unchanged.
	for _, p := range []string{"ws/link-out", "ws/sub/nested-link", ".ebb-op-0123456789abcdef0123456789abcdef"} {
		got, err := excludePattern(p)
		if err != nil || got != p {
			t.Errorf("excludePattern(%q) = %q, %v; want it unchanged", p, got, err)
		}
	}
	// Glob metacharacters are escaped into single-character classes; a
	// literal `]` stays literal (see escapeGlobSegment for why).
	cases := map[string]string{
		"ws/we*ird":       "ws/we[*]ird",
		"ws/huh?":         "ws/huh[?]",
		"ws/brack[et]":    "ws/brack[[]et]",
		"!negation":       "[!]negation",
		"ws/[x]*?[!].txt": "ws/[[]x][*][?][[][!]].txt",
		"tricky[]][":      "tricky[[]]][[]",
	}
	for in, want := range cases {
		got, err := excludePattern(in)
		if err != nil {
			t.Errorf("excludePattern(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("excludePattern(%q) = %q, want %q", in, got, want)
		}
	}
	// Malformed shapes are refused client-side.
	for _, bad := range []string{"", "/ws/abs", "ws//double", "ws/./dot", "ws/../up", "..", "ws\\back", "ws/\x00nul"} {
		if _, err := excludePattern(bad); err == nil {
			t.Errorf("excludePattern(%q) must be refused", bad)
		}
	}
}

// TestExcludePatternMatchesLiterals verifies with Go's own filepath.Match
// (the exact semantics restic's filter applies per segment) that an
// escaped pattern matches its literal source path — including hostile
// metacharacter names — and not near-miss siblings.
func TestExcludePatternMatchesLiterals(t *testing.T) {
	paths := []string{
		"ws/link-out", "ws/we*ird", "ws/huh?", "ws/brack[et]",
		"!negation", "tricky[]][", "]_[[", "x[y]z!", "][",
	}
	for _, p := range paths {
		pat, err := excludePattern(p)
		if err != nil {
			t.Fatalf("excludePattern(%q): %v", p, err)
		}
		ok, merr := filepath.Match(pat, p)
		if merr != nil || !ok {
			t.Errorf("pattern %q must match its literal path %q (%v, %v)", pat, p, ok, merr)
		}
		// Near-miss siblings (a class must not widen into other bytes).
		for _, sib := range []string{
			strings.Replace(p, "*", "X", 1),
			strings.Replace(p, "?", "X", 1),
			strings.Replace(p, "[", "X", 1),
			strings.Replace(p, "!", "X", 1),
		} {
			if sib == p || !strings.ContainsAny(p, "*?[!") {
				continue
			}
			if ok, _ := filepath.Match(pat, sib); ok {
				t.Errorf("pattern %q must not match sibling %q", pat, sib)
			}
		}
	}
}

// TestRestoreExcludingLinkNodesUnprivileged is the adapter half of the
// unprivileged-open fix: with the junction (and the op dir) excluded,
// restore must exit 0 on a machine that CANNOT materialize reparse
// points, and must still materialize every other node of the full tree.
func TestRestoreExcludingLinkNodesUnprivileged(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	f := newFixture(t)
	if !f.hasJunction {
		t.Skip("junction fixture unavailable on this machine")
	}

	ref := snap(t, s, f, repoDir, passfile, f.selected(true), "restore-excluding")
	dest := filepath.Join(t.TempDir(), "out")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	excludes := []string{"ws/junction-out", "opd"}
	if err := s.RestoreExcluding(ctx, repoDir, passfile, ref.BackendID, dest, excludes); err != nil {
		t.Fatalf("RestoreExcluding with link nodes excluded must exit 0 unprivileged: %v", err)
	}

	// The excluded nodes are absent...
	if _, err := os.Lstat(filepath.Join(dest, "ws", "junction-out")); !os.IsNotExist(err) {
		t.Errorf("excluded junction must not be materialized (stat err = %v)", err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "opd")); !os.IsNotExist(err) {
		t.Errorf("excluded op dir must not be materialized (stat err = %v)", err)
	}
	// ...and every OTHER selected FILE round-trips byte-identically
	// (directories and excluded paths are not content-checked here).
	for _, rel := range f.selected(true) {
		if rel == "ws/junction-out" || rel == "opd/manifest.json" {
			continue // excluded on purpose
		}
		if f.oracle[rel].kind != domain.KindFile {
			continue // directories are checked separately below
		}
		content, rerr := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if rerr != nil {
			t.Errorf("restored %s: %v", rel, rerr)
			continue
		}
		if sha256Bytes(content) != f.digests[rel] {
			t.Errorf("restored %s digest mismatch", rel)
		}
	}
	if fi, err := os.Stat(filepath.Join(dest, "ws", "emptydir")); err != nil || !fi.IsDir() {
		t.Errorf("empty dir must survive exclusion-based restore: %v", err)
	}
}

// TestRestoreExcludingRefusesBadPatterns pins the client-side argv
// guard: no exclude ever reaches restic unvalidated.
func TestRestoreExcludingRefusesBadPatterns(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, bad := range []string{"/abs", "ws//x", "..", "ws\\x"} {
		err := s.RestoreExcluding(ctx, repoDir, passfile, strings.Repeat("ab", 16), t.TempDir(), []string{bad})
		if err == nil {
			t.Fatalf("exclude %q must be refused before restic runs", bad)
		}
		var se *domain.StoreError
		if !errors.As(err, &se) || se.Class != domain.StoreErrUsage {
			t.Errorf("exclude %q refusal class = %v, want usage", bad, err)
		}
	}
}
