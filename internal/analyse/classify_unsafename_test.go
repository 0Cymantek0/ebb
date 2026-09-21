package analyse

// Terminal-injection hardening tests (F4): the control-character
// predicate and the [UNSAFE NAME] shield that keeps hostile project
// names/paths out of copyable command lines and batch execution. The
// classification itself must stay honest (a hostile-named project is
// still stale/merged-worktree — it is shielded, not misreported).

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHasControlChars: the predicate is the injection gate. Path
// separators and printable text pass; newlines, other C0 bytes and DEL
// fail; multi-byte runes never false-positive (their continuation bytes
// are all >= 0x80).
func TestHasControlChars(t *testing.T) {
	clean := []string{"", "proj", "my proj", "a/b/c", `C:\Users\u`, "branche-café", "日本ブランチ", "it's"}
	for _, s := range clean {
		if HasControlChars(s) {
			t.Errorf("HasControlChars(%q) = true, want false", s)
		}
	}
	hostile := []string{"\n", "evil\nname", "evil\rname", "a\tb", "\x1b[31mred", "\x00", "\x7f", "x\x01y"}
	for _, s := range hostile {
		if !HasControlChars(s) {
			t.Errorf("HasControlChars(%q) = false, want true", s)
		}
	}
}

// TestUnsafeNameShieldedCommandWithheld: a project whose name or root
// path carries control characters is shielded out of every batch and
// its copyable command is withheld — a hostile name must never reach a
// paste-able command line (a newline would make the pasted line execute
// a second line).
func TestUnsafeNameShieldedCommandWithheld(t *testing.T) {
	stale := func(name, root string) Project {
		p := Project{Name: name, Root: root,
			Repo:           RepoSummary{IsRepo: true},
			LastActivityAt: ago(45 * 24 * time.Hour),
		}
		classify(&p, nowFixed, defaultThresholds)
		return p
	}

	// Stale bucket with a hostile name.
	p := stale("evil\nname", filepath.Join("root", "evil\nname"))
	if p.Category != CategoryStale {
		t.Errorf("category = %q, want stale (classification stays honest)", p.Category)
	}
	if !containsStr(p.Shields, ShieldUnsafeName) || !p.Shielded() {
		t.Errorf("unsafe-name shield missing: %v", p.Shields)
	}
	if p.Recommendation.Command != nil {
		t.Errorf("copyable command rendered for a hostile name: %v", p.Recommendation.Command)
	}
	if !strings.Contains(p.Recommendation.Reason, ShieldUnsafeName) {
		t.Errorf("reason must name the shield: %q", p.Recommendation.Reason)
	}
	if p.ReclaimCandidate() {
		t.Error("unsafe-name project must never be a batch candidate")
	}

	// Merged-worktree bucket (the early-return path) with an ANSI path.
	wt := Project{
		Name: "wt", Root: "root/\x1b[31mwt",
		Repo:           RepoSummary{IsWorktree: true, WorktreeMain: "root/main", MergedUpstream: true},
		LastActivityAt: ago(18 * 24 * time.Hour),
	}
	classify(&wt, nowFixed, defaultThresholds)
	if wt.Category != CategoryMergedWorktree {
		t.Errorf("worktree category = %q", wt.Category)
	}
	if !containsStr(wt.Shields, ShieldUnsafeName) || wt.PruneCandidate() {
		t.Errorf("unsafe-name worktree must be shielded out of pruning: %v", wt.Shields)
	}
	if wt.Recommendation.Command != nil {
		t.Errorf("copyable command rendered for a hostile path: %v", wt.Recommendation.Command)
	}

	// A clean name keeps its command (no over-blocking).
	ok := stale("plain", filepath.Join("root", "plain"))
	if ok.Shielded() || ok.Recommendation.Command == nil {
		t.Errorf("clean project shielded or commandless: %+v", ok)
	}
}
