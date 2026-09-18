package gitadapter

// Topology fixtures (D004 rule 5; Foundation §9.2 support matrix). Each
// fixture asserts the exact GitObservation fields and the derived
// DestructiveParkBlockers codes.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestObserveCleanRepo(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "base.txt", "one\n")

	obs := observeOK(t, repo)
	if !obs.AdminInsideRoot {
		t.Error("AdminInsideRoot = false, want true")
	}
	canon := canonicalToplevel(t, repo)
	if !samePath(obs.GitDir, filepath.Join(canon, ".git")) {
		t.Errorf("GitDir = %s, want %s", obs.GitDir, filepath.Join(canon, ".git"))
	}
	if !samePath(obs.CommonDir, filepath.Join(canon, ".git")) {
		t.Errorf("CommonDir = %s, want %s", obs.CommonDir, filepath.Join(canon, ".git"))
	}
	if obs.Unborn || obs.Detached {
		t.Errorf("Unborn=%v Detached=%v, want false/false", obs.Unborn, obs.Detached)
	}
	if obs.HeadBranch != "refs/heads/main" {
		t.Errorf("HeadBranch = %q, want refs/heads/main", obs.HeadBranch)
	}
	if !isHexCommit(obs.HeadCommit) {
		t.Errorf("HeadCommit = %q, want 40-hex", obs.HeadCommit)
	}
	if obs.StagedEntries != 1 {
		t.Errorf("StagedEntries = %d, want 1", obs.StagedEntries)
	}
	if obs.DirtyWorktree || obs.UntrackedEntries != 0 || obs.UnmergedEntries != 0 || obs.StashCount != 0 {
		t.Errorf("clean repo flagged dirty: dirty=%v untracked=%d unmerged=%d stash=%d",
			obs.DirtyWorktree, obs.UntrackedEntries, obs.UnmergedEntries, obs.StashCount)
	}
	if obs.MergeInProgress || obs.RebaseInProgress || obs.CherryPickInProgress || obs.RevertInProgress {
		t.Error("in-progress flags set on clean repo")
	}
	if obs.HasShallow || obs.HasAlternates || obs.IsPartialClone || obs.HasLFS {
		t.Error("dependency flags set on plain repo")
	}
	if obs.ObjectFormat != "sha1" {
		t.Errorf("ObjectFormat = %q, want sha1", obs.ObjectFormat)
	}
	if !strings.HasPrefix(obs.GitVersion, "git version ") {
		t.Errorf("GitVersion = %q", obs.GitVersion)
	}
	if b := obs.DestructiveParkBlockers(); len(b) != 0 {
		t.Errorf("blockers = %v, want none", b)
	}
	// System config on this machine carries filter.lfs.*; its absence
	// proves GIT_CONFIG_NOSYSTEM construction (lab/git-probe O23).
	if obs.HasLFS {
		t.Error("HasLFS = true without any repo-level LFS config (system config leaked?)")
	}
	if len(obs.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", obs.Warnings)
	}
}

func TestObserveDirtyConflictedRepo(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "base.txt", "one\n")
	writeAndCommit(t, repo, "keep.txt", "one\n")
	runGit(t, repo, "checkout", "-qb", "feat")
	writeAndCommit(t, repo, "base.txt", "feat\n")
	runGit(t, repo, "checkout", "-q", "main")
	writeAndCommit(t, repo, "base.txt", "main\n")
	if rc := runPlainGit(t, repo, nil, "merge", "feat"); rc == 0 {
		t.Fatal("merge unexpectedly succeeded; conflict fixture broken")
	}
	writeRepoFile(t, repo, "staged.txt", "staged\n")
	runGit(t, repo, "add", "staged.txt")
	writeRepoFile(t, repo, "keep.txt", "modified\n") // unstaged
	writeRepoFile(t, repo, "untracked-dir/u.txt", "u\n")

	obs := observeOK(t, repo)
	if !obs.DirtyWorktree {
		t.Error("DirtyWorktree = false, want true")
	}
	if obs.UnmergedEntries != 1 {
		t.Errorf("UnmergedEntries = %d, want 1", obs.UnmergedEntries)
	}
	if obs.UntrackedEntries != 1 {
		t.Errorf("UntrackedEntries = %d, want 1 (collapsed dir)", obs.UntrackedEntries)
	}
	// ls-files --stage: keep.txt + staged.txt + 3 conflict stages of base.txt.
	if obs.StagedEntries != 5 {
		t.Errorf("StagedEntries = %d, want 5", obs.StagedEntries)
	}
	if !obs.MergeInProgress {
		t.Error("MergeInProgress = false, want true")
	}
	if obs.RebaseInProgress || obs.CherryPickInProgress || obs.RevertInProgress {
		t.Error("wrong in-progress flags set")
	}
	if b := obs.DestructiveParkBlockers(); len(b) != 0 {
		t.Errorf("blockers = %v, want none", b)
	}
}

func TestObserveUnbornBranch(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo) // no commits

	obs := observeOK(t, repo)
	if !obs.Unborn {
		t.Error("Unborn = false, want true")
	}
	if obs.Detached {
		t.Error("Detached = true, want false")
	}
	if obs.HeadCommit != "" {
		t.Errorf("HeadCommit = %q, want empty", obs.HeadCommit)
	}
	if obs.HeadBranch != "refs/heads/main" {
		t.Errorf("HeadBranch = %q, want refs/heads/main", obs.HeadBranch)
	}
	if obs.StagedEntries != 0 || obs.DirtyWorktree {
		t.Errorf("empty unborn repo flagged content: staged=%d dirty=%v", obs.StagedEntries, obs.DirtyWorktree)
	}
	if b := obs.DestructiveParkBlockers(); len(b) != 0 {
		t.Errorf("blockers = %v, want none", b)
	}
}

func TestObserveDetachedHead(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	runGit(t, repo, "checkout", "-q", "--detach", "HEAD")

	obs := observeOK(t, repo)
	if !obs.Detached {
		t.Error("Detached = false, want true")
	}
	if obs.Unborn {
		t.Error("Unborn = true, want false")
	}
	if obs.HeadBranch != "" {
		t.Errorf("HeadBranch = %q, want empty on detached", obs.HeadBranch)
	}
	if !isHexCommit(obs.HeadCommit) {
		t.Errorf("HeadCommit = %q, want 40-hex", obs.HeadCommit)
	}
}

func TestObserveStashStack(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "stashsrc.txt", "s1\n")
	writeRepoFile(t, repo, "stashsrc.txt", "w1\n")
	runGit(t, repo, "stash", "-q")
	writeRepoFile(t, repo, "stashsrc.txt", "w2\n")
	runGit(t, repo, "stash", "-q")

	obs := observeOK(t, repo)
	if obs.StashCount != 2 {
		t.Errorf("StashCount = %d, want 2", obs.StashCount)
	}
	if obs.DirtyWorktree {
		t.Error("worktree dirty after stashing everything")
	}
}

func TestObserveRemotes(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	runGit(t, repo, "remote", "add", "origin", "https://example.com/proj.git")
	runGit(t, repo, "config", "remote.origin.pushurl", "git@example.com:proj.git")

	obs := observeOK(t, repo)
	if len(obs.Remotes) != 1 {
		t.Fatalf("Remotes = %+v, want 1", obs.Remotes)
	}
	r := obs.Remotes[0]
	if r.Name != "origin" || r.URL != "https://example.com/proj.git" || r.Push != "git@example.com:proj.git" {
		t.Errorf("remote = %+v", r)
	}
}

func TestObserveShallowClone(t *testing.T) {
	requireGit(t)
	origin := t.TempDir()
	initRepo(t, origin)
	writeAndCommit(t, origin, "f.txt", "one\n")
	tmp := t.TempDir()
	shallow := filepath.Join(tmp, "shallow")
	runGit(t, tmp, "clone", "-q", "--depth=1", fileURL(origin), shallow)

	obs := observeOK(t, shallow)
	if !obs.HasShallow {
		t.Error("HasShallow = false, want true")
	}
	if obs.IsPartialClone {
		t.Error("IsPartialClone = true on a plain shallow clone")
	}
}

func TestObservePartialClone(t *testing.T) {
	requireGit(t)
	origin := t.TempDir()
	initRepo(t, origin)
	writeAndCommit(t, origin, "f.txt", "one\n")
	tmp := t.TempDir()
	partial := filepath.Join(tmp, "partial")
	if _, err := tryGit(t, tmp, "clone", "-q", "--filter=blob:none", "--no-checkout", fileURL(origin), partial); err != nil {
		t.Skipf("local partial clone unsupported: %v", err)
	}

	obs := observeOK(t, partial)
	if !obs.IsPartialClone {
		t.Error("IsPartialClone = false, want true (promisor remote)")
	}
	if obs.HasShallow {
		t.Error("HasShallow = true on a non-shallow partial clone")
	}
	// Offline observation must not hang or lazy-fetch (GIT_NO_LAZY_FETCH=1;
	// lab/git-probe O16).
	if !isHexCommit(obs.HeadCommit) {
		t.Errorf("HeadCommit = %q, want resolved without network", obs.HeadCommit)
	}
}

func TestObserveLinkedWorktree(t *testing.T) {
	requireGit(t)
	tmp := t.TempDir()
	parent := filepath.Join(tmp, "wtparent")
	leaf := filepath.Join(tmp, "wt-leaf")
	initRepo(t, parent)
	writeAndCommit(t, parent, "w.txt", "one\n")
	runGit(t, parent, "worktree", "add", "-q", leaf, "-b", "leaf")

	obs := observeOK(t, parent)
	if len(obs.Worktrees) != 2 {
		t.Fatalf("Worktrees = %+v, want 2 entries (main + linked)", obs.Worktrees)
	}
	if obs.Worktrees[0].Bare || obs.Worktrees[0].Branch != "refs/heads/main" {
		t.Errorf("main worktree entry = %+v", obs.Worktrees[0])
	}
	if obs.Worktrees[1].Branch != "refs/heads/leaf" {
		t.Errorf("linked entry = %+v", obs.Worktrees[1])
	}
	if !obs.AdminInsideRoot {
		t.Error("AdminInsideRoot = false at parent, want true")
	}
	if !hasBlocker(obs, "EBB_E_SHARED_GIT") {
		t.Errorf("blockers = %v, want EBB_E_SHARED_GIT", obs.DestructiveParkBlockers())
	}
	if hasBlocker(obs, "EBB_E_GIT_ADMIN_OUTSIDE_ROOT") {
		t.Errorf("blockers = %v, admin is inside parent root", obs.DestructiveParkBlockers())
	}

	// Observing the leaf: its administration lives in the parent's .git.
	leafObs := observeOK(t, leaf)
	if leafObs.AdminInsideRoot {
		t.Error("AdminInsideRoot = true at leaf, want false")
	}
	if !hasBlocker(leafObs, "EBB_E_GIT_ADMIN_OUTSIDE_ROOT") {
		t.Errorf("blockers = %v, want EBB_E_GIT_ADMIN_OUTSIDE_ROOT", leafObs.DestructiveParkBlockers())
	}
	if !hasBlocker(leafObs, "EBB_E_SHARED_GIT") {
		t.Errorf("blockers = %v, want EBB_E_SHARED_GIT", leafObs.DestructiveParkBlockers())
	}
	if leafObs.HeadBranch != "refs/heads/leaf" {
		t.Errorf("HeadBranch = %q, want refs/heads/leaf", leafObs.HeadBranch)
	}
}

func TestObserveSubmodule(t *testing.T) {
	requireGit(t)
	tmp := t.TempDir()
	childSrc := filepath.Join(tmp, "child-src")
	parent := filepath.Join(tmp, "subparent")
	initRepo(t, childSrc)
	writeAndCommit(t, childSrc, "c.txt", "c\n")
	initRepo(t, parent)
	writeAndCommit(t, parent, "p.txt", "p\n")
	runGit(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "-q", gitConfigValue(childSrc), "child")
	runGit(t, parent, "commit", "-qm", "submodule")

	obs := observeOK(t, parent)
	if len(obs.Submodules) != 1 || obs.Submodules[0] != "child" {
		t.Errorf("Submodules = %v, want [child]", obs.Submodules)
	}
	if !obs.AdminInsideRoot {
		t.Error("AdminInsideRoot = false (modules dir is inside the parent root)")
	}
	// .gitmodules + p.txt + the gitlink.
	if obs.StagedEntries != 3 {
		t.Errorf("StagedEntries = %d, want 3 (.gitmodules + file + gitlink)", obs.StagedEntries)
	}
	if b := obs.DestructiveParkBlockers(); len(b) != 0 {
		t.Errorf("blockers = %v, want none", b)
	}
}

func TestObserveLFSMarkers(t *testing.T) {
	requireGit(t)
	// Config-only fake: no git-lfs binary is involved (Foundation §9.2 —
	// never invoke git-lfs, an alias-hijackable non-builtin).
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	runGit(t, repo, "config", "filter.lfs.clean", "git-lfs clean -- %f")
	if !observeOK(t, repo).HasLFS {
		t.Error("HasLFS = false with filter.lfs config")
	}

	// Directory marker only.
	repo2 := t.TempDir()
	initRepo(t, repo2)
	writeAndCommit(t, repo2, "f.txt", "one\n")
	if err := os.MkdirAll(filepath.Join(repo2, ".git", "lfs", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !observeOK(t, repo2).HasLFS {
		t.Error("HasLFS = false with .git/lfs present")
	}
}

func TestObserveRebaseInProgress(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "1\n")
	runGit(t, repo, "checkout", "-qb", "feat")
	writeAndCommit(t, repo, "f.txt", "feat\n")
	runGit(t, repo, "checkout", "-q", "main")
	writeAndCommit(t, repo, "f.txt", "main\n")
	if _, err := tryGit(t, repo, "rebase", "feat"); err == nil {
		t.Fatal("rebase unexpectedly succeeded; conflict fixture broken")
	}

	obs := observeOK(t, repo)
	if !obs.RebaseInProgress {
		t.Error("RebaseInProgress = false, want true")
	}
	if obs.MergeInProgress || obs.CherryPickInProgress || obs.RevertInProgress {
		t.Error("wrong in-progress flags set")
	}
}

func TestObserveCherryPickInProgress(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "1\n")
	runGit(t, repo, "checkout", "-qb", "pickme")
	writeAndCommit(t, repo, "f.txt", "picked\n")
	sha := strings.TrimSpace(runGit(t, repo, "rev-parse", "pickme"))
	runGit(t, repo, "checkout", "-q", "main")
	writeAndCommit(t, repo, "f.txt", "main\n")
	if _, err := tryGit(t, repo, "cherry-pick", sha); err == nil {
		t.Fatal("cherry-pick unexpectedly succeeded; conflict fixture broken")
	}

	obs := observeOK(t, repo)
	if !obs.CherryPickInProgress {
		t.Error("CherryPickInProgress = false, want true")
	}
	if obs.MergeInProgress || obs.RebaseInProgress || obs.RevertInProgress {
		t.Error("wrong in-progress flags set")
	}
}

func TestObserveAlternates(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	other := t.TempDir()
	initRepo(t, other)
	writeAndCommit(t, other, "g.txt", "one\n")

	if err := os.MkdirAll(filepath.Join(repo, ".git", "objects", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	alt := gitConfigValue(filepath.Join(other, ".git", "objects")) + "\n"
	if err := os.WriteFile(filepath.Join(repo, ".git", "objects", "info", "alternates"), []byte(alt), 0o644); err != nil {
		t.Fatal(err)
	}

	obs := observeOK(t, repo)
	if !obs.HasAlternates {
		t.Fatal("HasAlternates = false, want true")
	}
	if !hasBlocker(obs, "EBB_E_GIT_ALTERNATES") {
		t.Errorf("blockers = %v, want EBB_E_GIT_ALTERNATES", obs.DestructiveParkBlockers())
	}
}

func TestObserveNotARepo(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	obs, err := Observe(t.Context(), dir)
	if err != nil {
		t.Fatalf("Observe(empty dir) error = %v, want nil (IsRepo=false is an observation)", err)
	}
	if obs.IsRepo {
		t.Error("IsRepo = true on an empty directory")
	}
	if obs.GitDir != "" || obs.CommonDir != "" || obs.HeadCommit != "" {
		t.Errorf("non-repo observation carries repo data: %+v", obs)
	}
	if !strings.HasPrefix(obs.GitVersion, "git version ") {
		t.Errorf("GitVersion = %q, want recorded even for non-repos", obs.GitVersion)
	}
}

func TestObserveMissingRootIsError(t *testing.T) {
	requireGit(t)
	if _, err := Observe(t.Context(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("missing root accepted, want error")
	}
}

// Discovery containment (lab/git-probe O24): GIT_CEILING_DIRECTORIES is
// the parent of the observed root, so a root that is a subdirectory of a
// repository does not silently adopt the parent's administration.
func TestObserveSubdirectoryRootCeilingContained(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	sub := filepath.Join(repo, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	obs, err := Observe(t.Context(), sub)
	if err != nil {
		t.Fatalf("Observe(subdir): %v", err)
	}
	if obs.IsRepo {
		t.Errorf("IsRepo = true from subdirectory; ceiling should contain discovery at %s", repo)
	}
}
