package gitadapter

// Survey tests (D037 repository survey). Real-git tests follow the
// suite convention: gated on exec.LookPath("git"), fixtures built with
// real git init/add/commit, observation always through SurveyRepo
// (which internally runs the hardened Observe). Every behavior claim of
// the RepoSummary contract is traced by at least one test below.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

func surveyOK(t *testing.T, root string) RepoSummary {
	t.Helper()
	sum, err := SurveyRepo(t.Context(), root)
	if err != nil {
		t.Fatalf("SurveyRepo(%s): %v", root, err)
	}
	if !sum.IsRepo {
		t.Fatalf("SurveyRepo(%s): IsRepo = false (warnings: %v)", root, sum.Warnings)
	}
	return sum
}

func hasWarning(sum RepoSummary, substr string) bool {
	for _, w := range sum.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// pushSetUpstream wires a local bare origin as work's upstream with the
// current main pushed (local file transport only, no network).
func pushSetUpstream(t *testing.T, work string) {
	t.Helper()
	tmp := t.TempDir()
	origin := filepath.Join(tmp, "origin.git")
	runGit(t, tmp, "init", "-q", "--bare", origin)
	runGit(t, work, "remote", "add", "origin", fileURL(origin))
	runGit(t, work, "push", "-q", "-u", "origin", "main")
}

// writeLFSObject fabricates an LFS object file under <repo>/.git/lfs/objects
// (no git-lfs involved; Foundation §9.2 — git-lfs is an alias-hijackable
// non-builtin that is never invoked).
func writeLFSObject(t *testing.T, repo, rel string, size int) {
	t.Helper()
	p := filepath.Join(repo, ".git", "lfs", "objects", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytes.Repeat([]byte("x"), size), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Plain repo without upstream: unpushed unknown (-1 + warning), the
// merged verdict falls back to main (HEAD is trivially its own
// ancestor), stale list excludes the current branch.
func TestSurveyPlainRepo(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "base.txt", "one\n")

	sum := surveyOK(t, repo)
	if sum.Branch != "main" {
		t.Errorf("Branch = %q, want main", sum.Branch)
	}
	if !isHexCommit(sum.HeadCommit) {
		t.Errorf("HeadCommit = %q, want 40-hex", sum.HeadCommit)
	}
	if sum.Detached || sum.DirtyWorktree || sum.UnmergedEntries != 0 {
		t.Errorf("clean repo flagged: detached=%v dirty=%v unmerged=%d",
			sum.Detached, sum.DirtyWorktree, sum.UnmergedEntries)
	}
	if sum.IsWorktree || sum.WorktreeMain != "" {
		t.Errorf("plain repo classified as linked worktree: %+v", sum)
	}
	if sum.UnpushedCommits != -1 {
		t.Errorf("UnpushedCommits = %d, want -1 (no upstream)", sum.UnpushedCommits)
	}
	if !hasWarning(sum, "no usable upstream") {
		t.Errorf("Warnings = %v, want a no-upstream warning", sum.Warnings)
	}
	if !sum.MergedUpstream {
		t.Errorf("MergedUpstream = false, want true (HEAD is main's tip via main fallback)")
	}
	if len(sum.StaleMergedBranches) != 0 {
		t.Errorf("StaleMergedBranches = %v, want empty (main is current)", sum.StaleMergedBranches)
	}
	if sum.LastActivityAt.IsZero() || sum.LastActivityAt.After(time.Now()) ||
		sum.LastActivityAt.Before(time.Now().Add(-24*time.Hour)) {
		t.Errorf("LastActivityAt = %v, want the HEAD commit time (recent)", sum.LastActivityAt)
	}
	if sum.LFSObjectsBytes != 0 {
		t.Errorf("LFSObjectsBytes = %d, want 0 (no lfs dir)", sum.LFSObjectsBytes)
	}
	if len(sum.Warnings) != 1 {
		t.Errorf("Warnings = %v, want exactly the no-upstream warning", sum.Warnings)
	}
}

func TestSurveyNotARepo(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	sum, err := SurveyRepo(t.Context(), dir)
	if err != nil {
		t.Fatalf("SurveyRepo(empty dir) error = %v, want nil (IsRepo=false is an observation)", err)
	}
	if sum.IsRepo {
		t.Error("IsRepo = true on an empty directory")
	}
	if sum.Branch != "" || sum.HeadCommit != "" || sum.StaleMergedBranches != nil ||
		sum.WorktreeMain != "" || sum.LastActivityAt != (time.Time{}) {
		t.Errorf("non-repo summary carries repo data: %+v", sum)
	}
	if sum.LFSObjectsBytes != 0 || sum.UnpushedCommits != 0 {
		t.Errorf("non-repo summary carries sentinels: %+v", sum)
	}
	if len(sum.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", sum.Warnings)
	}
}

// Unborn repo: every derived fact degrades to its unknown sentinel with
// an explicit warning; the survey still completes.
func TestSurveyUnbornRepo(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo) // no commits

	sum := surveyOK(t, repo)
	if sum.Branch != "main" {
		t.Errorf("Branch = %q, want main (unborn branch name is known)", sum.Branch)
	}
	if sum.HeadCommit != "" {
		t.Errorf("HeadCommit = %q, want empty on unborn", sum.HeadCommit)
	}
	if sum.Detached {
		t.Error("Detached = true, want false")
	}
	if sum.UnpushedCommits != -1 || !hasWarning(sum, "no usable upstream") {
		t.Errorf("unborn unpushed = %d, warnings %v", sum.UnpushedCommits, sum.Warnings)
	}
	if sum.MergedUpstream || !hasWarning(sum, "neither main nor master") {
		t.Errorf("unborn merged = %v, warnings %v; want false + limitation warning",
			sum.MergedUpstream, sum.Warnings)
	}
	if !sum.LastActivityAt.IsZero() || !hasWarning(sum, "author time unavailable") {
		t.Errorf("unborn activity = %v, warnings %v; want zero + warning",
			sum.LastActivityAt, sum.Warnings)
	}
	if sum.StaleMergedBranches != nil || !hasWarning(sum, "for-each-ref --merged=HEAD exited") {
		t.Errorf("unborn stale = %v, warnings %v; want nil + warning",
			sum.StaleMergedBranches, sum.Warnings)
	}
	if sum.LFSObjectsBytes != 0 {
		t.Errorf("LFSObjectsBytes = %d, want 0", sum.LFSObjectsBytes)
	}
}

func TestSurveyDetachedHead(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	runGit(t, repo, "checkout", "-q", "--detach", "HEAD")

	sum := surveyOK(t, repo)
	if sum.Branch != "" {
		t.Errorf("Branch = %q, want empty on detached", sum.Branch)
	}
	if !sum.Detached || !isHexCommit(sum.HeadCommit) {
		t.Errorf("detached facts wrong: detached=%v head=%q", sum.Detached, sum.HeadCommit)
	}
	// No branch holds HEAD: @{u} is unresolvable, main decides the merge
	// verdict, and every local branch (main itself) counts as stale.
	if sum.UnpushedCommits != -1 || !hasWarning(sum, "no usable upstream") {
		t.Errorf("detached unpushed = %d, warnings %v", sum.UnpushedCommits, sum.Warnings)
	}
	if !sum.MergedUpstream {
		t.Errorf("MergedUpstream = false, want true (HEAD is main's tip)")
	}
	if len(sum.StaleMergedBranches) != 1 || sum.StaleMergedBranches[0] != "main" {
		t.Errorf("StaleMergedBranches = %v, want [main] (no current branch to exclude)",
			sum.StaleMergedBranches)
	}
	if sum.LastActivityAt.IsZero() {
		t.Error("LastActivityAt zero on a resolvable detached HEAD")
	}
}

// In-sync upstream: zero unpushed, merged, and a warning-free survey.
func TestSurveyUpstreamInSync(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	pushSetUpstream(t, repo)

	sum := surveyOK(t, repo)
	if sum.UnpushedCommits != 0 {
		t.Errorf("UnpushedCommits = %d, want 0", sum.UnpushedCommits)
	}
	if !sum.MergedUpstream {
		t.Errorf("MergedUpstream = false, want true (HEAD == upstream)")
	}
	if len(sum.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none on an in-sync upstream", sum.Warnings)
	}
}

// Local commits ahead of upstream: unpushed > 0 and NOT merged.
func TestSurveyUpstreamAheadUnpushed(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	pushSetUpstream(t, repo)
	writeAndCommit(t, repo, "g.txt", "local work\n")

	sum := surveyOK(t, repo)
	if sum.UnpushedCommits != 1 {
		t.Errorf("UnpushedCommits = %d, want 1", sum.UnpushedCommits)
	}
	if sum.MergedUpstream {
		t.Errorf("MergedUpstream = true, want false (HEAD is ahead of upstream)")
	}
	if hasWarning(sum, "upstream") {
		t.Errorf("in-sync-adjacent warnings on a usable upstream: %v", sum.Warnings)
	}
}

// Upstream ahead of HEAD (repo rolled back after push): nothing to
// push and HEAD is merged into the upstream.
func TestSurveyUpstreamAheadOfHead(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	writeAndCommit(t, repo, "g.txt", "two\n")
	pushSetUpstream(t, repo)
	runGit(t, repo, "reset", "-q", "--hard", "HEAD~1")

	sum := surveyOK(t, repo)
	if sum.UnpushedCommits != 0 {
		t.Errorf("UnpushedCommits = %d, want 0 (every local commit is in upstream)", sum.UnpushedCommits)
	}
	if !sum.MergedUpstream {
		t.Errorf("MergedUpstream = false, want true (HEAD is an ancestor of upstream)")
	}
}

// branch.<name>.remote/merge configured but the remote-tracking ref is
// gone: @{u} does not resolve, so the survey must report unknown (-1)
// with a warning instead of silently treating it as zero.
func TestSurveyUpstreamRefMissing(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	pushSetUpstream(t, repo)
	runGit(t, repo, "update-ref", "-d", "refs/remotes/origin/main")

	sum := surveyOK(t, repo)
	if sum.UnpushedCommits != -1 {
		t.Errorf("UnpushedCommits = %d, want -1 (unusable upstream)", sum.UnpushedCommits)
	}
	if !hasWarning(sum, "no usable upstream") {
		t.Errorf("Warnings = %v, want a no-usable-upstream warning", sum.Warnings)
	}
	// The main fallback still decides the merge verdict.
	if !sum.MergedUpstream {
		t.Errorf("MergedUpstream = false, want true via main fallback")
	}
}

// The D037 flagship: a linked worktree whose branch was fully merged
// into main is a prunable merged worktree.
func TestSurveyMergedLinkedWorktree(t *testing.T) {
	requireGit(t)
	tmp := t.TempDir()
	parent := filepath.Join(tmp, "wtparent")
	leaf := filepath.Join(tmp, "wt-leaf")
	initRepo(t, parent)
	writeAndCommit(t, parent, "w.txt", "one\n")
	runGit(t, parent, "worktree", "add", "-q", leaf, "-b", "leaf")
	writeAndCommit(t, leaf, "leaf.txt", "leaf work\n")
	runGit(t, parent, "merge", "-q", "--no-edit", "leaf")

	sum := surveyOK(t, leaf)
	if !sum.IsWorktree {
		t.Error("IsWorktree = false at the linked leaf, want true")
	}
	if !samePath(sum.WorktreeMain, canonicalToplevel(t, parent)) {
		t.Errorf("WorktreeMain = %q, want the parent checkout %q",
			sum.WorktreeMain, canonicalToplevel(t, parent))
	}
	if !sum.MergedUpstream {
		t.Errorf("MergedUpstream = false, want true (leaf branch merged into main)")
	}
	if sum.DirtyWorktree || sum.Branch != "leaf" {
		t.Errorf("leaf facts wrong: dirty=%v branch=%q", sum.DirtyWorktree, sum.Branch)
	}
	if sum.UnpushedCommits != -1 || !hasWarning(sum, "no usable upstream") {
		t.Errorf("leaf unpushed = %d, warnings %v", sum.UnpushedCommits, sum.Warnings)
	}

	// The main checkout side: not a worktree, and the merged leaf branch
	// is now a stale branch of the parent.
	psum := surveyOK(t, parent)
	if psum.IsWorktree || psum.WorktreeMain != "" {
		t.Errorf("parent classified as linked worktree: %+v", psum)
	}
	if !psum.MergedUpstream {
		t.Errorf("parent MergedUpstream = false, want true")
	}
	if len(psum.StaleMergedBranches) != 1 || psum.StaleMergedBranches[0] != "leaf" {
		t.Errorf("parent StaleMergedBranches = %v, want [leaf]", psum.StaleMergedBranches)
	}
}

// Unmerged + dirty linked worktree: shielded from pruning (merged=false,
// dirty=true) — the exact facts ebb analyse keys on.
func TestSurveyUnmergedDirtyLinkedWorktree(t *testing.T) {
	requireGit(t)
	tmp := t.TempDir()
	parent := filepath.Join(tmp, "wtparent")
	leaf := filepath.Join(tmp, "wt-leaf2")
	initRepo(t, parent)
	writeAndCommit(t, parent, "w.txt", "one\n")
	runGit(t, parent, "worktree", "add", "-q", leaf, "-b", "leaf2")
	writeAndCommit(t, leaf, "leaf2.txt", "unmerged work\n")
	writeRepoFile(t, leaf, "extra.txt", "uncommitted\n")

	sum := surveyOK(t, leaf)
	if sum.MergedUpstream {
		t.Error("MergedUpstream = true on an unmerged branch, want false")
	}
	if !sum.DirtyWorktree {
		t.Error("DirtyWorktree = false, want true (untracked file)")
	}
	if !sum.IsWorktree || sum.Branch != "leaf2" {
		t.Errorf("leaf topology wrong: isWT=%v branch=%q", sum.IsWorktree, sum.Branch)
	}
}

// Conflict-state facts flow through from the reused Observe observation.
func TestSurveyUnmergedConflictFacts(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "base.txt", "one\n")
	runGit(t, repo, "checkout", "-qb", "feat")
	writeAndCommit(t, repo, "base.txt", "feat\n")
	runGit(t, repo, "checkout", "-q", "main")
	writeAndCommit(t, repo, "base.txt", "main\n")
	if rc := runPlainGit(t, repo, nil, "merge", "feat"); rc == 0 {
		t.Fatal("merge unexpectedly succeeded; conflict fixture broken")
	}

	sum := surveyOK(t, repo)
	if sum.UnmergedEntries != 1 {
		t.Errorf("UnmergedEntries = %d, want 1", sum.UnmergedEntries)
	}
	if !sum.DirtyWorktree {
		t.Error("DirtyWorktree = false during a conflict, want true")
	}
}

func TestSurveyStaleMergedBranches(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	runGit(t, repo, "branch", "feat-a") // merged: points at main's tip
	runGit(t, repo, "branch", "feat-b") // merged
	runGit(t, repo, "checkout", "-qb", "live")
	writeAndCommit(t, repo, "live.txt", "diverged\n")
	runGit(t, repo, "checkout", "-q", "main")

	sum := surveyOK(t, repo)
	want := []string{"feat-a", "feat-b"}
	if len(sum.StaleMergedBranches) != len(want) {
		t.Fatalf("StaleMergedBranches = %v, want %v", sum.StaleMergedBranches, want)
	}
	for i, name := range want {
		if sum.StaleMergedBranches[i] != name {
			t.Errorf("StaleMergedBranches[%d] = %q, want %q", i, sum.StaleMergedBranches[i], name)
		}
	}
	if hasWarning(sum, "stale") {
		t.Errorf("unexpected stale warnings: %v", sum.Warnings)
	}
}

func TestSurveyStaleMergedBranchesCap(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	for i := 1; i <= 55; i++ {
		runGit(t, repo, "branch", "z"+string(rune('0'+i/10))+string(rune('0'+i%10)))
	}

	sum := surveyOK(t, repo)
	if len(sum.StaleMergedBranches) != maxStaleBranches {
		t.Fatalf("len(StaleMergedBranches) = %d, want cap %d", len(sum.StaleMergedBranches), maxStaleBranches)
	}
	for _, b := range sum.StaleMergedBranches {
		if b == "z51" || b == "z55" {
			t.Errorf("stale list exceeds the cap: %v", sum.StaleMergedBranches)
		}
	}
	if !hasWarning(sum, "truncated at 50 entries") {
		t.Errorf("Warnings = %v, want a truncation warning", sum.Warnings)
	}
}

// Author time is read from git's epoch format, never a locale-parsed
// date string.
func TestSurveyLastActivityDeterministic(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeRepoFile(t, repo, "f.txt", "dated\n")
	runGit(t, repo, "add", "-A")
	runGit(t, repo, "commit", "-qm", "dated", "--date=@1700000000")

	sum := surveyOK(t, repo)
	want := time.Unix(1700000000, 0).UTC()
	if !sum.LastActivityAt.Equal(want) {
		t.Errorf("LastActivityAt = %v, want %v (author date 1700000000 UTC)", sum.LastActivityAt, want)
	}
}

func TestSurveyLFSObjectsSums(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	writeLFSObject(t, repo, "ab/cd/oid1", 1000)
	writeLFSObject(t, repo, "ab/cd/oid2", 32)
	writeLFSObject(t, repo, "ab/cd/oid3", 8)
	writeLFSObject(t, repo, "ef/gh/oid4", 5)

	sum := surveyOK(t, repo)
	if sum.LFSObjectsBytes != 1045 {
		t.Errorf("LFSObjectsBytes = %d, want 1045", sum.LFSObjectsBytes)
	}
	if hasWarning(sum, "lfs") {
		t.Errorf("unexpected lfs warnings: %v", sum.Warnings)
	}

	// Missing lfs dir is 0 bytes, not unknown.
	repo2 := t.TempDir()
	initRepo(t, repo2)
	writeAndCommit(t, repo2, "f.txt", "one\n")
	if s := surveyOK(t, repo2); s.LFSObjectsBytes != 0 {
		t.Errorf("LFSObjectsBytes = %d without an lfs dir, want 0", s.LFSObjectsBytes)
	}
}

// Linked worktrees reach the shared LFS objects through commondir.
func TestSurveyLFSLinkedWorktreeCommonDir(t *testing.T) {
	requireGit(t)
	tmp := t.TempDir()
	parent := filepath.Join(tmp, "wtparent")
	leaf := filepath.Join(tmp, "wt-leaf")
	initRepo(t, parent)
	writeAndCommit(t, parent, "w.txt", "one\n")
	runGit(t, parent, "worktree", "add", "-q", leaf, "-b", "leaf")
	writeLFSObject(t, parent, "ab/cd/oid1", 4096)

	sum := surveyOK(t, leaf)
	if sum.LFSObjectsBytes != 4096 {
		t.Errorf("LFSObjectsBytes at linked worktree = %d, want 4096 (via commondir)",
			sum.LFSObjectsBytes)
	}
	if s := surveyOK(t, parent); s.LFSObjectsBytes != 4096 {
		t.Errorf("LFSObjectsBytes at main checkout = %d, want 4096", s.LFSObjectsBytes)
	}
}

// An lfs/objects that exists but is not a directory is unknown (-1).
func TestSurveyLFSFileInsteadOfDir(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	if err := os.MkdirAll(filepath.Join(repo, ".git", "lfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "lfs", "objects"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}

	sum := surveyOK(t, repo)
	if sum.LFSObjectsBytes != -1 {
		t.Errorf("LFSObjectsBytes = %d, want -1 (unsurveyable)", sum.LFSObjectsBytes)
	}
	if !hasWarning(sum, "not a directory") {
		t.Errorf("Warnings = %v, want a not-a-directory warning", sum.Warnings)
	}
}

// The walk budgets (files, wall clock) stop with a partial sum + warning.
func TestSurveyLFSBounds(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")
	for i := 1; i <= 5; i++ {
		writeLFSObject(t, repo, "o"+string(rune('0'+i)), i)
	}

	oldLimit := lfsWalkFileLimit
	lfsWalkFileLimit = 3
	sum := surveyOK(t, repo)
	lfsWalkFileLimit = oldLimit
	if sum.LFSObjectsBytes != 6 { // o1+o2+o3 in lexical walk order
		t.Errorf("LFSObjectsBytes = %d, want partial sum 6", sum.LFSObjectsBytes)
	}
	if !hasWarning(sum, "stopped at 3 files; byte sum is partial") {
		t.Errorf("Warnings = %v, want a file-limit warning", sum.Warnings)
	}

	oldBudget := lfsWalkTimeBudget
	lfsWalkTimeBudget = -time.Second
	sum = surveyOK(t, repo)
	lfsWalkTimeBudget = oldBudget
	if sum.LFSObjectsBytes != 0 {
		t.Errorf("LFSObjectsBytes = %d, want 0 (deadline already passed)", sum.LFSObjectsBytes)
	}
	if !hasWarning(sum, "wall-clock budget") {
		t.Errorf("Warnings = %v, want a wall-clock warning", sum.Warnings)
	}
}

// Hostile branch names: git's refname format admits leading dashes and
// unicode but rejects spaces and control bytes (verified below so the
// battery's scope is honest). None of these names ever enters argv —
// every survey verb is a fixed shape — so hostile spellings cannot alter
// option parsing; the survey must simply report them.
func TestSurveyHostileBranchNames(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")

	hostile := []string{"--porcelain", "-O", "--flag=value", "branche-café", "日本ブランチ"}
	for _, name := range hostile {
		// update-ref creates refs the `git branch` UI refuses (verified:
		// git 2.49 rejects dash-leading names at the branch command).
		runGit(t, repo, "update-ref", "refs/heads/"+name, "HEAD")
	}
	// The boundary: names git itself refuses to store. If a future git
	// ever accepts these, this fails loudly and the battery must widen.
	if _, err := tryGit(t, repo, "branch", "--", "has space"); err == nil {
		t.Error("git accepted a space in a branch name; refname boundary moved — widen the battery")
	}
	if _, err := tryGit(t, repo, "branch", "--", "ctl\x01name"); err == nil {
		t.Error("git accepted a control byte in a branch name; refname boundary moved — widen the battery")
	}

	// Make a dash-leading hostile name the current branch.
	runGit(t, repo, "symbolic-ref", "HEAD", "refs/heads/--porcelain")
	runGit(t, repo, "reset", "-q", "--hard")

	sum := surveyOK(t, repo)
	if sum.Branch != "--porcelain" {
		t.Errorf("Branch = %q, want the hostile current branch name --porcelain", sum.Branch)
	}
	for _, want := range []string{"--flag=value", "-O", "branche-café", "main", "日本ブランチ"} {
		found := false
		for _, b := range sum.StaleMergedBranches {
			if b == want {
				found = true
			}
		}
		if !found {
			t.Errorf("StaleMergedBranches = %v, want it to contain %q", sum.StaleMergedBranches, want)
		}
	}
	for _, b := range sum.StaleMergedBranches {
		if b == "--porcelain" {
			t.Errorf("current hostile branch listed as stale: %v", sum.StaleMergedBranches)
		}
	}
	if len(sum.StaleMergedBranches) != 5 {
		t.Errorf("StaleMergedBranches = %v, want exactly 5 entries", sum.StaleMergedBranches)
	}
	// The verdicts operated normally: merged via main fallback, no
	// upstream; anything else means a hostile name derailed a verb.
	if !sum.MergedUpstream || sum.UnpushedCommits != -1 {
		t.Errorf("verdicts derailed by hostile names: merged=%v unpushed=%d",
			sum.MergedUpstream, sum.UnpushedCommits)
	}
	if len(sum.Warnings) != 1 || !hasWarning(sum, "no usable upstream") {
		t.Errorf("Warnings = %v, want only the no-upstream warning (hostile names broke nothing)",
			sum.Warnings)
	}
	if sum.LastActivityAt.IsZero() {
		t.Error("LastActivityAt zero under hostile branch names")
	}
}

// Full hostile-configuration battery over SurveyRepo (methodology of
// TestHostileFullRecipeNoWritesNoExecution): the control arm proves the
// attacks fire; the survey arm proves no execution and no .git writes
// while every survey verb runs.
func TestSurveyHostileConfigBattery(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeRepoFile(t, repo, ".gitattributes", "*.txt filter=evil\n")
	writeRepoFile(t, repo, "tracked.txt", "hello\n")
	commitAll(t, repo, "one")

	mark := t.TempDir()
	fsmMk := filepath.Join(mark, "fsmhook.mk")
	cleanMk := filepath.Join(mark, "cleansmudge.mk")
	picMk := filepath.Join(mark, "pic.mk")
	extMk := filepath.Join(mark, "extdiff.mk")
	aliasBuiltinMk := filepath.Join(mark, "alias-builtin.mk")
	aliasNonBuiltinMk := filepath.Join(mark, "alias-nonbuiltin.mk")
	fsmScript := markerScript(t, mark, "fsmhook", fsmMk)
	cleanScript := markerScript(t, mark, "cleansmudge", cleanMk)
	extScript := markerScript(t, mark, "extdiff", extMk)
	aliasBuiltinScript := markerScript(t, mark, "alias-builtin", aliasBuiltinMk)
	aliasNonBuiltinScript := markerScript(t, mark, "alias-nonbuiltin", aliasNonBuiltinMk)

	hooks := filepath.Join(mark, "evil-hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, "post-index-change"),
		[]byte("#!/bin/sh\ntouch '"+filepath.ToSlash(picMk)+"'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	attrs := filepath.Join(mark, "evil-attributes")
	if err := os.WriteFile(attrs, []byte("*.txt filter=evil diff=evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inc := filepath.Join(mark, "evil-included.conf")
	incContent := "[remote \"inc\"]\n\turl = https://example.com/inc.git\n" +
		"[alias]\n\tfrom-include = !" + gitConfigValue(aliasNonBuiltinScript) + "\n"
	if err := os.WriteFile(inc, []byte(incContent), 0o644); err != nil {
		t.Fatal(err)
	}

	runGit(t, repo, "-c", "core.fsmonitor=true", "update-index", "--fsmonitor")
	stopFsmonitorDaemon(t, repo)
	runGit(t, repo, "config", "core.fsmonitor", gitConfigValue(fsmScript))
	runGit(t, repo, "config", "core.attributesfile", gitConfigValue(attrs))
	runGit(t, repo, "config", "core.hooksPath", gitConfigValue(hooks))
	runGit(t, repo, "config", "diff.external", gitConfigValue(extScript))
	runGit(t, repo, "config", "diff.evil.textconv", gitConfigValue(extScript))
	runGit(t, repo, "config", "filter.evil.clean", gitConfigValue(cleanScript))
	runGit(t, repo, "config", "filter.evil.smudge", gitConfigValue(cleanScript))
	runGit(t, repo, "config", "alias.status", "!"+gitConfigValue(aliasBuiltinScript))
	runGit(t, repo, "config", "alias.rev-parse", "!"+gitConfigValue(aliasBuiltinScript))
	runGit(t, repo, "config", "alias.probe-evil", "!"+gitConfigValue(aliasNonBuiltinScript))
	runGit(t, repo, "config", "include.path", gitConfigValue(inc))

	// Control: plain status fires the index/worktree attack trio.
	for _, m := range []string{fsmMk, cleanMk, picMk} {
		resetMarker(t, m)
	}
	makeStatDirty(t, filepath.Join(repo, "tracked.txt"))
	runPlainGit(t, repo, nil, "status", "--porcelain=v2", "--branch")
	assertMarkerFired(t, fsmMk, "fsmonitor hook (survey fixture)")
	assertMarkerFired(t, cleanMk, "clean filter (survey fixture)")
	assertMarkerFired(t, picMk, "post-index-change hook (survey fixture)")

	// Hardened arm: survey under the full hostile configuration.
	for _, m := range []string{fsmMk, cleanMk, picMk, extMk, aliasBuiltinMk, aliasNonBuiltinMk} {
		resetMarker(t, m)
	}
	gitDir := filepath.Join(repo, ".git")
	snap := snapshotGitDir(t, gitDir)
	idxHash := fileSHA256(t, filepath.Join(gitDir, "index"))

	sum := surveyOK(t, repo)

	for _, m := range []string{fsmMk, cleanMk, picMk, extMk, aliasBuiltinMk, aliasNonBuiltinMk} {
		assertMarkerAbsent(t, m, "survey hostile fixture")
	}
	if !sameSnapshot(snap, snapshotGitDir(t, gitDir)) {
		t.Error("survey mutated .git (file set/sizes changed)")
	}
	if got := fileSHA256(t, filepath.Join(gitDir, "index")); got != idxHash {
		t.Error("survey rewrote .git/index")
	}

	// Survey quality under full hostility.
	if sum.Branch != "main" || !isHexCommit(sum.HeadCommit) {
		t.Errorf("HEAD facts degraded under hostility: %+v", sum)
	}
	if !sum.MergedUpstream || sum.UnpushedCommits != -1 {
		t.Errorf("verdicts degraded under hostility: merged=%v unpushed=%d",
			sum.MergedUpstream, sum.UnpushedCommits)
	}
	if sum.LastActivityAt.IsZero() {
		t.Error("LastActivityAt zero under hostility")
	}
}

func TestSurveyCancelledContext(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sum, err := SurveyRepo(ctx, repo)
	if err == nil {
		t.Fatalf("SurveyRepo with cancelled ctx succeeded, want error (summary %+v)", sum)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled in the chain", err)
	}
}

// The survey's argv surface is exactly the seven fixed shapes: every
// drifted variant — including the deliberately excluded `git show` —
// must be refused before any process spawns.
func TestSurveyAllowlistShapesFixed(t *testing.T) {
	accepted := [][]string{
		{"rev-parse", "--symbolic-full-name", "@{u}"},
		{"merge-base", "--is-ancestor", "HEAD", "@{u}"},
		{"merge-base", "--is-ancestor", "HEAD", "main"},
		{"merge-base", "--is-ancestor", "HEAD", "master"},
		{"rev-list", "--count", "@{u}..HEAD"},
		{"rev-list", "-1", "--format=%at", "HEAD"},
		{"for-each-ref", "--merged=HEAD", "--format=%(refname)", "refs/heads/"},
	}
	for _, argv := range accepted {
		if err := allowlistCheck(argv); err != nil {
			t.Errorf("allowlistCheck(%q) = %v, want accepted", argv, err)
		}
	}
	rejected := [][]string{
		// `show` intentionally absent: log-family porcelain honors
		// log.showSignature (config-driven gpg execution).
		{"show", "-s", "--format=%at", "HEAD"},
		{"branch", "--merged"}, // human format; for-each-ref is used instead
		{"merge-base", "--is-ancestor", "HEAD"},
		{"merge-base", "--is-ancestor", "HEAD", "main", "--extra"},
		{"merge-base", "--is-ancestor", "HEAD", "refs/heads/evil"}, // no repo data in argv
		{"merge-base", "--is-ancestor", "HEAD", "--", "main"},
		{"rev-list", "--count", "HEAD..@{u}"}, // reversed range
		{"rev-list", "-1", "--format=%at"},
		{"rev-list", "-1", "--format=%at", "HEAD", "HEAD"},
		{"for-each-ref", "--merged=HEAD", "--format=%(refname)"},
		{"for-each-ref", "--merged=HEAD", "--format=%(refname)", "refs/heads/", "extra"},
		{"for-each-ref", "--format=%(refname)", "refs/heads/"},
		{"rev-parse", "--symbolic-full-name"},
		{"rev-parse", "--symbolic-full-ref", "@{u}"}, // the wrong-flag variant
	}
	for _, argv := range rejected {
		if err := allowlistCheck(argv); err == nil {
			t.Errorf("allowlistCheck(%q) accepted, want rejected", argv)
		}
	}
}

// Synthetic topology classification: unexpected porcelain shapes
// degrade to warnings, never panics (spec rule 8).
func TestSurveyWorktreeTopologySynthetic(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "r")
	entries := []domain.GitWorktree{
		{Path: filepath.Join(string(filepath.Separator), "main")},
		{Path: root},
	}
	main, linked, warns := worktreeTopology(entries, root)
	if !linked || main != entries[0].Path {
		t.Errorf("topology = (%q, %v), want (%q, true)", main, linked, entries[0].Path)
	}
	if len(warns) != 0 {
		t.Errorf("warnings = %v, want none", warns)
	}

	// Root IS the main checkout (git always lists it first).
	main, linked, warns = worktreeTopology([]domain.GitWorktree{{Path: root}, {Path: entries[0].Path}}, root)
	if linked || main != "" || len(warns) != 0 {
		t.Errorf("main-checkout topology = (%q, %v, %v), want (\"\", false, none)", main, linked, warns)
	}

	// Root absent from the list: classification unavailable, warned.
	_, linked, warns = worktreeTopology([]domain.GitWorktree{{Path: entries[0].Path}}, root)
	if linked || len(warns) != 1 || !strings.Contains(warns[0], "did not report the surveyed root") {
		t.Errorf("absent-root topology = (%v, %v), want false + one warning", linked, warns)
	}

	// Entry without a path: ignored with a warning, never a panic.
	_, _, warns = worktreeTopology([]domain.GitWorktree{{Path: ""}, {Path: root}}, root)
	if len(warns) != 1 || !strings.Contains(warns[0], "entry without a path") {
		t.Errorf("empty-path topology warnings = %v, want one entry-without-path warning", warns)
	}
}
