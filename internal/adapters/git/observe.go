// Package gitadapter observes Git repository topology for an owned root
// using the hardened two-pass recipe validated in lab/git-probe and
// frozen as decision D004.
//
// Threat model (Foundation §9.1-9.2, §13.4): the repository's .git/config,
// the global config and the inherited environment are attacker-controlled.
// Observe extracts a domain.GitObservation with no execution of
// project-controlled code and no mutation of .git:
//
//   - the child environment is constructed, never inherited (env.go);
//   - pass 1 inventories the merged config; pass 2 empty-overrides every
//     execution-capable key it revealed (config.go, runner.go);
//   - only exact allowlisted builtin argv shapes ever run (runner.go);
//   - HEAD, operation markers, shallow, alternates, LFS and .gitmodules
//     are read directly as files (files.go, ini.go).
//
// "No config read" is explicitly not a goal: config must be read to be
// neutralized. Observations are diagnostics riding alongside preserved
// bytes; they never substitute for them and never authorize anything.
package gitadapter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ebb/internal/domain"
)

// maxListOutput bounds outputs that are only counted (ls-files --stage).
// Exceeding it produces a warning instead of unbounded memory.
const maxListOutput = 64 << 20 // 64 MiB

// Observe produces a GitObservation for rootPath.
//
// rootPath must be an existing directory. A path with no Git
// administration at or above it (with discovery ceiling-limited to
// rootPath's parent) yields IsRepo=false and a nil error — that is an
// observation, not a failure. An error is returned only for
// infrastructure failures (unusable root, git not runnable, timeout,
// cancelled context). Repo-level anomalies become Warnings and the
// observation continues on a best-effort basis; see Foundation §9.2
// ("already-corrupt repository: preserve readable bytes as evidence").
func Observe(ctx context.Context, rootPath string) (domain.GitObservation, error) {
	var obs domain.GitObservation
	if ctx == nil {
		ctx = context.Background()
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		return obs, fmt.Errorf("gitadapter: root: %w", err)
	}
	if !info.IsDir() {
		return obs, fmt.Errorf("gitadapter: root is not a directory: %s", rootPath)
	}
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return obs, fmt.Errorf("gitadapter: root: %w", err)
	}

	box, err := newEnvBox(absRoot)
	if err != nil {
		return obs, err
	}
	defer box.cleanup()
	r := &runner{env: box.env}

	// git --version: run once, no repository needed (allowlisted). The
	// hardening recipe is version-specific, so the version is recorded
	// with every observation (D004).
	verOut, _, verRc, err := r.run(ctx, box.dir, versionTimeout, "--version")
	if err != nil {
		return obs, fmt.Errorf("gitadapter: git --version: %w", err)
	}
	if verRc != 0 {
		return obs, fmt.Errorf("gitadapter: git --version exited %d", verRc)
	}
	obs.GitVersion = firstLine(verOut)

	// ---- Pass 1: config inventory -------------------------------------
	cfgOut, cfgErrStr, cfgRc, err := r.run(ctx, absRoot, commandTimeout,
		"config", "--list", "--show-origin", "--show-scope")
	if err != nil {
		return obs, fmt.Errorf("gitadapter: config inventory: %w", err)
	}
	inv := parseConfigList(cfgOut)
	if len(cfgOut) > maxConfigOutput {
		obs.Warnings = append(obs.Warnings,
			"config inventory exceeded "+strconv.Itoa(maxConfigOutput)+" bytes; neutralization covers the truncated view only")
	}
	if cfgRc != 0 {
		// Distinguish "no repository here" from "repository with an
		// unreadable config": the rev-parse triplet is allowlisted and
		// repository-agnostic.
		_, _, rpRc, rpErr := r.run(ctx, absRoot, commandTimeout,
			"rev-parse", "--git-dir", "--git-common-dir", "--absolute-git-dir")
		if rpErr != nil {
			return obs, rpErr
		}
		if rpRc != 0 {
			// Genuinely no repository (or discovery ceiling-contained).
			return obs, nil
		}
		obs.Warnings = append(obs.Warnings,
			"config inventory failed (exit "+strconv.Itoa(cfgRc)+"): "+firstLine(cfgErrStr)+
				"; static neutralization only")
	}
	if len(inv.unneutralizable) > 0 {
		// GIT-NEUT-2: an execution key no -c spelling can neutralize is
		// present. The argv allowlist contains no filter-applying command
		// today, but proceeding with a known-live execution key violates
		// the fail-closed rule; refuse observation entirely.
		return obs, fmt.Errorf("gitadapter: refusing observation: repository config contains execution keys that cannot be neutralized (subsection contains '='): %q", inv.unneutralizable[0])
	}
	r.overrides = inv.overrideArgs()

	// ---- Pass 2: allowlisted observations ------------------------------
	// Git-dir triplet. Failure here (with pass 1 also failing) means no
	// repository; a solo failure is reported as a warning and the
	// observation stops — nothing downstream is meaningful without it.
	out, _, rc, err := r.run(ctx, absRoot, commandTimeout,
		"rev-parse", "--git-dir", "--git-common-dir", "--absolute-git-dir")
	if err != nil {
		return obs, err
	}
	if rc != 0 {
		return obs, nil // not a repository
	}
	lines := nonEmptyLines(out)
	if len(lines) != 3 {
		return obs, fmt.Errorf("gitadapter: rev-parse git-dir triplet returned %d lines: %q", len(lines), firstLine(out))
	}
	gitDir := canonicalForm(filepath.Clean(lines[2])) // --absolute-git-dir (absolute)
	commonDir := canonicalForm(resolveAgainst(lines[1], absRoot))
	obs.IsRepo = true
	obs.GitDir = gitDir
	obs.CommonDir = commonDir

	// Work-tree containment (A2). A bare repository reports false here and
	// skips work-tree-scoped commands below.
	insideWorkTree := false
	toplevel := ""
	out, _, rc, err = r.run(ctx, absRoot, commandTimeout,
		"rev-parse", "--is-inside-work-tree", "--show-toplevel")
	if err != nil {
		return obs, err
	}
	if rc == 0 {
		l := nonEmptyLines(out)
		if len(l) >= 1 && l[0] == "true" {
			insideWorkTree = true
			if len(l) >= 2 && l[1] != "" {
				toplevel = canonicalForm(filepath.Clean(l[1]))
			}
		}
	}
	if !insideWorkTree {
		obs.Warnings = append(obs.Warnings, "root is not inside a work tree (bare repository?); status and index observations skipped")
	}

	// Containment root in git's own canonical path form (D004 rule 5).
	// The caller's rootPath spelling can differ cosmetically from what
	// git reports (Windows 8.3 short names, forward/back slashes), while
	// the discovery ceiling guarantees the repository was found AT the
	// root — so containment compares the git-reported toplevel (or, for
	// a bare repository, the git dir itself) against the git-reported
	// git dir and common dir. All three come from the same getcwd-derived
	// form; no symlink resolution is performed on any of them.
	containmentRoot := absRoot
	if insideWorkTree && toplevel != "" {
		containmentRoot = toplevel
	} else if !insideWorkTree {
		containmentRoot = gitDir
	}
	canonRoot := canonicalForm(absRoot) // caller spelling may be 8.3-short; git reports long form
	adminInRoot := adminInside(canonRoot, gitDir) && adminInside(canonRoot, commonDir)
	obs.AdminInsideRoot = adminInside(containmentRoot, gitDir) &&
		adminInside(containmentRoot, commonDir)
	// GIT-WT-1: a repository whose administration lives INSIDE the
	// observed root must have its work tree AT the root. A hostile
	// core.worktree pointing elsewhere (e.g. an ancestor) makes the
	// allowlisted status enumerate far outside the workspace; refuse
	// before any work-tree-scoped command runs. (A workspace that is a
	// subdirectory of a larger repository has its admin OUTSIDE the
	// root and is not affected.)
	if adminInRoot && insideWorkTree && toplevel != "" && toplevel != canonRoot {
		return obs, fmt.Errorf("gitadapter: refusing observation: repository administration is inside the root but its work tree is %q (core.worktree override?); git status would enumerate outside the workspace", toplevel)
	}

	// HEAD state (A3/A4 + direct file read). Unborn: symbolic-ref resolves
	// but HEAD has no commit. Detached: symbolic-ref reports "not a
	// symbolic ref" while a commit resolves.
	headBranchFile, headHexFile := readHeadState(gitDir)
	symOut, symErr, symRc, err := r.run(ctx, absRoot, commandTimeout, "symbolic-ref", "HEAD")
	if err != nil {
		return obs, err
	}
	var headBranch string
	if symRc == 0 {
		headBranch = firstLine(symOut)
	} else if !strings.Contains(symErr, "not a symbolic ref") {
		obs.Warnings = append(obs.Warnings,
			"symbolic-ref HEAD exited "+strconv.Itoa(symRc)+": "+firstLine(symErr))
	}
	rpOut, _, rpRc, err := r.run(ctx, absRoot, commandTimeout, "rev-parse", "HEAD")
	if err != nil {
		return obs, err
	}
	headCommit := ""
	if rpRc == 0 {
		headCommit = firstLine(rpOut)
	}
	if headBranch == "" && headBranchFile != "" {
		// symbolic-ref failed for a reason other than "not a symbolic
		// ref"; the direct HEAD read is the documented fallback.
		headBranch = headBranchFile
	}
	if headBranch != "" {
		obs.HeadBranch = headBranch
		if headCommit == "" {
			obs.Unborn = true
		}
	} else if headCommit != "" || headHexFile != "" {
		obs.Detached = true
		if headCommit == "" {
			obs.HeadCommit = headHexFile
			obs.Warnings = append(obs.Warnings,
				"rev-parse HEAD failed; commit id taken from direct HEAD read")
		}
	} else {
		obs.Warnings = append(obs.Warnings, "HEAD is neither symbolic nor a resolvable commit id")
	}
	if headCommit != "" {
		obs.HeadCommit = headCommit
	}

	// Working state (A5, A6, A11). Status and the index exist only inside
	// a work tree; stash/reflog/remotes/worktrees are common-dir facts.
	if insideWorkTree {
		stOut, stErr, stRc, err := r.run(ctx, absRoot, commandTimeout,
			"status", "--porcelain=v2", "--branch", "--ignore-submodules=all")
		if err != nil {
			return obs, err
		}
		if stRc != 0 {
			obs.Warnings = append(obs.Warnings,
				"status exited "+strconv.Itoa(stRc)+": "+firstLine(stErr))
		} else {
			c := parsePorcelainV2(stOut)
			obs.UnmergedEntries = c.unmerged
			obs.UntrackedEntries = c.untracked
			obs.DirtyWorktree = c.dirty
		}

		lsOut, lsErr, lsRc, err := r.run(ctx, absRoot, commandTimeout, "ls-files", "--stage")
		if err != nil {
			return obs, err
		}
		if lsRc != 0 {
			obs.Warnings = append(obs.Warnings,
				"ls-files --stage exited "+strconv.Itoa(lsRc)+": "+firstLine(lsErr))
		} else {
			if len(lsOut) > maxListOutput {
				obs.Warnings = append(obs.Warnings, "ls-files output exceeded size bound; index entry count is a lower bound")
			}
			obs.StagedEntries = countNonEmptyLines(lsOut)
		}
	}

	stashOut, _, stashRc, err := r.run(ctx, absRoot, commandTimeout, "stash", "list", "--format=%H")
	if err != nil {
		return obs, err
	}
	if stashRc == 0 {
		obs.StashCount = countNonEmptyLines(stashOut)
	} else {
		obs.Warnings = append(obs.Warnings, "stash list exited "+strconv.Itoa(stashRc))
	}

	// Reflogs (A7) cross-checked against the raw logs/ files (direct
	// read). A mismatch usually means extensions.refstorage=reftable,
	// where reflogs live inside the reftable files (lab/git-probe O14/O27).
	rlOut, rlErr, rlRc, err := r.run(ctx, absRoot, commandTimeout,
		"reflog", "show", "--format=%H", "HEAD")
	if err != nil {
		return obs, err
	}
	gitReflog := int64(-1)
	if rlRc == 0 {
		gitReflog = countNonEmptyLines(rlOut)
	}
	if logsHead := firstExisting(
		filepath.Join(gitDir, "logs", "HEAD"),
		filepath.Join(commonDir, "logs", "HEAD"),
	); logsHead != "" {
		n := countFileLines(logsHead)
		switch {
		case gitReflog < 0:
			obs.Warnings = append(obs.Warnings,
				"git reflog show HEAD failed while logs/HEAD exists: "+firstLine(rlErr))
		case gitReflog != n:
			obs.Warnings = append(obs.Warnings,
				fmt.Sprintf("HEAD reflog mismatch: logs/HEAD has %d lines, git reflog show reports %d (reftable refstorage?)", n, gitReflog))
		}
	}
	if stashLogs := firstExisting(
		filepath.Join(gitDir, "logs", "refs", "stash"),
		filepath.Join(commonDir, "logs", "refs", "stash"),
	); stashLogs != "" {
		srOut, _, srRc, err := r.run(ctx, absRoot, commandTimeout,
			"reflog", "show", "--format=%H", "refs/stash")
		if err != nil {
			return obs, err
		}
		if srRc == 0 {
			if n := countNonEmptyLines(srOut); n != obs.StashCount {
				obs.Warnings = append(obs.Warnings,
					fmt.Sprintf("stash reflog has %d entries but stash list reported %d", n, obs.StashCount))
			}
		}
	}

	// Remotes (A8).
	remOut, remErr, remRc, err := r.run(ctx, absRoot, commandTimeout, "remote", "-v")
	if err != nil {
		return obs, err
	}
	if remRc != 0 {
		obs.Warnings = append(obs.Warnings,
			"remote -v exited "+strconv.Itoa(remRc)+": "+firstLine(remErr))
	} else {
		obs.Remotes = parseRemoteV(remOut)
	}

	// Worktree family (A10).
	wtOut, wtErr, wtRc, err := r.run(ctx, absRoot, commandTimeout, "worktree", "list", "--porcelain")
	if err != nil {
		return obs, err
	}
	if wtRc != 0 {
		obs.Warnings = append(obs.Warnings,
			"worktree list exited "+strconv.Itoa(wtRc)+": "+firstLine(wtErr))
	} else {
		obs.Worktrees = parseWorktreePorcelain(wtOut)
	}

	// ---- Direct file reads (D004 rule 4) --------------------------------
	obs.MergeInProgress = fileExists(filepath.Join(gitDir, "MERGE_HEAD"))
	obs.RebaseInProgress = dirExists(filepath.Join(gitDir, "rebase-merge")) ||
		dirExists(filepath.Join(gitDir, "rebase-apply"))
	obs.CherryPickInProgress = fileExists(filepath.Join(gitDir, "CHERRY_PICK_HEAD"))
	obs.RevertInProgress = fileExists(filepath.Join(gitDir, "REVERT_HEAD"))
	obs.HasShallow = fileExists(filepath.Join(gitDir, "shallow")) ||
		fileExists(filepath.Join(commonDir, "shallow"))
	obs.HasAlternates = fileExists(filepath.Join(commonDir, "objects", "info", "alternates")) ||
		fileExists(filepath.Join(gitDir, "objects", "info", "alternates"))
	obs.HasLFS = dirExists(filepath.Join(gitDir, "lfs")) ||
		dirExists(filepath.Join(commonDir, "lfs")) ||
		inv.hasPrefixKey("filter.lfs.")
	obs.IsPartialClone = inv.isPartialClone()
	if v := inv.values["extensions.objectformat"]; v != "" {
		obs.ObjectFormat = strings.ToLower(v)
	} else {
		obs.ObjectFormat = "sha1"
	}

	// .gitmodules: parsed as INI in pure Go; submodules are never
	// initialized (Foundation §9.2). Read ONLY at a toplevel that is
	// the observed root itself: an empty toplevel would join to a
	// PROCESS-CWD-relative ".gitmodules" (GIT-GM-1), and a toplevel
	// outside the root belongs to a different scope than this
	// workspace.
	if toplevel == "" {
		obs.Warnings = append(obs.Warnings, ".gitmodules not inspected: no work-tree toplevel reported")
	} else {
		gmPath := filepath.Join(toplevel, ".gitmodules")
		if toplevel != canonRoot {
			obs.Warnings = append(obs.Warnings, ".gitmodules not inspected: toplevel is outside the observed root")
		} else if _, statErr := os.Stat(gmPath); statErr == nil {
			data, readErr := os.ReadFile(gmPath)
			if readErr != nil {
				obs.Warnings = append(obs.Warnings, ".gitmodules unreadable: "+readErr.Error())
			} else {
				obs.Submodules = parseGitmodulesINI(data)
			}
		}
	}

	return obs, nil
}

// resolveAgainst absolutizes a git-reported path that may be relative
// (e.g. ".git" or "../..") against the observation root, which is the cwd
// git resolved it from.
func resolveAgainst(p, root string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(root, p))
}

// firstLine returns the first line of captured output, trimmed.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(strings.TrimRight(s, "\r"))
}

// nonEmptyLines splits captured output into trimmed non-empty lines.
func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// countNonEmptyLines counts non-empty lines of captured output.
func countNonEmptyLines(s string) int64 {
	var n int64
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimRight(line, "\r") != "" {
			n++
		}
	}
	return n
}
