// Repository survey (D037 deep-git alignment): the workspace-triage
// facts `ebb analyse` consumes layered on top of the hardened observer.
//
// SurveyRepo reuses Observe internally (branch, dirty, unmerged and
// commit facts are copied, never re-derived) and extends it with:
// worktree topology (main checkout vs linked worktree), upstream merge
// state, unpushed commit count, HEAD author time, stale fully-merged
// local branches, and LFS object bloat.
//
// Hardening contract (D004/D005, unchanged):
//
//   - Every subprocess goes through run()'s exact-argv allowlist with
//     the constructed environment and two-pass config neutralization
//     (a second session built exactly the way TrackedFiles builds its
//     own; Observe's session cannot be reused across calls).
//   - Every survey argv shape is FULLY FIXED: no repository-controlled
//     data (branch names, remote names, paths) ever enters argv, so
//     hostile spellings cannot alter option parsing. Verdicts over a
//     variable ref use the fixed literals @{u}, main and master.
//   - `git show` was deliberately NOT allowlisted for the author
//     timestamp: the log-family porcelain honors log.showSignature, a
//     config knob that can spawn gpg and sits outside the D004
//     neutralization set. `rev-list -1 --format=%at HEAD` is plumbing
//     with no signature path and yields the same fact.
//   - LFS bloat is a direct bounded filesystem walk of the resolved
//     common dir's lfs/objects tree (linked worktrees share the main
//     checkout's objects through commondir). git-lfs itself is a
//     non-builtin and is never invoked (O21).
package gitadapter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// maxStaleBranches caps the stale merged branch list; beyond it the
// list is truncated with a warning (spec rule 6).
const maxStaleBranches = 50

// LFS walk budgets (spec rule 7: <=10k files, <=1s wall). Variables so
// tests can exercise the truncation paths without materializing 10k
// files; the production values are the spec defaults.
var (
	lfsWalkFileLimit  = 10000
	lfsWalkTimeBudget = time.Second
)

// RepoSummary is the repository survey consumed by `ebb analyse`
// (D037). Unknown values are explicit sentinels with a matching
// Warnings entry so consumers can tell known-false from unknown.
type RepoSummary struct {
	IsRepo bool `json:"is_repo"`

	// Branch is the display form of HEAD's branch ("refs/heads/"
	// stripped); "" on detached HEAD.
	Branch string `json:"branch,omitempty"`
	// HeadCommit is HEAD's object id; "" on an unborn branch.
	HeadCommit string `json:"head_commit,omitempty"`
	Detached   bool   `json:"detached"`

	// Working state (copied from the Observe observation).
	DirtyWorktree   bool  `json:"dirty_worktree"`
	UnmergedEntries int64 `json:"unmerged_entries"`

	// Worktree topology: IsWorktree reports that the surveyed root is a
	// linked worktree of a main checkout; WorktreeMain is that main
	// checkout's path ("" when the root IS the main checkout).
	IsWorktree   bool   `json:"is_worktree"`
	WorktreeMain string `json:"worktree_main,omitempty"`

	// MergedUpstream: HEAD is an ancestor of the current branch's
	// upstream, or of main/master when no upstream exists. False with a
	// warning means the verdict could not be established.
	MergedUpstream bool `json:"merged_upstream"`
	// UnpushedCommits counts @{u}..HEAD; -1 = no usable upstream (never
	// silently zero).
	UnpushedCommits int64 `json:"unpushed_commits"`
	// LastActivityAt is the HEAD commit's author time (UTC); zero time
	// = unknown (unborn or unresolvable HEAD).
	LastActivityAt time.Time `json:"last_activity_at,omitempty"`

	// StaleMergedBranches lists local branches fully merged into HEAD,
	// excluding the current branch, display-form, capped at
	// maxStaleBranches entries.
	StaleMergedBranches []string `json:"stale_merged_branches,omitempty"`

	// LFSObjectsBytes sums file sizes under <commondir>/lfs/objects
	// (bounded walk); 0 when the directory is absent, -1 when it exists
	// but cannot be surveyed.
	LFSObjectsBytes int64 `json:"lfs_objects_bytes"`

	Warnings []string `json:"warnings,omitempty"`
}

// SurveyRepo surveys the repository at rootPath.
//
// rootPath must be an existing directory. A path with no Git
// administration at or above it (discovery ceiling-limited to rootPath's
// parent, exactly like Observe) yields IsRepo=false and a nil error —
// that is an observation, not a failure. An error is returned only for
// infrastructure failures (unusable root, git not runnable, timeout,
// cancelled context); survey-level anomalies become Warnings and the
// survey continues on a best-effort basis.
func SurveyRepo(ctx context.Context, rootPath string) (RepoSummary, error) {
	var sum RepoSummary
	if ctx == nil {
		ctx = context.Background()
	}

	// Reuse, never duplicate: everything Observe already observes is
	// copied from its observation (spec rule 1).
	obs, err := Observe(ctx, rootPath)
	if err != nil {
		return sum, err
	}
	sum.IsRepo = obs.IsRepo
	sum.Warnings = append(sum.Warnings, obs.Warnings...)
	if !obs.IsRepo {
		return sum, nil
	}
	sum.Branch = displayBranch(obs.HeadBranch)
	sum.HeadCommit = obs.HeadCommit
	sum.Detached = obs.Detached
	sum.DirtyWorktree = obs.DirtyWorktree
	sum.UnmergedEntries = obs.UnmergedEntries

	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return sum, fmt.Errorf("gitadapter: root: %w", err)
	}

	// Worktree topology, from the observation's already-parsed porcelain.
	mainPath, linked, topoWarnings := worktreeTopology(obs.Worktrees, absRoot)
	sum.IsWorktree = linked
	sum.WorktreeMain = mainPath
	sum.Warnings = append(sum.Warnings, topoWarnings...)

	// LFS bloat: direct bounded walk, no git involved.
	lfsBytes, lfsWarnings := lfsObjectsSize(obs.GitDir, obs.CommonDir)
	sum.LFSObjectsBytes = lfsBytes
	sum.Warnings = append(sum.Warnings, lfsWarnings...)

	// Survey verbs run in their own constructed-environment session with
	// the same two-pass neutralization (TrackedFiles precedent).
	box, err := newEnvBox(absRoot)
	if err != nil {
		return sum, err
	}
	defer box.cleanup()
	r := &runner{env: box.env}
	cfgOut, _, cfgRc, err := r.run(ctx, absRoot, commandTimeout,
		"config", "--list", "--show-origin", "--show-scope")
	if err != nil {
		return sum, fmt.Errorf("gitadapter: config inventory: %w", err)
	}
	if cfgRc == 0 {
		inv := parseConfigList(cfgOut)
		if len(inv.unneutralizable) > 0 {
			// Same fail-closed rule as Observe (GIT-NEUT-2): never run
			// even allowlisted commands with a live execution key.
			return sum, fmt.Errorf("gitadapter: refusing survey: repository config contains execution keys that cannot be neutralized (subsection contains '='): %q", inv.unneutralizable[0])
		}
		r.overrides = inv.overrideArgs()
	}
	// cfgRc != 0 degrades to static neutralization only; Observe has
	// already recorded the warning and proved repository-ness.

	// ---- Upstream presence ----------------------------------------------
	_, upErr, upRc, err := r.run(ctx, absRoot, commandTimeout,
		"rev-parse", "--symbolic-full-name", "@{u}")
	if err != nil {
		return sum, err
	}
	// rc 0 <=> a usable upstream exists: with branch.<name>.remote/merge
	// configured but the remote-tracking ref missing, @{u} also fails to
	// resolve (verified against git 2.49) and is honestly reported as no
	// usable upstream.
	hasUpstream := upRc == 0
	if !hasUpstream {
		sum.UnpushedCommits = -1
		sum.Warnings = append(sum.Warnings,
			"no usable upstream for HEAD (rev-parse @{u} exited "+strconv.Itoa(upRc)+": "+firstLineClean(upErr)+
				"); unpushed commit count unknown (reported -1)")
	} else {
		out, errStr, rc, err := r.run(ctx, absRoot, commandTimeout,
			"rev-list", "--count", "@{u}..HEAD")
		if err != nil {
			return sum, err
		}
		switch {
		case rc == 0:
			if n, perr := strconv.ParseInt(firstLineClean(out), 10, 64); perr == nil {
				sum.UnpushedCommits = n
			} else {
				sum.UnpushedCommits = -1
				sum.Warnings = append(sum.Warnings,
					fmt.Sprintf("unparseable rev-list count %q; unpushed commit count unknown (reported -1)", firstLineClean(out)))
			}
		default:
			sum.UnpushedCommits = -1
			sum.Warnings = append(sum.Warnings,
				fmt.Sprintf("rev-list --count @{u}..HEAD exited %d: %s; unpushed commit count unknown (reported -1)",
					rc, firstLineClean(errStr)))
		}
	}

	// ---- Merged-upstream verdict ----------------------------------------
	if hasUpstream {
		merged, known, detail, err := headAncestorOf(ctx, r, absRoot, "@{u}")
		if err != nil {
			return sum, err
		}
		if known {
			sum.MergedUpstream = merged
		} else {
			sum.Warnings = append(sum.Warnings,
				"merge-base --is-ancestor vs @{u} "+detail+
					"; merged-upstream state unknown (reported false)")
		}
	} else {
		decided := false
		for _, candidate := range []string{"main", "master"} {
			merged, known, _, err := headAncestorOf(ctx, r, absRoot, candidate)
			if err != nil {
				return sum, err
			}
			if !known {
				continue // ref does not exist or is unusable: try the next
			}
			sum.MergedUpstream = merged
			decided = true
			break
		}
		if !decided {
			sum.Warnings = append(sum.Warnings,
				"no upstream branch and neither main nor master exists; merged-upstream state unknown (reported false)")
		}
	}

	// ---- Last activity: HEAD commit author time (epoch, never locale) --
	out, errStr, rc, err := r.run(ctx, absRoot, commandTimeout,
		"rev-list", "-1", "--format=%at", "HEAD")
	if err != nil {
		return sum, err
	}
	lines := nonEmptyLines(out)
	switch {
	case rc != 0:
		sum.Warnings = append(sum.Warnings,
			fmt.Sprintf("HEAD author time unavailable: rev-list --format=%%at exited %d: %s", rc, firstLineClean(errStr)))
	case len(lines) == 0:
		sum.Warnings = append(sum.Warnings, "HEAD author time unavailable: rev-list --format=%at produced no output")
	default:
		// rev-list --format output is "commit <oid>\n<formatted>"; the
		// timestamp is the final line.
		if sec, perr := strconv.ParseInt(lines[len(lines)-1], 10, 64); perr == nil {
			sum.LastActivityAt = time.Unix(sec, 0).UTC()
		} else {
			sum.Warnings = append(sum.Warnings,
				fmt.Sprintf("unparseable author timestamp %q; last activity unknown", lines[len(lines)-1]))
		}
	}

	// ---- Stale fully-merged local branches --------------------------------
	out, errStr, rc, err = r.run(ctx, absRoot, commandTimeout,
		"for-each-ref", "--merged=HEAD", "--format=%(refname)", "refs/heads/")
	if err != nil {
		return sum, err
	}
	if rc != 0 {
		sum.Warnings = append(sum.Warnings,
			fmt.Sprintf("for-each-ref --merged=HEAD exited %d: %s; stale merged branches unknown", rc, firstLineClean(errStr)))
	} else {
		var stale []string
		truncated := false
		for _, ref := range nonEmptyLines(out) {
			// The current branch is trivially merged into itself and is
			// never "stale"; on detached HEAD there is no current branch
			// to exclude (obs.HeadBranch is "" and matches nothing).
			if ref == obs.HeadBranch {
				continue
			}
			if len(stale) >= maxStaleBranches {
				truncated = true
				break
			}
			stale = append(stale, displayBranch(ref))
		}
		if truncated {
			sum.Warnings = append(sum.Warnings,
				fmt.Sprintf("stale merged branch list truncated at %d entries", maxStaleBranches))
		}
		sum.StaleMergedBranches = stale
	}

	return sum, nil
}

// headAncestorOf resolves the allowlisted verdict "HEAD is an ancestor
// of ref" via merge-base --is-ancestor: exit 0 = merged, exit 1 = not
// merged, any other exit = the verdict could not be established
// (typically the ref does not exist) and is reported as unknown with a
// detail string, never as a false verdict.
func headAncestorOf(ctx context.Context, r *runner, dir, ref string) (merged, known bool, detail string, err error) {
	_, errStr, rc, err := r.run(ctx, dir, commandTimeout,
		"merge-base", "--is-ancestor", "HEAD", ref)
	if err != nil {
		return false, false, "", err
	}
	switch rc {
	case 0:
		return true, true, "", nil
	case 1:
		return false, true, "", nil
	default:
		return false, false, fmt.Sprintf("exited %d: %s", rc, firstLineClean(errStr)), nil
	}
}

// worktreeTopology classifies the surveyed root against the observed
// `worktree list --porcelain` entries. Git always reports the main
// worktree first; a root matching any later entry is a linked worktree
// and the first entry is its main checkout. Paths round-trip through
// the same canonicalization Observe applies to git-reported paths
// (filepath.Clean then canonicalForm: porcelain prints forward-slash
// forms on Windows, and 8.3 short spellings expand to long forms).
func worktreeTopology(entries []domain.GitWorktree, root string) (mainPath string, linked bool, warnings []string) {
	canonRoot := canonicalForm(filepath.Clean(root))
	idx := -1
	for i, e := range entries {
		if e.Path == "" {
			warnings = append(warnings, "worktree list entry without a path; entry ignored")
			continue
		}
		if pathIdentical(canonRoot, canonicalForm(filepath.Clean(e.Path))) {
			idx = i
			break
		}
	}
	if idx < 0 {
		warnings = append(warnings,
			"worktree list did not report the surveyed root; linked-worktree classification unavailable")
		return "", false, warnings
	}
	if idx == 0 {
		return "", false, warnings // the surveyed root IS the main checkout
	}
	return canonicalForm(filepath.Clean(entries[0].Path)), true, warnings
}

// lfsObjectsSize sums regular file sizes under the LFS objects tree
// resolved through the repo's administration. The common dir is
// preferred (linked worktrees share the main checkout's lfs/objects
// through commondir); a missing directory is 0, an existing but
// unsurveyable path is -1 with a warning.
func lfsObjectsSize(gitDir, commonDir string) (int64, []string) {
	for i, base := range []string{commonDir, gitDir} {
		if base == "" {
			continue
		}
		if i == 1 && pathIdentical(commonDir, gitDir) {
			break // same directory; a second walk would double-count
		}
		dir := filepath.Join(base, "lfs", "objects")
		fi, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue // absent LFS storage is 0 bytes, not unknown
			}
			return -1, []string{fmt.Sprintf("lfs objects path %s unreadable (%v); lfs object bytes unknown (reported -1)", dir, err)}
		}
		if !fi.IsDir() {
			return -1, []string{fmt.Sprintf("lfs objects path %s exists but is not a directory; lfs object bytes unknown (reported -1)", dir)}
		}
		n, warning := walkLFSObjects(dir)
		if warning != "" {
			return n, []string{warning}
		}
		return n, nil
	}
	return 0, nil
}

// walkLFSObjects walks the LFS objects directory under the file-count
// and wall-clock budgets, summing regular file sizes. Links are opaque
// leaves: the link test follows the project rule (ModeSymlink OR
// ModeIrregular — Go reports NTFS junctions as ModeIrregular, with or
// without ModeDir depending on the Go version), so a junction inside
// .git/lfs/objects is never descended into even when it carries the
// directory bit. Exceeding either budget stops the walk with a partial
// sum and a warning.
func walkLFSObjects(dir string) (bytes int64, warning string) {
	deadline := time.Now().Add(lfsWalkTimeBudget)
	files := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			warning = "lfs objects walk exceeded wall-clock budget; byte sum is partial"
			return fs.SkipAll
		}
		if mode := d.Type(); mode&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			// Opaque link (symlink or junction): a directory-shaped one
			// is skipped whole; SkipDir on a file-shaped one would skip
			// the remaining siblings, so a leaf is simply not counted.
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if files >= lfsWalkFileLimit {
			warning = fmt.Sprintf("lfs objects walk stopped at %d files; byte sum is partial", lfsWalkFileLimit)
			return fs.SkipAll
		}
		files++
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		bytes += info.Size()
		return nil
	})
	if errors.Is(err, fs.SkipAll) {
		err = nil
	}
	if err != nil && warning == "" {
		warning = fmt.Sprintf("lfs objects walk stopped on error (%v); byte sum is partial", err)
	}
	return bytes, warning
}

// stripControlChars removes terminal-control bytes (anything below 0x20
// and DEL 0x7f) from git-provided text before it is embedded into
// warnings: git stderr is external text and ANSI escapes must not echo
// into ebb's human stream (terminal-injection hardening). Each control
// byte becomes a space; UTF-8 continuation bytes are always >= 0x80 so
// the byte-level pass cannot damage multi-byte runes.
func stripControlChars(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// firstLineClean is firstLine with control characters stripped: the
// form used whenever git output is embedded into summary warnings.
func firstLineClean(s string) string { return stripControlChars(firstLine(s)) }

// displayBranch strips the refs/heads/ prefix for summary display.
func displayBranch(ref string) string {
	return strings.TrimPrefix(ref, "refs/heads/")
}

// pathIdentical compares two already-cleaned paths with the platform's
// case sensitivity (Windows filesystems are case-insensitive; the same
// rule adminInside applies).
func pathIdentical(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
