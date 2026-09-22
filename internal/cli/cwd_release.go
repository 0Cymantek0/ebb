// cwd_release.go releases the process working directory from inside a
// workspace that is about to be RENAMED or REMOVED at its root (Wave 4
// gauntlet bug A).
//
// Windows semantics (Learnings, platform probe): a process's own cwd is
// an open directory handle without FILE_SHARE_DELETE, and Go stdlib
// opens carry no share-delete either — so a process whose working
// directory is the workspace root (or anywhere under it) pins the root
// against the §12.2 step-7 quarantine rename, and `ebb park` run from
// inside the workspace deterministically fails with errno 32. The same
// invocation from outside the root succeeds. The fix is at the CLI
// layer, immediately before the lifecycle park runs: move the process
// cwd out, visibly.
//
// Scope (verified against internal/lifecycle/removal.go): only the park
// tail renames or removes the workspace ROOT (renameToQuarantine +
// removeRoot, both park-only). Trim removes children under the live
// root and never the root itself (removeEmptyAncestors stops at the
// live root); delete/open never rename a live workspace root. Hence
// this helper is wired into cmd_park and the reclaim→park escalation
// ONLY.
//
// Caller contract: every path handed to the command (flags, discovery
// results) must already be ABSOLUTE — discovery resolves the root
// before this runs, and later steps use only discovery-derived absolute
// paths. After a successful move the process stays outside the root for
// the rest of the invocation (the park removes the tree; there is
// nothing to move back to).

package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/0Cymantek0/ebb/internal/pathcanon"
)

// releaseWorkspaceCwd moves the process working directory out of the
// workspace root when it lies inside the root (root == cwd or cwd under
// root, compared through the shared junction-aware canonicalizer — a
// cwd reached through a junction into the workspace pins the same
// directory). Target: the root's parent; on failure the state dir; on
// failure of both, proceed unmoved (the typed errno-32 blocker then
// fires and, with the SEALED --resume-removal door, names a working
// recovery command).
//
// The move is announced: a human note on the error stream in human
// mode, a warning in the JSON envelope in --json mode (never stdout —
// stdout carries the machine envelope alone). The note is honest about
// the limit of the fix: ebb can only move ITS OWN working directory; a
// SHELL still cd'd into the workspace holds its own pin, which ebb
// cannot release, and the note says so.
func releaseWorkspaceCwd(deps Deps, streams Streams, rootAbs string, env *Envelope, jsonOut bool) {
	cwd, err := os.Getwd()
	if err != nil {
		// The cwd cannot even be observed; proceed. If it does pin the
		// root, the park fails with the typed sharing-violation blocker
		// whose safe action is a working recovery door.
		return
	}
	rootCanon := pathcanon.CanonicalPath(rootAbs)
	cwdCanon := pathcanon.CanonicalPath(cwd)
	if !pathcanon.UnderPath(rootCanon, cwdCanon) {
		return // cwd already outside the workspace; nothing to release
	}

	target := filepath.Dir(rootCanon)
	if chdirErr := os.Chdir(target); chdirErr != nil {
		moved := false
		if deps.StateDir != nil {
			if dir, derr := deps.StateDir(); derr == nil && dir != "" {
				if os.Chdir(dir) == nil {
					target, moved = dir, true
				}
			}
		}
		if !moved {
			// Destructive work proceeds under the existing gates; if the
			// cwd really is the holder, the quarantine rename blocks with
			// the typed errno-32 error and the SEALED resume door governs.
			note := fmt.Sprintf(
				"note: the process working directory %s is inside the workspace and moving it out failed (%v); if the removal blocks with a sharing violation, that working directory is the likely holder",
				cwd, chdirErr)
			env.Warnings = append(env.Warnings, note)
			if !jsonOut {
				fmt.Fprintln(streams.Err, note)
			}
			return
		}
	}
	note := fmt.Sprintf(
		"note: ebb was launched with its working directory inside the workspace; it was moved to %s for the removal phase (ebb can only release its own handle — a shell still cd'd into the workspace pins the removal too; cd out of the workspace in that shell)",
		target)
	env.Warnings = append(env.Warnings, note)
	if !jsonOut {
		fmt.Fprintln(streams.Err, note)
	}
}
