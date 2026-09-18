package gitadapter

import (
	"strings"

	"ebb/internal/domain"
)

// Parsers for the allowlisted commands' machine-readable outputs. They
// consume captured stdout only and never interpret content as paths to
// follow or programs to run.

// statusCounts summarizes `git status --porcelain=v2 --branch
// --ignore-submodules=all` output.
type statusCounts struct {
	unmerged  int64 // "u " conflict-stage lines (one per unmerged path)
	untracked int64 // "? " entries (collapsed directories count once)
	changed   int64 // "1 "/"2 " ordinary/rename entries
	dirty     bool  // any 1/2/u/? entry at all
}

// parsePorcelainV2 counts porcelain v2 record lines. Branch headers
// ("# ...") never count; ignored entries ("! ", only present with
// --ignored) are not requested and not counted as dirt.
func parsePorcelainV2(out string) statusCounts {
	var c statusCounts
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "u "):
			c.unmerged++
			c.dirty = true
		case strings.HasPrefix(line, "? "):
			c.untracked++
			c.dirty = true
		case strings.HasPrefix(line, "1 "), strings.HasPrefix(line, "2 "):
			c.changed++
			c.dirty = true
		}
	}
	return c
}

// parseRemoteV parses `git remote -v`: lines of
// `<name>\t<url> (fetch)` / `<name>\t<url> (push)`. Remote names are
// deduplicated; fetch and push URLs are recorded per name. `url.*.insteadOf`
// rewriting is pure string substitution and cannot execute (O9).
func parseRemoteV(out string) []domain.GitRemote {
	var order []string
	byName := map[string]*domain.GitRemote{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		name, rest := line[:tab], line[tab+1:]
		var kind, url string
		switch {
		case strings.HasSuffix(rest, " (fetch)"):
			kind, url = "fetch", strings.TrimSuffix(rest, " (fetch)")
		case strings.HasSuffix(rest, " (push)"):
			kind, url = "push", strings.TrimSuffix(rest, " (push)")
		default:
			continue
		}
		r, ok := byName[name]
		if !ok {
			r = &domain.GitRemote{Name: name}
			byName[name] = r
			order = append(order, name)
		}
		if kind == "fetch" {
			r.URL = url
		} else {
			r.Push = url
		}
	}
	if len(order) == 0 {
		return nil
	}
	remotes := make([]domain.GitRemote, 0, len(order))
	for _, n := range order {
		remotes = append(remotes, *byName[n])
	}
	return remotes
}

// parseWorktreePorcelain parses `git worktree list --porcelain`.
//
// Every administrative worktree entry is returned, including the main
// worktree (and a bare entry for bare repositories). The frozen
// GitObservation contract derives EBB_E_SHARED_GIT from
// len(Worktrees) > 1, so the list must contain the main entry for the
// blocker to fire on a repository with exactly one linked worktree
// (Foundation §9.2 requires that).
func parseWorktreePorcelain(out string) []domain.GitWorktree {
	var wts []domain.GitWorktree
	var cur *domain.GitWorktree
	flush := func() {
		if cur != nil {
			wts = append(wts, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "worktree "):
			flush()
			cur = &domain.GitWorktree{Path: strings.TrimSpace(line[len("worktree "):])}
		case cur == nil:
			// Stray header before any worktree line; ignore.
		case strings.HasPrefix(line, "HEAD "):
			cur.Head = strings.TrimSpace(line[len("HEAD "):])
		case strings.HasPrefix(line, "branch "):
			cur.Branch = strings.TrimSpace(line[len("branch "):])
		case line == "bare":
			cur.Bare = true
		case line == "detached":
			cur.Detached = true
		default:
			// locked/prunable with optional reason text: recorded nowhere
			// in the frozen contract; intentionally skipped.
		}
	}
	flush()
	return wts
}
