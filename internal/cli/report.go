// report.go defines the `ebb inspect` result payload (Foundation §5.3
// inspect UX; §17.2 machine output) and its human rendering. Field names
// of the JSON tags are a stable machine contract; slices and maps are
// never null.

package cli

import (
	"fmt"
	"sort"
	"strings"

	"ebb/internal/domain"
	"ebb/internal/planner"
)

// InspectReport is the full inspect result (the --json details object).
type InspectReport struct {
	Workspace string             `json:"workspace"`
	Root      RootReport         `json:"root"`
	Volume    domain.VolumeUsage `json:"volume"`
	Git       GitReport          `json:"git"`
	Inventory InventoryReport    `json:"inventory"`
	Groups    []GroupReport      `json:"groups"`
	Plan      planner.Plan       `json:"plan"`
	Blockers  []string           `json:"blockers"`
	Warnings  []string           `json:"warnings"`
}

// RootReport ties the inspected path to its native identity.
type RootReport struct {
	Path     string              `json:"path"`
	Identity domain.RootIdentity `json:"identity"`
}

// GitReport summarizes the Git observation (branch, dirty state,
// blockers via DestructiveParkBlockers) and the evidence annotation
// counts applied to inventory entries.
type GitReport struct {
	IsRepo           bool     `json:"is_repo"`
	Branch           string   `json:"branch,omitempty"`
	HeadCommit       string   `json:"head_commit,omitempty"`
	Detached         bool     `json:"detached"`
	Unborn           bool     `json:"unborn"`
	DirtyWorktree    bool     `json:"dirty_worktree"`
	StagedEntries    int64    `json:"staged_entries"`
	UntrackedEntries int64    `json:"untracked_entries"`
	StashCount       int64    `json:"stash_count"`
	AdminInsideRoot  bool     `json:"admin_inside_root"`
	TrackedEvidence  int      `json:"tracked_evidence_entries"`
	AdminEvidence    int      `json:"admin_evidence_entries"`
	Blockers         []string `json:"blockers"`
	Warnings         []string `json:"warnings"`
}

// InventoryReport is the inventory summary view: counts, preserved
// bytes, per-route decisions, exclusive reclaimability per top-level
// dir and scan issues by stable code.
type InventoryReport struct {
	TotalEntries    int64            `json:"total_entries"`
	Preserved       int64            `json:"preserved"`
	PreservedBytes  int64            `json:"preserved_bytes"`
	Routes          map[string]int64 `json:"routes"`
	Blocking        []string         `json:"blocking"`
	ExclReclaimable []DirBytes       `json:"excl_reclaimable"`
	IssuesByCode    map[string]int   `json:"issues_by_code"`
	IssueCount      int              `json:"issue_count"`
}

// DirBytes is one top-level directory's exclusively reclaimable bytes.
type DirBytes struct {
	Dir   string `json:"dir"`
	Bytes int64  `json:"bytes"`
}

// GroupReport records one regenerate group's route decision, including
// F53 cancellations with their reason and the cancelling entry.
type GroupReport struct {
	ID         string   `json:"id"`
	Adapter    string   `json:"adapter"`
	Outputs    []string `json:"outputs"`
	Applicable bool     `json:"applicable"`
	Cancelled  bool     `json:"cancelled,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Canceller  string   `json:"canceller,omitempty"`
	Members    int      `json:"members"`
}

// buildInspectReport assembles the report from one completed discovery
// plus its plan preview. Pure; output is deterministic.
func buildInspectReport(d discovery, plan planner.Plan) InspectReport {
	git := GitReport{
		IsRepo:           d.Obs.IsRepo,
		Branch:           d.Obs.HeadBranch,
		HeadCommit:       d.Obs.HeadCommit,
		Detached:         d.Obs.Detached,
		Unborn:           d.Obs.Unborn,
		DirtyWorktree:    d.Obs.DirtyWorktree,
		StagedEntries:    d.Obs.StagedEntries,
		UntrackedEntries: d.Obs.UntrackedEntries,
		StashCount:       d.Obs.StashCount,
		AdminInsideRoot:  d.Obs.AdminInsideRoot,
		TrackedEvidence:  d.TrackedEntries,
		AdminEvidence:    d.AdminEntries,
		Blockers:         d.Obs.DestructiveParkBlockers(),
		Warnings:         d.Obs.Warnings,
	}
	if git.Blockers == nil {
		git.Blockers = []string{}
	}
	if git.Warnings == nil {
		git.Warnings = []string{}
	}

	routes := map[string]int64{}
	for _, e := range d.Resolved.Entries {
		routes[string(e.Route)]++
	}

	excl := make([]DirBytes, 0, len(d.Summary.ExclReclaimable))
	for dir, bytes := range d.Summary.ExclReclaimable {
		excl = append(excl, DirBytes{Dir: dir, Bytes: bytes})
	}
	sort.Slice(excl, func(i, j int) bool {
		if excl[i].Bytes != excl[j].Bytes {
			return excl[i].Bytes > excl[j].Bytes
		}
		return excl[i].Dir < excl[j].Dir
	})

	issues := map[string]int{}
	for _, iss := range d.Summary.Issues {
		issues[iss.Code]++
	}
	blocking := d.Summary.Blocking
	if blocking == nil {
		blocking = []string{}
	}

	groups := make([]GroupReport, 0, len(d.Resolved.Groups))
	for _, g := range d.Resolved.Groups {
		gr := GroupReport{
			ID:         g.ID,
			Adapter:    string(g.Adapter),
			Outputs:    g.Outputs,
			Applicable: g.Applicable,
			Cancelled:  g.Cancelled,
			Reason:     g.Reason,
			Canceller:  g.Canceller,
		}
		for _, e := range d.Resolved.Entries {
			if e.Root != domain.RootMain || e.Route != domain.RouteReconstruct {
				continue
			}
			for _, o := range g.Outputs {
				if pathUnder(o, e.Path) {
					gr.Members++
					break
				}
			}
		}
		if gr.Outputs == nil {
			gr.Outputs = []string{}
		}
		groups = append(groups, gr)
	}

	warnings := d.Warnings
	if warnings == nil {
		warnings = []string{}
	}

	return InspectReport{
		Workspace: d.Policy.Workspace.Name,
		Root:      RootReport{Path: d.Root, Identity: d.Ident},
		Volume:    d.Volume,
		Git:       git,
		Inventory: InventoryReport{
			TotalEntries:    d.Summary.TotalEntries,
			Preserved:       d.Summary.Preserved,
			PreservedBytes:  d.Summary.PreservedBytes,
			Routes:          routes,
			Blocking:        blocking,
			ExclReclaimable: excl,
			IssuesByCode:    issues,
			IssueCount:      len(d.Summary.Issues),
		},
		Groups:   groups,
		Plan:     plan,
		Blockers: git.Blockers,
		Warnings: warnings,
	}
}

// pathUnder reports whether path equals or lies below dir, using the
// root-relative '/'-separated convention.
func pathUnder(dir, path string) bool {
	return path == dir || len(path) > len(dir) && path[:len(dir)+1] == dir+"/"
}

// renderInspectHuman renders the grouped, humanized report for stderr.
func renderInspectHuman(r InspectReport) string {
	var b strings.Builder
	line := func(format string, a ...any) {
		fmt.Fprintf(&b, format, a...)
	}

	line("workspace: %s\n", r.Workspace)
	line("root: %s\n  identity: %s\n", r.Root.Path, r.Root.Identity)

	vol := r.Volume.VolumeID
	if vol == "" {
		vol = "default"
	}
	line("volume %s: %s available to caller, %s free, %s total\n",
		vol, HumanBytes(r.Volume.FreeToCaller), HumanBytes(r.Volume.VolumeFree), HumanBytes(r.Volume.Total))

	if !r.Git.IsRepo {
		line("git: no repository at root\n")
	} else {
		head := "detached HEAD"
		if r.Git.Branch != "" {
			// Display form strips the ref namespace; the JSON keeps the
			// raw symbolic ref.
			head = strings.TrimPrefix(r.Git.Branch, "refs/heads/")
			if r.Git.Unborn {
				head += " (unborn)"
			}
		}
		state := "clean"
		if r.Git.DirtyWorktree {
			state = "dirty"
		}
		line("git: repository, %s, worktree %s\n", head, state)
		line("  index entries: %d, untracked: %d, stash: %d\n",
			r.Git.StagedEntries, r.Git.UntrackedEntries, r.Git.StashCount)
		if r.Git.AdminInsideRoot {
			line("  administration inside root\n")
		} else {
			line("  administration outside root\n")
		}
		line("  evidence applied: git:tracked on %d entries, git:admin on %d entries\n",
			r.Git.TrackedEvidence, r.Git.AdminEvidence)
		for _, w := range r.Git.Warnings {
			line("  git warning: %s\n", w)
		}
	}
	for _, bl := range r.Git.Blockers {
		line("git blocker: %s\n", bl)
	}

	inv := r.Inventory
	line("inventory: %d entries, %d preserved (%s), %d blocking\n",
		inv.TotalEntries, inv.Preserved, HumanBytes(inv.PreservedBytes), len(inv.Blocking))
	line("  routes: %s\n", formatRouteCounts(inv.Routes))
	if len(inv.ExclReclaimable) == 0 {
		line("  exclusively reclaimable: none\n")
	} else {
		line("  exclusively reclaimable (top-level dir):\n")
		for _, d := range inv.ExclReclaimable {
			line("    %-24s %10s\n", d.Dir, HumanBytes(d.Bytes))
		}
	}
	if inv.IssueCount == 0 {
		line("  scan issues: none\n")
	} else {
		line("  scan issues:\n")
		for _, ic := range sortedIntCounts(inv.IssuesByCode) {
			line("    %s x%d\n", ic.key, ic.n)
		}
	}
	for _, bl := range inv.Blocking {
		line("  blocking entry: %s\n", bl)
	}

	if len(r.Groups) == 0 {
		line("regenerate groups: none declared\n")
	} else {
		line("regenerate groups:\n")
		for _, g := range r.Groups {
			line("  %s [%s] outputs: %s\n", g.ID, g.Adapter, strings.Join(g.Outputs, ", "))
			switch {
			case g.Applicable:
				line("    applicable: reconstruct (%d entries inside outputs)\n", g.Members)
			case g.Cancelled:
				line("    cancelled: %s\n", g.Reason)
				line("    canceller: %s\n", g.Canceller)
			default:
				line("    not applicable: %s\n", g.Reason)
			}
		}
	}

	b.WriteString("plan preview (no target):\n")
	b.WriteString(renderPlanBody(r.Plan))

	if len(r.Blockers) == 0 {
		line("blockers: none\n")
	} else {
		for _, bl := range r.Blockers {
			line("blocker: %s\n", bl)
		}
	}
	for _, w := range r.Warnings {
		line("warning: %s\n", w)
	}
	return b.String()
}

// formatRouteCounts renders a route histogram deterministically.
func formatRouteCounts(routes map[string]int64) string {
	if len(routes) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(routes))
	for k := range routes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, routes[k]))
	}
	return strings.Join(parts, ", ")
}

// sortedIntCounts orders a string->int map by key for stable rendering.
func sortedIntCounts(m map[string]int) []struct {
	key string
	n   int
} {
	out := make([]struct {
		key string
		n   int
	}, 0, len(m))
	for k, v := range m {
		out = append(out, struct {
			key string
			n   int
		}{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}
