package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// Stable issue codes emitted by Resolve.
const (
	// IssueRegenCancelled: a regenerate group flipped to preservation.
	IssueRegenCancelled = "EBB_POLICY_REGEN_CANCELLED"
	// IssueEntryPathInvalid: an inventory entry path failed the
	// root-relative contract; it is preserved and reported.
	IssueEntryPathInvalid = "EBB_POLICY_ENTRY_PATH_INVALID"
	// IssueEntryRootInvalid: an inventory entry carried an unknown root
	// identifier; it is preserved and reported.
	IssueEntryRootInvalid = "EBB_POLICY_ENTRY_ROOT_INVALID"
)

// Issue is a non-fatal resolution observation that plans and reports
// must surface.
type Issue struct {
	Code string `json:"code"`
	Path string `json:"path,omitempty"`
	Note string `json:"note"`
}

// GroupDecision records the applicability of one [[regenerate]] group
// after resolution. A group is applicable only when nothing inside its
// outputs outranks regeneration.
type GroupDecision struct {
	ID         string   `json:"id"`
	Adapter    Adapter  `json:"adapter"`
	Outputs    []string `json:"outputs"`
	Applicable bool     `json:"applicable"`
	Cancelled  bool     `json:"cancelled,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Canceller  string   `json:"canceller,omitempty"`
}

// Resolved is the output of Resolve: per-entry routes with evidence,
// per-group applicability decisions, and issues.
type Resolved struct {
	Entries []domain.Entry  `json:"entries"`
	Issues  []Issue         `json:"issues,omitempty"`
	Groups  []GroupDecision `json:"groups,omitempty"`
}

// Resolve applies the policy to inventory entries and returns their
// final routes (Foundation §7.2 precedence: root/ownership restrictions
// > required source and Git state > explicit preservation > generated
// content > locally approved reconstruction > preserve everything else).
//
// Resolve is pure: it does no I/O and never mutates the caller's slice
// or the backing arrays of any entry's Evidence. Errors are returned for
// invalid policy, conflicting regenerate output ownership and action
// cycles; per-entry anomalies are Issues, not errors. Unclassified
// entries (empty route) resolve to RoutePreserve — never RouteDiscard,
// which v1 policy cannot express.
func Resolve(entries []domain.Entry, pol Policy) (Resolved, error) {
	if err := pol.Validate(); err != nil {
		return Resolved{}, err
	}
	if err := checkOutputConflicts(pol); err != nil {
		return Resolved{}, err
	}
	if err := checkActionCycles(pol); err != nil {
		return Resolved{}, err
	}

	pre, err := pol.PreserveMatcher()
	if err != nil {
		return Resolved{}, err
	}
	sens, err := pol.SensitiveMatcher()
	if err != nil {
		return Resolved{}, err
	}

	out := make([]domain.Entry, len(entries))
	copy(out, entries)

	// Pass 1: preserve-matched directories, for containment decisions.
	var preserveDirs []string
	for _, e := range out {
		if e.Kind != domain.KindDir || e.Root != domain.RootMain || !validEntryPath(e.Path) {
			continue
		}
		if r, err := pre.Match(e.Path); err == nil && r.Matched {
			preserveDirs = append(preserveDirs, e.Path)
		}
	}

	// Pass 2: regenerate applicability. Deterministic group order (by
	// id); deterministic canceller (lowest offending path in entry
	// order).
	groups := make([]GroupDecision, 0, len(pol.Regenerate))
	byID := make(map[string]GroupDecision, len(pol.Regenerate))
	sortedGen := append([]Regenerate(nil), pol.Regenerate...)
	sort.Slice(sortedGen, func(i, j int) bool { return sortedGen[i].ID < sortedGen[j].ID })

	var issues []Issue
	for _, g := range sortedGen {
		d := GroupDecision{ID: g.ID, Adapter: g.Adapter, Outputs: g.Outputs, Applicable: true}
		for i := range out {
			e := &out[i]
			if e.Root != domain.RootMain || !validEntryPath(e.Path) || !insideAny(g.Outputs, e.Path) {
				continue
			}
			if reason := cancellationReason(e, pre, preserveDirs); reason != "" {
				d.Applicable = false
				d.Cancelled = true
				d.Reason = reason
				d.Canceller = e.Path
				issues = append(issues, Issue{
					Code: IssueRegenCancelled,
					Path: e.Path,
					Note: fmt.Sprintf("regenerate group %q cancelled: %s", g.ID, reason),
				})
				break
			}
		}
		groups = append(groups, d)
		byID[g.ID] = d
	}

	// Pass 3: per-entry routing.
	for i := range out {
		e := &out[i]

		// Sensitivity affects logging/export only; it never selects or
		// changes a route (Foundation §6.2).
		if e.Root == domain.RootMain && validEntryPath(e.Path) {
			if sr, err := sens.Match(e.Path); err == nil && sr.Matched {
				e.Sensitivity = domain.SensitivitySensitive
				addEvidence(e, "policy:sensitive="+sr.Source)
			}
		}

		// Locally recorded routes that outrank policy assignment are
		// respected, never weakened.
		switch e.Route {
		case domain.RouteDiscard, domain.RouteExternal, domain.RouteRetainedArtifact:
			addEvidence(e, "policy:respected="+string(e.Route))
			continue
		}

		switch {
		case !e.Root.Valid():
			issues = append(issues, Issue{
				Code: IssueEntryRootInvalid,
				Path: e.Path,
				Note: fmt.Sprintf("unknown root %q; entry preserved", e.Root),
			})
			e.Route = domain.RoutePreserve
			addEvidence(e, "policy:default-preserve")
		case e.Root == domain.RootMeta:
			// Policy paths are main-root-relative; Ebb's private meta
			// root bypasses them entirely.
			e.Route = domain.RoutePreserve
			addEvidence(e, "policy:meta-root")
		case !validEntryPath(e.Path):
			issues = append(issues, Issue{
				Code: IssueEntryPathInvalid,
				Path: e.Path,
				Note: "entry path violates the root-relative contract; entry preserved",
			})
			e.Route = domain.RoutePreserve
			addEvidence(e, "policy:default-preserve")
		default:
			routeEntry(e, pre, preserveDirs, sortedGen, byID)
		}
	}

	sortIssues(issues)
	return Resolved{Entries: out, Issues: issues, Groups: groups}, nil
}

// routeEntry assigns the route for one main-root entry with a valid
// path, in precedence order.
func routeEntry(e *domain.Entry, pre *Matcher, preserveDirs []string, groups []Regenerate, byID map[string]GroupDecision) {
	if r, err := pre.Match(e.Path); err == nil && r.Matched {
		e.Route = domain.RoutePreserve
		addEvidence(e, "policy:preserve="+r.Source)
		return
	}
	if dir := containingDir(preserveDirs, e.Path); dir != "" {
		e.Route = domain.RoutePreserve
		addEvidence(e, "policy:preserve-dir="+dir)
		return
	}
	for _, g := range groups {
		if !insideAny(g.Outputs, e.Path) {
			continue
		}
		if byID[g.ID].Applicable {
			e.Route = domain.RouteReconstruct
			addEvidence(e, "policy:regenerate="+g.ID)
		} else {
			e.Route = domain.RoutePreserve
			addEvidence(e, "policy:regenerate-cancelled="+g.ID)
		}
		return
	}
	e.Route = domain.RoutePreserve
	addEvidence(e, "policy:default-preserve")

	// Inputs of any declared group are preserved and tagged for audit.
	for _, g := range groups {
		if insideAny(g.Inputs, e.Path) {
			addEvidence(e, "policy:regenerate-input="+g.ID)
			break
		}
	}
}

// cancellationReason returns a non-empty reason when entry e (inside a
// regenerate group's outputs) must cancel regeneration for the whole
// group (F53 and the higher precedence classes).
func cancellationReason(e *domain.Entry, pre *Matcher, preserveDirs []string) string {
	if r, err := pre.Match(e.Path); err == nil && r.Matched {
		return fmt.Sprintf("explicit preservation rule %s covers this path", r.Source)
	}
	if dir := containingDir(preserveDirs, e.Path); dir != "" {
		return fmt.Sprintf("path lies inside preserve-matched directory %q", dir)
	}
	if tok := sourceEvidenceToken(e.Evidence); tok != "" {
		return fmt.Sprintf("required source/Git state inside outputs (F53): evidence %q", tok)
	}
	if e.Ownership != domain.OwnershipOwned && e.Ownership != "" {
		return fmt.Sprintf("entry ownership %q is not owned", e.Ownership)
	}
	if !e.Kind.DestructiveSafe() {
		return fmt.Sprintf("entry kind %q is not destructively safe in v1", e.Kind)
	}
	return ""
}

// sourceEvidenceToken returns the first evidence token marking an entry
// as required source/Git state. The scanner attaches these tokens:
//
//	git:tracked[:detail] — tracked by Git
//	git:admin[:detail]   — Git administration (e.g. a nested repository)
func sourceEvidenceToken(ev []string) string {
	for _, t := range ev {
		if strings.HasPrefix(t, "git:tracked") || strings.HasPrefix(t, "git:admin") {
			return t
		}
	}
	return ""
}

// addEvidence appends tokens to an entry's evidence without mutating the
// backing array of the caller's slice.
func addEvidence(e *domain.Entry, tokens ...string) {
	merged := make([]string, 0, len(e.Evidence)+len(tokens))
	merged = append(merged, e.Evidence...)
	merged = append(merged, tokens...)
	e.Evidence = merged
}

// validEntryPath reports whether an inventory entry path satisfies the
// root-relative contract.
func validEntryPath(p string) bool { return ValidateRelPath(p, false) == nil }

// insideAny reports whether path equals or lies below one of the
// root-relative prefixes.
func insideAny(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if pathUnder(p, path) {
			return true
		}
	}
	return false
}

// containingDir returns the first directory in dirs that contains path.
func containingDir(dirs []string, path string) string {
	for _, d := range dirs {
		if pathUnder(d, path) {
			return d
		}
	}
	return ""
}

// checkOutputConflicts rejects two regenerate groups whose outputs
// overlap (equal or nested): ambiguous output ownership is an error
// (Foundation §6.3).
func checkOutputConflicts(pol Policy) error {
	gs := append([]Regenerate(nil), pol.Regenerate...)
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })
	for i := 0; i < len(gs); i++ {
		for j := i + 1; j < len(gs); j++ {
			for _, oa := range gs[i].Outputs {
				for _, ob := range gs[j].Outputs {
					if pathsOverlap(oa, ob) {
						return fmt.Errorf("Ebbfile: conflicting regenerate output ownership: group %q output %q overlaps group %q output %q",
							gs[i].ID, oa, gs[j].ID, ob)
					}
				}
			}
		}
	}
	return nil
}

// checkActionCycles rejects action dependency cycles: an edge exists
// from group A to group B when an input of A is at or below an output of
// B (A rebuilds using B's output). An input inside a group's own outputs
// is a self-cycle.
func checkActionCycles(pol Policy) error {
	gs := append([]Regenerate(nil), pol.Regenerate...)
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })

	adj := make(map[string][]string, len(gs))
	for _, a := range gs {
		for _, in := range a.Inputs {
			for _, b := range gs {
				for _, ob := range b.Outputs {
					if !pathsOverlap(in, ob) {
						continue
					}
					if b.ID == a.ID {
						return fmt.Errorf("Ebbfile: action cycle: regenerate %q input %q is inside its own outputs", a.ID, in)
					}
					adj[a.ID] = append(adj[a.ID], b.ID)
				}
			}
		}
	}

	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(gs))
	var stack []string
	var visit func(id string) error
	visit = func(id string) error {
		color[id] = gray
		stack = append(stack, id)
		deps := adj[id]
		sort.Strings(deps)
		for _, dep := range deps {
			switch color[dep] {
			case gray:
				cycle := append(append([]string(nil), stack...), dep)
				return fmt.Errorf("Ebbfile: action cycle detected: %s", strings.Join(cycle, " -> "))
			case white:
				if err := visit(dep); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[id] = black
		return nil
	}
	for _, g := range gs {
		if color[g.ID] == white {
			if err := visit(g.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// sortIssues orders issues deterministically by (code, path, note).
func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		if issues[i].Path != issues[j].Path {
			return issues[i].Path < issues[j].Path
		}
		return issues[i].Note < issues[j].Note
	})
}
