// Package planner builds deterministic, effect-free reclaim plans from a
// resolved policy and an inventory summary (Foundation §6.3, §17.4).
//
// Steps are produced in the fixed least-disruptive order and never
// reordered: (1) groups already carrying an explicit discard route; (2)
// approved reconstructible groups (trim); (3) provider-native
// dehydration — none exist in v1, so a request for it is reported as an
// unsupported step; (4) full workspace parking, flagged as an escalation
// that requires its own approval and a stopped-writers confirmation.
//
// Target semantics: without a target the plan requests the maximal safe
// release; with a target the planner stops adding steps once the
// cumulative estimate reaches it. A target NEVER reorders precedence,
// weakens an approval requirement or unlocks park escalation — if the
// target cannot be met, the plan reports the exact shortfall instead of
// manufacturing a larger number.
//
// Estimates are conservative: per-step bytes prefer the smaller of the
// inventory's exclusively-reclaimable figure and the summed entry
// allocation (round down, never up); unavailable estimates are omitted
// and the step is marked unknown.
//
// All functions are pure: no I/O, no clocks, no randomness. Shuffling
// the input groups or entries yields an identical plan.
package planner

import (
	"fmt"
	"sort"

	"ebb/internal/domain"
	"ebb/internal/policy"
)

// StepKind identifies one class of reclaim action.
type StepKind string

// The v1 step kinds, in fixed precedence order.
const (
	StepDiscard   StepKind = "discard"
	StepTrim      StepKind = "trim"
	StepDehydrate StepKind = "dehydrate"
	StepPark      StepKind = "park"
)

// Disruption classifies how much a step disturbs the live workspace.
type Disruption string

// The v1 disruption classes.
const (
	DisruptionDiscard   Disruption = "explicit-loss"
	DisruptionRebuild   Disruption = "rebuild-required"
	DisruptionDehydrate Disruption = "degraded-first-access"
	DisruptionPark      Disruption = "workspace-unavailable"
)

// Result summarizes the plan outcome.
type Result string

// The v1 plan results.
const (
	// ResultSufficient: no target, or the target is met by planned steps.
	ResultSufficient Result = "sufficient"
	// ResultShortfall: the target cannot be met (park missing or not
	// approved, or insufficient reclaimable bytes).
	ResultShortfall Result = "shortfall"
	// ResultNoGain: the plan contains zero useful steps.
	ResultNoGain Result = "no-gain"
)

// Input is everything the planner needs. It is pure data.
type Input struct {
	// Summary is the inventory accounting (ExclReclaimable, Blocking, ...).
	Summary domain.InventorySummary
	// Resolved is the output of policy.Resolve.
	Resolved policy.Resolved
	// Target is the optional space goal in bytes. Nil means "release as
	// much as safely possible".
	Target *int64
	// Volume labels the volume the estimates are reported for (v1 plans
	// a single volume; VolumeID "" is reported as "default").
	Volume domain.VolumeUsage
	// ParkApproved reports whether full-park escalation is permitted.
	// It is never implied by a target.
	ParkApproved bool
	// DehydrateRequested reports whether provider-native dehydration was
	// asked for; v1 has no such adapter, so the planner reports the step
	// as unsupported.
	DehydrateRequested bool
}

// Step is one planned release action. It is a description, not an
// execution instruction.
type Step struct {
	Kind        StepKind         `json:"kind"`
	Groups      []string         `json:"groups"`
	Reclaimable map[string]int64 `json:"reclaimable"` // volume id -> bytes
	// EstimateUnknown marks a step whose reclaimable bytes could not be
	// estimated; its Reclaimable map then carries no numbers.
	EstimateUnknown bool         `json:"estimate_unknown"`
	Disruption      Disruption   `json:"disruption"`
	RecoveryRoute   domain.Route `json:"recovery_route"`
	Blockers        []string     `json:"blockers,omitempty"`
	// RequiresApproval marks steps needing their own explicit approval.
	RequiresApproval bool `json:"requires_approval"`
	// RequiresStoppedWriters marks steps needing a stopped-writers
	// confirmation before any destructive phase.
	RequiresStoppedWriters bool `json:"requires_stopped_writers"`
	// Unsupported marks a requested step v1 cannot provide (dehydration).
	Unsupported bool `json:"unsupported,omitempty"`
	// Escalation marks the material change of recovery conditions that
	// full parking represents.
	Escalation bool `json:"escalation,omitempty"`
}

// Plan is the planner's complete, effect-free proposal.
type Plan struct {
	Result    Result           `json:"result"`
	Steps     []Step           `json:"steps"`
	Target    *int64           `json:"target,omitempty"`
	Achieved  map[string]int64 `json:"achieved"`            // volume id -> planned bytes
	Shortfall map[string]int64 `json:"shortfall,omitempty"` // volume id -> unmet bytes
	Reasons   []string         `json:"reasons,omitempty"`
	Warnings  []string         `json:"warnings,omitempty"`
}

// PlanReclaim computes the plan. It returns an error only for invalid
// input (negative target); everything else is expressed in the Plan.
func PlanReclaim(in Input) (Plan, error) {
	if in.Target != nil && *in.Target < 0 {
		return Plan{}, fmt.Errorf("planner: negative target %d", *in.Target)
	}
	vol := volumeKey(in.Volume)

	plan := Plan{Result: ResultSufficient, Target: in.Target, Achieved: map[string]int64{}}
	var cum int64
	stopped := false
	tryAdd := func(s Step) {
		if stopped {
			return
		}
		plan.Steps = append(plan.Steps, s)
		cum += stepTotal(s)
		if in.Target != nil && cum >= *in.Target {
			stopped = true
		}
	}

	// (1) Entries already carrying an explicit discard route.
	if s, ok, why := discardStep(in, vol); ok {
		tryAdd(s)
	} else if why != "" {
		plan.Reasons = append(plan.Reasons, why)
	}

	// (2) Approved reconstructible groups, least-disruptive sufficient
	// order: largest estimate first, ties by group id.
	trims, notes := trimSteps(in, vol)
	plan.Reasons = append(plan.Reasons, notes...)
	for _, s := range trims {
		tryAdd(s)
	}

	// (3) Provider-native dehydration: unsupported in v1. It never
	// counts toward a target, so it is reported whenever requested,
	// even after the target has been met by earlier steps.
	if in.DehydrateRequested {
		plan.Steps = append(plan.Steps, Step{
			Kind:            StepDehydrate,
			Groups:          []string{"provider-native"},
			Reclaimable:     map[string]int64{},
			EstimateUnknown: true,
			Disruption:      DisruptionDehydrate,
			RecoveryRoute:   domain.RouteReconstruct,
			Blockers:        []string{"EBB_E_DEHYDRATION_UNSUPPORTED"},
			Unsupported:     true,
		})
		plan.Warnings = append(plan.Warnings,
			"provider-native dehydration requested but no supported adapter exists in v1; step reported as unsupported")
	}

	// (4) Full park: escalation requiring its own approval and a
	// stopped-writers confirmation. A target never supplies either.
	park, parkOK, parkWhy := parkStep(in, vol)
	needPark := in.Target == nil || cum < *in.Target
	if parkOK && needPark {
		tryAdd(park)
	} else if parkWhy != "" && in.Target == nil {
		// With a target an unmet gap is reported as a shortfall below,
		// not as a park reason; without a target the omission deserves
		// an explicit note.
		plan.Reasons = append(plan.Reasons, parkWhy)
	}

	if in.Target == nil && !in.ParkApproved && parkBytes(in) > 0 {
		plan.Warnings = append(plan.Warnings,
			"full park could release further bytes but is not approved; plan stops at the safe routes above")
	}

	// Outcome.
	useful := 0
	for _, s := range plan.Steps {
		if s.EstimateUnknown || stepTotal(s) > 0 {
			useful++
		}
	}
	switch {
	case useful == 0:
		plan.Result = ResultNoGain
		if len(plan.Reasons) == 0 {
			plan.Reasons = append(plan.Reasons, "no step releases a measurable amount of space")
		}
	case in.Target != nil && cum < *in.Target:
		plan.Result = ResultShortfall
	}

	plan.Achieved[vol] = cum
	if plan.Result == ResultShortfall || (plan.Result == ResultNoGain && in.Target != nil && cum < *in.Target) {
		plan.Shortfall = map[string]int64{vol: *in.Target - cum}
		if !in.ParkApproved {
			plan.Warnings = append(plan.Warnings,
				"target unmet: full park would be the next escalation but is not approved (approval is never implied by a target)")
		}
	}
	return plan, nil
}

func volumeKey(v domain.VolumeUsage) string {
	if v.VolumeID == "" {
		return "default"
	}
	return v.VolumeID
}

func stepTotal(s Step) int64 {
	var n int64
	for _, b := range s.Reclaimable {
		n += b
	}
	return n
}

// under reports whether path is at or below dir, using the root-relative
// '/'-separated convention.
func under(dir, path string) bool {
	return path == dir || len(path) > len(dir) && path[:len(dir)+1] == dir+"/"
}

// discardStep builds step (1) from entries whose route is already
// RouteDiscard (authority recorded outside the policy file). The third
// return value explains why no step exists when ok is false.
func discardStep(in Input, vol string) (Step, bool, string) {
	var entries []domain.Entry
	for _, e := range in.Resolved.Entries {
		if e.Route == domain.RouteDiscard {
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return Step{}, false, "no group carries an explicit discard route"
	}
	bytes, _ := sumEntries(entries)
	s := Step{
		Kind:          StepDiscard,
		Groups:        []string{"explicit-discard"},
		Reclaimable:   map[string]int64{},
		Disruption:    DisruptionDiscard,
		RecoveryRoute: domain.RouteDiscard,
	}
	if bytes > 0 {
		s.Reclaimable[vol] = bytes
	} else {
		s.EstimateUnknown = true
	}
	s.Blockers = blockersUnder(in.Summary.Blocking, entries)
	return s, true, ""
}

// trimSteps builds one step per applicable regenerate group, ordered by
// (estimate desc, id asc). Zero-byte applicable groups remain as steps
// for visibility; their note is appended to the returned notes.
func trimSteps(in Input, vol string) ([]Step, []string) {
	var steps []Step
	var notes []string
	for _, g := range in.Resolved.Groups {
		if !g.Applicable {
			notes = append(notes, fmt.Sprintf("regenerate group %q not applicable: %s", g.ID, g.Reason))
			continue
		}
		members := groupMembers(in.Resolved.Entries, g.Outputs)
		bytes, unknown := estimateGroup(in.Summary, members, g.Outputs)
		s := Step{
			Kind:          StepTrim,
			Groups:        []string{g.ID},
			Reclaimable:   map[string]int64{},
			Disruption:    DisruptionRebuild,
			RecoveryRoute: domain.RouteReconstruct,
		}
		if unknown {
			s.EstimateUnknown = true
		} else if bytes > 0 {
			s.Reclaimable[vol] = bytes
		} else {
			notes = append(notes, fmt.Sprintf("regenerate group %q applicable but reclaims no measurable bytes", g.ID))
		}
		s.Blockers = blockersUnder(in.Summary.Blocking, members)
		steps = append(steps, s)
	}
	sort.SliceStable(steps, func(i, j int) bool {
		bi, bj := stepTotal(steps[i]), stepTotal(steps[j])
		if bi != bj {
			return bi > bj
		}
		if steps[i].EstimateUnknown != steps[j].EstimateUnknown {
			return !steps[i].EstimateUnknown
		}
		return steps[i].Groups[0] < steps[j].Groups[0]
	})
	return steps, notes
}

// parkStep builds the escalation step. It exists only when ParkApproved
// is set; otherwise the third return value explains the omission.
func parkStep(in Input, vol string) (Step, bool, string) {
	if !in.ParkApproved {
		return Step{}, false, "full park not approved (escalation requires its own approval and stopped-writers confirmation)"
	}
	bytes, unknown := estimateAll(in.Summary, in.Resolved.Entries)
	s := Step{
		Kind:                   StepPark,
		Groups:                 []string{"workspace"},
		Reclaimable:            map[string]int64{},
		Disruption:             DisruptionPark,
		RecoveryRoute:          domain.RoutePreserve,
		RequiresApproval:       true,
		RequiresStoppedWriters: true,
		Escalation:             true,
	}
	if unknown {
		s.EstimateUnknown = true
	} else if bytes > 0 {
		s.Reclaimable[vol] = bytes
	}
	for _, b := range in.Summary.Blocking {
		s.Blockers = append(s.Blockers, "blocked-entry:"+b)
	}
	return s, true, ""
}

// parkBytes estimates what a park could release (used for the
// not-approved warning).
func parkBytes(in Input) int64 {
	n, _ := estimateAll(in.Summary, in.Resolved.Entries)
	return n
}

// groupMembers selects the main-root entries routed reconstruct inside
// the group's outputs.
func groupMembers(entries []domain.Entry, outputs []string) []domain.Entry {
	var members []domain.Entry
	for _, e := range entries {
		if e.Root != domain.RootMain || e.Route != domain.RouteReconstruct {
			continue
		}
		for _, o := range outputs {
			if under(o, e.Path) {
				members = append(members, e)
				break
			}
		}
	}
	return members
}

// blockersUnder filters summary blocking paths that fall at or below one
// of the entries (a directory entry contains its children).
func blockersUnder(blocking []string, entries []domain.Entry) []string {
	var out []string
	for _, b := range blocking {
		for _, e := range entries {
			if e.Kind == domain.KindDir && under(e.Path, b) || b == e.Path {
				out = append(out, "blocked-entry:"+b)
				break
			}
		}
	}
	return out
}
