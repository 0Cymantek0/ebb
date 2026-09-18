// cmdReclaim implements `ebb reclaim [path] [--target N]` (Foundation
// §17.4, §5.4): the ordinary entry point for "I need disk space". Reclaim
// composes independently safe operations rather than introducing a new
// storage strategy:
//
//  1. plan against the measured workspace allocation and the requested
//     target (default: return as much as safely possible);
//  2. execute the planned trim groups under the FULL trim validation and
//     the SAME grouped-approval UX as `ebb trim` (--yes accepts; a
//     declined or blocked group routes around and is reported — §17.4
//     F10/F11);
//  3. escalate into whole-root parking ONLY when the plan says park is
//     needed (target unmet after trim, or no target and trim released
//     nothing meaningful). Escalation is a material change of recovery
//     conditions: it requires the full §17.2 writer assertion AND its own
//     typed confirmation showing the additional estimated release against
//     the workspace being REMOVED. --yes NEVER answers the escalation
//     confirmation ("a reclaim invocation never supplies them silently");
//     it is only answerable on a terminal.
//
// --dry-run prints the staged plan and has no effects.
//
// Exit contract: 0 requested outcome completed; 2 usage; 3 blocked (a
// failed escalation-approval gate is REPORTED and falls through to the
// shortfall outcome; 3 is for failures of an executing step); 4 capture
// verification failure; 5 removal blocked mid-walk (reconcile with `ebb
// recover`); 7 vault; 8 requested physical-space outcome not reached
// (target shortfall or no useful gain — an honest result, never an
// invitation to weaken policy); 130 cancelled.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/lifecycle"
	"ebb/internal/planner"
	"ebb/internal/policy"
)

// reclaimTrimStep is one planned trim group's execution outcome.
type reclaimTrimStep struct {
	Group    string   `json:"group"`
	Status   string   `json:"status"` // planned (preview) | removed | skipped
	Reason   string   `json:"reason,omitempty"`
	Outputs  []string `json:"outputs,omitempty"`
	Recreate []string `json:"recreate,omitempty"`
	// BytesEstimated is the plan's conservative estimate for this group
	// (0 when the planner could not estimate).
	BytesEstimated int64 `json:"bytes_estimated,omitempty"`
	// EntriesRemoved / SnapshotID are set for executed steps.
	EntriesRemoved int    `json:"entries_removed,omitempty"`
	SnapshotID     string `json:"snapshot_id,omitempty"`
}

// reclaimPark is the escalation stage's outcome.
type reclaimPark struct {
	// Status: proposed (dry run) | not-needed | declined | executed |
	// not-proposable.
	Status string `json:"status"`
	// Reason carries the note for non-executed stages.
	Reason string `json:"reason,omitempty"`
	// EstimatedAdditionalRelease is the park step's plan estimate.
	EstimatedAdditionalRelease int64 `json:"estimated_additional_release,omitempty"`
	// SnapshotID / deltas / assertion are set when the park executed.
	SnapshotID      string `json:"snapshot_id,omitempty"`
	FreedObserved   int64  `json:"freed_observed,omitempty"`
	FreedEstimated  int64  `json:"freed_estimated,omitempty"`
	WriterAssertion string `json:"writer_assertion,omitempty"`
}

// reclaimDetails is the --json payload of a reclaim (preview or result).
type reclaimDetails struct {
	Workspace string       `json:"workspace"`
	Root      string       `json:"root"`
	Target    *int64       `json:"target,omitempty"`
	Plan      planner.Plan `json:"plan"`
	// DryRun marks a no-effects preview.
	DryRun bool `json:"dry_run,omitempty"`
	// Trims carries one entry per planned trim step, in plan order.
	Trims []reclaimTrimStep `json:"trims"`
	// Park is the escalation stage outcome (nil when the request never
	// reaches an escalation decision).
	Park *reclaimPark `json:"park,omitempty"`
	// AchievedEstimated sums the executed steps' conservative estimates.
	AchievedEstimated int64 `json:"achieved_estimated"`
	// AchievedObserved is the measured free-space delta on the source
	// volume (0 when unavailable; open handles may delay release and
	// other writers make it a delta, not an attribution).
	AchievedObserved int64 `json:"achieved_observed,omitempty"`
	// Shortfall is target-achieved when a target was requested and unmet.
	Shortfall int64 `json:"shortfall,omitempty"`
	// Blockers lists the remaining blockers reported by the plan/steps.
	Blockers []string `json:"blockers"`
}

func cmdReclaim(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("reclaim", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	targetStr := fs.String("target", "", "space goal, e.g. 25GiB (default: release as much as safely possible)")
	dryRun := fs.Bool("dry-run", false, "print the staged plan without effects")
	yes := fs.Bool("yes", false, "accept the trim removal confirmations (NEVER answers the park escalation)")
	assertStopped := fs.Bool("assert-writers-stopped", false,
		"writer assertion for the park escalation (does NOT answer the escalation confirmation)")
	if err := fs.Parse(reorderFlags(args, "target")); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb reclaim: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}

	env := newEnvelope("reclaim", "error")
	var target *int64
	if *targetStr != "" {
		t, err := ParseByteCount(*targetStr)
		if err != nil {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("--target: %v", err))
		}
		target = &t
	}

	sess, disc, probe, opts, ctx, stop, err := openCaptureCommand(deps, streams, root)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("reclaim %s: %v", root, err))
	}
	defer stop()
	defer sess.close()

	// The EXECUTED plan never grants park by itself (ParkApproved=false: a
	// target never supplies the escalation's approvals, §17.4). A second
	// pure consultation with ParkApproved=true reads only the park step's
	// estimate for the escalation preview.
	plan, perr := planner.PlanReclaim(planner.Input{
		Summary: disc.Summary, Resolved: disc.Resolved,
		Target: target, Volume: disc.Volume,
	})
	if perr != nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage, perr.Error())
	}
	parkStep, perr2 := parkStepOf(planner.Input{
		Summary: disc.Summary, Resolved: disc.Resolved,
		Target: target, Volume: disc.Volume, ParkApproved: true,
	})
	if perr2 != nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage, perr2.Error())
	}

	env.Warnings = append(env.Warnings, plan.Warnings...)
	for _, iss := range disc.Resolved.Issues {
		env.Warnings = append(env.Warnings, fmt.Sprintf("%s %s: %s", iss.Code, iss.Path, iss.Note))
	}
	for _, r := range plan.Reasons {
		env.Warnings = append(env.Warnings, "note: "+r)
	}

	// ---- --dry-run: the staged plan, no effects ------------------------
	if *dryRun {
		details := reclaimDetails{
			Workspace: disc.Policy.Workspace.Name, Root: disc.Root,
			Target: target, Plan: plan, DryRun: true,
			Trims:    previewTrims(plan, disc.Policy),
			Blockers: planBlockers(plan),
		}
		if target != nil && plan.Result != planner.ResultSufficient {
			details.Shortfall = *target - sumPlanAchieved(plan)
		}
		if parkStep != nil && needsEscalation(target, plan) {
			details.Park = proposedPark(parkStep)
		}
		env.Outcome = "dry-run"
		env.WorkspaceID = string(sess.resolveWorkspaceID(opts.WorkspaceName, disc.Root))
		env.Conditions = []string{"dry-run", "no-effects"}
		env.Details = details
		emit(env, *jsonOut, streams, renderReclaimHuman(details))
		if target != nil && plan.Result != planner.ResultSufficient {
			return ExitShortfall
		}
		return ExitOK
	}

	// ---- execution ------------------------------------------------------
	declared := map[string]policy.Regenerate{}
	for _, g := range disc.Policy.Regenerate {
		declared[g.ID] = g
	}
	coord, cerr := sess.newLifecycle(probe)
	if cerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cerr),
			fmt.Sprintf("reclaim %s: %v", disc.Root, cerr))
	}

	details := reclaimDetails{
		Workspace: disc.Policy.Workspace.Name, Root: disc.Root,
		Target: target, Plan: plan, Trims: []reclaimTrimStep{},
		Blockers: planBlockers(plan),
	}
	var conditions []string
	var achieved int64
	anyExecuted := false

	for _, s := range plan.Steps {
		switch s.Kind {
		case planner.StepDiscard:
			details.Blockers = append(details.Blockers,
				"explicit-discard step not executable in v1: no per-entry discard authority is recordable (skipped; the entries stay preserved)")
		case planner.StepDehydrate:
			details.Blockers = append(details.Blockers, s.Blockers...)
		case planner.StepTrim:
			step, serr := runReclaimTrimStep(ctx, sess, coord, deps, streams, disc, opts, declared, s, *yes, &env.Warnings)
			if serr != nil {
				return emitFailure(env, *jsonOut, streams, classifyExitCode(serr),
					fmt.Sprintf("reclaim %s: trim group %s: %s", disc.Root, s.Groups[0], codedWithSafeAction(serr)))
			}
			details.Trims = append(details.Trims, step)
			if step.Status == "removed" {
				achieved += step.BytesEstimated
				anyExecuted = anyExecuted || step.BytesEstimated > 0 || step.EntriesRemoved > 0
				conditions = append(conditions, "trim:"+step.Group)
				if step.SnapshotID != "" {
					env.SnapshotID = step.SnapshotID
					env.Phase = catalog.PhaseTrimDone
				}
			} else {
				details.Blockers = append(details.Blockers,
					fmt.Sprintf("group %s skipped: %s", step.Group, step.Reason))
			}
		case planner.StepPark:
			// Never present in the executed plan (ParkApproved=false);
			// the escalation stage below owns park.
		}
	}

	// ---- park escalation stage (§17.4) ----------------------------------
	targetUnmet := target != nil && achieved < *target
	if parkStep != nil && (targetUnmet || !anyExecuted) {
		pk := proposedPark(parkStep)
		assertion, ok, reason := reclaimEscalationGate(deps, streams, disc, *assertStopped, pk)
		if !ok {
			pk.Status = "declined"
			pk.Reason = reason
			conditions = append(conditions, "park-escalation:declined")
		} else {
			parkOpts := opts
			parkOpts.Park = true
			parkOpts.WriterAssertion = assertion
			var res lifecycle.ParkResult
			pErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
				var rErr error
				res, rErr = coord.Park(ctx, lifecycleVaultRef(repoDir, passfile), disc.Root, parkOpts)
				return rErr
			})
			if pErr != nil {
				return emitFailure(env, *jsonOut, streams, classifyExitCode(pErr),
					fmt.Sprintf("reclaim %s: park escalation: %s", disc.Root, codedWithSafeAction(pErr)))
			}
			pk.Status = "executed"
			pk.SnapshotID = string(res.Snapshot.SnapshotID)
			pk.FreedObserved = res.VolumeDeltaObserved
			pk.FreedEstimated = res.VolumeDeltaEstimated
			pk.WriterAssertion = assertion
			// The measured delta is the honest capacity number (§14.1);
			// the logical estimate is the fallback when measurement was
			// unavailable.
			parkGain := res.VolumeDeltaObserved
			if parkGain <= 0 {
				parkGain = res.VolumeDeltaEstimated
			}
			achieved += parkGain
			anyExecuted = true
			conditions = append(conditions, "park-escalation:executed", "workspace-parked")
			env.SnapshotID = pk.SnapshotID
			env.Phase = catalog.PhaseDone
			env.Warnings = append(env.Warnings, res.Snapshot.Warnings...)
		}
		details.Park = pk
	} else if parkStep != nil {
		details.Park = &reclaimPark{Status: "not-needed", EstimatedAdditionalRelease: stepTotal(*parkStep),
			Reason: "the executed stages reached the request; the workspace stays in place"}
		conditions = append(conditions, "park-escalation:not-needed")
	} else if targetUnmet {
		details.Park = &reclaimPark{Status: "not-proposable",
			Reason: "the escalation plan carries no park stage for this request; the shortfall stands"}
		conditions = append(conditions, "park-escalation:unavailable")
	}

	// Measured free-space delta on the source volume (observed system
	// change; the estimate above carries the attribution, §14.1).
	if usage, verr := probe.VolumeUsage(filepath.Dir(disc.Root)); verr == nil &&
		disc.Volume.VolumeID != "" && usage.VolumeID == disc.Volume.VolumeID &&
		usage.FreeToCaller >= disc.Volume.FreeToCaller {
		details.AchievedObserved = usage.FreeToCaller - disc.Volume.FreeToCaller
	} else if verr != nil {
		env.Warnings = append(env.Warnings, fmt.Sprintf("measured free-space delta unavailable: %v", verr))
	}
	details.AchievedEstimated = achieved

	// ---- outcome --------------------------------------------------------
	switch {
	case target != nil && achieved < *target:
		details.Shortfall = *target - achieved
		conditions = append(conditions, "shortfall")
	case target == nil && !anyExecuted:
		// §17.5 exit 8: no useful gain (nothing was released and no park
		// ran). Refusing to manufacture a saving is the correct outcome.
		conditions = append(conditions, "no-useful-gain")
	}

	env.Outcome = "ok"
	env.WorkspaceID = string(sess.resolveWorkspaceID(opts.WorkspaceName, disc.Root))
	env.Conditions = conditions
	env.Bytes = &BytesSummary{
		FreedEstimated: details.AchievedEstimated,
		FreedObserved:  details.AchievedObserved,
	}
	env.Details = details
	emit(env, *jsonOut, streams, renderReclaimHuman(details))
	switch {
	case target != nil && achieved < *target:
		return ExitShortfall
	case target == nil && !anyExecuted:
		return ExitShortfall
	default:
		return ExitOK
	}
}

// runReclaimTrimStep executes one planned trim step through the same
// approval UX as `ebb trim`: a grouped confirmation listing the group's
// outputs and recreate command (--yes accepts; a non-terminal without
// --yes cannot confirm, so the step is skipped and reported). A step
// blocked by its own validation (modified or unmanaged group, changed
// applicability, nothing left to trim) routes around and is reported as
// skipped (§17.4 F10/F11); any other failure of an EXECUTING step
// (vault, verification, removal-blocked, source-changed, cancellation)
// is returned as an error and fails the whole command.
func runReclaimTrimStep(
	ctx context.Context, sess *session, coord *lifecycle.Coordinator,
	deps Deps, streams Streams, disc discovery, opts lifecycle.CaptureOptions,
	declared map[string]policy.Regenerate, s planner.Step, yes bool,
	warnings *[]string,
) (reclaimTrimStep, error) {
	groupID := s.Groups[0]
	step := reclaimTrimStep{
		Group:          groupID,
		Status:         "skipped",
		BytesEstimated: stepTotal(s),
		Reason:         "approval unavailable (stdin is not a terminal and --yes was not given)",
	}
	if g, ok := declared[groupID]; ok {
		step.Recreate = reclaimCommandForDisplay(g)
		step.Outputs = g.Outputs
	}

	approved := false
	switch {
	case yes:
		approved = true
	case deps.StdinIsTerminal != nil && deps.StdinIsTerminal():
		fmt.Fprint(streams.Err, trimApprovalText(disc.Root, []string{groupID}, declared))
		approved = confirmYes(deps, streams.Err, "")
	default:
		return step, nil
	}
	if !approved {
		step.Reason = "the removal confirmation was declined"
		return step, nil
	}

	trimOpts := opts
	trimOpts.DoTrim = []string{groupID}
	// The recorded decision is the confirmation above (defense in depth:
	// lifecycle re-validates policy and applicability itself).
	trimOpts.ApprovalReady = func(string) error { return nil }
	var res lifecycle.TrimResult
	err := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		res, rErr = coord.Trim(ctx, lifecycleVaultRef(repoDir, passfile), disc.Root, trimOpts)
		return rErr
	})
	if err != nil {
		var blocked *lifecycle.ErrDestructiveBlocked
		var invalid *lifecycle.ErrInvalidOptions
		if errors.As(err, &blocked) || errors.As(err, &invalid) {
			step.Reason = codedMessage(err)
			*warnings = append(*warnings, fmt.Sprintf("reclaim: trim group %s blocked: %v", groupID, err))
			return step, nil
		}
		return step, err
	}
	step.Status = "removed"
	step.Reason = ""
	step.EntriesRemoved = res.EntriesRemoved
	step.SnapshotID = string(res.Snapshot.SnapshotID)
	for i, g := range res.Groups {
		if g == groupID && i < len(res.ReclaimCommands) {
			step.Recreate = res.ReclaimCommands[i]
		}
	}
	*warnings = append(*warnings, res.Snapshot.Warnings...)
	return step, nil
}

// parkStepOf consults the planner with ParkApproved=true and returns the
// park escalation step it would propose (nil when the request is already
// satisfied without one). The planner is the single estimator; the
// returned step is used ONLY for the preview — executing park always goes
// through the escalation gates below.
func parkStepOf(in planner.Input) (*planner.Step, error) {
	parkPlan, err := planner.PlanReclaim(in)
	if err != nil {
		return nil, err
	}
	for i := range parkPlan.Steps {
		if parkPlan.Steps[i].Kind == planner.StepPark {
			s := parkPlan.Steps[i]
			return &s, nil
		}
	}
	return nil, nil
}

func proposedPark(s *planner.Step) *reclaimPark {
	pk := &reclaimPark{Status: "proposed", EstimatedAdditionalRelease: stepTotal(*s)}
	if s.EstimateUnknown {
		pk.EstimatedAdditionalRelease = 0
		pk.Reason = "release estimate unknown"
	}
	return pk
}

// reclaimEscalationGate enforces the §17.4 escalation gates: the full
// §17.2 writer assertion (flag or the interactive confirmation itself;
// never silent) AND an explicit typed confirmation of the material change
// of recovery conditions. --yes does not answer it; without a terminal it
// cannot be answered, so the escalation is declined with the reason.
func reclaimEscalationGate(deps Deps, streams Streams, disc discovery, assertStopped bool, pk *reclaimPark) (string, bool, string) {
	isTTY := deps.StdinIsTerminal != nil && deps.StdinIsTerminal()
	if !isTTY {
		return "", false, blockerMessage(CodeEscalationUnconfirmed, "reclaim",
			"the park escalation needs an explicit confirmation on a terminal (stdin is not one); --yes never supplies it (Foundation §17.4)",
			"Safe action: rerun `ebb reclaim` in a terminal and confirm the escalation, or accept the reported shortfall")
	}
	// The typed confirmation doubles as the interactive writer assertion
	// when the flag was not given (same rule as `ebb park`).
	fmt.Fprint(streams.Err, escalationText(disc, pk))
	if !confirmYes(deps, streams.Err, "") {
		return "", false, blockerMessage(CodeEscalationUnconfirmed, "reclaim",
			"the park escalation confirmation was declined; the workspace was NOT removed",
			"Safe action: the achieved-so-far result stands; rerun `ebb reclaim` to try again or review `ebb plan`")
	}
	assertion := assertionFlagSource
	if !assertStopped {
		assertion = assertionInteractiveSource
	}
	return assertion, true, ""
}

// escalationText renders the escalation preview: additional estimated
// release against the workspace being REMOVED, plus the retention
// headroom note (§5.4/§17.4).
func escalationText(disc discovery, pk *reclaimPark) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Park escalation: trim alone does not reach the request.\n")
	fmt.Fprintf(&b, "  estimated additional release: %s\n", estBytes(pk.EstimatedAdditionalRelease))
	fmt.Fprintf(&b, "  the workspace %s will be REMOVED after a verified capture and parking\n", disc.Root)
	fmt.Fprintf(&b, "  retention needs headroom for about %s of preserved bytes (volume %s has %s free)\n",
		HumanBytes(disc.Summary.PreservedBytes), volumeLabel(disc), HumanBytes(disc.Volume.FreeToCaller))
	fmt.Fprintf(&b, "  this stage needs its own confirmation and a stopped-writers assertion (--yes does not answer it)\n")
	fmt.Fprintf(&b, "Escalate to parking? type 'yes': ")
	return b.String()
}

// estBytes renders an estimate that may be unknown.
func estBytes(n int64) string {
	if n <= 0 {
		return "unknown"
	}
	return HumanBytes(n)
}

// volumeLabel renders the volume id for display.
func volumeLabel(disc discovery) string {
	if disc.Volume.VolumeID == "" {
		return "(default)"
	}
	return disc.Volume.VolumeID
}

// previewTrims maps the plan's trim steps onto the preview payload.
func previewTrims(plan planner.Plan, pol policy.Policy) []reclaimTrimStep {
	declared := map[string]policy.Regenerate{}
	for _, g := range pol.Regenerate {
		declared[g.ID] = g
	}
	var out []reclaimTrimStep
	for _, s := range plan.Steps {
		if s.Kind != planner.StepTrim {
			continue
		}
		st := reclaimTrimStep{Group: s.Groups[0], Status: "planned", BytesEstimated: stepTotal(s)}
		if g, ok := declared[st.Group]; ok {
			st.Recreate = reclaimCommandForDisplay(g)
			st.Outputs = g.Outputs
		}
		out = append(out, st)
	}
	return out
}

// planBlockers collects the plan's blockers for the report.
func planBlockers(plan planner.Plan) []string {
	var out []string
	for _, s := range plan.Steps {
		out = append(out, s.Blockers...)
	}
	return out
}

// sumPlanAchieved sums the executed plan's achieved map.
func sumPlanAchieved(plan planner.Plan) int64 {
	var n int64
	for _, v := range plan.Achieved {
		n += v
	}
	return n
}

// needsEscalation reports whether the staged plan proposes the park stage
// for this request: a target the trim stages alone cannot reach, or (no
// target) trim stages that release nothing meaningful.
func needsEscalation(target *int64, plan planner.Plan) bool {
	if target != nil {
		return sumPlanAchieved(plan) < *target
	}
	for _, s := range plan.Steps {
		if s.Kind == planner.StepTrim && (stepTotal(s) > 0 || s.EstimateUnknown) {
			return false
		}
	}
	return true
}

// renderReclaimHuman renders the staged plan (dry run) or the result
// report (§17.4: achieved vs requested, groups released, recreate
// commands, park outcome, remaining blockers).
func renderReclaimHuman(d reclaimDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	if d.DryRun {
		line("reclaim plan for workspace %q (dry run: nothing will be removed; no captures are made)\n", d.Workspace)
	} else {
		line("reclaim for workspace %q\n", d.Workspace)
	}
	if d.Target != nil {
		line("  requested: %s\n", HumanBytes(*d.Target))
	} else {
		line("  requested: as much as safely possible\n")
	}
	for i, s := range d.Trims {
		cmdLine := "(no recreate command recorded)"
		if len(s.Recreate) > 0 {
			cmdLine = strings.Join(s.Recreate, " ")
		}
		switch s.Status {
		case "planned":
			line("  stage %d trim %s [%s]: outputs: %s; recreate: %s\n",
				i+1, s.Group, HumanBytes(s.BytesEstimated), strings.Join(s.Outputs, ", "), cmdLine)
		case "removed":
			line("  removed group %s; recreate with: %s (%d entries; plan retained as snapshot %s)\n",
				s.Group, cmdLine, s.EntriesRemoved, s.SnapshotID)
		default:
			line("  skipped group %s: %s\n", s.Group, s.Reason)
		}
	}
	if d.Park != nil {
		switch d.Park.Status {
		case "proposed":
			line("  park escalation stage: would REMOVE the workspace after a verified capture and parking;\n")
			line("    staged-plan additional release: %s; needs its own confirmation and a stopped-writers assertion (--yes does not answer it)\n",
				estBytes(d.Park.EstimatedAdditionalRelease))
		case "executed":
			line("  park escalation executed: workspace removed; snapshot %s retained (pinned)\n", d.Park.SnapshotID)
			line("    space returned: %s measured (estimated %s); writer assertion: %s\n",
				HumanBytes(d.Park.FreedObserved), HumanBytes(d.Park.FreedEstimated), d.Park.WriterAssertion)
			line("    reopen later with: ebb open %s\n", d.Workspace)
		case "not-needed":
			line("  park escalation not needed: %s\n", d.Park.Reason)
		case "declined":
			line("  park escalation declined: %s\n", d.Park.Reason)
		case "not-proposable":
			line("  park escalation unavailable: %s\n", d.Park.Reason)
		}
	}
	if !d.DryRun {
		line("  achieved (estimated): %s", HumanBytes(d.AchievedEstimated))
		if d.AchievedObserved > 0 {
			line("; measured free-space delta: %s", HumanBytes(d.AchievedObserved))
		}
		line("\n")
	}
	if d.Shortfall > 0 {
		line("  shortfall: %s still needed — honest result; no unsafe removal was performed\n", HumanBytes(d.Shortfall))
	}
	if d.Target == nil && d.AchievedEstimated == 0 && d.Park != nil && d.Park.Status != "executed" {
		line("  no useful gain: no safe route released measurable space and no park ran (§17.5 exit 8 is the honest result)\n")
	}
	for _, r := range d.Plan.Reasons {
		line("  note: %s\n", r)
	}
	for _, w := range d.Plan.Warnings {
		line("  warning: %s\n", w)
	}
	for _, bl := range d.Blockers {
		line("  blocker: %s\n", bl)
	}
	if d.Plan.Result != "" && d.DryRun {
		line("  plan result: %s\n", d.Plan.Result)
	}
	if d.DryRun {
		line("  run without --dry-run to execute the plan\n")
	}
	return b.String()
}
