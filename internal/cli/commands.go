package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"ebb/internal/domain"
	"ebb/internal/planner"
	"ebb/internal/policy"
)

// cmdVersion implements `ebb version`.
func cmdVersion(args []string, streams Streams) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(streams.Err, "ebb version: takes no arguments (got %q)\n", fs.Arg(0))
		return ExitUsage
	}

	details := map[string]string{
		"version":       Version,
		"restic_target": ResticTarget,
		"go_version":    goVersion(),
	}
	if *jsonOut {
		env := newEnvelope("version", "ok")
		env.Details = details
		if err := env.emitJSON(streams.Out); err != nil {
			fmt.Fprintf(streams.Err, "ebb: writing result: %v\n", err)
			return ExitUsage
		}
		return ExitOK
	}
	fmt.Fprintf(streams.Err, "ebb %s\nrestic target: %s\ngo: %s\n",
		Version, ResticTarget, goVersion())
	return ExitOK
}

// cmdInspect implements `ebb inspect <path>`. The inventory seam is a
// wave-B stub, so the command currently reports "not yet integrated"
// with exit 2 (unsupported command feature).
func cmdInspect(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintf(streams.Err, "ebb inspect: takes at most one path\n")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}

	scan := deps.ScanInventory
	if scan == nil {
		scan = DefaultDeps().ScanInventory
	}
	_, _, _, err := scan(root)
	env := newEnvelope("inspect", "error")
	if err != nil {
		if errors.Is(err, ErrNotIntegrated) {
			env.Outcome = "unsupported"
			env.Errors = []string{"inspect: inventory scan " + err.Error()}
		} else {
			env.Errors = []string{fmt.Sprintf("inspect %s: %v", root, err)}
		}
	} else {
		// Unreachable until wave B wires a real scanner; kept so the
		// success path is explicit rather than implicit.
		env.Outcome = "ok"
	}
	emit(env, *jsonOut, streams, fmt.Sprintf("inspect %s: %s\n", root, env.Outcome))
	if env.Outcome == "ok" {
		return ExitOK
	}
	if env.Outcome == "unsupported" {
		return ExitUsage
	}
	return ExitBlocked
}

// planDetails is the --json payload of the plan command.
type planDetails struct {
	Workspace string       `json:"workspace"`
	Plan      planner.Plan `json:"plan"`
}

// cmdPlan implements `ebb plan <path>`: parse the Ebbfile (or apply
// conservative defaults), load or scan an inventory, resolve routes and
// compute the effect-free plan.
func cmdPlan(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	fromInventory := fs.String("from-inventory", "", "load a saved inventory JSON instead of scanning")
	targetStr := fs.String("target", "", "space goal, e.g. 25GiB (default: maximal safe release)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb plan: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}

	env := newEnvelope("plan", "error")
	fail := func(code int) int {
		emit(env, *jsonOut, streams, "")
		return code
	}

	// Target.
	var target *int64
	if *targetStr != "" {
		t, err := ParseByteCount(*targetStr)
		if err != nil {
			env.Errors = []string{fmt.Sprintf("--target: %v", err)}
			return fail(ExitUsage)
		}
		target = &t
	}

	// Policy: an explicit Ebbfile must parse strictly; when absent the
	// conservative defaults apply (Foundation §7.1).
	pol, polErr := policy.ParseFile(filepath.Join(root, "Ebbfile.toml"))
	switch {
	case polErr == nil:
	case errors.Is(polErr, os.ErrNotExist):
		pol = policy.Default(workspaceLabel(root))
	default:
		env.Errors = []string{polErr.Error()}
		return fail(ExitUsage)
	}

	// Inventory.
	var (
		summary domain.InventorySummary
		entries []domain.Entry
		volume  domain.VolumeUsage
	)
	if *fromInventory != "" {
		inv, err := LoadInventory(*fromInventory)
		if err != nil {
			env.Errors = []string{fmt.Sprintf("--from-inventory: %v", err)}
			return fail(ExitUsage)
		}
		summary, entries, volume = inv.Summary, inv.Entries, inv.Volume
	} else {
		scan := deps.ScanInventory
		if scan == nil {
			scan = DefaultDeps().ScanInventory
		}
		s, es, v, err := scan(root)
		if err != nil {
			if errors.Is(err, ErrNotIntegrated) {
				env.Outcome = "unsupported"
				env.Errors = []string{"plan: inventory scan " + err.Error() + "; pass --from-inventory or wait for wave B"}
			} else {
				env.Errors = []string{fmt.Sprintf("plan %s: %v", root, err)}
			}
			code := ExitBlocked
			if env.Outcome == "unsupported" {
				code = ExitUsage
			}
			return fail(code)
		}
		summary, entries, volume = s, es, v
	}

	resolved, err := policy.Resolve(entries, pol)
	if err != nil {
		env.Errors = []string{err.Error()}
		return fail(ExitUsage)
	}

	plan, err := planner.PlanReclaim(planner.Input{
		Summary:  summary,
		Resolved: resolved,
		Target:   target,
		Volume:   volume,
	})
	if err != nil {
		env.Errors = []string{err.Error()}
		return fail(ExitUsage)
	}

	env.Outcome = planOutcome(plan.Result)
	env.Details = planDetails{Workspace: pol.Workspace.Name, Plan: plan}
	env.Warnings = append(env.Warnings, plan.Warnings...)
	for _, iss := range resolved.Issues {
		env.Warnings = append(env.Warnings, fmt.Sprintf("%s %s: %s", iss.Code, iss.Path, iss.Note))
	}
	human := renderPlanHuman(pol.Workspace.Name, plan)
	emit(env, *jsonOut, streams, human)

	switch plan.Result {
	case planner.ResultNoGain, planner.ResultShortfall:
		return ExitShortfall
	default:
		return ExitOK
	}
}

// planOutcome maps a planner result to an envelope outcome.
func planOutcome(r planner.Result) string {
	switch r {
	case planner.ResultNoGain:
		return "no-gain"
	case planner.ResultShortfall:
		return "shortfall"
	default:
		return "ok"
	}
}

// emit writes the terminal result: JSON to stdout when jsonOut is set,
// otherwise the human text to stderr.
func emit(env Envelope, jsonOut bool, streams Streams, human string) {
	if jsonOut {
		if err := env.emitJSON(streams.Out); err != nil {
			fmt.Fprintf(streams.Err, "ebb: writing result: %v\n", err)
		}
		return
	}
	if human != "" {
		fmt.Fprint(streams.Err, human)
	}
	if len(env.Errors) > 0 {
		for _, e := range env.Errors {
			fmt.Fprintf(streams.Err, "ebb: %s\n", e)
		}
	}
}

// workspaceLabel derives a default workspace name from a root path.
func workspaceLabel(root string) string {
	clean := filepath.Clean(root)
	base := filepath.Base(clean)
	if base == "" || base == "." || base == string(filepath.Separator) {
		return "workspace"
	}
	return base
}

// renderPlanHuman renders the plan for the human stream (stderr).
func renderPlanHuman(workspace string, plan planner.Plan) string {
	var b []byte
	appendLine := func(format string, a ...any) {
		b = append(b, []byte(fmt.Sprintf(format, a...))...)
	}
	appendLine("plan for workspace %q: %s\n", workspace, plan.Result)
	if plan.Target != nil {
		appendLine("target: %d bytes\n", *plan.Target)
	}
	for vol, got := range plan.Achieved {
		appendLine("planned release on volume %s: %d bytes\n", vol, got)
	}
	for i, s := range plan.Steps {
		appendLine("step %d: %s groups=%v", i+1, s.Kind, s.Groups)
		if s.EstimateUnknown {
			appendLine(" reclaim=unknown")
		} else {
			appendLine(" reclaim=%d bytes", stepTotal(s))
		}
		appendLine(" disruption=%s recovery=%s\n", s.Disruption, s.RecoveryRoute)
		if s.Unsupported {
			appendLine("  unsupported in v1\n")
		}
		if s.Escalation {
			appendLine("  escalation: requires its own approval and a stopped-writers confirmation\n")
		}
		for _, bl := range s.Blockers {
			appendLine("  blocker: %s\n", bl)
		}
	}
	for vol, gap := range plan.Shortfall {
		appendLine("shortfall on volume %s: %d bytes\n", vol, gap)
	}
	for _, r := range plan.Reasons {
		appendLine("note: %s\n", r)
	}
	for _, w := range plan.Warnings {
		appendLine("warning: %s\n", w)
	}
	return string(b)
}

// stepTotal sums a step's per-volume estimates. It mirrors the planner
// helper for presentation.
func stepTotal(s planner.Step) int64 {
	var n int64
	for _, v := range s.Reclaimable {
		n += v
	}
	return n
}
