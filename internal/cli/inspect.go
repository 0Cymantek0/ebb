// cmdInspect implements `ebb inspect <path>` (Foundation §5.3, §8.1):
// the real metadata-first pipeline through Deps — identity, volume,
// Git topology, tracked-files evidence, no-digest scan, policy
// resolution and a plan preview — assembled into an InspectReport.
//
// Exit contract: 0 for a completed inspection (blockers are data, not
// failures); 2 for usage/schema errors; 3 when the path is missing (and
// for infrastructure failures that prevent completion: unidentifiable
// root or incomplete scan).

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"ebb/internal/planner"
)

func cmdInspect(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb inspect: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}

	env := newEnvelope("inspect", "error")
	disc, err := runDiscovery(context.Background(), deps, root, streams.Err)
	if err != nil {
		var ce *cliError
		if errors.As(err, &ce) {
			env.Errors = []string{fmt.Sprintf("inspect %s: %v", root, err)}
			emit(env, *jsonOut, streams, "")
			return ce.code
		}
		env.Errors = []string{fmt.Sprintf("inspect %s: %v", root, err)}
		emit(env, *jsonOut, streams, "")
		return ExitBlocked
	}

	// Planner preview without a target: what a reclaim COULD do with
	// this state. Preview grants no removal authority (Foundation §17.1).
	plan, err := planner.PlanReclaim(planner.Input{
		Summary:  disc.Summary,
		Resolved: disc.Resolved,
		Volume:   disc.Volume,
	})
	if err != nil {
		env.Errors = []string{fmt.Sprintf("inspect %s: %v", root, err)}
		emit(env, *jsonOut, streams, "")
		return ExitUsage
	}

	report := buildInspectReport(disc, plan)
	env.Outcome = "ok"
	env.Details = report
	env.Warnings = append(env.Warnings, report.Warnings...)
	env.Warnings = append(env.Warnings, plan.Warnings...)
	for _, iss := range disc.Resolved.Issues {
		env.Warnings = append(env.Warnings, fmt.Sprintf("%s %s: %s", iss.Code, iss.Path, iss.Note))
	}

	emit(env, *jsonOut, streams, renderInspectHuman(report))
	return ExitOK
}
