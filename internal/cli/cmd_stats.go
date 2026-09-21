// cmd_stats.go implements `ebb stats` (Wave 3, product plan task 3A):
// the Developer Space Economy dashboard — lifetime reclaimed/restored
// bytes, workspace counts, space-efficiency ratio, clean-desk streak,
// hoarding score, zombie bytes, SSD-wear proxy and top verbs, plus two
// offline scale comparisons from the embedded catalog.
//
// The command is a pure catalog + shallow-scan view: no vault unlock,
// no mutation, no network. The clutter facts come from the analyse
// engine's SHALLOW probe (no git survey, no docker — staleness falls
// back to mtimes, which is exactly what the rubric wants) under a ~2s
// budget; on timeout the partial facts are used with a warning, never
// a block.
//
// Exit contract: 0 report produced (an empty journal is a valid report);
// 2 usage (positional arguments are not accepted); 3 blocked (catalog
// read failure).

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"ebb/internal/analyse"
	"ebb/internal/config"
	"ebb/internal/stats"
)

// statsScanBudget bounds the shallow clutter scan (~2s): the dashboard
// is a view people glance at, and partial facts beat a slow render.
const statsScanBudget = 2 * time.Second

// statsDetails is the --json payload: the metrics object plus the two
// rendered comparisons (the same sentences the dashboard shows).
type statsDetails struct {
	Metrics     stats.Metrics       `json:"metrics"`
	Comparisons [2]stats.Comparison `json:"comparisons"`
}

func cmdStats(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(streams.Err, "ebb stats: takes no arguments (got %q); it reports over the whole journal\n", fs.Arg(0))
		return ExitUsage
	}

	env := newEnvelope("stats", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("stats: %v", err))
	}
	defer sess.close()

	ctx, stop := commandContext(deps)
	defer stop()

	events, err := sess.cat.ListStatEvents(ctx, 0)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, ExitBlocked,
			fmt.Sprintf("stats: reading the stats journal: %v", err))
	}
	summaries, err := sess.cat.ListWorkspaceSummaries()
	if err != nil {
		return emitFailure(env, *jsonOut, streams, ExitBlocked,
			fmt.Sprintf("stats: reading workspace summaries: %v", err))
	}
	facts, scanWarnings := gatherScanFacts(ctx, deps)

	m := stats.Compute(events, summaries, facts)
	cmps := [2]stats.Comparison{
		stats.PickForBytes(m.LifetimeReclaimedBytes, uint64(m.TotalInvocations)),
		stats.PickForCount(m.TotalInvocations, uint64(m.TotalInvocations)),
	}

	env.Outcome = "ok"
	env.Conditions = []string{fmt.Sprintf("events:%d", len(events))}
	if facts.Available {
		env.Conditions = append(env.Conditions,
			fmt.Sprintf("scan-stale:%d", facts.StaleArtifactCount))
	} else {
		env.Conditions = append(env.Conditions, "scan-unavailable")
	}
	env.Details = statsDetails{Metrics: m, Comparisons: cmps}
	env.Warnings = append(env.Warnings, scanWarnings...)
	emit(env, *jsonOut, streams, stats.RenderDashboard(m, cmps, false, false))
	return ExitOK
}

// gatherScanFacts drives the analyse engine's shallow probe over the
// configured projects_dir roots and maps its stale findings (the
// engine's own 30-day staleness threshold) into stats.ScanFacts. A
// missing projects_dir yields Available=false; a timeout yields
// partial facts plus a warning (never a failure).
func gatherScanFacts(ctx context.Context, deps Deps) (stats.ScanFacts, []string) {
	if deps.StateDir == nil {
		return stats.ScanFacts{}, nil
	}
	dir, err := deps.StateDir()
	if err != nil {
		return stats.ScanFacts{}, []string{fmt.Sprintf("clutter scan skipped: state dir: %v", err)}
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return stats.ScanFacts{}, []string{fmt.Sprintf("clutter scan skipped: loading configuration: %v", err)}
	}
	roots := cfg.ProjectsDirs()
	if len(roots) == 0 {
		// No roots configured: an honest unknown; the renderer marks it.
		return stats.ScanFacts{}, nil
	}

	scanCtx, cancel := context.WithTimeout(ctx, statsScanBudget)
	defer cancel()

	engine := analyse.NewEngine(nil, nil, nil) // shallow only: no git survey, no docker
	rep := engine.Scan(scanCtx, roots)

	var facts stats.ScanFacts
	facts.Available = true
	for _, p := range rep.Projects {
		if p.Offline {
			continue
		}
		switch p.Category {
		case analyse.CategoryStale, analyse.CategoryAbandoned:
			// Untouched beyond the 30-day threshold. Shielded projects
			// still count: clutter is clutter even when it carries
			// unpushed work.
			facts.StaleArtifactCount++
			facts.StaleReclaimableBytes += p.FootprintBytes
			if age := int(p.AgeDays); age > facts.WorstStaleAgeDays {
				facts.WorstStaleAgeDays = age
			}
		}
	}
	var warnings []string
	if scanCtx.Err() != nil {
		warnings = append(warnings,
			fmt.Sprintf("clutter scan hit its %s budget; facts are partial (%d project(s) probed)", statsScanBudget, rep.Scanned))
	}
	// The shallow engine's own honesty notes ride along, minus the one
	// degradation this command builds in (no git surveyor wired).
	for _, w := range rep.Warnings {
		if strings.Contains(w, "git survey unavailable") {
			continue
		}
		warnings = append(warnings, "clutter scan: "+w)
	}
	return facts, warnings
}
