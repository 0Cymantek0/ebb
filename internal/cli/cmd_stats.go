// cmd_stats.go implements `ebb stats` (Wave 3, product plan task 3A +
// 3C wiring): the Developer Space Economy dashboard — lifetime
// reclaimed/restored bytes, workspace counts, space-efficiency ratio,
// clean-desk streak, hoarding score, zombie bytes, SSD-wear proxy and
// top verbs, plus two offline scale comparisons from the embedded
// catalog.
//
// The command is a pure catalog + shallow-scan view: no vault unlock,
// no mutation, no network — except the two deliberate Wave 3 views:
//
//	--share  render the dashboard as a shareable PNG card
//	         (internal/stats/card) next to the terminal output;
//	--web    serve the read-only local control center
//	         (internal/web) until Ctrl+C. --web is interactive-only:
//	         --json is refused for it (its machine surface is the
//	         server's own /api/* endpoints), while --json --share is
//	         allowed and the envelope carries the written card path.
//
// The clutter facts come from the analyse engine's SHALLOW probe (no
// git survey, no docker — staleness falls back to mtimes, which is
// exactly what the rubric wants) under a ~2s budget; on timeout the
// partial facts are used with a warning, never a block.
//
// Exit contract: 0 report produced (an empty journal is a valid report);
// 2 usage (positional arguments, impossible flag combinations); 3
// blocked (catalog read failure, card write failure, server failure);
// 130 cancelled (SIGINT during --web).

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
	"ebb/internal/stats/card"
	"ebb/internal/web"
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
	webOut := fs.Bool("web", false, "serve the read-only local control center on 127.0.0.1 (stop with Ctrl+C)")
	shareOut := fs.Bool("share", false, "export the dashboard as a shareable PNG card")
	outPath := fs.String("out", "", "output path for --share (default: ebb-stats-YYYYMMDD.png in the current directory)")
	if err := fs.Parse(reorderFlags(args, "out")); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(streams.Err, "ebb stats: takes no arguments (got %q); it reports over the whole journal\n", fs.Arg(0))
		return ExitUsage
	}

	// Flag combinations: --web is the interactive view (no --json, no
	// --share); --json --share is the machine form of the card export.
	switch {
	case *webOut && *shareOut:
		fmt.Fprintln(streams.Err, "ebb stats: --web and --share are mutually exclusive; run one view per invocation")
		return ExitUsage
	case *webOut && *jsonOut:
		fmt.Fprintln(streams.Err, "ebb stats: --json cannot combine with --web (the dashboard is interactive; its machine surface is the server's /api endpoints)")
		return ExitUsage
	case *outPath != "" && !*shareOut:
		fmt.Fprintln(streams.Err, "ebb stats: --out only names the --share card's destination file")
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

	// --web: serve the control center over the SAME opened session until
	// the context ends (SIGINT → the server's bounded graceful shutdown
	// → exit 130, the cancellation contract every command honors). The
	// single dispatch-time stats event (statrec.go) is the only
	// recording: serving requests writes nothing to the journal.
	if *webOut {
		return runStatsWeb(env, streams, deps, sess, ctx)
	}

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

	// --share: one deterministic card render (the bytes-comparison
	// sentence, rotation-seeded like the dashboard's own pick) written
	// to --out or the same-day default name in the current directory.
	shareLine := ""
	if *shareOut {
		path := *outPath
		if path == "" {
			path = "ebb-stats-" + time.Now().Format("20060102") + ".png"
		}
		if werr := card.WriteFile(card.Input{
			Metrics:    m,
			Comparison: cmps[0],
			Path:       path,
			AsOf:       time.Now().Format("2006-01-02"),
		}); werr != nil {
			return emitFailure(env, *jsonOut, streams, ExitBlocked,
				fmt.Sprintf("stats: writing the share card: %v", werr))
		}
		env.Conditions = append(env.Conditions, "card:"+path)
		shareLine = fmt.Sprintf("\n share card: %s — paste it in a chat or a PR; the numbers are yours\n", path)
	}

	env.Outcome = "ok"
	env.Conditions = append(env.Conditions, fmt.Sprintf("events:%d", len(events)))
	if facts.Available {
		env.Conditions = append(env.Conditions,
			fmt.Sprintf("scan-stale:%d", facts.StaleArtifactCount))
	} else {
		env.Conditions = append(env.Conditions, "scan-unavailable")
	}
	env.Details = statsDetails{Metrics: m, Comparisons: cmps}
	env.Warnings = append(env.Warnings, scanWarnings...)
	emit(env, *jsonOut, streams, stats.RenderDashboard(m, cmps, true, true)+shareLine)
	return ExitOK
}

// runStatsWeb serves the control center until the context ends. The
// browser opener only fires on an interactive terminal (stdin a TTY):
// piped invocations — CI, tests, remote shells — get the URL printed
// and never spawn an opener.
func runStatsWeb(env Envelope, streams Streams, deps Deps, sess *session, ctx context.Context) int {
	openBrowser := deps.StdinIsTerminal != nil && deps.StdinIsTerminal()
	err := web.Run(ctx, &statsWebProvider{deps: deps, sess: sess, ctx: ctx}, web.Options{
		Out:         streams.Err,
		Err:         streams.Err,
		OpenBrowser: openBrowser,
	})
	if err != nil {
		return emitFailure(env, false, streams, ExitBlocked, fmt.Sprintf("stats --web: %v", err))
	}
	if ctx.Err() != nil {
		return ExitCancelled // SIGINT: clean shutdown, exit 130
	}
	return ExitOK
}

// runShallowScan is the ONE bounded analyse invocation every stats-side
// consumer uses: resolve the configured projects_dir roots and drive the
// engine's shallow probe (no git survey, no docker) under
// statsScanBudget. Both the dashboard's clutter facts
// (gatherScanFacts) and the web control center's recommendations ride
// it, so the two views can never disagree about what was scanned.
//
// Results: configured=false with err=nil means no roots are configured
// (an honest unknown, not a failure); err non-nil is an infrastructure
// failure (state dir, configuration) the caller classifies; warnings
// carries the budget/degradation notes.
func runShallowScan(ctx context.Context, deps Deps) (rep analyse.Report, configured bool, warnings []string, err error) {
	if deps.StateDir == nil {
		return analyse.Report{}, false, nil, fmt.Errorf("state dir %w", ErrNotIntegrated)
	}
	dir, err := deps.StateDir()
	if err != nil {
		return analyse.Report{}, false, nil, fmt.Errorf("state dir: %w", err)
	}
	cfg, err := config.Load(dir)
	if err != nil {
		return analyse.Report{}, false, nil, fmt.Errorf("loading configuration: %w", err)
	}
	roots := cfg.ProjectsDirs()
	if len(roots) == 0 {
		return analyse.Report{}, false, nil, nil
	}

	scanCtx, cancel := context.WithTimeout(ctx, statsScanBudget)
	defer cancel()

	engine := analyse.NewEngine(nil, nil, nil) // shallow only: no git survey, no docker
	rep = engine.Scan(scanCtx, roots)

	if scanCtx.Err() != nil {
		warnings = append(warnings,
			fmt.Sprintf("clutter scan hit its %s budget; facts are partial (%d project(s) probed)", statsScanBudget, rep.Scanned))
	}
	// The shallow engine's own honesty notes ride along, minus the one
	// degradation this invocation builds in (no git surveyor wired).
	for _, w := range rep.Warnings {
		if strings.Contains(w, "git survey unavailable") {
			continue
		}
		warnings = append(warnings, "clutter scan: "+w)
	}
	return rep, true, warnings, nil
}

// gatherScanFacts maps the shared shallow scan into stats.ScanFacts. A
// missing projects_dir yields Available=false; a timeout yields partial
// facts plus a warning (never a failure).
func gatherScanFacts(ctx context.Context, deps Deps) (stats.ScanFacts, []string) {
	rep, configured, warnings, err := runShallowScan(ctx, deps)
	if err != nil || !configured {
		if err != nil {
			warnings = []string{fmt.Sprintf("clutter scan skipped: %v", err)}
		}
		return stats.ScanFacts{}, warnings
	}

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
	return facts, warnings
}
