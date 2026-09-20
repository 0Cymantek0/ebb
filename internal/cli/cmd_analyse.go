// cmd_analyse.go implements `ebb analyse` (alias `analyze`; product
// evolution plan §11, ADR D037): autonomous workspace discovery over
// the configured projects_dir roots (or one explicit directory),
// shallow footprint probing, staleness/merge classification and batch
// reclamation recommendations.
//
// Scan mode is 100% non-destructive: it stats, lists and reads one
// manifest, nothing else. Destructive action exists ONLY behind the
// explicit batch flags:
//
//	--reclaim-stale     print (and, when confirmed, execute) the exact
//	                    per-project `ebb reclaim --yes` runs through the
//	                    in-process command — the full lifecycle gates
//	                    (capture, verify, grouped approvals) stay in
//	                    charge; only unshielded stale projects run.
//	--prune-worktrees   print (and, when confirmed, execute) native
//	                    `git worktree remove <path>` for merged+clean+
//	                    unshielded linked worktrees only, each listed
//	                    before execution.
//
// Execution consent: --yes (headless) or a per-item typed confirmation
// (interactive). Without either, the flags are print-only. Any failure
// skips that project and continues; the report lists every item.
//
// Exit contract: 0 ok; 2 usage; 3 blocked (no scan roots configured —
// the message shows how to add one); 130 cancelled. No secrets are
// involved anywhere on this surface.

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"ebb/internal/analyse"
	"ebb/internal/config"
)

// analyseDetails is the --json payload: the full scan report plus the
// batch-item ledger (present whenever a batch flag was given).
type analyseDetails struct {
	analyse.Report
	// Batches carries one entry per batch-flag item (printed or
	// executed).
	Batches []analyseBatchItem `json:"batches,omitempty"`
}

// analyseBatchItem is one batch action's outcome.
type analyseBatchItem struct {
	Project string   `json:"project"`
	Action  string   `json:"action"` // reclaim | worktree-remove
	Status  string   `json:"status"` // printed | executed | skipped-declined | skipped-shielded | failed
	Detail  string   `json:"detail,omitempty"`
	Command []string `json:"command,omitempty"`
}

func cmdAnalyse(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("analyse", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	dockerFlag := fs.Bool("docker", false, "append the Docker tier analysis (workspace-correlated, read-only)")
	reclaimStale := fs.Bool("reclaim-stale", false, "act on stale unshielded projects via `ebb reclaim` (print-only without --yes or a typed confirmation)")
	pruneWorktrees := fs.Bool("prune-worktrees", false, "act on merged+clean unshielded worktrees via native `git worktree remove` (print-only without --yes or a typed confirmation)")
	yes := fs.Bool("yes", false, "accept batch execution without per-item prompts (never affects the projects' own safety gates)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb analyse: takes at most one path (a directory whose immediate children are scanned)")
		return ExitUsage
	}

	ctx, stop := commandContext(deps)
	defer stop()

	env := newEnvelope("analyse", "error")

	// ---- roots: explicit path or the configured projects_dir list ----
	var roots []string
	if fs.NArg() == 1 {
		abs, err := filepath.Abs(fs.Arg(0))
		if err != nil {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("ebb analyse: resolving path %q: %v", fs.Arg(0), err))
		}
		roots = []string{abs}
	} else {
		if deps.StateDir == nil {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("ebb analyse: state dir %v", ErrNotIntegrated))
		}
		dir, err := deps.StateDir()
		if err != nil {
			return emitFailure(env, *jsonOut, streams, ExitBlocked,
				fmt.Sprintf("ebb analyse: state directory: %v", err))
		}
		cfg, err := config.Load(dir)
		if err != nil {
			return emitFailure(env, *jsonOut, streams, ExitBlocked,
				fmt.Sprintf("ebb analyse: loading configuration: %v", err))
		}
		roots = cfg.ProjectsDirs()
		if len(roots) == 0 {
			return emitFailure(env, *jsonOut, streams, ExitBlocked,
				"ebb analyse: no scan roots are configured, so there is nothing to analyse. Safe action: add a parent directory with `ebb config add projects_dir <path>` (or scan one directly: `ebb analyse <path>`)")
		}
	}

	// ---- scan ---------------------------------------------------------
	engine := analyse.NewEngine(deps.AnalyseGitSurvey, nil, deps.AnalyseLockProbe)
	rep := engine.Scan(ctx, roots)

	var humanExtra strings.Builder

	// ---- docker tiers (explicit flag; honest degradation) --------------
	if *dockerFlag {
		if deps.AnalyseDocker == nil {
			rep.Warnings = append(rep.Warnings,
				"docker analysis unavailable: no docker engine is wired in this build (tiers were not gathered)")
		} else {
			rootsForDocker := make([]string, 0, len(rep.Projects))
			for _, p := range rep.Projects {
				if !p.Offline {
					rootsForDocker = append(rootsForDocker, p.Root)
				}
			}
			dr, derr := deps.AnalyseDocker.Report(ctx, rootsForDocker)
			switch {
			case derr != nil:
				rep.Warnings = append(rep.Warnings, "docker analysis failed: "+derr.Error())
			case !dr.Available:
				rep.Warnings = append(rep.Warnings, "docker engine unavailable (daemon not reachable or unsupported); tiers were not gathered")
				for _, w := range dr.Warnings {
					rep.Warnings = append(rep.Warnings, "docker: "+w)
				}
			default:
				rep.Warnings = append(rep.Warnings, dr.Warnings...)
				rep.Docker = &dr
			}
		}
	}

	// ---- batches ------------------------------------------------------
	// The details payload snapshots the report AFTER the docker section
	// (embedded by value); batches append to it below.
	details := analyseDetails{Report: rep}
	// Print mode happens without consent; execution additionally needs
	// --yes (headless) or a per-item typed confirmation (interactive).
	interactive := deps.StdinIsTerminal != nil && deps.StdinIsTerminal()
	if *reclaimStale {
		details.Batches = append(details.Batches, analyseRunReclaimBatch(ctx, deps, streams, &rep, interactive, *yes, &humanExtra)...)
	}
	if *pruneWorktrees {
		details.Batches = append(details.Batches, analyseRunPruneBatch(ctx, deps, streams, &rep, interactive, *yes, &humanExtra)...)
	}

	// ---- outcome ------------------------------------------------------
	if ctx.Err() != nil {
		env.Outcome = outcomeForExit(ExitCancelled)
		env.Details = details
		emit(env, *jsonOut, streams, renderAnalyseHuman(details, true))
		return ExitCancelled
	}

	executed, failed := 0, 0
	for _, b := range details.Batches {
		switch b.Status {
		case "executed":
			executed++
		case "failed":
			failed++
		}
	}
	conditions := []string{fmt.Sprintf("scanned:%d", rep.Scanned)}
	if len(rep.OfflineRoots) > 0 {
		conditions = append(conditions, fmt.Sprintf("offline-roots:%d", len(rep.OfflineRoots)))
	}
	if *dockerFlag {
		conditions = append(conditions, "docker")
	}
	if len(details.Batches) > 0 {
		conditions = append(conditions, fmt.Sprintf("batch-items:%d", len(details.Batches)),
			fmt.Sprintf("batch-executed:%d", executed), fmt.Sprintf("batch-failed:%d", failed))
	}
	env.Outcome = "ok"
	env.Conditions = conditions
	env.Details = details
	emit(env, *jsonOut, streams, renderAnalyseHuman(details, false)+humanExtra.String())
	return ExitOK
}

// analyseRunReclaimBatch prints (and, with consent, executes) one
// `ebb reclaim --yes` per unshielded stale project THROUGH the
// in-process command function, so the full lifecycle validation,
// capture, verification and approval gates stay in charge. Shielded
// stale projects are listed as skipped-shielded. A failing project
// skips and the batch continues.
func analyseRunReclaimBatch(ctx context.Context, deps Deps, streams Streams, rep *analyse.Report, interactive, yes bool, out *strings.Builder) []analyseBatchItem {
	var items []analyseBatchItem
	fmt.Fprintln(out)
	fmt.Fprintln(out, "batch: --reclaim-stale (ebb reclaim --yes per unshielded stale project)")
	for i := range rep.Projects {
		p := &rep.Projects[i]
		if p.Category != analyse.CategoryStale {
			continue
		}
		cmd := []string{"ebb", "reclaim", p.Root, "--yes"}
		item := analyseBatchItem{Project: p.Root, Action: "reclaim", Command: cmd}
		switch {
		case p.Shielded():
			item.Status = "skipped-shielded"
			item.Detail = "shielded " + strings.Join(p.Shields, ", ") + " — resolve the shield first (analyse never batches shielded projects)"
		default:
			fmt.Fprintf(out, "  %s\n", strings.Join(cmd, " "))
			item.Status = "printed"
			if analyseItemConsent(deps, streams, interactive, yes, strings.Join(cmd, " ")) {
				fmt.Fprintf(out, "  executing: %s\n", strings.Join(cmd, " "))
				item.Status, item.Detail = analyseExecReclaim(ctx, deps, streams, p.Root)
				verdict := "failed"
				if item.Status == "executed" {
					verdict = "done"
				}
				fmt.Fprintf(out, "  %s: %s (%s)\n", verdict, p.Name, item.Detail)
			}
		}
		items = append(items, item)
	}
	return items
}

// analyseExecReclaim runs one in-process `ebb reclaim <root> --yes`.
// The inner command's own streams are discarded: its envelope would
// corrupt the outer one, and in --json mode its human text must not
// leak to stderr (Foundation §17.1). Only the exit code and a summary
// line are surfaced.
func analyseExecReclaim(ctx context.Context, deps Deps, streams Streams, root string) (status, detail string) {
	code := cmdReclaim([]string{root, "--yes"}, Streams{Out: io.Discard, Err: io.Discard}, deps)
	switch code {
	case ExitOK:
		return "executed", "reclaim completed"
	case ExitShortfall:
		// An honest per-project outcome (e.g. nothing safe left to trim):
		// reported, not a failure.
		return "executed", "reclaim completed with a shortfall/no-useful-gain outcome (nothing unsafe was done)"
	default:
		return "failed", fmt.Sprintf("reclaim exited %d — project skipped, batch continues (rerun `ebb reclaim %s` to inspect)", code, root)
	}
}

// analyseRunPruneBatch prints (and, with consent, executes) native
// `git worktree remove <path>` for merged+clean+unshielded linked
// worktrees ONLY, each listed before execution. The git binary's own
// dirty/locked refusal is defense in depth behind ebb's gate.
func analyseRunPruneBatch(ctx context.Context, deps Deps, streams Streams, rep *analyse.Report, interactive, yes bool, out *strings.Builder) []analyseBatchItem {
	var items []analyseBatchItem
	fmt.Fprintln(out)
	fmt.Fprintln(out, "batch: --prune-worktrees (native git worktree remove per merged+clean+unshielded worktree)")
	gitBin, gerr := exec.LookPath("git")
	if gerr != nil {
		fmt.Fprintln(out, "  (no git binary on PATH — commands are printed only)")
	}
	for i := range rep.Projects {
		p := &rep.Projects[i]
		if p.Category != analyse.CategoryMergedWorktree {
			continue
		}
		cmd := []string{"git", "worktree", "remove", p.Root}
		item := analyseBatchItem{Project: p.Root, Action: "worktree-remove", Command: cmd}
		switch {
		case p.Shielded():
			item.Status = "skipped-shielded"
			item.Detail = "shielded " + strings.Join(p.Shields, ", ") + " — resolve the shield first"
		case gerr != nil:
			fmt.Fprintf(out, "  %s\n", strings.Join(cmd, " "))
			item.Status = "printed"
			item.Detail = "no git binary on PATH; command printed only"
		default:
			fmt.Fprintf(out, "  %s\n", strings.Join(cmd, " "))
			item.Status = "printed"
			if analyseItemConsent(deps, streams, interactive, yes, strings.Join(cmd, " ")) {
				// `git worktree remove <path>` resolves the path against
				// the repository it runs in: anchor it to the main
				// checkout the survey reported (WorktreeMain), so the
				// call works from any process cwd. Without an anchor the
				// attempt runs bare and an honest failure is reported.
				gitArgs := []string{"worktree", "remove", p.Root}
				if p.Repo.WorktreeMain != "" {
					gitArgs = append([]string{"-C", p.Repo.WorktreeMain}, gitArgs...)
				}
				fmt.Fprintf(out, "  executing: %s\n", strings.Join(cmd, " "))
				run := exec.CommandContext(ctx, gitBin, gitArgs...)
				if outb, err := run.CombinedOutput(); err != nil {
					item.Status = "failed"
					item.Detail = strings.TrimSpace(string(outb))
					if item.Detail == "" {
						item.Detail = err.Error()
					}
					fmt.Fprintf(out, "  failed: %s (%s) — skipped, batch continues\n", p.Name, item.Detail)
				} else {
					item.Status = "executed"
					item.Detail = "worktree removed (git administrative state kept in sync by git itself)"
					fmt.Fprintf(out, "  done: %s\n", p.Name)
				}
			}
		}
		items = append(items, item)
	}
	return items
}

// analyseItemConsent resolves one batch item's execution consent:
// --yes accepts (headless or not); otherwise a terminal gets a typed
// confirmation; a non-terminal without --yes gets print-only. The
// consent NEVER crosses into the projects' own gates (reclaim's park
// escalation, park's writer assertion remain unanswerable by it).
func analyseItemConsent(deps Deps, streams Streams, interactive, yes bool, cmd string) bool {
	if yes {
		return true
	}
	if !interactive {
		return false
	}
	return confirmYes(deps, streams.Err, "  execute? type 'yes' ("+cmd+"): ")
}

// ---- human rendering (plan §11.3 mockup) --------------------------------

// renderAnalyseHuman renders the report to the mockup's shape: scanned
// counts, the four actionable categories with shields and copyable
// commands, subtotals, the total recoverable estimate, then the
// recommendation letters [R] [P] [W] [A].
func renderAnalyseHuman(d analyseDetails, cancelled bool) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	r := d.Report
	line("Ebb workspace analysis\n")
	line("  scanned %d project(s) across %d root(s) (%s estimated footprint — %s)\n",
		r.Scanned, len(r.Roots), HumanBytes(r.Totals.FootprintBytes), "shallow stat estimate, not a full walk")
	if len(r.OfflineRoots) > 0 {
		line("  [OFFLINE] %d root(s) not readable: %s\n", len(r.OfflineRoots), strings.Join(r.OfflineRoots, ", "))
	}

	sections := []struct {
		n   string
		cat analyse.Category
	}{
		{"1. ", analyse.CategoryBloatedActive},
		{"2. ", analyse.CategoryStale},
		{"3. ", analyse.CategoryAbandoned},
		{"4. ", analyse.CategoryMergedWorktree},
	}
	for _, s := range sections {
		var rows []string
		for _, p := range r.Projects {
			if p.Category != s.cat {
				continue
			}
			rows = append(rows, renderAnalyseProject(p))
		}
		if len(rows) == 0 {
			continue
		}
		line("%s%s\n", s.n, analyseSectionTitle(s.cat))
		for _, row := range rows {
			line("  %s\n", row)
		}
		switch s.cat {
		case analyse.CategoryStale:
			line("  Subtotal reclaimable (unshielded, estimated): %s\n", HumanBytes(r.Totals.ReclaimableStale))
		case analyse.CategoryAbandoned:
			line("  Subtotal parkable (estimated): %s\n", HumanBytes(r.Totals.ParkableAbandoned))
		case analyse.CategoryMergedWorktree:
			line("  Subtotal worktrees (unshielded, estimated): %s\n", HumanBytes(r.Totals.WorktreeBytes))
		}
		line("\n")
	}

	line("Total recoverable (estimated): %s\n\n", HumanBytes(r.Totals.RecoverableTotal))

	// Recommendations (copyable).
	stale := countCat(r, analyse.CategoryStale)
	abandoned := countCat(r, analyse.CategoryAbandoned)
	worktrees := countCat(r, analyse.CategoryMergedWorktree)
	if stale+abandoned+worktrees == 0 {
		line("Recommendations: none (no stale, abandoned or merged-worktree projects)\n")
	} else {
		line("Recommendations (copyable):\n")
		if stale > 0 {
			line("  [R] Reclaim stale projects (%d project(s), %s estimated): ebb analyse --reclaim-stale --yes\n",
				stale, HumanBytes(r.Totals.ReclaimableStale))
		}
		if abandoned > 0 {
			line("  [P] Park abandoned projects (%d project(s), %s estimated): run `ebb park <path>` per project above\n",
				abandoned, HumanBytes(r.Totals.ParkableAbandoned))
			line("      (park captures and verifies first, and needs its own writer assertion — analyse never batch-executes it)\n")
		}
		if worktrees > 0 {
			line("  [W] Prune merged worktrees (%d worktree(s), %s estimated): ebb analyse --prune-worktrees --yes\n",
				worktrees, HumanBytes(r.Totals.WorktreeBytes))
		}
		if stale+worktrees > 0 {
			line("  [A] Apply all batch recommendations: ebb analyse --reclaim-stale --prune-worktrees --yes\n")
		} else {
			line("  [A] Apply all batch recommendations: (no batch-executable actions; use the per-project commands above)\n")
		}
	}

	// Honest summary of the non-actionable buckets.
	other := r.Categories[string(analyse.CategoryActive)] + r.Categories[string(analyse.CategoryQuiet)] +
		r.Categories[string(analyse.CategoryUnknown)] + r.Categories[string(analyse.CategoryOffline)]
	if other > 0 {
		line("  (%d other project(s): %d active, %d quiet, %d unknown, %d offline — no recommendation)\n",
			other, r.Categories[string(analyse.CategoryActive)], r.Categories[string(analyse.CategoryQuiet)],
			r.Categories[string(analyse.CategoryUnknown)], r.Categories[string(analyse.CategoryOffline)])
	}

	// Docker tiers.
	if r.Docker != nil {
		line("\nDocker tiers (%s)\n", "workspace-correlated, read-only")
		for _, t := range r.Docker.Tiers {
			if len(t.Items) == 0 {
				continue
			}
			line("  tier %d — %s\n", t.Tier, t.Title)
			for _, it := range t.Items {
				if it.Shield != "" {
					line("    %s  %s  [SHIELDED: %s]\n", it.ID, it.Detail, it.Shield)
				} else {
					line("    %s  %s\n", it.ID, it.Detail)
				}
			}
			if t.CopyCommand != "" {
				line("    copy & run: %s\n", t.CopyCommand)
			}
		}
		if r.Docker.HostSlack > 0 {
			line("  host VHDX slack: %s\n", HumanBytes(r.Docker.HostSlack))
			if r.Docker.SlackCommand != "" {
				line("    copy & run: %s\n", r.Docker.SlackCommand)
			}
		}
	}

	for _, w := range r.Warnings {
		line("warning: %s\n", w)
	}
	if cancelled {
		line("cancelled: the scan or batch was interrupted; partial results above\n")
	}
	return b.String()
}

// analyseSectionTitle renders one category's heading with its live
// thresholds.
func analyseSectionTitle(c analyse.Category) string {
	switch c {
	case analyse.CategoryBloatedActive:
		return fmt.Sprintf("Bloated Active (active within %d days, heavy regenerable output)", int(analyse.ActiveWindow.Hours()/24))
	case analyse.CategoryStale:
		return fmt.Sprintf("Stale (untouched %d-%d days)", int(analyse.StaleAfter.Hours()/24), int(analyse.AbandonedAfter.Hours()/24))
	case analyse.CategoryAbandoned:
		return fmt.Sprintf("Abandoned (untouched >%d days; ready to park)", int(analyse.AbandonedAfter.Hours()/24))
	case analyse.CategoryMergedWorktree:
		return "Merged Worktrees (merged upstream, clean tree)"
	}
	return string(c)
}

// renderAnalyseProject renders one listing row: name, ecosystems, the
// heavy-folder names or age, the estimate, shields, and the copyable
// command.
func renderAnalyseProject(p analyse.Project) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%-28s", p.Name))
	eco := "plain"
	if len(p.Ecosystems) > 0 {
		eco = strings.Join(p.Ecosystems, "/")
	}
	parts = append(parts, fmt.Sprintf("[%-12s]", eco))
	mid := analyseProjectMid(p)
	parts = append(parts, fmt.Sprintf("%-24s", mid))
	parts = append(parts, fmt.Sprintf("%12s estimated", HumanBytes(p.FootprintBytes)))
	if len(p.Shields) > 0 {
		parts = append(parts, strings.Join(p.Shields, " "))
	}
	row := strings.Join(parts, "  ")
	if len(p.Recommendation.Command) > 0 && !p.Shielded() {
		row += "\n       -> " + strings.Join(p.Recommendation.Command, " ")
	} else if len(p.Recommendation.Reason) > 0 {
		row += "\n       (" + p.Recommendation.Reason + ")"
	}
	return row
}

// analyseProjectMid builds the middle column: output-folder names for
// footprint-heavy rows, age/merge evidence otherwise.
func analyseProjectMid(p analyse.Project) string {
	if len(p.OutputRoots) > 0 {
		names := make([]string, 0, len(p.OutputRoots))
		for _, o := range p.OutputRoots {
			names = append(names, o.Name)
		}
		sort.Strings(names)
		return strings.Join(names, " + ")
	}
	if p.AgeDays >= 0 {
		return fmt.Sprintf("untouched %dd", int(p.AgeDays))
	}
	return ""
}

// countCat counts a category's projects.
func countCat(r analyse.Report, c analyse.Category) int { return r.Categories[string(c)] }
