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
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	gitadapter "ebb/internal/adapters/git"
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
// stale projects are listed as skipped-shielded. Immediately before an
// execution the git shields are re-probed: a project that became
// dirty/conflicted/unpushed after the scan is skipped with a clear
// status instead of a doomed reclaim attempt (the lifecycle's own
// re-validation remains the safety authority — this re-probe is the
// honest UX layer in front of it). A failing project skips and the
// batch continues.
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
			cmdLine, ok := renderCommand(cmd)
			if !ok {
				// Unreachable behind the [UNSAFE NAME] shield; handled
				// honestly anyway (F4: never render an unquotable path).
				item.Status = "skipped"
				item.Detail = "command withheld: the project path cannot be quoted safely for the shell"
				items = append(items, item)
				continue
			}
			fmt.Fprintf(out, "  %s\n", cmdLine)
			item.Status = "printed"
			if analyseItemConsent(deps, streams, interactive, yes, cmdLine) {
				if fresh := analyseRecheckShields(ctx, deps, p); len(fresh) > 0 {
					item.Status = "skipped-shielded"
					item.Detail = "newly shielded since the scan (" + strings.Join(fresh, ", ") + ") — resolve the shield, rerun `ebb analyse`, then batch again"
					fmt.Fprintf(out, "  skipped: %s (%s)\n", stripControlChars(p.Name), item.Detail)
				} else {
					fmt.Fprintf(out, "  executing: %s\n", cmdLine)
					item.Status, item.Detail = analyseExecReclaim(ctx, deps, p.Root)
					verdict := "failed"
					if item.Status == "executed" {
						verdict = "done"
					}
					fmt.Fprintf(out, "  %s: %s (%s)\n", verdict, stripControlChars(p.Name), item.Detail)
				}
			}
		}
		items = append(items, item)
	}
	return items
}

// analyseRecheckShields re-runs the git shield probe (the same
// SurveyRepo the scan used) immediately before a batch execution and
// returns the shields that appeared since the scan. A probe error
// returns nil: the re-check degrades honestly and the inner `ebb
// reclaim` gates — which re-validate everything themselves — stay in
// charge. Locked-file shields are scan-time evidence the lifecycle
// re-validates at trim time; only the git facts are cheap to re-probe.
func analyseRecheckShields(ctx context.Context, deps Deps, p *analyse.Project) []string {
	if deps.AnalyseGitSurvey == nil || !p.Repo.IsRepo {
		return nil
	}
	sum, err := deps.AnalyseGitSurvey.SurveyRepo(ctx, p.Root)
	if err != nil {
		return nil
	}
	var fresh []string
	if sum.UnmergedEntries > 0 {
		fresh = append(fresh, analyse.ShieldConflict)
	}
	if sum.UnpushedCommits > 0 {
		fresh = append(fresh, analyse.ShieldUnpushed)
	}
	if sum.DirtyWorktree {
		fresh = append(fresh, analyse.ShieldDirty)
	}
	return fresh
}

// errNestedInteractive is the refusal every nested invocation's ReadLine
// seam returns: batch children are never interactive, so no inner gate
// can ever consume a line of real stdin.
var errNestedInteractive = errors.New("ebb analyse: nested batch invocations are never interactive")

// nestedHeadlessDeps derives the dependency set for an in-process nested
// command. Interactivity is a property of the streams, never of the
// process: StdinIsTerminal and ReadLine are process-global seams, and a
// batch spawned from a real terminal would otherwise let an inner gate
// (reclaim's park escalation, the carve confirmation) print its question
// into a discarded stream and then BLOCK reading the user's next typed
// line — invisibly authorizing park-and-REMOVE. Both seams are forced
// headless here (belt and braces): every nested gate takes its
// headless refusal path, which is a reported decline, never a hang.
func nestedHeadlessDeps(deps Deps) Deps {
	nested := deps
	nested.StdinIsTerminal = func() bool { return false }
	nested.ReadLine = func() (string, error) { return "", errNestedInteractive }
	return nested
}

// analyseStderrDigest reduces the nested command's captured stderr to
// one sanitized line worth surfacing in the batch report: gate
// refusals (escalation, blockers, declines, skips) win over progress
// noise, and any park-escalation involvement gains an explicit
// interactive-rerun advisory — the gate is only answerable on a real
// terminal, by `ebb reclaim <root>` itself.
func analyseStderrDigest(stderr, root string) string {
	digest, fallback := "", ""
	for _, raw := range strings.Split(stderr, "\n") {
		line := strings.TrimSpace(stripControlChars(raw))
		if line == "" {
			continue
		}
		if fallback == "" {
			fallback = line
		}
		if digest == "" {
			for _, mark := range []string{"escalation", "blocker", "declined", "skipped", "failed", "error"} {
				if strings.Contains(line, mark) {
					digest = line
					break
				}
			}
		}
	}
	if digest == "" {
		digest = fallback
	}
	if digest == "" {
		return ""
	}
	if len(digest) > 240 {
		digest = digest[:240] + "…"
	}
	if strings.Contains(stderr, "escalation") {
		digest += " — the park escalation gate is answerable only on a real terminal; run `ebb reclaim " + root + "` interactively"
	}
	return digest
}

// analyseExecReclaim runs one in-process `ebb reclaim <root> --yes` on
// the headless nested dependency set. The inner command's stdout stays
// discarded (its envelope would corrupt the outer one) but its stderr
// is captured and reduced to one sanitized digest line, so gate
// refusals are VISIBLE in the batch report instead of vanishing into
// io.Discard. Only the exit code and the digest are surfaced.
func analyseExecReclaim(ctx context.Context, deps Deps, root string) (status, detail string) {
	var errBuf bytes.Buffer
	code := cmdReclaim([]string{root, "--yes"}, Streams{Out: io.Discard, Err: &errBuf}, nestedHeadlessDeps(deps))
	digest := analyseStderrDigest(errBuf.String(), root)
	if digest != "" {
		digest = "; " + digest
	}
	switch code {
	case ExitOK:
		return "executed", "reclaim completed" + digest
	case ExitShortfall:
		// An honest per-project outcome (e.g. nothing safe left to trim):
		// reported, not a failure.
		return "executed", "reclaim completed with a shortfall/no-useful-gain outcome (nothing unsafe was done)" + digest
	default:
		return "failed", fmt.Sprintf("reclaim exited %d — project skipped, batch continues (rerun `ebb reclaim %s` to inspect)%s", code, root, digest)
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
	// The presence probe only decides whether commands can run at all —
	// execution itself goes through the hardened session (which resolves
	// git the same way every other ebb git invocation does).
	_, gerr := exec.LookPath("git")
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
			printLine, pok := renderCommand(cmd)
			if !pok {
				printLine = strings.Join(cmd, " ") // print-only fallback; execution never runs without git
			}
			fmt.Fprintf(out, "  %s\n", printLine)
			item.Status = "printed"
			item.Detail = "no git binary on PATH; command printed only"
		default:
			cmdLine, ok := renderCommand(cmd)
			if !ok {
				// Unreachable behind the [UNSAFE NAME] shield; handled
				// honestly anyway (F4: never render an unquotable path).
				item.Status = "skipped"
				item.Detail = "command withheld: the worktree path cannot be quoted safely for the shell"
				items = append(items, item)
				continue
			}
			fmt.Fprintf(out, "  %s\n", cmdLine)
			item.Status = "printed"
			if analyseItemConsent(deps, streams, interactive, yes, cmdLine) {
				// `git worktree remove <path>` resolves the path against
				// the repository it runs in: anchor it to the main
				// checkout the survey reported (WorktreeMain), so the
				// call works from any process cwd. Without an anchor the
				// attempt runs bare and an honest failure is reported.
				anchor := p.Root
				gitArgs := []string{"worktree", "remove", p.Root}
				if p.Repo.WorktreeMain != "" {
					anchor = p.Repo.WorktreeMain
					gitArgs = append([]string{"-C", anchor}, gitArgs...)
				}
				fmt.Fprintf(out, "  executing: %s\n", cmdLine)
				// The user-consented mutation runs through the SAME
				// D004/D005 hardening the observe/survey verbs get
				// (constructed env, static + per-repo -c neutralization,
				// fixed mutating argv shape): a hostile repository must
				// not execute its configuration during a removal ebb
				// drives (fsmonitor was live-verified firing on the plain
				// inherited-env invocation).
				sess, serr := gitadapter.NewMutatingSession(ctx, anchor)
				if serr != nil {
					item.Status = "failed"
					item.Detail = stripControlChars(serr.Error())
					fmt.Fprintf(out, "  failed: %s (%s) — skipped, batch continues\n", stripControlChars(p.Name), item.Detail)
				} else {
					run, cerr := sess.Command(ctx, gitArgs...)
					if cerr != nil {
						item.Status = "failed"
						item.Detail = stripControlChars(cerr.Error())
						fmt.Fprintf(out, "  failed: %s (%s) — skipped, batch continues\n", stripControlChars(p.Name), item.Detail)
					} else if outb, err := run.CombinedOutput(); err != nil {
						item.Status = "failed"
						// git's own output is external text: strip control
						// characters before embedding it (F4).
						item.Detail = stripControlChars(strings.TrimSpace(string(outb)))
						if item.Detail == "" {
							item.Detail = stripControlChars(err.Error())
						}
						fmt.Fprintf(out, "  failed: %s (%s) — skipped, batch continues\n", stripControlChars(p.Name), item.Detail)
					} else {
						item.Status = "executed"
						item.Detail = "worktree removed (git administrative state kept in sync by git itself)"
						fmt.Fprintf(out, "  done: %s\n", stripControlChars(p.Name))
					}
					sess.Cleanup()
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

// ---- terminal-injection hardening (F4) -----------------------------------
//
// Project names, roots and git output are external text. Rendered raw
// into "copyable" command lines and prompts they become an injection
// surface: a newline in a project directory name makes the copyable
// line multi-line (pasting it executes the second line), and ANSI
// escapes in git stderr echo into the human stream. Three rules:
//
//   - control characters (bytes < 0x20 and DEL) are stripped from every
//     human-rendered external string (JSON envelopes escape structurally
//     and stay intact);
//   - copyable command lines quote every element POSIX-safely;
//   - an element that cannot be quoted safely (control characters)
//     withholds the whole line with an explicit note — the analyse
//     engine additionally shields such projects out of every batch.

// stripControlChars removes terminal-control bytes (anything below 0x20
// and DEL 0x7f) from external text before it is rendered, replacing
// each with a space so words do not fuse. UTF-8 continuation bytes are
// always >= 0x80, so byte-level filtering cannot damage multi-byte
// runes.
func stripControlChars(s string) string {
	if !analyse.HasControlChars(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// renderCommand joins an argv into one copyable command line, quoting
// every element POSIX-safely. ok=false means some element cannot be
// quoted safely and the line must be withheld with an explicit note.
func renderCommand(argv []string) (string, bool) {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		q, ok := shellQuote(a)
		if !ok {
			return "", false
		}
		parts = append(parts, q)
	}
	return strings.Join(parts, " "), true
}

// shellQuote renders one argv element for a POSIX shell: tokens from
// the bare-safe set stay unquoted (commands and flags read naturally);
// everything else is single-quoted with the '\” escape. Control
// characters make an element unquotable (ok=false) — they are stripped
// or withheld one layer up, never pasted raw.
func shellQuote(s string) (string, bool) {
	if analyse.HasControlChars(s) {
		return "", false
	}
	if s == "" {
		return "''", true
	}
	if shellBareSafe(s) {
		return s, true
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'", true
}

// shellBareSafe reports whether s needs no quoting in a POSIX shell:
// the classic exec-safe character set (letters, digits and
// @ % + = : , . / - _).
func shellBareSafe(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("@%+=:,./-_", c) >= 0:
		default:
			return false
		}
	}
	return true
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
		line("  [OFFLINE] %d root(s) not readable: %s\n", len(r.OfflineRoots), stripControlChars(strings.Join(r.OfflineRoots, ", ")))
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

	// Docker tiers (external text: sanitized like every other rendered
	// external string).
	if r.Docker != nil {
		line("\nDocker tiers (%s)\n", "workspace-correlated, read-only")
		for _, t := range r.Docker.Tiers {
			if len(t.Items) == 0 {
				continue
			}
			line("  tier %d — %s\n", t.Tier, stripControlChars(t.Title))
			for _, it := range t.Items {
				if it.Shield != "" {
					line("    %s  %s  [SHIELDED: %s]\n", stripControlChars(it.ID), stripControlChars(it.Detail), stripControlChars(it.Shield))
				} else {
					line("    %s  %s\n", stripControlChars(it.ID), stripControlChars(it.Detail))
				}
			}
			if t.CopyCommand != "" {
				line("    copy & run: %s\n", stripControlChars(t.CopyCommand))
			}
		}
		if r.Docker.HostSlack > 0 {
			line("  host VHDX slack: %s\n", HumanBytes(r.Docker.HostSlack))
			if r.Docker.SlackCommand != "" {
				line("    copy & run: %s\n", stripControlChars(r.Docker.SlackCommand))
			}
		}
	}

	for _, w := range r.Warnings {
		line("warning: %s\n", stripControlChars(w))
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
// command. External text (the name) is sanitized and the command line
// is POSIX-quoted; an unquotable path withholds the line with a note
// (F4).
func renderAnalyseProject(p analyse.Project) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("%-28s", stripControlChars(p.Name)))
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
		if cmdLine, ok := renderCommand(p.Recommendation.Command); ok {
			row += "\n       -> " + cmdLine
		} else {
			row += "\n       (command withheld: the project path cannot be quoted safely for the shell)"
		}
	} else if len(p.Recommendation.Reason) > 0 {
		row += "\n       (" + stripControlChars(p.Recommendation.Reason) + ")"
	}
	return row
}

// analyseProjectMid builds the middle column: output-folder names for
// footprint-heavy rows, age/merge evidence otherwise (names are external
// directory names — sanitized).
func analyseProjectMid(p analyse.Project) string {
	if len(p.OutputRoots) > 0 {
		names := make([]string, 0, len(p.OutputRoots))
		for _, o := range p.OutputRoots {
			names = append(names, stripControlChars(o.Name))
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
