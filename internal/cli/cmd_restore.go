// cmdRestore implements `ebb restore [path]` (D033): the direct
// functional inverse of `ebb reclaim`/`ebb trim` on an ACTIVE workspace.
// It re-executes the recipes the latest completed trim sealed in its
// payload, in-place, behind the Git pre-flight gate, 3-way drift
// reconciliation and the post-flight protected-file integrity gate
// (internal/restore/liverestore.go owns the sequence; this file owns
// flags, prompts, the §17.2 envelope and the exit mapping).
//
// Restore is NOT destructive to preserved data, so it never needs
// --yes: recipes whose recorded approval matches the CURRENT tool and
// input digests run silently (the trim-time approval is stored in the
// state dir's approvalstore and verified verbatim — wave-5 D4), and the
// only decisions are the branch-mismatch and drift menus —
// terminal-only, NEVER auto-decided, and opted out entirely by --json
// (machine mode refuses with the typed error instead of prompting; the
// approval resolver obeys the same rule). A legacy trim manifest (one
// without frozen action definitions) needs fresh explicit approval:
// --legacy-approve records it headless — for LEGACY pendings only — an
// interactive terminal confirms it instead (wave-5 D5).
//
// Exit contract: 0 restored (or previewed, with --dry-run); 2 usage
// (bad flags); 3 blocked (nothing to restore, in-flight Git conflict,
// unresolved branch mismatch, live outputs present, legacy manifest
// without approval, approval drift without a terminal, already
// restored, drift without a strategy, declined menu); 6 recipe
// execution or protected-gate failure (the op lands RESTORE_FAILED and
// rerunning resumes); 7 vault; 130 cancelled (signal).

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/platform"
	"github.com/0Cymantek0/ebb/internal/restore"
)

// restoreGroupDetails is one group's slice of the --json payload.
type restoreGroupDetails struct {
	ID       string               `json:"id"`
	Command  []string             `json:"command"`
	Drift    []restore.DriftEntry `json:"drift,omitempty"`
	Overlays []string             `json:"overlays,omitempty"`
	// Legacy marks a group replayed through the legacy synthesis path
	// (wave-5 D5): freshly approved at restore time, never claimed to
	// be the previously-approved action.
	Legacy bool `json:"legacy,omitempty"`
}

// restoreDetails is the --json payload of a restore (preview or result).
type restoreDetails struct {
	Workspace       string                `json:"workspace"`
	Root            string                `json:"root"`
	TrimOperationID string                `json:"trim_operation_id"`
	SnapshotID      string                `json:"snapshot_id"`
	Strategy        string                `json:"strategy,omitempty"`
	DryRun          bool                  `json:"dry_run,omitempty"`
	Groups          []restoreGroupDetails `json:"groups"`
	Actions         []openActionRun       `json:"actions,omitempty"`
	OverlaysApplied []string              `json:"overlays_applied,omitempty"`
	// ProtectedGate is the post-flight integrity gate outcome ("passed";
	// "not-run" on a dry run; "" when the restore failed before it).
	ProtectedGate string `json:"protected_gate,omitempty"`
}

func cmdRestore(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	strategyFlag := fs.String("strategy", "", "drift reconciliation: merge (union manifests, live wins) | current (run the live files) | baseline (revert inputs to the trim baseline)")
	dryRun := fs.Bool("dry-run", false, "report the selected trim, commands, drift and overlays without effects")
	legacyApprove := fs.Bool("legacy-approve", false,
		"record the fresh explicit approval legacy trim manifests (without frozen action definitions) need, without a prompt; a legacy replay is labeled a 'legacy recovery attempt' and is never claimed to be the previously-approved action")
	if err := fs.Parse(reorderFlags(args, "strategy")); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb restore: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}

	env := newEnvelope("restore", "error")
	strategy := restore.Strategy(strings.TrimSpace(*strategyFlag))
	if strategy != "" && !strategy.Valid() {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			fmt.Sprintf("--strategy %q is not one of merge, current, baseline", *strategyFlag))
	}

	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("restore %s: %v", root, err))
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	if deps.NewProbe == nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			fmt.Sprintf("restore %s: platform probe %v", root, ErrNotIntegrated))
	}
	runner := newActionRunner(deps)
	if runner == nil && !*dryRun {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			fmt.Sprintf("restore %s: action runner %v", root, ErrNotIntegrated))
	}
	// Wave-5 (D4): the REAL local approval store and the CLI-owned
	// grouped approval resolver — the same machinery `ebb open`'s
	// rebuild uses. Exact matches never reach the resolver (silent
	// replay, D033 preserved); missing/stale/drifted approvals resolve
	// through it (prompted on a terminal, blocked headless OR in --json
	// machine mode) — restore has no --yes, so nothing else auto-records
	// (wave-5 review P1-A: --legacy-approve is NOT a generic yes; see
	// the wrapper below). The resolver is wrapped with the legacy
	// disclosure: actions synthesized from a manifest without frozen
	// definitions are presented as what they are (freshly approved
	// legacy recovery attempts). The fresh-approval guidance names
	// restore's REAL remediation — restore has no --yes, so the clause
	// must never recommend one (small-B review fix); the interactive
	// approval in a terminal is the only consent path for a non-legacy
	// pending.
	approvalStore := approvalstore.New(sess.approvalsPath())
	lr, err := restore.NewLiveRestorer(restore.LiveDependencies{
		Store:      sess.store,
		Cat:        sess.cat,
		Probe:      deps.NewProbe(),
		CreateLink: platform.CreateLink,
		Runner:     runner,
		Approver:   approvalStore,
		Approve: restoreLegacyApprovalResolver(deps, streams, *legacyApprove, *jsonOut,
			approvalStore, openApprovalResolver(deps, streams, false, *jsonOut, approvalStore,
				"run in a terminal to review the actions and confirm the approval there")),
		ObserveGit: deps.ObserveGit,
		Prompt:     newRestorePrompter(deps, streams, *jsonOut),
	})
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("restore %s: %v", root, err))
	}

	var res restore.LiveRestoreResult
	var rerr error
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		rerr = nil
		res, rerr = lr.LiveRestore(ctx, restore.VaultRef{RepoDir: repoDir, Passfile: passfile},
			root, restore.LiveRestoreOptions{Strategy: strategy, DryRun: *dryRun, LegacyApprove: *legacyApprove})
		return rerr
	})
	if cErr != nil {
		// Gate failures (nothing to restore, conflict, mismatch, already
		// restored, strategy required, declined) never began an operation:
		// their envelope claims no phase. An execution failure (exit 6)
		// still reports its partial details — the recipes may have produced
		// outputs and the op is resumable by rerunning.
		var liveFailed *restore.ErrLiveRestoreFailed
		if errors.As(cErr, &liveFailed) {
			details := restoreResultDetails(sess, res, "not-run")
			details.DryRun = false // a failed execution is not a preview
			env.OperationID = string(res.OperationID)
			env.WorkspaceID = string(res.WorkspaceID)
			env.SnapshotID = string(res.SnapshotID)
			env.Phase = catalog.PhaseRestoreFailed
			env.Details = details
			env.Warnings = res.Warnings
			return emitFailure(env, *jsonOut, streams, ExitRebuildFailed,
				fmt.Sprintf("restore %s: %s", res.Root, codedWithSafeAction(cErr)))
		}
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("restore %s: %s", root, codedWithSafeAction(cErr)))
	}

	details := restoreResultDetails(sess, res, "passed")
	env.Outcome = "ok"
	env.OperationID = string(res.OperationID)
	env.WorkspaceID = string(res.WorkspaceID)
	env.SnapshotID = string(res.SnapshotID)
	env.Phase = res.Phase
	env.Warnings = append(env.Warnings, res.Warnings...)
	if res.DryRun {
		env.Outcome = "dry-run"
		env.Conditions = []string{"dry-run", "no-effects"}
	} else {
		env.Conditions = restoreConditions(res)
	}
	env.Details = details
	emit(env, *jsonOut, streams, renderRestoreHuman(details))
	return ExitOK
}

// restoreResultDetails assembles the JSON/human details from a result.
// gate is the protected-gate outcome label for completed runs.
func restoreResultDetails(sess *session, res restore.LiveRestoreResult, gate string) restoreDetails {
	details := restoreDetails{
		Root:            res.Root,
		TrimOperationID: string(res.TrimOperationID),
		SnapshotID:      string(res.SnapshotID),
		Strategy:        res.Strategy.String(),
		DryRun:          res.DryRun,
		Groups:          []restoreGroupDetails{},
		ProtectedGate:   gate,
	}
	if res.DryRun {
		details.ProtectedGate = "not-run"
	}
	if ws, err := sess.cat.GetWorkspace(res.WorkspaceID); err == nil {
		details.Workspace = ws.Name
	}
	for _, g := range res.Groups {
		details.Groups = append(details.Groups, restoreGroupDetails{
			ID: g.GroupID, Command: g.Command, Drift: g.Drift, Overlays: g.Overlays,
			Legacy: g.Legacy,
		})
	}
	for _, a := range res.Actions {
		details.Actions = append(details.Actions, openActionRun{
			ID: a.ID, Status: a.Status, ExitCode: a.ExitCode, Skipped: a.Skipped,
		})
	}
	details.OverlaysApplied = res.OverlaysApplied
	return details
}

// restoreConditions derives the envelope conditions from the result.
func restoreConditions(res restore.LiveRestoreResult) []string {
	conds := []string{"trim-replayed:" + string(res.TrimOperationID)}
	if res.Strategy != "" {
		conds = append(conds, "strategy:"+res.Strategy.String())
	}
	conds = append(conds, "protected-gate:passed")
	if len(res.OverlaysApplied) > 0 {
		conds = append(conds, fmt.Sprintf("overlays-applied:%d", len(res.OverlaysApplied)))
	}
	if restoreIsLegacy(res) {
		conds = append(conds, "legacy-recovery-attempt")
	}
	return conds
}

// restoreIsLegacy reports whether any replayed group ran through the
// legacy synthesis path (wave-5 D5): the envelope must label such a
// run a "legacy recovery attempt", never a previously-approved replay.
func restoreIsLegacy(res restore.LiveRestoreResult) bool {
	for _, g := range res.Groups {
		if g.Legacy {
			return true
		}
	}
	return false
}

// restoreLegacyApprovalResolver wraps open's grouped approval resolver
// with the wave-5 D5 legacy disclosure — and scopes the --legacy-approve
// consent to its advertised subject (wave-5 review P1-A): the flag
// authorizes ONLY pendings marked Legacy, actions synthesized from a
// trim manifest WITHOUT frozen action definitions whose historical
// approval identity is unavailable. Everything else resolves through the
// grouped resolver with yes=false (restore has no --yes): prompted on a
// terminal, blocked with the approval-required error otherwise — the
// flag can never stand in for a missing regular approval.
//
// machine is the --json mode: like a missing terminal for every prompt
// path (zero terminal reads), while an explicit --legacy-approve still
// records genuinely-legacy approvals headless — flag consent is not a
// prompt. The consented legacy approvals are recorded HERE (labeled
// flag:--legacy-approve), not by delegating to the grouped resolver:
// that resolver runs with yes=false, so a headless delegation would
// refuse the very replay the user just consented to.
func restoreLegacyApprovalResolver(deps Deps, streams Streams, legacyApprove, machine bool, store *approvalstore.FileApprover, base restore.ApprovalResolver) restore.ApprovalResolver {
	return func(ctx context.Context, pending []restore.PendingApproval) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		interactive := !machine && deps.StdinIsTerminal != nil && deps.StdinIsTerminal()
		var legacy []restore.PendingApproval
		for _, p := range pending {
			if p.Legacy {
				legacy = append(legacy, p)
			}
		}
		if len(legacy) == 0 {
			return base(ctx, pending)
		}
		if !legacyApprove && !interactive {
			return blockedError(fmt.Errorf("%s: %d action(s) of this trim manifest have no frozen action definition, so the exact previously-approved action is not on record and its historical approval identity is unavailable; normal replay is refused.%s Safe action: rerun with --legacy-approve to record the fresh explicit approval headless (a legacy replay is labeled a 'legacy recovery attempt' and is never claimed to be the previously-approved action), or rerun in a terminal to review the recorded recipes and confirm",
				restore.CodeLegacyManifest, len(legacy), legacyRecipeDisclosure(legacy)))
		}
		fmt.Fprint(streams.Err, legacyRecoveryBanner(legacy))
		if legacyApprove {
			if store == nil {
				return blockedError(fmt.Errorf("%s: no approval store is wired, so the explicit --legacy-approve consent cannot be recorded; nothing ran",
					restore.CodeLegacyManifest))
			}
			for _, p := range legacy {
				if _, err := store.Approve(p.Def, p.Tool, p.InputDigests, "flag:--legacy-approve"); err != nil {
					return fmt.Errorf("recording the legacy approval for action %s: %w", p.Def.ID, err)
				}
			}
		}
		// The remainder resolves normally: with the flag absent the
		// legacy pendings rejoin the grouped listing (one interactive
		// decision, banner already disclosed); with the flag they are
		// settled above. Non-legacy pendings were never touched by the
		// flag — missing approvals still need a terminal, stale ones
		// still refuse until re-approved interactively.
		rest := make([]restore.PendingApproval, 0, len(pending))
		for _, p := range pending {
			if legacyApprove && p.Legacy {
				continue
			}
			rest = append(rest, p)
		}
		if len(rest) == 0 {
			return nil
		}
		return base(ctx, rest)
	}
}

// legacyRecoveryBanner is the pre-approval disclosure for a consented
// (terminal or --legacy-approve) legacy replay: what is about to be
// approved, and the honest label it carries.
func legacyRecoveryBanner(pending []restore.PendingApproval) string {
	var b strings.Builder
	fmt.Fprintf(&b, "legacy recovery attempt: this trim manifest predates frozen action definitions, so its historical approval identity is unavailable; the recipes below were freshly approved NOW and are not the previously-approved actions\n")
	fmt.Fprint(&b, strings.TrimPrefix(legacyRecipeDisclosure(pending), "\n"))
	return b.String()
}

// legacyRecipeDisclosure renders every legacy pending action's recorded
// recipe data (command, working root, inputs, outputs) — the same
// disclosure shape the driver's refusal carries.
func legacyRecipeDisclosure(pending []restore.PendingApproval) string {
	var b strings.Builder
	for _, p := range pending {
		fmt.Fprintf(&b, "\n  action %s\n    command: %s\n    root: %s\n    inputs: %s\n    outputs: %s",
			p.Def.ID, strings.Join(p.Def.Argv, " "), p.Def.WorkingRoot,
			strings.Join(p.Def.Inputs, ", "), strings.Join(p.Def.Outputs, ", "))
	}
	return b.String()
}

// renderRestoreHuman renders the restore report (preview or result).
func renderRestoreHuman(d restoreDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	if d.DryRun {
		line("restore preview for workspace %q (dry run: nothing will run; no operation is recorded)\n", workspaceLabelOf(d))
	} else {
		line("restored workspace %q in place\n", workspaceLabelOf(d))
	}
	line("  root: %s\n", d.Root)
	line("  replaying trim %s (snapshot %s)\n", d.TrimOperationID, d.SnapshotID)
	if d.Strategy != "" {
		line("  drift strategy: %s\n", d.Strategy)
	}
	for _, g := range d.Groups {
		cmdLine := strings.Join(g.Command, " ")
		line("  group %s: %s\n", g.ID, cmdLine)
		if g.Legacy {
			line("    legacy recovery attempt: no frozen action definition; freshly approved now, not the previously-approved action\n")
		}
		for _, dr := range g.Drift {
			line("    drift: %s\n", driftLine(dr))
		}
		for _, o := range g.Overlays {
			applied := ""
			for _, a := range d.OverlaysApplied {
				if a == o {
					applied = " (applied)"
				}
			}
			line("    overlay: %s%s\n", o, applied)
		}
	}
	for _, a := range d.Actions {
		switch {
		case a.Skipped:
			line("  action %s: skipped\n", a.ID)
		case a.Status == "succeeded":
			line("  action %s: succeeded\n", a.ID)
		default:
			line("  action %s: %s (exit %d)\n", a.ID, a.Status, a.ExitCode)
		}
	}
	if d.ProtectedGate == "passed" {
		line("  protected-file gate: passed (everything outside the groups' outputs is unchanged)\n")
	}
	if d.DryRun {
		line("  run without --dry-run to execute the recipes\n")
	}
	return b.String()
}

func workspaceLabelOf(d restoreDetails) string {
	if d.Workspace != "" {
		return d.Workspace
	}
	return d.Root
}

// driftLine renders one drift entry for the human stream.
func driftLine(d restore.DriftEntry) string {
	switch d.State {
	case "missing":
		return fmt.Sprintf("%s: recorded at trim time, live file absent", d.Path)
	case "new":
		return fmt.Sprintf("%s: absent at trim time, exists now", d.Path)
	default:
		return fmt.Sprintf("%s: content differs from the trim baseline", d.Path)
	}
}

// ---- the interactive decision seam (terminal-only, never auto-decided) ----

// newRestorePrompter returns the terminal prompter, or nil when stdin is
// not a terminal (non-interactive refusals then apply). `--json` is
// machine mode (Wave 1 restore review F6): it forces a nil prompter even
// on a terminal, so branch mismatch and drift refuse with their typed
// errors instead of dropping a scripted consumer into an interactive
// menu it can never answer.
func newRestorePrompter(deps Deps, streams Streams, jsonOut bool) restore.Prompter {
	if jsonOut {
		return nil
	}
	if deps.StdinIsTerminal == nil || !deps.StdinIsTerminal() || deps.ReadLine == nil {
		return nil
	}
	return &restorePrompter{deps: deps, streams: streams}
}

type restorePrompter struct {
	deps    Deps
	streams Streams
}

// choose reads one menu selection (1..n); an unparseable or exhausted
// line means the user cancelled.
func (p *restorePrompter) choose(prompt string, n int) (int, bool) {
	fmt.Fprint(p.streams.Err, prompt)
	line, err := p.deps.ReadLine()
	if err != nil {
		return 0, false
	}
	switch strings.TrimSpace(line) {
	case "1", "2", "3", "4":
		v := int(line[0] - '0')
		if v >= 1 && v <= n {
			return v, true
		}
	}
	return 0, false
}

// ChooseBranch renders the D033 branch-mismatch menu.
func (p *restorePrompter) ChooseBranch(ctx context.Context, m restore.BranchMismatch) (restore.BranchChoice, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	branch := m.RecordedBranch
	if branch == "" {
		branch = m.RecordedCommit
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Branch mismatch: the trim was recorded on %s,\n", m.RecordedLabel())
	fmt.Fprintf(&b, "but the workspace is currently on %s.\n", m.LiveLabel())
	fmt.Fprintf(&b, "Cross-branch dependency pollution is possible; Ebb will not auto-decide.\n")
	fmt.Fprintf(&b, "  [1] Switch back to %s and restore (Recommended)\n", branch)
	fmt.Fprintf(&b, "  [2] Rebuild for the current %s (using the live manifests)\n", m.LiveLabel())
	fmt.Fprintf(&b, "  [3] Cancel\n")
	fmt.Fprintf(&b, "Select: ")
	sel, ok := p.choose(b.String(), 3)
	if !ok {
		return 0, &restore.ErrRestoreDeclined{Root: m.Root, Detail: "no valid branch choice"}
	}
	switch sel {
	case 1:
		return restore.BranchSwitchBack, nil
	case 2:
		return restore.BranchRebuildCurrent, nil
	default:
		return restore.BranchCancel, nil
	}
}

// ChooseStrategy renders the D033 drift-reconciliation menu.
func (p *restorePrompter) ChooseStrategy(ctx context.Context, drift []restore.DriftEntry) (restore.Strategy, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Drift detected: project configuration changed after the last cleanup.\n")
	for _, d := range drift {
		fmt.Fprintf(&b, "  %s: %s\n", d.Path, d.Describe())
	}
	fmt.Fprintf(&b, "Select reconciliation method:\n")
	fmt.Fprintf(&b, "  [1] Merge (Recommended): union manifest dependencies, keep your new packages\n")
	fmt.Fprintf(&b, "  [2] Rebuild current: run a clean install using only the current configuration\n")
	fmt.Fprintf(&b, "  [3] Revert to baseline: restore the recorded configuration (backs up current files)\n")
	fmt.Fprintf(&b, "  [4] Cancel\n")
	fmt.Fprintf(&b, "Select: ")
	sel, ok := p.choose(b.String(), 4)
	if !ok {
		return "", &restore.ErrRestoreDeclined{Detail: "no valid strategy choice"}
	}
	switch sel {
	case 1:
		return restore.StrategyMerge, nil
	case 2:
		return restore.StrategyCurrent, nil
	case 3:
		return restore.StrategyBaseline, nil
	default:
		return "", nil // cancelled
	}
}
