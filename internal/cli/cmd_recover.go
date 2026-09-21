// cmdRecover implements `ebb recover <operation-id> [--resume-removal]
// [--cancel]` (Foundation §12.4, §17.1): reconcile an interrupted
// operation from durable evidence.
//
// Plain Recover performs only the safe reconciliation per the §12.4
// table: PLANNED/CAPTURING (and TRIM_PLANNED) cancel, PAYLOAD_COMMITTED
// re-verifies and seals, SEALED revalidates and reports — including
// adopting the quarantine-rename crash window (committing SEALED ->
// QUARANTINED and completing the walk) — and QUARANTINED/REMOVING/
// TRIM_SEALING finish their idempotent removal completion, recording
// the writer-assertion source "resume:<phase>" in the journal.
//
// --resume-removal is the explicit verb for a BLOCKED removal walk
// (REMOVAL_BLOCKED): plain Recover is REPORT-ONLY for that phase
// because resuming re-opens the §12.3 digest->remove race window; the
// user resolves the blocker, re-establishes the stopped-writers
// condition, and asks for the destructive resume explicitly (the flag
// also accepts the interrupted phases plain Recover completes anyway).
// It additionally accepts a SEALED park whose removal tail was
// attempted and blocked before the quarantine rename succeeded (Wave 4
// gauntlet bug B — the park-time error's safe action names this flag):
// the door revalidates the live source against the sealed inventory
// before removing anything, honoring §12.4's "revalidate, do not
// assume deletion remains authorized".
//
// --cancel abandons an operation whose removal never started
// (PLANNED/CAPTURING/PAYLOAD_COMMITTED/SEALED/TRIM_PLANNED) without
// performing its reconciliation — the escape hatch for a SEALED
// operation whose live root is intact, which would otherwise block the
// workspace. It also closes every crashed capsule transport
// (EXPORT_*/IMPORT_* phases, Wave J review J1) and every dead restore
// (RESTORE_RUNNING/RESTORE_FAILED, Wave 1 restore review F3): both own
// no removal authority, so cancel-after-crash is always safe — the
// export's duration pins are released audit-only and anything the
// transport left behind is reported, never deleted; a canceled restore
// keeps whatever its recipes produced. Retained snapshots stay pinned
// (I07); deliberate release is `ebb forget`, never cancel.
//
// Exit contract: 0 reconciliation completed (report-only outcomes
// included — a terminal operation IS a completed reconciliation); 2
// usage (unknown operation id, contradictory flags); 5 journal/evidence
// mismatch or a reconciliation that itself got blocked mid-removal; 7
// vault; 130 cancelled.

package cli

import (
	"flag"
	"fmt"
	"strings"

	"ebb/internal/domain"
	"ebb/internal/lifecycle"
)

// recoverDetails is the --json payload: the RecoveryReport verbatim.
type recoverDetails struct {
	OperationID      string   `json:"operation_id"`
	WorkspaceID      string   `json:"workspace_id"`
	Kind             string   `json:"kind"`
	PhaseBefore      string   `json:"phase_before"`
	PhaseAfter       string   `json:"phase_after"`
	Actions          []string `json:"actions"`
	Remaining        []string `json:"remaining"`
	LastRemovedPath  string   `json:"last_removed_path,omitempty"`
	LastRemovedCount int      `json:"last_removed_count,omitempty"`
	NextAction       string   `json:"next_action"`
	Warnings         []string `json:"warnings"`
}

func cmdRecover(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	resume := fs.Bool("resume-removal", false,
		"explicitly resume a blocked/interrupted removal walk (required for REMOVAL_BLOCKED after the blocker is resolved and writers are stopped again; QUARANTINED/REMOVING/TRIM_SEALING also complete under plain recover; a SEALED park whose removal tail was blocked is accepted too — it revalidates the source against the sealed inventory first)")
	cancel := fs.Bool("cancel", false,
		"abandon an operation whose removal never started (PLANNED/CAPTURING/PAYLOAD_COMMITTED/SEALED/TRIM_PLANNED), any crashed capsule transport (EXPORT_*/IMPORT_*) or any dead restore (RESTORE_RUNNING/RESTORE_FAILED); retained snapshots stay pinned (I07)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	if *resume && *cancel {
		fmt.Fprintln(streams.Err, "ebb recover: --resume-removal and --cancel are contradictory verbs")
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb recover: takes exactly one operation id")
		return ExitUsage
	}
	opArg := fs.Arg(0)
	opID := domain.OperationID(opArg)
	if _, perr := domain.ParseID(opArg); perr != nil {
		fmt.Fprintf(streams.Err, "ebb recover: %v (got %q)\n", perr, opArg)
		return ExitUsage
	}

	env := newEnvelope("recover", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	probe := deps.NewProbe()
	if probe == nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			fmt.Sprintf("platform probe %v", ErrNotIntegrated))
	}
	coord, err := sess.newLifecycle(probe)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("recover %s: %v", opArg, err))
	}

	var rep lifecycle.RecoveryReport
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		switch {
		case *cancel:
			rep, rErr = coord.CancelOperation(ctx, lifecycleVaultRef(repoDir, passfile), opID)
		case *resume:
			rep, rErr = coord.ResumeRemoval(ctx, lifecycleVaultRef(repoDir, passfile), opID)
		default:
			rep, rErr = coord.Recover(ctx, lifecycleVaultRef(repoDir, passfile), opID)
		}
		return rErr
	})
	if cErr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("recover %s: %s", opArg, codedWithSafeAction(cErr)))
	}

	details := recoverDetails{
		OperationID:      string(rep.OperationID),
		WorkspaceID:      string(rep.WorkspaceID),
		Kind:             rep.Kind,
		PhaseBefore:      rep.PhaseBefore,
		PhaseAfter:       rep.PhaseAfter,
		Actions:          orEmpty(rep.Actions),
		Remaining:        orEmpty(rep.Remaining),
		LastRemovedPath:  rep.LastRemovedPath,
		LastRemovedCount: rep.LastRemovedCount,
		NextAction:       rep.NextAction,
		Warnings:         orEmpty(rep.Warnings),
	}
	env.Outcome = "ok"
	env.OperationID = details.OperationID
	env.Phase = details.PhaseAfter
	env.WorkspaceID = details.WorkspaceID
	env.Details = details
	env.Warnings = append(env.Warnings, rep.Warnings...)
	emit(env, *jsonOut, streams, renderRecoverHuman(details))
	return ExitOK
}

// orEmpty keeps slices non-null in the machine payload.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// renderRecoverHuman renders the reconciliation report.
func renderRecoverHuman(d recoverDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("recovered operation %s (%s): %s -> %s\n", d.OperationID, d.Kind, d.PhaseBefore, d.PhaseAfter)
	for _, a := range d.Actions {
		line("  action: %s\n", a)
	}
	if d.LastRemovedCount > 0 {
		line("  last removed entry: %s (%d removed before the journal stopped)\n", d.LastRemovedPath, d.LastRemovedCount)
	}
	if len(d.Remaining) > 0 {
		line("  remaining:\n")
		for _, r := range d.Remaining {
			line("    - %s\n", r)
		}
	}
	if d.NextAction != "" {
		line("  next: %s\n", d.NextAction)
	}
	for _, w := range d.Warnings {
		line("  warning: %s\n", w)
	}
	return b.String()
}
