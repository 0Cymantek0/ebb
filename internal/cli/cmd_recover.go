// cmdRecover implements `ebb recover <operation-id> [--resume-removal]`
// (Foundation §12.4, §17.1): reconcile an interrupted operation from
// durable evidence. Recover performs only the safe reconciliation per
// the §12.4 table and never auto-continues from SEALED into removal;
// --resume-removal is the explicit verb for a blocked/interrupted
// removal walk (REMOVAL_BLOCKED / REMOVING / QUARANTINED park, or a
// TRIM_SEALING trim).
//
// Exit contract: 0 reconciliation completed (report-only outcomes
// included — a terminal operation IS a completed reconciliation); 2
// usage (unknown operation id); 5 journal/evidence mismatch or a
// reconciliation that itself got blocked mid-removal; 7 vault; 130
// cancelled.

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
	OperationID       string   `json:"operation_id"`
	WorkspaceID       string   `json:"workspace_id"`
	Kind              string   `json:"kind"`
	PhaseBefore       string   `json:"phase_before"`
	PhaseAfter        string   `json:"phase_after"`
	Actions           []string `json:"actions"`
	Remaining         []string `json:"remaining"`
	LastRemovedPath   string   `json:"last_removed_path,omitempty"`
	LastRemovedCount  int      `json:"last_removed_count,omitempty"`
	NextAction        string   `json:"next_action"`
	Warnings          []string `json:"warnings"`
}

func cmdRecover(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("recover", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	resume := fs.Bool("resume-removal", false, "explicitly resume a blocked/interrupted removal walk")
	if err := fs.Parse(args); err != nil {
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
		env.Errors = []string{err.Error()}
		emit(env, *jsonOut, streams, "")
		return classifyExitCode(err)
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	probe := deps.NewProbe()
	if probe == nil {
		env.Errors = []string{fmt.Sprintf("platform probe %v", ErrNotIntegrated)}
		emit(env, *jsonOut, streams, "")
		return ExitUsage
	}
	coord, err := sess.newLifecycle(probe)
	if err != nil {
		env.Errors = []string{fmt.Sprintf("recover %s: %v", opArg, err)}
		emit(env, *jsonOut, streams, "")
		return classifyExitCode(err)
	}

	var rep lifecycle.RecoveryReport
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		if *resume {
			rep, rErr = coord.ResumeRemoval(ctx, lifecycleVaultRef(repoDir, passfile), opID)
		} else {
			rep, rErr = coord.Recover(ctx, lifecycleVaultRef(repoDir, passfile), opID)
		}
		return rErr
	})
	if cErr != nil {
		env.Errors = []string{fmt.Sprintf("recover %s: %v", opArg, cErr)}
		emit(env, *jsonOut, streams, "")
		return classifyExitCode(cErr)
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
