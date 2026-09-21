// cmdPark implements `ebb park [path]` (Foundation §12.2, §17.1): the
// full capture/verify/remove sequence. The destructive tail runs only
// after a writer assertion exists (Foundation §17.2): the recorded
// assertion is either the interactive terminal confirmation ("interactive-
// confirm") or the explicit --assert-writers-stopped flag ("flag:--assert-
// writers-stopped"). --yes never supplies it; without a terminal and
// without the flag the command is blocked before any capture.
//
// Exit contract: 0 parked; 2 usage; 3 blocked (writer assertion missing
// or declined, destructive blockers, source changed, op in progress); 4
// verification failure (retained unsealed payload per §11.3); 5 removal
// blocked mid-walk (reconcile with `ebb recover`); 7 vault; 130
// cancelled (journal keeps the last durable phase).

package cli

import (
	"flag"
	"fmt"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/lifecycle"
)

// parkDetails is the --json payload of a completed park (§5.2 shape).
type parkDetails struct {
	snapshotDetails
	// WriterAssertionSource records where the §17.2 assertion came from.
	WriterAssertionSource string `json:"writer_assertion_source"`
	// FreedObserved is the measured free-space change on the source
	// volume (positive = freed); FreedEstimated is the logical estimate.
	FreedObserved  int64 `json:"freed_observed"`
	FreedEstimated int64 `json:"freed_estimated"`
}

func cmdPark(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("park", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	assertStopped := fs.Bool("assert-writers-stopped", false,
		"assert all writers on the workspace are stopped (required for unattended park; recorded in the operation journal)")
	yes := fs.Bool("yes", false, "accept ordinary prompts (NEVER supplies the writer assertion)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb park: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}
	_ = yes // parsed for contract clarity; deliberately unused below (§17.2)

	env := newEnvelope("park", "error")
	sess, disc, probe, opts, ctx, stop, err := openCaptureCommand(deps, streams, root)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("park %s: %v", root, err))
	}
	defer stop()
	defer sess.close()

	// ---- §17.2 writer assertion, BEFORE any capture ------------------
	// The interactive prompt shows the §5.2 summary lines first: what is
	// preserved, what is reconstructed, what will be removed.
	parkPrompt(deps, streams.Err, disc)
	assertion, aerr := writerAssertion(deps, *assertStopped, streams.Err)
	if aerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(aerr),
			fmt.Sprintf("park %s: %v", disc.Root, aerr))
	}
	opts.Park = true
	opts.WriterAssertion = assertion

	coord, err := sess.newLifecycle(probe)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("park %s: %v", disc.Root, err))
	}

	// Release the process cwd from inside the workspace BEFORE the
	// destructive tail (Wave 4 gauntlet bug A: a cwd under the root pins
	// the §12.2 step-7 quarantine rename on Windows). disc.Root is
	// absolute and every later path derives from it, so moving now is
	// safe; the note names the shell-pin limit.
	releaseWorkspaceCwd(deps, streams, disc.Root, &env, *jsonOut)

	var res lifecycle.ParkResult
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		res, rErr = coord.Park(ctx, lifecycleVaultRef(repoDir, passfile), disc.Root, opts)
		return rErr
	})
	if cErr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("park %s: %s", disc.Root, codedWithSafeAction(cErr)))
	}

	details := parkDetails{
		snapshotDetails:       snapshotDetailsFrom(opts.WorkspaceName, disc.Root, res.Snapshot),
		WriterAssertionSource: assertion,
		FreedObserved:         res.VolumeDeltaObserved,
		FreedEstimated:        res.VolumeDeltaEstimated,
	}
	env.Outcome = "ok"
	env.Phase = catalog.PhaseDone
	env.WorkspaceID = string(sess.resolveWorkspaceID(opts.WorkspaceName, disc.Root))
	env.SnapshotID = details.SnapshotID
	env.Conditions = []string{"writer-assertion:" + assertion, "workspace-parked"}
	env.Bytes = &BytesSummary{
		Preserved:      res.Snapshot.PreservedBytes,
		FreedObserved:  res.VolumeDeltaObserved,
		FreedEstimated: res.VolumeDeltaEstimated,
	}
	env.Details = details
	env.Warnings = append(env.Warnings, res.Snapshot.Warnings...)
	emit(env, *jsonOut, streams, renderParkHuman(details, disc.Volume.VolumeID))
	return ExitOK
}

// parkPrompt prints the §5.2 pre-confirmation summary (human stream).
func parkPrompt(deps Deps, w interface{ Write([]byte) (int, error) }, disc discovery) {
	var b strings.Builder
	fmt.Fprintf(&b, "Workspace: %s\n", disc.Policy.Workspace.Name)
	fmt.Fprintf(&b, "Preserve: %d entries (%s)\n", disc.Summary.Preserved, HumanBytes(disc.Summary.PreservedBytes))
	if names := applicableGroupNames(disc); len(names) > 0 {
		fmt.Fprintf(&b, "Reconstruct: %s\n", strings.Join(names, ", "))
	} else {
		fmt.Fprintf(&b, "Reconstruct: none declared\n")
	}
	if disc.Volume.VolumeID != "" {
		fmt.Fprintf(&b, "Volume %s: %s available\n", disc.Volume.VolumeID, HumanBytes(disc.Volume.FreeToCaller))
	}
	_, _ = w.Write([]byte(b.String()))
}

// applicableGroupNames lists the resolved regenerate groups that route
// reconstruct.
func applicableGroupNames(disc discovery) []string {
	var out []string
	for _, g := range disc.Resolved.Groups {
		if g.Applicable {
			out = append(out, g.ID)
		}
	}
	return out
}

// renderParkHuman renders the §5.2-shaped completion report.
func renderParkHuman(d parkDetails, volumeID string) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("parked workspace %q\n", d.Workspace)
	line("  snapshot retained: %s (pinned; P=%s S=%s)\n", d.SnapshotID, d.BackendIDs[0], d.BackendIDs[1])
	line("  entries preserved: %d (%s); omitted: %d\n",
		d.EntriesPreserved, HumanBytes(d.PreservedBytes), d.EntriesOmitted)
	line("  root removed: %s\n", d.Root)
	if volumeID == "" {
		volumeID = "source volume"
	}
	line("  space returned to %s: %s measured (estimated %s)\n",
		volumeID, HumanBytes(d.FreedObserved), HumanBytes(d.FreedEstimated))
	line("  writer assertion recorded: %s\n", d.WriterAssertionSource)
	line("  reopen later with: ebb open %s\n", d.Workspace)
	return b.String()
}
