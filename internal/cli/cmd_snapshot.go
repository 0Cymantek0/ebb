// cmdSnapshot implements `ebb snapshot [path]` (Foundation §17.1):
// capture and verify without removing workspace entries. The shared
// pipeline: session (state dir + catalog + store + vault) → discovery
// (identity, git observation, policy) → lifecycle.Snapshot (§12.2 steps
// 1-5, terminal DONE). The source tree is byte-identical before/after.
//
// Exit contract: 0 sealed snapshot; 2 usage (bad Ebbfile, flags); 3
// blocked (missing path, scan failure, op in progress); 4 verification
// failure (no removal was ever authorized); 7 vault; 130 cancelled.

package cli

import (
	"context"
	"flag"
	"fmt"

	"ebb/internal/domain"
	"ebb/internal/lifecycle"
)

// snapshotDetails is the --json payload shared by snapshot and park (park
// embeds it plus its tail measurements).
type snapshotDetails struct {
	Workspace        string   `json:"workspace"`
	Root             string   `json:"root"`
	SnapshotID       string   `json:"snapshot_id"`
	BackendIDs       [2]string `json:"backend_ids"`
	EntriesPreserved int64    `json:"entries_preserved"`
	EntriesOmitted   int64    `json:"entries_omitted"`
	PreservedBytes   int64    `json:"preserved_bytes"`
}

func snapshotDetailsFrom(wsName, root string, r lifecycle.SnapshotResult) snapshotDetails {
	return snapshotDetails{
		Workspace: wsName, Root: root, SnapshotID: string(r.SnapshotID),
		BackendIDs: r.BackendIDs,
		EntriesPreserved: r.EntriesPreserved, EntriesOmitted: r.EntriesOmitted,
		PreservedBytes: r.PreservedBytes,
	}
}

// openCaptureCommand runs the shared pre-capture pipeline every capture
// command (snapshot/park/trim) needs: the cancellable command context,
// the session, the root resolved through discovery (identity, git
// observation, strict policy parse, resolve) and the base
// CaptureOptions with the CLI-owned workspace-name → id binding. The
// caller owns sess.close() and stop().
func openCaptureCommand(deps Deps, streams Streams, root string) (*session, discovery, domain.PlatformProbe, lifecycle.CaptureOptions, context.Context, func(), error) {
	sess, err := openSession(deps)
	if err != nil {
		return nil, discovery{}, nil, lifecycle.CaptureOptions{}, nil, nil, err
	}
	ctx, stop := commandContext(deps)
	disc, derr := runDiscovery(ctx, deps, root, streams.Err)
	if derr != nil {
		stop()
		sess.close()
		return nil, discovery{}, nil, lifecycle.CaptureOptions{}, nil, nil, derr
	}
	opts := lifecycle.CaptureOptions{
		WorkspaceName: disc.Policy.Workspace.Name,
		WorkspaceID:   sess.resolveWorkspaceID(disc.Policy.Workspace.Name, disc.Root),
		Policy:        disc.Policy,
		Git:           disc.Obs,
	}
	probe := deps.NewProbe()
	if probe == nil {
		stop()
		sess.close()
		return nil, discovery{}, nil, lifecycle.CaptureOptions{}, nil, nil,
			usageError(fmt.Errorf("platform probe %w", ErrNotIntegrated))
	}
	return sess, disc, probe, opts, ctx, stop, nil
}

func cmdSnapshot(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb snapshot: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}

	env := newEnvelope("snapshot", "error")
	sess, disc, probe, opts, ctx, stop, err := openCaptureCommand(deps, streams, root)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("snapshot %s: %v", root, err))
	}
	defer stop()
	defer sess.close()

	coord, err := sess.newLifecycle(probe)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("snapshot %s: %v", root, err))
	}

	var res lifecycle.SnapshotResult
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		res, rErr = coord.Snapshot(ctx, lifecycleVaultRef(repoDir, passfile), disc.Root, opts)
		return rErr
	})
	if cErr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("snapshot %s: %s", disc.Root, codedWithSafeAction(cErr)))
	}

	details := snapshotDetailsFrom(opts.WorkspaceName, disc.Root, res)
	env.Outcome = "ok"
	env.WorkspaceID = string(sess.resolveWorkspaceID(opts.WorkspaceName, disc.Root))
	env.SnapshotID = details.SnapshotID
	env.Bytes = &BytesSummary{Preserved: res.PreservedBytes}
	env.Details = details
	env.Warnings = append(env.Warnings, res.Warnings...)
	emit(env, *jsonOut, streams, renderSnapshotHuman(details))
	return ExitOK
}

// renderSnapshotHuman renders the snapshot result for the human stream.
func renderSnapshotHuman(d snapshotDetails) string {
	var b []byte
	b = append(b, fmt.Sprintf("snapshot %s sealed for workspace %q\n", d.SnapshotID, d.Workspace)...)
	b = append(b, fmt.Sprintf("  root: %s\n", d.Root)...)
	b = append(b, fmt.Sprintf("  entries preserved: %d (%s); omitted: %d\n",
		d.EntriesPreserved, HumanBytes(d.PreservedBytes), d.EntriesOmitted)...)
	b = append(b, fmt.Sprintf("  retained pair: P=%s S=%s (pinned; nothing was removed)\n",
		d.BackendIDs[0], d.BackendIDs[1])...)
	return string(b)
}
