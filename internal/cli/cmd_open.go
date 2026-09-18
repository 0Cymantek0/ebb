// cmdOpen implements `ebb open <name-or-snapshot-id> [--to dir]`
// (Foundation §5.3, §12.5, §17.1): recover a retained workspace state
// without an implicit upstream update. v1 is files-only: the open
// sequence validates the seal, verifies the payload documents and the
// staged tree against an independent oracle, publishes by rename and
// reports files-ready; approved reconstruction actions are REPORTED as
// rebuild hints, never run (exit 6 is unused in v1).
//
// Target resolution: a 32-hex argument selects that snapshot directly;
// a name selects the workspace's latest sealed park snapshot (falling
// back to the latest plain snapshot when no park exists) — never the
// vault's global latest (§5.3). Destination: --to, else the workspace's
// recorded original root; a parked/unbound workspace without --to is a
// usage error.
//
// Exit contract: 0 files-ready; 2 usage (unknown target, no destination,
// unopenable kind is NOT usage — see 3); 3 blocked (trim/seal-kind
// snapshot, occupied destination, insufficient space); 4 seal/document
// verification failure; 5 publish blocked (staging kept, RESTORING);
// 7 vault; 130 cancelled.

package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/restore"
)

// openDetails is the --json payload of a completed files-only open.
type openDetails struct {
	Workspace        string             `json:"workspace"`
	SnapshotID       string             `json:"snapshot_id"`
	Kind             string             `json:"snapshot_kind"`
	Destination      string             `json:"destination"`
	EntriesRestored  int64              `json:"entries_restored"`
	BytesRestored    int64              `json:"bytes_restored"`
	RebuildHints     []openRebuildHint  `json:"rebuild_hints"`
}

type openRebuildHint struct {
	GroupID string   `json:"group_id"`
	Command []string `json:"command"`
	Inputs  []string `json:"inputs"`
	Network string   `json:"network"`
}

func cmdOpen(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	to := fs.String("to", "", "destination directory (default: the workspace's recorded original root)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb open: takes exactly one argument: a workspace name or a snapshot id (32 hex chars)")
		return ExitUsage
	}
	target := fs.Arg(0)

	env := newEnvelope("open", "error")
	sess, err := openSession(deps)
	if err != nil {
		env.Errors = []string{err.Error()}
		emit(env, *jsonOut, streams, "")
		return classifyExitCode(err)
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	// ---- resolve the target to one sealed snapshot ---------------------
	snapID, wsRow, rerr := resolveOpenTarget(sess, target)
	if rerr != nil {
		env.Errors = []string{fmt.Sprintf("open %s: %v", target, rerr)}
		emit(env, *jsonOut, streams, "")
		return classifyExitCode(rerr)
	}

	// ---- destination: --to, else the recorded root ---------------------
	dest := strings.TrimSpace(*to)
	if dest == "" {
		if wsRow.RootPath == "" {
			env.Errors = []string{fmt.Sprintf(
				"%s: workspace %q has no recorded root path (parked or unbound) and --to was not given. Safe action: pass --to <dir> with the destination directory",
				CodeOpenNoDestination, wsRow.Name)}
			emit(env, *jsonOut, streams, "")
			return ExitUsage
		}
		dest = wsRow.RootPath
	}
	absDest, aerr := filepath.Abs(dest)
	if aerr != nil {
		env.Errors = []string{fmt.Sprintf("--to %s: %v", dest, aerr)}
		emit(env, *jsonOut, streams, "")
		return ExitUsage
	}

	if deps.NewRestoreOp == nil {
		env.Errors = []string{fmt.Sprintf("restore opener %v", ErrNotIntegrated)}
		emit(env, *jsonOut, streams, "")
		return ExitUsage
	}
	if deps.NewProbe == nil {
		env.Errors = []string{fmt.Sprintf("platform probe %v", ErrNotIntegrated)}
		emit(env, *jsonOut, streams, "")
		return ExitUsage
	}
	opener, err := deps.NewRestoreOp(restore.Dependencies{
		Store: sess.store,
		Cat:   sess.cat,
		Probe: deps.NewProbe(),
	})
	if err != nil {
		env.Errors = []string{fmt.Sprintf("open %s: %v", target, err)}
		emit(env, *jsonOut, streams, "")
		return classifyExitCode(err)
	}

	var res restore.Result
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		res, rErr = opener.Open(ctx, restore.VaultRef{RepoDir: repoDir, Passfile: passfile},
			snapID, restore.Options{Destination: absDest, FilesOnly: true})
		return rErr
	})
	if cErr != nil {
		env.Errors = []string{fmt.Sprintf("open %s: %v", target, cErr)}
		emit(env, *jsonOut, streams, "")
		return classifyExitCode(cErr)
	}

	snap, _ := sess.cat.GetSnapshot(snapID)
	details := openDetails{
		Workspace:       wsRow.Name,
		SnapshotID:      string(snapID),
		Kind:            snap.Kind,
		Destination:     res.Destination,
		EntriesRestored: res.EntriesRestored,
		BytesRestored:   res.BytesRestored,
		RebuildHints:    []openRebuildHint{},
	}
	for _, h := range res.RebuildHints {
		details.RebuildHints = append(details.RebuildHints, openRebuildHint{
			GroupID: h.GroupID, Command: h.Command, Inputs: h.Inputs, Network: h.Network})
	}

	env.Outcome = "ok"
	env.OperationID = string(res.OperationID)
	env.Phase = catalog.PhaseFilesReady
	env.WorkspaceID = string(res.WorkspaceID)
	env.SnapshotID = string(snapID)
	env.Conditions = []string{"files-ready", "snapshot-pinned"}
	env.Bytes = &BytesSummary{Restored: res.BytesRestored}
	env.Details = details
	env.Warnings = append(env.Warnings, res.Warnings...)
	emit(env, *jsonOut, streams, renderOpenHuman(details))
	return ExitOK
}

// resolveOpenTarget maps the CLI argument onto one sealed snapshot and
// its workspace row. A 32-hex argument addresses the snapshot directly;
// anything else is a workspace NAME (exact match; when several rows share
// the name the parked one wins — the recoverable one). Name resolution
// prefers the latest sealed park snapshot, then the latest sealed plain
// snapshot; never a trim/seal-only record (§5.3).
func resolveOpenTarget(sess *session, target string) (domain.SnapshotID, catalog.Workspace, error) {
	if id, err := domain.ParseID(target); err == nil {
		snap, gerr := sess.cat.GetSnapshot(domain.SnapshotID(id))
		if gerr != nil {
			return "", catalog.Workspace{}, usageError(fmt.Errorf("%s: no snapshot %s in the catalog. Safe action: check `ebb status` for available snapshots",
				CodeOpenUnknownTarget, target))
		}
		ws, werr := sess.cat.GetWorkspace(snap.WorkspaceID)
		if werr != nil {
			return "", catalog.Workspace{}, usageError(fmt.Errorf("snapshot %s has no workspace row: %v", target, werr))
		}
		return snap.ID, ws, nil
	}

	workspaces, lerr := sess.cat.ListWorkspaces()
	if lerr != nil {
		return "", catalog.Workspace{}, blockedError(lerr)
	}
	var candidates []catalog.Workspace
	for _, w := range workspaces {
		if w.Name == target {
			candidates = append(candidates, w)
		}
	}
	if len(candidates) == 0 {
		return "", catalog.Workspace{}, usageError(fmt.Errorf(
			"%s: no workspace named %q is recorded (and the argument is not a 32-hex snapshot id). Safe action: check `ebb status` for workspace names and snapshot ids",
			CodeOpenUnknownTarget, target))
	}
	ws := candidates[0]
	for _, c := range candidates {
		if c.Status == catalog.WorkspaceParked {
			ws = c
			break
		}
	}
	snaps, serr := sess.cat.ListSnapshots(ws.ID)
	if serr != nil {
		return "", ws, blockedError(serr)
	}
	var latestPark, latestSnap *catalog.Snapshot
	for i := range snaps {
		s := snaps[i]
		if s.PayloadBackendID == "" || s.SealBackendID == "" {
			continue // unsealed payloads are never publishable (§11.3)
		}
		switch s.Kind {
		case catalog.SnapshotKindPark:
			if latestPark == nil {
				sCopy := s
				latestPark = &sCopy
			}
		case catalog.SnapshotKindSnapshot:
			if latestSnap == nil {
				sCopy := s
				latestSnap = &sCopy
			}
		}
	}
	if latestPark != nil {
		return latestPark.ID, ws, nil
	}
	if latestSnap != nil {
		return latestSnap.ID, ws, nil
	}
	return "", ws, blockedError(fmt.Errorf(
		"%s: workspace %q has no sealed openable snapshot (park or snapshot kind). Safe action: check `ebb status`; a trim snapshot is not a workspace payload and a failed capture may have left an unsealed payload",
		CodeOpenUnknownTarget, target))
}

// renderOpenHuman renders the files-ready open report.
func renderOpenHuman(d openDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("opened workspace %q at %s\n", d.Workspace, d.Destination)
	line("  snapshot: %s (kind %s, stays pinned)\n", d.SnapshotID, d.Kind)
	line("  entries restored: %d (%s)\n", d.EntriesRestored, HumanBytes(d.BytesRestored))
	line("  status: files-ready — preserved files are back; v1 open does not run reconstruction\n")
	if len(d.RebuildHints) == 0 {
		line("  rebuild: nothing to reconstruct\n")
	} else {
		line("  rebuild hints (run them yourself; Ebb will not execute them):\n")
		for _, h := range d.RebuildHints {
			line("    - %s: %s", h.GroupID, strings.Join(h.Command, " "))
			if len(h.Inputs) > 0 {
				line(" (inputs: %s)", strings.Join(h.Inputs, ", "))
			}
			line("\n")
		}
	}
	return b.String()
}
