// cmdStatus implements `ebb status [workspace]` (Foundation §17.1): a
// pure CATALOG view — workspaces (name/status/root), their latest
// snapshots (id/kind/pinned/created) and active operations
// (id/kind/phase/last error/next step). No vault unlock, no network
// rechecks (Foundation §17.1: network rechecks require --check, out of
// v1 scope), no filesystem mutation.
//
// Exit contract: 0 report produced (an empty catalog is a valid
// report); 2 usage (unknown --workspace filter argument shape); 3
// blocked (catalog read failure).

package cli

import (
	"flag"
	"fmt"
	"strings"
)

// statusDetails is the --json payload.
type statusDetails struct {
	Workspaces []statusWorkspace `json:"workspaces"`
}

// statusWorkspace is one workspace row plus its snapshots and active
// operations.
type statusWorkspace struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Status          string            `json:"status"`
	Root            string            `json:"root,omitempty"`
	CreatedAt       string            `json:"created_at"`
	LatestSnapshots []statusSnapshot  `json:"latest_snapshots"`
	ActiveOps       []statusOperation `json:"active_operations"`
}

// statusSnapshot is one retained snapshot of the workspace (the newest
// few; the catalog is the authority, this is a view).
type statusSnapshot struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Pinned    bool   `json:"pinned"`
	CreatedAt string `json:"created_at"`
}

// statusOperation is one non-terminal operation row.
type statusOperation struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Phase     string `json:"phase"`
	LastError string `json:"last_error,omitempty"`
	NextStep  string `json:"next_step,omitempty"`
}

// statusSnapshotLimit bounds per-workspace snapshot history in the
// view (newest first).
const statusSnapshotLimit = 5

func cmdStatus(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	filter := ""
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb status: takes at most one workspace name")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		filter = fs.Arg(0)
	}

	env := newEnvelope("status", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()

	workspaces, lerr := sess.cat.ListWorkspaces()
	if lerr != nil {
		return emitFailure(env, *jsonOut, streams, ExitBlocked,
			fmt.Sprintf("status: %v", lerr))
	}
	matched := 0
	details := statusDetails{Workspaces: []statusWorkspace{}}
	for _, w := range workspaces {
		if filter != "" && w.Name != filter {
			continue
		}
		matched++
		sw := statusWorkspace{
			ID: string(w.ID), Name: w.Name, Status: w.Status,
			Root: w.RootPath, CreatedAt: w.CreatedAt,
			LatestSnapshots: []statusSnapshot{}, ActiveOps: []statusOperation{},
		}
		if snaps, serr := sess.cat.ListSnapshots(w.ID); serr == nil {
			for i := len(snaps) - 1; i >= 0 && len(sw.LatestSnapshots) < statusSnapshotLimit; i-- {
				sw.LatestSnapshots = append(sw.LatestSnapshots, statusSnapshot{
					ID: string(snaps[i].ID), Kind: snaps[i].Kind,
					Pinned: snaps[i].Pinned, CreatedAt: snaps[i].CreatedAt,
				})
			}
		} else {
			env.Warnings = append(env.Warnings, fmt.Sprintf("snapshots of %s unavailable: %v", w.Name, serr))
		}
		if ops, oerr := sess.cat.ActiveOperations(w.ID); oerr == nil {
			for _, op := range ops {
				sw.ActiveOps = append(sw.ActiveOps, statusOperation{
					ID: string(op.ID), Kind: op.Kind, Phase: op.Phase,
					LastError: op.LastError, NextStep: op.NextAction,
				})
			}
		} else {
			env.Warnings = append(env.Warnings, fmt.Sprintf("active operations of %s unavailable: %v", w.Name, oerr))
		}
		details.Workspaces = append(details.Workspaces, sw)
	}
	if filter != "" && matched == 0 {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			fmt.Sprintf("status: no workspace named %q is recorded; run `ebb status` without a filter to list all", filter))
	}

	env.Outcome = "ok"
	env.Details = details
	emit(env, *jsonOut, streams, renderStatusHuman(details))
	return ExitOK
}

// renderStatusHuman renders the catalog view.
func renderStatusHuman(d statusDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	if len(d.Workspaces) == 0 {
		line("no workspaces recorded (run `ebb snapshot <path>` or `ebb park <path>` to create one)\n")
		return b.String()
	}
	for _, w := range d.Workspaces {
		root := w.Root
		if root == "" {
			root = "(unbound)"
		}
		line("workspace %s [%s] root %s\n", w.Name, w.Status, root)
		line("  id %s\n", w.ID)
		if len(w.LatestSnapshots) == 0 {
			line("  snapshots: none\n")
		} else {
			line("  snapshots (newest first):\n")
			for _, s := range w.LatestSnapshots {
				pin := ""
				if s.Pinned {
					pin = ", pinned"
				}
				line("    %s kind %s%s created %s\n", s.ID, s.Kind, pin, s.CreatedAt)
			}
		}
		if len(w.ActiveOps) == 0 {
			line("  active operations: none\n")
		} else {
			line("  active operations:\n")
			for _, op := range w.ActiveOps {
				line("    %s kind %s phase %s\n", op.ID, op.Kind, op.Phase)
				if op.LastError != "" {
					line("      last error: %s\n", op.LastError)
				}
				if op.NextStep != "" {
					line("      next: %s\n", op.NextStep)
				}
				line("      reconcile with: ebb recover %s\n", op.ID)
			}
		}
	}
	return b.String()
}
