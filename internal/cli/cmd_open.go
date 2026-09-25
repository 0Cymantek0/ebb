// cmdOpen implements `ebb open <name-or-snapshot-id> [--to dir]`
// (Foundation §5.3, §12.5, §17.1): recover a retained workspace state
// without an implicit upstream update. The open sequence validates the
// seal, verifies the payload documents and the staged tree against an
// independent oracle, and publishes by rename. When the manifest froze
// exact action definitions, the reconstruction phase then runs the
// retained, locally-approved actions at the final destination
// (REBUILDING → READY → DONE, F36-verified); `--files-only` stops after
// publication (FILES_READY → DONE) and legacy manifests without
// definitions are hint-only.
//
// Approvals (Foundation §7.3): recorded approvals that still match
// exactly are reused without prompting (§5.2); missing approvals get ONE
// grouped interactive prompt (argv, resolved tool identity, inputs,
// outputs, network, shell warning); `--yes` records approvals for
// never-approved actions without a prompt but NEVER covers drift — a
// stale approval always re-prompts interactively and blocks in
// non-interactive mode.
//
// `ebb open --resume <op-id-or-workspace>` re-enters the rebuild of the
// workspace's REBUILD_FAILED/REBUILDING/FILES_READY open operation,
// re-running only actions without a journaled successful run.
// `ebb open --cancel <op-id-or-workspace>` records an explicit cancel of
// such an operation (CANCELED, terminal): the published files stay and
// the snapshot stays pinned.
//
// Target resolution: a 32-hex argument selects that snapshot directly
// (an operation id under --resume/--cancel); a name selects the
// workspace's NEWEST sealed park snapshot (falling back to the newest
// plain snapshot when no park exists) — never the vault's global latest
// (§5.3). A name matching several workspaces, and a created_at tie
// inside the winning kind, are ambiguity refusals demanding the explicit
// snapshot id (Wave 5 E10/E12). Destination: --to, else the workspace's
// recorded original root; a parked/unbound workspace without --to is a
// usage error.
//
// Exit contract: 0 done (files-only included); 2 usage; 3 blocked
// (trim/seal-kind snapshot, occupied destination, insufficient space);
// 4 seal/document verification failure; 5 publish blocked (staging
// kept, RESTORING); 6 rebuild failed/blocked (files intact, resumable);
// 7 vault; 130 cancelled.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/cli/tui"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/platform"
	"github.com/0Cymantek0/ebb/internal/restore"
)

// WorkspaceChoice is one row of the bare-`ebb open` picker (D032).
type WorkspaceChoice struct {
	Name   string
	Detail string
	Right  string
}

// pickParkedWorkspace runs the D032 bare-invocation picker over the
// catalog's parked workspaces. handled=false means no picker interaction
// is possible (the caller reports its own failure); handled=true with an
// empty name means an exit code was already emitted (cancel 130, blocked
// 3); otherwise the returned name is the chosen open target.
func pickParkedWorkspace(ctx context.Context, deps Deps, sess *session, streams Streams) (string, int, bool) {
	wss, err := sess.cat.ListWorkspaces()
	if err != nil {
		fmt.Fprintf(streams.Err, "ebb open: listing workspaces: %v\n", err)
		return "", ExitBlocked, true
	}
	var rows []WorkspaceChoice
	for _, w := range wss {
		if w.Status != catalog.WorkspaceParked {
			continue
		}
		detail := w.RootPath
		if detail == "" {
			if orig := originalRootOf(sess.cat, w.ID); orig != "" {
				detail = "original: " + orig
			} else {
				detail = "no recorded root (open with --to)"
			}
		}
		rows = append(rows, WorkspaceChoice{Name: w.Name, Detail: detail, Right: "parked"})
	}
	if len(rows) == 0 {
		fmt.Fprintln(streams.Err, "ebb open: no parked workspaces recorded; pass a workspace name or snapshot id (see `ebb status`)")
		return "", ExitBlocked, true
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	idx, perr := deps.PickWorkspace(ctx, "Ebb: select parked workspace to open", rows, streams.Err)
	if perr != nil {
		if errors.Is(perr, tui.ErrCanceled) {
			fmt.Fprintln(streams.Err, "ebb open: canceled")
			return "", ExitCancelled, true
		}
		fmt.Fprintf(streams.Err, "ebb open: workspace picker unavailable (%v); pass a workspace name or snapshot id\n", perr)
		return "", ExitBlocked, true
	}
	return rows[idx].Name, ExitOK, true
}

// originalRootOf returns the workspace's best-evidence original root for
// an unbound (parked) workspace: the latest park operation's journaled
// source root (ListOperations is updated_at-ascending, so the last match
// is the newest). Empty when no park op recorded a root.
func originalRootOf(cat *catalog.Catalog, wsID domain.WorkspaceID) string {
	ops, err := cat.ListOperations(wsID)
	if err != nil {
		return ""
	}
	root := ""
	for _, op := range ops {
		if op.Kind == catalog.OpKindPark && op.SourceRoot != "" {
			root = op.SourceRoot
		}
	}
	return root
}

// openDetails is the --json payload of a completed open.
type openDetails struct {
	Workspace  string `json:"workspace"`
	SnapshotID string `json:"snapshot_id"`
	Kind       string `json:"snapshot_kind"`
	// SnapshotCreatedAt is the restored snapshot's RFC3339Nano creation
	// timestamp: the receipt names WHICH state came back (Wave 5 E10),
	// which matters precisely because recency now decides the target.
	SnapshotCreatedAt string            `json:"snapshot_created_at,omitempty"`
	Destination       string            `json:"destination"`
	EntriesRestored   int64             `json:"entries_restored"`
	BytesRestored     int64             `json:"bytes_restored"`
	RebuildHints      []openRebuildHint `json:"rebuild_hints"`
	Actions           []openActionRun   `json:"actions"`
}

type openRebuildHint struct {
	GroupID string   `json:"group_id"`
	Command []string `json:"command"`
	Inputs  []string `json:"inputs"`
	Network string   `json:"network"`
}

type openActionRun struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code,omitempty"`
	Skipped  bool   `json:"skipped,omitempty"`
}

func cmdOpen(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("open", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	to := fs.String("to", "", "destination directory (default: the workspace's recorded original root)")
	filesOnly := fs.Bool("files-only", false, "stop after the preserved files are published; do not run reconstruction")
	yes := fs.Bool("yes", false, "record approvals for not-yet-approved actions without a prompt (never covers approval drift)")
	resume := fs.Bool("resume", false, "resume the rebuild of the workspace's interrupted open operation")
	cancel := fs.Bool("cancel", false, "cancel the workspace's REBUILD_FAILED/REBUILDING open operation (files stay, snapshot stays pinned)")
	if err := fs.Parse(reorderFlags(args, "to")); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb open: takes exactly one argument: a workspace name, a snapshot id (32 hex chars), or with --resume/--cancel an operation id")
		return ExitUsage
	}
	// D032 bare invocation: no target + interactive terminal + not machine
	// mode → the parked-workspace picker. Everything else keeps the
	// ordinary usage error below, exactly as before.
	barePick := fs.NArg() == 0 && !*resume && !*cancel && !*jsonOut &&
		deps.PickWorkspace != nil && deps.StdinIsTerminal != nil && deps.StdinIsTerminal()
	if fs.NArg() == 0 && !barePick {
		fmt.Fprintln(streams.Err, "ebb open: takes exactly one argument: a workspace name, a snapshot id (32 hex chars), or with --resume/--cancel an operation id")
		return ExitUsage
	}
	if *resume && *cancel {
		fmt.Fprintln(streams.Err, "ebb open: --resume and --cancel are mutually exclusive")
		return ExitUsage
	}

	env := newEnvelope("open", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	var target string
	if fs.NArg() == 1 {
		target = fs.Arg(0)
	} else {
		picked, code, handled := pickParkedWorkspace(ctx, deps, sess, streams)
		if !handled || picked == "" {
			return code
		}
		target = picked
	}

	if *resume || *cancel {
		return runOpenRecovery(env, *jsonOut, streams, deps, sess, ctx, target, *resume, *yes)
	}

	// ---- resolve the target to one sealed snapshot ---------------------
	snapID, wsRow, rerr := resolveOpenTarget(sess, target)
	if rerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(rerr),
			fmt.Sprintf("open %s: %v", target, rerr))
	}

	// ---- destination: --to, else the recorded root ---------------------
	dest := strings.TrimSpace(*to)
	if dest == "" {
		if wsRow.RootPath == "" {
			// Parked workspaces are unbound by design (§16.5), but the
			// park operation's journal still records the original root —
			// the D032 default destination ("original location").
			dest = originalRootOf(sess.cat, wsRow.ID)
		} else {
			dest = wsRow.RootPath
		}
		if dest == "" {
			return emitFailure(env, *jsonOut, streams, ExitUsage, fmt.Sprintf(
				"%s: workspace %q has no recorded root path (parked or unbound) and --to was not given. Safe action: pass --to <dir> with the destination directory",
				CodeOpenNoDestination, wsRow.Name))
		}
	}
	absDest, aerr := filepath.Abs(dest)
	if aerr != nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			fmt.Sprintf("--to %s: %v", dest, aerr))
	}

	opener, err := newOpenOpener(deps, sess, streams, !*filesOnly, *yes, *jsonOut)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("open %s: %v", target, err))
	}

	var res restore.Result
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		res, rErr = opener.Open(ctx, restore.VaultRef{RepoDir: repoDir, Passfile: passfile},
			snapID, restore.Options{Destination: absDest, FilesOnly: *filesOnly})
		return rErr
	})
	if cErr != nil {
		var rebuild *restore.ErrRebuildFailed
		if errors.As(cErr, &rebuild) {
			// Files ARE published; the rebuild failed. Report the partial
			// success + exit 6 naming the failed actions and the resume
			// command (§17.5).
			return emitOpenRebuildFailure(env, *jsonOut, streams, target, rebuild,
				openResultDetails(sess, snapID, res))
		}
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("open %s: %s", target, codedWithSafeAction(cErr)))
	}

	details := openResultDetails(sess, snapID, res)
	env.Outcome = "ok"
	env.OperationID = string(res.OperationID)
	env.Phase = res.Phase
	env.WorkspaceID = string(res.WorkspaceID)
	env.SnapshotID = string(snapID)
	env.Conditions = openConditions(res)
	env.Bytes = &BytesSummary{Restored: res.BytesRestored}
	env.Details = details
	env.Warnings = append(env.Warnings, res.Warnings...)
	emit(env, *jsonOut, streams, renderOpenHuman(details))
	return ExitOK
}

// runOpenRecovery serves `ebb open --resume` and `ebb open --cancel`.
func runOpenRecovery(env Envelope, jsonOut bool, streams Streams, deps Deps, sess *session, ctx context.Context, target string, resume, yes bool) int {
	op, rerr := resolveOpenOperation(sess, target)
	if rerr != nil {
		return emitFailure(env, jsonOut, streams, classifyExitCode(rerr),
			fmt.Sprintf("open %s: %v", target, rerr))
	}
	env.OperationID = string(op.ID)
	env.WorkspaceID = string(op.WorkspaceID)

	if !resume {
		op, err := cancelOpenOp(deps, sess, op)
		if err != nil {
			return emitFailure(env, jsonOut, streams, classifyExitCode(err),
				fmt.Sprintf("open --cancel %s: %s", target, codedWithSafeAction(err)))
		}
		env.Outcome = "ok"
		env.Phase = catalog.PhaseCanceled
		env.Conditions = []string{"operation-canceled", "files-kept", "snapshot-pinned"}
		emit(env, jsonOut, streams, fmt.Sprintf(
			"canceled open operation %s at %s\n  published files kept at %s; the snapshot stays pinned\n",
			op.ID, op.Phase, op.SourceRoot))
		return ExitOK
	}

	opener, err := newOpenOpener(deps, sess, streams, true, yes, jsonOut)
	if err != nil {
		return emitFailure(env, jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("open --resume %s: %v", target, err))
	}
	var res restore.Result
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		res, rErr = opener.ResumeRebuild(ctx, restore.VaultRef{RepoDir: repoDir, Passfile: passfile}, op.ID)
		return rErr
	})
	if cErr != nil {
		var rebuild *restore.ErrRebuildFailed
		if errors.As(cErr, &rebuild) {
			return emitOpenRebuildFailure(env, jsonOut, streams, target, rebuild, openResultDetails(sess, res.SnapshotID, res))
		}
		return emitFailure(env, jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("open --resume %s: %s", target, codedWithSafeAction(cErr)))
	}

	details := openResultDetails(sess, res.SnapshotID, res)
	env.Outcome = "ok"
	env.Phase = res.Phase
	env.SnapshotID = string(res.SnapshotID)
	env.Conditions = openConditions(res)
	env.Bytes = &BytesSummary{Restored: res.BytesRestored}
	env.Details = details
	env.Warnings = append(env.Warnings, res.Warnings...)
	emit(env, jsonOut, streams, renderOpenHuman(details))
	return ExitOK
}

// newOpenOpener builds the restore opener with the reconstruction seams:
// the real actions runner (or the Deps test seam), the approvalstore in
// the state dir, and the CLI-owned grouped approval resolver. withRebuild
// false (a --files-only open) wires nothing — no approvals are needed.
// jsonOut threads machine mode into the resolver (--json never prompts,
// on a terminal or off one).
func newOpenOpener(deps Deps, sess *session, streams Streams, withRebuild, yes, jsonOut bool) (*restore.Opener, error) {
	if deps.NewRestoreOp == nil {
		return nil, usageError(fmt.Errorf("restore opener %w", ErrNotIntegrated))
	}
	if deps.NewProbe == nil {
		return nil, usageError(fmt.Errorf("platform probe %w", ErrNotIntegrated))
	}
	d := restore.Dependencies{
		Store: sess.store,
		Cat:   sess.cat,
		Probe: deps.NewProbe(),
		// Native link recreation: junctions unprivileged on Windows,
		// symlinks privilege-typed (Wave F link staging). The stdlib
		// default cannot create junctions, so production injects the
		// platform implementation.
		CreateLink: platform.CreateLink,
	}
	if withRebuild {
		runner := newActionRunner(deps)
		if runner == nil {
			return nil, usageError(fmt.Errorf("action runner %w", ErrNotIntegrated))
		}
		store := approvalstore.New(sess.approvalsPath())
		d.Runner = runner
		d.Approver = store
		d.Approve = openApprovalResolver(deps, streams, yes, jsonOut, store)
	}
	opener, err := deps.NewRestoreOp(d)
	if err != nil {
		return nil, blockedError(err)
	}
	return opener, nil
}

// newActionRunner returns the production actions.Runner (or the Deps
// test seam), or nil when unwired.
func newActionRunner(deps Deps) restore.ActionRunner {
	if deps.NewActionRunner != nil {
		return deps.NewActionRunner()
	}
	return actions.New()
}

// openApprovalResolver builds the CLI-side approval seam: ONE grouped
// interactive prompt listing every pending action (argv, resolved tool
// identity, inputs, outputs, network, shell warning; drift lines for
// stale approvals), or --yes recording never-approved actions without a
// prompt. Recorded approvals that match exactly never prompt (§5.2).
// Drift ALWAYS re-prompts interactively and blocks in non-interactive
// mode — --yes never silently covers a changed action.
//
// machine is the --json mode (the same rule the restore prompter
// follows): a scripted consumer must never wait on hidden input, so
// machine mode behaves exactly like a missing terminal — missing
// approvals and drift refuse with their typed errors and no line is
// ever read. Explicit --yes is unaffected (flag consent is not a prompt).
func openApprovalResolver(deps Deps, streams Streams, yes, machine bool, store *approvalstore.FileApprover) restore.ApprovalResolver {
	return func(ctx context.Context, pending []restore.PendingApproval) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		interactive := !machine && deps.StdinIsTerminal != nil && deps.StdinIsTerminal()
		var required, stale []restore.PendingApproval
		for _, p := range pending {
			var staleErr *actions.ErrApprovalStale
			if errors.As(p.Cause, &staleErr) {
				stale = append(stale, p)
				continue
			}
			required = append(required, p)
		}

		// Drift blocks without a terminal, even with --yes.
		if len(stale) > 0 && !interactive {
			return fmt.Errorf("%s: %d recorded approval(s) no longer match the action (drift) and stdin is not a terminal, so the required re-approval cannot be asked. Safe action: rerun in a terminal and re-approve after reviewing the drift",
				CodeApprovalDrift, len(stale))
		}
		// Fresh approvals need --yes or a terminal.
		if len(required) > 0 && !yes && !interactive {
			return fmt.Errorf("%s: %d action(s) have no recorded approval and stdin is not a terminal. Safe action: rerun with --yes to record the approval, or run in a terminal to review the actions first",
				CodeApprovalRequired, len(required))
		}

		// What is confirmed interactively? With --yes the never-approved
		// set is auto-recorded, so only drift still prompts; without
		// --yes everything prompts (one grouped decision).
		var listing []restore.PendingApproval
		switch {
		case yes && len(stale) > 0:
			listing = stale
		case !yes:
			listing = append(append([]restore.PendingApproval(nil), required...), stale...)
		}
		if len(listing) > 0 {
			fmt.Fprint(streams.Err, approvalPromptText(listing))
			if !confirmYes(deps, streams.Err, "") {
				return fmt.Errorf("%s: the reconstruction approval was declined; nothing ran. Safe action: review the listed actions and rerun, or use --files-only to stop after publishing the files",
					CodeApprovalDeclined)
			}
		}

		// Record: never-approved actions under --yes record without a
		// prompt; everything confirmed above records as interactive.
		for _, p := range required {
			approvedBy := "flag:--yes"
			if !yes {
				approvedBy = "interactive-confirm"
			}
			if _, aerr := store.Approve(p.Def, p.Tool, p.InputDigests, approvedBy); aerr != nil {
				return fmt.Errorf("recording the approval for action %s: %w", p.Def.ID, aerr)
			}
		}
		for _, p := range stale {
			if _, aerr := store.Approve(p.Def, p.Tool, p.InputDigests, "interactive-confirm"); aerr != nil {
				return fmt.Errorf("recording the re-approval for action %s: %w", p.Def.ID, aerr)
			}
		}
		return nil
	}
}

// approvalPromptText renders the grouped approval listing (§7.3: the
// exact command, executable identity, working root, inputs, outputs,
// env allowlist and network the approval would pin; shell actions carry
// the stronger warning verbatim; stale approvals show their drift
// lines). Secret-bearing env keys (Ebb's own denylist, Foundation
// §13.1) are never displayed by name — an action asking for one is
// definitionally unapprovable (actions.ErrEnvDenylisted refuses the
// definition before a prompt can exist), so the prompt says that
// instead of spelling the key or offering a yes/no choice.
func approvalPromptText(pending []restore.PendingApproval) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The following reconstruction actions will run at the destination:\n")
	for _, p := range pending {
		fmt.Fprintf(&b, "  - %s: %s\n", p.Def.ID, strings.Join(p.Def.Argv, " "))
		fmt.Fprintf(&b, "      tool: %s (sha256 %s…)\n", p.Tool.ResolvedPath, shaPrefix(p.Tool.SHA256))
		if p.Def.WorkingRoot != "" {
			fmt.Fprintf(&b, "      working root: %s\n", p.Def.WorkingRoot)
		}
		if len(p.Def.Inputs) > 0 {
			fmt.Fprintf(&b, "      inputs: %s\n", strings.Join(p.Def.Inputs, ", "))
		}
		fmt.Fprintf(&b, "      outputs: %s\n", strings.Join(p.Def.Outputs, ", "))
		if len(p.Def.EnvAllow) > 0 {
			keys := make([]string, 0, len(p.Def.EnvAllow))
			for _, k := range actions.CanonicalEnvAllow(p.Def.EnvAllow) {
				if actions.EnvKeyDenylisted(k) {
					keys = append(keys, "<secret-bearing env key suppressed; an action asking for it is unapprovable>")
					continue
				}
				keys = append(keys, k)
			}
			fmt.Fprintf(&b, "      env allow: %s\n", strings.Join(keys, ", "))
		}
		fmt.Fprintf(&b, "      network: %s\n", p.Def.Network)
		if w := p.Def.ShellWarning(); w != "" {
			fmt.Fprintf(&b, "      %s\n", w)
		}
		var stale *actions.ErrApprovalStale
		if errors.As(p.Cause, &stale) {
			fmt.Fprintf(&b, "      approval drift since last approval:\n")
			for _, d := range stale.Diff {
				fmt.Fprintf(&b, "        - %s\n", d)
			}
		}
	}
	fmt.Fprint(&b, "Approve these actions? type 'yes': ")
	return b.String()
}

func shaPrefix(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

// resolveOpenOperation maps a --resume/--cancel argument onto one open
// operation: a 32-hex argument addresses the operation row directly; a
// name selects the workspace's single open operation in a resumable
// phase (FILES_READY, REBUILDING, REBUILD_FAILED).
func resolveOpenOperation(sess *session, target string) (catalog.Operation, error) {
	resumable := func(op catalog.Operation) bool {
		return op.Kind == catalog.OpKindOpen && restore.ResumablePhase(op.Phase)
	}
	if id, err := domain.ParseID(target); err == nil {
		op, gerr := sess.cat.GetOperation(domain.OperationID(id))
		if gerr != nil {
			return catalog.Operation{}, usageError(fmt.Errorf("%s: no operation %s in the catalog. Safe action: check `ebb status` for operation ids",
				CodeOpenUnknownTarget, target))
		}
		if !resumable(op) {
			return catalog.Operation{}, usageError(fmt.Errorf(
				"operation %s is %s/%s; --resume/--cancel apply to an open in FILES_READY, REBUILDING or REBUILD_FAILED", target, op.Kind, op.Phase))
		}
		return op, nil
	}
	workspaces, lerr := sess.cat.ListWorkspaces()
	if lerr != nil {
		return catalog.Operation{}, blockedError(lerr)
	}
	for _, w := range workspaces {
		if w.Name != target {
			continue
		}
		active, aerr := sess.cat.ActiveOperations(w.ID)
		if aerr != nil {
			return catalog.Operation{}, blockedError(aerr)
		}
		var found []catalog.Operation
		for _, op := range active {
			if resumable(op) {
				found = append(found, op)
			}
		}
		switch len(found) {
		case 1:
			return found[0], nil
		case 0:
			return catalog.Operation{}, usageError(fmt.Errorf(
				"%s: workspace %q has no open operation to resume or cancel. Safe action: check `ebb status`",
				CodeOpenUnknownTarget, target))
		default:
			ids := make([]string, 0, len(found))
			for _, op := range found {
				ids = append(ids, string(op.ID))
			}
			return catalog.Operation{}, usageError(fmt.Errorf(
				"workspace %q has %d resumable open operations (%s); pass the operation id explicitly", target, len(found), strings.Join(ids, ", ")))
		}
	}
	return catalog.Operation{}, usageError(fmt.Errorf(
		"%s: no workspace named %q is recorded (and the argument is not a 32-hex operation id). Safe action: check `ebb status`",
		CodeOpenUnknownTarget, target))
}

// cancelOpenOp cancels a resumable open operation through the restore
// cancel path (phase → CANCELED; a pure journal act — the published
// files and the snapshot pin are untouched).
func cancelOpenOp(deps Deps, sess *session, op catalog.Operation) (catalog.Operation, error) {
	if deps.NewRestoreOp == nil || deps.NewProbe == nil {
		return op, usageError(fmt.Errorf("restore opener %w", ErrNotIntegrated))
	}
	opener, err := deps.NewRestoreOp(restore.Dependencies{
		Store: sess.store, Cat: sess.cat, Probe: deps.NewProbe(),
	})
	if err != nil {
		return op, blockedError(err)
	}
	return opener.CancelRebuild(op.ID)
}

// openResultDetails assembles the JSON/human details from a result.
func openResultDetails(sess *session, snapID domain.SnapshotID, res restore.Result) openDetails {
	details := openDetails{
		Destination:     res.Destination,
		EntriesRestored: res.EntriesRestored,
		BytesRestored:   res.BytesRestored,
		RebuildHints:    []openRebuildHint{},
		Actions:         []openActionRun{},
	}
	snap, _ := sess.cat.GetSnapshot(snapID)
	details.SnapshotID = string(snapID)
	details.Kind = snap.Kind
	details.SnapshotCreatedAt = snap.CreatedAt
	if ws, err := sess.cat.GetWorkspace(res.WorkspaceID); err == nil {
		details.Workspace = ws.Name
	}
	for _, h := range res.RebuildHints {
		details.RebuildHints = append(details.RebuildHints, openRebuildHint{
			GroupID: h.GroupID, Command: h.Command, Inputs: h.Inputs, Network: h.Network})
	}
	for _, a := range res.Actions {
		details.Actions = append(details.Actions, openActionRun{
			ID: a.ID, Status: a.Status, ExitCode: a.ExitCode, Skipped: a.Skipped})
	}
	return details
}

// openConditions derives the envelope conditions from the result.
func openConditions(res restore.Result) []string {
	conds := []string{"snapshot-pinned"}
	switch res.Phase {
	case catalog.PhaseDone:
		if len(res.Actions) > 0 {
			conds = append([]string{"ready", "rebuild-complete"}, conds...)
		} else {
			conds = append([]string{"files-ready"}, conds...)
		}
	case catalog.PhaseRebuildFailed:
		conds = append([]string{"rebuild-failed", "files-intact"}, conds...)
	}
	return conds
}

// emitOpenRebuildFailure reports the §17.5 exit-6 outcome: files
// recovered and intact, rebuild failed, naming the failed actions and
// the resume command.
func emitOpenRebuildFailure(env Envelope, jsonOut bool, streams Streams, target string, rebuild *restore.ErrRebuildFailed, details openDetails) int {
	env.Outcome = outcomeForExit(ExitRebuildFailed)
	env.Phase = catalog.PhaseRebuildFailed
	env.Details = details
	env.Conditions = []string{"rebuild-failed", "files-intact", "snapshot-pinned"}
	msg := codedWithSafeAction(rebuild)
	emit(env, jsonOut, streams, fmt.Sprintf(
		"open %s: %s\n  recovered files are intact at %s; resolve the blocker and rerun with: ebb open --resume %s\n",
		target, msg, details.Destination, rebuild.OperationID))
	return ExitRebuildFailed
}

// resolveOpenTarget maps the CLI argument onto one sealed snapshot and
// its workspace row. A 32-hex argument addresses the snapshot directly;
// anything else is a workspace NAME (exact match; several rows sharing
// the name are an ambiguity refusal naming every candidate — names are
// labels, not identities, Wave 5 E12). Name resolution prefers the
// NEWEST sealed park snapshot, then the NEWEST sealed plain snapshot
// (Wave 5 E10: ListSnapshots is created_at-ascending, so the newest
// eligible row is the LAST match, never the first); a created_at tie
// inside the winning kind is itself an ambiguity refusal. Never a
// trim/seal-only record (§5.3).
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
	if len(candidates) > 1 {
		var b strings.Builder
		for _, c := range candidates {
			root := c.RootPath
			if root == "" {
				root = "(no recorded root)"
			}
			fmt.Fprintf(&b, "  - %s (status %s, root %s)\n", c.ID, c.Status, root)
		}
		return "", catalog.Workspace{}, blockedError(fmt.Errorf(
			"%s: the name %q matches %d workspaces; names are labels, not identities:\n%sSafe action: pass the explicit snapshot id of the state to open (`ebb open <snapshot-id>`); `ebb status` lists every workspace's id, status and root",
			CodeOpenAmbiguousTarget, target, len(candidates), b.String()))
	}
	ws := candidates[0]
	snaps, serr := sess.cat.ListSnapshots(ws.ID)
	if serr != nil {
		return "", ws, blockedError(serr)
	}
	// E10: any sealed park still beats any plain snapshot (kind
	// precedence preserved), but WITHIN the winning kind the NEWEST
	// created_at must win — the ascending list made the old first-match
	// loop restore the OLDEST state.
	latest, aerr := newestSealedOfKind(snaps, catalog.SnapshotKindPark)
	if aerr != nil {
		return "", ws, aerr
	}
	if latest == nil {
		latest, aerr = newestSealedOfKind(snaps, catalog.SnapshotKindSnapshot)
		if aerr != nil {
			return "", ws, aerr
		}
	}
	if latest == nil {
		return "", ws, blockedError(fmt.Errorf(
			"%s: workspace %q has no sealed openable snapshot (park or snapshot kind). Safe action: check `ebb status`; a trim snapshot is not a workspace payload and a failed capture may have left an unsealed payload",
			CodeOpenUnknownTarget, target))
	}
	return latest.ID, ws, nil
}

// newestSealedOfKind returns the newest (max created_at) sealed snapshot
// of one kind, or nil when the workspace has none of that kind. Two
// eligible rows sharing the exact same created_at string are refused as
// ambiguous (Wave 5 E10): recency cannot decide between them, so the
// caller must pass the explicit snapshot id.
func newestSealedOfKind(snaps []catalog.Snapshot, kind string) (*catalog.Snapshot, error) {
	var newest *catalog.Snapshot
	var newestT time.Time
	var ties []*catalog.Snapshot
	for i := range snaps {
		s := &snaps[i]
		if s.Kind != kind || s.PayloadBackendID == "" || s.SealBackendID == "" {
			continue // unsealed payloads are never publishable (§11.3)
		}
		t, terr := time.Parse(time.RFC3339Nano, s.CreatedAt)
		if terr != nil {
			// Fail closed on corrupt evidence: an unparseable timestamp
			// can never justify recency-based selection (and a lexical
			// fallback would order representations, not instants).
			return nil, blockedError(fmt.Errorf(
				"%s: sealed %s snapshot %s has an unparseable creation timestamp %q; recency cannot be decided from corrupt evidence. Safe action: pass the explicit snapshot id (`ebb open <snapshot-id>`, see `ebb status`), or inspect the row with `ebb verify`",
				CodeOpenTimestampInvalid, kind, s.ID, s.CreatedAt))
		}
		switch {
		case newest == nil || t.After(newestT):
			newest, newestT = s, t
			ties = []*catalog.Snapshot{s}
		case t.Equal(newestT):
			// Parsed-instant equality, NOT string equality: the same
			// instant has multiple RFC3339Nano spellings (".123Z" vs
			// ".123000000Z") and RecordSnapshot does not normalize
			// supplied timestamps.
			ties = append(ties, s)
		}
	}
	if newest == nil {
		return nil, nil
	}
	if len(ties) > 1 {
		ids := make([]string, 0, len(ties))
		for _, c := range ties {
			ids = append(ids, string(c.ID))
		}
		return nil, blockedError(fmt.Errorf(
			"%s: %d sealed %s snapshots of this workspace share the same creation instant %s (%s); recency cannot decide. Safe action: pass the explicit snapshot id (`ebb open <snapshot-id>`, see `ebb status`)",
			CodeOpenAmbiguousTarget, len(ties), kind, newest.CreatedAt, strings.Join(ids, ", ")))
	}
	return newest, nil
}

// renderOpenHuman renders the open report.
func renderOpenHuman(d openDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("opened workspace %q at %s\n", d.Workspace, d.Destination)
	line("  snapshot: %s (kind %s", d.SnapshotID, d.Kind)
	if d.SnapshotCreatedAt != "" {
		line(", created %s", d.SnapshotCreatedAt)
	}
	line(", stays pinned)\n")
	line("  entries restored: %d (%s)\n", d.EntriesRestored, HumanBytes(d.BytesRestored))
	if len(d.Actions) == 0 {
		line("  status: files-ready — preserved files are back; no reconstruction actions ran\n")
	} else {
		for _, a := range d.Actions {
			switch {
			case a.Skipped:
				line("  action %s: skipped (already succeeded earlier)\n", a.ID)
			case a.Status == "succeeded":
				line("  action %s: succeeded\n", a.ID)
			default:
				line("  action %s: %s (exit %d)\n", a.ID, a.Status, a.ExitCode)
			}
		}
		line("  status: ready — approved reconstruction completed\n")
	}
	if len(d.RebuildHints) > 0 {
		hinted := false
		for _, h := range d.RebuildHints {
			ran := false
			for _, a := range d.Actions {
				if a.ID == h.GroupID && a.Status == "succeeded" {
					ran = true
				}
			}
			if !ran {
				hinted = true
				line("  rebuild hint (not executable from this snapshot; run it yourself): %s: %s\n",
					h.GroupID, strings.Join(h.Command, " "))
			}
		}
		_ = hinted
	}
	return b.String()
}
