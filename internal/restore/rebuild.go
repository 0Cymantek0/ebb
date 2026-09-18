package restore

// The reconstruction phase of Foundation §12.5's last paragraphs: after
// the preserved files are published (FILES_READY), run the retained,
// locally-approved reconstruction actions at the FINAL destination
// through the actions.Runner, journal every attempt in the catalog's
// action_runs table, verify protected files were not damaged (F36), and
// drive the open operation REBUILDING → READY → DONE. Any failure lands
// at REBUILD_FAILED — non-terminal, resolvable by `ebb open --resume` —
// with the published files untouched (I08) and the snapshot pinned (I07).
//
// This package owns the driver and journal; it NEVER owns prompting:
// interactive approval UX lives in internal/cli, injected through the
// ApprovalResolver seam (restore must not import internal/cli). The
// actions package owns execution; this package adds no removal rights
// beyond its existing staging/empty-destination rules (Foundation §9.5).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ebb/internal/actions"
	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// ActionRunner executes one approved action definition under a workspace
// root. It is satisfied by *actions.Runner; tests substitute a fake. The
// seam exists so the driver is testable without spawning processes.
type ActionRunner interface {
	Run(ctx context.Context, def actions.Definition, wsRoot string, appr actions.Approver, capture actions.OutputSink) (actions.Result, error)
}

// PendingApproval describes one action whose recorded approval is
// missing (Cause is *actions.ErrApprovalRequired) or stale (Cause is
// *actions.ErrApprovalStale, whose Diff names every drifted field). The
// resolved tool identity and input digests are supplied so the resolver
// can display exactly what would run and record an approval pinning it.
type PendingApproval struct {
	Def          actions.Definition
	Tool         actions.ToolIdentity
	InputDigests map[string]string
	Cause        error
}

// ApprovalResolver is the CLI-supplied seam that resolves pending
// approvals BEFORE any action runs: it may prompt the user (grouped, one
// prompt listing every pending action) and record approvals through the
// same approvalstore that backs Dependencies.Approver. Returning nil
// asserts every listed action is now approved; returning an error fails
// the rebuild as declined/blocked (never executes anything).
type ApprovalResolver func(ctx context.Context, pending []PendingApproval) error

// Action status values reported in ActionReport (mirroring the catalog's
// action_runs vocabulary plus the resume-only "skipped").
const (
	ActionSucceeded = "succeeded"
	ActionFailed    = "failed"
	ActionCancelled = "cancelled"
	ActionSkipped   = "skipped"
)

// ActionReport is one action's outcome in the rebuild result.
type ActionReport struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	ExitCode int    `json:"exit_code,omitempty"`
	// Skipped marks actions a resume did not re-run because a successful
	// attempt is already journaled in action_runs.
	Skipped bool `json:"skipped,omitempty"`
}

// runRebuild executes the rebuild phase for opID at dest: approval
// pre-pass, deterministic DAG order, per-attempt journaling, then the
// F36 protected-file verification. The caller has already advanced the
// operation to REBUILDING. resume skips actions with a journaled
// successful run (never auto-re-runs a succeeded action).
func (o *Opener) runRebuild(ctx context.Context, opID domain.OperationID, dest string, defs []actions.Definition, retained []domain.Entry, resume bool) ([]ActionReport, error) {
	if o.runner == nil {
		return nil, o.rebuildFailed(opID, nil, "rebuild requested but the actions runner seam is not wired", nil)
	}
	if o.approver == nil {
		return nil, o.rebuildFailed(opID, nil, "rebuild requested but no approval store is wired; approvals are mandatory (Foundation §7.3)", nil)
	}
	if err := actions.ValidateGraph(defs); err != nil {
		return nil, o.rebuildFailed(opID, nil, "action definitions invalid", err)
	}

	// Resume: never auto-re-run a succeeded action.
	var reports []ActionReport
	toRun := defs
	if resume {
		succeeded, err := o.cat.SucceededActions(opID)
		if err != nil {
			return nil, o.rebuildFailed(opID, nil, "reading the action_runs journal", err)
		}
		if len(succeeded) > 0 {
			toRun = make([]actions.Definition, 0, len(defs))
			for _, d := range defs {
				if succeeded[d.ID] {
					reports = append(reports, ActionReport{ID: d.ID, Status: ActionSkipped, Skipped: true})
					continue
				}
				toRun = append(toRun, d)
			}
		}
	}

	// Approval pre-pass: resolve tools and input digests, classify each
	// action against the recorded approvals, and hand every pending one
	// to the interactive seam (one grouped decision — §5.2).
	if len(toRun) > 0 {
		pending, err := o.approvalPrepass(opID, dest, toRun)
		if err != nil {
			return nil, err
		}
		if len(pending) > 0 {
			if o.approve == nil {
				return nil, o.rebuildFailed(opID, actionIDs(toRun),
					"approval required but no approval resolver is available (non-interactive mode)",
					pending[0].Cause)
			}
			if aerr := o.approve(ctx, pending); aerr != nil {
				return nil, o.rebuildFailed(opID, actionIDs(toRun), "approval declined or blocked", aerr)
			}
			// Re-check: the resolver must have recorded exact approvals.
			still, rerr := o.approvalPrepass(opID, dest, toRun)
			if rerr != nil {
				return nil, rerr
			}
			if len(still) > 0 {
				return nil, o.rebuildFailed(opID, actionIDs(toRun),
					"approval still not recorded after the approval step", still[0].Cause)
			}
		}
	}

	for _, def := range topoOrder(toRun) {
		if err := ctx.Err(); err != nil {
			return reports, o.rebuildFailed(opID, []string{def.ID}, "cancelled before action started", err)
		}
		rep, err := o.runOneAction(ctx, opID, dest, def)
		reports = append(reports, rep)
		if err != nil {
			return reports, err
		}
	}
	if err := ctx.Err(); err != nil {
		return reports, o.rebuildFailed(opID, actionIDs(toRun), "cancelled", err)
	}

	// F36 gate (mandatory): after all actions pass, re-verify every
	// retained entry that is NOT under a declared output.
	if err := o.verifyProtected(dest, retained, defs); err != nil {
		return reports, o.rebuildFailed(opID, actionIDs(defs), "protected preserved content changed", err)
	}
	return reports, nil
}

// runOneAction executes one definition with per-attempt journaling and
// the single approval retry the brief fixes: an ErrApprovalRequired /
// ErrApprovalStale surfacing at run time (a drift race between the
// pre-pass and exec) goes to the resolver once, then the retry's result
// is final.
func (o *Opener) runOneAction(ctx context.Context, opID domain.OperationID, dest string, def actions.Definition) (ActionReport, error) {
	runID, err := o.cat.StartActionRun(opID, def.ID)
	if err != nil {
		return ActionReport{}, o.rebuildFailed(opID, []string{def.ID}, "journaling the action run", err)
	}
	res, rerr := o.runner.Run(ctx, def, dest, o.approver, nil)

	if rerr != nil && isApprovalError(rerr) && o.approve != nil {
		// One retry through the seam, with the exact pending cause.
		tool, terr := actions.ResolveTool(def.Argv[0])
		if terr == nil {
			digests, derr := o.inputDigests(dest, def)
			if derr == nil {
				_ = o.approve(ctx, []PendingApproval{{Def: def, Tool: tool, InputDigests: digests, Cause: rerr}})
				res, rerr = o.runner.Run(ctx, def, dest, o.approver, nil)
			}
		}
	}

	switch {
	case rerr != nil && errors.Is(rerr, context.Canceled):
		_ = o.cat.FinishActionRun(runID, catalog.ActionRunCancelled, res.ExitCode, res.OutputExcerpt)
		return ActionReport{ID: def.ID, Status: ActionCancelled, ExitCode: res.ExitCode},
			o.rebuildFailed(opID, []string{def.ID}, "cancelled", rerr)
	case rerr != nil:
		_ = o.cat.FinishActionRun(runID, catalog.ActionRunFailed, res.ExitCode, res.OutputExcerpt)
		return ActionReport{ID: def.ID, Status: ActionFailed, ExitCode: res.ExitCode},
			o.rebuildFailed(opID, []string{def.ID}, "action failed", rerr)
	case res.ExitCode != 0:
		_ = o.cat.FinishActionRun(runID, catalog.ActionRunFailed, res.ExitCode, res.OutputExcerpt)
		return ActionReport{ID: def.ID, Status: ActionFailed, ExitCode: res.ExitCode},
			o.rebuildFailed(opID, []string{def.ID}, fmt.Sprintf("action exited %d", res.ExitCode), nil)
	}
	if err := o.cat.FinishActionRun(runID, catalog.ActionRunSucceeded, res.ExitCode, res.OutputExcerpt); err != nil {
		return ActionReport{ID: def.ID, Status: ActionSucceeded}, o.rebuildFailed(opID, []string{def.ID}, "journaling the action result", err)
	}
	return ActionReport{ID: def.ID, Status: ActionSucceeded, ExitCode: 0}, nil
}

// approvalPrepass resolves tools and input digests for every definition
// and classifies its recorded approval. Missing tools surface here as a
// precise requirement (F14): nothing runs when a pinned toolchain is
// unavailable.
func (o *Opener) approvalPrepass(opID domain.OperationID, dest string, defs []actions.Definition) ([]PendingApproval, error) {
	var pending []PendingApproval
	for _, def := range topoOrder(defs) {
		tool, terr := actions.ResolveTool(def.Argv[0])
		if terr != nil {
			return nil, o.rebuildFailed(opID, []string{def.ID}, fmt.Sprintf(
				"required tool %q is not resolvable on this host (F14): %v", def.Argv[0], terr), nil)
		}
		digests, derr := o.inputDigests(dest, def)
		if derr != nil {
			return nil, o.rebuildFailed(opID, []string{def.ID}, "declared action inputs are not available at the destination", derr)
		}
		if _, merr := o.approver.Matches(def, tool, digests); merr != nil {
			if isApprovalError(merr) {
				pending = append(pending, PendingApproval{Def: def, Tool: tool, InputDigests: digests, Cause: merr})
				continue
			}
			return nil, o.rebuildFailed(opID, []string{def.ID}, "reading the approval store", merr)
		}
	}
	return pending, nil
}

// inputDigests digests every declared input under dest, mapping the
// actions package's missing-input error through unchanged.
func (o *Opener) inputDigests(dest string, def actions.Definition) (map[string]string, error) {
	digests := make(map[string]string, len(def.Inputs))
	for _, rel := range def.Inputs {
		d, err := actions.DigestFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		digests[rel] = d
	}
	return digests, nil
}

// verifyProtected is the F36 gate: every retained inventory entry NOT
// under any action's declared Outputs must be byte-for-byte what the
// open published — same entry kind, same file digest, same link text
// (the same comparison discipline as the staged-tree oracle). Entries
// under declared outputs are expected to change and are not compared.
// On any difference the caller fails the rebuild; this function itself
// NEVER modifies or removes anything (the new files may be user work).
func (o *Opener) verifyProtected(dest string, retained []domain.Entry, defs []actions.Definition) error {
	var outputRoots []string
	for _, d := range defs {
		outputRoots = append(outputRoots, d.Outputs...)
	}
	underOutput := func(p string) bool {
		for _, out := range outputRoots {
			if p == out || strings.HasPrefix(p, out+"/") {
				return true
			}
		}
		return false
	}
	var changes []string
	for _, e := range retained {
		if underOutput(e.Path) {
			continue
		}
		abs := filepath.Join(dest, filepath.FromSlash(e.Path))
		facts, err := o.probe.ProbeFile(abs)
		switch {
		case err != nil:
			changes = append(changes, fmt.Sprintf("%s: %s (was retained %s): %v", e.Path, "missing or unprobeable", e.Kind, err))
			continue
		case facts.Kind != e.Kind:
			changes = append(changes, fmt.Sprintf("%s: kind %s, retained %s", e.Path, facts.Kind, e.Kind))
			continue
		}
		switch e.Kind {
		case domain.KindFile:
			got, derr := actions.DigestFile(abs)
			if derr != nil {
				changes = append(changes, fmt.Sprintf("%s: unreadable after rebuild: %v", e.Path, derr))
				continue
			}
			if got != e.Digest {
				changes = append(changes, fmt.Sprintf("%s: content digest %s, retained %s", e.Path, got, e.Digest))
			}
		case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
			if facts.LinkTarget != e.LinkTarget {
				changes = append(changes, fmt.Sprintf("%s: link text %q, retained %q", e.Path, facts.LinkTarget, e.LinkTarget))
			}
		}
	}
	if len(changes) > 0 {
		sort.Strings(changes)
		return &ErrProtectedChanged{Changes: changes}
	}
	return nil
}

// rebuildFailed lands the operation at REBUILD_FAILED (from REBUILDING),
// records the failure on the journal row and returns the typed error.
// The published files are never touched and the snapshot stays pinned
// (I07, I08): REBUILD_FAILED is non-terminal and resolvable by
// `ebb open --resume`.
func (o *Opener) rebuildFailed(opID domain.OperationID, ids []string, reason string, cause error) error {
	if opID != "" {
		msg := reason
		if cause != nil {
			msg = reason + ": " + cause.Error()
		}
		_ = o.cat.FailOperation(opID, catalog.PhaseRebuilding, msg)
		_ = o.cat.AdvanceOperation(opID, catalog.PhaseRebuilding, catalog.PhaseRebuildFailed)
	}
	return &ErrRebuildFailed{OperationID: opID, FailedActions: ids, Reason: reason, Err: cause}
}

// topoOrder returns the definitions in deterministic DAG order:
// dependencies before dependents, lexicographically smallest id first
// among the ready set (Kahn's algorithm). The graph itself was already
// validated acyclic by actions.ValidateGraph; a cycle here (impossible
// for validated input) surfaces as an error prefixed by the order step.
func topoOrder(defs []actions.Definition) []actions.Definition {
	byID := make(map[string]actions.Definition, len(defs))
	indegree := make(map[string]int, len(defs))
	dependents := make(map[string][]string, len(defs))
	for _, d := range defs {
		byID[d.ID] = d
		indegree[d.ID] = len(d.DependsOn)
		for _, dep := range d.DependsOn {
			dependents[dep] = append(dependents[dep], d.ID)
		}
	}
	var ready []string
	for _, d := range defs {
		if indegree[d.ID] == 0 {
			ready = append(ready, d.ID)
		}
	}
	sort.Strings(ready)
	var out []actions.Definition
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		out = append(out, byID[id])
		next := dependents[id]
		sort.Strings(next)
		for _, dep := range next {
			indegree[dep]--
			if indegree[dep] == 0 {
				ready = append(ready, dep)
				sort.Strings(ready)
			}
		}
	}
	return out
}

func actionIDs(defs []actions.Definition) []string {
	ids := make([]string, 0, len(defs))
	for _, d := range defs {
		ids = append(ids, d.ID)
	}
	return ids
}

func isApprovalError(err error) bool {
	var req *actions.ErrApprovalRequired
	var stale *actions.ErrApprovalStale
	return errors.As(err, &req) || errors.As(err, &stale)
}

// ---- resume + cancel ------------------------------------------------------

// resumePhases are the open-operation phases `ebb open --resume` accepts:
// REBUILD_FAILED (a failed rebuild), REBUILDING (a crash mid-rebuild)
// and FILES_READY (published, rebuild never started — same latent-bug
// class: the operation must not block the workspace forever).
var resumePhases = map[string]bool{
	catalog.PhaseRebuildFailed: true,
	catalog.PhaseRebuilding:    true,
	catalog.PhaseFilesReady:    true,
}

// ResumablePhase reports whether phase is one an open operation can be
// resumed (--resume) or explicitly canceled (--cancel) from.
func ResumablePhase(phase string) bool { return resumePhases[phase] }

// ResumeRebuild re-enters the rebuild phase of an interrupted open
// operation (Foundation §12.5 "ebb open --resume reruns only an
// explicitly retryable action after rechecking inputs and current
// outputs"): it re-validates the seal and payload documents exactly like
// Open, re-enters REBUILDING, re-runs ONLY actions without a recorded
// successful run in action_runs (never auto-re-runs a succeeded action),
// re-checks approvals per the same rules, and completes READY → DONE on
// success. Any failure lands back at REBUILD_FAILED.
func (o *Opener) ResumeRebuild(ctx context.Context, vault VaultRef, opID domain.OperationID) (Result, error) {
	res := Result{OperationID: opID}
	if err := checkContext(ctx); err != nil {
		return res, err
	}
	op, err := o.cat.GetOperation(opID)
	if err != nil {
		return res, fmt.Errorf("restore: resume: %w", err)
	}
	if op.Kind != catalog.OpKindOpen {
		return res, &ErrInvalidOptions{Detail: fmt.Sprintf("operation %s is kind %q, not an open", opID, op.Kind)}
	}
	if !resumePhases[op.Phase] {
		return res, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"operation %s is %s; --resume applies to an open in FILES_READY, REBUILDING or REBUILD_FAILED", opID, op.Phase)}
	}
	dest := op.SourceRoot
	fi, ferr := os.Stat(dest)
	if ferr != nil || !fi.IsDir() {
		return res, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"destination %s recorded for the operation is not a published directory: %v", dest, ferr)}
	}

	// Full document re-verification (same gates as Open): find the
	// snapshot row by the operation's recorded backend pair.
	snap, err := o.snapshotOfOperation(op)
	if err != nil {
		return res, err
	}
	res.SnapshotID = snap.ID
	res.WorkspaceID = snap.WorkspaceID
	receipt, err := o.loadSeal(ctx, vault, snap.ID, snap)
	if err != nil {
		return res, err
	}
	docs, err := o.loadDocuments(ctx, vault, snap.ID, snap, receipt)
	if err != nil {
		return res, err
	}
	defs, derr := rebuildDefinitions(docs.manifest)
	if derr != nil {
		return res, derr
	}

	// Re-enter REBUILDING (idempotent when already there).
	if op.Phase != catalog.PhaseRebuilding {
		if err := o.cat.AdvanceOperation(opID, op.Phase, catalog.PhaseRebuilding); err != nil {
			return res, fmt.Errorf("restore: resume: %s -> REBUILDING: %w", op.Phase, err)
		}
	}

	res.Destination = dest
	res.EntriesRestored = docs.entriesRestored
	res.BytesRestored = docs.preservedBytes
	res.RebuildHints = rebuildHints(docs.manifest)

	if len(defs) == 0 {
		// Nothing outstanding: complete the operation (D006 convention).
		if err := o.completeRebuild(opID); err != nil {
			return res, err
		}
		res.Phase = catalog.PhaseDone
		return res, nil
	}

	reports, rerr := o.runRebuild(ctx, opID, dest, defs, docs.retained, true)
	res.Actions = reports
	if rerr != nil {
		res.Phase = catalog.PhaseRebuildFailed
		return res, rerr
	}
	if err := o.completeRebuild(opID); err != nil {
		return res, err
	}
	res.Phase = catalog.PhaseDone
	return res, nil
}

// CancelRebuild explicitly cancels an open operation sitting at
// FILES_READY, REBUILDING or REBUILD_FAILED: the phase advances to
// CANCELED (terminal), unblocking the workspace for future operations.
// The published files stay exactly where they are and the snapshot stays
// pinned; cancelling is an act of record, never a filesystem change.
func (o *Opener) CancelRebuild(opID domain.OperationID) (catalog.Operation, error) {
	op, err := o.cat.GetOperation(opID)
	if err != nil {
		return op, fmt.Errorf("restore: cancel: %w", err)
	}
	if op.Kind != catalog.OpKindOpen {
		return op, &ErrInvalidOptions{Detail: fmt.Sprintf("operation %s is kind %q, not an open", opID, op.Kind)}
	}
	if !resumePhases[op.Phase] {
		return op, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"operation %s is %s; cancel applies to an open in FILES_READY, REBUILDING or REBUILD_FAILED", opID, op.Phase)}
	}
	if err := o.cat.AdvanceOperation(opID, op.Phase, catalog.PhaseCanceled); err != nil {
		return op, fmt.Errorf("restore: cancel %s: %w", opID, err)
	}
	return op, nil
}

// snapshotOfOperation resolves the catalog snapshot row of an open
// operation through its recorded backend pair (never by name).
func (o *Opener) snapshotOfOperation(op catalog.Operation) (catalog.Snapshot, error) {
	if op.PayloadSnap == "" || op.SealSnap == "" {
		return catalog.Snapshot{}, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"operation %s records no payload/seal backend pair; its snapshot cannot be resolved", op.ID)}
	}
	snaps, err := o.cat.ListSnapshots(op.WorkspaceID)
	if err != nil {
		return catalog.Snapshot{}, fmt.Errorf("restore: resume: list snapshots: %w", err)
	}
	for i := range snaps {
		if snaps[i].PayloadBackendID == op.PayloadSnap && snaps[i].SealBackendID == op.SealSnap {
			return snaps[i], nil
		}
	}
	return catalog.Snapshot{}, &ErrInvalidOptions{Detail: fmt.Sprintf(
		"no snapshot row records the backend pair (%s, %s) of operation %s", op.PayloadSnap, op.SealSnap, op.ID)}
}

// completeRebuild walks READY → DONE (the D006 convention: DONE means no
// reconciliation outstanding; the workspace row already carries live
// status).
func (o *Opener) completeRebuild(opID domain.OperationID) error {
	if err := o.cat.AdvanceOperation(opID, catalog.PhaseRebuilding, catalog.PhaseReady); err != nil {
		return fmt.Errorf("restore: advance %s: REBUILDING -> READY: %w", opID, err)
	}
	if err := o.cat.AdvanceOperation(opID, catalog.PhaseReady, catalog.PhaseDone); err != nil {
		return fmt.Errorf("restore: advance %s: READY -> DONE: %w", opID, err)
	}
	return nil
}
