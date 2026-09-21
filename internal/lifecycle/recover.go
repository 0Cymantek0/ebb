package lifecycle

// Crash recovery (Foundation §12.4). Recover reconciles an interrupted
// operation from DURABLE EVIDENCE ONLY — the catalog journal row, the
// backend snapshots it references, the retained op-dir documents inside P
// and the on-disk progress journal. It must work on a fresh Coordinator
// in a new process: nothing is carried in memory.
//
// Evidence rules:
//
//   - retained documents are re-parsed STRICTLY (decodeStrictJSON:
//     DisallowUnknownFields + trailing-data check);
//   - identity comparisons use native root identities recorded in the
//     journal, never path-name guesses (I13);
//   - every removal is re-authorized per entry by the removalPermit's
//     own re-digest, so resuming an interrupted authorized walk is
//     idempotent (already-removed entries skip).
//
// The §12.4 table row decides the behavior per phase; Recover performs
// only the SAFE reconciliation and never auto-continues from SEALED into
// removal ("do not assume deletion remains authorized").

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// RecoveryReport is the outcome of one reconciliation: what the operation
// was, what Recover did, what remains and what the user should do next.
type RecoveryReport struct {
	OperationID domain.OperationID
	WorkspaceID domain.WorkspaceID
	Kind        string
	PhaseBefore string
	PhaseAfter  string
	// Actions describes what Recover did, in order.
	Actions []string
	// Remaining describes what is left to reconcile (entries, blockers,
	// retained-but-unsealed payloads...).
	Remaining []string
	// LastRemovedPath/LastRemovedCount come from the progress journal
	// (lastRemoved); "" / 0 when no removal ever ran.
	LastRemovedPath  string
	LastRemovedCount int
	// NextAction is the user-facing next step (never performed
	// implicitly by Recover itself).
	NextAction string
	Warnings   []string
}

// Recover diagnoses the operation's current phase and performs the safe
// reconciliation per the §12.4 table. Terminal phases report only.
func (c *Coordinator) Recover(ctx context.Context, vault VaultRef, opID domain.OperationID) (RecoveryReport, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryReport{}, err
	}
	op, err := c.cat.GetOperation(opID)
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("lifecycle: recover: %w", err)
	}
	rep := RecoveryReport{
		OperationID: op.ID, WorkspaceID: op.WorkspaceID,
		Kind: op.Kind, PhaseBefore: op.Phase,
	}
	rep.PhaseAfter = op.Phase // a report-only outcome keeps the phase
	parent := filepath.Dir(filepath.Clean(op.SourceRoot))
	rep.LastRemovedPath, rep.LastRemovedCount = lastRemoved(readJournalOrWarn(parent, opID, &rep))

	switch op.Phase {
	case catalog.PhasePlanned, catalog.PhaseCapturing:
		// Source untouched by Ebb removal: cancel.
		return c.recoverCancelCapture(ctx, vault, op, rep)

	case catalog.PhasePayloadCommitted:
		return c.recoverPayloadCommitted(ctx, vault, op, rep)

	case catalog.PhaseSealed:
		return c.recoverSealed(ctx, vault, op, rep)

	case catalog.PhaseQuarantined, catalog.PhaseRemoving:
		return c.resumeParkRemoval(ctx, vault, op, rep)

	case catalog.PhaseRemovalBlocked:
		// Writer-condition discipline (Wave F review F7): plain Recover
		// is REPORT-ONLY for a blocked removal walk — resuming re-opens
		// the §12.3 digest->remove race window, so it belongs to the
		// explicit verb (ResumeRemoval / --resume-removal).
		return c.reportRemovalBlocked(op, rep)

	case catalog.PhaseParked:
		// Nonterminal legacy rows (pre-PARKED→DONE completions): the
		// root is gone and the workspace is parked; finish idempotently.
		return c.recoverParked(op, rep)

	case catalog.PhaseTrimPlanned:
		return c.recoverCancelCapture(ctx, vault, op, rep)

	case catalog.PhaseTrimSealing:
		return c.resumeTrimRemoval(ctx, vault, op, rep)

	case catalog.PhaseExportPlanned, catalog.PhaseExportCopying, catalog.PhaseExportVerifying,
		catalog.PhaseImportPlanned, catalog.PhaseImportCopying, catalog.PhaseImportVerifying:
		// The capsule transports (Wave H/I export/import; Wave J review
		// J1): plain Recover stays REPORT-ONLY — consistent with the
		// non-removal semantics every other externally-owned kind gets —
		// and names the verb that closes the operation.
		return c.reportCapsuleTransport(op, rep)

	case catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed:
		// A dead restore (Wave 1 restore review F3): RESTORE_RUNNING is a
		// crash leftover and RESTORE_FAILED a failed execution; both are
		// deliberately NON-terminal because rerunning `ebb restore` IS the
		// resume. Plain Recover stays REPORT-ONLY — the resume belongs to
		// the restore command — and names both exits (rerun, or cancel the
		// dead row so the workspace accepts destructive work again).
		return c.reportDeadRestore(op, rep)

	default:
		// Terminal (CANCELED/DONE/TRIM_DONE/RESTORE_DONE) or phases owned
		// by other commands (RESTORING/FILES_READY/REBUILDING/READY/
		// REBUILD_FAILED/RESTORE_PLANNED): nothing lifecycle-side to
		// reconcile.
		rep.Actions = append(rep.Actions, "phase is terminal or owned by another command; nothing reconciled")
		if op.LastError != "" {
			rep.Remaining = append(rep.Remaining, "last recorded failure: "+op.LastError)
		}
		rep.NextAction = "no lifecycle action required"
		return rep, nil
	}
}

// ResumeRemoval is the explicit verb for REMOVAL_BLOCKED / REMOVING /
// QUARANTINED park operations (and a TRIM_SEALING trim mid-removal),
// used after the user resolved the blocker (closed handles, freed
// space...). It performs the same evidence-verified resume Recover does,
// but refuses phases that are not mid-removal.
//
// One SEALED entry (Wave 4 gauntlet bug B): a park whose destructive
// tail was attempted and blocked BEFORE the quarantine rename succeeded
// also sits in SEALED — the rename never ran, so no later phase was
// ever committed — yet its park-time error advises --resume-removal
// (the generic ErrRemovalBlocked safe action). resumeSealedParkRemoval
// accepts that state, gated by the durable record (last_error proves a
// tail attempt) and re-running the FULL tail, whose step-6 revalidation
// is exactly the §12.4 SEALED rule ("Revalidate; do not assume deletion
// remains authorized").
func (c *Coordinator) ResumeRemoval(ctx context.Context, vault VaultRef, opID domain.OperationID) (RecoveryReport, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryReport{}, err
	}
	op, err := c.cat.GetOperation(opID)
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("lifecycle: resume removal: %w", err)
	}
	rep := RecoveryReport{
		OperationID: op.ID, WorkspaceID: op.WorkspaceID,
		Kind: op.Kind, PhaseBefore: op.Phase,
	}
	parent := filepath.Dir(filepath.Clean(op.SourceRoot))
	rep.LastRemovedPath, rep.LastRemovedCount = lastRemoved(readJournalOrWarn(parent, opID, &rep))

	switch op.Phase {
	case catalog.PhaseQuarantined, catalog.PhaseRemoving, catalog.PhaseRemovalBlocked:
		return c.resumeParkRemoval(ctx, vault, op, rep)
	case catalog.PhaseSealed:
		return c.resumeSealedParkRemoval(ctx, vault, op, rep)
	case catalog.PhaseTrimSealing:
		return c.resumeTrimRemoval(ctx, vault, op, rep)
	default:
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s is %s; ResumeRemoval applies to QUARANTINED/REMOVING/REMOVAL_BLOCKED (park), a SEALED park whose removal tail was attempted and blocked, or TRIM_SEALING (trim)", opID, op.Phase)}
	}
}

// CancelOperation is the explicit verb for abandoning an interrupted
// operation WITHOUT performing its remaining reconciliation (Wave F
// review F5: without it, a SEALED operation whose root is intact and
// present permanently blocks its workspace — Recover is report-only
// there by design, and a rerun hits the single-active-operation lock).
// It applies only to phases where Ebb removal never started (PLANNED,
// CAPTURING, PAYLOAD_COMMITTED, SEALED, TRIM_PLANNED); a mid-removal
// operation (QUARANTINED/REMOVING/REMOVAL_BLOCKED/TRIM_SEALING) must be
// reconciled (Recover/ResumeRemoval), never abandoned mid-walk. A SEALED
// operation whose deterministic quarantine sibling exists (the §12.2
// step-7 rename crash window, ANY identity — G4) is likewise refused:
// only Recover may reconcile that state.
//
// The capsule transports (Wave H/I export/import; Wave J review J1) add
// their own closable set: EVERY non-terminal EXPORT_*/IMPORT_* phase.
// The transports own NO removal authority — nothing in the source
// workspace or vault is ever removed by them — so cancel-after-crash is
// always safe: the op closes idempotently to CANCELED, the export's
// duration pins (pin:export:<opID>) are released audit-only (the
// snapshot keeps every original pin; deliberate release stays forget's
// job, I07), and any backend snapshots the interrupted transport had
// already created are NAMED in the report from durable state, never
// deleted (the export's copies live only inside the identifiable
// .partial capsule file; an import's unregistered copies are not
// journaled and are reported as unnameable rather than guessed).
//
// Dead restore operations (Wave 1 restore review F3) close the same way:
// RESTORE_RUNNING (a crash leftover) and RESTORE_FAILED are deliberately
// non-terminal because a rerun IS the resume — but a restore that can
// never complete must not brick the workspace against every later
// destructive operation. A restore owns NO removal authority (the
// recipes only re-create what a trim already removed; the protected-file
// gate watches everything they touch), so cancel-after-crash is always
// safe by the same argument as the Wave J capsule transports: the op
// closes idempotently to CANCELED, whatever the interrupted recipes
// produced stays in place (never undone — it may be wanted work), and
// the replayed trim's retained snapshots stay pinned (I07).
// RESTORE_DONE is terminal-uncancelable like every DONE phase.
//
// Cancel never releases recovery obligations (I07): a sealed P/S pair
// stays pinned — deliberate release is `ebb forget`, never cancel.
func (c *Coordinator) CancelOperation(ctx context.Context, vault VaultRef, opID domain.OperationID) (RecoveryReport, error) {
	if err := ctx.Err(); err != nil {
		return RecoveryReport{}, err
	}
	op, err := c.cat.GetOperation(opID)
	if err != nil {
		return RecoveryReport{}, fmt.Errorf("lifecycle: cancel: %w", err)
	}
	rep := RecoveryReport{
		OperationID: op.ID, WorkspaceID: op.WorkspaceID,
		Kind: op.Kind, PhaseBefore: op.Phase,
	}
	rep.PhaseAfter = op.Phase
	switch {
	case capsuleTransportPhase(op.Kind, op.Phase) || (capsuleTransportKind(op.Kind) && op.Phase == catalog.PhaseCanceled):
		// The already-CANCELED arm keeps the close idempotent (rerunning
		// --cancel after a crash mid-close must not refuse).
		return c.cancelCapsuleTransport(op, rep)
	case op.Kind == catalog.OpKindRestore && deadRestorePhase(op.Phase):
		// The already-CANCELED arm keeps the close idempotent (same
		// crash-mid-close shape as the capsule transports).
		return c.cancelRestore(op, rep)
	case op.Phase == catalog.PhasePlanned || op.Phase == catalog.PhaseCapturing ||
		op.Phase == catalog.PhasePayloadCommitted || op.Phase == catalog.PhaseTrimPlanned:
		// Pre-seal territory: the existing cancel path (records any
		// recorded payload as an unsealed, pinned snapshot per §11.3).
		return c.recoverCancelCapture(ctx, vault, op, rep)
	case op.Phase == catalog.PhaseSealed:
		return c.cancelSealed(op, rep)
	default:
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s is %s; cancel applies to phases before removal starts (PLANNED/CAPTURING/PAYLOAD_COMMITTED/SEALED/TRIM_PLANNED), to the capsule transports' EXPORT_*/IMPORT_* phases, or to a dead restore (RESTORE_RUNNING/RESTORE_FAILED) — mid-removal phases require reconciliation (Recover/ResumeRemoval)", opID, op.Phase)}
	}
}

// deadRestorePhase reports whether phase belongs to the restore kind's
// cancel-after-crash set: the two non-terminal dead states plus CANCELED
// (idempotent rerun). RESTORE_DONE is terminal and unclosable;
// RESTORE_PLANNING belongs to a live planning pass, not a dead row.
func deadRestorePhase(phase string) bool {
	switch phase {
	case catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed, catalog.PhaseCanceled:
		return true
	}
	return false
}

// capsuleTransportPhase reports whether phase belongs to the given
// capsule-transport kind's non-terminal phase set (EXPORT_* for export,
// IMPORT_* for import).
func capsuleTransportPhase(kind, phase string) bool {
	switch kind {
	case catalog.OpKindExport:
		switch phase {
		case catalog.PhaseExportPlanned, catalog.PhaseExportCopying, catalog.PhaseExportVerifying:
			return true
		}
	case catalog.OpKindImport:
		switch phase {
		case catalog.PhaseImportPlanned, catalog.PhaseImportCopying, catalog.PhaseImportVerifying:
			return true
		}
	}
	return false
}

// capsuleTransportKind reports whether kind is one of the two capsule
// transports (export/import).
func capsuleTransportKind(kind string) bool {
	return kind == catalog.OpKindExport || kind == catalog.OpKindImport
}

// exportPinReasons are the pin-audit reason spellings an export op takes
// and releases (cmdExport's duration pin, Foundation §15.2).
const (
	exportPinPrefix  = "export:"
	exportPinTaken   = "pin:" + exportPinPrefix
	exportPinRelease = "unpin:" + exportPinPrefix
)

// reportCapsuleTransport is plain Recover's report-only outcome for a
// crashed export/import operation: the state is described and --cancel
// is named as the closing verb, but nothing is reconciled (the same
// discipline Recover applies to every kind whose phases another command
// owns).
func (c *Coordinator) reportCapsuleTransport(op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if want := capsuleTransportKindForPhase(op.Phase); want != "" && op.Kind != want {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s is kind %q but its phase %s belongs to the %s vocabulary; durable state diverged — inspect manually", op.ID, op.Kind, op.Phase, want)}
	}
	rep.Actions = append(rep.Actions, fmt.Sprintf(
		"reported the interrupted %s operation in %s (report-only: the capsule transport owns no removal authority, so the workspace, the source vault and every snapshot are untouched)", op.Kind, op.Phase))
	if op.LastError != "" {
		rep.Remaining = append(rep.Remaining, "last recorded failure: "+op.LastError)
	}
	rep.Remaining = append(rep.Remaining, capsuleTransportLeftovers(op)...)
	rep.NextAction = fmt.Sprintf(
		"this operation blocks the workspace and gc until closed — close it with `ebb recover %s --cancel` (always safe for a capsule transport: cancel removes nothing), then rerun the command if the transfer is still wanted", op.ID)
	return rep, nil
}

// capsuleTransportKindForPhase names the operation kind a capsule phase
// belongs to ("" for non-capsule phases).
func capsuleTransportKindForPhase(phase string) string {
	switch phase {
	case catalog.PhaseExportPlanned, catalog.PhaseExportCopying, catalog.PhaseExportVerifying:
		return catalog.OpKindExport
	case catalog.PhaseImportPlanned, catalog.PhaseImportCopying, catalog.PhaseImportVerifying:
		return catalog.OpKindImport
	}
	return ""
}

// capsuleTransportLeftovers describes, from durable state only, what a
// crashed transport may have left behind. It never guesses ids and it
// never deletes anything.
func capsuleTransportLeftovers(op catalog.Operation) []string {
	if op.Kind == catalog.OpKindExport {
		// The transport's backend snapshots live INSIDE the capsule's
		// partial file — the source vault is never written by an export.
		return []string{
			"a partial capsule file (<output>.partial) may exist at the intended output path; it was not removed and a rerun of the export refuses until it is removed explicitly",
			"the export duration pin (pin:export:" + string(op.ID) + ") may still be taken on the exported snapshot",
		}
	}
	// Import: the CLI records the copied destination ids on the op row
	// once the transport completes, so a crash between the copy and the
	// registration can name them; without that record they are journaled
	// nowhere and are reported as unnameable rather than guessed.
	var created []string
	if op.PayloadSnap != "" {
		created = append(created, op.PayloadSnap)
	}
	if op.SealSnap != "" {
		created = append(created, op.SealSnap)
	}
	if len(created) > 0 {
		return []string{fmt.Sprintf(
			"backend snapshot(s) %s were copied into the destination vault before the interruption (durable op-row record) and were NOT removed — no catalog row references them; inspect and resolve them explicitly (a completed rerun re-copies and a registration-failure rerun starts clean)",
			strings.Join(created, ", "))}
	}
	return []string{
		fmt.Sprintf("backend snapshots the interrupted copy created in the destination vault (if the crash struck mid-copy) are recorded NOWHERE in the catalog — they are not nameable from durable state and were not removed; a completed rerun copies fresh and any orphans need explicit external cleanup (capsule: %s)", op.SourceRoot),
	}
}

// cancelCapsuleTransport closes a crashed export/import operation:
// idempotently to CANCELED, releasing the export's duration pins
// audit-only and reporting (never deleting) whatever the transport left
// behind. It performs no backend calls and no removals.
func (c *Coordinator) cancelCapsuleTransport(op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if op.Phase == catalog.PhaseCanceled {
		// Idempotent rerun (a crash between the CAS commit and the
		// report): nothing left to do.
		rep.Actions = append(rep.Actions, "the operation is already CANCELED; nothing to close")
		rep.NextAction = "the workspace accepts new operations"
		return rep, nil
	}
	if want := capsuleTransportKindForPhase(op.Phase); want != "" && op.Kind != want {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s is kind %q but its phase %s belongs to the %s vocabulary; durable state diverged — inspect manually", op.ID, op.Kind, op.Phase, want)}
	}

	// The export's duration pin, taken before the transport started, is
	// the only obligation this operation added. Release it AUDIT-ONLY
	// (RecordPinRelease): the pinned flag keeps whatever the snapshot's
	// original reasons say — cancel errs toward retention (I07) and
	// never becomes a forget. The durable record of WHICH snapshot was
	// pinned is the pin audit itself.
	if op.Kind == catalog.OpKindExport {
		snaps, serr := c.cat.ListSnapshots(op.WorkspaceID)
		if serr != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"listing the workspace's snapshots to release the export pin: %v (the audit-only release could not run; `ebb status` shows the pin)", serr))
		}
		for _, s := range snaps {
			taken, released := false, false
			for _, r := range s.PinReasons {
				if r == exportPinTaken+string(op.ID) {
					taken = true
				}
				if r == exportPinRelease+string(op.ID) {
					released = true
				}
			}
			if !taken || released {
				continue
			}
			if rerr := c.cat.RecordPinRelease(s.ID, exportPinPrefix+string(op.ID)); rerr != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf(
					"releasing the export pin on snapshot %s failed: %v (the snapshot stays pinned — conservative; `ebb status` shows the pin)", s.ID, rerr))
			} else {
				rep.Actions = append(rep.Actions, fmt.Sprintf(
					"released the export duration pin on snapshot %s (audit-only: the snapshot keeps its original pins; deliberate release remains `ebb forget`)", s.ID))
			}
		}
	}

	if err := c.cat.FailOperation(op.ID, op.Phase, "canceled by user request while "+op.Phase+" (capsule transport; no removal authority)"); err != nil {
		// Best effort: the phase advance below is the authority.
		_ = err
	}
	if aerr := c.cat.AdvanceOperation(op.ID, op.Phase, catalog.PhaseCanceled); aerr != nil {
		return rep, fmt.Errorf("lifecycle: cancel %s: %w", op.ID, aerr)
	}
	rep.PhaseAfter = catalog.PhaseCanceled
	rep.Actions = append(rep.Actions, fmt.Sprintf(
		"canceled the interrupted %s operation in %s (the capsule transport owns no removal authority: nothing in the source workspace or any vault was removed)", op.Kind, op.Phase))
	rep.Remaining = append(rep.Remaining, capsuleTransportLeftovers(op)...)
	rep.NextAction = "operation canceled; the workspace accepts new operations (rerun the export/import if the capsule transfer is still wanted)"
	return rep, nil
}

// reportDeadRestore is plain Recover's report-only outcome for a dead
// restore operation (RESTORE_RUNNING crash leftover or RESTORE_FAILED):
// the state is described and BOTH exits are named — the rerun that
// resumes it, and --cancel for the row that can never complete — but
// nothing is reconciled (the resume belongs to the restore command, the
// same discipline Recover applies to every kind whose phases another
// command owns).
func (c *Coordinator) reportDeadRestore(op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if op.Kind != catalog.OpKindRestore {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s is kind %q but its phase %s belongs to the restore vocabulary; durable state diverged — inspect manually", op.ID, op.Kind, op.Phase)}
	}
	rep.Actions = append(rep.Actions, fmt.Sprintf(
		"reported the dead %s operation in %s (report-only: a restore owns no removal authority, so the workspace and every retained snapshot are untouched)", op.Kind, op.Phase))
	if op.LastError != "" {
		rep.Remaining = append(rep.Remaining, "last recorded failure: "+op.LastError)
	}
	rep.Remaining = append(rep.Remaining,
		"whatever the interrupted recipes produced stays in place (never undone — it may be wanted work)",
		"the replayed trim's retained snapshots stay pinned (I07)")
	rep.NextAction = fmt.Sprintf(
		"rerun `ebb restore` to resume this operation (package managers tolerate partial output directories), or close it with `ebb recover %s --cancel` (always safe for a restore: cancel removes nothing) when no rerun can complete — until then the workspace refuses destructive operations", op.ID)
	return rep, nil
}

// cancelRestore closes a dead restore operation (RESTORE_RUNNING crash
// leftover or RESTORE_FAILED): idempotently to CANCELED. A restore owns
// NO removal authority — the recipes only re-create what a trim already
// removed, and the protected-file gate watches everything they touch —
// so cancel-after-crash is always safe (the Wave J capsule-transport
// argument): whatever the interrupted recipes produced stays in place
// (never undone), the replayed trim's retained snapshots stay pinned
// (I07 — deliberate release is `ebb forget`), and rerunning `ebb
// restore` remains available for a fresh attempt. It performs no
// backend calls and no removals.
func (c *Coordinator) cancelRestore(op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if op.Phase == catalog.PhaseCanceled {
		// Idempotent rerun (a crash between the CAS commit and the
		// report): nothing left to do.
		rep.Actions = append(rep.Actions, "the operation is already CANCELED; nothing to close")
		rep.NextAction = "the workspace accepts new operations"
		return rep, nil
	}
	if err := c.cat.FailOperation(op.ID, op.Phase, "canceled by user request while "+op.Phase+" (restore; no removal authority)"); err != nil {
		// Best effort: the phase advance below is the authority.
		_ = err
	}
	if aerr := c.cat.AdvanceOperation(op.ID, op.Phase, catalog.PhaseCanceled); aerr != nil {
		return rep, fmt.Errorf("lifecycle: cancel %s: %w", op.ID, aerr)
	}
	rep.PhaseAfter = catalog.PhaseCanceled
	rep.Actions = append(rep.Actions, fmt.Sprintf(
		"canceled the dead %s operation in %s (a restore owns no removal authority: whatever the recipes produced stays in place, nothing was undone)", op.Kind, op.Phase))
	rep.Remaining = append(rep.Remaining,
		"whatever the interrupted recipes produced stays in place (inspect the workspace; rerun `ebb restore` for a fresh attempt if the outputs are still wanted)",
		"the replayed trim's retained snapshots stay pinned (I07 — deliberate release is `ebb forget`, never cancel)")
	rep.NextAction = "operation canceled; the workspace accepts new operations (rerun `ebb restore` if the recreation is still wanted)"
	return rep, nil
}

// cancelSealed abandons a SEALED operation with its live root intact:
// the retained P/S pair was already committed to the catalog at seal
// time and stays pinned untouched (no second, unsealed row is recorded
// for it); the Ebb-owned local scratch (op/seal dirs, journal) is
// cleaned because its content lives in the retained snapshots.
//
// G4 (Wave G review): the deterministic quarantine sibling is probed
// FIRST, with the same construction recoverSealed uses. If it EXISTS —
// regardless of identity, and it is never touched — the operation is in
// (or past) the §12.2 step-7 rename crash window and canceling would
// strand the user's entire tree at an opaque path with no durable
// pointer while deleting the very scratch that names it. Refuse with
// *ErrCancelRefused; `ebb recover <op>` is the reconciliation path (it
// adopts-or-reports by native identity). Only when no sibling exists
// may the cancel proceed — and the report then claims "live root
// intact" only when the root is actually present.
func (c *Coordinator) cancelSealed(op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	parent := filepath.Dir(filepath.Clean(op.SourceRoot))
	quar := quarantinePath(parent, op.ID)
	if _, qerr := os.Lstat(quar); qerr == nil {
		return rep, &ErrCancelRefused{OperationID: op.ID, Quarantine: quar}
	} else if !os.IsNotExist(qerr) {
		return rep, fmt.Errorf("lifecycle: cancel %s: probe quarantine sibling %s: %w", op.ID, quar, qerr)
	}

	if err := c.cat.AdvanceOperation(op.ID, catalog.PhaseSealed, catalog.PhaseCanceled); err != nil {
		return rep, fmt.Errorf("lifecycle: cancel %s: %w", op.ID, err)
	}
	rep.PhaseAfter = catalog.PhaseCanceled
	if _, rerr := os.Lstat(op.SourceRoot); rerr == nil {
		rep.Actions = append(rep.Actions, "canceled the sealed operation (live root intact; removal never started)")
	} else if os.IsNotExist(rerr) {
		// Honest report (the G4 blind spot): no quarantine sibling, no
		// live root — the tree left this operation's tracked location by
		// some other route and cancel must not claim otherwise.
		rep.Actions = append(rep.Actions, fmt.Sprintf(
			"canceled the sealed operation; the live root %s is ABSENT and no quarantine sibling exists — its content is no longer at the location this operation tracked (the retained P/S pair is the recovery copy)", op.SourceRoot))
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"live root %s not found at cancel time; nothing was renamed to the quarantine path by this operation", op.SourceRoot))
	} else {
		rep.Actions = append(rep.Actions, "canceled the sealed operation (removal never started; root presence could not be verified)")
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"live root %s could not be probed (%v); its presence was not verified", op.SourceRoot, rerr))
	}
	rep.Actions = append(rep.Actions, "retained P/S pair stays pinned (I07 — deliberate release is `ebb forget`, never cancel)")
	rep.Remaining = append(rep.Remaining, fmt.Sprintf(
		"sealed pair (payload %s) remains retained and pinned; end it deliberately with ebb forget when no longer needed", op.PayloadSnap))
	if err := removeEbbOwned(filepath.Join(parent, opDirName(op.ID))); err != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("cleanup op dir failed: %v", err))
	}
	if err := removeEbbOwned(filepath.Join(parent, sealDirName(op.ID))); err != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("cleanup seal dir failed: %v", err))
	}
	_ = removeEbbOwned(journalPath(parent, op.ID))
	rep.NextAction = "operation canceled; the workspace accepts new operations (rerun the original command for a fresh capture)"
	return rep, nil
}

// ---- shared evidence loaders -----------------------------------------

// recoveredEvidence is the durable evidence rebuilt from P's own retained
// op-dir copy. Every document is dumped from the payload snapshot and
// re-parsed strictly; digests are recomputed over the dumped bytes.
type recoveredEvidence struct {
	manifest  manifestDoc
	entries   []domain.Entry // parsed inventory.jsonl records
	wsPrefix  string         // manifest bijection, never a basename guess
	opDirName string

	manifestBytes   []byte
	inventoryBytes  []byte
	policyBytes     []byte
	manifestDigest  string
	inventoryDigest string
}

// loadPayloadEvidence rebuilds the capture evidence from P: manifest,
// inventory entries, frozen-policy bytes and the digests binding them.
// It re-verifies NOTHING yet — callers run coverage/readback on top.
func (c *Coordinator) loadPayloadEvidence(ctx context.Context, vault VaultRef, op catalog.Operation) (recoveredEvidence, error) {
	var ev recoveredEvidence
	if op.PayloadSnap == "" {
		return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s (%s) references no payload snapshot", op.ID, op.Phase)}
	}
	// Bind P to this operation through the backend tags (the catalog is
	// not the sole recovery authority; the tag names the op, and the
	// manifest below re-binds workspace and documents).
	refs, err := c.store.List(ctx, vault.RepoDir, vault.Passfile)
	if err != nil {
		return ev, fmt.Errorf("lifecycle: list vault: %w", err)
	}
	bound := false
	for _, r := range refs {
		if r.BackendID == op.PayloadSnap {
			bound = r.Tags["ebb-op"] == string(op.ID)
			break
		}
	}
	if !bound {
		return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"payload snapshot %s is not tagged for operation %s (wrong vault?)", op.PayloadSnap, op.ID)}
	}

	prefix := "/" + opDirName(op.ID)
	mb, err := c.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, op.PayloadSnap, prefix+"/"+manifestName)
	if err != nil {
		return ev, fmt.Errorf("lifecycle: dump %s%s: %w", prefix, manifestName, err)
	}
	if err := decodeStrictJSON(mb, &ev.manifest); err != nil {
		return ev, err
	}
	if ev.manifest.SchemaVersion != schemaVersionCurrent {
		return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"payload manifest schema_version %d != %d", ev.manifest.SchemaVersion, schemaVersionCurrent)}
	}
	if ev.manifest.WorkspaceID != string(op.WorkspaceID) {
		return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"payload manifest workspace %s != journal workspace %s", ev.manifest.WorkspaceID, op.WorkspaceID)}
	}
	for _, r := range ev.manifest.Roots {
		switch r.ID {
		case string(domain.RootMain):
			ev.wsPrefix = r.BackendPrefix
		case string(domain.RootMeta):
			ev.opDirName = r.BackendPrefix
		}
	}
	if ev.wsPrefix == "" || ev.opDirName != opDirName(op.ID) {
		return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"payload manifest root bijection (main=%q meta=%q) does not match operation %s", ev.wsPrefix, ev.opDirName, op.ID)}
	}
	ev.manifestDigest = digestBytes(mb)
	ev.manifestBytes = mb

	invBytes, err := c.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, op.PayloadSnap, prefix+"/"+ev.manifest.Inventory.Path)
	if err != nil {
		return ev, fmt.Errorf("lifecycle: dump %s/%s: %w", prefix, ev.manifest.Inventory.Path, err)
	}
	if d := digestBytes(invBytes); d != ev.manifest.Inventory.Digest {
		return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"retained %s digest %s differs from the manifest-recorded digest %s", ev.manifest.Inventory.Path, d, ev.manifest.Inventory.Digest)}
	}
	// The accounting document is inventory.jsonl for park/snapshot
	// captures and the removal manifest for trims (buildManifest points
	// Inventory.Path at whichever document the capture sealed).
	var entries []domain.Entry
	if ev.manifest.Inventory.Path == removalManifestName {
		plan, perr := parseTrimPlan(invBytes)
		if perr != nil {
			return ev, perr
		}
		if perr := plan.bindsOperation(op); perr != nil {
			return ev, perr
		}
		for _, g := range plan.Groups {
			for _, m := range g.Members {
				// Security (Wave F review F1): trim-plan members are
				// retained-document input on the resume path — same
				// validation rule as inventory lines.
				if verr := m.Entry.Validate(); verr != nil {
					return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
						"retained trim plan group %s member %q fails entry validation (tampered payload?): %v", g.GroupID, m.Path, verr)}
				}
				entries = append(entries, m.Entry)
			}
		}
	} else {
		entries, err = parseInventoryLines(invBytes)
		if err != nil {
			return ev, err
		}
	}
	if int64(len(entries)) != ev.manifest.Inventory.Count {
		return ev, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"retained %s has %d records; manifest declares %d", ev.manifest.Inventory.Path, len(entries), ev.manifest.Inventory.Count)}
	}
	ev.entries = entries
	ev.inventoryDigest = digestBytes(invBytes)

	// Security (Wave F review F1): the catalog's seal-time snapshot row
	// is an INDEPENDENT record of what was sealed. P-internal
	// self-consistency alone let a tampered payload steer recovery;
	// the retained digests are cross-checked against the row.
	if cerr := c.crossCheckSealDigests(op, ev.manifestDigest, ev.inventoryDigest); cerr != nil {
		return ev, cerr
	}
	ev.inventoryBytes = invBytes

	// The frozen policy inside P must equal the policy text the manifest
	// froze (self-consistency of the two retained copies).
	polBytes, err := c.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, op.PayloadSnap, prefix+"/"+policyFrozenName)
	if err != nil {
		return ev, fmt.Errorf("lifecycle: dump %s%s: %w", prefix, policyFrozenName, err)
	}
	if digestBytes(polBytes) != ev.manifest.Policy.FrozenDigest || string(polBytes) != ev.manifest.Policy.Frozen {
		return ev, &ErrJournalMismatch{Detail: "retained policy.toml differs from the manifest's frozen policy"}
	}
	ev.policyBytes = polBytes
	return ev, nil
}

// sealedPhases are the phases at or after the seal commit: the catalog
// snapshot row MUST exist for them, so its seal-time digests are a hard
// requirement rather than a cross-check-of-opportunity.
var sealedPhases = map[string]bool{
	catalog.PhaseSealed:         true,
	catalog.PhaseQuarantined:    true,
	catalog.PhaseRemoving:       true,
	catalog.PhaseRemovalBlocked: true,
	catalog.PhaseParked:         true,
	catalog.PhaseTrimSealing:    true,
}

// crossCheckSealDigests compares the digests of the retained documents
// just re-read from the vault against the snapshot row recorded at seal
// time (Wave F review F1 fix). The catalog row is the tamper-independent
// witness: an attacker who rewrites P's manifest+inventory to agree with
// each other cannot make them agree with this row without writing the
// catalog too.
func (c *Coordinator) crossCheckSealDigests(op catalog.Operation, manifestDigest, inventoryDigest string) error {
	snaps, err := c.cat.ListSnapshots(op.WorkspaceID)
	if err != nil {
		return fmt.Errorf("lifecycle: list snapshots for seal cross-check: %w", err)
	}
	var match *catalog.Snapshot
	for i := range snaps {
		if snaps[i].PayloadBackendID == op.PayloadSnap {
			if match != nil {
				return &ErrJournalMismatch{Detail: fmt.Sprintf(
					"multiple snapshot rows reference payload %s; durable state diverged — inspect manually", op.PayloadSnap)}
			}
			match = &snaps[i]
		}
	}
	if match == nil {
		if sealedPhases[op.Phase] {
			return &ErrJournalMismatch{Detail: fmt.Sprintf(
				"operation %s is %s but no snapshot row records payload %s; refusing to trust retained documents alone", op.ID, op.Phase, op.PayloadSnap)}
		}
		// Pre-seal phases (PAYLOAD_COMMITTED and earlier) have no
		// snapshot row yet; P-internal consistency is the only
		// available evidence and remains the gate.
		return nil
	}
	if match.ManifestDigest != "" && match.ManifestDigest != manifestDigest {
		return &ErrJournalMismatch{Detail: fmt.Sprintf(
			"retained manifest digest %s differs from the seal-time catalog record %s — vault tampering suspected; refusing",
			manifestDigest, match.ManifestDigest)}
	}
	if match.InventoryDigest != "" && match.InventoryDigest != inventoryDigest {
		return &ErrJournalMismatch{Detail: fmt.Sprintf(
			"retained inventory digest %s differs from the seal-time catalog record %s — vault tampering suspected; refusing",
			inventoryDigest, match.InventoryDigest)}
	}
	return nil
}

// parseTrimPlan strictly parses and validates a retained trim plan.
func parseTrimPlan(b []byte) (trimPlanDoc, error) {
	var plan trimPlanDoc
	if err := decodeStrictJSON(b, &plan); err != nil {
		return plan, err
	}
	if plan.SchemaVersion != schemaVersionCurrent {
		return plan, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"retained removal plan schema_version %d != %d", plan.SchemaVersion, schemaVersionCurrent)}
	}
	return plan, nil
}

// bindsOperation asserts the plan is THIS operation's authorized plan.
func (p trimPlanDoc) bindsOperation(op catalog.Operation) error {
	if p.OperationID != string(op.ID) {
		return &ErrJournalMismatch{Detail: fmt.Sprintf(
			"retained removal plan (op %s) is not operation %s's authorized plan", p.OperationID, op.ID)}
	}
	return nil
}

// reverifyPayload runs the two §11.4 checks against P from evidence
// rebuilt out of P itself (expected tree via expectedTreeAndReadback —
// the same rules the original capture used — plus the op-dir documents).
func (c *Coordinator) reverifyPayload(ctx context.Context, vault VaultRef, op catalog.Operation, ev recoveredEvidence) error {
	expected, readback := expectedTreeAndReadback(ev.entries, ev.wsPrefix)
	opPrefix := "/" + opDirName(op.ID)
	addExpectedPath(expected, opPrefix+"/"+manifestName, expectedNode{Kind: domain.KindFile, Size: int64(len(ev.manifestBytes))})
	addExpectedPath(expected, opPrefix+"/"+ev.manifest.Inventory.Path, expectedNode{Kind: domain.KindFile, Size: int64(len(ev.inventoryBytes))})
	addExpectedPath(expected, opPrefix+"/"+policyFrozenName, expectedNode{Kind: domain.KindFile, Size: int64(len(ev.policyBytes))})
	readback = append(readback,
		readbackFile{SnapPath: opPrefix + "/" + manifestName, Digest: ev.manifestDigest},
		readbackFile{SnapPath: opPrefix + "/" + ev.manifest.Inventory.Path, Digest: ev.inventoryDigest},
		readbackFile{SnapPath: opPrefix + "/" + policyFrozenName, Digest: ev.manifest.Policy.FrozenDigest},
	)
	ls, err := c.store.Ls(ctx, vault.RepoDir, vault.Passfile, op.PayloadSnap)
	if err != nil {
		return fmt.Errorf("lifecycle: listing payload: %w", err)
	}
	if err := verifyCoverage(ls, expected, []string{ev.wsPrefix, opDirName(op.ID)}); err != nil {
		return err
	}
	return verifyReadback(ctx, c.store, vault.RepoDir, vault.Passfile, op.PayloadSnap, readback)
}

// ---- per-phase reconciliation ---------------------------------------

// recoverCancelCapture handles PLANNED/CAPTURING (park) and TRIM_PLANNED
// (trim): the source was untouched by Ebb removal, so the safe
// reconciliation is cancellation. A recorded payload is retained unsealed
// and pinned per §11.3 — never erased.
func (c *Coordinator) recoverCancelCapture(ctx context.Context, vault VaultRef, op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	from := op.Phase
	if err := c.cat.AdvanceOperation(op.ID, from, catalog.PhaseCanceled); err != nil {
		return rep, fmt.Errorf("lifecycle: cancel %s: %w", op.ID, err)
	}
	rep.PhaseAfter = catalog.PhaseCanceled
	rep.Actions = append(rep.Actions, fmt.Sprintf("canceled interrupted operation in %s (source untouched by Ebb removal)", from))
	if op.PayloadSnap != "" {
		if snapID, err := c.recordUnsealedPayload(ctx, vault, op); err != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("recording unsealed payload failed: %v", err))
		} else {
			rep.Actions = append(rep.Actions, fmt.Sprintf(
				"retained unsealed payload snapshot %s (pinned; §11.3 — it may contain useful captured work)", snapID))
			rep.Remaining = append(rep.Remaining, fmt.Sprintf("unsealed payload %s retained; resolve with ebb forget explicitly", op.PayloadSnap))
		}
	}
	// Ebb-owned scratch (op dir) is safe to clean; nothing irreplaceable
	// lives outside the backend.
	parent := filepath.Dir(filepath.Clean(op.SourceRoot))
	if err := removeEbbOwned(filepath.Join(parent, opDirName(op.ID))); err != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("cleanup op dir failed: %v", err))
	}
	_ = removeEbbOwned(journalPath(parent, op.ID)) // absent unless a walk began
	rep.NextAction = "rerun the original command for a fresh capture"
	return rep, nil
}

// recoverPayloadCommitted handles PAYLOAD_COMMITTED: P exists and was
// verified in the crashed run; resume = re-verify P from its own
// evidence, then create the seal — then STOP (§12.4: never delete based
// on P alone; a seal re-read is required before removal, and removal is
// never auto-continued from recovery).
func (c *Coordinator) recoverPayloadCommitted(ctx context.Context, vault VaultRef, op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if op.Kind != catalog.OpKindPark && op.Kind != catalog.OpKindTrim {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("operation kind %q has no payload commit phase", op.Kind)}
	}
	ev, err := c.loadPayloadEvidence(ctx, vault, op)
	if err != nil {
		return rep, err
	}
	rep.Actions = append(rep.Actions, "re-verified payload evidence (manifest, inventory, frozen policy) from P's retained copies")
	if err := c.reverifyPayload(ctx, vault, op, ev); err != nil {
		// §11.3/§12.4: P fails re-verification → cancel, retain P
		// unsealed+pinned, report. Never erase, never seal.
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("payload re-verification failed: %v", err))
		c.failOperation(op.ID, catalog.PhasePayloadCommitted, err.Error())
		if aerr := c.cat.AdvanceOperation(op.ID, catalog.PhasePayloadCommitted, catalog.PhaseCanceled); aerr != nil {
			return rep, fmt.Errorf("lifecycle: cancel after failed re-verification: %w", aerr)
		}
		rep.PhaseAfter = catalog.PhaseCanceled
		if snapID, rerr := c.recordUnsealedPayload(ctx, vault, op); rerr != nil {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("recording unsealed payload failed: %v", rerr))
		} else {
			rep.Actions = append(rep.Actions, fmt.Sprintf("retained unsealed payload snapshot %s (pinned; §11.3)", snapID))
		}
		rep.Remaining = append(rep.Remaining, fmt.Sprintf("payload %s retained unsealed; resolve explicitly with ebb forget", op.PayloadSnap))
		rep.NextAction = "payload failed re-verification; start a fresh capture"
		return rep, err
	}
	rep.Actions = append(rep.Actions, "payload coverage + full readback re-verified")

	// Seal from the reconstructed state (receipt references the digests
	// recomputed from P's own bytes).
	st, err := c.rebuildCaptureState(ctx, vault, op, ev)
	if err != nil {
		return rep, err
	}
	defer st.journal.close()
	if err := c.sealPayload(ctx, st, catalog.PhasePayloadCommitted, catalog.PhaseSealed); err != nil {
		c.failOperation(op.ID, catalog.PhasePayloadCommitted, err.Error())
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("seal resume failed: %v", err))
		return rep, err
	}
	rep.PhaseAfter = catalog.PhaseSealed
	rep.Actions = append(rep.Actions, fmt.Sprintf("sealed payload (seal %s) and committed SEALED; the retained pair is pinned", st.seal.BackendID))
	rep.Remaining = append(rep.Remaining, "live source root is intact; removal has NOT been performed")
	rep.NextAction = "removal is not assumed authorized: rerun the command for a fresh capture, or inspect with ebb status"
	return rep, nil
}

// recoverSealed handles SEALED: revalidate the live source against the
// sealed inventory and report. Recovery never auto-continues into
// removal (§12.4: a changed source invalidates removal; an unchanged one
// still requires a deliberate act).
//
// Crash-window reconciliation (Wave F review F5): §12.2 step 7 renames
// the owned root to the quarantine sibling BEFORE the SEALED→QUARANTINED
// CAS commits. A crash between the two leaves phase SEALED with the live
// root ABSENT and the sibling present — previously reported as "source
// changed", leaving an unreconcilable operation that blocked the
// workspace forever. When the root is absent, the deterministic sibling
// (the same quarantinePath construction park uses) is probed FIRST: a
// sibling carrying the operation's recorded root identity IS the durable
// rename intent, so SEALED→QUARANTINED is committed and the existing
// QUARANTINED reconciliation governs. A sibling with the wrong identity
// (or an unreadable one) is reported and never adopted (I13).
func (c *Coordinator) recoverSealed(ctx context.Context, vault VaultRef, op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	ev, err := c.loadPayloadEvidence(ctx, vault, op)
	if err != nil {
		return rep, err
	}
	ident, perr := parseRootIdentity(op.SourceIdentity)
	if perr != nil {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("operation %s: %v", op.ID, perr)}
	}

	// ---- F5: the quarantine-rename crash window ----------------------
	parent := filepath.Dir(filepath.Clean(op.SourceRoot))
	quar := quarantinePath(parent, op.ID)
	_, rootStatErr := os.Lstat(op.SourceRoot)
	if rootStatErr != nil && !os.IsNotExist(rootStatErr) {
		return rep, fmt.Errorf("lifecycle: probe source root %s: %w", op.SourceRoot, rootStatErr)
	}
	rootPresent := rootStatErr == nil
	siblingPresent := false
	if !rootPresent {
		qinfo, qerr := os.Lstat(quar)
		switch {
		case qerr != nil && os.IsNotExist(qerr):
			// No sibling: the root disappeared without Ebb's rename —
			// the source-changed report below governs (unchanged).
		case qerr != nil:
			return rep, fmt.Errorf("lifecycle: probe quarantine sibling %s: %w", quar, qerr)
		case !qinfo.IsDir():
			return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
				"quarantine sibling %s exists but is not a directory; refusing to touch it — inspect manually", quar)}
		default:
			siblingPresent = true
			qid, ierr := c.probe.RootIdentity(quar)
			if ierr != nil {
				return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
					"quarantine sibling %s is unreadable (%v); refusing to touch it — inspect manually", quar, ierr)}
			}
			if qid != ident {
				return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
					"quarantine sibling %s identity %s does not match the recorded source identity %s; refusing to adopt it (I13) — inspect manually", quar, qid, op.SourceIdentity)}
			}
			// The rename intent was durable (park.go performed step 7's
			// rename before the CAS); commit it and let the QUARANTINED
			// reconciliation govern (reconfirm → resume removal).
			if aerr := c.advance(op.ID, catalog.PhaseSealed, catalog.PhaseQuarantined, nil); aerr != nil {
				return rep, aerr
			}
			rep.PhaseAfter = catalog.PhaseQuarantined
			rep.Actions = append(rep.Actions, fmt.Sprintf(
				"detected the crash window between the quarantine rename and its journal commit: %s carries the sealed root identity; committed SEALED -> QUARANTINED", quar))
			op.Phase = catalog.PhaseQuarantined
			return c.resumeParkRemoval(ctx, vault, op, rep)
		}
	}

	if err := c.revalidateSource(ctx, op.SourceRoot, ident, ev.entries, nil); err != nil {
		var sc *ErrSourceChanged
		if errors.As(err, &sc) {
			rep.Remaining = append(rep.Remaining, fmt.Sprintf("source no longer matches the sealed inventory: %s", sc.Error()))
			rep.Warnings = append(rep.Warnings, sc.Diff...)
		} else {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("revalidation failed: %v", err))
		}
		rep.Remaining = append(rep.Remaining, "sealed P/S pair remains pinned; the live root is intact")
		rep.NextAction = "resolve the source change, then cancel this operation (`ebb recover <op> --cancel`) and rerun the command for a fresh capture"
		return rep, nil
	}
	rep.Actions = append(rep.Actions, "revalidated the live source against the sealed inventory: exact match")
	if siblingPresent {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf(
			"both the live root %s and a quarantine sibling %s exist while the journal says SEALED; durable state diverged — inspect manually", op.SourceRoot, quar))
	} else {
		rep.Remaining = append(rep.Remaining, "removal was never started (no quarantine exists)")
	}
	if op.LastError != "" {
		// The tail WAS attempted and failed (durable record): plain
		// Recover still only reports, but the next action must name the
		// door that works in THIS state (bug B: it used to advise only
		// --cancel + recapture while the park-time error advised
		// --resume-removal, which was then refused).
		rep.Remaining = append(rep.Remaining, "the removal tail was attempted and failed: "+op.LastError)
		rep.NextAction = fmt.Sprintf(
			"after resolving the recorded blocker (e.g. cd any shell out of the workspace, close writers), resume with `ebb recover %s --resume-removal` (it revalidates the source against the sealed inventory before removing anything), or abandon with `ebb recover %s --cancel` and rerun the command for a fresh capture; the retained pair stays pinned",
			op.ID, op.ID)
	} else {
		rep.NextAction = "removal is not assumed authorized by recovery: cancel this operation to unblock the workspace (`ebb recover <op> --cancel`), then rerun the command for a fresh capture; the retained pair stays pinned"
	}
	return rep, nil
}

// recoverParked advances a nonterminal PARKED legacy row to DONE
// idempotently and re-asserts the workspace's parked status.
func (c *Coordinator) recoverParked(op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if ws, err := c.cat.GetWorkspace(op.WorkspaceID); err == nil && ws.Status != catalog.WorkspaceParked {
		if err := c.cat.UpsertWorkspace(catalog.Workspace{ID: ws.ID, Name: ws.Name, Status: catalog.WorkspaceParked}); err != nil {
			return rep, fmt.Errorf("lifecycle: mark workspace parked: %w", err)
		}
		rep.Actions = append(rep.Actions, "re-asserted workspace status parked")
	}
	if err := c.cat.AdvanceOperation(op.ID, catalog.PhaseParked, catalog.PhaseDone); err != nil {
		return rep, fmt.Errorf("lifecycle: finish parked operation: %w", err)
	}
	rep.PhaseAfter = catalog.PhaseDone
	rep.Actions = append(rep.Actions, "advanced PARKED -> DONE (park completed before the terminal transition existed)")
	rep.NextAction = "workspace is parked; use ebb open to restore it"
	return rep, nil
}

// resumeParkRemoval reconciles QUARANTINED / REMOVING / REMOVAL_BLOCKED:
// verify the quarantine's identity against the recorded source identity,
// then resume the authorized removal walk (each entry re-digested;
// already-removed entries skip). Completes to PARKED→DONE with the
// workspace parked.
func (c *Coordinator) resumeParkRemoval(ctx context.Context, vault VaultRef, op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if op.Kind != catalog.OpKindPark {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("operation %s is kind %q, not a park", op.ID, op.Kind)}
	}
	ev, err := c.loadPayloadEvidence(ctx, vault, op)
	if err != nil {
		return rep, err
	}
	ident, perr := parseRootIdentity(op.SourceIdentity)
	if perr != nil {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("operation %s: %v", op.ID, perr)}
	}

	parent := filepath.Dir(filepath.Clean(op.SourceRoot))
	quar := quarantinePath(parent, op.ID)
	qinfo, qerr := os.Lstat(quar)
	switch {
	case qerr == nil && qinfo.IsDir():
		// Reconfirm the quarantine identity (F32/I13).
		qid, err := c.probe.RootIdentity(quar)
		if err != nil {
			return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("identity probe of quarantine %s failed: %v", quar, err)}
		}
		if qid != ident {
			return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
				"quarantine %s identity %s does not match the recorded source identity %s; refusing to remove (inspect manually)", quar, qid, op.SourceIdentity)}
		}
		if _, err := os.Lstat(op.SourceRoot); err == nil {
			return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
				"both the source root %s and its quarantine %s exist; durable state diverged — inspect manually", op.SourceRoot, quar)}
		}
		rep.Actions = append(rep.Actions, fmt.Sprintf("verified quarantine identity (%s)", quar))
	case qerr == nil && !qinfo.IsDir():
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("quarantine path %s exists but is not a directory", quar)}
	case os.IsNotExist(qerr):
		// Root removal may have completed before the PARKED commit; the
		// walk below is idempotent (everything skips, root removal of an
		// absent path is success). The source root must be gone too.
		if _, err := os.Lstat(op.SourceRoot); err == nil {
			return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
				"journal says %s but neither the quarantine %s nor a completed removal explains the live root %s", op.Phase, quar, op.SourceRoot)}
		}
		rep.Actions = append(rep.Actions, "quarantine already absent; verifying completion idempotently")
	default:
		return rep, fmt.Errorf("lifecycle: quarantine %s: %w", quar, qerr)
	}

	st, err := c.rebuildCaptureState(ctx, vault, op, ev)
	if err != nil {
		return rep, err
	}
	defer st.journal.close()
	st.rootIdent = ident

	// F7: record the writer-assertion source of this destructive resume
	// (both Recover's idempotent completions and the explicit verb).
	c.recordResumeAssertion(op, st.journal)

	if op.Phase == catalog.PhaseQuarantined {
		_, perr := c.removeQuarantinedRoot(ctx, st, quar)
		if perr != nil {
			return c.resumeRemovalFailed(rep, perr)
		}
	} else {
		if op.Phase == catalog.PhaseRemovalBlocked {
			if err := c.advance(op.ID, catalog.PhaseRemovalBlocked, catalog.PhaseRemoving, st.journal); err != nil {
				return rep, err
			}
		}
		allowed := make(map[string]domain.Entry, len(st.entries))
		for _, e := range st.entries {
			allowed[e.Path] = e
		}
		permit, err := newRemovalPermit(op.ID, domain.SnapshotID(ev.manifest.SnapshotID), quar, ident, allowed)
		if err != nil {
			return rep, err
		}
		if _, perr := c.finishParkRemoval(ctx, st, permit); perr != nil {
			return c.resumeRemovalFailed(rep, perr)
		}
	}

	rep.PhaseAfter = catalog.PhaseDone
	rep.Actions = append(rep.Actions, "resumed the authorized removal walk to completion; committed PARKED -> DONE")
	rep.Actions = append(rep.Actions, "workspace marked parked")
	rep.NextAction = "workspace is parked; use ebb open to restore it"
	return rep, nil
}

// resumeSealedParkRemoval is the explicit --resume-removal door for a
// SEALED park whose destructive tail was attempted and blocked before
// the quarantine rename succeeded (Wave 4 gauntlet bug B). The state is
// real: parkTail fails the rename (errno 32 — the launching shell's own
// cwd pin, an open handle without FILE_SHARE_DELETE) while the seal is
// already committed, so the operation sits in SEALED with its removal
// blocked — and the park-time error's safe action names --resume-removal,
// which until this door existed refused exactly this phase.
//
// Acceptance gate, from durable evidence only:
//
//   - kind must be park with phase SEALED and last_error non-empty.
//     Invariant: on a SEALED row, last_error is written only by the
//     park tail (every capture-phase failure records under the row's
//     pre-seal phase), so a non-empty last_error IS the durable record
//     of an attempted tail. A plain crash-after-seal (empty last_error)
//     keeps the report-only discipline — plain `ebb recover` governs.
//   - the deterministic quarantine sibling must NOT exist: if it does,
//     the step-7 rename already committed and recoverSealed's F5
//     crash-window adoption (identity-checked) is the door, not this.
//
// The §12.4 SEALED rule ("Revalidate; do not assume deletion remains
// authorized") is honored by construction: the door re-enters parkTail,
// whose step 6 revalidates the live source against the sealed inventory
// (root identity + full re-scan with hashing) BEFORE the rename; a
// changed source fails closed with ErrSourceChanged and the row stays
// SEALED. Every later gate (quarantine identity re-probe, per-entry
// re-digest, CAS phase transitions) applies unchanged.
func (c *Coordinator) resumeSealedParkRemoval(ctx context.Context, vault VaultRef, op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if op.Kind != catalog.OpKindPark {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s is kind %q in SEALED; the SEALED --resume-removal door applies to a park whose removal tail was blocked", op.ID, op.Kind)}
	}
	if op.LastError == "" {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"operation %s is SEALED with no recorded failure: its removal tail was never attempted (crash after seal), so there is no blocked removal to resume; plain `ebb recover %s` revalidates and reports, and `ebb recover %s --cancel` unblocks the workspace for a fresh capture", op.ID, op.ID, op.ID)}
	}
	// The F5 crash window: a sibling means the rename DID succeed before
	// the journal commit — recoverSealed adopts it by identity instead.
	parent := filepath.Dir(filepath.Clean(op.SourceRoot))
	quar := quarantinePath(parent, op.ID)
	if _, qerr := os.Lstat(quar); qerr == nil {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"quarantine sibling %s exists, so the removal already renamed the root (crash window before the journal commit); run plain `ebb recover %s` — it adopts the quarantine by native identity and completes the removal", quar, op.ID)}
	} else if !os.IsNotExist(qerr) {
		return rep, fmt.Errorf("lifecycle: probe quarantine sibling %s: %w", quar, qerr)
	}

	ev, err := c.loadPayloadEvidence(ctx, vault, op)
	if err != nil {
		return rep, err
	}
	ident, perr := parseRootIdentity(op.SourceIdentity)
	if perr != nil {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("operation %s: %v", op.ID, perr)}
	}
	st, err := c.rebuildCaptureState(ctx, vault, op, ev)
	if err != nil {
		return rep, err
	}
	defer st.journal.close()
	st.rootIdent = ident

	// F7: record the writer-assertion source of this destructive resume
	// ("resume:SEALED") — same discipline as the later-phase resumes.
	c.recordResumeAssertion(op, st.journal)

	// Re-enter the full tail: step 6 revalidation (the do-not-assume
	// gate) runs before the quarantine rename and the authorized walk.
	if _, terr := c.parkTail(ctx, st); terr != nil {
		// parkTail's failure paths record SEALED (tail never advanced)
		// or REMOVAL_BLOCKED (the walk blocked) — report the durable
		// truth, not a guess.
		if fresh, ferr := c.cat.GetOperation(op.ID); ferr == nil {
			rep.PhaseAfter = fresh.Phase
		}
		return c.resumeRemovalFailed(rep, terr)
	}
	rep.PhaseAfter = catalog.PhaseDone
	rep.Actions = append(rep.Actions, fmt.Sprintf(
		"re-entered the blocked removal tail from SEALED (recorded blocker: %s): revalidated the live source against the sealed inventory, quarantined the root and removed the authorized entries", op.LastError))
	rep.Actions = append(rep.Actions, "resumed the authorized removal walk to completion; committed PARKED -> DONE")
	rep.Actions = append(rep.Actions, "workspace marked parked")
	rep.NextAction = "workspace is parked; use ebb open to restore it"
	return rep, nil
}

// resumeTrimRemoval reconciles TRIM_SEALING: rebuild the member set from
// the removal manifest retained in P, re-verify the live root's identity,
// resume the idempotent removal and complete TRIM_DONE.
func (c *Coordinator) resumeTrimRemoval(ctx context.Context, vault VaultRef, op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	if op.Kind != catalog.OpKindTrim {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("operation %s is kind %q, not a trim", op.ID, op.Kind)}
	}
	ev, err := c.loadPayloadEvidence(ctx, vault, op)
	if err != nil {
		return rep, err
	}
	prefix := "/" + opDirName(op.ID)
	rmBytes, err := c.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, op.PayloadSnap, prefix+"/"+removalManifestName)
	if err != nil {
		return rep, fmt.Errorf("lifecycle: dump retained removal plan: %w", err)
	}
	plan, err := parseTrimPlan(rmBytes)
	if err != nil {
		return rep, err
	}
	if err := plan.bindsOperation(op); err != nil {
		return rep, err
	}
	if plan.SnapshotID != ev.manifest.SnapshotID {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf(
			"removal plan snapshot %s does not match the sealed manifest snapshot %s", plan.SnapshotID, ev.manifest.SnapshotID)}
	}

	ident, perr := parseRootIdentity(op.SourceIdentity)
	if perr != nil {
		return rep, &ErrJournalMismatch{Detail: fmt.Sprintf("operation %s: %v", op.ID, perr)}
	}
	allowed := make(map[string]domain.Entry)
	var outputs []string
	members := 0
	for _, g := range plan.Groups {
		outputs = append(outputs, g.Outputs...)
		for _, m := range g.Members {
			allowed[m.Path] = m.Entry
			members++
		}
	}
	if len(allowed) == 0 {
		return rep, &ErrJournalMismatch{Detail: "retained removal plan carries no members; refusing to guess what to remove"}
	}

	// The live root must still carry the sealed identity (I13).
	rootPresent := true
	now, rerr := c.probe.RootIdentity(op.SourceRoot)
	if rerr != nil {
		if !os.IsNotExist(rerr) {
			return rep, fmt.Errorf("lifecycle: identity probe of live root: %w", rerr)
		}
		rootPresent = false
	}
	if rootPresent && now != ident {
		return rep, &ErrSourceChanged{Diff: []string{fmt.Sprintf(
			"live root %s identity %s differs from the sealed identity %s; trim removal refused", op.SourceRoot, now, ident)}}
	}

	st, err := c.rebuildCaptureState(ctx, vault, op, ev)
	if err != nil {
		return rep, err
	}
	defer st.journal.close()
	st.rootIdent = ident
	j := st.journal

	// F7: record the writer-assertion source of this destructive resume.
	c.recordResumeAssertion(op, j)

	permit, err := newRemovalPermit(op.ID, domain.SnapshotID(ev.manifest.SnapshotID), op.SourceRoot, ident, allowed)
	if err != nil {
		return rep, err
	}
	stats, err := permit.execute(ctx, c.probe, j, nil)
	if err != nil {
		c.failOperation(op.ID, catalog.PhaseTrimSealing, err.Error())
		rep.Warnings = append(rep.Warnings, err.Error())
		rep.NextAction = "resolve the blocker (close handles / restore missing files' intent), then ResumeRemoval"
		return rep, err
	}
	if rootPresent {
		if err := permit.removeEmptyAncestors(outputs, j); err != nil {
			c.failOperation(op.ID, catalog.PhaseTrimSealing, err.Error())
			return rep, err
		}
	}
	if err := c.advance(op.ID, catalog.PhaseTrimSealing, catalog.PhaseTrimDone, j); err != nil {
		return rep, err
	}
	rep.PhaseAfter = catalog.PhaseTrimDone
	rep.Actions = append(rep.Actions, fmt.Sprintf(
		"resumed the authorized trim removal from the retained plan (%d member(s): removed=%d skipped-gone=%d); committed TRIM_DONE",
		members, stats.Removed, stats.SkippedGone))
	c.cleanupScratch(st)
	rep.NextAction = "trim complete; the workspace remains live"
	return rep, nil
}

// reportRemovalBlocked (Wave F review F7): plain Recover is REPORT-ONLY
// for a REMOVAL_BLOCKED park — the §12.4 REMOVAL_BLOCKED row says
// "report exact location; never mark parked", and resuming the walk
// re-opens the §12.3 digest->remove race window, so the destructive
// resume belongs to the explicit verb (ResumeRemoval /
// `ebb recover <op> --resume-removal`) after the user resolved the
// blocker and re-established the stopped-writers condition.
func (c *Coordinator) reportRemovalBlocked(op catalog.Operation, rep RecoveryReport) (RecoveryReport, error) {
	rep.Actions = append(rep.Actions, "reported the blocked removal walk (report-only; the destructive resume requires the explicit verb)")
	if op.LastError != "" {
		rep.Remaining = append(rep.Remaining, "blocker: "+op.LastError)
	}
	rep.Remaining = append(rep.Remaining,
		"remaining authorized entries stay retained in the quarantine; the P/S pair stays pinned")
	rep.NextAction = fmt.Sprintf(
		"resolve the blocker (e.g. close open handles), then resume with `ebb recover %s --resume-removal` after re-establishing the stopped-writers condition", op.ID)
	return rep, nil
}

// recordResumeAssertion durably names the writer-assertion source of a
// destructive resume (Wave F review F7, §12.4 QUARANTINED row: "reconfirm
// identities and writer condition"). A resumed walk re-enters the §12.3
// digest->remove window under the coordinator's own authority, so the
// journal records where the stopped-writers condition now comes from:
// "resume:<phase>", the interrupted phase the walk resumed from. No new
// tables — the note rides the progress journal and the operation row's
// last_error/updated_at fields (best effort; the catalog phase remains
// the authority).
func (c *Coordinator) recordResumeAssertion(op catalog.Operation, j *opJournal) {
	const note = "writer assertion source: resume:"
	j.step("writer-assertion", note+op.Phase)
	_ = c.cat.FailOperation(op.ID, op.Phase, note+op.Phase)
}

// resumeRemovalFailed folds a failed resume attempt into a report.
func (c *Coordinator) resumeRemovalFailed(rep RecoveryReport, err error) (RecoveryReport, error) {
	rep.Warnings = append(rep.Warnings, err.Error())
	var blocked *ErrRemovalBlocked
	var changed *ErrSourceChanged
	switch {
	case errors.As(err, &blocked):
		rep.Remaining = append(rep.Remaining, fmt.Sprintf("removal blocked at %s (%s); remaining authorized entries retained", blocked.Path, blocked.Code))
		rep.NextAction = "resolve the blocker (e.g. close open handles), then ResumeRemoval"
	case errors.As(err, &changed):
		// The revalidation gate refused (§12.2 step 6 / §12.4 SEALED): the
		// live source no longer matches the sealed inventory, so removal
		// stays invalidated — the resume is NOT retryable as-is.
		rep.Remaining = append(rep.Remaining, "the live source no longer matches the sealed inventory; removal is invalidated (P/S retained, source intact)")
		rep.NextAction = "resolve the source change, then cancel this operation (`ebb recover <operation-id> --cancel`) and rerun the command for a fresh capture"
	default:
		rep.NextAction = "inspect the operation journal; the walk can be resumed after the cause is fixed"
	}
	return rep, err
}

// ---- state reconstruction --------------------------------------------

// rebuildCaptureState reconstructs the in-memory capture state from
// durable evidence so the shared seal/removal helpers run identically on
// a fresh Coordinator (new-process simulation is exact: nothing is
// cached).
func (c *Coordinator) rebuildCaptureState(ctx context.Context, vault VaultRef, op catalog.Operation, ev recoveredEvidence) (*captureState, error) {
	repoID, err := c.store.RepoID(ctx, vault.RepoDir, vault.Passfile)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: vault identity: %w", err)
	}
	rootAbs := filepath.Clean(op.SourceRoot)
	parent := filepath.Dir(rootAbs)
	snapKind := catalog.SnapshotKindPark
	if op.Kind == catalog.OpKindTrim {
		snapKind = catalog.SnapshotKindTrim
	}
	wsName := ""
	if ws, werr := c.cat.GetWorkspace(op.WorkspaceID); werr == nil {
		wsName = ws.Name
	}
	var warn []string
	j, jerr := openJournal(parent, op.ID)
	if jerr != nil {
		j = nil
		warn = append(warn, "progress journal unavailable; catalog phases remain authoritative")
	}
	return &captureState{
		opID: op.ID, wsID: op.WorkspaceID,
		snapID: domain.SnapshotID(ev.manifest.SnapshotID),
		kind:   op.Kind, snapKind: snapKind,
		rootAbs: rootAbs, parent: parent,
		wsPrefix: ev.wsPrefix, // manifest bijection, never Base() of a path (I13)
		entries:  append([]domain.Entry(nil), ev.entries...),
		journal:  j, vault: vault, repoID: repoID,
		opts:            CaptureOptions{WorkspaceName: wsName},
		opDir:           filepath.Join(parent, opDirName(op.ID)),
		opDirName:       opDirName(op.ID),
		sealDir:         filepath.Join(parent, sealDirName(op.ID)),
		manifestDigest:  ev.manifestDigest,
		inventoryDigest: ev.inventoryDigest,
		payload:         domain.SnapshotRef{BackendID: op.PayloadSnap},
		warnings:        warn,
	}, nil
}

// recordUnsealedPayload records a §11.3 unsealed payload snapshot row
// (pinned, never auto-erased). The snapshot id and document digests are
// recovered from P's own manifest when readable.
func (c *Coordinator) recordUnsealedPayload(ctx context.Context, vault VaultRef, op catalog.Operation) (domain.SnapshotID, error) {
	snapID := domain.SnapshotID(domain.NewID())
	var manifestD, invD string
	prefix := "/" + opDirName(op.ID)
	if mb, err := c.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, op.PayloadSnap, prefix+"/"+manifestName); err == nil {
		var md manifestDoc
		if perr := decodeStrictJSON(mb, &md); perr == nil {
			snapID = domain.SnapshotID(md.SnapshotID)
			manifestD = digestBytes(mb)
			if ib, ierr := c.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, op.PayloadSnap, prefix+"/"+md.Inventory.Path); ierr == nil {
				invD = digestBytes(ib)
			}
		}
	}
	kind := catalog.SnapshotKindPark
	if op.Kind == catalog.OpKindTrim {
		kind = catalog.SnapshotKindTrim
	}
	repoID, err := c.store.RepoID(ctx, vault.RepoDir, vault.Passfile)
	if err != nil {
		repoID = ""
	}
	if _, err := c.cat.RecordSnapshot(catalog.Snapshot{
		ID: snapID, WorkspaceID: op.WorkspaceID,
		PayloadBackendID: op.PayloadSnap, VaultID: c.vaultIDFor(repoID, vault),
		ManifestDigest: manifestD, InventoryDigest: invD, Kind: kind,
	}); err != nil {
		return "", err
	}
	return snapID, nil
}

// readJournalOrWarn loads the progress journal, tolerating absence.
func readJournalOrWarn(parent string, opID domain.OperationID, rep *RecoveryReport) []journalRecord {
	recs, err := readJournal(parent, opID)
	if err != nil && rep != nil {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("progress journal unreadable: %v", err))
	}
	return recs
}
