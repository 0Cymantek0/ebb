// errors.go maps the typed errors of the lifecycle/restore/vault layers
// onto Ebb's public exit-code contract (Foundation §17.5) and defines the
// stable CLI-side blocker codes with their §5.5 wording (code + affected
// group + reason + safe action). Classification is centralized so every
// command maps identically.

package cli

import (
	"context"
	"errors"
	"fmt"

	"ebb/internal/capsule"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/restore"
	"ebb/internal/vault"
)

// Stable CLI blocker codes (Foundation §5.5). The lifecycle/restore typed
// errors carry their own EBB_E_* codes; these are the blockers the CLI
// layer itself raises before a coordinator call.
const (
	CodeNoVault               = "EBB_E_NO_VAULT"
	CodeUnlockRejected        = "EBB_E_UNLOCK_REJECTED"
	CodeWritersUnasserted     = "EBB_E_WRITERS_UNASSERTED"
	CodeOpenUnknownTarget     = "EBB_E_OPEN_UNKNOWN_TARGET"
	CodeOpenNoDestination     = "EBB_E_OPEN_NO_DESTINATION"
	CodeEscalationUnconfirmed = "EBB_E_ESCALATION_UNCONFIRMED"
	CodeForgetLastOfParked    = "EBB_E_LAST_OF_PARKED"
	CodeForgetUnconfirmed     = "EBB_E_FORGET_UNCONFIRM"
	CodeForgetUnsealed        = "EBB_E_FORGET_UNSEALED"
	CodeForgetNotForgettable  = "EBB_E_NOT_FORGETTABLE"
	// gc eligibility blockers (Foundation §11.6/§16.6: maintenance is
	// serialized against captures/opens/forgets and runs only after
	// retention is fully resolved — F38).
	CodeGcActiveOperation = "EBB_E_GC_ACTIVE_OPERATION"
	CodeGcPendingIntent   = "EBB_E_GC_PENDING_INTENT"
	CodeGcUnsupported     = "EBB_E_GC_UNSUPPORTED"
	// Reconstruction-approval blockers (open's rebuild phase). The
	// outcome is exit 6 either way: preserved files were recovered, the
	// reconstruction is blocked (Foundation §17.5).
	CodeApprovalRequired = "EBB_E_APPROVAL_REQUIRED"
	CodeApprovalDrift    = "EBB_E_APPROVAL_DRIFT"
	CodeApprovalDeclined = "EBB_E_APPROVAL_DECLINED"
	// Export blockers (Wave H, Foundation §15.2): scoped like verify's
	// not-openable refusals — exit 3, source untouched. The capsule
	// package owns the codes for the failures it raises; the CLI owns
	// the eligibility refusals.
	CodeExportNotExportable = "EBB_E_NOT_EXPORTABLE"
	// CodeExportPartialStale and CodeExportOutputOccupied are the
	// capsule-typed blockers (aliased here for the presentation layer).
	CodeExportPartialStale   = capsule.CodePartialStale
	CodeExportOutputOccupied = capsule.CodeOutputOccupied
)

// blockerMessage renders one §5.5 blocker: stable code, reason and a
// safe action. affected may be "" when the blocker is not group-scoped.
func blockerMessage(code, affected, reason, safeAction string) string {
	msg := code
	if affected != "" {
		msg += " [" + affected + "]"
	}
	msg += ": " + reason + ". " + safeAction
	return msg
}

// classifyExitCode maps a command failure to its §17.5 exit code. A
// nil-seam *cliError short-circuits first (its code wins).
func classifyExitCode(err error) int {
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.code
	}
	if err == nil {
		return ExitOK
	}
	// Controlled cancellation: the journal keeps the last durable phase.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return ExitCancelled
	}
	// Caller mistakes (before any durable side effect).
	var invOpt *lifecycle.ErrInvalidOptions
	if errors.As(err, &invOpt) {
		return ExitUsage
	}
	var rInvOpt *restore.ErrInvalidOptions
	if errors.As(err, &rInvOpt) {
		return ExitUsage
	}
	// Blocked before mutation by policy/capability/trust/stopped-writers.
	var inProgress *lifecycle.ErrOpInProgress
	if errors.As(err, &inProgress) {
		return ExitBlocked
	}
	var destructive *lifecycle.ErrDestructiveBlocked
	if errors.As(err, &destructive) {
		return ExitBlocked
	}
	var sourceChanged *lifecycle.ErrSourceChanged
	if errors.As(err, &sourceChanged) {
		// §17.5 read: removal was invalidated BEFORE any mutation; the
		// source is intact and P/S retained — a block, not an
		// interruption.
		return ExitBlocked
	}
	var notOpenable *restore.ErrNotOpenable
	if errors.As(err, &notOpenable) {
		return ExitBlocked
	}
	var occupied *restore.ErrDestinationOccupied
	if errors.As(err, &occupied) {
		return ExitBlocked
	}
	var vaultOverlap *restore.ErrVaultOverlap
	if errors.As(err, &vaultOverlap) {
		// The open-side I06 twin (G3): the destination overlaps the vault
		// through a direct or alias spelling; blocked before any staging.
		return ExitBlocked
	}
	var space *restore.ErrInsufficientSpace
	if errors.As(err, &space) {
		return ExitBlocked
	}
	// Capture/integrity verification failures; no removal authorized.
	var ver *lifecycle.ErrVerification
	if errors.As(err, &ver) {
		return ExitCaptureVerify
	}
	var rver *restore.ErrVerification
	if errors.As(err, &rver) {
		return ExitCaptureVerify
	}
	var sealInvalid *restore.ErrSealInvalid
	if errors.As(err, &sealInvalid) {
		return ExitCaptureVerify
	}
	// Capsule export (Wave H): a failed export check published nothing
	// and left the source intact — same honest class as capture verify.
	var cver *capsule.ErrVerification
	if errors.As(err, &cver) {
		return ExitCaptureVerify
	}
	if capsule.IsInvalidParams(err) {
		return ExitUsage
	}
	var occupiedOut *capsule.ErrOutputOccupied
	if errors.As(err, &occupiedOut) {
		return ExitBlocked
	}
	var partial *capsule.ErrPartialExists
	if errors.As(err, &partial) {
		return ExitBlocked
	}
	// Capsule import (Wave I, §15.3): the wrong capsule passphrase is
	// an auth failure (7); a file that is not a usable capsule is an
	// argument mistake (2 — the file argument is wrong, not the
	// system); headroom and trim-kind refusals are blocks (3, nothing
	// extracted); an unprovable copy is an integrity failure (4, the
	// destination was rolled back and List-verified by the transport).
	var capsUnlock *capsule.ErrCapsuleUnlock
	if errors.As(err, &capsUnlock) {
		return ExitVault
	}
	var notCapsule *capsule.ErrNotACapsule
	if errors.As(err, &notCapsule) {
		return ExitUsage
	}
	var importSpace *capsule.ErrImportSpace
	if errors.As(err, &importSpace) {
		return ExitBlocked
	}
	var trimCapsule *capsule.ErrTrimCapsule
	if errors.As(err, &trimCapsule) {
		return ExitBlocked
	}
	var copyIntegrity *capsule.ErrCopyIntegrity
	if errors.As(err, &copyIntegrity) {
		return ExitCaptureVerify
	}
	// Interrupted/partial operations that require reconciliation.
	var removalBlocked *lifecycle.ErrRemovalBlocked
	if errors.As(err, &removalBlocked) {
		return ExitInterrupted
	}
	var journalMismatch *lifecycle.ErrJournalMismatch
	if errors.As(err, &journalMismatch) {
		return ExitInterrupted
	}
	var cancelRefused *lifecycle.ErrCancelRefused
	if errors.As(err, &cancelRefused) {
		// --cancel was refused inside the quarantine-rename crash window
		// (G4): the workspace is mid-rename and only Recover reconciles.
		return ExitInterrupted
	}
	var publishBlocked *restore.ErrPublishBlocked
	if errors.As(err, &publishBlocked) {
		// The staged tree is kept and the operation stays RESTORING for
		// recovery (§12.5): reconciliation is outstanding.
		return ExitInterrupted
	}
	// Preserved files recovered but reconstruction failed/blocked
	// (§17.5 exit 6): non-zero action exit, timeout, missing outputs,
	// unresolvable tool (F14), declined/stale approval or a protected
	// file changed (F36). Note a cancellation inside the rebuild keeps
	// its 130 semantics: the context check above wins over this branch.
	var rebuild *restore.ErrRebuildFailed
	if errors.As(err, &rebuild) {
		return ExitRebuildFailed
	}
	// Vault/unlock/provider unavailable.
	var noSource *vault.NoSourceError
	if errors.As(err, &noSource) {
		return ExitVault
	}
	var rejected *vault.UnlockRejectedError
	if errors.As(err, &rejected) {
		return ExitVault
	}
	if errors.Is(err, vault.ErrNotFound) {
		return ExitVault
	}
	if errors.Is(err, vault.ErrRepoDirNotEmpty) {
		return ExitUsage
	}
	var se *domain.StoreError
	if errors.As(err, &se) {
		switch se.Class {
		case domain.StoreErrSource:
			// A source read failed mid-capture: the capture failed; no
			// removal is authorized.
			return ExitCaptureVerify
		case domain.StoreErrIntegrity:
			// A backend-side outcome could not be proven safe AFTER a
			// mutation ran (gc: the snapshot set changed or could not be
			// re-listed across a prune): integrity verification failed.
			return ExitCaptureVerify
		case domain.StoreErrRepo, domain.StoreErrAuth:
			return ExitVault
		default:
			return ExitUsage
		}
	}
	if errors.Is(err, catalog.ErrNotFound) {
		// An unknown operation/snapshot/workspace id is an argument
		// mistake, not a system failure.
		return ExitUsage
	}
	// Unknown failures are reported as blocked (the same honest default
	// inspect uses for infrastructure failures); nothing was removed.
	return ExitBlocked
}

// outcomeForExit maps an exit code onto the envelope outcome vocabulary.
func outcomeForExit(code int) string {
	switch code {
	case ExitOK:
		return "ok"
	case ExitUsage:
		return "usage-error"
	case ExitBlocked:
		return "blocked"
	case ExitCaptureVerify:
		return "verification-failed"
	case ExitInterrupted:
		return "reconciliation-required"
	case ExitRebuildFailed:
		return "rebuild-failed"
	case ExitVault:
		return "vault-unavailable"
	case ExitShortfall:
		return "shortfall"
	case ExitCancelled:
		return "cancelled"
	default:
		return fmt.Sprintf("exit-%d", code)
	}
}

// codedMessage renders err prefixed with its stable EBB_E_ code when
// the typed error exposes one (restore's errors implement Code();
// lifecycle removal blockers already carry their code in the text).
// This is the §5.5 "stable code" half of every human blocker.
func codedMessage(err error) string {
	var c interface{ Code() string }
	if errors.As(err, &c) {
		return c.Code() + ": " + err.Error()
	}
	return err.Error()
}

// safeActionFor appends the §5.5 safe action for the restore/lifecycle
// typed blockers whose own text carries only code+reason ("" when the
// error already includes one or none applies).
func safeActionFor(err error) string {
	var occupied *restore.ErrDestinationOccupied
	if errors.As(err, &occupied) {
		return ". Safe action: choose a different --to destination or move the occupant aside; nothing was overwritten"
	}
	var vaultOverlap *restore.ErrVaultOverlap
	if errors.As(err, &vaultOverlap) {
		return ". Safe action: choose a destination outside the vault repository (and not containing it); nothing was staged"
	}
	var cancelRefused *lifecycle.ErrCancelRefused
	if errors.As(err, &cancelRefused) {
		return fmt.Sprintf(". Safe action: run `ebb recover %s` — it adopts-or-reports the quarantine tree by identity; the sibling was not touched", cancelRefused.OperationID)
	}
	var space *restore.ErrInsufficientSpace
	if errors.As(err, &space) {
		return ". Safe action: free space on the destination volume or choose another --to destination"
	}
	var notOpenable *restore.ErrNotOpenable
	if errors.As(err, &notOpenable) {
		return ". Safe action: pick a park- or snapshot-kind snapshot (see `ebb status`)"
	}
	var sealInvalid *restore.ErrSealInvalid
	if errors.As(err, &sealInvalid) {
		return ". Safe action: keep the snapshot pinned and inspect the vault (`ebb doctor`); nothing was staged"
	}
	var rver *restore.ErrVerification
	if errors.As(err, &rver) {
		return ". Safe action: keep the snapshot pinned and retry the open; staged content was discarded"
	}
	var publish *restore.ErrPublishBlocked
	if errors.As(err, &publish) {
		return ". Safe action: clear the destination, then `ebb recover <operation-id>` to reconcile the RESTORING operation"
	}
	var removal *lifecycle.ErrRemovalBlocked
	if errors.As(err, &removal) {
		return ". Safe action: resolve the blocker (close handles, fix permissions), then `ebb recover <operation-id> --resume-removal`"
	}
	var inProgress *lifecycle.ErrOpInProgress
	if errors.As(err, &inProgress) {
		return fmt.Sprintf(". Safe action: reconcile the active operation first: `ebb recover %s`", inProgress.Operations[0])
	}
	var sourceChanged *lifecycle.ErrSourceChanged
	if errors.As(err, &sourceChanged) {
		return ". Safe action: the sealed snapshot stays retained and the source is intact; resolve the change and run a fresh capture"
	}
	var rebuild *restore.ErrRebuildFailed
	if errors.As(err, &rebuild) {
		return fmt.Sprintf(". Safe action: the recovered files are intact at the destination and the snapshot stays pinned; resolve the blocker (install the missing toolchain, fix the action), then `ebb open --resume %s`",
			rebuild.OperationID)
	}
	var cver *capsule.ErrVerification
	if errors.As(err, &cver) {
		return ". Safe action: nothing was published and the source snapshot is intact and still pinned; rerun the export after resolving the check failure"
	}
	var occupiedOut *capsule.ErrOutputOccupied
	if errors.As(err, &occupiedOut) {
		return ". Safe action: choose a different --output path or move the existing file aside; nothing was overwritten"
	}
	var partial *capsule.ErrPartialExists
	if errors.As(err, &partial) {
		return ". Safe action: inspect the partial (its ebb-export.json names the operation that left it), delete it explicitly, then rerun the export"
	}
	var capsUnlock *capsule.ErrCapsuleUnlock
	if errors.As(err, &capsUnlock) {
		return ". Safe action: nothing was imported; supply the capsule's recovery passphrase (shown once at export time) via EBB_CAPSULE_PASSWORD or a terminal prompt"
	}
	var notCapsule *capsule.ErrNotACapsule
	if errors.As(err, &notCapsule) {
		return ". Safe action: pass a capsule produced by `ebb export`; nothing was imported and the file was not modified"
	}
	var copyIntegrity *capsule.ErrCopyIntegrity
	if errors.As(err, &copyIntegrity) {
		return ". Safe action: everything this import created in the destination vault was forgotten and List-verified gone; inspect the vault (`ebb doctor`) and rerun the import"
	}
	if capsule.IsInvalidParams(err) {
		return ". Safe action: fix the arguments (an existing output directory and a fresh --output path are required)"
	}
	return ""
}

// codedWithSafeAction renders err as codedMessage plus its safe action.
func codedWithSafeAction(err error) string {
	msg := codedMessage(err)
	if a := safeActionFor(err); a != "" {
		return msg + a
	}
	return msg
}

// emitFailure stamps the §17.2 outcome for code, records the error
// lines, emits the terminal envelope and returns the exit code. The
// Wave E commands route every failure through it so the machine outcome
// always matches the process exit.
func emitFailure(env Envelope, jsonOut bool, streams Streams, code int, msgs ...string) int {
	env.Outcome = outcomeForExit(code)
	env.Errors = msgs
	emit(env, jsonOut, streams, "")
	return code
}
