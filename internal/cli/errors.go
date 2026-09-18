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
	CodeNoVault          = "EBB_E_NO_VAULT"
	CodeUnlockRejected   = "EBB_E_UNLOCK_REJECTED"
	CodeWritersUnasserted = "EBB_E_WRITERS_UNASSERTED"
	CodeOpenUnknownTarget = "EBB_E_OPEN_UNKNOWN_TARGET"
	CodeOpenNoDestination = "EBB_E_OPEN_NO_DESTINATION"
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
	// Interrupted/partial operations that require reconciliation.
	var removalBlocked *lifecycle.ErrRemovalBlocked
	if errors.As(err, &removalBlocked) {
		return ExitInterrupted
	}
	var journalMismatch *lifecycle.ErrJournalMismatch
	if errors.As(err, &journalMismatch) {
		return ExitInterrupted
	}
	var publishBlocked *restore.ErrPublishBlocked
	if errors.As(err, &publishBlocked) {
		// The staged tree is kept and the operation stays RESTORING for
		// recovery (§12.5): reconciliation is outstanding.
		return ExitInterrupted
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
