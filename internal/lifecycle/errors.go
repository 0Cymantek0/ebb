package lifecycle

import (
	"errors"
	"fmt"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// Typed errors of the lifecycle coordinator. Every failure that decides
// whether source data may be removed is one of these (matched with
// errors.Is / errors.As), never a bare fmt.Errorf.

// ErrOpInProgress reports that the workspace already has an active
// (non-terminal) operation (F37, Foundation §12.1: two clients must not
// each believe they are sole authority for the same live workspace).
type ErrOpInProgress struct {
	WorkspaceID domain.WorkspaceID
	Operations  []string // active operation ids
}

func (e *ErrOpInProgress) Error() string {
	return fmt.Sprintf("lifecycle: workspace %s has active operation(s) %s; reconcile with Recover before starting another",
		e.WorkspaceID, strings.Join(e.Operations, ", "))
}

// ErrDestructiveBlocked reports that a destructive operation was refused
// BEFORE any mutation: source contains entries whose fidelity v1 cannot
// promise (scan blockers such as named data streams, placeholders,
// unrecognized reparse points), a git topology blocker, an unauthorized
// route, or a vault/source containment violation. Nothing was captured
// for removal and nothing was removed.
type ErrDestructiveBlocked struct {
	Reasons []string
}

func (e *ErrDestructiveBlocked) Error() string {
	return "lifecycle: destructive operation blocked: " + strings.Join(e.Reasons, "; ")
}

// ErrSourceChanged reports revalidation failure (Foundation §12.2 step 6):
// the live source no longer matches the sealed inventory exactly, so
// removal is invalidated. The sealed P/S pair is retained (pinned) and
// the source is intact; a new capture is required after the user resolves
// the change.
type ErrSourceChanged struct {
	Diff []string
}

func (e *ErrSourceChanged) Error() string {
	return "lifecycle: source changed since capture; removal invalidated (P/S retained, source intact): " +
		strings.Join(e.Diff, "; ")
}

// ErrVerification reports a coverage or readback failure (Foundation
// §11.4, I04/I12). The payload may exist in the backend but is NOT a
// verified capture; per §11.3 it is retained as unsealed (never silently
// forgotten) and no removal is authorized.
type ErrVerification struct {
	Check   string // "coverage" | "readback"
	Details []string
}

func (e *ErrVerification) Error() string {
	return fmt.Sprintf("lifecycle: %s verification failed: %s", e.Check, strings.Join(e.Details, "; "))
}

// Removal blocker codes carried by ErrRemovalBlocked.
const (
	BlockSharingViolation = "EBB_E_SHARING_VIOLATION" // Windows errno 32: open handle
	BlockKindMismatch     = "EBB_E_KIND_MISMATCH"     // entry is not the sealed kind (reparse substitution)
	BlockDigestChanged    = "EBB_E_DIGEST_CHANGED"    // file content differs from the sealed digest (E08)
	BlockLinkChanged      = "EBB_E_LINK_CHANGED"      // link text differs from the sealed text
	BlockDirNotEmpty      = "EBB_E_DIR_NOT_EMPTY"     // new content appeared under a removal dir
	BlockProbeFailed      = "EBB_E_PROBE_FAILED"      // entry could not be re-observed
	BlockRemoveFailed     = "EBB_E_REMOVE_FAILED"     // os.Remove failed with an unclassified error
)

// ErrRemovalBlocked reports that the authorized removal walk stopped at
// Path (Foundation §12.2 step 8 / §12.3: "a blocked Windows handle is an
// error to retain and report"). Remaining entries are retained in the
// quarantine; the operation is REMOVAL_BLOCKED and P/S stay pinned. The
// walk is resumable with ResumeRemoval after the cause is resolved.
// OperationID (when the constructing site knows it) lets the CLI render
// a literally runnable recovery command instead of a placeholder.
type ErrRemovalBlocked struct {
	OperationID domain.OperationID
	Path        string
	Code        string
	Err         error
}

func (e *ErrRemovalBlocked) Error() string {
	msg := fmt.Sprintf("lifecycle: removal blocked at %s (%s)", e.Path, e.Code)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ErrRemovalBlocked) Unwrap() error { return e.Err }

// ErrInvalidOptions reports caller mistakes (empty root, missing
// WriterAssertion for park, unknown trim group...) before any durable
// side effect.
type ErrInvalidOptions struct {
	Detail string
}

func (e *ErrInvalidOptions) Error() string {
	return "lifecycle: invalid options: " + e.Detail
}

// ErrJournalMismatch reports durable-evidence inconsistencies found by
// Recover (identity not matching the journal, missing quarantine,
// snapshot pair disagreement). Recovery refuses to guess (I13).
type ErrJournalMismatch struct {
	Detail string
}

func (e *ErrJournalMismatch) Error() string {
	return "lifecycle: durable evidence inconsistent: " + e.Detail
}

// ErrCancelRefused reports that --cancel was refused because the
// operation sits in the §12.2 step-7 quarantine-rename crash window (or
// its aftermath): the deterministic quarantine sibling exists, so the
// workspace tree may be mid-rename at that path and canceling would
// strand it with no durable pointer (Wave G review finding G4). The
// sibling is probed EXISTENCE-ONLY and never touched regardless of
// identity; `ebb recover <op>` is the reconciliation path — it
// adopts-or-reports by native identity (F5/D020) and never deletes
// anything unrecognized. The operation's phase is unchanged.
type ErrCancelRefused struct {
	OperationID domain.OperationID
	Quarantine  string
}

func (e *ErrCancelRefused) Error() string {
	return fmt.Sprintf(
		"lifecycle: cancel of operation %s refused: the quarantine sibling %s EXISTS — the workspace may be mid-rename at the quarantine path (crash window between the \u00a712.2 step-7 rename and its journal commit); canceling now would strand the tree there with no durable pointer and this error never claims otherwise. Run `ebb recover %s` instead: it adopts-or-reports the sibling by identity (F5/D020)",
		e.OperationID, e.Quarantine, e.OperationID)
}

// errPayloadIncomplete is the internal marker wrapped into returned
// errors when a payload snapshot exists but failed verification, so the
// caller-facing text can state the §11.3 retention rule.
var errPayloadIncomplete = errors.New("payload retained unsealed per Foundation \u00a711.3 (never auto-erased; it may contain useful captured work)")
