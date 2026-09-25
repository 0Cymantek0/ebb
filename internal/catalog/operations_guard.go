// operations_guard.go holds the atomic operation-begin primitive and the
// forget operation's dedicated phase vocabulary (Wave 5 safety wave,
// E11 follow-up).
//
// BeginOperation itself is one INSERT; the single-active-operation check
// lived at the CALLER (lifecycle.beginOperation: ActiveOperations, then
// BeginOperation) — two transactions, with the §12.1 race window its own
// comment documents: two simultaneous invocations could both pass.
// BeginOperationIfNoActive performs the check and the insert as ONE
// SQLite transaction. The catalog's pooled connections already take
// BEGIN IMMEDIATE (catalog.go's _txlock=immediate DSN parameter), so
// concurrent writers serialize on SQLite's write lock and only one
// caller can observe "no active operation" and insert.
//
// Honest scope (deliberately no more than this): the primitive makes
// concurrent EBB invocations that begin through it mutually exclusive at
// the CATALOG level — one active operation row per workspace. External
// vault mutation (restic run by hand, another tool writing the
// repository) was never inside Ebb's coordination contract and remains
// outside it.
//
// The forget vocabulary (Foundation §12.4 discipline applied to a kind
// that performs destructive work mid-flow): each phase commit is a CAS
// transition that names a DURABLE state already reached, so a crashed
// forget leaves a row that says exactly what happened — and cancel
// ("nothing destructive happened") stops being a valid reading once the
// snapshot is unpinned:
//
//	FORGET_PLANNED → FORGET_INTENT_RECORDED → FORGET_UNPINNED →
//	FORGET_BACKEND_FORGOTTEN → FORGET_DONE (terminal)
//
// The retention_intents row remains the authoritative evidence of the
// release obligation (§16.6); the operation row records orchestration
// state only.

package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// ErrActiveOperation reports a refused BeginOperationIfNoActive: the
// workspace already holds a non-terminal operation row. Match with
// errors.Is; the holder row read inside the refusing transaction is
// available on *ActiveOperationError.
var ErrActiveOperation = errors.New("catalog: workspace already has an active operation")

// ActiveOperationError is the typed refusal of BeginOperationIfNoActive.
// Operation identifies the holder: id and kind for messages, phase for
// the caller's adopt-or-refuse decision.
type ActiveOperationError struct {
	Operation Operation
}

func (e *ActiveOperationError) Error() string {
	return fmt.Sprintf("%s: operation %s (kind %s, phase %s) holds workspace %s",
		ErrActiveOperation, e.Operation.ID, e.Operation.Kind, e.Operation.Phase, e.Operation.WorkspaceID)
}

func (e *ActiveOperationError) Unwrap() error { return ErrActiveOperation }

// Forget operation phases (kind "forget"): each names durable evidence
// that already exists, never an intention. FORGET_UNPINNED and past are
// POST-DESTRUCTION states — the recovery obligation was already released
// locally — so from there the only valid exits are the idempotent rerun
// (which adopts the row) or reporting; a generic cancel would reason
// from a false "nothing destructive happened" invariant.
const (
	PhaseForgetPlanned          = "FORGET_PLANNED"
	PhaseForgetIntentRecorded   = "FORGET_INTENT_RECORDED"
	PhaseForgetUnpinned         = "FORGET_UNPINNED"
	PhaseForgetBackendForgotten = "FORGET_BACKEND_FORGOTTEN"
	PhaseForgetDone             = "FORGET_DONE"
)

// forgetPhaseOrder is the causal order of the forget walk. It lives in
// one slice so the rank helper and future readers cannot drift.
var forgetPhaseOrder = []string{
	PhaseForgetPlanned,
	PhaseForgetIntentRecorded,
	PhaseForgetUnpinned,
	PhaseForgetBackendForgotten,
	PhaseForgetDone,
}

// ForgetPhaseRank orders the forget vocabulary (later durable state
// ranks higher; FORGET_DONE ranks highest). Any phase outside the
// vocabulary ranks -1, so a rank comparison against a foreign phase
// never reads as "already reached".
func ForgetPhaseRank(phase string) int {
	for i, p := range forgetPhaseOrder {
		if p == phase {
			return i
		}
	}
	return -1
}

// The phase vocabulary tables are central in records.go; this wave's
// registrations ride an init here to keep the footprint additive (the
// wave's file ownership concentrates forget changes in this file).
// Go runs package init exactly once per process, so both tables are
// complete before any use.
func init() {
	for _, p := range forgetPhaseOrder {
		validPhases[p] = true
	}
	terminalPhases = append(terminalPhases, PhaseForgetDone)
}

// BeginOperationIfNoActive opens a new journaled operation ONLY when the
// workspace holds no active (non-terminal) operation — the check and the
// INSERT are one IMMEDIATE transaction, closing the check-then-begin
// race window the caller-side pattern had (§12.1). kind must be in the
// operation kind vocabulary; startPhase must be in the phase vocabulary
// ("" means the generic PhasePlanned — kinds with a dedicated vocabulary
// pass their own first phase, e.g. PhaseForgetPlanned).
//
// On success it returns the created row. When an operation is already
// active it returns an *ActiveOperationError (errors.Is
// ErrActiveOperation) carrying the holder row; nothing is inserted.
func (c *Catalog) BeginOperationIfNoActive(ws domain.WorkspaceID, kind, startPhase string) (Operation, error) {
	if ws == "" {
		return Operation{}, errors.New("catalog: operation workspace id required")
	}
	if !validOpKinds[kind] {
		return Operation{}, fmt.Errorf("catalog: invalid operation kind %q", kind)
	}
	if startPhase == "" {
		startPhase = PhasePlanned
	}
	if !validPhases[startPhase] {
		return Operation{}, fmt.Errorf("catalog: invalid start phase %q", startPhase)
	}
	id := domain.OperationID(domain.NewID())
	now := domain.FormatTime(time.Now())
	var created Operation
	err := withTx(c.db, func(tx *sql.Tx) error {
		holder, err := firstActiveOperationTx(tx, ws)
		if err != nil {
			return err
		}
		if holder != nil {
			return &ActiveOperationError{Operation: *holder}
		}
		const q = `INSERT INTO operations
			(id, workspace_id, kind, phase, generation, source_root, source_identity,
			 intent_digest, started_at, updated_at)
			VALUES (?, ?, ?, ?, 1, NULL, NULL, NULL, ?, ?)`
		if _, err := tx.Exec(q, string(id), string(ws), kind, startPhase, now, now); err != nil {
			return fmt.Errorf("catalog: begin operation if no active: %w", err)
		}
		created = Operation{
			ID: id, WorkspaceID: ws, Kind: kind, Phase: startPhase,
			Generation: 1, StartedAt: now, UpdatedAt: now,
		}
		return nil
	})
	if err != nil {
		return Operation{}, err
	}
	return created, nil
}

// firstActiveOperationTx returns the workspace's oldest active operation
// row (the holder a refusal names), or nil when none is active. It runs
// inside the caller's transaction — under BEGIN IMMEDIATE this read and
// the guarded insert are serialized against every other writer.
func firstActiveOperationTx(tx *sql.Tx, ws domain.WorkspaceID) (*Operation, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(terminalPhases)), ",")
	args := make([]any, 0, len(terminalPhases)+1)
	args = append(args, string(ws))
	for _, p := range terminalPhases {
		args = append(args, p)
	}
	q := operationSelect + ` WHERE workspace_id = ? AND phase NOT IN (` + placeholders + `)
		ORDER BY started_at, id LIMIT 1`
	op, err := scanOperation(tx.QueryRow(q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("catalog: active operation check of %s: %w", ws, err)
	}
	return &op, nil
}
