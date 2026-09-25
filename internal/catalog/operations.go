package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// BeginOperation opens a new journaled operation in phase PLANNED at
// generation 1 (Foundation §12.2 step 1: identities, locks and intent
// are resolved before any durable side effect). The workspace must
// exist; sourceRoot/sourceIdentity record the operation's root identity
// (§12.1: a path alone cannot distinguish a replaced directory).
func (c *Catalog) BeginOperation(ws domain.WorkspaceID, kind, sourceRoot, sourceIdentity, intentDigest string) (domain.OperationID, error) {
	if ws == "" {
		return "", errors.New("catalog: operation workspace id required")
	}
	if !validOpKinds[kind] {
		return "", fmt.Errorf("catalog: invalid operation kind %q", kind)
	}
	id := domain.OperationID(domain.NewID())
	now := domain.FormatTime(time.Now())
	return id, withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO operations
			(id, workspace_id, kind, phase, generation, source_root, source_identity,
			 intent_digest, started_at, updated_at)
			VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`
		if _, err := tx.Exec(q, string(id), string(ws), kind, PhasePlanned,
			nullStr(sourceRoot), nullStr(sourceIdentity), nullStr(intentDigest), now, now); err != nil {
			return fmt.Errorf("catalog: begin operation: %w", err)
		}
		return nil
	})
}

// AdvanceOperation transitions the operation's phase with a
// compare-and-swap guard (Foundation §12.4): the update only applies
// when the row still carries fromPhase at the generation previously
// read. On any mismatch it returns ErrCASConflict and never retries
// internally — the caller re-reads the journal and reconciles.
func (c *Catalog) AdvanceOperation(id domain.OperationID, fromPhase, toPhase string) error {
	if !validPhases[fromPhase] {
		return fmt.Errorf("catalog: invalid from-phase %q", fromPhase)
	}
	if !validPhases[toPhase] {
		return fmt.Errorf("catalog: invalid to-phase %q", toPhase)
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		var phase string
		var generation int64
		err := tx.QueryRow(`SELECT phase, generation FROM operations WHERE id = ?`, string(id)).
			Scan(&phase, &generation)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: operation %s", ErrNotFound, id)
		}
		if err != nil {
			return fmt.Errorf("catalog: advance operation %s: read: %w", id, err)
		}
		if phase != fromPhase {
			return fmt.Errorf("%w: operation %s is %s at generation %d, not %s",
				ErrCASConflict, id, phase, generation, fromPhase)
		}
		res, err := tx.Exec(`UPDATE operations
			SET phase = ?, generation = generation + 1, updated_at = ?
			WHERE id = ? AND phase = ? AND generation = ?`,
			toPhase, domain.FormatTime(time.Now()), string(id), fromPhase, generation)
		if err != nil {
			return fmt.Errorf("catalog: advance operation %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("catalog: advance operation %s: rows affected: %w", id, err)
		} else if n == 0 {
			return fmt.Errorf("%w: operation %s changed between read and update",
				ErrCASConflict, id)
		}
		return nil
	})
}

// FailOperation records errMsg as the operation's last_error, guarded
// by the expected phase, WITHOUT changing the phase: failure is an
// observation on the journal, not a transition (the phase walk to
// REMOVAL_BLOCKED or REBUILD_FAILED remains an explicit
// AdvanceOperation). A phase mismatch returns ErrCASConflict.
func (c *Catalog) FailOperation(id domain.OperationID, phase, errMsg string) error {
	if !validPhases[phase] {
		return fmt.Errorf("catalog: invalid phase %q", phase)
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE operations SET last_error = ?, updated_at = ?
			WHERE id = ? AND phase = ?`, errMsg, domain.FormatTime(time.Now()), string(id), phase)
		if err != nil {
			return fmt.Errorf("catalog: fail operation %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("catalog: fail operation %s: rows affected: %w", id, err)
		} else if n == 0 {
			if err := operationExists(tx, id); err != nil {
				return err
			}
			return fmt.Errorf("%w: operation %s is not in phase %s", ErrCASConflict, id, phase)
		}
		return nil
	})
}

// SetForgetTarget records the LOGICAL identity of a forget operation's
// target (snapshot id) alongside the backend pair (schemaV5): backend
// ids identify physical objects; the snapshot id identifies the logical
// recovery obligation whose unpin/retention this operation releases.
// Rerun adoption compares all three.
func (c *Catalog) SetForgetTarget(id domain.OperationID, snapID, payload, seal string) error {
	return withTx(c.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE operations
			SET snap_id = ?, payload_snap = ?, seal_snap = ?, updated_at = ?
			WHERE id = ?`, nullStr(snapID), nullStr(payload), nullStr(seal), domain.FormatTime(time.Now()), string(id))
		if err != nil {
			return fmt.Errorf("catalog: set forget target of %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("catalog: set forget target of %s: rows affected: %w", id, err)
		} else if n == 0 {
			return fmt.Errorf("%w: operation %s", ErrNotFound, id)
		}
		return nil
	})
}

// SetBackendRefs records the committed payload and seal backend
// snapshot ids on the operation (§12.2 steps 4-5). It does not guard on
// phase: the P id is recorded right after capture, the S id after the
// seal readback, with phase transitions carrying the ordering contract.
func (c *Catalog) SetBackendRefs(id domain.OperationID, payload, seal string) error {
	return withTx(c.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE operations
			SET payload_snap = ?, seal_snap = ?, updated_at = ?
			WHERE id = ?`, nullStr(payload), nullStr(seal), domain.FormatTime(time.Now()), string(id))
		if err != nil {
			return fmt.Errorf("catalog: set backend refs of %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("catalog: set backend refs of %s: rows affected: %w", id, err)
		} else if n == 0 {
			return fmt.Errorf("%w: operation %s", ErrNotFound, id)
		}
		return nil
	})
}

// GetOperation returns the journal row for id, or ErrNotFound.
func (c *Catalog) GetOperation(id domain.OperationID) (Operation, error) {
	op, err := scanOperation(c.db.QueryRow(operationSelect+` WHERE id = ?`, string(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, fmt.Errorf("%w: operation %s", ErrNotFound, id)
	}
	if err != nil {
		return Operation{}, fmt.Errorf("catalog: get operation %s: %w", id, err)
	}
	return op, nil
}

// ActiveOperations returns the workspace's operations that are not in a
// terminal phase (CANCELED, DONE, TRIM_DONE) — the rows crash recovery
// must reconcile. An empty workspace id returns active operations of all
// workspaces.
func (c *Catalog) ActiveOperations(ws domain.WorkspaceID) ([]Operation, error) {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(terminalPhases)), ",")
	args := make([]any, 0, len(terminalPhases)+1)
	q := operationSelect
	if ws != "" {
		q += ` WHERE workspace_id = ? AND phase NOT IN (` + placeholders + `)`
		args = append(args, string(ws))
	} else {
		q += ` WHERE phase NOT IN (` + placeholders + `)`
	}
	for _, p := range terminalPhases {
		args = append(args, p)
	}
	q += ` ORDER BY updated_at, id`
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("catalog: active operations of %s: %w", ws, err)
	}
	defer rows.Close()
	var out []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: active operations of %s: %w", ws, err)
		}
		out = append(out, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: active operations of %s: %w", ws, err)
	}
	return out, nil
}

// ListOperations returns every operation row of one workspace in any
// phase (terminal included), ordered by recency then id. An empty
// workspace id lists the operations of all workspaces (mirroring
// ActiveOperations). Preflight uses it to recognize destinations a
// completed open already published at.
func (c *Catalog) ListOperations(ws domain.WorkspaceID) ([]Operation, error) {
	q := operationSelect
	var args []any
	if ws != "" {
		q += ` WHERE workspace_id = ?`
		args = append(args, string(ws))
	}
	q += ` ORDER BY updated_at, id`
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("catalog: list operations of %s: %w", ws, err)
	}
	defer rows.Close()
	var out []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: list operations of %s: %w", ws, err)
		}
		out = append(out, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list operations of %s: %w", ws, err)
	}
	return out, nil
}

const operationSelect = `SELECT id, workspace_id, kind, phase, generation, source_root, source_identity,
	dest_path, payload_snap, seal_snap, snap_id, intent_digest, last_error, next_action, started_at, updated_at
	FROM operations`

func scanOperation(r rowScanner) (Operation, error) {
	var op Operation
	var workspaceID, sourceRoot, sourceIdentity, destPath, payloadSnap, sealSnap,
		snapID, intentDigest, lastError, nextAction sql.NullString
	if err := r.Scan(&op.ID, &workspaceID, &op.Kind, &op.Phase, &op.Generation,
		&sourceRoot, &sourceIdentity, &destPath, &payloadSnap, &sealSnap, &snapID,
		&intentDigest, &lastError, &nextAction, &op.StartedAt, &op.UpdatedAt); err != nil {
		return Operation{}, err
	}
	op.SnapID = snapID.String
	op.WorkspaceID = domain.WorkspaceID(workspaceID.String)
	op.SourceRoot = sourceRoot.String
	op.SourceIdentity = sourceIdentity.String
	op.DestPath = destPath.String
	op.PayloadSnap = payloadSnap.String
	op.SealSnap = sealSnap.String
	op.IntentDigest = intentDigest.String
	op.LastError = lastError.String
	op.NextAction = nextAction.String
	return op, nil
}

func operationExists(tx *sql.Tx, id domain.OperationID) error {
	var one int
	err := tx.QueryRow(`SELECT 1 FROM operations WHERE id = ?`, string(id)).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: operation %s", ErrNotFound, id)
	}
	if err != nil {
		return fmt.Errorf("catalog: operation %s exists check: %w", id, err)
	}
	return nil
}
