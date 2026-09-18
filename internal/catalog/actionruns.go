package catalog

// action_runs journaling (Foundation §16.5): one durable row per
// recovery-action ATTEMPT executed by an open operation's rebuild phase
// (Foundation §12.5 last paragraphs). A row is inserted when the attempt
// starts (status "running") and finished with its terminal status, so a
// crash mid-action leaves a visible "running" row that resume treats as
// NOT successful and re-runs.

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"ebb/internal/domain"
)

// Action run status vocabulary (closed set enforced at the API edge).
//
//   - ActionRunRunning: the attempt started and has no terminal record
//     (a crash mid-action leaves this behind; resume re-runs it).
//   - ActionRunSucceeded: the action exited 0, produced every declared
//     output and passed the F36 protected-file check of its phase.
//   - ActionRunFailed: non-zero exit, timeout, missing outputs, missing
//     tool, declined approval or protected-file mismatch.
//   - ActionRunCancelled: the caller's context was cancelled mid-action
//     (the running child completes/kills first; the row records what
//     was observable).
const (
	ActionRunRunning   = "running"
	ActionRunSucceeded = "succeeded"
	ActionRunFailed    = "failed"
	ActionRunCancelled = "cancelled"
)

var validActionRunStatus = map[string]bool{
	ActionRunRunning:   true,
	ActionRunSucceeded: true,
	ActionRunFailed:    true,
	ActionRunCancelled: true,
}

// ActionRun is one row of the action_runs table: one recorded attempt of
// one recovery action inside one operation. ExitCode is the child's
// observable exit code (-1 when it could not be observed or no child
// ran); OutputExcerpt is the bounded capture stored verbatim.
type ActionRun struct {
	ID            domain.ID
	OperationID   domain.OperationID
	ActionID      string
	Status        string
	ExitCode      int
	StartedAt     string // RFC3339Nano UTC
	EndedAt       string // RFC3339Nano UTC, "" while running
	OutputExcerpt string
}

// StartActionRun inserts one "running" row for an attempt of actionID
// inside opID and returns its row id.
func (c *Catalog) StartActionRun(opID domain.OperationID, actionID string) (domain.ID, error) {
	if actionID == "" {
		return "", errors.New("catalog: action run action id required")
	}
	id := domain.NewID()
	now := domain.FormatTime(time.Now())
	return id, withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO action_runs (id, operation_id, action_id, status, exit_code, started_at)
			VALUES (?, ?, ?, ?, -1, ?)`
		if _, err := tx.Exec(q, string(id), string(opID), actionID, ActionRunRunning, now); err != nil {
			return fmt.Errorf("catalog: start action run: %w", err)
		}
		return nil
	})
}

// FinishActionRun records the terminal status of one attempt. status
// must be one of the terminal statuses (succeeded/failed/cancelled);
// finishing a row that is already terminal is rejected (one attempt has
// exactly one outcome). exitCode is the child's exit code (-1 when not
// observable); excerpt is the bounded output capture (may be empty).
func (c *Catalog) FinishActionRun(id domain.ID, status string, exitCode int, excerpt string) error {
	if !validActionRunStatus[status] || status == ActionRunRunning {
		return fmt.Errorf("catalog: finish action run: invalid terminal status %q", status)
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE action_runs
			SET status = ?, exit_code = ?, ended_at = ?, output_excerpt = ?
			WHERE id = ? AND status = ?`,
			status, exitCode, domain.FormatTime(time.Now()), excerpt, string(id), ActionRunRunning)
		if err != nil {
			return fmt.Errorf("catalog: finish action run %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("catalog: finish action run %s: rows affected: %w", id, err)
		} else if n == 0 {
			var st string
			qerr := tx.QueryRow(`SELECT status FROM action_runs WHERE id = ?`, string(id)).Scan(&st)
			if errors.Is(qerr, sql.ErrNoRows) {
				return fmt.Errorf("%w: action run %s", ErrNotFound, id)
			}
			if qerr != nil {
				return fmt.Errorf("catalog: finish action run %s: exists check: %w", id, qerr)
			}
			return fmt.Errorf("%w: action run %s already finished with status %q", ErrCASConflict, id, st)
		}
		return nil
	})
}

// ListActionRuns returns every recorded attempt of one operation, in
// start order (oldest first). An operation with no runs returns an empty
// slice.
func (c *Catalog) ListActionRuns(opID domain.OperationID) ([]ActionRun, error) {
	rows, err := c.db.Query(`SELECT id, operation_id, action_id, status, exit_code,
		started_at, ended_at, output_excerpt
		FROM action_runs WHERE operation_id = ?
		ORDER BY started_at, id`, string(opID))
	if err != nil {
		return nil, fmt.Errorf("catalog: list action runs of %s: %w", opID, err)
	}
	defer rows.Close()
	var out []ActionRun
	for rows.Next() {
		var r ActionRun
		var op, endedAt, excerpt sql.NullString
		if err := rows.Scan(&r.ID, &op, &r.ActionID, &r.Status, &r.ExitCode,
			&r.StartedAt, &endedAt, &excerpt); err != nil {
			return nil, fmt.Errorf("catalog: list action runs of %s: %w", opID, err)
		}
		r.OperationID = domain.OperationID(op.String)
		r.EndedAt = endedAt.String
		r.OutputExcerpt = excerpt.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list action runs of %s: %w", opID, err)
	}
	return out, nil
}

// SucceededActions returns the set of action ids with at least one
// recorded successful run inside opID. Resume uses it to never re-run a
// succeeded action automatically (Foundation §12.5).
func (c *Catalog) SucceededActions(opID domain.OperationID) (map[string]bool, error) {
	runs, err := c.ListActionRuns(opID)
	if err != nil {
		return nil, err
	}
	succeeded := map[string]bool{}
	for _, r := range runs {
		if r.Status == ActionRunSucceeded {
			succeeded[r.ActionID] = true
		}
	}
	return succeeded, nil
}
