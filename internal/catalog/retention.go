package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// CreateRetentionIntent durably records the explicit, acknowledged loss
// of one snapshot's recovery obligation (Foundation §16.6) BEFORE the
// backend pair is forgotten. The intent is created already acknowledged
// ('1'): the caller may only invoke this after obtaining the operator's
// acknowledgement. The snapshot must exist.
func (c *Catalog) CreateRetentionIntent(snapshotID domain.SnapshotID, requestedBy string) (domain.ID, error) {
	id := domain.NewID()
	return id, withTx(c.db, func(tx *sql.Tx) error {
		var one int
		err := tx.QueryRow(`SELECT 1 FROM snapshots WHERE id = ?`, string(snapshotID)).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: snapshot %s", ErrNotFound, snapshotID)
		}
		if err != nil {
			return fmt.Errorf("catalog: retention intent for %s: snapshot check: %w", snapshotID, err)
		}
		const q = `INSERT INTO retention_intents
			(id, snapshot_id, requested_by, acknowledged, created_at)
			VALUES (?, ?, ?, '1', ?)`
		if _, err := tx.Exec(q, string(id), string(snapshotID), nullStr(requestedBy),
			domain.FormatTime(time.Now())); err != nil {
			return fmt.Errorf("catalog: retention intent for %s: %w", snapshotID, err)
		}
		return nil
	})
}

// CompleteRetentionIntent marks the intent completed: the backend
// forget/prune for the named pair finished. Completing an
// already-completed intent is a documented no-op (success); an unknown
// id returns ErrNotFound.
func (c *Catalog) CompleteRetentionIntent(id domain.ID) error {
	return withTx(c.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE retention_intents SET completed_at = ?
			WHERE id = ? AND completed_at IS NULL`, domain.FormatTime(time.Now()), string(id))
		if err != nil {
			return fmt.Errorf("catalog: complete retention intent %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("catalog: complete retention intent %s: rows affected: %w", id, err)
		} else if n == 0 {
			var one int
			err := tx.QueryRow(`SELECT 1 FROM retention_intents WHERE id = ?`, string(id)).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: retention intent %s", ErrNotFound, id)
			}
			if err != nil {
				return fmt.Errorf("catalog: complete retention intent %s: exists check: %w", id, err)
			}
			// Already completed: idempotent success.
			return nil
		}
		return nil
	})
}

// PendingRetentionIntents returns intents whose backend forget has not
// completed — an interrupted forget stays visible (Foundation §16.6).
func (c *Catalog) PendingRetentionIntents() ([]RetentionIntent, error) {
	const q = `SELECT id, snapshot_id, requested_by, acknowledged, created_at, completed_at
		FROM retention_intents WHERE completed_at IS NULL ORDER BY created_at, id`
	rows, err := c.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("catalog: pending retention intents: %w", err)
	}
	defer rows.Close()
	var out []RetentionIntent
	for rows.Next() {
		var ri RetentionIntent
		var requestedBy, completedAt sql.NullString
		var acknowledged string
		if err := rows.Scan(&ri.ID, &ri.SnapshotID, &requestedBy, &acknowledged,
			&ri.CreatedAt, &completedAt); err != nil {
			return nil, fmt.Errorf("catalog: pending retention intents: %w", err)
		}
		ri.RequestedBy = requestedBy.String
		ri.Acknowledged = acknowledged == "1"
		ri.CompletedAt = completedAt.String
		out = append(out, ri)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: pending retention intents: %w", err)
	}
	return out, nil
}
