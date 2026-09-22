package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// RecordApproval inserts a recorded local consent to run one exact
// action (Foundation §7.3). Missing id, approved-by and approved-at are
// filled in; a new record is always live (not revoked).
func (c *Catalog) RecordApproval(a Approval) (domain.ID, error) {
	if a.ID == "" {
		a.ID = domain.NewID()
	}
	if a.ActionID == "" {
		return "", errors.New("catalog: approval action id required")
	}
	if a.ArgvDigest == "" {
		return "", errors.New("catalog: approval argv digest required")
	}
	if a.InputDigests == "" {
		return "", errors.New("catalog: approval input digests required")
	}
	if a.ApprovedBy == "" {
		a.ApprovedBy = "user"
	}
	if a.ApprovedAt == "" {
		a.ApprovedAt = domain.FormatTime(time.Now())
	}
	return a.ID, withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO approvals
			(id, workspace_id, action_id, argv_digest, tool_identity, input_digests,
			 network, approved_by, approved_at, revoked_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`
		if _, err := tx.Exec(q, string(a.ID), nullStr(string(a.WorkspaceID)), a.ActionID,
			a.ArgvDigest, nullStr(a.ToolIdentity), a.InputDigests, nullStr(a.Network),
			a.ApprovedBy, a.ApprovedAt); err != nil {
			return fmt.Errorf("catalog: record approval: %w", err)
		}
		return nil
	})
}

// FindApproval returns the live (non-revoked) approval that exactly
// matches workspace, action, argv digest and input digests — the
// exact-match rule of Foundation §7.3: any drift in what would run or
// what it consumes is a different approval. When several rows match,
// the most recently approved wins. No match returns ErrNotFound.
func (c *Catalog) FindApproval(ws domain.WorkspaceID, actionID, argvDigest, inputDigests string) (Approval, error) {
	const q = `SELECT id, workspace_id, action_id, argv_digest, tool_identity, input_digests,
		network, approved_by, approved_at, revoked_at
		FROM approvals
		WHERE workspace_id IS ? AND action_id = ? AND argv_digest = ? AND input_digests = ?
		  AND revoked_at IS NULL
		ORDER BY approved_at DESC, id DESC
		LIMIT 1`
	a, err := scanApproval(c.db.QueryRow(q, nullStr(string(ws)), actionID, argvDigest, inputDigests))
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, fmt.Errorf("%w: live approval for action %s", ErrNotFound, actionID)
	}
	if err != nil {
		return Approval{}, fmt.Errorf("catalog: find approval for action %s: %w", actionID, err)
	}
	return a, nil
}

// RevokeApproval marks the approval revoked; revoked approvals never
// match FindApproval again. Revoking an already-revoked approval is a
// documented no-op (success); an unknown id returns ErrNotFound.
func (c *Catalog) RevokeApproval(id domain.ID) error {
	return withTx(c.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE approvals SET revoked_at = ?
			WHERE id = ? AND revoked_at IS NULL`, domain.FormatTime(time.Now()), string(id))
		if err != nil {
			return fmt.Errorf("catalog: revoke approval %s: %w", id, err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("catalog: revoke approval %s: rows affected: %w", id, err)
		} else if n == 0 {
			var one int
			err := tx.QueryRow(`SELECT 1 FROM approvals WHERE id = ?`, string(id)).Scan(&one)
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: approval %s", ErrNotFound, id)
			}
			if err != nil {
				return fmt.Errorf("catalog: revoke approval %s: exists check: %w", id, err)
			}
			// Already revoked: idempotent success.
			return nil
		}
		return nil
	})
}

func scanApproval(r rowScanner) (Approval, error) {
	var a Approval
	var workspaceID, toolIdentity, network, revokedAt sql.NullString
	if err := r.Scan(&a.ID, &workspaceID, &a.ActionID, &a.ArgvDigest, &toolIdentity,
		&a.InputDigests, &network, &a.ApprovedBy, &a.ApprovedAt, &revokedAt); err != nil {
		return Approval{}, err
	}
	a.WorkspaceID = domain.WorkspaceID(workspaceID.String)
	a.ToolIdentity = toolIdentity.String
	a.Network = network.String
	a.RevokedAt = revokedAt.String
	return a, nil
}
