package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"ebb/internal/domain"
)

// UpsertWorkspace inserts the workspace, or rebinds name, root and
// status when the id already exists (created_at is preserved). An empty
// status defaults to UNBOUND — catalog code never guesses liveness
// (Foundation §16.5).
func (c *Catalog) UpsertWorkspace(w Workspace) error {
	if w.ID == "" {
		return errors.New("catalog: workspace id required")
	}
	if w.Status == "" {
		w.Status = WorkspaceUnbound
	}
	switch w.Status {
	case WorkspaceLive, WorkspaceParked, WorkspaceUnbound:
	default:
		return fmt.Errorf("catalog: invalid workspace status %q", w.Status)
	}
	if w.CreatedAt == "" {
		w.CreatedAt = domain.FormatTime(time.Now())
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO workspaces (id, name, created_at, root_path, root_identity, status)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name = excluded.name,
				root_path = excluded.root_path,
				root_identity = excluded.root_identity,
				status = excluded.status`
		if _, err := tx.Exec(q, string(w.ID), w.Name, w.CreatedAt,
			nullStr(w.RootPath), nullStr(w.RootIdentity), w.Status); err != nil {
			return fmt.Errorf("catalog: upsert workspace %s: %w", w.ID, err)
		}
		return nil
	})
}

// GetWorkspace returns the workspace row for id, or ErrNotFound.
func (c *Catalog) GetWorkspace(id domain.WorkspaceID) (Workspace, error) {
	const q = `SELECT id, name, created_at, root_path, root_identity, status
		FROM workspaces WHERE id = ?`
	var w Workspace
	var rootPath, rootIdentity sql.NullString
	err := c.db.QueryRow(q, string(id)).Scan(
		&w.ID, &w.Name, &w.CreatedAt, &rootPath, &rootIdentity, &w.Status)
	if errors.Is(err, sql.ErrNoRows) {
		return Workspace{}, fmt.Errorf("%w: workspace %s", ErrNotFound, id)
	}
	if err != nil {
		return Workspace{}, fmt.Errorf("catalog: get workspace %s: %w", id, err)
	}
	w.RootPath, w.RootIdentity = rootPath.String, rootIdentity.String
	return w, nil
}

// RegisterVault inserts the vault, or updates path/repo_id/kind when
// the id already exists (registered_at is preserved). Kind defaults to
// "local".
func (c *Catalog) RegisterVault(v Vault) error {
	if v.ID == "" {
		return errors.New("catalog: vault id required")
	}
	if v.Path == "" {
		return errors.New("catalog: vault path required")
	}
	if v.Kind == "" {
		v.Kind = "local"
	}
	if v.RegisteredAt == "" {
		v.RegisteredAt = domain.FormatTime(time.Now())
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO vaults (id, path, repo_id, kind, registered_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				path = excluded.path,
				repo_id = excluded.repo_id,
				kind = excluded.kind`
		if _, err := tx.Exec(q, string(v.ID), v.Path, nullStr(v.RepoID), v.Kind, v.RegisteredAt); err != nil {
			return fmt.Errorf("catalog: register vault %s: %w", v.ID, err)
		}
		return nil
	})
}

// GetVault returns the vault row for id, or ErrNotFound.
func (c *Catalog) GetVault(id domain.VaultID) (Vault, error) {
	const q = `SELECT id, path, repo_id, kind, registered_at
		FROM vaults WHERE id = ?`
	var v Vault
	var repoID sql.NullString
	err := c.db.QueryRow(q, string(id)).Scan(&v.ID, &v.Path, &repoID, &v.Kind, &v.RegisteredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Vault{}, fmt.Errorf("%w: vault %s", ErrNotFound, id)
	}
	if err != nil {
		return Vault{}, fmt.Errorf("catalog: get vault %s: %w", id, err)
	}
	v.RepoID = repoID.String
	return v, nil
}

// WorkspacesForVault returns the distinct workspaces having at least one
// snapshot stored in the given vault. It is the reconciliation query
// behind vault recovery: "which workspaces does this vault hold evidence
// for?" (Foundation §11.5).
func (c *Catalog) WorkspacesForVault(vaultID domain.VaultID) ([]domain.WorkspaceID, error) {
	const q = `SELECT DISTINCT workspace_id FROM snapshots
		WHERE vault_id = ? ORDER BY workspace_id`
	rows, err := c.db.Query(q, string(vaultID))
	if err != nil {
		return nil, fmt.Errorf("catalog: workspaces for vault %s: %w", vaultID, err)
	}
	defer rows.Close()
	var ids []domain.WorkspaceID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("catalog: workspaces for vault %s: %w", vaultID, err)
		}
		ids = append(ids, domain.WorkspaceID(id))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: workspaces for vault %s: %w", vaultID, err)
	}
	return ids, nil
}
