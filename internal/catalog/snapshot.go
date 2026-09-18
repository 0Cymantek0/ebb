package catalog

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"ebb/internal/domain"
)

// RecordSnapshot inserts a new snapshot row. It always records the
// snapshot as pinned (I07: presumed retained) with reason "creation"
// first in the audit list, regardless of the pinned state passed in.
// The workspace must already exist (foreign key enforced).
func (c *Catalog) RecordSnapshot(s Snapshot) (domain.SnapshotID, error) {
	if s.ID == "" {
		s.ID = domain.SnapshotID(domain.NewID())
	}
	if s.WorkspaceID == "" {
		return "", errors.New("catalog: snapshot workspace id required")
	}
	if !validSnapshotKinds[s.Kind] {
		return "", fmt.Errorf("catalog: invalid snapshot kind %q", s.Kind)
	}
	if s.CreatedAt == "" {
		s.CreatedAt = domain.FormatTime(time.Now())
	}
	reasons, err := marshalReasons(prependReason(PinReasonCreation, s.PinReasons))
	if err != nil {
		return "", err
	}
	return s.ID, withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO snapshots
			(id, workspace_id, created_at, payload_backend_id, seal_backend_id, vault_id,
			 manifest_digest, inventory_digest, kind, pinned, pin_reasons)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
		if _, err := tx.Exec(q, string(s.ID), string(s.WorkspaceID), s.CreatedAt,
			nullStr(s.PayloadBackendID), nullStr(s.SealBackendID), nullStr(string(s.VaultID)),
			nullStr(s.ManifestDigest), nullStr(s.InventoryDigest), s.Kind, reasons); err != nil {
			return fmt.Errorf("catalog: record snapshot %s: %w", s.ID, err)
		}
		return nil
	})
}

// GetSnapshot returns the snapshot row for id, or ErrNotFound.
func (c *Catalog) GetSnapshot(id domain.SnapshotID) (Snapshot, error) {
	const q = `SELECT id, workspace_id, created_at, payload_backend_id, seal_backend_id, vault_id,
		manifest_digest, inventory_digest, kind, pinned, pin_reasons
		FROM snapshots WHERE id = ?`
	s, err := scanSnapshot(c.db.QueryRow(q, string(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, fmt.Errorf("%w: snapshot %s", ErrNotFound, id)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("catalog: get snapshot %s: %w", id, err)
	}
	return s, nil
}

// ListSnapshots returns the snapshots of one workspace in creation
// order.
func (c *Catalog) ListSnapshots(ws domain.WorkspaceID) ([]Snapshot, error) {
	const q = `SELECT id, workspace_id, created_at, payload_backend_id, seal_backend_id, vault_id,
		manifest_digest, inventory_digest, kind, pinned, pin_reasons
		FROM snapshots WHERE workspace_id = ? ORDER BY created_at, id`
	rows, err := c.db.Query(q, string(ws))
	if err != nil {
		return nil, fmt.Errorf("catalog: list snapshots of %s: %w", ws, err)
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		s, err := scanSnapshot(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: list snapshots of %s: %w", ws, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list snapshots of %s: %w", ws, err)
	}
	return out, nil
}

// Pin marks the snapshot pinned and appends the reason to the pin audit
// list. The reason must be non-empty.
func (c *Catalog) Pin(id domain.SnapshotID, reason string) error {
	if reason == "" {
		return errors.New("catalog: pin reason required")
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		s, err := getSnapshotForUpdate(tx, id)
		if err != nil {
			return err
		}
		reasons, err := marshalReasons(appendReason(s.PinReasons, "pin:"+reason))
		if err != nil {
			return err
		}
		const q = `UPDATE snapshots SET pinned = 1, pin_reasons = ? WHERE id = ?`
		if _, err := tx.Exec(q, reasons, string(id)); err != nil {
			return fmt.Errorf("catalog: pin snapshot %s: %w", id, err)
		}
		return nil
	})
}

// Unpin clears the snapshot's pinned state and records "unpin:<reason>"
// in the pin audit list. It refuses with ErrLastPinned when the snapshot
// is the last pinned snapshot of a live workspace (I07), unless force
// is set — force requires a non-empty reason, which is recorded.
func (c *Catalog) Unpin(id domain.SnapshotID, reason string, force bool) error {
	if reason == "" {
		return errors.New("catalog: unpin reason required")
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		s, err := getSnapshotForUpdate(tx, id)
		if err != nil {
			return err
		}
		if !s.Pinned {
			// Already unpinned; the audit trail keeps the original event.
			return nil
		}
		var status string
		if err := tx.QueryRow(`SELECT status FROM workspaces WHERE id = ?`,
			string(s.WorkspaceID)).Scan(&status); err != nil {
			return fmt.Errorf("catalog: unpin snapshot %s: workspace lookup: %w", id, err)
		}
		if !force && status == WorkspaceLive {
			var pinnedCount int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM snapshots
				WHERE workspace_id = ? AND pinned = 1`, string(s.WorkspaceID)).Scan(&pinnedCount); err != nil {
				return fmt.Errorf("catalog: unpin snapshot %s: pinned count: %w", id, err)
			}
			if pinnedCount <= 1 {
				return fmt.Errorf("%w: snapshot %s of workspace %s (pass force with an explicit reason to override)",
					ErrLastPinned, id, s.WorkspaceID)
			}
		}
		reasons, err := marshalReasons(appendReason(s.PinReasons, "unpin:"+reason))
		if err != nil {
			return err
		}
		const q = `UPDATE snapshots SET pinned = 0, pin_reasons = ? WHERE id = ?`
		if _, err := tx.Exec(q, reasons, string(id)); err != nil {
			return fmt.Errorf("catalog: unpin snapshot %s: %w", id, err)
		}
		return nil
	})
}

// ImportDiscoveredSnapshot records one snapshot discovered by vault
// recovery (Foundation §11.5). If the workspace row does not exist it is
// created with status UNBOUND and the snapshot's creation time —
// reconstruction never guesses live or parked (§16.5). Re-importing an
// already-known snapshot id refreshes the discovered backend facts
// (payload/seal ids, vault, digests, kind) but never touches the pinned
// state or the pin audit list.
func (c *Catalog) ImportDiscoveredSnapshot(wsID domain.WorkspaceID, wsName string, s Snapshot) error {
	if wsID == "" {
		return errors.New("catalog: discovered workspace id required")
	}
	if wsName == "" {
		return errors.New("catalog: discovered workspace name required")
	}
	if s.ID == "" {
		s.ID = domain.SnapshotID(domain.NewID())
	}
	s.WorkspaceID = wsID
	if !validSnapshotKinds[s.Kind] {
		return fmt.Errorf("catalog: invalid snapshot kind %q", s.Kind)
	}
	if s.CreatedAt == "" {
		s.CreatedAt = domain.FormatTime(time.Now())
	}
	reasons, err := marshalReasons(prependReason(PinReasonCreation, s.PinReasons))
	if err != nil {
		return err
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		// INSERT with conflict-do-nothing: an existing workspace row is
		// never modified by recovery — not even its display name.
		const wq = `INSERT INTO workspaces (id, name, created_at, root_path, root_identity, status)
			VALUES (?, ?, ?, NULL, NULL, ?)
			ON CONFLICT(id) DO NOTHING`
		if _, err := tx.Exec(wq, string(wsID), wsName, s.CreatedAt, WorkspaceUnbound); err != nil {
			return fmt.Errorf("catalog: import workspace %s: %w", wsID, err)
		}
		const sq = `INSERT INTO snapshots
			(id, workspace_id, created_at, payload_backend_id, seal_backend_id, vault_id,
			 manifest_digest, inventory_digest, kind, pinned, pin_reasons)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
			ON CONFLICT(id) DO UPDATE SET
				payload_backend_id = excluded.payload_backend_id,
				seal_backend_id = excluded.seal_backend_id,
				vault_id = excluded.vault_id,
				manifest_digest = excluded.manifest_digest,
				inventory_digest = excluded.inventory_digest,
				kind = excluded.kind`
		if _, err := tx.Exec(sq, string(s.ID), string(s.WorkspaceID), s.CreatedAt,
			nullStr(s.PayloadBackendID), nullStr(s.SealBackendID), nullStr(string(s.VaultID)),
			nullStr(s.ManifestDigest), nullStr(s.InventoryDigest), s.Kind, reasons); err != nil {
			return fmt.Errorf("catalog: import snapshot %s: %w", s.ID, err)
		}
		return nil
	})
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanSnapshot(r rowScanner) (Snapshot, error) {
	var s Snapshot
	var payload, seal, vaultID, manifest, inventory sql.NullString
	var pinned int64
	var reasonsJSON string
	if err := r.Scan(&s.ID, &s.WorkspaceID, &s.CreatedAt, &payload, &seal, &vaultID,
		&manifest, &inventory, &s.Kind, &pinned, &reasonsJSON); err != nil {
		return Snapshot{}, err
	}
	s.PayloadBackendID, s.SealBackendID = payload.String, seal.String
	s.VaultID = domain.VaultID(vaultID.String)
	s.ManifestDigest, s.InventoryDigest = manifest.String, inventory.String
	s.Pinned = pinned != 0
	var reasons []string
	if err := json.Unmarshal([]byte(reasonsJSON), &reasons); err != nil {
		return Snapshot{}, fmt.Errorf("catalog: snapshot %s pin_reasons: %w", s.ID, err)
	}
	s.PinReasons = reasons
	return s, nil
}

func getSnapshotForUpdate(tx *sql.Tx, id domain.SnapshotID) (Snapshot, error) {
	const q = `SELECT id, workspace_id, created_at, payload_backend_id, seal_backend_id, vault_id,
		manifest_digest, inventory_digest, kind, pinned, pin_reasons
		FROM snapshots WHERE id = ?`
	s, err := scanSnapshot(tx.QueryRow(q, string(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, fmt.Errorf("%w: snapshot %s", ErrNotFound, id)
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("catalog: get snapshot %s: %w", id, err)
	}
	return s, nil
}

// prependReason returns want followed by the rest, without duplicates.
func prependReason(want string, rest []string) []string {
	out := []string{want}
	for _, r := range rest {
		if r != want {
			out = append(out, r)
		}
	}
	return out
}

// appendReason returns in with want appended when not already present.
func appendReason(in []string, want string) []string {
	for _, r := range in {
		if r == want {
			return in
		}
	}
	return append(append([]string{}, in...), want)
}

func marshalReasons(reasons []string) (string, error) {
	b, err := json.Marshal(reasons)
	if err != nil {
		return "", fmt.Errorf("catalog: pin reasons: %w", err)
	}
	return string(b), nil
}
