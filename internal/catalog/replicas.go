package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"ebb/internal/domain"
)

// replicas.go records VERIFIED independent recovery copies (Foundation
// §15.5): "replication creates and verifies a destination seal, then
// records a replica receipt containing repository identity, payload
// identity, verification scope and time. URLs or object-store
// acknowledgments alone do not count as a verified independent recovery
// copy." Wave H's portable capsules record one row per produced capsule
// file (VaultID empty, Path set — the capsule repository's identity and
// payload id live inside the capsule's destination seal, not in this
// plaintext catalog).

// RecordReplica inserts one replica receipt. The snapshot must exist.
// A capsule replica (empty VaultID, non-empty Path) and a vault replica
// (non-empty VaultID, empty Path) are both accepted; anything else is an
// argument error so the two identity shapes can never be silently
// conflated.
func (c *Catalog) RecordReplica(r Replica) (domain.ID, error) {
	if r.SnapshotID == "" {
		return "", errors.New("catalog: replica snapshot id required")
	}
	capsule := r.VaultID == "" && r.Path != ""
	vaultRep := r.VaultID != "" && r.Path == ""
	if !capsule && !vaultRep {
		return "", errors.New("catalog: replica must be either a vault replica (vault id, no path) or a capsule replica (path, no vault id)")
	}
	if r.VerifiedAt == "" {
		r.VerifiedAt = domain.FormatTime(time.Now())
	}
	id := r.ID
	if id == "" {
		id = domain.NewID()
	}
	return id, withTx(c.db, func(tx *sql.Tx) error {
		var one int
		err := tx.QueryRow(`SELECT 1 FROM snapshots WHERE id = ?`, string(r.SnapshotID)).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: snapshot %s", ErrNotFound, r.SnapshotID)
		}
		if err != nil {
			return fmt.Errorf("catalog: replica for %s: snapshot check: %w", r.SnapshotID, err)
		}
		const q = `INSERT INTO replicas (id, snapshot_id, vault_id, verified_at, scope, path)
			VALUES (?, ?, ?, ?, ?, ?)`
		if _, err := tx.Exec(q, string(id), string(r.SnapshotID), nullStr(string(r.VaultID)),
			r.VerifiedAt, nullStr(r.Scope), nullStr(r.Path)); err != nil {
			return fmt.Errorf("catalog: record replica for %s: %w", r.SnapshotID, err)
		}
		return nil
	})
}

// ListReplicas returns the replica receipts of one snapshot in
// verification order (an empty snapshot id lists every replica).
func (c *Catalog) ListReplicas(snapshotID domain.SnapshotID) ([]Replica, error) {
	q := `SELECT id, snapshot_id, vault_id, verified_at, scope, path FROM replicas`
	var args []any
	if snapshotID != "" {
		q += ` WHERE snapshot_id = ?`
		args = append(args, string(snapshotID))
	}
	q += ` ORDER BY verified_at, id`
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("catalog: list replicas of %s: %w", snapshotID, err)
	}
	defer rows.Close()
	var out []Replica
	for rows.Next() {
		var r Replica
		var vaultID, verifiedAt, scope, path sql.NullString
		if err := rows.Scan(&r.ID, &r.SnapshotID, &vaultID, &verifiedAt, &scope, &path); err != nil {
			return nil, fmt.Errorf("catalog: list replicas of %s: %w", snapshotID, err)
		}
		r.VaultID = domain.VaultID(vaultID.String)
		r.VerifiedAt = verifiedAt.String
		r.Scope = scope.String
		r.Path = path.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list replicas of %s: %w", snapshotID, err)
	}
	return out, nil
}
