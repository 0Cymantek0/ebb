package catalog

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
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

// RecordPinRelease appends "unpin:<reason>" to the pin audit list
// WITHOUT changing the pinned flag: it closes a scoped, additive pin
// (e.g. an export pin, Foundation §15.2 "take a retention pin for the
// duration") while the snapshot stays pinned by its original reasons.
// Use Unpin for the deliberate end of the whole recovery obligation
// (forget); this method never unpins. The reason must be non-empty and
// should carry the owning operation id.
func (c *Catalog) RecordPinRelease(id domain.SnapshotID, reason string) error {
	if reason == "" {
		return errors.New("catalog: pin release reason required")
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		s, err := getSnapshotForUpdate(tx, id)
		if err != nil {
			return err
		}
		reasons, err := marshalReasons(appendReason(s.PinReasons, "unpin:"+reason))
		if err != nil {
			return err
		}
		// pinned is deliberately untouched: the flag reflects the original
		// obligation, which the scoped pin never replaced.
		const q = `UPDATE snapshots SET pin_reasons = ? WHERE id = ?`
		if _, err := tx.Exec(q, reasons, string(id)); err != nil {
			return fmt.Errorf("catalog: record pin release of %s: %w", id, err)
		}
		return nil
	})
}

// ErrWitnessDivergence reports that a discovered snapshot id collides
// with an EXISTING row whose witness-bearing fields differ (Wave J
// review J4): payload/seal backend ids, vault binding, manifest and
// inventory digests, workspace binding or kind. Those fields are the
// D017/D020 tamper witness (a retained receipt is validated against the
// row's seal-time digests), so a merge that overwrote them from
// vault-derived values would re-anchor trust to the tampered source.
// The row is NEVER modified when this is returned; the caller surfaces
// the pair as a suspicious finding instead.
type ErrWitnessDivergence struct {
	SnapshotID domain.SnapshotID
	// Existing is the untouched catalog row (the intact witness).
	Existing Snapshot
	// Incoming is the discovered candidate that was refused.
	Incoming Snapshot
	// Fields names the diverging columns in a stable order.
	Fields []string
}

func (e *ErrWitnessDivergence) Error() string {
	return fmt.Sprintf(
		"catalog: discovered snapshot %s diverges from the existing row's witness fields (%s); the row was left untouched",
		e.SnapshotID, strings.Join(e.Fields, ", "))
}

// Reasons renders one line per diverging field with both values, for
// suspicious-refusal reports.
func (e *ErrWitnessDivergence) Reasons() []string {
	field := func(name, existing, incoming string) string {
		return fmt.Sprintf("%s: catalog row has %q, vault discovery claims %q", name, existing, incoming)
	}
	get := func(s Snapshot, name string) string {
		switch name {
		case "workspace_id":
			return string(s.WorkspaceID)
		case "payload_backend_id":
			return s.PayloadBackendID
		case "seal_backend_id":
			return s.SealBackendID
		case "vault_id":
			return string(s.VaultID)
		case "manifest_digest":
			return s.ManifestDigest
		case "inventory_digest":
			return s.InventoryDigest
		case "kind":
			return s.Kind
		default:
			return name
		}
	}
	out := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		out = append(out, field(f, get(e.Existing, f), get(e.Incoming, f)))
	}
	return out
}

// witnessFields is the ordered set of identity/witness-bearing columns
// ImportDiscoveredSnapshot compares on a conflict. A field the existing
// row does not carry (NULL/empty — legacy rows) is not a divergence;
// every non-empty value must match exactly.
var witnessFields = [...]string{
	"workspace_id", "payload_backend_id", "seal_backend_id", "vault_id",
	"manifest_digest", "inventory_digest", "kind",
}

// witnessDivergence returns the names of the witness fields on which the
// existing row (authoritative, never overwritten) disagrees with the
// incoming discovered candidate. Empty existing values never diverge.
func witnessDivergence(existing, incoming Snapshot) []string {
	type pair struct{ existing, incoming string }
	carry := map[string]pair{
		"workspace_id":       {string(existing.WorkspaceID), string(incoming.WorkspaceID)},
		"payload_backend_id": {existing.PayloadBackendID, incoming.PayloadBackendID},
		"seal_backend_id":    {existing.SealBackendID, incoming.SealBackendID},
		"vault_id":           {string(existing.VaultID), string(incoming.VaultID)},
		"manifest_digest":    {existing.ManifestDigest, incoming.ManifestDigest},
		"inventory_digest":   {existing.InventoryDigest, incoming.InventoryDigest},
		"kind":               {existing.Kind, incoming.Kind},
	}
	var fields []string
	for _, f := range witnessFields {
		p := carry[f]
		if p.existing != "" && p.existing != p.incoming {
			fields = append(fields, f)
		}
	}
	return fields
}

// ImportDiscoveredSnapshot records one snapshot discovered by vault
// recovery (Foundation §11.5). If the workspace row does not exist it is
// created with status UNBOUND and the snapshot's creation time —
// reconstruction never guesses live or parked (§16.5). Re-importing an
// already-known snapshot id is COMPARED, never merged: the existing
// row's witness-bearing fields (payload/seal backend ids, vault,
// manifest/inventory digests, kind — the D017/D020 tamper witness) are
// authoritative and are never overwritten by vault-derived values. An
// exact match is a benign duplicate (the row is left completely
// untouched, including its pinned state and pin audit); a divergence
// returns *ErrWitnessDivergence with the row still untouched, for the
// caller to surface as a suspicious finding (rebuild-from-catalog-LOSS
// is unaffected: with no row there is nothing to conflict).
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
		// J4: compare before touching anything. The existing row IS the
		// witness; the discovered candidate may only confirm it.
		existing, gerr := getSnapshotForUpdate(tx, s.ID)
		switch {
		case gerr == nil:
			if fields := witnessDivergence(existing, s); len(fields) > 0 {
				return &ErrWitnessDivergence{SnapshotID: s.ID, Existing: existing, Incoming: s, Fields: fields}
			}
			return nil // benign duplicate: nothing to write, nothing to overwrite
		case !errors.Is(gerr, ErrNotFound):
			return gerr
		}
		const sq = `INSERT INTO snapshots
			(id, workspace_id, created_at, payload_backend_id, seal_backend_id, vault_id,
			 manifest_digest, inventory_digest, kind, pinned, pin_reasons)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`
		if _, err := tx.Exec(sq, string(s.ID), string(s.WorkspaceID), s.CreatedAt,
			nullStr(s.PayloadBackendID), nullStr(s.SealBackendID), nullStr(string(s.VaultID)),
			nullStr(s.ManifestDigest), nullStr(s.InventoryDigest), s.Kind, reasons); err != nil {
			return fmt.Errorf("catalog: import snapshot %s: %w", s.ID, err)
		}
		return nil
	})
}

// Counts is the row-count summary of one catalog: the cheap emptiness
// probe the rebuild-catalog path (`ebb init --rebuild-catalog`,
// Foundation §11.5) and `ebb doctor` use to tell a lost/empty catalog
// from one holding live records. DockerImages counts docker_images rows
// (schemaV3 freeze records): a catalog that only ever served `ebb
// freeze` holds 0 workspaces and 0 snapshots but real retained freeze
// rows — it is NOT lost, and this count is what proves it.
type Counts struct {
	Workspaces   int64
	Snapshots    int64
	DockerImages int64
}

// Counts returns the workspace, snapshot and docker-image row counts.
func (c *Catalog) Counts() (Counts, error) {
	var ct Counts
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM workspaces`).Scan(&ct.Workspaces); err != nil {
		return Counts{}, fmt.Errorf("catalog: count workspaces: %w", err)
	}
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM snapshots`).Scan(&ct.Snapshots); err != nil {
		return Counts{}, fmt.Errorf("catalog: count snapshots: %w", err)
	}
	if err := c.db.QueryRow(`SELECT COUNT(*) FROM docker_images`).Scan(&ct.DockerImages); err != nil {
		return Counts{}, fmt.Errorf("catalog: count docker images: %w", err)
	}
	return ct, nil
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
