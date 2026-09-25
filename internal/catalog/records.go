package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// Workspace status values (Foundation §16.5). After a catalog rebuild
// the status is UNBOUND, never a guessed live/parked: a seal proves a
// retained snapshot exists, not that the source workspace was removed.
const (
	WorkspaceLive    = "live"
	WorkspaceParked  = "parked"
	WorkspaceUnbound = "UNBOUND"
)

// Snapshot kind values (snapshots.kind).
const (
	SnapshotKindPark     = "park"     // snapshot retained by a park operation
	SnapshotKindTrim     = "trim"     // snapshot retained by a staged trim
	SnapshotKindSnapshot = "snapshot" // plain capture snapshot
	SnapshotKindSeal     = "seal"     // seal-only record
)

// Operation kind values (operations.kind).
const (
	OpKindPark    = "park"
	OpKindOpen    = "open"
	OpKindTrim    = "trim"
	OpKindForget  = "forget"
	OpKindExport  = "export"  // Wave H: portable-capsule production (§15.2)
	OpKindImport  = "import"  // Wave I: capsule registration into a vault (§15.3)
	OpKindRestore = "restore" // D033: in-place recreation of trimmed groups on a live workspace
)

// Operation phases — Foundation §12.4 recovery state machine, verbatim.
const (
	PhasePlanned          = "PLANNED"
	PhaseCapturing        = "CAPTURING"
	PhasePayloadCommitted = "PAYLOAD_COMMITTED"
	PhaseSealed           = "SEALED"
	PhaseQuarantined      = "QUARANTINED"
	PhaseRemoving         = "REMOVING"
	PhaseRemovalBlocked   = "REMOVAL_BLOCKED"
	PhaseParked           = "PARKED"
	PhaseRestoring        = "RESTORING"
	PhaseFilesReady       = "FILES_READY"
	PhaseRebuilding       = "REBUILDING"
	PhaseReady            = "READY"
)

// Export operations (kind "export", Wave H) produce a portable capsule
// (Foundation §15.2). They never touch the source workspace, so they
// carry their own small phase set mirroring the trim precedent: a
// controlled failure closes CANCELED after removing the capsule's own
// partial/working artifacts (nothing needs reconciliation); a crash
// between phases leaves the row active with the .partial file as the
// recognizable on-disk artifact.
const (
	PhaseExportPlanned   = "EXPORT_PLANNED"
	PhaseExportCopying   = "EXPORT_COPYING"
	PhaseExportVerifying = "EXPORT_VERIFYING"
)

// Import operations (kind "import", Wave I) register a snapshot
// discovered inside a capsule into a destination vault (Foundation
// §15.3) without publishing a working directory. They mirror the export
// phase set: copying moves the payload through the destination backend,
// verifying covers coverage/readback plus the destination seal, and a
// controlled failure closes CANCELED after removing the import's own
// working artifacts.
const (
	PhaseImportPlanned   = "IMPORT_PLANNED"
	PhaseImportCopying   = "IMPORT_COPYING"
	PhaseImportVerifying = "IMPORT_VERIFYING"
)

// Terminal phases: the operation's reconciliation is over; it is no
// longer returned by ActiveOperations.
const (
	PhaseCanceled = "CANCELED"
	PhaseDone     = "DONE"
)

// PhaseRebuildFailed is the failed-action outcome of Foundation §12.5
// ("a failed action leaves FILES_READY or REBUILD_FAILED"); it stays
// active because `ebb open --resume` may resolve it.
const PhaseRebuildFailed = "REBUILD_FAILED"

// Trim operations (kind "trim") stage approved generated-output removal
// (Foundation §17.3) before a park; they never walk the park sequence,
// so they carry their own small phase set instead of borrowing capture
// phases.
const (
	PhaseTrimPlanned = "TRIM_PLANNED"
	PhaseTrimSealing = "TRIM_SEALING"
	PhaseTrimDone    = "TRIM_DONE"
)

// Restore operations (kind "restore", D033) re-execute a sealed trim's
// recorded recipes in-place on the live workspace. They mirror the trim
// precedent of a small dedicated phase set: RESTORE_PLANNED covers
// workspace/trim selection, document readback and the gates; the
// RESTORE_RUNNING transition gates recipe execution; RESTORE_DONE is
// terminal. RESTORE_FAILED is deliberately NON-terminal (the same
// posture as REBUILD_FAILED): a failed restore is resumable by simply
// rerunning `ebb restore` — package managers tolerate existing partial
// output directories — and the rerun supersedes the dead row.
const (
	PhaseRestorePlanning = "RESTORE_PLANNED"
	PhaseRestoreRunning  = "RESTORE_RUNNING"
	PhaseRestoreDone     = "RESTORE_DONE"
	PhaseRestoreFailed   = "RESTORE_FAILED"
)

// validPhases is the closed v1 phase vocabulary accepted by the journal
// API; a typo'd phase would be an unrecoverable journal state, so it is
// rejected at the API edge.
var validPhases = map[string]bool{
	PhasePlanned:          true,
	PhaseCapturing:        true,
	PhasePayloadCommitted: true,
	PhaseSealed:           true,
	PhaseQuarantined:      true,
	PhaseRemoving:         true,
	PhaseRemovalBlocked:   true,
	PhaseParked:           true,
	PhaseRestoring:        true,
	PhaseFilesReady:       true,
	PhaseRebuilding:       true,
	PhaseReady:            true,
	PhaseCanceled:         true,
	PhaseDone:             true,
	PhaseRebuildFailed:    true,
	PhaseTrimPlanned:      true,
	PhaseTrimSealing:      true,
	PhaseTrimDone:         true,
	PhaseExportPlanned:    true,
	PhaseExportCopying:    true,
	PhaseExportVerifying:  true,
	PhaseImportPlanned:    true,
	PhaseImportCopying:    true,
	PhaseImportVerifying:  true,
	PhaseRestorePlanning:  true,
	PhaseRestoreRunning:   true,
	PhaseRestoreDone:      true,
	PhaseRestoreFailed:    true,
}

// terminalPhases are the phases ActiveOperations excludes.
var terminalPhases = []string{PhaseCanceled, PhaseDone, PhaseTrimDone, PhaseRestoreDone}

// validSnapshotKinds and validOpKinds are the closed v1 kind
// vocabularies for snapshots and operations.
var validSnapshotKinds = map[string]bool{
	SnapshotKindPark:     true,
	SnapshotKindTrim:     true,
	SnapshotKindSnapshot: true,
	SnapshotKindSeal:     true,
}

var validOpKinds = map[string]bool{
	OpKindPark:    true,
	OpKindOpen:    true,
	OpKindTrim:    true,
	OpKindForget:  true,
	OpKindExport:  true,
	OpKindImport:  true,
	OpKindRestore: true,
}

// PinReasonCreation is the reason every snapshot is pinned with at
// record time (I07: presumed retained).
const PinReasonCreation = "creation"

// Workspace is one row of the workspaces table. Empty RootPath /
// RootIdentity mean unbound (parked or rebuilt-but-unbound).
type Workspace struct {
	ID           domain.WorkspaceID
	Name         string
	CreatedAt    string // RFC3339Nano UTC
	RootPath     string // "" when unbound
	RootIdentity string // platform RootIdentity string, "" when unbound
	Status       string // WorkspaceLive | WorkspaceParked | WorkspaceUnbound
}

// Vault is one row of the vaults table: a registered storage boundary.
type Vault struct {
	ID           domain.VaultID
	Path         string // absolute path to the vault directory
	RepoID       string // backend repository identity, "" when unbound
	Kind         string // "local" in v1
	RegisteredAt string // RFC3339Nano UTC
}

// Snapshot is one row of the snapshots table: a retained P/S pair.
// Pinned is the current state; PinReasons is the append-only audit of
// pin lifecycle events ("creation", "pin:<r>", "unpin:<r>").
type Snapshot struct {
	ID               domain.SnapshotID
	WorkspaceID      domain.WorkspaceID
	CreatedAt        string         // RFC3339Nano UTC
	PayloadBackendID string         // backend snapshot id of payload P, "" when absent
	SealBackendID    string         // backend snapshot id of seal S, "" when absent
	VaultID          domain.VaultID // "" when not bound to a vault yet
	ManifestDigest   string
	InventoryDigest  string
	Kind             string // SnapshotKind*
	Pinned           bool
	PinReasons       []string
}

// Operation is one row of the operations journal. Generation increments
// on every successful CAS transition (Foundation §12.4).
type Operation struct {
	ID             domain.OperationID
	WorkspaceID    domain.WorkspaceID // never empty for v1 operations
	Kind           string             // OpKind*
	Phase          string             // Phase*
	Generation     int64
	SourceRoot     string // absolute path of the operation's source root
	SourceIdentity string // platform RootIdentity string of the source root
	DestPath       string // vault/destination path, "" until chosen
	PayloadSnap    string // backend id of committed payload P
	SealSnap       string // backend id of committed seal S
	SnapID         string // logical snapshot id of the target (schemaV5; forget adoption)
	IntentDigest   string // policy intent digest (Foundation §7.1)
	LastError      string // last recorded failure message
	NextAction     string // next permitted reconciliation step, "" when none recorded
	StartedAt      string // RFC3339Nano UTC
	UpdatedAt      string // RFC3339Nano UTC
}

// Approval is one row of the approvals table: a recorded local user
// consent to run one exact action (Foundation §7.3). RevokedAt is ""
// while the approval is live.
type Approval struct {
	ID           domain.ID
	WorkspaceID  domain.WorkspaceID
	ActionID     string
	ArgvDigest   string // digest of the exact literal argv
	ToolIdentity string // e.g. interpreter identity, "" when n/a
	InputDigests string // canonical digest bundle JSON (caller-built)
	Network      string // network capability grant, "" when none
	ApprovedBy   string // defaults to "user"
	ApprovedAt   string // RFC3339Nano UTC
	RevokedAt    string // RFC3339Nano UTC, "" while live
}

// Replica is one row of the replicas table: a VERIFIED independent
// recovery copy of one snapshot (Foundation §15.5). A vault replica
// carries VaultID + empty Path; a capsule replica (Wave H) carries an
// empty VaultID (a capsule is not a registered vault) and the capsule
// file's output path. Scope names the verification that was actually
// performed, never a free-form "safe=true".
type Replica struct {
	ID         domain.ID
	SnapshotID domain.SnapshotID
	VaultID    domain.VaultID // "" for capsule replicas
	VerifiedAt string         // RFC3339Nano UTC
	Scope      string
	Path       string // capsule output file (Wave H); "" for vault replicas
}

// RetentionIntent is one row of the retention_intents table: an
// explicitly acknowledged loss of one snapshot's recovery obligation
// (Foundation §16.6), durably recorded before the backend pair is
// forgotten.
type RetentionIntent struct {
	ID           domain.ID
	SnapshotID   domain.SnapshotID
	RequestedBy  string
	Acknowledged bool
	CreatedAt    string // RFC3339Nano UTC
	CompletedAt  string // RFC3339Nano UTC, "" until completed
}

// DockerImage is one row of the docker_images table (schemaV3, D040
// tier 3): the durable record of one Freeze-to-Vault capture. It is the
// restore authority for `ebb freeze --restore`: snapshot_id + filename
// address the blob inside the vault, sha256 + bytes are the readback
// witness recorded in-flight at freeze time, and VerifiedAt/RemovedAt
// carry the verification and daemon-removal audit. A row with an empty
// VerifiedAt was captured but never proven by independent readback — it
// is retained and pinned, never trusted as evidence (Foundation §11.3).
type DockerImage struct {
	ID              domain.ID
	ImageID         string // canonical docker image id (e.g. sha256:<64hex>) or tag spelling
	VaultID         domain.VaultID
	SnapshotID      string // restic backend snapshot id (64 hex)
	Filename        string // --stdin-filename of the blob inside the snapshot
	SHA256          string // digest of the docker-save stream, hashed in-flight
	Bytes           int64  // byte count of the stream
	CreatedAt       string // RFC3339Nano UTC
	VerifiedAt      string // RFC3339Nano UTC, "" until readback verification passed
	Pinned          bool
	DaemonRemovedAt string // RFC3339Nano UTC, "" while the image is still in the daemon
}

// ---- docker_images rows (schemaV3, D040 tier 3) ------------------------

const dockerImageCols = `id, image_id, vault_id, snapshot_id, filename, sha256, bytes,
	created_at, verified_at, pinned, daemon_removed_at`

// RecordDockerImage inserts one freeze row. The row is always recorded
// pinned (I07 posture for the new recovery obligation); verified_at
// starts empty and is only ever set by MarkDockerImageVerified after the
// independent readback digest check. Re-freezing the same image appends
// a new row (entries are append-only history; lookup prefers the newest
// verified row).
func (c *Catalog) RecordDockerImage(im DockerImage) (domain.ID, error) {
	if im.ImageID == "" {
		return "", errors.New("catalog: docker image id required")
	}
	if im.SnapshotID == "" || im.Filename == "" || im.SHA256 == "" || im.Bytes <= 0 {
		return "", fmt.Errorf("catalog: docker image %s: snapshot id, filename, sha256 and a positive byte count are required (got snapshot=%q filename=%q sha256=%q bytes=%d)",
			im.ImageID, im.SnapshotID, im.Filename, im.SHA256, im.Bytes)
	}
	if im.ID == "" {
		im.ID = domain.NewID()
	}
	if im.CreatedAt == "" {
		im.CreatedAt = domain.FormatTime(time.Now())
	}
	return im.ID, withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO docker_images
			(` + dockerImageCols + `)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 1, NULL)`
		if _, err := tx.Exec(q, string(im.ID), im.ImageID, nullStr(string(im.VaultID)),
			im.SnapshotID, im.Filename, im.SHA256, im.Bytes, im.CreatedAt); err != nil {
			return fmt.Errorf("catalog: record docker image %s: %w", im.ID, err)
		}
		return nil
	})
}

// GetDockerImage returns the freeze row for id, or ErrNotFound.
func (c *Catalog) GetDockerImage(id domain.ID) (DockerImage, error) {
	const q = `SELECT ` + dockerImageCols + ` FROM docker_images WHERE id = ?`
	im, err := scanDockerImage(c.db.QueryRow(q, string(id)))
	if errors.Is(err, sql.ErrNoRows) {
		return DockerImage{}, fmt.Errorf("%w: docker image entry %s", ErrNotFound, id)
	}
	if err != nil {
		return DockerImage{}, fmt.Errorf("catalog: get docker image %s: %w", id, err)
	}
	return im, nil
}

// FindDockerImages returns the freeze rows whose image_id matches
// imageID exactly (the CLI resolves a user-supplied image id or tag),
// oldest first. The caller prefers the newest VERIFIED row and refuses
// to trust unverified rows as evidence.
func (c *Catalog) FindDockerImages(imageID string) ([]DockerImage, error) {
	const q = `SELECT ` + dockerImageCols + ` FROM docker_images
		WHERE image_id = ? ORDER BY created_at, id`
	rows, err := c.db.Query(q, imageID)
	if err != nil {
		return nil, fmt.Errorf("catalog: find docker images %q: %w", imageID, err)
	}
	defer rows.Close()
	var out []DockerImage
	for rows.Next() {
		im, err := scanDockerImage(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: find docker images %q: %w", imageID, err)
		}
		out = append(out, im)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: find docker images %q: %w", imageID, err)
	}
	return out, nil
}

// ListDockerImages returns every freeze row, oldest first (the status
// view; `ebb freeze --restore` resolves through FindDockerImages).
func (c *Catalog) ListDockerImages() ([]DockerImage, error) {
	const q = `SELECT ` + dockerImageCols + ` FROM docker_images ORDER BY created_at, id`
	rows, err := c.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("catalog: list docker images: %w", err)
	}
	defer rows.Close()
	var out []DockerImage
	for rows.Next() {
		im, err := scanDockerImage(rows)
		if err != nil {
			return nil, fmt.Errorf("catalog: list docker images: %w", err)
		}
		out = append(out, im)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list docker images: %w", err)
	}
	return out, nil
}

// MarkDockerImageVerified stamps the row's verified_at — only after the
// caller proved the vault's bytes read back to the recorded digest and
// byte count (Foundation §11.4; the stamp itself never creates proof).
func (c *Catalog) MarkDockerImageVerified(id domain.ID, at string) error {
	if at == "" {
		return errors.New("catalog: verification timestamp required")
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE docker_images SET verified_at = ? WHERE id = ?`, at, string(id))
		if err != nil {
			return fmt.Errorf("catalog: mark docker image %s verified: %w", id, err)
		}
		n, rerr := res.RowsAffected()
		if rerr != nil {
			return fmt.Errorf("catalog: mark docker image %s verified: %w", id, rerr)
		}
		if n != 1 {
			return fmt.Errorf("%w: docker image entry %s", ErrNotFound, id)
		}
		return nil
	})
}

// MarkDockerImageRemoved records the audited docker rmi of a VERIFIED
// freeze row (the daemon-side removal only ever runs behind the CLI's
// separate typed confirmation). Refuses an unverified row: removal
// authority requires proven evidence, exactly like workspace removal.
func (c *Catalog) MarkDockerImageRemoved(id domain.ID, at string) error {
	if at == "" {
		return errors.New("catalog: removal timestamp required")
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		var verified sql.NullString
		if err := tx.QueryRow(`SELECT verified_at FROM docker_images WHERE id = ?`,
			string(id)).Scan(&verified); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("%w: docker image entry %s", ErrNotFound, id)
			}
			return fmt.Errorf("catalog: mark docker image %s removed: %w", id, err)
		}
		if !verified.Valid || verified.String == "" {
			return fmt.Errorf("catalog: docker image %s is UNVERIFIED; the daemon image can only be removed after a verified freeze", id)
		}
		if _, err := tx.Exec(`UPDATE docker_images SET daemon_removed_at = ? WHERE id = ?`,
			at, string(id)); err != nil {
			return fmt.Errorf("catalog: mark docker image %s removed: %w", id, err)
		}
		return nil
	})
}

func scanDockerImage(r rowScanner) (DockerImage, error) {
	var im DockerImage
	var vaultID, verified, removed sql.NullString
	var pinned int64
	if err := r.Scan(&im.ID, &im.ImageID, &vaultID, &im.SnapshotID, &im.Filename,
		&im.SHA256, &im.Bytes, &im.CreatedAt, &verified, &pinned, &removed); err != nil {
		return DockerImage{}, err
	}
	im.VaultID = domain.VaultID(vaultID.String)
	im.VerifiedAt = verified.String
	im.Pinned = pinned != 0
	im.DaemonRemovedAt = removed.String
	return im, nil
}
