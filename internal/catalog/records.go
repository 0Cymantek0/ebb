package catalog

import "ebb/internal/domain"

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
	OpKindPark   = "park"
	OpKindOpen   = "open"
	OpKindTrim   = "trim"
	OpKindForget = "forget"
	OpKindExport = "export" // Wave H: portable-capsule production (§15.2)
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
}

// terminalPhases are the phases ActiveOperations excludes.
var terminalPhases = []string{PhaseCanceled, PhaseDone, PhaseTrimDone}

// validSnapshotKinds and validOpKinds are the closed v1 kind
// vocabularies for snapshots and operations.
var validSnapshotKinds = map[string]bool{
	SnapshotKindPark:     true,
	SnapshotKindTrim:     true,
	SnapshotKindSnapshot: true,
	SnapshotKindSeal:     true,
}

var validOpKinds = map[string]bool{
	OpKindPark:   true,
	OpKindOpen:   true,
	OpKindTrim:   true,
	OpKindForget: true,
	OpKindExport: true,
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
