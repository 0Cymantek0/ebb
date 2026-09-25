package catalog

// Forward-only schema migrations. The slice index is the version
// recorded in schema_migrations; migration N runs inside one transaction
// together with its version insert (see Catalog.migrate).
var migrations = []string{schemaV1, schemaV2, schemaV3, schemaV4, schemaV5, schemaV6}

// schemaMigrationsDDL is created separately from any versioned
// migration so a fresh database can record versions at all.
const schemaMigrationsDDL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
)`

// schemaV1 is the Foundation §16.5 minimum table set. Notes:
//
//   - workspaces.status is 'live', 'parked' or 'UNBOUND'. UNBOUND is the
//     post-rebuild state: a seal proves a snapshot exists, never that the
//     source was removed (§16.5), so catalog reconstruction never guesses
//     liveness.
//   - snapshots.pinned defaults TRUE with a JSON pin-reason audit list
//     (invariant I07: a live workspace always keeps a recovery
//     obligation; a snapshot is presumed retained until explicitly
//     unpinned).
//   - replicas and action_runs carry future-wave data (verification
//     receipts, approved-action history); the tables exist now so later
//     waves never need destructive migrations.
const schemaV1 = `
CREATE TABLE workspaces (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	created_at TEXT NOT NULL,
	root_path TEXT,
	root_identity TEXT,
	status TEXT NOT NULL DEFAULT 'UNBOUND'
);

CREATE TABLE vaults (
	id TEXT PRIMARY KEY,
	path TEXT NOT NULL,
	repo_id TEXT,
	kind TEXT NOT NULL DEFAULT 'local',
	registered_at TEXT NOT NULL
);

CREATE TABLE snapshots (
	id TEXT PRIMARY KEY,
	workspace_id TEXT NOT NULL REFERENCES workspaces(id),
	created_at TEXT NOT NULL,
	payload_backend_id TEXT,
	seal_backend_id TEXT,
	vault_id TEXT REFERENCES vaults(id),
	manifest_digest TEXT,
	inventory_digest TEXT,
	kind TEXT NOT NULL,
	pinned INTEGER NOT NULL DEFAULT 1,
	pin_reasons TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE replicas (
	id TEXT PRIMARY KEY,
	snapshot_id TEXT REFERENCES snapshots(id),
	vault_id TEXT REFERENCES vaults(id),
	verified_at TEXT,
	scope TEXT,
	UNIQUE (snapshot_id, vault_id)
);

CREATE TABLE operations (
	id TEXT PRIMARY KEY,
	workspace_id TEXT REFERENCES workspaces(id),
	kind TEXT NOT NULL,
	phase TEXT NOT NULL,
	generation INTEGER NOT NULL DEFAULT 1,
	source_root TEXT,
	source_identity TEXT,
	dest_path TEXT,
	payload_snap TEXT,
	seal_snap TEXT,
	intent_digest TEXT,
	last_error TEXT,
	next_action TEXT,
	started_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE action_runs (
	id TEXT PRIMARY KEY,
	operation_id TEXT REFERENCES operations(id),
	action_id TEXT,
	status TEXT,
	exit_code INTEGER,
	started_at TEXT,
	ended_at TEXT,
	output_excerpt TEXT
);

CREATE TABLE approvals (
	id TEXT PRIMARY KEY,
	workspace_id TEXT REFERENCES workspaces(id),
	action_id TEXT NOT NULL,
	argv_digest TEXT NOT NULL,
	tool_identity TEXT,
	input_digests TEXT NOT NULL,
	network TEXT,
	approved_by TEXT NOT NULL DEFAULT 'user',
	approved_at TEXT NOT NULL,
	revoked_at TEXT
);

CREATE TABLE retention_intents (
	id TEXT PRIMARY KEY,
	snapshot_id TEXT REFERENCES snapshots(id),
	requested_by TEXT,
	acknowledged TEXT NOT NULL DEFAULT '0',
	created_at TEXT NOT NULL,
	completed_at TEXT
);

CREATE INDEX idx_snapshots_workspace ON snapshots(workspace_id, created_at);
CREATE INDEX idx_snapshots_vault ON snapshots(vault_id);
CREATE INDEX idx_operations_workspace ON operations(workspace_id, updated_at);
`

// schemaV2 (Wave H) widens replicas for portable capsules: a capsule
// export records one row per produced capsule file with vault_id NULL
// (a capsule is NOT one of the registered vaults) and the capsule's
// output path in the new column. SQLite UNIQUE(snapshot_id, vault_id)
// treats NULL vault ids as distinct, so multiple capsules of the same
// snapshot remain representable. Non-destructive ALTERs only.
const schemaV2 = `
ALTER TABLE replicas ADD COLUMN path TEXT;
`

// schemaV3 (Wave 2, D040 tier 3) adds the docker_images table: the
// durable row of one Freeze-to-Vault capture. A dedicated table (not a
// snapshots row with a new kind) is the minimal additive representation:
// freeze entries have no workspace (snapshots.workspace_id is NOT NULL),
// no manifest/inventory digests, and their own witness set — the stream
// digest, the byte count, the --stdin-filename inside the restic
// snapshot and the daemon-removal audit. A CREATE TABLE touches no
// existing row shape, no closed vocabulary and no witness comparison.
//
// pinned defaults to 1 mirroring I07 (a frozen image creates a recovery
// obligation; it is presumed retained until an explicit forget path
// exists). verified_at stays NULL until the independent readback digest
// check passes; an unverified row is retained AND pinned (§11.3: nothing
// is auto-forgotten on failure). daemon_removed_at records the audited
// docker rmi (only ever executed behind the CLI's separate typed
// confirmation after a verified freeze).
const schemaV3 = `
CREATE TABLE docker_images (
	id TEXT PRIMARY KEY,
	image_id TEXT NOT NULL,
	vault_id TEXT REFERENCES vaults(id),
	snapshot_id TEXT NOT NULL,
	filename TEXT NOT NULL,
	sha256 TEXT NOT NULL,
	bytes INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	verified_at TEXT,
	pinned INTEGER NOT NULL DEFAULT 1,
	daemon_removed_at TEXT
);

CREATE INDEX idx_docker_images_image ON docker_images(image_id, created_at);
`

// schemaV4 (Wave 3, stats foundation) adds the stats_events table: one
// append-only row per dispatched CLI verb recording its byte flows for
// `ebb stats` (the Developer Space Economy dashboard). The table is pure
// telemetry — it never feeds a safety decision, holds no secrets (bytes,
// the command verb, a workspace label and a compact detail object we
// minted ourselves) and a lost table degrades the dashboard to "—", never
// a recovery. A CREATE TABLE touches no existing row shape.
const schemaV4 = `
CREATE TABLE IF NOT EXISTS stats_events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  command TEXT NOT NULL,
  workspace TEXT,
  bytes_in INTEGER NOT NULL DEFAULT 0,
  bytes_out INTEGER NOT NULL DEFAULT 0,
  detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_stats_events_ts ON stats_events(ts);
`

// schemaV5 (Wave 5, D060) adds operations.snap_id: the LOGICAL snapshot
// identity of an operation's target. Payload/seal backend ids identify
// physical backend objects, not logical recovery obligations — two
// catalog rows can reference the same pair (catalog reconstruction,
// imports, corruption repair) — so forget's rerun-adoption fingerprint
// must bind the logical snapshot id alongside the pair.
const schemaV5 = `
ALTER TABLE operations ADD COLUMN snap_id TEXT;
`

// schemaV6 (Wave 5 safety follow-up, P0-2) adds operations.vault_id: the
// VAULT a forget operation must run against, recorded as the target
// snapshot's own snapshots.vault_id value (the catalog vault-row id
// capture and import both derive with lifecycle.VaultIDFor). Multi-vault
// is real — `ebb import --vault` binds snapshots to non-default vaults —
// and a forget's durable fingerprint must include the vault: a resumed
// forget that opened a DIFFERENT repository would find nothing to
// forget and complete the release intent while the material sits
// untouched in its true vault. Rows predating the column (and rows of
// the default-vault capture path, which bind no vault) carry NULL, read
// as "": the default vault, exactly as forget behaved before.
const schemaV6 = `
ALTER TABLE operations ADD COLUMN vault_id TEXT;
`
