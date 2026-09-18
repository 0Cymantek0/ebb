// Package restore implements Foundation §12.5's restore ("open")
// sequence for files: validate the retained seal, read back and verify
// the payload documents against the seal's digests, materialize the
// preserved workspace tree into a private staging directory, VERIFY the
// staged tree against an oracle independent of the restore encoder (a
// fresh inventory scan compared to the retained inventory — the E10
// defense), publish by renaming onto the absent destination, and record
// durable open-operation state (PLANNED → RESTORING → FILES_READY).
//
// v1 terminal state: an open operation stops at FILES_READY. The
// reconstruction actions of §12.5's last paragraphs (running approved
// recipes at the final destination, REBUILDING → READY, and
// REBUILD_FAILED) are the future actions wave; this package only
// REPORTS them as RebuildHints and never executes project code (I05).
// Opening never releases the recovery obligation: the snapshot stays
// pinned (I07).
//
// The ONLY filesystem mutations this package performs: creating its
// staging directories, restoring the backend subtree into them
// (link nodes excluded), recreating retained links inside the staging
// from the retained inventory's LinkTarget (links.go), the publish
// rename onto an absent destination, shape-gated removal of its own
// .ebb-stage-<opID> directories, and removal of an EMPTY destination
// directory. Unrelated content is never touched (§12.5: "An unrelated
// nonempty directory is never overwritten").
//
// The frozen document formats parsed here (receipt, manifest,
// inventory.jsonl records, and the .ebb-op-<opID> / .ebb-seal-<opID>
// tree prefixes) are defined by internal/lifecycle/manifest.go; this
// package re-declares them locally as a strict reader rather than
// importing the removal-authority package (Foundation §16.7 module
// boundaries).
package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// Dependencies wires the opener. All fields except Clock and CreateLink
// are required; New refuses nil seams so a half-constructed opener can
// never reach publishing code (mirroring lifecycle.New).
type Dependencies struct {
	Store domain.SnapshotStore // required: the backend seam (restic adapter)
	Cat   *catalog.Catalog     // required: durable operation journal
	Probe domain.PlatformProbe // required: identity, volume usage, oracle facts
	// CreateLink recreates retained links during staging (links.go).
	// Optional; defaults to the stdlib os.Symlink creator with the
	// Windows privilege refusal mapped to the typed contract. Production
	// wiring passes platform.CreateLink so junctions — the unprivileged
	// case — recreate natively (this package cannot import platform;
	// the seam is the module boundary).
	CreateLink LinkCreator
	Clock      func() time.Time // optional; defaults to time.Now
}

// VaultRef names one backend repository: the repo directory and the
// passfile holding its unlock secret. Local definition mirroring
// lifecycle.VaultRef; restore never imports that package.
type VaultRef struct {
	RepoDir  string
	Passfile string
}

// Options parameterizes one Open. FilesOnly is always effectively true
// in v1 (rebuild is reported, never run); the field exists so the CLI
// contract (`ebb open --files-only`, Foundation §17.2) maps cleanly when
// the actions wave lands.
type Options struct {
	// Destination is the final absolute path for the workspace root.
	Destination string
	// FilesOnly is always true in v1 (rebuild is reported, never run).
	FilesOnly bool
}

// RebuildHint reports one omitted group the manifest says must be
// reconstructed at the final destination (§12.5 last paragraphs). v1
// reports these; it never runs them.
type RebuildHint struct {
	GroupID string
	Command []string
	Inputs  []string
	Network string
}

// Result reports a completed files-only open (op left at FILES_READY).
type Result struct {
	OperationID domain.OperationID
	SnapshotID  domain.SnapshotID
	WorkspaceID domain.WorkspaceID
	Destination string

	EntriesRestored int64
	BytesRestored   int64
	Warnings        []string
	RebuildHints    []RebuildHint
}

// Opener executes the §12.5 restore sequence. Safe for sequential use
// by the serialized CLI (D11); the catalog serializes journal writes.
type Opener struct {
	store      domain.SnapshotStore
	cat        *catalog.Catalog
	probe      domain.PlatformProbe
	createLink LinkCreator
	now        func() time.Time
}

// New validates the dependency seams and returns a ready Opener.
func New(d Dependencies) (*Opener, error) {
	if d.Store == nil {
		return nil, fmt.Errorf("restore: dependencies: Store is required")
	}
	if d.Cat == nil {
		return nil, fmt.Errorf("restore: dependencies: Cat is required")
	}
	if d.Probe == nil {
		return nil, fmt.Errorf("restore: dependencies: Probe is required")
	}
	if d.CreateLink == nil {
		d.CreateLink = stdlibCreateLink
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &Opener{store: d.Store, cat: d.Cat, probe: d.Probe, createLink: d.CreateLink, now: d.Clock}, nil
}

// Ebb-owned sibling names of the frozen capture layout (D003 and
// internal/lifecycle/manifest.go). stagePrefix is this package's own;
// the op/seal prefixes mirror the writer's shapes so the reader can
// derive operation ids from tree paths without guessing (I13).
const (
	stagePrefix = ".ebb-stage-"
	opPrefix    = ".ebb-op-"
	sealPrefix  = ".ebb-seal-"

	manifestName  = "manifest.json"
	inventoryName = "inventory.jsonl"
	receiptName   = "receipt.json"

	// schemaVersionCurrent is the only document schema this reader
	// accepts (Foundation §16.1: readers reject unsupported versions).
	schemaVersionCurrent = 1
)

// stagingRoot returns the private staging parent for opID: a sibling of
// the destination named .ebb-stage-<opID>. The workspace tree lands at
// stagingRoot/<backendPrefix> and is renamed onto the destination at
// publish time.
func stagingRoot(dest string, opID domain.OperationID) string {
	return filepath.Join(filepath.Dir(dest), stagePrefix+string(opID))
}

// opDirName mirrors the writer's payload op-dir name for opID.
func opDirName(opID string) string { return opPrefix + opID }

// sealDirID extracts the operation id from a ".ebb-seal-<32hex>" tree
// directory name, reporting whether the shape matches.
func sealDirID(name string) (string, bool) {
	id, ok := strings.CutPrefix(name, sealPrefix)
	if !ok || !isHex32(id) {
		return "", false
	}
	return id, true
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Open runs the §12.5 restore sequence for one retained snapshot and
// returns the files-only result. See the package comment for the phase
// walk and the invariants enforced on the way.
func (o *Opener) Open(ctx context.Context, vault VaultRef, snapID domain.SnapshotID, opts Options) (Result, error) {
	res := Result{SnapshotID: snapID}

	// ---- §12.5 step 1: catalog lookup, openable kind, sealed pair ----
	snap, err := o.cat.GetSnapshot(snapID)
	if err != nil {
		return res, &ErrNotOpenable{SnapshotID: snapID, Reason: fmt.Sprintf("catalog lookup: %v", err)}
	}
	res.WorkspaceID = snap.WorkspaceID
	switch snap.Kind {
	case catalog.SnapshotKindPark, catalog.SnapshotKindSnapshot:
		// Openable: the payload is a full workspace capture.
	case catalog.SnapshotKindTrim:
		return res, &ErrNotOpenable{SnapshotID: snapID, Kind: snap.Kind,
			Reason: "a trim snapshot covers only a removal plan; it is not a restorable workspace payload (Foundation §17.3)"}
	case catalog.SnapshotKindSeal:
		return res, &ErrNotOpenable{SnapshotID: snapID, Kind: snap.Kind,
			Reason: "a seal-only record has no payload to restore"}
	default:
		return res, &ErrNotOpenable{SnapshotID: snapID, Kind: snap.Kind, Reason: "unknown snapshot kind"}
	}
	if snap.PayloadBackendID == "" {
		return res, &ErrNotOpenable{SnapshotID: snapID, Kind: snap.Kind,
			Reason: "payload backend id is empty: an unsealed payload is never publishable (Foundation §11.3)"}
	}
	if snap.SealBackendID == "" {
		return res, &ErrNotOpenable{SnapshotID: snapID, Kind: snap.Kind,
			Reason: "seal backend id is empty: no seal to validate (Foundation §11.3)"}
	}
	if err := checkContext(ctx); err != nil {
		return res, err
	}
	if vault.RepoDir == "" || vault.Passfile == "" {
		return res, &ErrInvalidOptions{Detail: "vault RepoDir and Passfile are required"}
	}

	// ---- §12.5 step 2: validate the retained seal --------------------
	receipt, err := o.loadSeal(ctx, vault, snapID, snap)
	if err != nil {
		return res, err
	}
	if err := checkContext(ctx); err != nil {
		return res, err
	}

	// ---- §12.5 step 3: payload document readback + digest check ------
	docs, err := o.loadDocuments(ctx, vault, snapID, snap, receipt)
	if err != nil {
		return res, err
	}
	if err := checkContext(ctx); err != nil {
		return res, err
	}

	// ---- §12.5 step 4: destination preflight -------------------------
	dest, err := o.preflight(ctx, snap.WorkspaceID, opts.Destination, docs)
	if err != nil {
		return res, err
	}
	res.Destination = dest

	// ---- §12.5 interrupted-staging recovery (§12.4 RESTORING row) ----
	warnings, err := o.recoverInterruptedOpen(ctx, snap.WorkspaceID, dest)
	if err != nil {
		return res, err
	}
	res.Warnings = append(res.Warnings, warnings...)
	if !opts.FilesOnly {
		res.Warnings = append(res.Warnings,
			"FilesOnly=false requested, but v1 open is always files-only; rebuild groups are reported as hints, never executed (Foundation §17.2)")
	}
	if err := checkContext(ctx); err != nil {
		return res, err
	}

	// ---- §12.5 step 5: durable open operation ------------------------
	wsName, err := o.ensureWorkspace(snap.WorkspaceID, docs.wsPrefix)
	if err != nil {
		return res, err
	}
	// Contract note: the catalog has no SetDestPath and BeginOperation
	// takes no destination. For kind=open the source_root slot carries
	// the DESTINATION — an open has no live source root; the destination
	// is the operation's root of record and the only journal-carried
	// binding for locating .ebb-stage-<opID> during recovery.
	opID, err := o.cat.BeginOperation(snap.WorkspaceID, catalog.OpKindOpen, dest, "",
		openIntentDigest(snapID, dest, snap))
	if err != nil {
		return res, fmt.Errorf("restore: begin operation: %w", err)
	}
	res.OperationID = opID
	// Record the backend pair this open consumes (recovery evidence).
	if err := o.cat.SetBackendRefs(opID, snap.PayloadBackendID, snap.SealBackendID); err != nil {
		return res, fmt.Errorf("restore: record backend refs: %w", err)
	}
	if err := o.cat.AdvanceOperation(opID, catalog.PhasePlanned, catalog.PhaseRestoring); err != nil {
		return res, fmt.Errorf("restore: advance %s: PLANNED -> RESTORING: %w", opID, err)
	}
	fail := func(err error) (Result, error) {
		o.failOperation(opID, catalog.PhaseRestoring, err.Error())
		return res, err
	}

	// ---- §12.5 step 6: staging materialization -----------------------
	// Links are EXCLUDED from the backend stage (it cannot materialize
	// reparse points without SeCreateSymbolicLinkPrivilege) and recreated
	// natively right after (links.go): junctions unprivileged, true
	// symlinks privilege-gated with a typed per-entry blocker that fails
	// the open before publish.
	stage := stagingRoot(dest, opID)
	staged := filepath.Join(stage, docs.wsPrefix)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return fail(fmt.Errorf("restore: staging dir: %w", err))
	}
	linksExcluded, err := o.stagePayload(ctx, vault, snap, docs, stage)
	if err != nil {
		_ = removeStage(stage)
		return fail(err)
	}
	if linksExcluded && len(docs.links) > 0 {
		if err := o.recreateLinks(staged, docs.links); err != nil {
			_ = removeStage(stage)
			return fail(err)
		}
	}

	// ---- §12.5 step 7: independent-oracle verification (E10) ---------
	if err := o.verifyStaged(ctx, staged, docs.retained); err != nil {
		// Remove ONLY our own .ebb-stage-<opID> (shape-gated); never
		// publish; the operation fails at RESTORING with the typed error.
		_ = removeStage(stage)
		return fail(err)
	}

	// ---- §12.5 step 8: publish by rename onto the absent destination -
	if err := prepareDestination(dest); err != nil {
		// Racing occupant: KEEP staging, leave the operation RESTORING
		// for recovery; never clobber (F35).
		return fail(&ErrPublishBlocked{Destination: dest, Err: err})
	}
	if err := renameWithRetry(staged, dest); err != nil {
		return fail(&ErrPublishBlocked{Destination: dest, Err: err})
	}
	if err := o.cat.AdvanceOperation(opID, catalog.PhaseRestoring, catalog.PhaseFilesReady); err != nil {
		return res, fmt.Errorf("restore: advance %s: RESTORING -> FILES_READY: %w", opID, err)
	}
	// Re-bind identity at the new location (I13): a fresh RootIdentity,
	// not the recorded capture-time one.
	ident, err := o.probe.RootIdentity(dest)
	if err != nil {
		return res, fmt.Errorf("restore: identity of published root %s: %w", dest, err)
	}
	if err := o.cat.UpsertWorkspace(catalog.Workspace{
		ID: snap.WorkspaceID, Name: wsName,
		RootPath: dest, RootIdentity: ident.String(),
		Status: catalog.WorkspaceLive,
	}); err != nil {
		return res, fmt.Errorf("restore: mark workspace live: %w", err)
	}

	// ---- §12.5 step 9: finish (op stays FILES_READY; I07 pin intact) -
	if err := removeStage(stage); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("cleanup staging %s failed: %v", stage, err))
	}
	res.EntriesRestored = docs.entriesRestored
	res.BytesRestored = docs.preservedBytes
	res.RebuildHints = rebuildHints(docs.manifest)
	return res, nil
}

// ensureWorkspace returns the workspace's display name, creating the row
// (UNBOUND, name = backend prefix) only when it is missing. The manifest
// carries no workspace name; the backend prefix is the root's base name
// (D003), the best available proxy. An existing row is never modified
// before publish.
func (o *Opener) ensureWorkspace(wsID domain.WorkspaceID, fallbackName string) (string, error) {
	w, err := o.cat.GetWorkspace(wsID)
	if err == nil {
		return w.Name, nil
	}
	if !isNotFound(err) {
		return "", fmt.Errorf("restore: workspace lookup: %w", err)
	}
	if err := o.cat.UpsertWorkspace(catalog.Workspace{
		ID: wsID, Name: fallbackName, Status: catalog.WorkspaceUnbound,
	}); err != nil {
		return "", fmt.Errorf("restore: create workspace row: %w", err)
	}
	return fallbackName, nil
}

// failOperation records errMsg on the operation's journal row without
// changing the phase (failure is an observation — mirroring
// lifecycle's failOperation). Best effort; the primary error is what
// the caller sees.
func (o *Opener) failOperation(opID domain.OperationID, phase, errMsg string) {
	_ = o.cat.FailOperation(opID, phase, errMsg)
}

// openIntentDigest freezes what one open intends (Foundation §12.1):
// the snapshot, its backend pair and the chosen destination.
func openIntentDigest(snapID domain.SnapshotID, dest string, snap catalog.Snapshot) string {
	h := sha256.New()
	h.Write([]byte("ebb:open:v1\x00"))
	h.Write([]byte(snapID))
	h.Write([]byte{0})
	h.Write([]byte(snap.PayloadBackendID))
	h.Write([]byte{0})
	h.Write([]byte(snap.SealBackendID))
	h.Write([]byte{0})
	h.Write([]byte(dest))
	return hex.EncodeToString(h.Sum(nil))
}

func isNotFound(err error) bool {
	return errors.Is(err, catalog.ErrNotFound)
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("restore: nil context")
	}
	return ctx.Err()
}
