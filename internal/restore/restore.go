// Package restore implements Foundation §12.5's restore ("open")
// sequence: validate the retained seal, read back and verify the payload
// documents against the seal's digests, materialize the preserved
// workspace tree into a private staging directory, VERIFY the staged
// tree against an oracle independent of the restore encoder (a fresh
// inventory scan compared to the retained inventory — the E10 defense),
// publish by renaming onto the absent destination, and record durable
// open-operation state (PLANNED → RESTORING → FILES_READY).
//
// After publication, the reconstruction phase of §12.5's last paragraphs
// runs the RETAINED, locally-approved reconstruction actions at the
// final destination (rebuild.go: REBUILDING → READY → DONE, journaling
// every attempt in action_runs and verifying protected files — F36).
// `ebb open --files-only` stops after publication (FILES_READY → DONE);
// a legacy manifest without exact action definitions is hint-only —
// reported, never executed. A failed rebuild lands at REBUILD_FAILED
// (non-terminal, resolvable by `ebb open --resume`) and NEVER removes
// the published files (I08). Opening never releases the recovery
// obligation: the snapshot stays pinned (I07).
//
// The ONLY filesystem mutations this package performs: creating its
// staging directories, restoring the backend subtree into them
// (link nodes excluded), recreating retained links inside the staging
// from the retained inventory's LinkTarget (links.go), the publish
// rename onto an absent destination, shape-gated removal of its own
// .ebb-stage-<opID> directories, and removal of an EMPTY destination
// directory. Unrelated content is never touched (§12.5: "An unrelated
// nonempty directory is never overwritten"). Reconstruction actions
// execute through the injected actions.Runner seam — this package adds
// no removal authority of its own (Foundation §9.5).
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

	"ebb/internal/actions"
	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// Dependencies wires the opener. All fields except Clock, CreateLink and
// the rebuild seams are required; New refuses nil seams so a
// half-constructed opener can never reach publishing code (mirroring
// lifecycle.New).
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
	// Runner executes approved reconstruction actions at the destination
	// (Foundation §12.5, §9.5). Optional: required only when an Open
	// with recorded action definitions runs without FilesOnly.
	// Satisfied by *actions.Runner; tests substitute a fake.
	Runner ActionRunner
	// Approver reads the recorded local approvals (Foundation §7.3);
	// production wires the approvalstore. Required with Runner.
	Approver actions.Approver
	// Approve is the interactive approval seam (one grouped decision per
	// rebuild — Foundation §5.2): it receives every action whose
	// approval is missing or stale, may prompt and record through the
	// same store backing Approver, and must never be called from this
	// package's own logic beyond the rebuild flow. nil = non-interactive
	// (a pending approval then blocks the rebuild).
	Approve ApprovalResolver
	Clock   func() time.Time // optional; defaults to time.Now
}

// VaultRef names one backend repository: the repo directory and the
// passfile holding its unlock secret. Local definition mirroring
// lifecycle.VaultRef; restore never imports that package.
type VaultRef struct {
	RepoDir  string
	Passfile string
}

// Options parameterizes one Open. FilesOnly stops after the preserved
// files are published (`ebb open --files-only`, Foundation §17.2):
// reported as files-ready, never a runnable environment, and the
// operation completes FILES_READY → DONE (nothing outstanding). The
// default (FilesOnly=false) runs the recorded reconstruction actions at
// the final destination when the manifest carries exact action
// definitions; a manifest without definitions is effectively files-only
// (legacy payloads are hint-only — reported, never executed).
type Options struct {
	// Destination is the final absolute path for the workspace root.
	Destination string
	// FilesOnly stops after publication (no reconstruction).
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

// Result reports a completed (or rebuild-failed) open. Phase carries the
// operation's final durable phase (DONE, or REBUILD_FAILED when the
// returned error is *ErrRebuildFailed — the files are still published).
type Result struct {
	OperationID domain.OperationID
	SnapshotID  domain.SnapshotID
	WorkspaceID domain.WorkspaceID
	Destination string

	EntriesRestored int64
	BytesRestored   int64
	Warnings        []string
	RebuildHints    []RebuildHint
	// Phase is the operation's terminal-or-resting phase after the call.
	Phase string
	// Actions reports each reconstruction action's outcome (empty for
	// files-only opens and legacy hint-only payloads).
	Actions []ActionReport
}

// Opener executes the §12.5 restore sequence. Safe for sequential use
// by the serialized CLI (D11); the catalog serializes journal writes.
type Opener struct {
	store      domain.SnapshotStore
	cat        *catalog.Catalog
	probe      domain.PlatformProbe
	createLink LinkCreator
	runner     ActionRunner
	approver   actions.Approver
	approve    ApprovalResolver
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
	return &Opener{
		store: d.Store, cat: d.Cat, probe: d.Probe, createLink: d.CreateLink,
		runner: d.Runner, approver: d.Approver, approve: d.Approve,
		now: d.Clock,
	}, nil
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
	dest, err := o.preflight(ctx, snap.WorkspaceID, vault, opts.Destination, docs)
	if err != nil {
		return res, err
	}
	res.Destination = dest

	// The rebuild plan: exact definitions only (legacy manifests without
	// the definition extension are hint-only and never execute). The
	// runner/approver seams are validated BEFORE any staging side effect
	// so a wiring gap is a usage error, not a mid-operation failure.
	defs, derr := rebuildDefinitions(docs.manifest)
	if derr != nil {
		return res, derr
	}
	runRebuild := !opts.FilesOnly && len(defs) > 0
	if runRebuild && (o.runner == nil || o.approver == nil) {
		return res, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"the snapshot records %d reconstruction action(s) and FilesOnly is false, but the runner/approver seams are not wired", len(defs))}
	}

	// ---- §12.5 interrupted-staging recovery (§12.4 RESTORING row) ----
	warnings, err := o.recoverInterruptedOpen(ctx, snap.WorkspaceID, dest)
	if err != nil {
		return res, err
	}
	res.Warnings = append(res.Warnings, warnings...)
	if opts.FilesOnly && len(rebuildHints(docs.manifest)) > 0 {
		res.Warnings = append(res.Warnings,
			"FilesOnly: reconstruction actions were skipped (--files-only); the workspace is files-ready, not runnable (Foundation §17.2)")
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

	// ---- §12.5 step 9: finish ------------------------------------------
	// Files-only (or a legacy manifest with no definitions): nothing is
	// outstanding — complete the operation FILES_READY → DONE (the D006
	// convention: DONE means no reconciliation outstanding; leaving
	// FILES_READY active forever blocked the workspace's future
	// operations).
	res.EntriesRestored = docs.entriesRestored
	res.BytesRestored = docs.preservedBytes
	res.RebuildHints = rebuildHints(docs.manifest)
	if err := removeStage(stage); err != nil {
		res.Warnings = append(res.Warnings, fmt.Sprintf("cleanup staging %s failed: %v", stage, err))
	}
	if !runRebuild {
		if err := o.cat.AdvanceOperation(opID, catalog.PhaseFilesReady, catalog.PhaseDone); err != nil {
			return res, fmt.Errorf("restore: advance %s: FILES_READY -> DONE: %w", opID, err)
		}
		res.Phase = catalog.PhaseDone
		return res, nil
	}

	// ---- §12.5 last paragraphs: reconstruction at the final path ------
	// REBUILDING → (run retained, locally-approved actions) → F36 check
	// → READY → DONE. Any failure lands at REBUILD_FAILED (non-terminal,
	// resumable) with the published files intact (I08) and the snapshot
	// pinned (I07).
	if err := o.cat.AdvanceOperation(opID, catalog.PhaseFilesReady, catalog.PhaseRebuilding); err != nil {
		return res, fmt.Errorf("restore: advance %s: FILES_READY -> REBUILDING: %w", opID, err)
	}
	reports, rerr := o.runRebuild(ctx, opID, dest, defs, docs.retained, false)
	res.Actions = reports
	if rerr != nil {
		res.Phase = catalog.PhaseRebuildFailed
		return res, rerr
	}
	if err := o.completeRebuild(opID); err != nil {
		return res, err
	}
	res.Phase = catalog.PhaseDone
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
