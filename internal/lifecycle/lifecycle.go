// Package lifecycle is Ebb's removal-authority module (Foundation
// §16.7): it owns the capture/seal/park/trim state machines of §12.2 and
// §17.3 and is the ONLY code in the codebase permitted to remove or
// rename source files. Every destructive path runs through an
// unexported removalPermit constructed after the seal, source identity,
// generation and route approvals have been verified; the audit tripwire
// (TestRemovalAuthorityTripwire) proves os.Remove/os.RemoveAll/os.Rename
// appear nowhere outside removal.go.
//
// The coordinator drives three collaborators through narrow seams:
//
//   - domain.SnapshotStore (implemented by internal/storage/restic):
//     chunking, encryption, integrity — Ebb never reimplements these;
//   - catalog.Catalog: the durable operation journal with CAS phase
//     transitions (Foundation §12.4) and the pinned snapshot index;
//   - domain.PlatformProbe: native root identity, file facts, volume
//     usage.
//
// Workspace serialization (v1, D11): a workspace lock is the catalog's
// ActiveOperations check performed inside beginOperation. Two processes
// can both pass the check before either's INSERT lands — the serialized
// single-process CLI makes that window acceptable in v1 and it is
// documented here deliberately rather than papered over with a filesystem
// lock (the root may be read-only; Foundation §12.1 defers real locking).
//
// Operation kinds: the catalog's closed vocabulary (park/open/trim/
// forget) has no "snapshot" kind, so `ebb snapshot` journals under kind
// "park" (the §12.2 parking sequence IS the capture sequence) and stops
// at SEALED→DONE; the snapshot row's kind ("snapshot" vs "park") carries
// the retention intent. This is a lifecycle-side convention; the catalog
// package was not modified.
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"ebb/internal/actions"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/policy"
)

// Store is the storage seam this package drives. It is satisfied by
// internal/storage/restic.Store; tests substitute filesystem-backed
// fault-injection fakes (Foundation §16.7: "native adapters can be
// replaced in tests with deterministic fault-injection implementations").
type Store interface {
	domain.SnapshotStore
}

// Dependencies wires the coordinator. All fields are required; New
// refuses nil seams so a half-constructed coordinator can never reach
// destructive code.
type Dependencies struct {
	Store domain.SnapshotStore
	Cat   *catalog.Catalog
	Probe domain.PlatformProbe
	Clock func() time.Time // injectable; defaults to time.Now
}

// VaultRef names one backend repository: the repo directory and the
// passfile holding its unlock secret. The passfile must live OUTSIDE any
// captured root (enforced in preflight — deleting the password with the
// workspace would make the retained copy unrecoverable).
type VaultRef struct {
	RepoDir  string
	Passfile string
}

// CaptureOptions parameterizes one capture. Policy arrives already
// parsed/resolved upstream; the git observation is produced by the CLI
// via the hardened adapter (D004) — lifecycle never runs git itself.
type CaptureOptions struct {
	WorkspaceName string
	// WorkspaceID, when non-empty, rebinds the known workspace (stable
	// identity across captures; the CLI owns this mapping because the
	// catalog exposes no lookup-by-name). Empty creates a new workspace.
	WorkspaceID domain.WorkspaceID
	Policy      policy.Policy
	// DoTrim lists regenerate group IDs approved for trim in this
	// operation (""-free); a plain capture leaves it empty.
	DoTrim []string
	// Park: after seal + revalidation, quarantine and remove the root
	// (Foundation §12.2 steps 6-9).
	Park bool
	// WriterAssertion is required non-empty when Park: the recorded
	// "assert-writers-stopped" source (Foundation §17.2).
	WriterAssertion string
	// Git carries the CLI's hardened git observation (§9.1, D004).
	Git domain.GitObservation
	// ActionDefs carries the exact captured action definitions (§16.2)
	// derived by the CLI at capture time (ecosystem recipes and custom
	// commands). The manifest freezes them in each action's optional
	// `definition` extension object; a graph that cannot run (cycles,
	// invalid definitions) fails the capture. lifecycle imports
	// internal/actions — a core package with no removal authority —
	// solely for this validation and wire form.
	ActionDefs []actions.Definition
	// ApprovalReady is invoked per trim group; a non-nil error blocks
	// that group's removal (lifecycle never runs actions).
	ApprovalReady func(groupID string) error
}

// SnapshotResult reports a completed, sealed capture (§12.2 steps 1-5
// for plain snapshots, steps 1-7 for park/trim before their tails).
type SnapshotResult struct {
	SnapshotID domain.SnapshotID
	// BackendIDs is [payload P, seal S].
	BackendIDs       [2]string
	EntriesPreserved int64
	EntriesOmitted   int64
	PreservedBytes   int64
	Warnings         []string
}

// ParkResult reports a completed park (§12.2 step 9).
type ParkResult struct {
	Snapshot SnapshotResult
	// VolumeDeltaObserved is the measured free-space change on the
	// source volume (positive = freed). Open handles may delay actual
	// release (Foundation §12.3); the measured number never lies about
	// what the filesystem reports.
	VolumeDeltaObserved int64
	// VolumeDeltaEstimated is the logical byte estimate from the
	// inventory (what the plan predicted).
	VolumeDeltaEstimated int64
}

// TrimResult reports a completed trim (§17.3).
type TrimResult struct {
	Snapshot       SnapshotResult
	Groups         []string
	EntriesRemoved int
	// ReclaimCommands carries the literal argv needed to recreate each
	// removed group (from the adapter recipe), one per group, aligned
	// with Groups.
	ReclaimCommands [][]string
}

// Coordinator executes the lifecycle sequences. Safe for sequential use
// by the serialized CLI (D11); the catalog serializes journal writes.
type Coordinator struct {
	store domain.SnapshotStore
	cat   *catalog.Catalog
	probe domain.PlatformProbe
	now   func() time.Time
}

// New validates the dependency seams and returns a ready Coordinator.
func New(d Dependencies) (*Coordinator, error) {
	if d.Store == nil {
		return nil, fmt.Errorf("lifecycle: dependencies: Store is required")
	}
	if d.Cat == nil {
		return nil, fmt.Errorf("lifecycle: dependencies: Cat is required")
	}
	if d.Probe == nil {
		return nil, fmt.Errorf("lifecycle: dependencies: Probe is required")
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &Coordinator{store: d.Store, cat: d.Cat, probe: d.Probe, now: d.Clock}, nil
}

// Producer identity recorded in every manifest/receipt (Foundation
// §16.1: records declare their producer). ProducerEbbVersion must stay
// in lockstep with internal/cli.Version.
const (
	ProducerEbbVersion = "0.1.0-dev"
	ProducerBackend    = "restic 0.19.1"
	producerString     = "ebb " + ProducerEbbVersion + "; " + ProducerBackend
)

// Ebb-owned sibling names (D003: the op dir is a sibling of the owned
// root on the same volume). All are dot-prefixed and carry the operation
// id; removeEbbOwned refuses to touch anything whose base name does not
// match one of these shapes.
const (
	opPrefix         = ".ebb-op-"
	sealPrefix       = ".ebb-seal-"
	journalPrefix    = ".ebb-journal-"
	quarantinePrefix = ".ebb-quarantine-"
)

// opDirName returns the deterministic payload op-dir name for opID.
func opDirName(opID domain.OperationID) string { return opPrefix + string(opID) }

// sealDirName returns the deterministic seal-dir name for opID.
func sealDirName(opID domain.OperationID) string { return sealPrefix + string(opID) }

// journalPath returns the deterministic progress-journal path under the
// root's parent for opID.
func journalPath(parent string, opID domain.OperationID) string {
	return filepath.Join(parent, journalPrefix+string(opID)+".jsonl")
}

// quarantinePath returns the unique quarantine sibling for opID. It must
// not pre-exist (rename-over-dir always fails on Windows — platform
// probe), which callers treat as an error, never something to overwrite.
func quarantinePath(parent string, opID domain.OperationID) string {
	return filepath.Join(parent, quarantinePrefix+string(opID))
}

// intentDigest freezes what this operation intends (Foundation §12.1:
// every operation carries an intent digest). It hashes the frozen policy
// bytes plus the option fields that shape the capture.
func intentDigest(frozenPolicy []byte, opts CaptureOptions) string {
	h := sha256.New()
	h.Write(frozenPolicy)
	h.Write([]byte{0})
	fmt.Fprintf(h, "ws=%s\x00park=%v\x00", opts.WorkspaceName, opts.Park)
	for _, g := range sortedCopy(opts.DoTrim) {
		h.Write([]byte(g))
		h.Write([]byte{0})
	}
	h.Write([]byte(opts.WriterAssertion))
	return hex.EncodeToString(h.Sum(nil))
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// freezePolicy renders the parsed policy back to canonical TOML. The
// manifest freezes these bytes (§16.2 "frozen original policy"); a
// changed policy produces a different frozen digest and therefore a new
// logical snapshot.
func freezePolicy(p policy.Policy) ([]byte, error) {
	b, err := toml.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: freeze policy: %w", err)
	}
	return b, nil
}

// resolvedRoutesDigest digests the resolved effective policy: the
// canonical (path, route) stream plus group decisions (§16.2 "digest of
// resolved effective policy").
func resolvedRoutesDigest(entries []domain.Entry, groupIDs []string) string {
	h := sha256.New()
	for _, g := range sortedCopy(groupIDs) {
		h.Write([]byte("group:" + g + "\x00"))
	}
	for _, e := range entries {
		h.Write([]byte(e.Path))
		h.Write([]byte{0})
		h.Write([]byte(e.Route))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// preflight validates containment: the vault repository and passfile
// must live outside the captured root (capturing the repo into itself,
// or deleting the passfile with the workspace, are both unacceptable).
func preflight(rootAbs string, vault VaultRef) error {
	repoAbs := filepath.Clean(mustAbs(vault.RepoDir))
	if pathEqual(repoAbs, rootAbs) || underPath(rootAbs, repoAbs) {
		return &ErrDestructiveBlocked{Reasons: []string{
			fmt.Sprintf("vault repository %s is inside the captured root %s; capture would destroy its own backend", repoAbs, rootAbs)}}
	}
	if underPath(rootAbs, filepath.Clean(mustAbs(vault.Passfile))) {
		return &ErrDestructiveBlocked{Reasons: []string{
			fmt.Sprintf("vault passfile %s is inside the captured root %s; parking would delete the unlock secret", vault.Passfile, rootAbs)}}
	}
	return nil
}

func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

// pathEqual compares cleaned absolute paths. v1 requires callers to use
// one consistent spelling of a root (the journal records it and Recover
// compares identities, not names, per I13).
func pathEqual(a, b string) bool { return filepath.Clean(a) == filepath.Clean(b) }

// underPath reports whether child equals or lies below parent (native
// separators; both must already be cleaned/absolute).
func underPath(parent, child string) bool {
	if parent == child {
		return true
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// beginOperation resolves/creates the workspace and opens the journaled
// operation with the F37 single-active-operation check.
//
// §12.1 race window (documented, accepted for v1): the check and the
// INSERT are not one transaction across processes; two simultaneous
// invocations could both pass. The serialized CLI (D11) is the
// mitigation; a real cross-process lock is deferred with Foundation.
func (c *Coordinator) beginOperation(ctx context.Context, rootAbs string, ident domain.RootIdentity, opts CaptureOptions, kind string) (domain.WorkspaceID, domain.OperationID, error) {
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}
	wsID := opts.WorkspaceID
	if wsID == "" {
		wsID = domain.WorkspaceID(domain.NewID())
	}
	// Rebind name + identity; status stays live until a park completes.
	if err := c.cat.UpsertWorkspace(catalog.Workspace{
		ID:           wsID,
		Name:         opts.WorkspaceName,
		RootPath:     rootAbs,
		RootIdentity: ident.String(),
		Status:       catalog.WorkspaceLive,
	}); err != nil {
		return "", "", fmt.Errorf("lifecycle: upsert workspace: %w", err)
	}
	active, err := c.cat.ActiveOperations(wsID)
	if err != nil {
		return "", "", fmt.Errorf("lifecycle: active operations: %w", err)
	}
	if len(active) > 0 {
		ids := make([]string, 0, len(active))
		for _, op := range active {
			ids = append(ids, string(op.ID))
		}
		return "", "", &ErrOpInProgress{WorkspaceID: wsID, Operations: ids}
	}
	frozen, err := freezePolicy(opts.Policy)
	if err != nil {
		return "", "", err
	}
	opID, err := c.cat.BeginOperation(wsID, kind, rootAbs, ident.String(), intentDigest(frozen, opts))
	if err != nil {
		return "", "", fmt.Errorf("lifecycle: begin operation: %w", err)
	}
	return wsID, opID, nil
}

// failOperation records errMsg on the operation's journal row (phase
// unchanged — failure is an observation, not a transition). Best effort:
// the original error is what the caller sees.
func (c *Coordinator) failOperation(opID domain.OperationID, phase, errMsg string) {
	if err := c.cat.FailOperation(opID, phase, errMsg); err != nil {
		// Cannot fail the failure; the message is already in the returned
		// error. Surface nothing here — never mask the primary error.
		_ = err
	}
}
