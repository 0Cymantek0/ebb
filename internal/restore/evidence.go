package restore

// evidence.go is the exported retained-evidence loader shared by the CLI
// commands that refresh or consult a sealed snapshot's evidence without
// restoring it (`ebb verify`, `ebb forget`). It is the §12.5 steps 2-3
// half of the open sequence — seal validation plus payload document
// readback with the I12 digest gate — factored out of Opener.Open so the
// presentation layer never duplicates the strict-parsing rules. It
// performs NO coverage or content verification of the payload tree; that
// scope decision belongs to the caller (Foundation §11.4).

import (
	"context"
	"fmt"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// ReceiptFacts is the §16.4 seal receipt's verification evidence.
type ReceiptFacts struct {
	OperationID  string
	Checks       []string
	Scope        string
	Time         string
	ToolVersions map[string]string
}

// ManifestFacts is the §16.2 manifest subset the evidence loaders
// surface (identity, contract and the document digests/lengths a
// coverage re-derivation needs).
type ManifestFacts struct {
	CreatedAt   string
	Producer    string
	Scope       string
	Consistency string
	// Kind is the snapshot kind derived from the frozen manifest contract
	// (kindFromContract): trim-removal-plan scope → trim,
	// stopped-writers-asserted consistency → park, otherwise snapshot.
	Kind string
	// InventoryPath is the accounting document this capture sealed
	// (inventory.jsonl, or removal-manifest.json for a trim).
	InventoryPath  string
	InventoryCount int64
	// Digests bind the retained documents; ManifestBytes /
	// InventoryBytes / PolicyBytes are their exact lengths (the expected
	// op-dir tree nodes of a coverage re-check).
	ManifestDigest  string
	InventoryDigest string
	PolicyDigest    string
	ManifestBytes   int64
	InventoryBytes  int64
	PolicyBytes     int64
}

// Evidence is the read-back, digest-verified retained evidence of one
// sealed snapshot.
type Evidence struct {
	SnapshotID  domain.SnapshotID
	WorkspaceID domain.WorkspaceID
	Receipt     ReceiptFacts
	Manifest    ManifestFacts
	// Retained is the preserve-route entry set of the retained inventory
	// (the material the payload tree must cover; omitted entries carry
	// recorded routes instead, §16.3).
	Retained []domain.Entry
	// PreservedEntries / PreservedBytes summarize the retained set.
	PreservedEntries int64
	PreservedBytes   int64
	// WsPrefix / OpDirName are the manifest's tree-prefix bijection
	// (D003): the workspace tree and the op-dir tree inside the payload.
	WsPrefix  string
	OpDirName string
}

// LoadRetainedEvidence loads and verifies the retained evidence of one
// sealed snapshot: the seal receipt (strict-parsed, cross-checked against
// the catalog row) and the payload's manifest + accounting document
// (dumped from the backend, digest-checked against the receipt,
// strictly parsed). Failures are the typed restore errors (ErrSealInvalid
// / ErrVerification); the caller decides the exit outcome. store must be
// the vault's snapshot store and snap the snapshot's catalog row.
func LoadRetainedEvidence(ctx context.Context, store domain.SnapshotStore, vault VaultRef, snapID domain.SnapshotID, snap catalog.Snapshot) (Evidence, error) {
	o := &Opener{store: store, now: time.Now}
	receipt, err := o.loadSeal(ctx, vault, snapID, snap)
	if err != nil {
		return Evidence{}, err
	}
	docs, err := o.loadDocuments(ctx, vault, snapID, snap, receipt)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{
		SnapshotID:  snapID,
		WorkspaceID: snap.WorkspaceID,
		Receipt: ReceiptFacts{
			OperationID:  receipt.OperationID,
			Checks:       receipt.Verification.Checks,
			Scope:        receipt.Verification.Scope,
			Time:         receipt.Verification.Time,
			ToolVersions: receipt.Verification.ToolVersions,
		},
		Manifest: ManifestFacts{
			CreatedAt:       docs.manifest.CreatedAt,
			Producer:        docs.manifest.Producer,
			Scope:           docs.manifest.Contract.Scope,
			Consistency:     docs.manifest.Contract.Consistency,
			Kind:            kindFromContract(docs.manifest.Contract.Scope, docs.manifest.Contract.Consistency),
			InventoryPath:   docs.manifest.Inventory.Path,
			InventoryCount:  docs.manifest.Inventory.Count,
			ManifestDigest:  receipt.ManifestDigest,
			InventoryDigest: receipt.InventoryDigest,
			PolicyDigest:    docs.manifest.Policy.FrozenDigest,
			ManifestBytes:   docs.manifestLen,
			InventoryBytes:  docs.manifest.Inventory.Bytes,
			PolicyBytes:     int64(len(docs.manifest.Policy.Frozen)),
		},
		Retained:         docs.retained,
		PreservedEntries: docs.entriesRestored,
		PreservedBytes:   docs.preservedBytes,
		WsPrefix:         docs.wsPrefix,
		OpDirName:        opDirName(receipt.OperationID),
	}, nil
}

// LoadCapsuleEvidence loads and verifies the retained evidence of one
// payload held in a capsule's embedded repository WITHOUT a lifecycle
// seal receipt and WITHOUT a catalog row — the `ebb import` path of
// Foundation §15.3. A capsule's embedded seal is a DIFFERENT document
// (the destination seal of internal/capsule/seal.go), so the caller
// supplies only the two digests that seal declares
// (wantManifestDigest / wantInventoryDigest) plus the payload's backend
// id; everything else is re-derived from the payload's own bytes through
// the backend by the same shared trust core discovery uses
// (loadPayloadEvidence): the op dir is located by tree shape
// (.ebb-op-<32hex>/manifest.json — the destination seal's operation id
// belongs to the export, not to the payload's frozen op dir, so it is
// deliberately NOT consulted), both documents are dumped and
// digest-gated against the declared values, and the manifest is
// strict-parsed (schema version, required features, well-formed logical
// identities). I12 discipline throughout: a claimed digest is only ever
// compared against bytes read through the backend, and any mismatch —
// or a missing, ambiguous, malformed or inconsistent payload shape —
// refuses.
//
// The returned Evidence carries the identities and facts taken FROM the
// payload's own manifest: SnapshotID/WorkspaceID are the manifest's
// (the CALLER compares them against the capsule seal's replication
// claims — this loader takes no position on foreign identity fields),
// and Manifest.ManifestDigest / Manifest.InventoryDigest are the
// digests re-computed over the dumped bytes (equal to the want-digests
// on success).
//
// Receipt is the ZERO ReceiptFacts: no lifecycle receipt exists or was
// consulted on this path, and callers MUST NOT cite it as verification
// evidence (an imported snapshot gains a fresh LOCAL seal through the
// import protocol instead — Foundation §15.3).
//
// Failures are the typed restore errors: *ErrVerification{Check:
// "documents"} carrying the shared core's concrete refusal detail
// lines (same wording family as the discovery path's suspicious
// findings); the caller decides the exit outcome.
func LoadCapsuleEvidence(ctx context.Context, store domain.SnapshotStore, vault VaultRef, payloadBackendID, wantManifestDigest, wantInventoryDigest string) (Evidence, error) {
	if !isFullBackendID(payloadBackendID) {
		return Evidence{}, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("payload backend id %q is not a full 64-hex backend id", payloadBackendID)}}
	}
	ev, err := loadPayloadEvidence(ctx, store, vault, payloadBackendID, payloadClaims{
		manifestDigest:  wantManifestDigest,
		inventoryDigest: wantInventoryDigest,
		claimant:        "destination seal",
	})
	if err != nil {
		return Evidence{}, &ErrVerification{Check: "documents", Details: evidenceDetails(err)}
	}
	return Evidence{
		SnapshotID:  ev.snapshotID,
		WorkspaceID: ev.workspaceID,
		Manifest: ManifestFacts{
			CreatedAt:       ev.manifest.CreatedAt,
			Producer:        ev.manifest.Producer,
			Scope:           ev.manifest.Contract.Scope,
			Consistency:     ev.manifest.Contract.Consistency,
			Kind:            ev.kind,
			InventoryPath:   ev.manifest.Inventory.Path,
			InventoryCount:  ev.manifest.Inventory.Count,
			ManifestDigest:  ev.manifestDigest,
			InventoryDigest: ev.inventoryDigest,
			PolicyDigest:    ev.manifest.Policy.FrozenDigest,
			ManifestBytes:   ev.manifestLen,
			InventoryBytes:  ev.manifest.Inventory.Bytes,
			PolicyBytes:     int64(len(ev.manifest.Policy.Frozen)),
		},
		Retained:         ev.retained,
		PreservedEntries: ev.preservedEntries,
		PreservedBytes:   ev.preservedBytes,
		WsPrefix:         ev.wsPrefix,
		OpDirName:        ev.opDir,
	}, nil
}
