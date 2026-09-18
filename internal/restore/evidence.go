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
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
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
