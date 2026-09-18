package restore

// discovery.go implements the vault side of Foundation §11.5's catalog
// recovery: "Recovery from catalog loss opens the vault, discovers and
// verifies seals, reads their payload manifests, and reconstructs
// workspace/snapshot records. The user must still know the vault location
// and unlock secret." DiscoverVault walks ONE vault's backend snapshot
// listing, pairs payloads with seals, re-derives the payload verification
// from the vault's own bytes and returns what it found. It performs NO
// catalog writes — the caller (the CLI's `ebb init --rebuild-catalog`)
// imports the discoveries through catalog.ImportDiscoveredSnapshot so the
// durable-state ordering stays in one place.
//
// ---- The trust chain on the discovery path (D017/D020 tension) --------
//
// D017/D020 make every retained-document read cross-check the CATALOG's
// seal-time digests — the tamper-independent witness, because an attacker
// with vault write access can rewrite every document in the vault
// consistently. After catalog LOSS there is no such witness; nothing
// outside the vault survives. The discovery path therefore establishes
// trust differently, and the difference must be stated exactly:
//
// What the vault-password attacker CANNOT do on this path:
//
//   - Republish different content under an EXISTING backend snapshot id.
//     Restic snapshot ids are content-derived (the serialized snapshot
//     references the Merkle-ized tree, whose inner nodes commit to the
//     chunk ids of every file). The id named by a receipt therefore
//     deterministically names the exact bytes we then read and hash;
//     forging a second preimage is a SHA-256 break. The receipt digests
//     bind the manifest/inventory, and reading those documents ourselves
//     re-derives the binding from authenticated bytes rather than
//     trusting any listing (I12 discipline).
//
//   - Make discovery DESTROY or overwrite anything. Discovery is
//     read-only against the vault and purely additive against the
//     catalog; every reconstructed workspace is UNBOUND (§16.5: never a
//     guessed live/parked), every snapshot pinned (I07: absence of pin
//     records can never license release), and no destructive command
//     operates from UNBOUND state without further explicit user action
//     (`ebb open --to <dir>` names a destination; `ebb forget` demands a
//     typed id).
//
//   - Make a TAMPERED pair pass: the receipt's (manifest_digest,
//     inventory_digest) are re-hashed against the payload's actual
//     document bytes through the backend; any mismatch — plus any
//     malformed receipt/manifest, wrong-shape seal tree, missing payload,
//     duplicate logical id, or receipt minted for a different repository
//     id — is refused as suspicious (retain + report, never delete,
//     §11.5 repair mode).
//
// What the attacker CAN do, and why it is bounded:
//
//   - MINT wholly new, internally consistent P/S pairs (the password is
//     the vault's root of trust post-catalog-loss). The worst outcome is
//     plausible-looking injected workspace rows in the rebuilt catalog —
//     a phishing-shaped nuisance, not a safety break, because of the
//     UNBOUND/pinned/no-deletion posture above. Opening such a row
//     restores attacker-chosen bytes only into a destination the user
//     explicitly named.
//
//   - WITHHOLD or corrupt real snapshots (delete, or corrupt-and-reseal).
//     Discovery cannot detect absence of what it never saw; payloads
//     left without a valid seal are reported as unsealed-and-pinned
//     (§11.3: an incomplete operation, not garbage) and broken
//     consistencies as suspicious. Never does discovery compensate by
//     treating anything as disposable (§11.5).
//
// One consequence worth naming: because the rebuilt catalog rows carry
// the digests WE re-derived from the vault's authenticated bytes (not
// attacker-supplied strings), the rebuild RESTORES the D017/D020 witness
// for every future retained-document read — verify/forget/open bind
// against digests the local machine computed itself.
//
// Tags (ebb-kind/ebb-op/ws) on backend snapshots are treated as HINTS
// for pairing, never as proof: restic tags are mutable metadata (and
// retagging mints a new snapshot id). Every adoption decision rests on
// the seal tree's shape (.ebb-seal-<opID>/receipt.json), the strict
// receipt parse and the digest re-derivation described above.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// discoveryTags classify backend snapshots during discovery. They mirror
// the tags lifecycle's capture path writes (capture.go/trim.go); a
// snapshot without them is out of scope and merely reported.
const (
	tagEbbKind     = "ebb-kind"
	tagKindSeal    = "seal"
	tagKindPayload = "payload"
)

// Reader-side twins of the §16.2 contract vocabulary the writer freezes
// into manifests (lifecycle declares the authoritative constants; this
// package re-declares the strings it parses, per its local-reader rule).
const (
	scopeTrimPlanDoc        = "trim-removal-plan"
	consistencyStoppedWrDoc = "stopped-writers-asserted"
)

// DiscoveredPair is one SEALED pair (payload P + seal S) that passed the
// full discovery verification and may be imported as a snapshot row.
type DiscoveredPair struct {
	// SnapshotID / WorkspaceID are the LOGICAL 32-hex ids from the
	// receipt, cross-checked against the payload's manifest.
	SnapshotID  domain.SnapshotID
	WorkspaceID domain.WorkspaceID
	// WorkspaceName is the payload's main-root tree prefix (D003
	// bijection): the rebuilt workspace's display name.
	WorkspaceName string
	// PayloadBackendID / SealBackendID are the vault's snapshot ids; the
	// payload id comes from the receipt (inside the authenticated seal
	// bytes), the seal id from the listing.
	PayloadBackendID string
	SealBackendID    string
	// ManifestDigest / InventoryDigest were re-derived by hashing the
	// payload's actual documents and found equal to the receipt's.
	ManifestDigest  string
	InventoryDigest string
	// Kind is derived from the frozen manifest contract: trim-removal-plan
	// scope → trim; stopped-writers-asserted consistency → park;
	// best-effort-live → snapshot (a mis-derivation can only affect D011's
	// park-over-snapshot preference between openable kinds, never safety).
	Kind string
	// CreatedAt is the payload snapshot's backend time (recency for D011).
	CreatedAt string
	// Receipt holds the seal's verification evidence (checks/scope/time).
	Receipt ReceiptFacts
	// PreservedEntries / PreservedBytes summarize the retained inventory
	// (report shape; the same numbers verify/forget surface).
	PreservedEntries int64
	PreservedBytes   int64
}

// UnsealedPayload is a payload snapshot with no valid readable seal: an
// incomplete operation, not garbage (§11.3). Its identity comes from the
// payload's own manifest; without a seal nothing witnesses those bytes,
// so the caller records it pinned with an empty seal id — exactly the
// shape `ebb forget` refuses and D011 selection skips.
type UnsealedPayload struct {
	SnapshotID       domain.SnapshotID
	WorkspaceID      domain.WorkspaceID
	WorkspaceName    string
	PayloadBackendID string
	// ManifestDigest / InventoryDigest are computed over the bytes read
	// (no witness cross-check was possible).
	ManifestDigest  string
	InventoryDigest string
	Kind            string
	CreatedAt       string
	// SealBackendID names a seal snapshot that EXISTS for this payload but
	// failed verification ("" when no seal candidate referenced it).
	SealBackendID string
}

// SuspiciousFinding is one refusal: a seal-shaped candidate (or payload)
// whose evidence did not verify. Nothing is deleted; the material is
// retained for §11.5 repair-mode review.
type SuspiciousFinding struct {
	// BackendID is the snapshot the finding is about (the seal when one
	// was examined, else the payload).
	BackendID string
	// PayloadBackendID names the payload involved when known.
	PayloadBackendID string
	// SnapshotID / WorkspaceID when a parsed receipt or manifest claimed
	// them (report evidence).
	SnapshotID  string
	WorkspaceID string
	// Reasons are the concrete verification failures.
	Reasons []string
}

// VaultDiscovery is the full result of one vault walk.
type VaultDiscovery struct {
	// RepoID is the repository identity the walk observed ("" when the
	// caller did not supply one; see DiscoverVault).
	RepoID string
	// Pairs passed verification, ordered deterministically (payload
	// backend time, then ids).
	Pairs []DiscoveredPair
	// Unsealed are payloads without a valid seal, same order discipline.
	Unsealed []UnsealedPayload
	// Suspicious are refused candidates, same order discipline.
	Suspicious []SuspiciousFinding
	// Unrecognized backend snapshot ids carried no ebb tags: reported,
	// never touched (they may be the user's own restic snapshots).
	Unrecognized []string
}

// DiscoverVault walks one vault and reconstructs the sealed pairs,
// unsealed payloads and suspicious findings it contains. store must be
// the vault's snapshot store; vault its repo dir + passfile. repoID, when
// non-empty, is cross-checked against every receipt's backend_repo_id (a
// receipt minted for a different repository is suspicious). Backend
// infrastructure failures of the WALK itself (the initial listing, or the
// repository id probe) return an error for the caller to classify as a
// vault verification failure; per-snapshot read failures degrade into
// Suspicious findings so one corrupt snapshot cannot hide the rest
// (§11.5: retain data, enter repair mode).
func DiscoverVault(ctx context.Context, store domain.SnapshotStore, vault VaultRef, repoID string) (*VaultDiscovery, error) {
	refs, err := store.List(ctx, vault.RepoDir, vault.Passfile)
	if err != nil {
		return nil, fmt.Errorf("discovery: listing vault %s: %w", vault.RepoDir, err)
	}

	d := &VaultDiscovery{RepoID: repoID}
	present := map[string]domain.SnapshotRef{}
	for _, r := range refs {
		present[r.BackendID] = r
		switch r.Tags[tagEbbKind] {
		case tagKindSeal:
			// collected below
		case tagKindPayload:
			// collected below
		default:
			d.Unrecognized = append(d.Unrecognized, r.BackendID)
		}
	}

	// ---- pass 1: seals -------------------------------------------------
	// Deterministic order: backend time then id, so a repeated discovery
	// on an unchanged vault reports and adopts in the same order and the
	// first-wins duplicate policy below is stable.
	var seals, payloads []domain.SnapshotRef
	for _, r := range refs {
		switch r.Tags[tagEbbKind] {
		case tagKindSeal:
			seals = append(seals, r)
		case tagKindPayload:
			payloads = append(payloads, r)
		}
	}
	sortRefs(seals)
	sortRefs(payloads)

	claimedPayload := map[string]bool{} // payload ids adopted or implicated in a suspicious pair
	seenLogical := map[string]bool{}    // logical snapshot ids already adopted
	for _, s := range seals {
		pair, finding := discoverSeal(ctx, store, vault, s, present, repoID)
		if pair != nil {
			if seenLogical[string(pair.SnapshotID)] {
				d.Suspicious = append(d.Suspicious, SuspiciousFinding{
					BackendID: s.BackendID, PayloadBackendID: pair.PayloadBackendID,
					SnapshotID:  string(pair.SnapshotID),
					WorkspaceID: string(pair.WorkspaceID),
					Reasons: []string{fmt.Sprintf(
						"two seals claim the same logical snapshot id %s (duplicate logical identity is not adoption evidence)",
						pair.SnapshotID)},
				})
				claimedPayload[pair.PayloadBackendID] = true
				continue
			}
			seenLogical[string(pair.SnapshotID)] = true
			claimedPayload[pair.PayloadBackendID] = true
			d.Pairs = append(d.Pairs, *pair)
			continue
		}
		if finding != nil {
			if finding.PayloadBackendID != "" {
				claimedPayload[finding.PayloadBackendID] = true
			}
			d.Suspicious = append(d.Suspicious, *finding)
		}
	}

	// ---- pass 2: unclaimed payloads ------------------------------------
	for _, p := range payloads {
		if claimedPayload[p.BackendID] {
			continue
		}
		up, finding := discoverUnsealed(ctx, store, vault, p)
		if up != nil {
			d.Unsealed = append(d.Unsealed, *up)
			continue
		}
		if finding != nil {
			d.Suspicious = append(d.Suspicious, *finding)
		}
	}
	return d, nil
}

// discoverSeal verifies one seal candidate end to end. Exactly one of
// pair/finding is non-nil; (nil, nil) cannot happen (a seal that yields
// nothing is itself a finding).
func discoverSeal(ctx context.Context, store domain.SnapshotStore, vault VaultRef, seal domain.SnapshotRef, present map[string]domain.SnapshotRef, repoID string) (*DiscoveredPair, *SuspiciousFinding) {
	refuse := func(reasons ...string) (*DiscoveredPair, *SuspiciousFinding) {
		return nil, &SuspiciousFinding{BackendID: seal.BackendID, Reasons: reasons}
	}

	// Shape gate: exactly one .ebb-seal-<32hex>/receipt.json file node
	// (the same matching loadSeal applies on the open path).
	receiptPath, dirOpID, err := findReceiptNode(ctx, store, vault, seal.BackendID)
	if err != nil {
		return refuse(err.Error())
	}
	raw, err := store.DumpFile(ctx, vault.RepoDir, vault.Passfile, seal.BackendID, receiptPath)
	if err != nil {
		return refuse(fmt.Sprintf("reading seal receipt %s: %v", receiptPath, err))
	}
	var receipt receiptDoc
	if err := decodeStrict(raw, &receipt); err != nil {
		return refuse(fmt.Sprintf("receipt %s failed strict parsing: %v", receiptPath, err))
	}

	var problems []string
	if receipt.SchemaVersion != schemaVersionCurrent {
		problems = append(problems, fmt.Sprintf("receipt schema_version %d, reader supports %d",
			receipt.SchemaVersion, schemaVersionCurrent))
	}
	if len(receipt.RequiredFeatures) > 0 {
		problems = append(problems, fmt.Sprintf("receipt declares unsupported required features %v", receipt.RequiredFeatures))
	}
	if receipt.OperationID != dirOpID {
		problems = append(problems, fmt.Sprintf("receipt operation_id %q does not match the seal directory's embedded id %q",
			receipt.OperationID, dirOpID))
	}
	if _, perr := domain.ParseID(receipt.SnapshotID); perr != nil {
		problems = append(problems, fmt.Sprintf("receipt snapshot_id %q: %v", receipt.SnapshotID, perr))
	}
	if _, perr := domain.ParseID(receipt.WorkspaceID); perr != nil {
		problems = append(problems, fmt.Sprintf("receipt workspace_id %q: %v", receipt.WorkspaceID, perr))
	}
	if !isFullBackendID(receipt.PayloadBackendID) {
		problems = append(problems, fmt.Sprintf("receipt payload_backend_id %q is not a full 64-hex backend id", receipt.PayloadBackendID))
	}
	if receipt.ManifestDigest == "" || receipt.InventoryDigest == "" {
		problems = append(problems, "receipt carries an empty manifest/inventory digest; the payload cannot be verified")
	}
	if repoID != "" && receipt.BackendRepoID != "" && receipt.BackendRepoID != repoID {
		problems = append(problems, fmt.Sprintf("receipt backend_repo_id %q differs from this repository's id %q (seal minted for another vault)",
			receipt.BackendRepoID, repoID))
	}
	if len(problems) > 0 {
		return refuse(problems...)
	}

	payload, ok := present[receipt.PayloadBackendID]
	if !ok {
		return refuse(fmt.Sprintf("the receipt names payload %s, which is not present in the vault (withheld or never captured; retained as-is)",
			receipt.PayloadBackendID))
	}

	// Trust core: re-derive the payload verification from P's own bytes.
	// The receipt's digests bind the manifest and the accounting document;
	// we hash what the backend actually stores and compare (I12).
	opDir := opDirName(receipt.OperationID)
	manifestRaw, err := store.DumpFile(ctx, vault.RepoDir, vault.Passfile, payload.BackendID, "/"+opDir+"/"+manifestName)
	if err != nil {
		return refuse(fmt.Sprintf("reading %s from payload %s: %v", "/"+opDir+"/"+manifestName, payload.BackendID, err))
	}
	if got := digestBytes(manifestRaw); got != receipt.ManifestDigest {
		return refuse(fmt.Sprintf("%s: digest %s, receipt declares %s — the payload does not match its seal",
			manifestName, got, receipt.ManifestDigest))
	}
	var manifest manifestDoc
	if err := decodeStrict(manifestRaw, &manifest); err != nil {
		return refuse(fmt.Sprintf("%s failed strict parsing: %v", manifestName, err))
	}
	if manifest.SchemaVersion != schemaVersionCurrent {
		return refuse(fmt.Sprintf("manifest schema_version %d, reader supports %d", manifest.SchemaVersion, schemaVersionCurrent))
	}
	if len(manifest.RequiredFeatures) > 0 {
		return refuse(fmt.Sprintf("manifest declares unsupported required features %v", manifest.RequiredFeatures))
	}
	if manifest.SnapshotID != receipt.SnapshotID {
		return refuse(fmt.Sprintf("manifest snapshot_id %q disagrees with the receipt's %q", manifest.SnapshotID, receipt.SnapshotID))
	}
	if manifest.WorkspaceID != receipt.WorkspaceID {
		return refuse(fmt.Sprintf("manifest workspace_id %q disagrees with the receipt's %q", manifest.WorkspaceID, receipt.WorkspaceID))
	}
	if manifest.Inventory.Path == "" {
		return refuse("manifest names no accounting document (inventory.path empty)")
	}
	invRaw, err := store.DumpFile(ctx, vault.RepoDir, vault.Passfile, payload.BackendID, "/"+opDir+"/"+manifest.Inventory.Path)
	if err != nil {
		return refuse(fmt.Sprintf("reading %s from payload %s: %v", manifest.Inventory.Path, payload.BackendID, err))
	}
	if got := digestBytes(invRaw); got != receipt.InventoryDigest {
		return refuse(fmt.Sprintf("%s: digest %s, receipt declares %s — the payload does not match its seal",
			manifest.Inventory.Path, got, receipt.InventoryDigest))
	}

	// Workspace name + kind come from the frozen manifest (D003 prefix
	// bijection; §16.2 contract vocabulary).
	var main *manifestRoot
	for i := range manifest.Roots {
		if manifest.Roots[i].ID == string(domain.RootMain) {
			main = &manifest.Roots[i]
			break
		}
	}
	if main == nil {
		return refuse(fmt.Sprintf("manifest has no root with id %q; the workspace tree prefix is unknown", domain.RootMain))
	}
	if err := validBackendPrefix(main.BackendPrefix); err != nil {
		return refuse(fmt.Sprintf("main root backend_prefix: %v", err))
	}

	// Parse the accounting stream too: canonical order, validated entries
	// (the same strictness loadDocuments applies — a well-formed digest
	// over garbage bytes is not adoption evidence). Trim payloads carry
	// removal-manifest.json instead of inventory.jsonl, so only the
	// inventory.jsonl shape is parsed here; the digest gate above already
	// bound whichever document the manifest names.
	var preservedEntries, preservedBytes int64
	if manifest.Inventory.Path == inventoryName {
		entries, perr := parseInventory(invRaw)
		if perr != nil {
			return refuse(fmt.Sprintf("retained accounting document: %v", perr))
		}
		if manifest.Inventory.Count != int64(len(entries)) {
			return refuse(fmt.Sprintf("manifest inventory count %d, payload carries %d records",
				manifest.Inventory.Count, len(entries)))
		}
		for _, e := range entries {
			if e.Route != domain.RoutePreserve {
				continue
			}
			preservedEntries++
			if e.Kind == domain.KindFile {
				preservedBytes += e.LogicalSize
			}
		}
	}

	return &DiscoveredPair{
		SnapshotID:       domain.SnapshotID(receipt.SnapshotID),
		WorkspaceID:      domain.WorkspaceID(receipt.WorkspaceID),
		WorkspaceName:    main.BackendPrefix,
		PayloadBackendID: payload.BackendID,
		SealBackendID:    seal.BackendID,
		ManifestDigest:   receipt.ManifestDigest,
		InventoryDigest:  receipt.InventoryDigest,
		Kind:             kindFromContract(manifest.Contract.Scope, manifest.Contract.Consistency),
		CreatedAt:        firstNonEmpty(payload.Time, domain.FormatTime(time.Now().UTC())),
		Receipt: ReceiptFacts{
			OperationID:  receipt.OperationID,
			Checks:       receipt.Verification.Checks,
			Scope:        receipt.Verification.Scope,
			Time:         receipt.Verification.Time,
			ToolVersions: receipt.Verification.ToolVersions,
		},
		PreservedEntries: preservedEntries,
		PreservedBytes:   preservedBytes,
	}, nil
}

// discoverUnsealed reads one unclaimed payload's manifest to recover its
// logical identity. Without a seal there is no witness for those bytes;
// the caller records the row pinned with an empty seal backend id.
func discoverUnsealed(ctx context.Context, store domain.SnapshotStore, vault VaultRef, p domain.SnapshotRef) (*UnsealedPayload, *SuspiciousFinding) {
	refuse := func(reasons ...string) (*UnsealedPayload, *SuspiciousFinding) {
		return nil, &SuspiciousFinding{BackendID: p.BackendID, Reasons: reasons}
	}

	// The op dir is located by tree shape (.ebb-op-<32hex>/manifest.json),
	// not by the ws/ebb-op tags (tags are hints).
	ls, err := store.Ls(ctx, vault.RepoDir, vault.Passfile, p.BackendID)
	if err != nil {
		return refuse(fmt.Sprintf("listing payload: %v", err))
	}
	var manifestPath, dirOpID string
	matches := 0
	for _, e := range ls {
		if e.Kind != domain.KindFile {
			continue
		}
		dir, base := splitTreePath(e.Path)
		if base != manifestName {
			continue
		}
		id, ok := opDirID(strings.TrimSuffix(dir, "/"))
		if !ok {
			continue
		}
		matches++
		manifestPath, dirOpID = e.Path, id
	}
	switch {
	case matches == 0:
		return refuse(fmt.Sprintf("no %s<32hex>/%s node found (not an Ebb payload shape; retained as-is)",
			opPrefix, manifestName))
	case matches > 1:
		return refuse(fmt.Sprintf("%d candidate manifest nodes; the payload is ambiguous", matches))
	}

	raw, err := store.DumpFile(ctx, vault.RepoDir, vault.Passfile, p.BackendID, manifestPath)
	if err != nil {
		return refuse(fmt.Sprintf("reading %s: %v", manifestPath, err))
	}
	var manifest manifestDoc
	if err := decodeStrict(raw, &manifest); err != nil {
		return refuse(fmt.Sprintf("%s failed strict parsing: %v", manifestPath, err))
	}
	if manifest.SchemaVersion != schemaVersionCurrent {
		return refuse(fmt.Sprintf("manifest schema_version %d, reader supports %d", manifest.SchemaVersion, schemaVersionCurrent))
	}
	if _, perr := domain.ParseID(manifest.SnapshotID); perr != nil {
		return refuse(fmt.Sprintf("manifest snapshot_id %q: %v", manifest.SnapshotID, perr))
	}
	if _, perr := domain.ParseID(manifest.WorkspaceID); perr != nil {
		return refuse(fmt.Sprintf("manifest workspace_id %q: %v", manifest.WorkspaceID, perr))
	}
	if meta := manifestMetaOpDir(manifest); meta != opDirName(dirOpID) {
		return refuse(fmt.Sprintf("manifest meta-root backend_prefix %q does not match the tree's embedded op dir %q",
			meta, opDirName(dirOpID)))
	}

	var main *manifestRoot
	for i := range manifest.Roots {
		if manifest.Roots[i].ID == string(domain.RootMain) {
			main = &manifest.Roots[i]
			break
		}
	}
	if main == nil || validBackendPrefix(main.BackendPrefix) != nil {
		return refuse("manifest has no usable main root backend_prefix")
	}

	// Compute the accounting digest when the document is readable (the
	// row mirrors capture's unsealed-payload recording, which stores the
	// digests of the documents it wrote).
	invDigest := ""
	if manifest.Inventory.Path != "" {
		if invRaw, err := store.DumpFile(ctx, vault.RepoDir, vault.Passfile, p.BackendID, "/"+opDirName(dirOpID)+"/"+manifest.Inventory.Path); err == nil {
			invDigest = digestBytes(invRaw)
		}
	}

	return &UnsealedPayload{
		SnapshotID:       domain.SnapshotID(manifest.SnapshotID),
		WorkspaceID:      domain.WorkspaceID(manifest.WorkspaceID),
		WorkspaceName:    main.BackendPrefix,
		PayloadBackendID: p.BackendID,
		ManifestDigest:   digestBytes(raw),
		InventoryDigest:  invDigest,
		Kind:             kindFromContract(manifest.Contract.Scope, manifest.Contract.Consistency),
		CreatedAt:        firstNonEmpty(p.Time, domain.FormatTime(time.Now().UTC())),
	}, nil
}

// findReceiptNode locates the single receipt node in a seal snapshot:
// a file at .ebb-seal-<32hex>/receipt.json (shape gate; never content
// search). The second return is the operation id embedded in the dir name.
func findReceiptNode(ctx context.Context, store domain.SnapshotStore, vault VaultRef, sealID string) (path, opID string, err error) {
	ls, lerr := store.Ls(ctx, vault.RepoDir, vault.Passfile, sealID)
	if lerr != nil {
		return "", "", fmt.Errorf("listing seal snapshot %s: %v", sealID, lerr)
	}
	matches := 0
	for _, e := range ls {
		if e.Kind != domain.KindFile {
			continue
		}
		dir, base := splitTreePath(e.Path)
		if base != receiptName {
			continue
		}
		id, ok := sealDirID(strings.TrimSuffix(dir, "/"))
		if !ok {
			continue
		}
		matches++
		path, opID = e.Path, id
	}
	switch {
	case matches == 0:
		return "", "", fmt.Errorf("no %s<32hex>/%s node found (not an Ebb seal shape; retained as-is)", sealPrefix, receiptName)
	case matches > 1:
		return "", "", fmt.Errorf("%d candidate receipt nodes; the seal is ambiguous", matches)
	}
	return path, opID, nil
}

// kindFromContract derives the snapshot kind from the frozen manifest
// contract. lifecycle records park for park-asserted captures, trim for
// trim plans and snapshot for plain captures; the reconstructable
// evidence is exactly the contract scope + consistency vocabulary. A
// mis-derivation can only reorder D011's park-over-snapshot preference
// between openable kinds — trim kinds stay trim, and unguessable cases
// default to "snapshot", never to a release decision.
func kindFromContract(scope, consistency string) string {
	switch {
	case scope == scopeTrimPlanDoc:
		return catalog.SnapshotKindTrim
	case consistency == consistencyStoppedWrDoc:
		return catalog.SnapshotKindPark
	default:
		return catalog.SnapshotKindSnapshot
	}
}

// manifestMetaOpDir returns the manifest's meta-root backend_prefix (the
// payload op dir the writer froze), or "" when no meta root is declared.
func manifestMetaOpDir(m manifestDoc) string {
	for _, r := range m.Roots {
		if r.ID == string(domain.RootMeta) {
			return r.BackendPrefix
		}
	}
	return ""
}

// splitTreePath splits one backend tree path ("/a/b/name") into its
// parent directory ("a/b") and base name.
func splitTreePath(p string) (dir, base string) {
	p = strings.TrimPrefix(p, "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// opDirID extracts the operation id from a ".ebb-op-<32hex>" tree
// directory name (the payload twin of sealDirID).
func opDirID(name string) (string, bool) {
	id, ok := strings.CutPrefix(name, opPrefix)
	if !ok {
		return "", false
	}
	if _, perr := domain.ParseID(id); perr != nil {
		return "", false
	}
	return id, true
}

// isFullBackendID reports whether id is a full 64-hex backend snapshot
// id (the form restic mints and the receipt must name; prefixes are not
// accepted on this path — discovery never resolves ambiguity).
func isFullBackendID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// sortRefs orders backend refs deterministically (time, then id).
func sortRefs(refs []domain.SnapshotRef) {
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].Time != refs[j].Time {
			return refs[i].Time < refs[j].Time
		}
		return refs[i].BackendID < refs[j].BackendID
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
