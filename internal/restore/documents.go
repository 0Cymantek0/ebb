package restore

// The frozen document formats (Foundation §16.2-16.4), re-declared here
// as a STRICT reader. The writer of record is internal/lifecycle/
// manifest.go; this package must parse exactly what that writer emits —
// including rejecting unknown fields — without importing the
// removal-authority package. Any drift between the two is caught by the
// round-trip fixtures in this package's tests.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// receiptDoc is the §16.4 seal receipt: the only record binding the
// logical snapshot to the payload's backend id. Field set and JSON tags
// mirror the frozen writer exactly.
type receiptDoc struct {
	SchemaVersion    int                 `json:"schema_version"`
	SnapshotID       string              `json:"snapshot_id"`
	WorkspaceID      string              `json:"workspace_id"`
	BackendRepoID    string              `json:"backend_repo_id"`
	PayloadBackendID string              `json:"payload_backend_id"`
	ManifestDigest   string              `json:"manifest_digest"`
	InventoryDigest  string              `json:"inventory_digest"`
	RequiredFeatures []string            `json:"required_features"`
	Verification     receiptVerification `json:"verification"`
	OperationID      string              `json:"operation_id"`
	Retention        string              `json:"retention"`
}

type receiptVerification struct {
	Checks       []string          `json:"checks"`
	Scope        string            `json:"scope"`
	Time         string            `json:"time"`
	ToolVersions map[string]string `json:"tool_versions"`
}

// manifestDoc is the §16.2 field contract (subset read by restore; the
// full field set is still required to be present and typed correctly
// because parsing is strict over the complete document).
type manifestDoc struct {
	SchemaVersion    int                   `json:"schema_version"`
	SnapshotID       string                `json:"snapshot_id"`
	WorkspaceID      string                `json:"workspace_id"`
	CreatedAt        string                `json:"created_at"`
	Producer         string                `json:"producer"`
	Contract         contractDoc           `json:"contract"`
	Roots            []manifestRoot        `json:"roots"`
	Inventory        manifestInventoryRef  `json:"inventory"`
	Policy           manifestPolicy        `json:"policy"`
	Actions          []manifestAction      `json:"actions"`
	Externals        []manifestExternal    `json:"externals"`
	Capabilities     manifestCapabilities  `json:"capabilities"`
	GitObservations  domain.GitObservation `json:"git_observations"`
	ManagedOutputs   []manifestManagedOut  `json:"managed_outputs"`
	ScopeExclusions  []manifestExclusion   `json:"scope_exclusions"`
	RequiredFeatures []string              `json:"required_features"`
}

type contractDoc struct {
	Scope               string   `json:"scope"`
	Consistency         string   `json:"consistency"`
	ConsistencySource   string   `json:"consistency_source,omitempty"`
	Fidelity            []string `json:"fidelity"`
	Network             string   `json:"network"`
	TargetCompatibility string   `json:"target_compatibility"`
}

type manifestRoot struct {
	ID             string `json:"id"`
	Ownership      string `json:"ownership"`
	SourcePath     string `json:"source_path,omitempty"`
	SourceIdentity string `json:"source_identity,omitempty"`
	BackendPrefix  string `json:"backend_prefix"`
}

type manifestInventoryRef struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
}

type manifestPolicy struct {
	Frozen         string `json:"frozen"`
	FrozenDigest   string `json:"frozen_digest"`
	ResolvedDigest string `json:"resolved_digest"`
}

type manifestAction struct {
	ID        string   `json:"id"`
	Adapter   string   `json:"adapter"`
	Root      string   `json:"root"`
	Outputs   []string `json:"outputs"`
	Inputs    []string `json:"inputs"`
	Network   string   `json:"network"`
	Command   []string `json:"command,omitempty"`
	Ownership string   `json:"ownership"`
}

type manifestExternal struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"`
	Location     string   `json:"location"`
	Ownership    string   `json:"ownership"`
	Required     bool     `json:"required"`
	Evidence     []string `json:"evidence"`
	Availability string   `json:"availability"`
}

type manifestCapabilities struct {
	Captured    []string `json:"captured"`
	NotPromised []string `json:"not_promised"`
}

type manifestManagedOut struct {
	GroupID       string `json:"group_id"`
	Adapter       string `json:"adapter"`
	Declaration   string `json:"declaration"`
	Members       int    `json:"members"`
	MembersDigest string `json:"members_digest"`
	Baseline      string `json:"baseline,omitempty"`
}

type manifestExclusion struct {
	Path  string `json:"path,omitempty"`
	Route string `json:"route,omitempty"`
	Group string `json:"group,omitempty"`
	Note  string `json:"note"`
}

// inventoryRecord is one inventory.jsonl line: the domain entry plus the
// regenerate-group attribution the frozen writer attaches (§16.3).
type inventoryRecord struct {
	domain.Entry
	Group string `json:"group,omitempty"`
}

// payloadDocs carries everything step 3 read back, verified and parsed
// from the payload snapshot.
type payloadDocs struct {
	wsPrefix string // manifest main-root backend_prefix (tree prefix)
	// retained is the preserve-route entry set the oracle compares the
	// staged tree against (§12.5 / E10).
	retained []domain.Entry
	// preservedBytes sums preserved file logical sizes (peak-space check,
	// Result.BytesRestored).
	preservedBytes  int64
	entriesRestored int64
	manifest        manifestDoc
	// manifestLen is the exact byte length of the dumped manifest.json
	// (expected-tree evidence for callers re-deriving coverage).
	manifestLen int64
}

// digestBytes is SHA-256 over the exact bytes (§16.1: verification is
// over stored bytes, never over a re-parsed re-serialization).
func digestBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// decodeStrict parses one JSON document with unknown-field rejection
// and trailing-content rejection (Foundation §16.1, §13.4).
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing JSON content")
	}
	return nil
}

// loadSeal performs §12.5 step 2: list the seal snapshot's tree, find
// the .ebb-seal-<32hex>/receipt.json node, dump its bytes and parse it
// strictly, then cross-check it against the catalog row.
func (o *Opener) loadSeal(ctx context.Context, vault VaultRef, snapID domain.SnapshotID, snap catalog.Snapshot) (receiptDoc, error) {
	ls, err := o.store.Ls(ctx, vault.RepoDir, vault.Passfile, snap.SealBackendID)
	if err != nil {
		return receiptDoc{}, &ErrSealInvalid{Details: []string{
			fmt.Sprintf("listing seal snapshot %s: %v", snap.SealBackendID, err)}}
	}

	// Find the receipt node; derive the operation id from the seal dir
	// NAME (the shape embeds it — I13), never by content search.
	var receiptPath, dirOpID string
	matches := 0
	for _, e := range ls {
		if e.Kind != domain.KindFile {
			continue
		}
		dir, base := path.Split(strings.TrimPrefix(e.Path, "/"))
		if base != receiptName {
			continue
		}
		id, ok := sealDirID(strings.TrimSuffix(dir, "/"))
		if !ok {
			continue
		}
		matches++
		receiptPath, dirOpID = e.Path, id
	}
	switch {
	case matches == 0:
		return receiptDoc{}, &ErrSealInvalid{Details: []string{
			fmt.Sprintf("no %s<32hex>/%s node found in seal snapshot %s", sealPrefix, receiptName, snap.SealBackendID)}}
	case matches > 1:
		return receiptDoc{}, &ErrSealInvalid{Details: []string{
			fmt.Sprintf("%d candidate receipt nodes in seal snapshot %s; the seal is ambiguous", matches, snap.SealBackendID)}}
	}

	raw, err := o.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, snap.SealBackendID, receiptPath)
	if err != nil {
		return receiptDoc{}, &ErrSealInvalid{Details: []string{
			fmt.Sprintf("reading seal receipt %s: %v", receiptPath, err)}}
	}
	var receipt receiptDoc
	if err := decodeStrict(raw, &receipt); err != nil {
		return receiptDoc{}, &ErrSealInvalid{Details: []string{
			fmt.Sprintf("receipt %s failed strict parsing: %v", receiptPath, err)}}
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
	if receipt.SnapshotID != string(snapID) {
		problems = append(problems, fmt.Sprintf("receipt snapshot_id %q, requested %q", receipt.SnapshotID, snapID))
	}
	if receipt.WorkspaceID != string(snap.WorkspaceID) {
		problems = append(problems, fmt.Sprintf("receipt workspace_id %q, catalog says %q", receipt.WorkspaceID, snap.WorkspaceID))
	}
	if receipt.PayloadBackendID != snap.PayloadBackendID {
		problems = append(problems, fmt.Sprintf("receipt payload_backend_id %q does not match the catalog's payload %q",
			receipt.PayloadBackendID, snap.PayloadBackendID))
	}
	if receipt.ManifestDigest == "" || receipt.InventoryDigest == "" {
		problems = append(problems, "receipt carries an empty manifest/inventory digest; documents cannot be verified (I12)")
	}
	if len(problems) > 0 {
		return receiptDoc{}, &ErrSealInvalid{Details: problems}
	}
	return receipt, nil
}

// loadDocuments performs §12.5 step 3: dump the payload's manifest.json
// and inventory.jsonl from the frozen op dir (.ebb-op-<receipt op id>),
// verify their SHA-256 against the receipt's digests (I12 — never trust
// a listing without comparing bytes), parse both strictly, and extract
// the main root's backend prefix plus the retained preserve set.
func (o *Opener) loadDocuments(ctx context.Context, vault VaultRef, snapID domain.SnapshotID, snap catalog.Snapshot, receipt receiptDoc) (payloadDocs, error) {
	var docs payloadDocs
	opDir := opDirName(receipt.OperationID)
	manifestPath := "/" + opDir + "/" + manifestName
	inventoryPath := "/" + opDir + "/" + inventoryName

	manifestRaw, err := o.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, snap.PayloadBackendID, manifestPath)
	if err != nil {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("reading %s from payload %s: %v", manifestPath, snap.PayloadBackendID, err)}}
	}
	inventoryRaw, err := o.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, snap.PayloadBackendID, inventoryPath)
	if err != nil {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("reading %s from payload %s: %v", inventoryPath, snap.PayloadBackendID, err)}}
	}

	// I12: compare the bytes themselves before believing any listing.
	var problems []string
	if got := digestBytes(manifestRaw); got != receipt.ManifestDigest {
		problems = append(problems, fmt.Sprintf("%s: digest %s, receipt declares %s", manifestPath, got, receipt.ManifestDigest))
	}
	if got := digestBytes(inventoryRaw); got != receipt.InventoryDigest {
		problems = append(problems, fmt.Sprintf("%s: digest %s, receipt declares %s", inventoryPath, got, receipt.InventoryDigest))
	}
	if len(problems) > 0 {
		return docs, &ErrVerification{Check: "documents", Details: problems}
	}

	var manifest manifestDoc
	if err := decodeStrict(manifestRaw, &manifest); err != nil {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("%s failed strict parsing: %v", manifestPath, err)}}
	}
	if manifest.SchemaVersion != schemaVersionCurrent {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest schema_version %d, reader supports %d", manifest.SchemaVersion, schemaVersionCurrent)}}
	}
	if len(manifest.RequiredFeatures) > 0 {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest declares unsupported required features %v", manifest.RequiredFeatures)}}
	}
	if manifest.SnapshotID != string(snapID) {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest snapshot_id %q, requested %q", manifest.SnapshotID, snapID)}}
	}
	if manifest.WorkspaceID != string(snap.WorkspaceID) {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest workspace_id %q, catalog says %q", manifest.WorkspaceID, snap.WorkspaceID)}}
	}
	if manifest.Inventory.Digest != receipt.InventoryDigest {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest inventory digest %q disagrees with the receipt's %q", manifest.Inventory.Digest, receipt.InventoryDigest)}}
	}
	if manifest.Inventory.Path != inventoryName {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest inventory path %q, expected %q", manifest.Inventory.Path, inventoryName)}}
	}

	// The main root: its backend_prefix is the workspace tree prefix
	// (§11.2 bijection); source_path/source_identity are recorded
	// evidence of the capture-time location.
	var main *manifestRoot
	var meta *manifestRoot
	for i := range manifest.Roots {
		switch manifest.Roots[i].ID {
		case string(domain.RootMain):
			if main != nil {
				return docs, &ErrVerification{Check: "documents", Details: []string{"manifest declares more than one main root"}}
			}
			main = &manifest.Roots[i]
		case string(domain.RootMeta):
			meta = &manifest.Roots[i]
		}
	}
	if main == nil {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest has no root with id %q; the workspace tree prefix is unknown", domain.RootMain)}}
	}
	if err := validBackendPrefix(main.BackendPrefix); err != nil {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("main root backend_prefix: %v", err)}}
	}
	if meta != nil && meta.BackendPrefix != opDir {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("meta root backend_prefix %q does not match the op dir derived from the receipt (%q)", meta.BackendPrefix, opDir)}}
	}

	// Parse the inventory stream: one strict record per line, canonical
	// order, every entry validated (Foundation §16.3, §13.4).
	entries, err := parseInventory(inventoryRaw)
	if err != nil {
		return docs, &ErrVerification{Check: "documents", Details: []string{err.Error()}}
	}
	if manifest.Inventory.Count != int64(len(entries)) {
		return docs, &ErrVerification{Check: "documents", Details: []string{
			fmt.Sprintf("manifest inventory count %d, payload carries %d records", manifest.Inventory.Count, len(entries))}}
	}

	docs.manifest = manifest
	docs.manifestLen = int64(len(manifestRaw))
	docs.wsPrefix = main.BackendPrefix
	for _, e := range entries {
		if e.Route != domain.RoutePreserve {
			continue // omitted entries are reported as rebuild hints, not restored
		}
		docs.retained = append(docs.retained, e)
		docs.entriesRestored++
		if e.Kind == domain.KindFile {
			docs.preservedBytes += e.LogicalSize
		}
	}
	return docs, nil
}

// validBackendPrefix enforces the D003 tree-prefix shape: one path
// segment (the root's base name), never a nested or absolute path.
func validBackendPrefix(p string) error {
	if p == "" {
		return fmt.Errorf("empty")
	}
	if strings.ContainsAny(p, "/\\") {
		return fmt.Errorf("%q is not a single path segment", p)
	}
	if p == ".." || p == "." {
		return fmt.Errorf("%q is a relative navigation segment", p)
	}
	if len(p) >= 2 && p[1] == ':' {
		return fmt.Errorf("%q carries a drive prefix", p)
	}
	return nil
}

// parseInventory strictly decodes every non-empty line of the retained
// inventory stream and enforces the canonical invariants the oracle
// relies on (sorted, unique, main-root, preserve files digested,
// preserve links carrying link text).
func parseInventory(raw []byte) ([]domain.Entry, error) {
	var entries []domain.Entry
	seen := map[string]bool{}
	for i, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue // trailing newline / blank separators
		}
		var rec inventoryRecord
		if err := decodeStrict([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("inventory line %d failed strict parsing: %w", i+1, err)
		}
		if err := rec.Validate(); err != nil {
			return nil, fmt.Errorf("inventory line %d: %w", i+1, err)
		}
		if rec.Root != domain.RootMain {
			return nil, fmt.Errorf("inventory line %d: entry %q carries root %q; v1 payloads cover the main root only",
				i+1, rec.Path, rec.Root)
		}
		if seen[rec.Path] {
			return nil, fmt.Errorf("inventory line %d: duplicate path %q", i+1, rec.Path)
		}
		seen[rec.Path] = true
		if rec.Route == domain.RoutePreserve {
			switch rec.Kind {
			case domain.KindFile:
				if rec.Digest == "" {
					return nil, fmt.Errorf("inventory line %d: preserved file %q has no content digest", i+1, rec.Path)
				}
			case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
				if rec.LinkTarget == "" {
					return nil, fmt.Errorf("inventory line %d: preserved link %q has no link text", i+1, rec.Path)
				}
			}
		}
		entries = append(entries, rec.Entry)
	}
	if err := domain.CheckSortedAndUnique(entries); err != nil {
		return nil, fmt.Errorf("retained inventory is not in canonical order: %w", err)
	}
	return entries, nil
}

// rebuildHints derives the reported-not-run reconstruction plan from the
// manifest: every captured action whose group actually has omitted
// members (a scope_exclusions entry naming that group) becomes one hint
// carrying the literal command (the manifest's custom argv, or the
// pinned ecosystem recipe constant).
func rebuildHints(m manifestDoc) []RebuildHint {
	omitted := map[string]bool{}
	for _, ex := range m.ScopeExclusions {
		if ex.Group != "" {
			omitted[ex.Group] = true
		}
	}
	var hints []RebuildHint
	for _, a := range m.Actions {
		if !omitted[a.ID] {
			continue
		}
		cmd := append([]string(nil), a.Command...)
		if len(cmd) == 0 {
			cmd = ecosystemRecipe(a.Adapter, a.Inputs)
		}
		hints = append(hints, RebuildHint{
			GroupID: a.ID,
			Command: cmd,
			Inputs:  append([]string(nil), a.Inputs...),
			Network: a.Network,
		})
	}
	sort.Slice(hints, func(i, j int) bool { return hints[i].GroupID < hints[j].GroupID })
	return hints
}

// Adapter names of the frozen manifest vocabulary (they serialize from
// policy.Adapter; restore reads the strings, not the policy types).
const (
	adapterPNPM = "pnpm"
	adapterNPM  = "npm"
	adapterUV   = "uv"
	adapterPip  = "pip"
)

// ecosystemRecipe mirrors the pinned per-adapter recipe constants the
// capture side records (lifecycle's reclaimCommand): pnpm install
// --frozen-lockfile, npm ci, uv sync --frozen, pip's literal
// requirements invocation. A nil result means "no known recipe; the
// group's reconstruction is user-driven".
func ecosystemRecipe(adapter string, inputs []string) []string {
	firstInput := "requirements.txt"
	if len(inputs) > 0 {
		firstInput = inputs[0]
	}
	switch adapter {
	case adapterPNPM:
		return []string{"pnpm", "install", "--frozen-lockfile"}
	case adapterNPM:
		return []string{"npm", "ci"}
	case adapterUV:
		return []string{"uv", "sync", "--frozen"}
	case adapterPip:
		return []string{"python", "-m", "pip", "install", "-r", firstInput}
	}
	return nil
}
