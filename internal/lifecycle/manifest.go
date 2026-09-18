package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"ebb/internal/domain"
	"ebb/internal/inventory"
	"ebb/internal/policy"
)

// Strict-schema documents (Foundation §16.2-16.4). Every writer emits
// UTF-8 JSON with schema_version; every reader in this package
// (recover.go) re-parses with unknown-field rejection so a hostile or
// corrupted record cannot smuggle fields past verification.

// Document and sidecar names inside the op dirs.
const (
	manifestName         = "manifest.json"
	inventoryName        = "inventory.jsonl"
	policyFrozenName     = "policy.toml"
	receiptName          = "receipt.json"
	removalManifestName  = "removal-manifest.json"
	inputsDirName        = "inputs"
	schemaVersionCurrent = 1
)

// Verification check names (§16.4: a verification result names its
// checks; it is never a free-form "safe=true").
const (
	checkCoverageComplete    = "coverage-complete"
	checkPayloadReadback     = "payload-readback-complete"
	checkSealReadback        = "seal-readback-complete"
	checkSourceRevalidated   = "source-revalidated"
	checkRemovalPlanReadback = "removal-plan-readback-complete"
)

// Contract vocabulary (§16.2).
const (
	scopeSingleOwnedRoot = "single-owned-root"
	scopeTrimPlan        = "trim-removal-plan"

	consistencyStoppedWriters = "stopped-writers-asserted"
	consistencyBestEffort     = "best-effort-live"

	targetCompatV1 = "native-v1"
)

// manifestDoc is the §16.2 field contract. It NEVER contains the payload
// snapshot's backend id (that id does not exist when the manifest is
// frozen); the later seal references the manifest digest instead.
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

// receiptDoc is the §16.4 seal receipt: the only record binding the
// logical snapshot to the payload's backend id.
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

// trimPlanDoc is the sealed trim plan (§17.3): per group, the members
// to be removed with their sealed routes, and the recipe inputs with
// digests. It is the authoritative readback scope of a trim capture
// (§11.4: "a trim makes only its removal-plan manifest and required
// recipe inputs authoritative").
type trimPlanDoc struct {
	SchemaVersion int                  `json:"schema_version"`
	OperationID   string               `json:"operation_id"`
	SnapshotID    string               `json:"snapshot_id"`
	Groups        []removalManifestDoc `json:"groups"`
}

// removalManifestDoc is one group's removal declaration.
type removalManifestDoc struct {
	GroupID        string            `json:"group_id"`
	Adapter        string            `json:"adapter"`
	Root           string            `json:"root"`
	Outputs        []string          `json:"outputs"`
	ReclaimCommand []string          `json:"reclaim_command"`
	RecipeInputs   []recipeInput     `json:"recipe_inputs"`
	Members        []inventoryRecord `json:"members"`
}

type recipeInput struct {
	Path   string `json:"path"` // root-relative original location
	Copy   string `json:"copy"` // op-dir-relative copy ("inputs/<group>/<path>")
	Digest string `json:"digest"`
	// Missing records a policy-declared input that is absent from the
	// live workspace at trim time (recorded, never guessed).
	Missing bool `json:"missing,omitempty"`
}

// inventoryRecord is one inventory.jsonl line: the domain entry plus the
// explicit regenerate-group attribution required for omitted entries
// (§16.3 "omitted output groups refer to an action").
type inventoryRecord struct {
	domain.Entry
	Group string `json:"group,omitempty"`
}

// groupOf extracts the regenerate-group attribution from the policy
// evidence the resolver attached ("policy:regenerate=<id>").
func groupOf(e domain.Entry) string {
	for _, ev := range e.Evidence {
		if g, ok := strings.CutPrefix(ev, "policy:regenerate="); ok {
			return g
		}
	}
	return ""
}

// buildInventoryBytes serializes every entry (preserved AND omitted —
// §8.4 complete accounting) in canonical order, one JSON object per
// line, and returns the exact bytes plus their SHA-256. The digest is
// over the written bytes, never over a re-parsed copy (§16.1).
func buildInventoryBytes(entries []domain.Entry) ([]byte, string, error) {
	if err := domain.CheckSortedAndUnique(entries); err != nil {
		return nil, "", fmt.Errorf("lifecycle: inventory: %w", err)
	}
	var b strings.Builder
	for _, e := range entries {
		line, err := json.Marshal(inventoryRecord{Entry: e, Group: groupOf(e)})
		if err != nil {
			return nil, "", fmt.Errorf("lifecycle: inventory record %s: %w", e.Path, err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	raw := []byte(b.String())
	return raw, digestBytes(raw), nil
}

func digestBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// buildManifest assembles the §16.2 document.
func buildManifest(
	snapshotID domain.SnapshotID,
	wsID domain.WorkspaceID,
	created string,
	rootAbs string,
	ident domain.RootIdentity,
	wsPrefix, opDir string,
	invBytes []byte, invDigest string, entries []domain.Entry,
	frozen []byte, resolvedDigest string,
	pol policy.Policy,
	resolved policy.Resolved,
	scanIssues []domain.ScanIssue,
	blocking []string,
	opts CaptureOptions,
	trimScope bool,
) manifestDoc {
	scope := scopeSingleOwnedRoot
	if trimScope {
		scope = scopeTrimPlan
	}
	// A trim's authoritative accounting document is the removal plan
	// (§11.4 readback-scope-follows-authority); the inventory reference
	// names whichever document this capture actually sealed.
	invPath := inventoryName
	if trimScope {
		invPath = removalManifestName
	}
	consistency := consistencyBestEffort
	src := ""
	if opts.WriterAssertion != "" {
		// The recorded stopped-writers assertion is recorded truthfully
		// whenever the CLI supplies one (park requires it; trim may
		// supply one for the trimmed group; a plain snapshot's default
		// remains best-effort-live by omission).
		consistency = consistencyStoppedWriters
		src = opts.WriterAssertion
	}

	var actions []manifestAction
	for _, g := range resolved.Groups {
		// Exact captured action definitions (§16.2): from the frozen
		// policy groups, carrying ownership of outputs.
		var cmd []string
		for _, rg := range pol.Regenerate {
			if rg.ID == g.ID {
				cmd = rg.Command
			}
		}
		actions = append(actions, manifestAction{
			ID: g.ID, Adapter: string(g.Adapter), Root: groupRoot(pol, g.ID),
			Outputs: g.Outputs, Inputs: groupInputs(pol, g.ID),
			Network: string(groupNetwork(pol, g.ID)), Command: cmd,
			Ownership: string(domain.OwnershipOwned),
		})
	}

	var externals []manifestExternal
	for _, ex := range pol.External {
		externals = append(externals, manifestExternal{
			ID: ex.ID, Kind: string(ex.Kind), Location: ex.Location,
			Ownership: ex.Ownership, Required: ex.Required,
			Evidence:     []string{"policy-declared"},
			Availability: "unverified",
		})
	}

	// Capabilities: what this capture actually carries vs what v1
	// explicitly does not promise. Hardlink relinking, ADS, the sparse
	// flag and ACLs are backend-verified gaps (Learnings: restic 0.19.1
	// NTFS fidelity); scan issues add per-entry gaps.
	notPromised := []string{"alternate-data-streams", "hardlink-relink", "sparse-flag", "acls"}
	captured := []string{"file-bytes", "paths", "symlink-link-text", "directory-structure", "mtimes"}
	for _, iss := range scanIssues {
		switch iss.Code {
		case inventory.IssueADSPresent:
			notPromised = appendUnique(notPromised, "alternate-data-streams")
		case inventory.IssueHardlinkOutside:
			notPromised = appendUnique(notPromised, "exclusive-hardlink-reclaim")
		}
	}

	var managed []manifestManagedOut
	for _, g := range resolved.Groups {
		if !g.Applicable {
			continue
		}
		var members int
		h := sha256.New()
		for _, e := range entries {
			if groupOf(e) == g.ID && e.Route == domain.RouteReconstruct {
				members++
				h.Write([]byte(e.Path))
				h.Write([]byte{0})
				h.Write([]byte(e.Digest))
				h.Write([]byte{'\n'})
			}
		}
		managed = append(managed, manifestManagedOut{
			GroupID: g.ID, Adapter: string(g.Adapter),
			Declaration: "whole-group-replacement", // v1: no prior Ark baseline exists
			Members:     members, MembersDigest: hex.EncodeToString(h.Sum(nil)),
		})
	}

	var exclusions []manifestExclusion
	for _, e := range entries {
		if e.Route == domain.RoutePreserve {
			continue
		}
		exclusions = append(exclusions, manifestExclusion{
			Path: e.Path, Route: string(e.Route), Group: groupOf(e),
			Note: "omitted with recorded route (I02)",
		})
	}
	for _, p := range blocking {
		exclusions = append(exclusions, manifestExclusion{
			Path: p, Note: "blocking entry: not capturable with v1 fidelity; destructive operations refused",
		})
	}

	return manifestDoc{
		SchemaVersion: schemaVersionCurrent,
		SnapshotID:    string(snapshotID),
		WorkspaceID:   string(wsID),
		CreatedAt:     created,
		Producer:      producerString,
		Contract: contractDoc{
			Scope: scope, Consistency: consistency, ConsistencySource: src,
			Fidelity: captured, Network: string(pol.Rules.Network),
			TargetCompatibility: targetCompatV1,
		},
		Roots: []manifestRoot{
			{ID: string(domain.RootMain), Ownership: string(domain.OwnershipOwned),
				SourcePath: rootAbs, SourceIdentity: ident.String(), BackendPrefix: wsPrefix},
			{ID: string(domain.RootMeta), Ownership: string(domain.OwnershipOwned),
				BackendPrefix: opDir},
		},
		Inventory: manifestInventoryRef{
			Path: invPath, Digest: invDigest,
			Count: int64(len(entries)), Bytes: int64(len(invBytes)),
		},
		Policy: manifestPolicy{
			Frozen: string(frozen), FrozenDigest: digestBytes(frozen),
			ResolvedDigest: resolvedDigest,
		},
		Actions: actions, Externals: externals,
		Capabilities:    manifestCapabilities{Captured: captured, NotPromised: notPromised},
		GitObservations: opts.Git,
		ManagedOutputs:  managed, ScopeExclusions: exclusions,
		RequiredFeatures: []string{},
	}
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// groupRoot/Inputs/Network look the original declarations back up from
// the frozen policy (GroupDecision carries id/adapter/outputs only).
func groupRoot(pol policy.Policy, id string) string {
	for _, g := range pol.Regenerate {
		if g.ID == id {
			return g.Root
		}
	}
	return "."
}

func groupInputs(pol policy.Policy, id string) []string {
	for _, g := range pol.Regenerate {
		if g.ID == id {
			return g.Inputs
		}
	}
	return nil
}

func groupNetwork(pol policy.Policy, id string) policy.GroupNetwork {
	for _, g := range pol.Regenerate {
		if g.ID == id {
			return g.Network
		}
	}
	return policy.GroupNetworkAllowed
}

// writeJSONDoc writes one strict JSON document with LF endings and
// returns its exact bytes (digests are over these bytes).
func writeJSONDoc(path string, v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return b, nil
}

// decodeStrictJSON is the ONLY re-read path for retained documents
// (recover.go): encoding/json with DisallowUnknownFields plus a
// trailing-data check, so a hostile or corrupted record cannot smuggle
// fields past verification (the package comment promises this).
func decodeStrictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("lifecycle: strict document parse: %w", err)
	}
	if dec.More() {
		return fmt.Errorf("lifecycle: strict document parse: trailing data after JSON value")
	}
	return nil
}

// parseInventoryLines strictly parses inventory.jsonl bytes. A torn or
// malformed line is an error, never a silently dropped entry (complete
// accounting, §8.4).
func parseInventoryLines(b []byte) ([]domain.Entry, error) {
	var out []domain.Entry
	for i, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		var rec inventoryRecord
		if err := decodeStrictJSON([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("inventory line %d: %w", i+1, err)
		}
		out = append(out, rec.Entry)
	}
	return out, nil
}

// parseRootIdentity reverses RootIdentity.String() ("volume/file-id") as
// recorded in the catalog's source_identity column. Recover compares
// identities, not names (I13); the stored string is the durable form.
func parseRootIdentity(s string) (domain.RootIdentity, error) {
	vol, file, ok := strings.Cut(s, "/")
	if !ok || vol == "" || file == "" {
		return domain.RootIdentity{}, fmt.Errorf("lifecycle: unparsable root identity %q", s)
	}
	return domain.RootIdentity{VolumeID: vol, FileID: file}, nil
}

// buildReceipt assembles the §16.4 seal receipt. Written only after P
// has been read back and checked (§11.3); readback of S itself is the
// final gate before any removal authorization.
func buildReceipt(
	snapID domain.SnapshotID, wsID domain.WorkspaceID,
	repoID, payloadID, manifestDigest, inventoryDigest string,
	opID domain.OperationID, scope string, at string, checks []string,
) receiptDoc {
	return receiptDoc{
		SchemaVersion: schemaVersionCurrent,
		SnapshotID:    string(snapID), WorkspaceID: string(wsID),
		BackendRepoID: repoID, PayloadBackendID: payloadID,
		ManifestDigest: manifestDigest, InventoryDigest: inventoryDigest,
		RequiredFeatures: []string{},
		Verification: receiptVerification{
			Checks: checks, Scope: scope, Time: at,
			ToolVersions: map[string]string{"ebb": ProducerEbbVersion, "backend": ProducerBackend},
		},
		OperationID: string(opID), Retention: "pinned",
	}
}

// reclaimCommand derives the literal argv that recreates one group's
// output (§17.3: "the result names the groups removed and the commands
// required to recreate them"). Custom adapters carry their declared
// command; ecosystem adapters get the pinned per-adapter recipe.
func reclaimCommand(g policy.Regenerate) []string {
	if len(g.Command) > 0 {
		return g.Command
	}
	switch g.Adapter {
	case policy.AdapterPNPM:
		return []string{"pnpm", "install", "--frozen-lockfile"}
	case policy.AdapterNPM:
		return []string{"npm", "ci"}
	case policy.AdapterUV:
		return []string{"uv", "sync", "--frozen"}
	case policy.AdapterPip:
		return []string{"python", "-m", "pip", "install", "-r", firstInput(g)}
	}
	return nil
}

func firstInput(g policy.Regenerate) string {
	if len(g.Inputs) > 0 {
		return g.Inputs[0]
	}
	return "requirements.txt"
}

// sortedEntryPaths returns the sorted keys of an entry map (canonical
// order helpers).
func sortedEntryPaths(m map[string]domain.Entry) []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
