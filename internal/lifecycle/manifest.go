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

	"ebb/internal/actions"
	"ebb/internal/domain"
	"ebb/internal/inventory"
	"ebb/internal/policy"
	"ebb/internal/version"
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
	overlayDirName       = "overlay"
	linkSidecarSuffix    = ".ebb-link"
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

// manifestAction is one §16.2 action record: the policy-derived group
// declaration plus the OPTIONAL `definition` extension object (§16.1)
// carrying the exact wire form of the actions.Definition the open
// operation may run at the final destination (Foundation §12.5). The
// extension is optional so legacy manifests (wave E and earlier) parse
// unchanged: an action without `definition` is a HINT (reported, never
// executed). schema_version stays 1 — optional extension fields live in
// an explicitly named object rather than a new schema.
type manifestAction struct {
	ID        string   `json:"id"`
	Adapter   string   `json:"adapter"`
	Root      string   `json:"root"`
	Outputs   []string `json:"outputs"`
	Inputs    []string `json:"inputs"`
	Network   string   `json:"network"`
	Command   []string `json:"command,omitempty"`
	Ownership string   `json:"ownership"`
	// Definition is the exact captured action definition (§16.2 "exact
	// captured action definitions"): nil/absent on legacy manifests.
	Definition *actionDefDoc `json:"definition,omitempty"`
}

// actionDefDoc is the wire form of actions.Definition as frozen in the
// manifest's extension object. Field names are the actions package's
// vocabulary (snake_case); timeout is integer nanoseconds because the
// manifest carries byte/number fields as checked integers (§16.1), and
// json.Marshal renders a time.Duration as integer nanoseconds anyway.
type actionDefDoc struct {
	ID          string   `json:"id"`
	Argv        []string `json:"argv"`
	WorkingRoot string   `json:"working_root"`
	Inputs      []string `json:"inputs"`
	Outputs     []string `json:"outputs"`
	EnvAllow    []string `json:"env_allow"`
	Network     string   `json:"network"`
	TimeoutNS   int64    `json:"timeout_ns"`
	DependsOn   []string `json:"depends_on"`
}

// actionDefWire converts a Definition into its frozen wire form.
func actionDefWire(d actions.Definition) *actionDefDoc {
	return &actionDefDoc{
		ID:          d.ID,
		Argv:        append([]string(nil), d.Argv...),
		WorkingRoot: d.WorkingRoot,
		Inputs:      append([]string(nil), d.Inputs...),
		Outputs:     append([]string(nil), d.Outputs...),
		EnvAllow:    actions.CanonicalEnvAllow(d.EnvAllow),
		Network:     string(d.Network),
		TimeoutNS:   int64(d.Timeout),
		DependsOn:   append([]string(nil), d.DependsOn...),
	}
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
	// OverlayPatches (D034) records the carve-out entries of this group:
	// preserved/tracked entries inside the outputs whose bytes were
	// captured into the op dir as vault overlay patches before the group
	// was removed. Carved entries ALSO appear in Members — the removal
	// walk (and its Recover resume) must cover them like any member —
	// while this array is the restore-side reapplication contract.
	OverlayPatches []overlayPatchRecord `json:"overlay_patches,omitempty"`
	// RecreateLive (D033/D034) is the non-lockfile "live" recreate argv
	// the restore driver uses for drift reconciliation (it never wipes
	// additions the way a frozen lockfile replay would). Absent (nil)
	// for custom-command groups and pip: no drift-reconcilable live
	// variant exists and restore falls back to the frozen recipe.
	RecreateLive []string `json:"recreate_live,omitempty"`
}

// overlayPatchRecord is one D034 carve-out entry (FROZEN SCHEMA — the
// restore-side worker re-declares this shape from the trim-side spec;
// do not change field names or semantics without freezing a new schema
// version). It names one preserved/tracked entry that lived inside a
// cancelled regenerate group's outputs, was byte-captured into the op
// dir (and therefore into the sealed payload P), and was removed with
// the group. On restore, the base recipe recreates the tree first and
// the overlay is reapplied on top.
//
// Encoding contract (everything the restore driver needs is in THESE
// records; it re-derives semantics from the JSON alone):
//
//   - Path is the root-relative slash path of the ORIGINAL entry.
//   - Copy is the op-dir-relative copy location:
//     "overlay/<groupID>/<path>" for kind "file". For kind "link" the
//     copy is a sidecar REGULAR FILE at "overlay/<groupID>/<path>.ebb-link"
//     whose entire byte content is the link's TARGET TEXT (never the
//     target's content — links are never followed); the restore driver
//     re-creates the link from that text.
//   - Digest binds the carved bytes to durable state so payload-only
//     tampering is detectable at restore time. Its meaning is per kind
//     (F7 amendment): for kind "file" it is the sha256 hex of the
//     ORIGINAL file bytes (identical to the sealed member entry's
//     digest, verified again immediately before removal); for kind
//     "link" it is the sha256 hex OF THE SIDECAR TARGET-TEXT BYTES —
//     the exact bytes written to Copy, re-verified against the sealed
//     link text at capture time. "" means "unwitnessed" (a writer that
//     predates the F7 amendment); readers tolerate it only for those
//     legacy manifests.
//   - Kind is "file" for regular files and "link" for symlinks,
//     junctions and mount points alike (any kind whose identity is link
//     text).
//   - Mode (F9 amendment) is the source file's permission bits as the
//     platform reported them at capture time (0o644/0o755/...), recorded
//     so restore can reapply them instead of a blanket 0600. 0 means
//     "writer predates the field" (readers apply a safe default); links
//     always record 0 (link text carries no permission bits of its own).
type overlayPatchRecord struct {
	Path string `json:"path"` // root-relative slash path of the original
	Copy string `json:"copy"` // op-dir-relative copy: "overlay/<groupID>/<path>" (links: "....ebb-link")
	// Digest: file-kind = sha256 of the file bytes; link-kind = sha256 of
	// the sidecar target-text bytes; "" = unwitnessed legacy (see above).
	Digest string `json:"digest"`
	Kind   string `json:"kind"` // "file" | "link"
	// Mode is the source permission bits (0o644/0o755/...); 0 = field
	// predates the amendment or the entry is a link.
	Mode uint32 `json:"mode,omitempty"`
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

	var actionRecs []manifestAction
	defByID := make(map[string]actions.Definition, len(opts.ActionDefs))
	for _, d := range opts.ActionDefs {
		defByID[d.ID] = d
	}
	for _, g := range resolved.Groups {
		// Exact captured action definitions (§16.2): from the frozen
		// policy groups, carrying ownership of outputs. The optional
		// definition extension object (§16.1) freezes the exact argv the
		// open operation may run; a group without one stays hint-only.
		var cmd []string
		for _, rg := range pol.Regenerate {
			if rg.ID == g.ID {
				cmd = rg.Command
			}
		}
		ma := manifestAction{
			ID: g.ID, Adapter: string(g.Adapter), Root: groupRoot(pol, g.ID),
			Outputs: g.Outputs, Inputs: groupInputs(pol, g.ID),
			Network: string(groupNetwork(pol, g.ID)), Command: cmd,
			Ownership: string(domain.OwnershipOwned),
		}
		if def, ok := defByID[g.ID]; ok {
			ma.Definition = actionDefWire(def)
		}
		actionRecs = append(actionRecs, ma)
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
		Producer:      producerString(),
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
		Actions: actionRecs, Externals: externals,
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
		// Security (Wave F review F1): retained documents are untrusted
		// input — a tampered but internally self-consistent payload must
		// never feed unvalidated paths into a removal permit. Restore's
		// twin reader (documents.go) validates; the asymmetry here was
		// the deletion-authority escape.
		if err := rec.Entry.Validate(); err != nil {
			return nil, &ErrJournalMismatch{Detail: fmt.Sprintf(
				"retained inventory line %d (%s) fails entry validation (tampered payload?): %v", i+1, rec.Entry.Path, err)}
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
			ToolVersions: map[string]string{"ebb": version.Version, "backend": ProducerBackend},
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

// liveRecreateCommand derives the NON-lockfile recreate argv for one
// group (D033 drift reconciliation / D034 overlay reapplication): the
// command the restore driver runs to rebuild the output tree before
// reapplying carve-out overlays. Unlike reclaimCommand it must tolerate
// manifest drift (a frozen `ci`/`--frozen-lockfile` replay would refuse
// or wipe the developer's newer additions), so it carries the plain
// ecosystem install form. Custom-command groups have NO derivable live
// variant (an arbitrary command cannot be weakened safely) and pip has
// none either (pip cannot reconcile a drifted requirements pair); both
// return nil and the field is omitted from the manifest.
func liveRecreateCommand(g policy.Regenerate) []string {
	if len(g.Command) > 0 {
		return nil // custom command: no known drift-reconcilable live variant
	}
	switch g.Adapter {
	case policy.AdapterPNPM:
		return []string{"pnpm", "install"}
	case policy.AdapterNPM:
		return []string{"npm", "install"}
	case policy.AdapterUV:
		return []string{"uv", "sync"}
	}
	return nil
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
