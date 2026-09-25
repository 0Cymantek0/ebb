package restore

// trimdocs.go is the STRICT reader of a sealed trim payload's documents
// (D033: `ebb restore` re-executes the recipes a trim froze). The writer
// of record is internal/lifecycle (manifest.go's trimPlanDoc /
// removalManifestDoc / recipeInput and, on the D034 writer side,
// overlayPatchRecord); this package re-declares the frozen formats
// locally instead of importing the removal-authority package — the same
// convention documents.go applies to the capture formats. Any drift
// between writer and reader is caught by round-trip fixtures in this
// package's tests.
//
// Reader tolerances (frozen contract):
//   - Older manifests WITHOUT overlay_patches / recreate_live parse as
//     zero values (the fields are omitempty on the writer; a manifest
//     that predates D034 simply has no overlays and lockfile-pinned
//     recipes only).
//   - Unknown schema_version, unknown fields, trailing data, or any
//     structurally hostile path (traversal, absolute, backslash, drive
//     prefix, NUL, NTFS ADS colon alias, Win32-illegal characters,
//     device names, trailing dot/space) refuses the whole document.
//
// Digest discipline (I12/D017): the trim snapshot's catalog row carries
// the seal-time digests of manifest.json and removal-manifest.json; the
// reader compares the DUMPED bytes against them before believing any
// content. A row without digests cannot witness anything and refuses.

import (
	"context"
	"fmt"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// trimPlanDocReader mirrors lifecycle's trimPlanDoc (removal-manifest.json).
type trimPlanDocReader struct {
	SchemaVersion int                  `json:"schema_version"`
	OperationID   string               `json:"operation_id"`
	SnapshotID    string               `json:"snapshot_id"`
	Groups        []removalGroupReader `json:"groups"`
}

// removalGroupReader mirrors lifecycle's removalManifestDoc plus the
// D033/D034 extension fields (recreate_live, overlay_patches) and the
// wave-5 frozen action `definition` (D1/D2).
type removalGroupReader struct {
	GroupID        string   `json:"group_id"`
	Adapter        string   `json:"adapter"`
	Root           string   `json:"root"`
	Outputs        []string `json:"outputs"`
	ReclaimCommand []string `json:"reclaim_command"`
	// RecreateLive is the non-lockfile recipe variant (e.g.
	// ["pnpm","install"]) the merge/current strategies execute; empty on
	// older manifests (the lockfile-pinned reclaim_command is the only
	// recipe and drift reconciliation is baseline-only for the group).
	RecreateLive []string            `json:"recreate_live,omitempty"`
	RecipeInputs []recipeInputReader `json:"recipe_inputs"`
	Members      []trimMemberReader  `json:"members"`
	// OverlayPatches are the D034 carve-outs: preserved files inside the
	// group's outputs, re-applied AFTER the recipe recreates the outputs.
	OverlayPatches []overlayPatchReader `json:"overlay_patches,omitempty"`
	// Definition (wave-5, D1/D2) is the EXACT frozen action contract the
	// trim sealed: the restore driver replays it verbatim instead of
	// synthesizing a fresh Definition. Nil on legacy manifests (written
	// before the frozen contract existed) — the whole plan is then
	// legacy and normal replay refuses (D5).
	Definition *actionDefinitionDoc `json:"definition,omitempty"`
}

// recipeInputReader mirrors lifecycle's recipeInput.
type recipeInputReader struct {
	Path    string `json:"path"` // root-relative original location
	Copy    string `json:"copy"` // op-dir-relative copy ("inputs/<group>/<path>")
	Digest  string `json:"digest"`
	Missing bool   `json:"missing,omitempty"`
}

// overlayPatchReader mirrors the D034 overlayPatchRecord the trim-side
// writer freezes (identical JSON tags). Digest: files = sha256 of the
// file bytes; links = sha256 of the .ebb-link sidecar's target-text
// bytes (post-amendment witness) or "" (pre-amendment, unwitnessed).
// Mode = source permission bits at capture (0/absent = pre-amendment or
// link; a safe default applies on write).
type overlayPatchReader struct {
	Path   string `json:"path"`   // root-relative slash path of the original
	Copy   string `json:"copy"`   // op-dir-relative copy: "overlay/<groupID>/<path>"
	Digest string `json:"digest"` // sha256 hex (see semantics above)
	Kind   string `json:"kind"`   // "file" | "link"
	Mode   uint32 `json:"mode,omitempty"`
}

// trimMemberReader is one removal-manifest member line. Members are the
// entries the trim REMOVED (all under the group's outputs); the reader
// only requires them to parse — no field of a member ever feeds a
// filesystem write on the restore side (the overlay patches own that
// surface, with their own strict gate).
type trimMemberReader struct {
	domain.Entry
	Group string `json:"group,omitempty"`
}

// trimDocs is everything readTrimDocs produced from one sealed trim
// payload: the manifest (git observations, producer) and the parsed,
// validated removal plan.
type trimDocs struct {
	opDir    string
	manifest manifestDoc
	plan     trimPlanDocReader
}

// doc constants mirrored from the writer's vocabulary (documents.go
// carries the shared names; the trim-specific ones live here).
const (
	removalManifestName = "removal-manifest.json"
	trimScope           = "trim-removal-plan"
	overlayKindFile     = "file"
	overlayKindLink     = "link"
)

// readTrimDocs performs the document half of a live restore: dump the
// trim payload's manifest.json and removal-manifest.json, digest-check
// both against the snapshot row's seal-time digests (I12/D017), strict-
// parse both, and validate every path the driver would act on. payloadID
// is the trim operation's payload backend id; trimOpID names the op dir
// (.ebb-op-<trimOpID>).
func readTrimDocs(ctx context.Context, store domain.SnapshotStore, vault VaultRef, payloadID, trimOpID string, wantManifest, wantInventory string) (trimDocs, error) {
	var docs trimDocs
	opDir := opPrefix + trimOpID
	manifestPath := "/" + opDir + "/" + manifestName
	planPath := "/" + opDir + "/" + removalManifestName

	if wantManifest == "" || wantInventory == "" {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("snapshot row of payload %s carries no seal-time manifest/removal-plan digests (legacy row); the trim plan cannot be witnessed (D017)", payloadID)}}
	}

	manifestRaw, err := store.DumpFile(ctx, vault.RepoDir, vault.Passfile, payloadID, manifestPath)
	if err != nil {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("reading %s from payload %s: %v", manifestPath, payloadID, err)}}
	}
	planRaw, err := store.DumpFile(ctx, vault.RepoDir, vault.Passfile, payloadID, planPath)
	if err != nil {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("reading %s from payload %s: %v", planPath, payloadID, err)}}
	}
	var problems []string
	if got := digestBytes(manifestRaw); got != wantManifest {
		problems = append(problems, fmt.Sprintf("%s: digest %s, catalog seal-time record %s — vault tampering suspected (D017)", manifestPath, got, wantManifest))
	}
	if got := digestBytes(planRaw); got != wantInventory {
		problems = append(problems, fmt.Sprintf("%s: digest %s, catalog seal-time record %s — vault tampering suspected (D017)", planPath, got, wantInventory))
	}
	if len(problems) > 0 {
		return docs, &ErrVerification{Check: "trim-documents", Details: problems}
	}

	var manifest manifestDoc
	if err := decodeStrict(manifestRaw, &manifest); err != nil {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("%s failed strict parsing: %v", manifestPath, err)}}
	}
	if manifest.SchemaVersion != schemaVersionCurrent {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("manifest schema_version %d, reader supports %d", manifest.SchemaVersion, schemaVersionCurrent)}}
	}
	if len(manifest.RequiredFeatures) > 0 {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("manifest declares unsupported required features %v", manifest.RequiredFeatures)}}
	}
	if manifest.Contract.Scope != trimScope {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("manifest contract scope %q, expected %q — the payload is not a trim removal plan", manifest.Contract.Scope, trimScope)}}
	}
	if manifest.Inventory.Path != removalManifestName {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("manifest inventory path %q, expected %q", manifest.Inventory.Path, removalManifestName)}}
	}

	var plan trimPlanDocReader
	if err := decodeStrict(planRaw, &plan); err != nil {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("%s failed strict parsing: %v", planPath, err)}}
	}
	if plan.SchemaVersion != schemaVersionCurrent {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("removal manifest schema_version %d, reader supports %d", plan.SchemaVersion, schemaVersionCurrent)}}
	}
	if plan.OperationID != trimOpID {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			fmt.Sprintf("removal manifest operation_id %q, selected trim operation %q", plan.OperationID, trimOpID)}}
	}
	if len(plan.Groups) == 0 {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{
			"removal manifest declares no groups — nothing to re-create"}}
	}
	if err := validateTrimPlan(plan); err != nil {
		return docs, &ErrVerification{Check: "trim-documents", Details: []string{err.Error()}}
	}
	// Wave-5 (D2): every frozen action definition must itself validate
	// before anything trusts it — hostile paths, an unknown network
	// spelling, an input/output overlap or a non-positive timeout
	// refuse the document at read time (never mid-restore).
	for _, g := range plan.Groups {
		if g.Definition == nil {
			continue
		}
		def, err := defrostDefinition(g.Definition)
		if err != nil {
			return docs, &ErrVerification{Check: "trim-documents", Details: []string{
				fmt.Sprintf("trim group %s frozen definition: %v", g.GroupID, err)}}
		}
		if def.ID != g.GroupID {
			return docs, &ErrVerification{Check: "trim-documents", Details: []string{
				fmt.Sprintf("trim group %s frozen definition names action %q", g.GroupID, def.ID)}}
		}
	}

	docs.opDir = opDir
	docs.manifest = manifest
	docs.plan = plan
	return docs, nil
}

// validateTrimPlan enforces the structural invariants the driver relies
// on: unique group ids with declared outputs and recipes, valid
// root-relative input paths, frozen copies confined to the group's
// inputs/ prefix, and overlay patches surviving the full portable-name
// gate.
func validateTrimPlan(plan trimPlanDocReader) error {
	seen := map[string]bool{}
	for _, g := range plan.Groups {
		if g.GroupID == "" {
			return fmt.Errorf("removal manifest group with empty group_id")
		}
		if seen[g.GroupID] {
			return fmt.Errorf("removal manifest declares group %q twice", g.GroupID)
		}
		seen[g.GroupID] = true
		if len(g.Outputs) == 0 {
			return fmt.Errorf("trim group %s declares no outputs", g.GroupID)
		}
		for _, out := range g.Outputs {
			if err := validLiveRelPath(out); err != nil {
				return fmt.Errorf("trim group %s output: %v", g.GroupID, err)
			}
		}
		if len(g.ReclaimCommand) == 0 || g.ReclaimCommand[0] == "" {
			return fmt.Errorf("trim group %s records no reclaim command", g.GroupID)
		}
		for _, c := range g.RecreateLive {
			if c == "" {
				return fmt.Errorf("trim group %s records an empty recreate_live argument", g.GroupID)
			}
		}
		for _, in := range g.RecipeInputs {
			if err := validLiveRelPath(in.Path); err != nil {
				return fmt.Errorf("trim group %s recipe input: %v", g.GroupID, err)
			}
			if in.Missing {
				if in.Copy != "" || in.Digest != "" {
					return fmt.Errorf("trim group %s recipe input %s is recorded missing but carries a copy/digest", g.GroupID, in.Path)
				}
				continue
			}
			if err := validGroupCopy(in.Copy, "inputs", g.GroupID); err != nil {
				return fmt.Errorf("trim group %s recipe input %s: %v", g.GroupID, in.Path, err)
			}
			if !isHex64(in.Digest) {
				return fmt.Errorf("trim group %s recipe input %s: digest %q is not 64-hex", g.GroupID, in.Path, in.Digest)
			}
		}
		for _, p := range g.OverlayPatches {
			if err := validOverlayPatch(p, g.GroupID); err != nil {
				return err
			}
		}
	}
	return nil
}

// validOverlayPatch gates one carve-out record: a portable live path
// (full capsule-discipline name gate) plus a frozen copy confined to the
// group's overlay/ prefix, a known kind, and a digest contract: 64-hex
// for files (the file bytes); for links either 64-hex (the .ebb-link
// sidecar's target-text bytes — the post-amendment witness) or empty
// (pre-amendment manifests, unwitnessed and tolerated). Mode is the
// source permission bits at capture (0/absent = pre-amendment or link).
func validOverlayPatch(p overlayPatchReader, groupID string) error {
	if err := validPortableLivePath(p.Path); err != nil {
		return fmt.Errorf("trim group %s overlay patch: %v", groupID, err)
	}
	if err := validGroupCopy(p.Copy, "overlay", groupID); err != nil {
		return fmt.Errorf("trim group %s overlay patch %s: %v", groupID, p.Path, err)
	}
	switch p.Kind {
	case overlayKindFile:
		if !isHex64(p.Digest) {
			return fmt.Errorf("trim group %s file overlay patch %s: digest %q is not 64-hex", groupID, p.Path, p.Digest)
		}
	case overlayKindLink:
		if p.Digest != "" && !isHex64(p.Digest) {
			return fmt.Errorf("trim group %s link overlay patch %s: digest %q is not 64-hex", groupID, p.Path, p.Digest)
		}
	default:
		return fmt.Errorf("trim group %s overlay patch %s: unknown kind %q", groupID, p.Path, p.Kind)
	}
	return nil
}

// validGroupCopy gates an op-dir-relative frozen copy path: a plain
// slash path confined under "<kind>/<groupID>/" (inputs/<group>/... or
// overlay/<group>/...). Traversal anywhere refuses.
func validGroupCopy(copy, kind, groupID string) error {
	if copy == "" {
		return fmt.Errorf("frozen copy path is empty")
	}
	if strings.ContainsAny(copy, "\\\x00") {
		return fmt.Errorf("frozen copy path %q contains a backslash or NUL (forward slashes only)", copy)
	}
	if strings.HasPrefix(copy, "/") {
		return fmt.Errorf("frozen copy path %q is absolute", copy)
	}
	prefix := kind + "/" + groupID + "/"
	if !strings.HasPrefix(copy, prefix) {
		return fmt.Errorf("frozen copy path %q is not under %q", copy, prefix)
	}
	for _, seg := range strings.Split(copy, "/") {
		if seg == "" {
			return fmt.Errorf("frozen copy path %q has an empty segment", copy)
		}
		if seg == "." || seg == ".." {
			return fmt.Errorf("frozen copy path %q has a traversal segment", copy)
		}
		if strings.Contains(seg, ":") {
			return fmt.Errorf("frozen copy path %q segment %q contains a colon (an NTFS alternate-data-stream alias)", copy, seg)
		}
	}
	return nil
}

// validLiveRelPath gates a root-relative slash path the driver maps onto
// the live workspace (outputs, inputs): the policy path contract minus
// the policy import.
func validLiveRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if strings.Contains(p, "\x00") {
		return fmt.Errorf("path %q contains NUL", p)
	}
	if strings.Contains(p, "\\") {
		return fmt.Errorf("path %q contains a backslash; use '/' separators", p)
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("absolute path %q", p)
	}
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case "":
			return fmt.Errorf("path %q has an empty segment", p)
		case "..":
			return fmt.Errorf("path %q has a '..' segment", p)
		}
		if len(seg) >= 2 && seg[1] == ':' {
			return fmt.Errorf("path %q segment %q carries a drive prefix", p, seg)
		}
	}
	return nil
}

// validPortableLivePath gates a path the driver WRITES under the live
// root (overlay patches): the full capsule name-gate discipline —
// everything validLiveRelPath enforces plus the NTFS ADS colon alias,
// the Win32 illegal character class, C0 controls, trailing dot/space
// stripping, Windows device names and the 255 UTF-16 unit per-component
// limit. A hostile manifest must be refused at read time, never surface
// as a mid-restore I/O error.
func validPortableLivePath(p string) error {
	if err := validLiveRelPath(p); err != nil {
		return err
	}
	for _, seg := range strings.Split(p, "/") {
		if strings.ContainsAny(seg, `*?<>|"`) {
			return fmt.Errorf("path %q segment %q contains a Win32 illegal filename character (one of * ? < > | or double-quote)", p, seg)
		}
		for _, r := range seg {
			if r < 0x20 {
				return fmt.Errorf("path %q segment %q contains a C0 control character (%#U)", p, seg, r)
			}
		}
		if strings.Contains(seg, ":") {
			return fmt.Errorf("path %q segment %q contains a colon (an NTFS alternate-data-stream alias, not a file name)", p, seg)
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return fmt.Errorf("path %q segment %q ends in a dot or space (silently stripped by Windows on write)", p, seg)
		}
		base := seg
		for {
			ext := lastDotExt(base)
			if ext == "" {
				break
			}
			base = strings.TrimSuffix(base, ext)
		}
		if windowsDeviceNames[strings.ToUpper(base)] {
			return fmt.Errorf("path %q carries the Windows device-name segment %q", p, seg)
		}
		if len(seg) > maxSegmentUTF16Units {
			if units := utf16Len(seg); units > maxSegmentUTF16Units {
				return fmt.Errorf("path %q has a segment %d UTF-16 code units long — beyond the %d-unit NTFS per-component limit", p, units, maxSegmentUTF16Units)
			}
		}
	}
	return nil
}

// lastDotExt is filepath.Ext without the import (mirror of the capsule
// gate's helper): the suffix from the final dot, "" when none or when
// the dot is the first character of the segment.
func lastDotExt(seg string) string {
	for i := len(seg) - 1; i >= 0 && !isSlashByte(seg[i]); i-- {
		if seg[i] == '.' {
			return seg[i:]
		}
	}
	return ""
}

func isSlashByte(b byte) bool { return b == '/' || b == '\\' }

// windowsDeviceNames and the UTF-16 length bound mirror the capsule
// container's portable-name constants (J5/wave-J hardening).
var windowsDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true,
	"COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true,
	"LPT7": true, "LPT8": true, "LPT9": true,
}

const maxSegmentUTF16Units = 255

// utf16Len counts the UTF-16 code units of s (astral planes take two).
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func isHex64(s string) bool {
	if len(s) != 64 {
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
