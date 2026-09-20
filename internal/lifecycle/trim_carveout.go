package lifecycle

// Granular carve-out and overlay patching (ADR D034; Foundation §7.4
// and the F10/F53 amendment). When a regenerate group is cancelled by
// preserved or Git-tracked entries INSIDE its outputs, a whole-group
// refusal wastes the reclaim: a 2 KiB tracked tweak inside node_modules
// blocks 20 GB. The carve-out path isolates exactly those cancelling
// entries into vault overlay patches — byte copies inside the trim op
// dir, which is captured, verified and sealed as payload P like every
// other op-dir byte — records them in the removal manifest, and lets
// the clean reconstructible bulk be removed. The restore side (a
// parallel contract over the SAME frozen overlayPatchRecord schema)
// reruns the base recipe and reapplies the overlay.
//
// Safety shape:
//
//   - Consent is never inferred. A carve happens only when
//     opts.CarveOut is true (the CLI gates that behind its own typed
//     confirmation or --carve-out; lifecycle re-checks, mirroring
//     ApprovalReady) AND the entry's path is in the caller's approved
//     carve list opts.CarveOutPaths (F8: consent is pinned to the exact
//     candidate paths the consent surface displayed — the SET is the
//     authority, the boolean is defense in depth). A plan-time
//     canceller that is not in the set is drift between the two scans
//     and refuses the group exactly as a missing consent would.
//   - Carved entries are ordinary permit members: the removal walk
//     re-digests every file and re-verifies every link's text
//     immediately before removal (E08), exactly like bulk members, so
//     nothing is removed unless the sealed overlay bytes match the live
//     bytes.
//   - Budgets bound the overlay (64 MiB / 2000 entries) so a hostile
//     or accidental "everything is preserved" tree cannot balloon the
//     op dir; violations refuse the group with honest text.
//   - Only file/link content round-trips. Directories are captured
//     implicitly as parents of carved files: the recreate recipe
//     rebuilds the tree, the overlay only rewrites file/link content.
//
// This file performs NO removal (the removal-authority tripwire holds):
// it reads source bytes and writes op-dir copies only.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ebb/internal/domain"
	"ebb/internal/policy"
)

// Carve-out budgets (named, exported so the CLI approval surface can
// pre-check eligibility with the same constants the plan enforces).
const (
	// CarveOutMaxBytes bounds the total carved file content.
	CarveOutMaxBytes = 64 << 20 // 64 MiB
	// CarveOutMaxEntries bounds the carved entry count.
	CarveOutMaxEntries = 2000
)

// overlayPatchKind values (frozen schema vocabulary).
const (
	overlayKindFile = "file"
	overlayKindLink = "link"
)

// ---- F53 evidence parity ------------------------------------------------
//
// The CLI resolves routes over git-annotated entries (annotateGitEvidence,
// internal/cli); lifecycle's own inventory scan is evidence-blind, so a
// naive re-resolve would disagree with the approval surface about which
// groups are cancelled. applyGitEvidence re-annotates the scan's raw
// entries with the SAME tokens policy.Resolve consumes and re-resolves.
// The token spellings are the contract internal/policy matches
// ("git:tracked"/"git:admin" prefixes); the path derivation mirrors
// internal/cli's underGitAdmin (first ".git" segment counts only when the
// root repo's administration is inside the root; later ".git" segments
// are nested repositories, inside the root by construction).

// applyGitEvidence re-annotates the trim's own scan with the caller's
// git-index observation (plus the path-derivable nested-admin
// classification) and replaces the evidence-blind resolution with the
// annotated one.
func applyGitEvidence(st *captureState) error {
	raw := st.scan.Entries
	if len(raw) == 0 && len(st.opts.GitTrackedPaths) == 0 && !st.opts.Git.IsRepo {
		return nil
	}
	tracked := make(map[string]bool, len(st.opts.GitTrackedPaths))
	for _, p := range st.opts.GitTrackedPaths {
		tracked[p] = true
	}
	rootAdminInside := st.opts.Git.IsRepo && st.opts.Git.AdminInsideRoot
	for i := range raw {
		e := &raw[i]
		if e.Root != domain.RootMain {
			continue
		}
		var tokens []string
		if tracked[e.Path] {
			tokens = append(tokens, "git:tracked")
		}
		if underGitAdminRel(e.Path, rootAdminInside) {
			tokens = append(tokens, "git:admin")
		}
		if len(tokens) > 0 {
			merged := make([]string, 0, len(e.Evidence)+len(tokens))
			merged = append(merged, e.Evidence...)
			merged = append(merged, tokens...)
			e.Evidence = merged
		}
	}
	resolved, err := policy.Resolve(raw, st.opts.Policy)
	if err != nil {
		return fmt.Errorf("lifecycle: resolve policy: %w", err)
	}
	st.resolved = resolved
	st.entries = resolved.Entries
	return nil
}

// underGitAdminRel mirrors internal/cli's underGitAdmin (see the comment
// above applyGitEvidence): reports whether the root-relative slash path
// lies inside a Git administration directory.
func underGitAdminRel(p string, rootAdminInside bool) bool {
	if p == "" {
		return false
	}
	first := true
	for len(p) > 0 {
		var seg string
		if i := strings.IndexByte(p, '/'); i >= 0 {
			seg, p = p[:i], p[i+1:]
		} else {
			seg, p = p, ""
		}
		if seg == ".git" {
			if first {
				return rootAdminInside
			}
			return true
		}
		first = false
	}
	return false
}

// ---- canceller discovery -------------------------------------------------

// CarveCandidate names one canceller entry proposed for carve-out. The
// CLI approval surface renders these (path, kind, size) before any
// consent is asked for.
type CarveCandidate struct {
	Group string
	Path  string
	Kind  domain.EntryKind
	Bytes int64 // logical file size; 0 for links
}

// carveClassification sorts the entries under one CANCELLED group's
// outputs into the carve-out plan's three buckets.
type carveClassification struct {
	// Carved are the cancelling file/link entries to capture as overlay
	// patches and then remove.
	Carved []domain.Entry
	// Bulk is the clean reconstructible remainder under the outputs
	// (plus canceller directories, which empty out once their carved
	// children are removed; the recipe recreates the tree).
	Bulk []domain.Entry
	// Refusals are honest blocker strings: entries (or path shapes)
	// that make the group un-carve-able, so it must be refused exactly
	// as a whole-group cancellation would.
	Refusals []string
}

// classifyCarveOut is the pure canceller-discovery core shared by the
// plan builder and the CLI-facing CarveOutCandidates. entries are
// RESOLVED entries (policy.Resolve output); outputs are the group's
// declared output prefixes.
func classifyCarveOut(entries []domain.Entry, outputs []string) carveClassification {
	var cls carveClassification
	for _, e := range entries {
		if e.Root != domain.RootMain || !underAnyRelPrefix(outputs, e.Path) {
			continue
		}
		switch {
		case e.Route != domain.RoutePreserve && e.Route != domain.RouteReconstruct:
			// Locally recorded external/discard/retained-artifact routes
			// keep their route under a cancelled group; the removal
			// permit (correctly) refuses them, and their bytes are not
			// recipe output either — carve cannot cover them.
			cls.Refusals = append(cls.Refusals, fmt.Sprintf(
				"entry %s carries route %q, which a trim removal permit cannot cover (carve-out refuses the group)", e.Path, e.Route))
			continue
		case !e.Kind.DestructiveSafe():
			cls.Refusals = append(cls.Refusals, fmt.Sprintf(
				"entry %s has kind %q, which is neither a file nor a link and cannot be carved (F53 whole-group preservation stands)", e.Path, e.Kind))
			continue
		}
		if err := carveEntryShape(e); err != nil {
			// Hostile path semantics or broken enum shape: nothing from
			// this entry may reach a removal permit.
			cls.Refusals = append(cls.Refusals, fmt.Sprintf(
				"entry %s fails carve-out entry-shape validation (carve-out refuses the group): %v", e.Path, err))
			continue
		}
		if !carveCanceller(e) {
			cls.Bulk = append(cls.Bulk, e)
			continue
		}
		switch carveKindOf(e.Kind) {
		case overlayKindFile, overlayKindLink:
			cls.Carved = append(cls.Carved, e)
		default:
			// A cancelling directory (a preserve-rule dir match, the
			// nested .git admin dir itself, ...): captured implicitly as
			// the parent of any carved child; a canceller dir with NO
			// carve-able file inside is not itself captured — the recipe
			// recreates the tree, only file/link content round-trips.
			cls.Bulk = append(cls.Bulk, e)
		}
	}
	return cls
}

// carveEntryShape enforces the path/enum shape every entry must carry
// in BOTH scan passes. Digest presence is deliberately NOT checked
// here: the CLI's discovery pass defers hashing by design (Foundation
// §8.1 two passes), so digest-dependent gates live in carvePlanBlocker,
// which runs only over lifecycle's own hashed scan.
func carveEntryShape(e domain.Entry) error {
	if err := validRelPath(e.Path); err != nil {
		return err
	}
	if e.Route == "" {
		return fmt.Errorf("route unresolved (unknown is not a route)")
	}
	switch e.Ownership {
	case domain.OwnershipOwned, domain.OwnershipShared, domain.OwnershipReferenceOnly, "":
	default:
		return fmt.Errorf("invalid ownership %q", e.Ownership)
	}
	return nil
}

// carveCanceller reports whether the entry is one of the cancelling
// causes policy.Resolve acts on for a regenerate group: an explicit
// preservation rule (or a preserve-matched directory), required
// source/Git state (git:tracked / git:admin evidence), or a non-owned
// FILE (links are reference-only by scanner design and are ordinary
// recipe output, e.g. pnpm's layout).
func carveCanceller(e domain.Entry) bool {
	for _, ev := range e.Evidence {
		if strings.HasPrefix(ev, "policy:preserve=") ||
			strings.HasPrefix(ev, "policy:preserve-dir=") ||
			strings.HasPrefix(ev, "git:tracked") ||
			strings.HasPrefix(ev, "git:admin") {
			return true
		}
	}
	if e.Kind == domain.KindFile && e.Ownership != domain.OwnershipOwned && e.Ownership != "" {
		return true
	}
	return false
}

// carveKindOf maps a domain kind onto the frozen overlay schema's kind
// vocabulary; "" means the kind is not individually carve-able.
func carveKindOf(k domain.EntryKind) string {
	switch k {
	case domain.KindFile:
		return overlayKindFile
	case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
		return overlayKindLink
	}
	return ""
}

// CarveOutCandidates enumerates the carve-able canceller entries of one
// resolved group for an approval surface: the candidates (files and
// links only) plus the refusals that make the group un-carve-able. It
// is pure — no I/O, no consent, no plan mutation — so the CLI can offer
// exactly what lifecycle would carve. Budgets are the caller's to check
// against CarveOutMaxBytes / CarveOutMaxEntries.
func CarveOutCandidates(res policy.Resolved, groupID string) ([]CarveCandidate, []string) {
	var outputs []string
	cancelled := false
	for _, d := range res.Groups {
		if d.ID == groupID {
			outputs, cancelled = d.Outputs, d.Cancelled && !d.Applicable
			break
		}
	}
	if !cancelled {
		return nil, nil
	}
	cls := classifyCarveOut(res.Entries, outputs)
	cands := make([]CarveCandidate, 0, len(cls.Carved))
	for _, e := range cls.Carved {
		cands = append(cands, CarveCandidate{Group: groupID, Path: e.Path, Kind: e.Kind, Bytes: e.LogicalSize})
	}
	return cands, cls.Refusals
}

// ---- plan-side validation -------------------------------------------------

// carvePlanBlocker validates one group's classification for execution:
// refusals, digests (lifecycle's scan hashes by then), budgets and
// case-insensitive collisions. Empty string means the carve may
// proceed.
func carvePlanBlocker(groupID string, cls carveClassification) string {
	if n := len(cls.Refusals); n > 0 {
		return fmt.Sprintf("regenerate group %s is not applicable for removal and carve-out is refused: %s",
			groupID, strings.Join(cls.Refusals, "; "))
	}
	// Plan-time digest gates (lifecycle's own scan hashes here): a
	// carved file without a digest cannot be verified at removal time,
	// and a preserve-routed bulk file without one (placeholder-suspect,
	// never opened for hashing) cannot join a removal permit.
	for _, e := range cls.Carved {
		if carveKindOf(e.Kind) == overlayKindFile && e.Digest == "" {
			return fmt.Sprintf("carve-out of group %s refused: carved file %s has no content digest (unhashed or cloud-placeholder suspicion; Foundation §8.1)",
				groupID, e.Path)
		}
	}
	for _, e := range cls.Bulk {
		if e.Kind == domain.KindFile && e.Route == domain.RoutePreserve && e.Digest == "" {
			return fmt.Sprintf("carve-out of group %s refused: preserved file %s under the outputs has no content digest (unhashed or cloud-placeholder suspicion; Foundation §8.1)",
				groupID, e.Path)
		}
	}
	var total int64
	for _, e := range cls.Carved {
		total += e.LogicalSize
	}
	if len(cls.Carved) > CarveOutMaxEntries {
		return fmt.Sprintf("carve-out of group %s exceeds the entry budget: %d carved entries > %d (D034; whole-group preservation stands)",
			groupID, len(cls.Carved), CarveOutMaxEntries)
	}
	if total > CarveOutMaxBytes {
		return fmt.Sprintf("carve-out of group %s exceeds the byte budget: %d bytes > %d (D034; whole-group preservation stands)",
			groupID, total, CarveOutMaxBytes)
	}
	if coll := carveCaseFoldCollisions(cls); len(coll) > 0 {
		return fmt.Sprintf("carve-out of group %s refused: case-insensitive path collision between a carved entry and another entry under the outputs: %s",
			groupID, strings.Join(coll, "; "))
	}
	return ""
}

// carveConsentBlocker enforces F8 consent pinning: the carve set is
// re-derived from lifecycle's OWN scan at plan time, so consent must be
// pinned to the exact candidate paths the approval surface displayed
// (opts.CarveOutPaths), not to a set-level boolean. A plan-time
// canceller whose path is not in the approved list is drift between the
// two scans (e.g. a file that became git-tracked after the CLI's
// discovery); the group refuses exactly as it would without consent,
// with text naming the drift. Empty string means every candidate is
// approved. (Cancelling DIRECTORIES are not candidates — they are never
// displayed, so they cannot drift; the recipe recreates the tree.)
func carveConsentBlocker(groupID string, cls carveClassification, approvedPaths []string) string {
	if len(cls.Carved) == 0 {
		return ""
	}
	approved := make(map[string]bool, len(approvedPaths))
	for _, p := range approvedPaths {
		approved[p] = true
	}
	var drift []string
	for _, e := range cls.Carved {
		if !approved[e.Path] {
			drift = append(drift, e.Path)
		}
	}
	if len(drift) == 0 {
		return ""
	}
	sort.Strings(drift)
	return fmt.Sprintf(
		"regenerate group %s is not applicable for removal: carve candidate %s was not part of the approved carve list (the workspace changed between the carve confirmation and this scan; the entry was never displayed for consent, so nothing was carved or removed). Safe action: rerun the command and confirm the current candidate list",
		groupID, strings.Join(drift, ", "))
}

// carveCaseFoldCollisions reports carved-path collisions (case-
// insensitive) against the bulk and against other carved entries — on a
// case-insensitive filesystem two such entries are the same file, so the
// overlay copy and the manifest records would silently merge. Bulk-only
// collisions are pre-existing filesystem reality and not reported.
func carveCaseFoldCollisions(cls carveClassification) []string {
	folded := make(map[string]string, len(cls.Bulk)+len(cls.Carved))
	var out []string
	for _, e := range cls.Bulk {
		folded[strings.ToLower(e.Path)] = e.Path
	}
	for _, e := range cls.Carved {
		key := strings.ToLower(e.Path)
		if other, ok := folded[key]; ok && other != e.Path {
			out = append(out, fmt.Sprintf("%s collides with %s", e.Path, other))
			continue
		}
		folded[key] = e.Path
	}
	sort.Strings(out)
	return out
}

// ---- overlay capture ------------------------------------------------------

// writeOverlayCopies byte-copies every carved entry of one group into
// the op dir at overlay/<groupID>/<path> (files) or
// overlay/<groupID>/<path>.ebb-link (links: the sidecar's entire byte
// content is the link's target text — links are never followed). Every
// copy is verified against the sealed scan facts before it is written
// (digest for files, exact link text for links); a mid-operation
// change fails the trim as ErrSourceChanged instead of sealing a lie.
// The copies land inside the op dir, so buildTrimSelection's walk
// includes them in P's capture, coverage and readback automatically.
func writeOverlayCopies(st *captureState, gp trimGroupPlan) ([]overlayPatchRecord, error) {
	if len(gp.Carved) == 0 {
		return nil, nil
	}
	recs := make([]overlayPatchRecord, 0, len(gp.Carved))
	for _, e := range gp.Carved {
		if err := validRelPath(e.Path); err != nil {
			// Defense in depth under entry.Validate: the path also has
			// to survive the plan-side contract before it names an
			// op-dir file.
			return nil, fmt.Errorf("lifecycle: carve-out entry %q fails path validation: %w", e.Path, err)
		}
		src := filepath.Join(st.rootAbs, filepath.FromSlash(e.Path))
		switch carveKindOf(e.Kind) {
		case overlayKindFile:
			// F9: record the source permission bits the platform reports
			// at capture time, so the restore side can reapply them
			// (carved executables must not come back 0600).
			fi, err := os.Stat(src)
			if err != nil {
				return nil, fmt.Errorf("lifecycle: carve-out stat %s: %w", e.Path, err)
			}
			b, err := os.ReadFile(src)
			if err != nil {
				return nil, fmt.Errorf("lifecycle: carve-out read %s: %w", e.Path, err)
			}
			if got := digestBytes(b); got != e.Digest {
				return nil, &ErrSourceChanged{Diff: []string{fmt.Sprintf(
					"carve-out entry %s changed between scan and capture (digest %s, sealed %s); the overlay must capture exactly the sealed bytes",
					e.Path, got, e.Digest)}}
			}
			rel := overlayDirName + "/" + gp.GroupID + "/" + e.Path
			if err := writeOpDirFile(st, rel, b); err != nil {
				return nil, err
			}
			recs = append(recs, overlayPatchRecord{
				Path: e.Path, Copy: rel, Digest: e.Digest,
				Kind: overlayKindFile, Mode: uint32(fi.Mode().Perm()),
			})
		case overlayKindLink:
			target, err := os.Readlink(src)
			if err != nil {
				return nil, fmt.Errorf("lifecycle: carve-out readlink %s: %w", e.Path, err)
			}
			if target != e.LinkTarget {
				return nil, &ErrSourceChanged{Diff: []string{fmt.Sprintf(
					"carve-out link %s changed between scan and capture (text %q, sealed %q); the overlay must capture exactly the sealed link text",
					e.Path, target, e.LinkTarget)}}
			}
			// The sidecar bytes are exactly the re-verified link text; the
			// recorded digest is over THESE bytes (F7), so the sidecar is
			// witnessed in durable state and payload-only tampering that
			// rewrites a carved link's target is detectable at restore
			// time. Links carry no permission bits of their own: Mode 0.
			sidecar := []byte(target)
			rel := overlayDirName + "/" + gp.GroupID + "/" + e.Path + linkSidecarSuffix
			if err := writeOpDirFile(st, rel, sidecar); err != nil {
				return nil, err
			}
			recs = append(recs, overlayPatchRecord{
				Path: e.Path, Copy: rel, Digest: digestBytes(sidecar), Kind: overlayKindLink,
			})
		default:
			return nil, fmt.Errorf("lifecycle: carve-out entry %s has kind %q with no overlay encoding (internal inconsistency)", e.Path, e.Kind)
		}
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Path < recs[j].Path })
	return recs, nil
}

// writeOpDirFile writes one op-dir file at the op-dir-relative slash
// path rel, creating parent directories.
func writeOpDirFile(st *captureState, rel string, b []byte) error {
	dst := filepath.Join(st.opDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("lifecycle: carve-out overlay %s: %w", rel, err)
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		return fmt.Errorf("lifecycle: carve-out overlay %s: %w", rel, err)
	}
	return nil
}
