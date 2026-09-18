package lifecycle

// REMOVAL AUTHORITY (Foundation §16.7: "Destructive root operations
// require an operation-scoped removal authorization constructed only
// after the lifecycle coordinator has verified the seal, source
// identity, generation and route approvals").
//
// This file is the ONLY place in the entire codebase where os.Remove,
// os.RemoveAll and os.Rename may appear. TestRemovalAuthorityTripwire
// enforces that mechanically; do not weaken it. Two gates live here:
//
//   - removalPermit: source-entry removal. Constructed exclusively by
//     the park tail (after seal readback + revalidation + quarantine
//     identity re-probe) and the trim tail (after seal + member-set
//     comparison). Every removal re-verifies the entry's identity by
//     kind, and for files by a FULL re-hash of the content — metadata
//     is never evidence (E08).
//   - removeEbbOwned / renameToQuarantine: Ebb's own scratch objects
//     (op/seal/journal siblings). These never touch user content and
//     refuse path shapes outside the .ebb-* namespace.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"ebb/internal/domain"
)

// removalPermit is the operation-scoped removal authorization. It is
// deliberately unexported: no caller outside this package can construct
// one, and inside the package only the two verified tails do.
type removalPermit struct {
	opID       domain.OperationID
	snapshotID domain.SnapshotID
	// basePath is the directory under which entries are removed: the
	// quarantine sibling for a park, the live root for a trim.
	basePath string
	// rootIdentity is the sealed identity of the source root; the
	// coordinator re-probes it before constructing the permit (F32).
	rootIdentity domain.RootIdentity
	// allowed maps root-relative paths to their sealed inventory
	// entries; only these paths may be removed.
	allowed map[string]domain.Entry
}

// newRemovalPermit validates the authorization inputs. kindOfScope is
// "park" or "trim"; the caller has already verified the seal readback,
// the revalidation comparison and (park) the quarantine identity.
func newRemovalPermit(opID domain.OperationID, snapID domain.SnapshotID, basePath string, ident domain.RootIdentity, allowed map[string]domain.Entry) (*removalPermit, error) {
	if len(allowed) == 0 {
		return nil, fmt.Errorf("lifecycle: removal permit: empty allowed set (nothing authorized)")
	}
	for path, e := range allowed {
		if e.Route != domain.RoutePreserve && e.Route != domain.RouteReconstruct {
			return nil, fmt.Errorf("lifecycle: removal permit: entry %s carries route %q; only preserve/reconstruct entries are covered by a seal", path, e.Route)
		}
		if e.Root != domain.RootMain {
			return nil, fmt.Errorf("lifecycle: removal permit: entry %s is not main-root", path)
		}
		// Security (Wave F review F1c): the permit is the LAST gate
		// before os.Remove and must not trust its caller's path
		// hygiene — entries rebuilt from retained documents on the
		// recovery path are untrusted input. Validate() rejects
		// traversal, absolute, drive-prefix and backslash forms.
		if err := e.Validate(); err != nil {
			return nil, fmt.Errorf("lifecycle: removal permit: entry %s fails validation: %w", path, err)
		}
	}
	return &removalPermit{opID: opID, snapshotID: snapID, basePath: basePath, rootIdentity: ident, allowed: allowed}, nil
}

// removalStats reports one walk's outcome.
type removalStats struct {
	Removed     int
	SkippedGone int
}

// progressEvery: journal cadence for removal progress (§16.5 "per-entry
// removal progress can live in a bounded journal").
const progressEvery = 256

// execute walks the allowed set in REVERSE canonical order (children
// strictly before parents) and removes each entry after re-verifying
// its identity. Already-absent entries are skipped — idempotent
// reconciliation of a previously interrupted authorized walk (§12.4).
// Any kind/digest/link-text mismatch or removal failure stops the walk
// with *ErrRemovalBlocked; the source retains everything not removed.
func (p *removalPermit) execute(ctx context.Context, probe domain.PlatformProbe, j *opJournal, onProgress func(removed int, lastPath string)) (removalStats, error) {
	paths := make([]string, 0, len(p.allowed))
	for path := range p.allowed {
		paths = append(paths, path)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(paths))) // reverse canonical: children first

	var stats removalStats
	for _, rel := range paths {
		if err := ctx.Err(); err != nil {
			return stats, fmt.Errorf("lifecycle: removal canceled after %d entries: %w", stats.Removed, err)
		}
		abs := filepath.Join(p.basePath, filepath.FromSlash(rel))
		if _, err := os.Lstat(abs); errors.Is(err, fs.ErrNotExist) {
			stats.SkippedGone++
			continue
		} else if err != nil {
			return stats, &ErrRemovalBlocked{Path: abs, Code: BlockProbeFailed, Err: err}
		}
		sealed := p.allowed[rel]

		// Re-observe without following; probe classification
		// distinguishes junctions from other reparse points (Lstat
		// cannot — platform probe finding).
		facts, err := probe.ProbeFile(abs)
		if err != nil {
			return stats, &ErrRemovalBlocked{Path: abs, Code: BlockProbeFailed, Err: err}
		}
		if facts.Kind != sealed.Kind {
			return stats, &ErrRemovalBlocked{Path: abs, Code: BlockKindMismatch,
				Err: fmt.Errorf("on-disk kind %q is not the sealed kind %q (possible reparse substitution)", facts.Kind, sealed.Kind)}
		}
		switch sealed.Kind {
		case domain.KindFile:
			// Full re-hash per removed file: metadata is not evidence
			// (E08). A changed file blocks removal and stays.
			got, err := digestFile(abs)
			if err != nil {
				return stats, &ErrRemovalBlocked{Path: abs, Code: BlockProbeFailed, Err: err}
			}
			if got != sealed.Digest {
				return stats, &ErrRemovalBlocked{Path: abs, Code: BlockDigestChanged,
					Err: fmt.Errorf("content digest %s differs from sealed digest %s", got, sealed.Digest)}
			}
		case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
			if facts.LinkTarget != sealed.LinkTarget {
				return stats, &ErrRemovalBlocked{Path: abs, Code: BlockLinkChanged,
					Err: fmt.Errorf("link text %q differs from sealed text %q", facts.LinkTarget, sealed.LinkTarget)}
			}
		}

		if err := removeOne(abs); err != nil {
			return stats, p.classifyRemoveError(abs, err)
		}
		stats.Removed++
		if j != nil {
			j.append(journalRecord{Step: "removed", Path: rel, Removed: stats.Removed})
		}
		if stats.Removed%progressEvery == 0 && onProgress != nil {
			onProgress(stats.Removed, rel)
		}
	}
	return stats, nil
}

// removeRoot removes the (now empty) base directory itself — the final
// park step. Non-empty means new content appeared; that is a block,
// never a force-remove (§12.3: the system does not finish deleting just
// to achieve a tidy status). An already-absent root is success: a crash
// between the root removal and the PARKED commit reconciles idempotently
// on resume (§12.4).
func (p *removalPermit) removeRoot(j *opJournal) error {
	if err := removeOne(p.basePath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return p.classifyRemoveError(p.basePath, err)
	}
	if j != nil {
		j.append(journalRecord{Step: "quarantine-root-removed", Path: p.basePath})
	}
	return nil
}

// removeEmptyAncestors climbs from each output root's parent toward the
// live root, removing directories that the trim left empty (§17.3
// "empty parent dirs up the group root removed"). It stops at the
// first non-empty or missing directory and never touches the live root.
//
// Security (Wave F review F2/F3): outputs arrive from retained trim
// plans on the resume path — untrusted input — so every output is
// path-validated before climbing, and the climb itself never follows a
// link (a substituted junction is user content, not an empty ancestor:
// Lstat classifies before ReadDir, and a link is never removed here).
func (p *removalPermit) removeEmptyAncestors(outputs []string, j *opJournal) error {
	for _, out := range outputs {
		if err := validRelPath(out); err != nil {
			return fmt.Errorf("lifecycle: trim output %q fails path validation: %w", out, err)
		}
		dir := parentRel(out)
		for dir != "" && dir != "." && dir != "/" {
			abs := filepath.Join(p.basePath, filepath.FromSlash(dir))
			fi, err := os.Lstat(abs)
			if errors.Is(err, fs.ErrNotExist) {
				break // already gone; keep climbing is pointless
			}
			if err != nil {
				return p.classifyRemoveError(abs, err)
			}
			if !fi.IsDir() || fi.Mode()&(os.ModeSymlink|fs.ModeIrregular) != 0 {
				// A link or non-directory: stop climbing this branch
				// and never remove it (§12.2 step 8 no-follow).
				break
			}
			des, err := os.ReadDir(abs)
			if err != nil {
				return p.classifyRemoveError(abs, err)
			}
			if len(des) > 0 {
				break // retained content lives here; stop
			}
			if err := removeOne(abs); err != nil {
				return p.classifyRemoveError(abs, err)
			}
			if j != nil {
				j.append(journalRecord{Step: "removed-empty-ancestor", Path: dir})
			}
			dir = parentRel(dir)
		}
	}
	return nil
}

// validRelPath enforces the root-relative path contract for plan-supplied
// outputs (Wave F review F2): no traversal, no absolute/drive/backslash
// forms, no NUL, no empty segments.
func validRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") || strings.Contains(p, "\\") {
		return fmt.Errorf("not forward-slash root-relative form")
	}
	if len(p) >= 2 && p[1] == ':' {
		return fmt.Errorf("drive prefix")
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("NUL byte")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return fmt.Errorf(".. segment")
		}
		if seg == "" {
			return fmt.Errorf("empty segment")
		}
	}
	return nil
}

func parentRel(rel string) string {
	i := strings.LastIndexByte(rel, '/')
	if i < 0 {
		return "."
	}
	return rel[:i]
}

// removeOne performs the single audited os.Remove. Files, links
// (symlink/junction — the link only, never the target) and empty
// directories all remove through the same call; kind was verified
// beforehand.
func removeOne(abs string) error { return os.Remove(abs) }

// classifyRemoveError maps a failed os.Remove to the typed blocker.
func (p *removalPermit) classifyRemoveError(abs string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		// Raced with an authorized removal of the same entry; treat as
		// gone next iteration, but surface as blocked-with-context here
		// since the walk stops.
		return &ErrRemovalBlocked{Path: abs, Code: BlockRemoveFailed, Err: err}
	}
	if isSharingViolation(err) {
		return &ErrRemovalBlocked{Path: abs, Code: BlockSharingViolation, Err: fmt.Errorf(
			"Windows sharing violation (errno 32): a process holds an open handle without FILE_SHARE_DELETE; close it and ResumeRemoval (never scheduled on reboot, never killed — Foundation §12.3): %w", err)}
	}
	if errors.Is(err, syscall.ENOTEMPTY) {
		return &ErrRemovalBlocked{Path: abs, Code: BlockDirNotEmpty, Err: fmt.Errorf(
			"directory not empty: content that was not in the sealed inventory appeared under it: %w", err)}
	}
	return &ErrRemovalBlocked{Path: abs, Code: BlockRemoveFailed, Err: err}
}

// isSharingViolation reports Windows errno 32 (ERROR_SHARING_VIOLATION).
// On non-Windows platforms errno 32 is EPIPE and is deliberately not
// matched.
func isSharingViolation(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == 32
}

// ---- Ebb-owned scratch object cleanup (audited, shape-gated) --------

// ebbOwnedShape matches the base names this package may ever clean up:
// op/seal dirs and the journal file. Everything else is refused.
var ebbOwnedShape = regexp.MustCompile(`^\.ebb-(op|seal)-[0-9a-f]{32}$|^\.ebb-journal-[0-9a-f]{32}\.jsonl$`)

// removeEbbOwned removes an Ebb-owned sibling scratch object (op dir,
// seal dir, journal file) after its content was captured and verified.
// It refuses any path whose base name is not in the .ebb-* namespace,
// so it can never be repurposed against user content.
func removeEbbOwned(path string) error {
	if !ebbOwnedShape.MatchString(filepath.Base(path)) {
		return fmt.Errorf("lifecycle: refusing to remove %q: not an Ebb-owned scratch object", path)
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("lifecycle: cleanup %s: %w", path, err)
	}
	return nil
}

// renameToQuarantine performs the audited §12.2 step 7 rename. The
// target must not exist (rename-over-dir always fails on Windows —
// platform probe finding; a pre-existing quarantine of the same op id
// means this operation already ran its rename and crashed after).
func renameToQuarantine(root, quarantine string) error {
	if _, err := os.Lstat(quarantine); err == nil {
		return fmt.Errorf("lifecycle: quarantine %s already exists; a previous run may have renamed the root already (use Recover)", quarantine)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("lifecycle: quarantine %s pre-check: %w", quarantine, err)
	}
	if err := os.Rename(root, quarantine); err != nil {
		if isSharingViolation(err) {
			return &ErrRemovalBlocked{Path: root, Code: BlockSharingViolation, Err: fmt.Errorf(
				"rename to quarantine blocked by an open handle (errno 32); close writers and retry: %w", err)}
		}
		return fmt.Errorf("lifecycle: rename %s -> %s: %w", root, quarantine, err)
	}
	return nil
}

// renameBackFromQuarantine undoes the quarantine rename when the
// post-rename identity check failed (the only sanctioned reverse
// rename; both paths are the operation's own root/quarantine pair).
func renameBackFromQuarantine(quarantine, root string) error {
	return os.Rename(quarantine, root)
}
