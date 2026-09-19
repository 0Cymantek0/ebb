// Package pathcanon resolves filesystem path aliases — symlinks AND
// Windows junctions/mount points — to canonical absolute paths using
// only the standard library (no internal/platform import; Foundation
// §16.7 module boundaries).
//
// It exists so the two overlap-preflight owners (lifecycle's capture
// side and restore's destination side) share ONE canonicalizer instead
// of drifting twins: invariant I06 ("Root/vault/operation paths cannot
// overlap through aliases unnoticed") is only as strong as the weakest
// spelling comparison any side makes. The implementation is the
// Wave F/D020 component walk (finding F6), extracted verbatim.
package pathcanon

import (
	"os"
	"path/filepath"
	"strings"
)

// LinkBudget bounds alias resolution (chains of links pointing at
// links); beyond it the lexical spelling stands.
const LinkBudget = 32

// CanonicalPath resolves alias spellings — symlinks AND Windows
// junctions/mount points — to a final absolute path, stdlib only.
//
// filepath.EvalSymlinks alone is NOT sufficient on Windows: Go reports
// junctions as ModeIrregular (not ModeSymlink), so EvalSymlinks neither
// resolves them nor paths traversing them (probe-verified) — exactly the
// alias class of Wave F review finding F6. CanonicalPath therefore walks
// the path components itself: a component observed as a link
// (ModeSymlink or ModeIrregular) is resolved through os.Readlink (which
// DOES read junction text on Windows) and resolution restarts on the
// target (nested aliases collapse); a regular existing component is
// normalized through EvalSymlinks, which also expands 8.3-short and
// true-case spellings (the GIT-WT-1 lesson).
//
// Residual, documented honestly: a component that cannot be resolved —
// it does not exist yet (a not-yet-initialized vault repo), cannot be
// read, is a subst/ mapped drive with no link object to read, or the
// link budget is exhausted — falls back to its lexical spelling, and an
// alias expressed only through such a spelling can still go unnoticed
// by this comparison. Callers that remove data keep identity
// revalidation (I13) as the backstop for anything that slips past.
func CanonicalPath(p string) string {
	return canonicalFrom(filepath.Clean(mustAbs(p)), LinkBudget)
}

// UnderPath reports whether child equals or lies below parent (native
// separators; both must already be cleaned/absolute).
func UnderPath(parent, child string) bool {
	if parent == child {
		return true
	}
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// mustAbs is filepath.Abs with a clean-on-failure fallback (callers
// feed it vault paths that may be relative in tests).
func mustAbs(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

// canonicalFrom walks the components of one already-clean absolute
// path, resolving link-ish components (symlinks, junctions, mount
// points) through os.Readlink and normalizing the rest through
// per-component EvalSymlinks.
func canonicalFrom(p string, budget int) string {
	if budget <= 0 {
		return p
	}
	vol := filepath.VolumeName(p)
	rest := strings.TrimPrefix(p, vol)
	rest = strings.TrimPrefix(rest, string(filepath.Separator))
	cur := string(filepath.Separator)
	if vol != "" {
		cur = vol + string(filepath.Separator)
	}
	for _, comp := range strings.Split(rest, string(filepath.Separator)) {
		if comp == "" {
			continue
		}
		child := filepath.Join(cur, comp)
		fi, err := os.Lstat(child)
		if err == nil && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			// An alias component: resolve its target and continue from
			// the RESOLVED path (handles nested aliases).
			tgt, rerr := os.Readlink(child)
			if rerr != nil || tgt == "" {
				cur = child
				continue
			}
			tgt = strings.TrimPrefix(tgt, `\??\`) // junction substitute-name prefix
			if !filepath.IsAbs(tgt) {
				tgt = filepath.Join(cur, tgt)
			}
			cur = canonicalFrom(filepath.Clean(tgt), budget-1)
			continue
		}
		// A regular (or missing) component: EvalSymlinks resolves any
		// symlink spelling of the prefix AND normalizes short/case
		// forms; on failure keep the lexical spelling (residual above).
		if resolved, ferr := filepath.EvalSymlinks(child); ferr == nil {
			cur = resolved
		} else {
			cur = child
		}
	}
	return cur
}
