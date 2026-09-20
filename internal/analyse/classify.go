// classify.go assigns every scanned project its §11.3 category, its
// shields (§11.5B/§11.5C) and its copyable recommendation. All
// thresholds are named constants; the classification itself is pure so
// boundary behavior is exactly testable against an injected clock.

package analyse

import (
	"fmt"
	"time"
)

// Classification thresholds (plan §11.3 / D037 defaults).
const (
	// ActiveWindow: activity within this window counts as active
	// (bloated-active when the footprint exceeds BloatedBytes).
	ActiveWindow = 14 * 24 * time.Hour
	// StaleAfter: untouched for at least this long counts as stale.
	StaleAfter = 30 * 24 * time.Hour
	// AbandonedAfter: untouched for longer than this counts as abandoned
	// (park recommendation).
	AbandonedAfter = 90 * 24 * time.Hour
	// BloatedBytes: an estimated footprint above this on an active
	// project marks it bloated (2 GiB).
	BloatedBytes = int64(2) << 30
)

// classifyThresholds is the effective threshold set (defaults, or the
// engine's injected overrides).
type classifyThresholds struct {
	activeWindow   time.Duration
	staleAfter     time.Duration
	abandonedAfter time.Duration
	bloatedBytes   int64
}

var defaultThresholds = classifyThresholds{
	activeWindow:   ActiveWindow,
	staleAfter:     StaleAfter,
	abandonedAfter: AbandonedAfter,
	bloatedBytes:   BloatedBytes,
}

// classify sets p.Category, p.Shields and p.Recommendation. Order:
// offline placeholder first, then shields from the git survey, then the
// merged-worktree rule (native git delegation wins over age buckets),
// then the age/footprint buckets.
func classify(p *Project, now time.Time, t classifyThresholds) {
	if p.Offline {
		p.Category = CategoryOffline
		return
	}

	// ---- shields ------------------------------------------------------
	r := p.Repo
	if r.UnmergedEntries > 0 {
		p.Shields = append(p.Shields, ShieldConflict)
	}
	if r.UnpushedCommits > 0 {
		p.Shields = append(p.Shields, ShieldUnpushed)
	}
	if r.DirtyWorktree {
		p.Shields = append(p.Shields, ShieldDirty)
	}

	// ---- merged worktree (§11.5B) --------------------------------------
	// Merged upstream + clean tree → the native, Git-pointer-safe
	// removal route. Dirty or unmerged linked worktrees are shielded
	// from this recommendation and fall through to the age buckets.
	if r.IsWorktree && r.MergedUpstream && !r.DirtyWorktree {
		p.Category = CategoryMergedWorktree
		p.Recommendation = Recommendation{
			Kind:    "worktree-remove",
			Command: []string{"git", "worktree", "remove", p.Root},
			Reason:  "linked worktree whose HEAD is merged upstream with a clean tree",
		}
		appendShieldReasons(p)
		return
	}

	// ---- age buckets ----------------------------------------------------
	if p.LastActivityAt.IsZero() {
		p.Category = CategoryUnknown
		p.Recommendation = Recommendation{
			Reason: "age evidence unavailable (no git activity date, no usable mtime); not guessed into a recommendation",
		}
		return
	}
	age := now.Sub(p.LastActivityAt)
	switch {
	case age <= t.activeWindow:
		if p.FootprintBytes > t.bloatedBytes {
			p.Category = CategoryBloatedActive
			p.Recommendation = Recommendation{
				Kind:    "reclaim",
				Command: []string{"ebb", "reclaim", p.Root},
				Reason:  "active project whose estimated regenerable footprint exceeds the bloated threshold; reclaim trims it without parking",
			}
		} else {
			p.Category = CategoryActive
		}
	case age < t.staleAfter:
		// Between ActiveWindow and StaleAfter: honest non-actionable gap.
		p.Category = CategoryQuiet
	case age <= t.abandonedAfter:
		p.Category = CategoryStale
		p.Recommendation = Recommendation{
			Kind:    "reclaim",
			Command: []string{"ebb", "reclaim", p.Root},
			Reason:  fmt.Sprintf("untouched for %d days (stale)", int(age.Hours()/24)),
		}
	default:
		p.Category = CategoryAbandoned
		p.Recommendation = Recommendation{
			Kind:    "park",
			Command: []string{"ebb", "park", p.Root},
			Reason: fmt.Sprintf("untouched for %d days (abandoned); parking captures and verifies, then removes the workspace",
				int(age.Hours()/24)),
		}
	}

	// Unpushed work overrides the deletion-class advice: park or push,
	// NEVER a removal recommendation (§11.5B).
	if r.UnpushedCommits > 0 {
		p.Recommendation = Recommendation{
			Kind:    "push-or-park",
			Command: []string{"ebb", "park", p.Root},
			Reason: fmt.Sprintf("%d unpushed commit(s): park them into the vault or push to the remote; analyse never recommends deleting unpushed work",
				r.UnpushedCommits),
		}
	}
	appendShieldReasons(p)
}

// appendShieldReasons records the batch-skip consequences of active
// shields on the recommendation text.
func appendShieldReasons(p *Project) {
	if len(p.Shields) == 0 {
		return
	}
	skip := "shielded " + joinLabels(p.Shields) + ": skipped in batch operations"
	if p.Recommendation.Kind == "" {
		p.Recommendation.Reason = skip
		return
	}
	p.Recommendation.Reason += "; " + skip
}

// joinLabels joins shield labels with ", ".
func joinLabels(labels []string) string {
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += ", "
		}
		out += l
	}
	return out
}

// ReclaimCandidate reports whether --reclaim-stale may act on the
// project (stale, unshielded, facts present).
func (p Project) ReclaimCandidate() bool {
	return !p.Offline && p.Category == CategoryStale && !p.Shielded()
}

// PruneCandidate reports whether --prune-worktrees may act on the
// project (merged + clean + unshielded linked worktree).
func (p Project) PruneCandidate() bool {
	return !p.Offline && p.Category == CategoryMergedWorktree && !p.Shielded()
}
