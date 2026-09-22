package planner

import (
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// sumEntries conservatively sums the physical footprint of entries:
// allocated size where observable, logical size otherwise. The second
// return value reports whether any file's allocation was unknown.
func sumEntries(entries []domain.Entry) (int64, bool) {
	var n int64
	unknown := false
	for _, e := range entries {
		if e.AllocatedSize != nil {
			n += *e.AllocatedSize
		} else {
			n += e.LogicalSize
			if e.Kind == domain.KindFile {
				unknown = true
			}
		}
	}
	return n, unknown
}

// summaryLookup finds the exclusively-reclaimable figure the inventory
// recorded for the longest prefix of the given outputs. Keys are
// root-path prefixes; "/" and "" are tried as root-level keys.
func summaryLookup(summary domain.InventorySummary, outputs []string) (int64, bool) {
	bestLen := -1
	var best int64
	found := false
	for _, o := range outputs {
		for p := o; ; p = parentDir(p) {
			if v, ok := summary.ExclReclaimable[p]; ok && len(p) > bestLen {
				best, bestLen, found = v, len(p), true
			}
			if p == "/" || p == "" {
				break
			}
		}
	}
	return best, found
}

// parentDir returns the parent prefix of a root-relative path ("/" at
// the top).
func parentDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		if i == 0 {
			return "/"
		}
		return p[:i]
	}
	return "/"
}

// estimateGroup estimates one trim group's exclusively-reclaimable
// bytes. When both the summary figure and the member sum are known the
// SMALLER wins (conservative rounding down); unknown returns true only
// when no estimate could be derived at all.
func estimateGroup(summary domain.InventorySummary, members []domain.Entry, outputs []string) (int64, bool) {
	memberSum, _ := sumEntries(members)
	summaryVal, hasSummary := summaryLookup(summary, outputs)
	switch {
	case hasSummary && len(members) > 0:
		return min64(summaryVal, memberSum), false
	case hasSummary:
		return summaryVal, false
	case len(members) > 0:
		return memberSum, false
	default:
		return 0, true
	}
}

// estimateAll estimates the full-workspace footprint (park step). It
// cross-checks a root-level summary figure when present.
func estimateAll(summary domain.InventorySummary, entries []domain.Entry) (int64, bool) {
	if len(entries) == 0 {
		if v, ok := summary.ExclReclaimable["/"]; ok {
			return v, false
		}
		return 0, true
	}
	total, _ := sumEntries(entries)
	if v, ok := summary.ExclReclaimable["/"]; ok && v < total {
		return v, false
	}
	return total, false
}

func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
