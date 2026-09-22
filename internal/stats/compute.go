// compute.go derives Metrics from plain inputs. Everything here is pure
// and order-independent (the event order ListStatEvents returns is
// irrelevant): sums are commutative, the streak builds a date set, and
// ties in TopCommands break alphabetically so the result is stable.

package stats

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
)

// Compute derives the dashboard metrics at the current wall clock. Use
// ComputeAt for tests and any caller that needs a pinned "now".
func Compute(events []catalog.StatEvent, ws []catalog.WorkspaceSummary, scan ScanFacts) Metrics {
	return ComputeAt(events, ws, scan, time.Now())
}

// ComputeAt is Compute with an injected clock (day-boundary tests).
//
// Formulas (each mirrors the field documentation in stats.go):
//
//   - LifetimeReclaimedBytes   = Σ bytes_out over all events.
//   - LifetimeRestoredBytes    = Σ bytes_in over all events.
//   - ZombieBytesExorcised     = Σ bytes_out over events whose detail
//     object carries "stale": true (analyse batch reclaims).
//   - EstimatedSSDWearSaved    = LifetimeRestoredBytes (documented
//     simple proxy for avoided flash writes).
//   - CurrentlyParkedBytes     = Σ Size over parked workspace summaries.
//   - ActiveWorkspaces/Parked  = status counts over the summaries
//     (UNBOUND contributes to neither).
//   - SpaceEfficiencyRatio     = reclaimed / max(1, restored).
//   - TopCommands              = top 5 verbs by count, ties alphabetical.
//   - TotalInvocations         = len(events).
//   - TrackingSince            = oldest event TS ("" when none).
func ComputeAt(events []catalog.StatEvent, ws []catalog.WorkspaceSummary, scan ScanFacts, now time.Time) Metrics {
	var m Metrics
	m.ScanAvailable = scan.Available

	for _, e := range events {
		m.LifetimeReclaimedBytes += e.BytesOut
		m.LifetimeRestoredBytes += e.BytesIn
		if e.BytesOut > 0 && detailStale(e.Detail) {
			m.ZombieBytesExorcised += e.BytesOut
		}
	}
	m.EstimatedSSDWearSaved = m.LifetimeRestoredBytes

	for _, w := range ws {
		switch w.Status {
		case catalog.WorkspaceLive:
			m.ActiveWorkspaces++
		case catalog.WorkspaceParked:
			m.ParkedWorkspaces++
			m.CurrentlyParkedBytes += w.Size
		}
	}

	m.SpaceEfficiencyRatio = float64(m.LifetimeReclaimedBytes) / float64(max64(1, m.LifetimeRestoredBytes))
	m.TopCommands = topCommands(events, 5)
	m.TotalInvocations = int64(len(events))
	m.TrackingSince = oldestTS(events)

	m.CleanDeskStreakDays = cleanDeskStreak(events, scan, now)
	m.HoardingScore = hoardingScore(scan)
	return m
}

// detailStale reports whether a compact detail JSON object carries
// "stale": true. Unparsable or non-stale details are simply not stale.
func detailStale(detail string) bool {
	if detail == "" {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(detail), &obj); err != nil {
		return false
	}
	stale, _ := obj["stale"].(bool)
	return stale
}

// topCommands groups events by verb, sorts by count descending with
// alphabetical tiebreaks, and returns at most limit entries. The result
// is never nil (JSON arrays must not be null).
func topCommands(events []catalog.StatEvent, limit int) []CommandCount {
	counts := map[string]int64{}
	for _, e := range events {
		counts[e.Command]++
	}
	out := make([]CommandCount, 0, len(counts))
	for cmd, n := range counts {
		out = append(out, CommandCount{Command: cmd, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Command < out[j].Command
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// oldestTS returns the lexicographically smallest event timestamp. The
// journal stores RFC3339 UTC, so string order equals time order within
// the set (and a tie only means the same instant).
func oldestTS(events []catalog.StatEvent) string {
	oldest := ""
	for _, e := range events {
		if e.TS == "" {
			continue
		}
		if oldest == "" || e.TS < oldest {
			oldest = e.TS
		}
	}
	return oldest
}

// cleanDeskStreak counts consecutive UTC days, ending today or yesterday
// (a streak survives until tomorrow — yesterday's last use is still an
// unbroken desk at breakfast), with ≥1 stats event. Rules:
//
//   - stale clutter found by the scan breaks the streak outright (0):
//     a clean desk means clean, not merely unused;
//   - without scan facts the usage-day streak is returned anyway; the
//     renderer marks it (clutter was not scanned);
//   - events with unparsable timestamps count as invocations but carry
//     no day evidence.
func cleanDeskStreak(events []catalog.StatEvent, scan ScanFacts, now time.Time) int {
	if scan.Available && scan.StaleArtifactCount > 0 {
		return 0
	}
	days := make(map[string]bool, len(events))
	for _, e := range events {
		if e.TS == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, e.TS)
		if err != nil {
			continue
		}
		days[t.UTC().Format(dateKey)] = true
	}
	day := now.UTC()
	today := day.Format(dateKey)
	if !days[today] {
		day = day.AddDate(0, 0, -1) // a streak survives until tomorrow
	}
	streak := 0
	for days[day.Format(dateKey)] {
		streak++
		day = day.AddDate(0, 0, -1)
	}
	return streak
}

// dateKey is the day bucket format (UTC).
const dateKey = "2006-01-02"

// hoardingGradeOrder is the rubric ladder; downgrades move rightward,
// floored at the last entry.
var hoardingGradeOrder = [...]string{"A+", "A", "B", "C", "D", "F"}

// hoardingLabels maps each grade to its label.
var hoardingLabels = map[string]string{
	"A+": "Minimalist", "A": "Tidy", "B": "Balanced",
	"C": "Collector", "D": "Pack Rat", "F": "Hoarder",
}

// hoardingRubric thresholds (bytes of stale reclaimable footprint):
// 0 → A+, <2 GiB → A, <10 GiB → B, <30 GiB → C, <75 GiB → D, else F.
const (
	hoardTidy      = int64(2) << 30
	hoardBalanced  = int64(10) << 30
	hoardCollector = int64(30) << 30
	hoardPackRat   = int64(75) << 30
)

// hoardingAgeDowngradeDays: a stale artifact untouched for ≥180 days
// downgrades the verdict one step (floored at F) — old clutter weighs
// more than fresh clutter.
const hoardingAgeDowngradeDays = 180

// hoardingScore applies the stale-clutter rubric. Without scan facts the
// grade is "" and the label is the honest unknown with the fix.
func hoardingScore(scan ScanFacts) Score {
	if !scan.Available {
		return Score{Grade: "", Label: "unknown — configure projects_dir via `ebb config set projects_dir`"}
	}
	grade := 0 // index into hoardingGradeOrder
	switch n := scan.StaleReclaimableBytes; {
	case n <= 0:
		grade = 0
	case n < hoardTidy:
		grade = 1
	case n < hoardBalanced:
		grade = 2
	case n < hoardCollector:
		grade = 3
	case n < hoardPackRat:
		grade = 4
	default:
		grade = 5
	}
	if scan.WorstStaleAgeDays >= hoardingAgeDowngradeDays && grade < len(hoardingGradeOrder)-1 {
		grade++
	}
	return Score{Grade: hoardingGradeOrder[grade], Label: hoardingLabels[hoardingGradeOrder[grade]]}
}

// max64 is the integer max (Go's builtin max handles this since 1.21,
// but an explicit helper keeps the formula readable at a glance).
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
