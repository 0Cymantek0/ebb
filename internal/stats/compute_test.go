package stats

import (
	"testing"
	"time"

	"ebb/internal/catalog"
)

// GiB is the test byte unit.
const GiB = int64(1) << 30

// tsAt builds an RFC3339 UTC timestamp for a clock position.
func tsAt(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// TestComputeEmptyWorld: a virgin install has no events and no
// workspaces — every derived number is its zero value, the streak is 0,
// TrackingSince is "" and the top-commands slice is empty-but-not-null.
func TestComputeEmptyWorld(t *testing.T) {
	m := Compute(nil, nil, ScanFacts{})
	if m.LifetimeReclaimedBytes != 0 || m.LifetimeRestoredBytes != 0 ||
		m.CurrentlyParkedBytes != 0 || m.TotalInvocations != 0 {
		t.Errorf("empty world carries numbers: %+v", m)
	}
	if m.TrackingSince != "" {
		t.Errorf("TrackingSince = %q, want empty", m.TrackingSince)
	}
	if m.TopCommands == nil || len(m.TopCommands) != 0 {
		t.Errorf("TopCommands = %#v, want empty non-nil", m.TopCommands)
	}
	if m.HoardingScore.Grade != "" {
		t.Errorf("no scan facts must yield an unknown grade, got %+v", m.HoardingScore)
	}
}

// TestComputeLifetimeSumsAndZombies: bytes_in/out sums, the stale-only
// zombie sum, and the SSD-wear proxy (equal to restored bytes).
func TestComputeLifetimeSumsAndZombies(t *testing.T) {
	events := []catalog.StatEvent{
		{TS: "2026-01-01T10:00:00Z", Command: "park", BytesOut: 100},
		{TS: "2026-01-02T10:00:00Z", Command: "reclaim", BytesOut: 40, Detail: `{"stale":true}`},
		{TS: "2026-01-03T10:00:00Z", Command: "open", BytesIn: 60},
		{TS: "2026-01-04T10:00:00Z", Command: "reclaim", BytesOut: 10, Detail: `{"stale":false}`},
		{TS: "2026-01-05T10:00:00Z", Command: "reclaim", BytesOut: 5, Detail: `not json`},
		{TS: "2026-01-06T10:00:00Z", Command: "reclaim", BytesOut: 0, Detail: `{"stale":true}`}, // zero bytes: no zombie credit
	}
	m := Compute(events, nil, ScanFacts{})
	if m.LifetimeReclaimedBytes != 155 {
		t.Errorf("reclaimed = %d, want 155", m.LifetimeReclaimedBytes)
	}
	if m.LifetimeRestoredBytes != 60 {
		t.Errorf("restored = %d, want 60", m.LifetimeRestoredBytes)
	}
	if m.ZombieBytesExorcised != 40 {
		t.Errorf("zombie = %d, want exactly the stale 40", m.ZombieBytesExorcised)
	}
	if m.EstimatedSSDWearSaved != 60 {
		t.Errorf("ssd wear = %d, want 60 (restored proxy)", m.EstimatedSSDWearSaved)
	}
	if m.TrackingSince != "2026-01-01T10:00:00Z" {
		t.Errorf("tracking since = %q", m.TrackingSince)
	}
}

// TestComputeEfficiencyRatio: reclaimed/max(1, restored) — including the
// no-restores edge (divide by the max(1,…) floor, not by zero).
func TestComputeEfficiencyRatio(t *testing.T) {
	m := Compute([]catalog.StatEvent{
		{TS: "2026-01-01T00:00:00Z", Command: "reclaim", BytesOut: 37},
		{TS: "2026-01-02T00:00:00Z", Command: "open", BytesIn: 10},
	}, nil, ScanFacts{})
	if m.SpaceEfficiencyRatio < 3.699 || m.SpaceEfficiencyRatio > 3.701 {
		t.Errorf("ratio = %v, want 3.7", m.SpaceEfficiencyRatio)
	}
	m = Compute([]catalog.StatEvent{
		{TS: "2026-01-01T00:00:00Z", Command: "reclaim", BytesOut: 9},
	}, nil, ScanFacts{})
	if m.SpaceEfficiencyRatio != 9 {
		t.Errorf("no-restores ratio = %v, want 9 (floor divisor 1)", m.SpaceEfficiencyRatio)
	}
}

// TestComputeWorkspaceStatuses: live/parked counts, parked byte sum and
// the UNBOUND exclusion.
func TestComputeWorkspaceStatuses(t *testing.T) {
	ws := []catalog.WorkspaceSummary{
		{Name: "a", Status: catalog.WorkspaceLive, Size: 500},
		{Name: "b", Status: catalog.WorkspaceParked, Size: 200},
		{Name: "c", Status: catalog.WorkspaceParked, Size: 0}, // pre-Wave-3 park: size unknown
		{Name: "d", Status: catalog.WorkspaceUnbound, Size: 999},
	}
	m := Compute(nil, ws, ScanFacts{})
	if m.ActiveWorkspaces != 1 || m.ParkedWorkspaces != 2 {
		t.Errorf("counts = %d/%d, want 1/2 (UNBOUND in neither)", m.ActiveWorkspaces, m.ParkedWorkspaces)
	}
	if m.CurrentlyParkedBytes != 200 {
		t.Errorf("parked bytes = %d, want 200 (unknown sizes contribute 0)", m.CurrentlyParkedBytes)
	}
}

// TestComputeTopCommands: top five by count, ties broken
// alphabetically, invocations counted once per event.
func TestComputeTopCommands(t *testing.T) {
	var events []catalog.StatEvent
	add := func(cmd string, n int) {
		for i := 0; i < n; i++ {
			events = append(events, catalog.StatEvent{TS: "2026-01-01T00:00:00Z", Command: cmd})
		}
	}
	add("stats", 9)
	add("park", 7)
	add("analyse", 7) // tie with park → alphabetical: analyse before park
	add("open", 3)
	add("trim", 2)
	add("verify", 2) // tie with trim → trim before verify
	add("gc", 1)     // 6th distinct verb: cut by the top-5 cap
	m := Compute(events, nil, ScanFacts{})
	if m.TotalInvocations != int64(len(events)) {
		t.Errorf("invocations = %d, want %d", m.TotalInvocations, len(events))
	}
	want := []string{"stats", "analyse", "park", "open", "trim"}
	if len(m.TopCommands) != 5 {
		t.Fatalf("top commands = %#v", m.TopCommands)
	}
	for i, w := range want {
		if m.TopCommands[i].Command != w {
			t.Errorf("top[%d] = %s, want %s (%#v)", i, m.TopCommands[i].Command, w, m.TopCommands)
		}
	}
	if m.TopCommands[0].Count != 9 || m.TopCommands[1].Count != 7 || m.TopCommands[2].Count != 7 {
		t.Errorf("counts wrong: %#v", m.TopCommands)
	}
}

// TestComputeStreakDayBoundaries: a streak ending today; a streak
// surviving on yesterday; a gap; and the stale-clutter reset.
func TestComputeStreakDayBoundaries(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) // a Monday
	d := func(daysBack int) string {
		return tsAt(now.AddDate(0, 0, -daysBack))
	}
	scan := ScanFacts{Available: true, StaleArtifactCount: 0}

	events := []catalog.StatEvent{
		{TS: d(0), Command: "stats"},
		{TS: d(1), Command: "stats"},
		{TS: d(1), Command: "park"},
		{TS: d(2), Command: "open"},
	}
	if got := ComputeAt(events, nil, scan, now).CleanDeskStreakDays; got != 3 {
		t.Errorf("today-anchored streak = %d, want 3", got)
	}

	// Yesterday's last use still counts at breakfast (survives until
	// tomorrow); the two-day gap before it still ends the streak at 2.
	events = []catalog.StatEvent{{TS: d(1), Command: "stats"}, {TS: d(2), Command: "stats"}, {TS: d(4), Command: "stats"}}
	if got := ComputeAt(events, nil, scan, now).CleanDeskStreakDays; got != 2 {
		t.Errorf("yesterday-anchored streak = %d, want 2", got)
	}

	// Neither today nor yesterday: no streak.
	events = []catalog.StatEvent{{TS: d(3), Command: "stats"}}
	if got := ComputeAt(events, nil, scan, now).CleanDeskStreakDays; got != 0 {
		t.Errorf("stale streak = %d, want 0", got)
	}

	// Clutter found by the scan resets the streak even with daily use.
	events = []catalog.StatEvent{{TS: d(0), Command: "stats"}}
	clutter := ScanFacts{Available: true, StaleArtifactCount: 3}
	if got := ComputeAt(events, nil, clutter, now).CleanDeskStreakDays; got != 0 {
		t.Errorf("cluttered streak = %d, want 0", got)
	}

	// Unparsable timestamps never fabricate day evidence.
	events = []catalog.StatEvent{{TS: "yesterday-ish", Command: "stats"}}
	if got := ComputeAt(events, nil, scan, now).CleanDeskStreakDays; got != 0 {
		t.Errorf("unparsable-ts streak = %d, want 0", got)
	}
}

// TestComputeStreakWithoutScanFacts: the usage-day streak is returned
// even when clutter was never scanned (the renderer marks it).
func TestComputeStreakWithoutScanFacts(t *testing.T) {
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	events := []catalog.StatEvent{
		{TS: tsAt(now), Command: "stats"},
		{TS: tsAt(now.AddDate(0, 0, -1)), Command: "stats"},
	}
	if got := ComputeAt(events, nil, ScanFacts{}, now).CleanDeskStreakDays; got != 2 {
		t.Errorf("unscanned streak = %d, want 2", got)
	}
}

// TestHoardingScoreRubric walks the byte bands (boundaries are the
// exclusive upper edges) and the 180-day downgrade with its F floor.
func TestHoardingScoreRubric(t *testing.T) {
	tests := []struct {
		name    string
		bytes   int64
		ageDays int
		want    string
	}{
		{"zero bytes is Minimalist", 0, 0, "A+"},
		{"one byte under 2GiB is Tidy", 1, 0, "A"},
		{"just under 2GiB is Tidy", 2*GiB - 1, 0, "A"},
		{"2GiB sharp is Balanced", 2 * GiB, 0, "B"},
		{"just under 10GiB is Balanced", 10*GiB - 1, 0, "B"},
		{"10GiB sharp is Collector", 10 * GiB, 0, "C"},
		{"just under 30GiB is Collector", 30*GiB - 1, 0, "C"},
		{"30GiB sharp is Pack Rat", 30 * GiB, 0, "D"},
		{"just under 75GiB is Pack Rat", 75*GiB - 1, 0, "D"},
		{"75GiB sharp is Hoarder", 75 * GiB, 0, "F"},
		{"vast is Hoarder", 400 * GiB, 0, "F"},
		{"old clutter downgrades one step", 3 * GiB, 180, "C"},
		{"old clutter downgrades A+", 0, 365, "A"},
		{"downgrade floors at F", 80 * GiB, 900, "F"},
		{"179 days does not downgrade", 3 * GiB, 179, "B"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hoardingScore(ScanFacts{Available: true, StaleReclaimableBytes: tt.bytes, WorstStaleAgeDays: tt.ageDays})
			if got.Grade != tt.want {
				t.Errorf("grade = %s (%s), want %s", got.Grade, got.Label, tt.want)
			}
			if hoardingLabels[got.Grade] != got.Label {
				t.Errorf("label %q does not match grade %s", got.Label, got.Grade)
			}
		})
	}
}

// TestHoardingScoreUnknownWithoutScan: the honest unknown with the fix.
func TestHoardingScoreUnknownWithoutScan(t *testing.T) {
	s := hoardingScore(ScanFacts{})
	if s.Grade != "" {
		t.Errorf("grade = %q, want empty", s.Grade)
	}
	if s.Label != "unknown — configure projects_dir via `ebb config set projects_dir`" {
		t.Errorf("label = %q", s.Label)
	}
}

// TestComputeScanAvailabilityFlag: the additive field mirrors the input.
func TestComputeScanAvailabilityFlag(t *testing.T) {
	if !Compute(nil, nil, ScanFacts{Available: true}).ScanAvailable {
		t.Error("ScanAvailable lost")
	}
	if Compute(nil, nil, ScanFacts{}).ScanAvailable {
		t.Error("ScanAvailable fabricated")
	}
}
