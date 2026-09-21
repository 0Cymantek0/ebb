package stats

import (
	"strings"
	"testing"
	"unicode/utf8"

	"ebb/internal/catalog"
)

// sampleMetrics is a fully-populated dashboard model.
func sampleMetrics() Metrics {
	return Compute([]catalog.StatEvent{
		{TS: "2026-08-30T10:00:00Z", Command: "park", Workspace: "old-app", BytesOut: 3<<30 + 400<<20},
		{TS: "2026-08-31T10:00:00Z", Command: "open", Workspace: "old-app", BytesIn: 400 << 20},
		{TS: "2026-09-01T10:00:00Z", Command: "trim", Workspace: "web", BytesOut: 200 << 20},
		{TS: "2026-09-02T10:00:00Z", Command: "trim", Workspace: "web", BytesOut: 20 << 20, Detail: `{"stale":true}`},
		{TS: "2026-09-03T10:00:00Z", Command: "stats"},
		{TS: "2026-09-04T10:00:00Z", Command: "stats"},
	}, []catalog.WorkspaceSummary{
		{Name: "web", Status: catalog.WorkspaceLive, Size: 0},
		{Name: "old-app", Status: catalog.WorkspaceParked, Size: 3<<30 + 400<<20},
	}, ScanFacts{Available: true, StaleReclaimableBytes: 0})
}

// TestRenderDashboardShape: title, box integrity (every line the same
// cell width, closed top and bottom), key metric rows present, both
// comparisons prefixed with the ✦ marker, no footer hints when the web
// capabilities are absent.
func TestRenderDashboardShape(t *testing.T) {
	m := sampleMetrics()
	m.CleanDeskStreakDays = 4 // pin regardless of the wall clock
	cmps := [2]Comparison{
		PickForBytes(m.LifetimeReclaimedBytes, uint64(m.TotalInvocations)),
		PickForCount(m.TotalInvocations, uint64(m.TotalInvocations)),
	}
	out := RenderDashboard(m, cmps, false, false)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 12 {
		t.Fatalf("dashboard too short (%d lines):\n%s", len(lines), out)
	}
	if lines[0] != "┌"+strings.Repeat("─", dashboardInner+2)+"┐" {
		t.Errorf("bad top border: %q", lines[0])
	}
	if last := lines[len(lines)-1]; last != "└"+strings.Repeat("─", dashboardInner+2)+"┘" {
		t.Errorf("bad bottom border: %q", last)
	}
	for i, ln := range lines {
		if got := utf8.RuneCountInString(ln); got != dashboardInner+4 {
			t.Errorf("line %d width = %d cells, want %d: %q", i, got, dashboardInner+4, ln)
		}
	}
	for _, want := range []string{
		"Ebb Developer Space Economy",
		"Lifetime reclaimed",
		"Lifetime restored",
		"Active workspaces",
		"Parked workspaces",
		"Space efficiency",
		"Currently parked",
		"Clean-desk streak",
		"Hoarding score",
		"Zombie bytes exorcised",
		"SSD wear saved",
		"Top commands",
		"Total ebb keystrokes",
		"tracking since 2026-08-30",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dashboard lacks %q:\n%s", want, out)
		}
	}
	marks := strings.Count(out, "✦")
	if marks != 2 {
		t.Errorf("comparison markers = %d, want 2\n%s", marks, out)
	}
	if strings.Contains(out, "--web") || strings.Contains(out, "--share") {
		t.Errorf("footer hints leaked without capability flags\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("ANSI escapes in plain dashboard\n%s", out)
	}
}

// TestRenderDashboardUnknowns: a virgin install (no events, no scan
// facts) renders dashes, never fabricated zeros; the footer hints
// appear exactly when their capability flags are set.
func TestRenderDashboardUnknowns(t *testing.T) {
	out := RenderDashboard(Compute(nil, nil, ScanFacts{}), [2]Comparison{}, false, false)
	if !strings.Contains(out, "Hoarding score") {
		t.Fatalf("missing score row\n%s", out)
	}
	if !strings.Contains(out, "—") {
		t.Errorf("virgin dashboard shows no em-dashes (fake zeros?)\n%s", out)
	}
	if !strings.Contains(out, "(none yet)") {
		t.Errorf("empty top commands not labeled\n%s", out)
	}
	if strings.Contains(out, "— \n") {
		t.Errorf("untrimmed dash row\n%s", out)
	}

	// Footer hints appear only with the capability flags.
	withHints := RenderDashboard(sampleMetrics(), [2]Comparison{}, true, true)
	if !strings.Contains(withHints, "--web") || !strings.Contains(withHints, "--share") {
		t.Errorf("capability hints missing\n%s", withHints)
	}
	webOnly := RenderDashboard(sampleMetrics(), [2]Comparison{}, true, false)
	if !strings.Contains(webOnly, "--web") || strings.Contains(webOnly, "--share") {
		t.Errorf("hint gating wrong\n%s", webOnly)
	}
}

// TestRenderDashboardStreakMarks: an unscanned streak is marked as
// usage days only; a scanned one is clean.
func TestRenderDashboardStreakMarks(t *testing.T) {
	base := sampleMetrics()
	base.CleanDeskStreakDays = 2

	unscanned := base
	unscanned.ScanAvailable = false
	if out := RenderDashboard(unscanned, [2]Comparison{}, false, false); !strings.Contains(out, "clutter unscanned") {
		t.Errorf("unscanned streak not marked\n%s", out)
	}
	scanned := base
	scanned.ScanAvailable = true
	if out := RenderDashboard(scanned, [2]Comparison{}, false, false); strings.Contains(out, "clutter unscanned") {
		t.Errorf("scanned streak wrongly marked\n%s", out)
	}
}

// TestRenderDashboardParkedUnknownSize: parked workspaces whose size
// was never recorded render a dash, not a fake 0 B.
func TestRenderDashboardParkedUnknownSize(t *testing.T) {
	m := Compute(nil, []catalog.WorkspaceSummary{
		{Name: "ancient", Status: catalog.WorkspaceParked, Size: 0},
	}, ScanFacts{})
	out := RenderDashboard(m, [2]Comparison{}, false, false)
	if !strings.Contains(out, "Currently parked") {
		t.Fatalf("missing parked row\n%s", out)
	}
	idx := strings.Index(out, "Currently parked")
	if !strings.Contains(out[idx:idx+70], "—") {
		t.Errorf("unknown parked size not dashed\n%s", out)
	}
}

// TestHumanBytes pins the byte rendering.
func TestHumanBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"}, {512, "512 B"}, {1023, "1023 B"},
		{1024, "1.0 KiB"}, {1536, "1.5 KiB"},
		{2202009, "2.1 MiB"}, {734003200, "700.0 MiB"},
		{1 << 30, "1.0 GiB"}, {5 << 40, "5.0 TiB"},
		{3 << 50, "3.0 PiB"},
	}
	for _, tt := range tests {
		if got := HumanBytes(tt.n); got != tt.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// TestWrapText: greedy wrapping respects the width and keeps words
// whole.
func TestWrapText(t *testing.T) {
	lines := wrapText("alpha beta gamma delta epsilon zeta", 16)
	for _, ln := range lines {
		if utf8.RuneCountInString(ln) > 16 {
			t.Errorf("line %q exceeds width", ln)
		}
	}
	if strings.Join(lines, " ") != "alpha beta gamma delta epsilon zeta" {
		t.Errorf("wrapping lost words: %v", lines)
	}
	if got := wrapText("", 10); len(got) != 1 || got[0] != "" {
		t.Errorf("empty wrap = %v", got)
	}
	if got := wrapText("onesingleverylongword", 5); len(got) != 1 {
		t.Errorf("long word split: %v", got)
	}
}
