// render.go draws the `ebb stats` terminal dashboard: a plain UTF-8 box
// (~76 columns) that renders correctly in any terminal or pipe — no ANSI
// escapes, no cursor movement, no color. Unknown metrics render as "—",
// never as fake zeros; every wide line is word-wrapped inside the box.
//
// webAvailable/shareAvailable exist for the later --web/--share wiring
// (this wave always passes false); the footer hints only appear for the
// capabilities the invoking build actually has.

package stats

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// dashboardInner is the box's interior width in cells (plus the two
// border runes = 76 total).
const dashboardInner = 74

// RenderDashboard renders the full dashboard. cmps carries the two
// comparison sentences (bytes then count; zero Comparisons are skipped).
func RenderDashboard(m Metrics, cmps [2]Comparison, webAvailable, shareAvailable bool) string {
	var b strings.Builder
	row := func(format string, a ...any) {
		text := fmt.Sprintf(format, a...)
		// Pad to the exact inner width; count cells, not bytes (the box
		// must stay rectangular under CJK-wide runes as far as Go can
		// tell via utf8.RuneCountInString).
		pad := dashboardInner - utf8.RuneCountInString(text)
		if pad < 0 {
			pad = 0
		}
		fmt.Fprintf(&b, "│ %s%s │\n", text, strings.Repeat(" ", pad))
	}
	sep := "├" + strings.Repeat("─", dashboardInner+2) + "┤\n"
	top := "┌" + strings.Repeat("─", dashboardInner+2) + "┐\n"

	b.WriteString(top)
	row(" Ebb Developer Space Economy")
	b.WriteString(sep)

	// ---- headline pairs --------------------------------------------------
	pair := func(lLabel, lValue, rLabel, rValue string) {
		row("%-22s %-13s %-22s %s", lLabel, lValue, rLabel, rValue)
	}
	parkedBytes := HumanBytes(m.CurrentlyParkedBytes)
	if m.CurrentlyParkedBytes == 0 && m.ParkedWorkspaces > 0 {
		parkedBytes = "—" // parked workspaces exist but no park event ever recorded a size
	}
	efficiency := "—"
	if m.SpaceEfficiencyRatio > 0 {
		efficiency = fmt.Sprintf("%.1fx", m.SpaceEfficiencyRatio)
	}
	pair("Lifetime reclaimed", HumanBytes(m.LifetimeReclaimedBytes),
		"Lifetime restored", HumanBytes(m.LifetimeRestoredBytes))
	pair("Active workspaces", fmt.Sprintf("%d", m.ActiveWorkspaces),
		"Parked workspaces", fmt.Sprintf("%d", m.ParkedWorkspaces))
	pair("Space efficiency", efficiency,
		"Currently parked", parkedBytes)
	pair("Clean-desk streak", streakLabel(m),
		"Zombie bytes exorcised", HumanBytes(m.ZombieBytesExorcised))
	b.WriteString(sep)

	// ---- hoarding score (own block: the unknown label is a sentence) ----
	if m.HoardingScore.Grade == "" {
		row(" Hoarding score          %s", "—")
		for _, line := range wrapText(m.HoardingScore.Label, dashboardInner-26) {
			row("   %s", line)
		}
	} else {
		row(" Hoarding score          %s  %s", m.HoardingScore.Grade, m.HoardingScore.Label)
	}
	row(" SSD wear saved          %s", HumanBytes(m.EstimatedSSDWearSaved))
	b.WriteString(sep)

	// ---- top commands ----------------------------------------------------
	row(" Top commands")
	if len(m.TopCommands) == 0 {
		row("   (none yet)")
	}
	for _, c := range m.TopCommands {
		row("   %-14s %6d", c.Command, c.Count)
	}
	since := m.TrackingSince
	if since == "" {
		since = "—"
	}
	row(" Total ebb keystrokes    %-8d (tracking since %s)", m.TotalInvocations, since)
	b.WriteString(sep)

	// ---- comparisons -----------------------------------------------------
	for _, c := range cmps {
		if c.Text == "" {
			continue
		}
		for i, line := range wrapText(c.Text, dashboardInner-3) {
			if i == 0 {
				row(" ✦ %s", line)
			} else {
				row("   %s", line)
			}
		}
	}
	if webAvailable || shareAvailable {
		b.WriteString(sep)
		var hints []string
		if webAvailable {
			hints = append(hints, "--web    open the full web dashboard")
		}
		if shareAvailable {
			hints = append(hints, "--share  export a shareable dashboard card")
		}
		for _, h := range hints {
			row(" %s", h)
		}
	}
	b.WriteString("└" + strings.Repeat("─", dashboardInner+2) + "┘\n")
	return b.String()
}

// streakLabel renders the clean-desk streak with its honesty marks: a
// streak counted without a clutter scan is labeled as usage days only.
func streakLabel(m Metrics) string {
	if m.CleanDeskStreakDays <= 0 {
		return "0 days"
	}
	if m.CleanDeskStreakDays == 1 {
		if m.ScanAvailable {
			return "1 day"
		}
		return "1 day (usage days; clutter unscanned)"
	}
	if m.ScanAvailable {
		return fmt.Sprintf("%d days", m.CleanDeskStreakDays)
	}
	return fmt.Sprintf("%d days (usage days; clutter unscanned)", m.CleanDeskStreakDays)
}

// HumanBytes renders a byte count in binary units (B, KiB, MiB, GiB,
// TiB, PiB) with one decimal from KiB upward.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	suffixes := []string{"KiB", "MiB", "GiB", "TiB", "PiB"}
	for _, s := range suffixes {
		f /= unit
		if f < unit || s == suffixes[len(suffixes)-1] {
			return fmt.Sprintf("%.1f %s", f, s)
		}
	}
	return fmt.Sprintf("%.1f EiB", f/unit)
}

// wrapText greedily word-wraps text to width cells, never splitting a
// word, preserving single spaces (consecutive spaces collapse via the
// fields walk; terminal prose never carries runs anyway). Returns at
// least one (possibly empty) line.
func wrapText(text string, width int) []string {
	if width < 1 {
		width = 1
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if utf8.RuneCountInString(cur)+1+utf8.RuneCountInString(w) <= width {
			cur += " " + w
			continue
		}
		lines = append(lines, cur)
		cur = w
	}
	return append(lines, cur)
}
