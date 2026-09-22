// card_test.go pins the shareable card's structural contract: decodable
// 1600x900 PNG, degenerate inputs (all-zero metrics, PiB-scale values,
// pathological strings) render without panic, the comparison quote wraps
// to at most three lines, Render is byte-deterministic (no clock, no
// randomness — the footer date arrives via Input.AsOf), and WriteFile
// round-trips the bytes.

package card

import (
	"bytes"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/image/font"

	"github.com/0Cymantek0/ebb/internal/stats"
)

// decode renders and decodes, failing the test on any error.
func decode(t *testing.T, in Input) (width, height int) {
	t.Helper()
	b, err := Render(in)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("decode rendered card: %v", err)
	}
	return img.Bounds().Dx(), img.Bounds().Dy()
}

// sampleMetrics is a rich, fully-known dashboard.
func sampleMetrics() stats.Metrics {
	return stats.Metrics{
		LifetimeReclaimedBytes: 152*1<<30 + 400<<20,
		LifetimeRestoredBytes:  41 << 30,
		CurrentlyParkedBytes:   23 << 30,
		ActiveWorkspaces:       7,
		ParkedWorkspaces:       3,
		SpaceEfficiencyRatio:   3.7,
		CleanDeskStreakDays:    18,
		HoardingScore:          stats.Score{Grade: "A", Label: "Minimalist"},
		ZombieBytesExorcised:   12 << 30,
		EstimatedSSDWearSaved:  41 << 30,
		TopCommands: []stats.CommandCount{
			{Command: "reclaim", Count: 214},
			{Command: "open", Count: 96},
		},
		TotalInvocations: 2341,
		TrackingSince:    "2026-01-02T10:00:00Z",
		ScanAvailable:    true,
	}
}

func sampleComparison() stats.Comparison {
	return stats.Comparison{
		Category: "retro",
		Subject:  "3.5-inch floppy disks",
		Text:     "That is 112 copies of 3.5-inch floppy disks",
	}
}

func TestRenderDecodesPNG1600x900(t *testing.T) {
	w, h := decode(t, Input{Metrics: sampleMetrics(), Comparison: sampleComparison(), AsOf: "2026-09-21"})
	if w != cardWidth || h != cardHeight {
		t.Fatalf("card is %dx%d, want %dx%d", w, h, cardWidth, cardHeight)
	}
}

// TestRenderZeroMetricsEmptyStates: the all-unknown dashboard renders
// without panic and its empty states are visibly drawn — the donut
// center carries the "no data yet" note (pixels at the ring's center
// differ from the pure background) and the top-command badge degrades
// to its empty text.
func TestRenderZeroMetricsEmptyStates(t *testing.T) {
	b, err := Render(Input{AsOf: "2026-09-21"})
	if err != nil {
		t.Fatalf("Render(zero metrics): %v", err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := img.Bounds(); got.Dx() != cardWidth || got.Dy() != cardHeight {
		t.Fatalf("bounds = %v", got)
	}
	// Donut center (246, 506) final-scale: with no data the empty-ring
	// note is drawn there, so some pixel on that row differs from the
	// background color.
	bgR, bgG, bgB, _ := colBackground.RGBA()
	marked := 0
	for x := 186; x <= 306; x++ {
		r, g, b, _ := img.At(x, 506).RGBA()
		if r != bgR || g != bgG || b != bgB {
			marked++
		}
	}
	if marked == 0 {
		t.Error("no empty-state text drawn at the empty donut center")
	}
	if topCommandBadge(nil) != "no commands yet" {
		t.Errorf("topCommandBadge(nil) = %q", topCommandBadge(nil))
	}
}

// TestRenderHugeValues: PiB-scale and near-MaxInt64 byte counts stay
// in-bounds (no panic, decodable, fixed dimensions).
func TestRenderHugeValues(t *testing.T) {
	m := sampleMetrics()
	m.LifetimeReclaimedBytes = math.MaxInt64 / 2
	m.LifetimeRestoredBytes = 5 << 50 // 5 PiB
	m.CurrentlyParkedBytes = math.MaxInt64
	m.ZombieBytesExorcised = math.MaxInt64 / 3
	m.EstimatedSSDWearSaved = math.MaxInt64 / 4
	m.SpaceEfficiencyRatio = math.MaxFloat64 / 1e300
	w, h := decode(t, Input{Metrics: m, Comparison: sampleComparison()})
	if w != cardWidth || h != cardHeight {
		t.Fatalf("huge-value card is %dx%d", w, h)
	}
}

// TestRenderLongComparisonWraps: a pathologically long comparison
// sentence renders (bounded wrap, no panic).
func TestRenderLongComparisonWraps(t *testing.T) {
	long := stats.Comparison{
		Category: "physical",
		Subject:  strings.Repeat("very-long-subject-", 40),
		Text:     strings.Repeat("That is a lot of "+strings.Repeat("extremely ", 8)+"large words about scale. ", 60),
	}
	w, h := decode(t, Input{Metrics: sampleMetrics(), Comparison: long})
	if w != cardWidth || h != cardHeight {
		t.Fatalf("long-comparison card is %dx%d", w, h)
	}
}

// TestRenderWeirdStrings: control characters, invalid UTF-8 and empty
// fields never panic and always produce a decodable card.
func TestRenderWeirdStrings(t *testing.T) {
	m := sampleMetrics()
	m.HoardingScore = stats.Score{Grade: "", Label: "run \x1b[31m ebb analyse"}
	m.TopCommands = []stats.CommandCount{{Command: "bad\x00cmd", Count: -5}}
	cmp := stats.Comparison{Text: "quote \x00 with \r control \n bytes", Subject: "sub\x7fject"}
	w, h := decode(t, Input{Metrics: m, Comparison: cmp})
	if w != cardWidth || h != cardHeight {
		t.Fatalf("weird-strings card is %dx%d", w, h)
	}
}

// TestRenderDeterministic: identical Input (including AsOf) → identical
// bytes; a different AsOf changes the bytes (the date is rendered, and
// nothing else in Render consults a clock).
func TestRenderDeterministic(t *testing.T) {
	in := Input{Metrics: sampleMetrics(), Comparison: sampleComparison(), AsOf: "2026-09-21"}
	a, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("Render is not byte-deterministic for the same input")
	}
	in2 := in
	in2.AsOf = "2026-09-22"
	c, err := Render(in2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Error("different AsOf rendered identical bytes (date not derived from input)")
	}
}

// TestWriteFileRoundTrip: WriteFile writes decodable PNG bytes with the
// magic header, and overwrites (same-day rerun) rather than failing.
func TestWriteFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ebb-stats-20260921.png")
	in := Input{Metrics: sampleMetrics(), Comparison: sampleComparison(), Path: path, AsOf: "2026-09-21"}
	if err := WriteFile(in); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		t.Error("written file lacks the PNG magic bytes")
	}
	if _, err := png.Decode(bytes.NewReader(b)); err != nil {
		t.Errorf("written file does not decode: %v", err)
	}
	// Same path again: overwrite is allowed.
	if err := WriteFile(in); err != nil {
		t.Errorf("same-day rerun refused to overwrite: %v", err)
	}
}

// ---- helper-level unit tests -------------------------------------------------

func TestWrapClamp(t *testing.T) {
	f := quoteFace(t)
	// A short sentence stays one line.
	got := wrapClamp(f, "That is 95 copies of Doom", 4000, 3)
	if len(got) != 1 {
		t.Errorf("short text wrapped to %d lines: %q", len(got), got)
	}
	// A long text clamps to 3 lines, the last one ellipsized.
	long := strings.Repeat("word ", 400)
	got = wrapClamp(f, long, 900, 3)
	if len(got) != 3 {
		t.Fatalf("long text wrapped to %d lines, want 3", len(got))
	}
	if !strings.HasSuffix(got[2], "...") {
		t.Errorf("clamped last line = %q, want an ellipsis suffix", got[2])
	}
	for i, ln := range got {
		if w := stringWidth(f, ln); w > 900 {
			t.Errorf("line %d width %d exceeds the 900 budget", i, w)
		}
	}
	// A single unbreakable word wider than the region is hard-truncated.
	got = wrapClamp(f, strings.Repeat("x", 500), 900, 3)
	if len(got) != 1 || stringWidth(f, got[0]) > 900 {
		t.Errorf("unbreakable word result = %q", got)
	}
	// Empty/degenerate input.
	if got := wrapClamp(f, "", 900, 3); len(got) != 1 {
		t.Errorf("empty text = %q", got)
	}
}

func TestTruncateWidth(t *testing.T) {
	f := quoteFace(t)
	if got := truncateWidth(f, "short", 4000); got != "short" {
		t.Errorf("fitting text was altered: %q", got)
	}
	got := truncateWidth(f, strings.Repeat("long", 100), 900)
	if stringWidth(f, got) > 900 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncateWidth = %q (width %d)", got, stringWidth(f, got))
	}
	if got := truncateWidth(f, "anything", 0); got != "" {
		t.Errorf("zero-width region = %q, want empty", got)
	}
}

func TestGroupComma(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{{0, "0"}, {999, "999"}, {1000, "1,000"}, {2341, "2,341"}, {-5, "0"}, {1000000, "1,000,000"}}
	for _, tt := range tests {
		if got := groupComma(tt.n); got != tt.want {
			t.Errorf("groupComma(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestUnknownValueFormatters(t *testing.T) {
	if got := efficiencyLabel(0); got != "—" {
		t.Errorf("efficiencyLabel(0) = %q, want an em dash", got)
	}
	if got := efficiencyLabel(3.74); got != "3.7x" {
		t.Errorf("efficiencyLabel(3.74) = %q", got)
	}
	if got := streakLabel(0); got != "0 days" {
		t.Errorf("streakLabel(0) = %q", got)
	}
	if got := streakLabel(1); got != "1 day" {
		t.Errorf("streakLabel(1) = %q", got)
	}
	if got := hoardingBadge(stats.Score{}); got != "—" {
		t.Errorf("hoardingBadge(unknown) = %q, want an em dash", got)
	}
	if got := hoardingBadge(stats.Score{Grade: "A+", Label: "Minimalist"}); got != "A+ · Minimalist" {
		t.Errorf("hoardingBadge(A+) = %q", got)
	}
}

// quoteFace builds one shared face for the helper tests.
func quoteFace(t *testing.T) font.Face {
	t.Helper()
	bold, reg, mono, err := goFonts()
	if err != nil {
		t.Fatalf("fonts: %v", err)
	}
	fc, err := newFaces(bold, reg, mono)
	if err != nil {
		t.Fatalf("faces: %v", err)
	}
	return fc.quote
}
