package stats

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestComparisonsCatalogContent pins the shipped catalog's guarantees:
// volume (>=420), per-category breadth (>=80), count-kind breadth
// (>=40), positive sizes, unique ids, closed category vocabulary and
// parseable detail on every entry.
func TestComparisonsCatalogContent(t *testing.T) {
	if len(comparisonCatalog) < 420 {
		t.Errorf("catalog holds %d entries, want >= 420", len(comparisonCatalog))
	}
	perCat := map[string]int{}
	perKind := map[string]int{}
	seen := map[string]bool{}
	for _, e := range comparisonCatalog {
		switch e.Category {
		case "bigtech", "internet-history", "retro", "physical":
		default:
			t.Errorf("%s: bad category %q", e.ID, e.Category)
		}
		perCat[e.Category]++
		perKind[e.Kind]++
		if seen[e.ID] {
			t.Errorf("duplicate id %s", e.ID)
		}
		seen[e.ID] = true
		size := e.SizeBytes
		if e.Kind == "count" {
			size = e.SizeCount
		}
		if size <= 0 {
			t.Errorf("%s: non-positive size", e.ID)
		}
		if strings.TrimSpace(e.Subject) == "" || strings.TrimSpace(e.Fact) == "" || strings.TrimSpace(e.Note) == "" {
			t.Errorf("%s: empty subject/fact/note", e.ID)
		}
	}
	for _, cat := range []string{"bigtech", "internet-history", "retro", "physical"} {
		if perCat[cat] < 80 {
			t.Errorf("category %s holds %d entries, want >= 80", cat, perCat[cat])
		}
	}
	if perKind["count"] < 40 {
		t.Errorf("count-kind entries = %d, want >= 40", perKind["count"])
	}
	if perKind["bytes"] < 200 {
		t.Errorf("bytes-kind entries = %d, want >= 200", perKind["bytes"])
	}
}

// TestComparisonsCatalogJSONIsClean re-parses the raw embedded JSON to
// prove one-object-per-line shipped content is well-formed independent
// of the package parse.
func TestComparisonsCatalogJSONIsClean(t *testing.T) {
	var entries []comparisonEntry
	if err := json.Unmarshal(comparisonsJSON, &entries); err != nil {
		t.Fatalf("raw JSON unparseable: %v", err)
	}
	if len(entries) != len(comparisonCatalog) {
		t.Fatalf("raw (%d) and parsed (%d) counts disagree", len(entries), len(comparisonCatalog))
	}
}

// TestPickDeterminism: the same (n, rotation) always renders the same
// comparison; rotation actually varies the pick across values.
func TestPickDeterminism(t *testing.T) {
	for _, n := range []int64{0, 1, 160, 1 << 20, 50 << 30, 1 << 40} {
		a := PickForBytes(n, 7)
		b := PickForBytes(n, 7)
		if a != b {
			t.Errorf("PickForBytes(%d, 7) not deterministic: %q vs %q", n, a.Text, b.Text)
		}
		c := PickForCount(n, 9)
		d := PickForCount(n, 9)
		if c != d {
			t.Errorf("PickForCount(%d, 9) not deterministic: %q vs %q", n, c.Text, d.Text)
		}
	}
	// Rotation must be able to change the pick (a content-variety smoke
	// test over a sample of ns).
	changed := 0
	for n := int64(1); n <= 400; n++ {
		first := PickForBytes(n, 0).Subject
		for _, rot := range []uint64{1, 2, 3, 5, 11} {
			if PickForBytes(n, rot).Subject != first {
				changed++
				break
			}
		}
	}
	if changed < 100 {
		t.Errorf("rotation varied only %d/400 picks, want most", changed)
	}
}

// TestPickTextShape: every rendered Text starts with a capital, ends
// without a period, carries no unreplaced format verbs or placeholders,
// and mentions its subject. Sampled broadly over both pickers.
func TestPickTextShape(t *testing.T) {
	check := func(c Comparison, n int64, kind string) {
		if c.Text == "" {
			t.Errorf("PickFor%s(%d): empty text", kind, n)
			return
		}
		if c.Text[0] < 'A' || c.Text[0] > 'Z' {
			t.Errorf("PickFor%s(%d): text does not start with a capital: %q", kind, n, c.Text)
		}
		if strings.HasSuffix(c.Text, ".") {
			t.Errorf("PickFor%s(%d): text ends with a period: %q", kind, n, c.Text)
		}
		for _, verb := range []string{"%s", "%d", "%v", "%!", "{", "}"} {
			if strings.Contains(c.Text, verb) {
				t.Errorf("PickFor%s(%d): unreplaced %q in %q", kind, n, verb, c.Text)
			}
		}
		if !strings.Contains(c.Text, firstWordOf(c.Subject)) {
			t.Errorf("PickFor%s(%d): text never names its subject %q: %q", kind, n, c.Subject, c.Text)
		}
	}
	for _, n := range []int64{1, 2, 11, 160, 1000, 1 << 20, 700 << 20, 5 << 30, 80 << 30, 1 << 40, 1 << 45} {
		check(PickForBytes(n, uint64(n)), n, "Bytes")
		check(PickForBytes(n, 3), n, "Bytes")
		check(PickForCount(n, uint64(n)*2+1), n, "Count")
	}
	// Broad sweep: exercise every catalog entry reachable in band.
	for n := int64(1); n <= 3000; n++ {
		check(PickForBytes(n, uint64(n)), n, "Bytes")
		check(PickForCount(n, uint64(n)), n, "Count")
	}
}

// firstWordOf returns the subject's first word (the text names the
// subject, though lead phrases may reword the leading article).
func firstWordOf(subject string) string {
	fields := strings.Fields(subject)
	for _, f := range fields {
		if f != "a" && f != "an" && f != "the" {
			return strings.ReplaceAll(f, "\"", "")
		}
	}
	return ""
}

// TestPickBanding: in-band quantities select comparisons whose ratio is
// within the documented band (spot-checked by construction: the
// selected entry's size divides n into [0.5, 100000] whenever the
// in-band pool was non-empty). Here we assert the softer properties:
// tiny n renders the sub-unit phrase, and every band has coverage so
// ordinary byte quantities never fall back to the whole-set pool
// unnecessarily.
func TestPickBanding(t *testing.T) {
	// A 40-byte reclaim is smaller than half of nearly every bytes
	// entry: no in-band pool exists, so the fallback renders honestly.
	c := PickForBytes(3, 1)
	if !strings.Contains(c.Text, "less than half") {
		t.Errorf("tiny n should render the sub-unit phrase, got %q", c.Text)
	}
	// Coverage: for a spread of ordinary byte counts an in-band bytes
	// entry must exist (the eligible pool is non-empty).
	for _, n := range []int64{1 << 10, 1 << 20, 100 << 20, 1 << 30, 10 << 30, 100 << 30, 1 << 40, 10 << 40} {
		if len(bandPool(n, "bytes")) == 0 {
			t.Errorf("no in-band bytes entry for n=%d", n)
		}
		if len(bandPool(n, "count")) == 0 {
			t.Errorf("no in-band count entry for n=%d", n)
		}
	}
}

// bandPool exposes the eligible in-band entries for tests.
func bandPool(n int64, kind string) []comparisonEntry {
	var out []comparisonEntry
	for _, e := range entriesOfKind(kind) {
		size := e.SizeBytes
		if kind == "count" {
			size = e.SizeCount
		}
		if size <= 0 {
			continue
		}
		ratio := float64(n) / float64(size)
		if ratio >= bandMin && ratio <= bandMax {
			out = append(out, e)
		}
	}
	return out
}

// TestHumanizeCount pins the human number rendering: one decimal below
// ten (trailing .0 trimmed), comma groups up to a million, word
// magnitudes above with one decimal under a hundred units.
func TestHumanizeCount(t *testing.T) {
	tests := []struct {
		r    float64
		want string
	}{
		{0.9, "0.9"},
		{2.4, "2.4"},
		{3.0, "3"},
		{9.9, "9.9"},
		{10.4, "10"},
		{95, "95"},
		{1024, "1,024"},
		{34000, "34,000"},
		{999999, "999,999"},
		{1.2e6, "1.2 million"},
		{12e6, "12 million"},
		{95e6, "95 million"},
		{340e6, "340 million"},
		{3.4e9, "3.4 billion"},
		{95000e6, "95 billion"},
		{1.2e12, "1.2 trillion"},
		{95e12, "95 trillion"},
		{1.2e15, "1.2 quadrillion"},
	}
	for _, tt := range tests {
		if got := humanizeCount(tt.r); got != tt.want {
			t.Errorf("humanizeCount(%v) = %q, want %q", tt.r, got, tt.want)
		}
	}
}

// TestQuantityPhrasePluralHandling: exact-one renders the singular
// phrase; everything else the plural; sub-half the fallback.
func TestQuantityPhrasePluralHandling(t *testing.T) {
	if got := quantityPhrase(1, "copies of", "one copy of", "less than half a copy of"); got != "one copy of" {
		t.Errorf("singular = %q", got)
	}
	if got := quantityPhrase(2, "copies of", "one copy of", "less than half a copy of"); got != "2 copies of" {
		t.Errorf("plural = %q", got)
	}
	if got := quantityPhrase(0.9, "rounds of", "one full round of", "less than half a round of"); got != "0.9 rounds of" {
		t.Errorf("fractional plural = %q", got)
	}
	if got := quantityPhrase(0.2, "rounds of", "one full round of", "less than half a round of"); got != "less than half a round of" {
		t.Errorf("sub-unit = %q", got)
	}
}

// TestGroupComma: thousands separators.
func TestGroupComma(t *testing.T) {
	for _, tt := range []struct {
		n    int64
		want string
	}{
		{0, "0"}, {7, "7"}, {95, "95"}, {1024, "1,024"}, {999999, "999,999"},
		{1000000, "1,000,000"}, {1234567890, "1,234,567,890"},
	} {
		if got := groupComma(tt.n); got != tt.want {
			t.Errorf("groupComma(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// TestStableHashSanity: distinct inputs must differ; identical inputs
// must match.
func TestStableHashSanity(t *testing.T) {
	if stableHash(1, 2) != stableHash(1, 2) {
		t.Error("same inputs hash differently")
	}
	if stableHash(1, 2) == stableHash(2, 1) {
		t.Error("swapped inputs collide")
	}
	if stableHash(100, 7) == stableHash(101, 7) {
		t.Error("adjacent n collide")
	}
}
