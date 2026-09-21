// comparisons.go is the offline comparison engine of `ebb stats`: the
// "that is about 95 copies of Doom" sentences that translate raw byte
// counts into human scale.
//
// The catalog is shipped content (comparisons.json, embedded at build
// time — no network, no generation step). Selection is deterministic:
// the same (n, rotation) pair always renders the same comparison, and
// rotation exists so callers can vary the pick across runs (the CLI
// passes TotalInvocations).
//
// Factual grounding rules (hard): every catalog size is a widely
// documented public quantity, rounded conservatively; the note states
// the reference; approximate figures are marked with ≈ in the fact
// text; nothing is invented.

package stats

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

//go:embed comparisons.json
var comparisonsJSON []byte

// Comparison is one fully rendered scale sentence (frozen Wave 3 shape).
type Comparison struct {
	// Category is "bigtech" | "internet-history" | "retro" | "physical".
	Category string `json:"category"`
	// Subject names the reference object (e.g. "3.5-inch floppy disks").
	Subject string `json:"subject"`
	// Text is the fully rendered sentence: starts with a capital, ends
	// without a period, no unreplaced placeholders.
	Text string `json:"text"`
}

// comparisonEntry is one shipped catalog row.
type comparisonEntry struct {
	ID        string `json:"id"`
	Category  string `json:"category"`
	Kind      string `json:"kind"` // "bytes" | "count"
	Subject   string `json:"subject"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	SizeCount int64  `json:"size_count,omitempty"`
	Note      string `json:"note"`
	Fact      string `json:"fact"`
}

// comparisonCatalog is the parsed embedded catalog (file order).
var comparisonCatalog = mustParseComparisons()

func mustParseComparisons() []comparisonEntry {
	var entries []comparisonEntry
	if err := json.Unmarshal(comparisonsJSON, &entries); err != nil {
		panic("stats: embedded comparisons.json is invalid: " + err.Error())
	}
	return entries
}

// PickForBytes renders the deterministic comparison for a byte quantity.
func PickForBytes(n int64, rotation uint64) Comparison {
	return pick(n, rotation, "bytes")
}

// PickForCount renders the deterministic comparison for an invocation
// count (e.g. total ebb keystrokes).
func PickForCount(n int64, rotation uint64) Comparison {
	return pick(n, rotation, "count")
}

// band bounds the eligible ratio range: the comparison must plausibly
// read ("half a copy" through "a hundred thousand copies"); outside it
// the sentence degenerates into absurdity, so only in-band entries are
// eligible. When nothing is in band (tiny or enormous n) the whole kind
// set is used with sub-unit phrasing.
const (
	bandMin = 0.5
	bandMax = 100000
)

func pick(n int64, rotation uint64, kind string) Comparison {
	entries := entriesOfKind(kind)
	eligible := make([]comparisonEntry, 0, len(entries))
	if n > 0 {
		for _, e := range entries {
			size := e.SizeBytes
			if kind == "count" {
				size = e.SizeCount
			}
			if size <= 0 {
				continue
			}
			ratio := float64(n) / float64(size)
			if ratio >= bandMin && ratio <= bandMax {
				eligible = append(eligible, e)
			}
		}
	}
	pool := eligible
	if len(pool) == 0 {
		pool = entries // honest fallback: everything, sub/over-unit phrasing
	}
	h := stableHash(uint64(n), rotation)
	e := pool[h%uint64(len(pool))]
	size := e.SizeBytes
	if kind == "count" {
		size = e.SizeCount
	}
	ratio := 0.0
	if size > 0 {
		ratio = float64(n) / float64(size)
	}

	var quantity string
	if kind == "count" {
		quantity = quantityPhrase(ratio, "rounds of", "one full round of", "less than half a round of")
	} else {
		quantity = quantityPhrase(ratio, "copies of", "one copy of", "less than half a copy of")
	}
	subject := fmt.Sprintf("%s %s", quantity, e.Subject)
	leads := comparisonLeads[e.Category]
	lead := fmt.Sprintf(leads[(h>>32)%uint64(len(leads))], subject)
	// Text: capital start (the lead provides it), no trailing period —
	// the frozen contract's exact shape.
	text := strings.TrimSpace(strings.TrimRight(lead+" "+strings.TrimSpace(e.Fact), ". "))
	return Comparison{Category: e.Category, Subject: e.Subject, Text: text}
}

// quantityPhrase renders the count phrase for a ratio: the plural label
// ("95 copies of"), the exact-one singular ("one copy of") or the
// sub-unit fallback ("less than half a copy of").
func quantityPhrase(ratio float64, plural, singular, subUnit string) string {
	switch {
	case ratio < 0.5:
		return subUnit
	case ratio == 1:
		return singular
	default:
		return humanizeCount(ratio) + " " + plural
	}
}

// comparisonLeads is the per-category sentence-lead pool (each entry a
// complete lead ending before the quantity phrase; the fact follows as
// a second sentence).
var comparisonLeads = map[string][]string{
	"bigtech": {
		"That is %s.",
		"Cloud-scale translation: that is %s.",
		"Put against modern infrastructure, that is %s.",
	},
	"internet-history": {
		"That is %s.",
		"Internet-history scale: that is %s.",
		"Measured against the early web, that is %s.",
	},
	"retro": {
		"That is %s.",
		"Retro-computing scale: that is %s.",
		"Measured in vintage hardware, that is %s.",
	},
	"physical": {
		"That is %s.",
		"Real-world scale: that is %s.",
		"Made physical, that is %s.",
	},
}

// entriesOfKind filters the embedded catalog by kind in file order
// (deterministic: the JSON is fixed shipped content).
func entriesOfKind(kind string) []comparisonEntry {
	var out []comparisonEntry
	for _, e := range comparisonCatalog {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

// stableHash is FNV-1a 64 over the big-endian bytes of n and rotation:
// deterministic, cheap, good enough to vary picks across runs.
func stableHash(n, rotation uint64) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for _, v := range [2]uint64{n, rotation} {
		for i := 7; i >= 0; i-- {
			h ^= (v >> (8 * uint(i))) & 0xff
			h *= prime64
		}
	}
	return h
}

// humanizeCount renders a ratio for humans: one decimal below 10
// ("0.9", "2.4"), comma-grouped integers up to a million ("95",
// "1,024", "34,000"), then word magnitudes with one decimal below 100
// units ("3.4 million", "12 million", "95 billion").
func humanizeCount(r float64) string {
	if r < 0 || math.IsNaN(r) || math.IsInf(r, 0) {
		return "0"
	}
	switch {
	case r < 10:
		s := strconv.FormatFloat(r, 'f', 1, 64)
		return strings.TrimSuffix(s, ".0")
	case r < 1e6:
		return groupComma(int64(math.Round(r)))
	default:
		units := []struct {
			size float64
			name string
		}{{1e15, "quadrillion"}, {1e12, "trillion"}, {1e9, "billion"}, {1e6, "million"}}
		for _, u := range units {
			if r >= u.size {
				v := r / u.size
				if v < 100 {
					s := strconv.FormatFloat(v, 'f', 1, 64)
					return strings.TrimSuffix(s, ".0") + " " + u.name
				}
				return groupComma(int64(math.Round(v))) + " " + u.name
			}
		}
		return groupComma(int64(math.Round(r)))
	}
}

// groupComma renders an integer with thousands separators ("1,024").
func groupComma(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	out := strings.Join(parts, ",")
	if neg {
		return "-" + out
	}
	return out
}
