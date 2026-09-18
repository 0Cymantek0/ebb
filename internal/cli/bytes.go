package cli

import (
	"fmt"
	"strconv"
	"strings"
)

// byteUnits are the accepted --target suffixes. Binary (IEC) powers are
// used for the KiB family and decimal powers for the bare SI family,
// matching Foundation §17.2's byte-count conventions.
var byteUnits = []struct {
	suffix string
	mul    int64
}{
	{"KiB", 1 << 10},
	{"MiB", 1 << 20},
	{"GiB", 1 << 30},
	{"TiB", 1 << 40},
	{"PiB", 1 << 50},
	{"KB", 1e3},
	{"MB", 1e6},
	{"GB", 1e9},
	{"TB", 1e12},
	{"K", 1 << 10},
	{"M", 1 << 20},
	{"G", 1 << 30},
	{"T", 1 << 40},
	{"B", 1},
}

// ParseByteCount parses a byte-count argument such as "1500000",
// "25GiB" or "1.5MB". Plain integers must be whole bytes; fractional
// values are only allowed with a unit and are rounded DOWN (never
// up-claim capacity).
func ParseByteCount(s string) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, fmt.Errorf("empty byte count")
	}
	lower := strings.ToLower(t)
	for _, u := range byteUnits {
		suffix := strings.ToLower(u.suffix)
		if !strings.HasSuffix(lower, suffix) {
			continue
		}
		num := strings.TrimSpace(lower[:len(lower)-len(suffix)])
		f, err := strconv.ParseFloat(num, 64)
		if err != nil || f < 0 {
			return 0, fmt.Errorf("invalid byte count %q", s)
		}
		if f*float64(u.mul) > float64(1<<62) {
			return 0, fmt.Errorf("byte count %q overflows", s)
		}
		return int64(f * float64(u.mul)), nil
	}
	n, err := strconv.ParseInt(lower, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid byte count %q (plain counts are integer bytes; units: B, K/M/G/T, KiB/MiB/GiB/TiB)", s)
	}
	return n, nil
}
