//go:build security_poc

package capsule

// Wave J adversarial security PoCs (capsule container surface — the D028
// fixes under fresh attack). Opt-in via -tags security_poc; the default
// suite stays green. Each test names the finding it demonstrates and
// asserts the SPECIFIC misbehavior (a verify/extract disagreement, a
// silent zero-byte extraction), never an unrelated earlier gate — the
// harness fixtures satisfy every earlier check (strict docs, declared
// totals, STORED methods) on purpose.

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// J5 — validateEntryName must reject the full Win32 ILLEGAL-CHARACTER
// class host-agnostically. A container entry whose segment contains `*`
// (or `? < > | "` or a C0 control character) must be refused by
// verifyPackage — with an error naming the character class — because no
// filesystem write with that name can ever succeed on Windows
// (ERROR_INVALID_NAME, live-probed in
// lab/security-review/wave-J/winnameprobe). Pre-fix, the refusal
// surfaced only at extractRepository, deep inside the import, as an
// opaque I/O error naming neither the defect class nor the gate.
// Post-fix contract: verifyPackage REFUSES the container and the error
// names the illegal-character / C0-control class.
func TestJ5_IllegalCharEntriesPassVerifyButCannotExtract(t *testing.T) {
	for _, name := range []string{
		"repo/data/ab*c",    // wildcard: illegal in Win32 filenames
		"repo/data/ab<c",    // redirection char
		"repo/data/ab\x01c", // C0 control character
	} {
		dir := t.TempDir()
		body := "x"
		entries := map[string]string{
			"bootstrap.json":  minimalBootstrap(),
			name:              body,
			"ebb-export.json": minimalExportDoc(1, int64(len(body))),
		}
		path := writeRawCapsule(t, dir, entries)

		// The gate under test: verifyPackage must REFUSE the container,
		// and the refusal must name the character class (not trip some
		// unrelated earlier gate — the wave-C vacuous-PASS lesson).
		_, verr := verifyPackage(path)
		if verr == nil {
			t.Errorf("J5 [%s]: verifyPackage ACCEPTED an entry name Windows can never create — the container "+
				"is declared structurally verified yet cannot extract on the primary supported platform "+
				"(verify/extract contract disagreement; regression of the J5 fix)", name)
			continue
		}
		want := "illegal filename character"
		if strings.Contains(name, "\x01") {
			want = "C0 control character"
		}
		if !strings.Contains(verr.Error(), want) {
			t.Errorf("J5 [%s]: verifyPackage refused the container but the error does not name the character class (%q): %v", name, want, verr)
			continue
		}
		t.Logf("[%s] refused at verify, class named: %v", name, verr)
	}
}

// J6 — case-collision entries. Two entries differing only by ASCII case
// (repo/data/Ab, repo/data/ab) are not duplicates to exact-string dedup,
// and each name is individually portable, so pre-fix the container
// verified — but on a case-INSENSITIVE filesystem (default NTFS,
// live-probed: second O_EXCL create fails with "file exists") the
// extraction refused at the second entry, while Linux extracted both.
// D028's own rule — "a capsule is judged identically on every platform"
// — was broken between verify (accepts) and extract (Windows refuses).
// Post-fix contract (per the finding's fix directive): verifyPackage
// REFUSES the case-collision container on EVERY platform, with an error
// naming the colliding pair.
func TestJ6_CaseCollisionEntriesAcceptedAtVerifyDivergeAtExtract(t *testing.T) {
	dir := t.TempDir()
	entries := map[string]string{
		"bootstrap.json":  minimalBootstrap(),
		"repo/data/Ab":    "upper",
		"repo/data/ab":    "lower",
		"ebb-export.json": minimalExportDoc(2, int64(len("upper")+len("lower"))),
	}
	path := writeRawCapsule(t, dir, entries)

	_, verr := verifyPackage(path)
	if verr == nil {
		t.Fatalf("J6 REGRESSION: verifyPackage ACCEPTED the case-collision container (entries Ab + ab, " +
			"declared totals match) — the J6 fix requires a named refusal on every platform")
	}
	// The refusal must name the colliding pair, not just the container.
	for _, want := range []string{"repo/data/Ab", "repo/data/ab", "case-collision"} {
		if !strings.Contains(verr.Error(), want) {
			t.Errorf("J6: verifyPackage refusal does not name %q: %v", want, verr)
		}
	}
	t.Logf("J6: refused at verify on %s, pair named: %v", runtime.GOOS, verr)

	// Defense in depth: a caller that skips verify gets the same named
	// refusal at extract (not a platform-divergent mid-extraction error).
	dst := filepath.Join(dir, "out")
	exErr := extractRepository(path, dst, 1<<62)
	if exErr == nil {
		t.Fatalf("J6 REGRESSION: extractRepository accepted the case-collision container on %s — the skip-verify defense-in-depth fold is gone", runtime.GOOS)
	}
	if !strings.Contains(exErr.Error(), "repo/data/Ab") || !strings.Contains(exErr.Error(), "repo/data/ab") {
		t.Errorf("J6: extraction refusal does not name the colliding pair: %v", exErr)
	}
	t.Logf("J6: refused at extract (defense in depth), pair named: %v", exErr)
}

// J7 — the HI-2 byte-budget arithmetic overflowed at maxBytes ==
// math.MaxInt64. Pre-fix, `remaining := maxBytes - written + 1` wrapped
// to MinInt64, the negative clamp set it to 0, every io.Copy read zero
// bytes, and `written > maxBytes` never fired: the ENTIRE repository
// extracted as zero-byte files with NO error — the budget that exists to
// make over-budget writes refuse instead silently truncated everything
// and reported success. Unreachable through today's callers (the budget
// is the verified actual byte sum, so MaxInt64 needs 8 EiB of entries
// in a verified container), but it is a real hole in the enforcement
// itself. Post-fix contract: the allowance SATURATES — a MaxInt64
// budget extracts the real bytes exactly like the MaxInt64-1 control,
// and over-budget detection still fires below the true content size.
func TestJ7_BudgetMaxInt64OverflowSilentlyExtractsZeroBytes(t *testing.T) {
	dir := t.TempDir()
	body := "hello"
	entries := map[string]string{
		"bootstrap.json":  minimalBootstrap(),
		"repo/data/a":     body,
		"repo/data/b":     body,
		"ebb-export.json": minimalExportDoc(2, 2*int64(len(body))),
	}
	path := writeRawCapsule(t, dir, entries)

	extractAll := func(budget int64) string {
		dst := filepath.Join(dir, fmt.Sprintf("out-%d", budget))
		if err := extractRepository(path, dst, budget); err != nil {
			t.Fatalf("J7: extraction under budget %d failed: %v", budget, err)
		}
		for _, f := range []string{"data/a", "data/b"} {
			b, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(f)))
			if err != nil || string(b) != body {
				t.Fatalf("J7: budget %d: %s = %q (%v) — real bytes must extract", budget, f, b, err)
			}
		}
		return dst
	}

	// Control: MaxInt64-1 (no overflow) extracts the real bytes.
	extractAll(math.MaxInt64 - 1)
	// The fixed defect: MaxInt64 must behave identically — the saturating
	// allowance extracts the real bytes instead of silently truncating
	// every entry to zero bytes shaped like success.
	extractAll(math.MaxInt64)
	t.Log("J7: MaxInt64 and MaxInt64-1 budgets both extract the real bytes — the allowance saturates")

	// The over-budget detection the HI-2 budget exists for still fires:
	// a budget below the true content (10 bytes) must refuse with the
	// named budget error, not silently under-extract.
	dst := filepath.Join(dir, "over")
	err := extractRepository(path, dst, int64(len(body)))
	if err == nil || !strings.Contains(err.Error(), "exceeded the verified byte budget") {
		t.Fatalf("J7: over-budget extraction must refuse with the named budget error, got: %v", err)
	}
	t.Logf("J7: over-budget write refused: %v", err)
}
