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
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// J5 — validateEntryName misses the Win32 ILLEGAL-CHARACTER class. A
// container entry whose segment contains `*` (or `? < > | "` or a C0
// control character) passes every gate in verifyPackage — name
// validation, method, length, declared totals — so the container is
// declared "structurally verified", but no filesystem write with that
// name can ever succeed on Windows (ERROR_INVALID_NAME, live-probed in
// lab/security-review/wave-J/winnameprobe). The refusal surfaces only
// at extractRepository, deep inside the import, as an opaque I/O error.
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

		// The gate under test: verifyPackage ACCEPTS the container.
		if _, verr := verifyPackage(path); verr != nil {
			t.Logf("[%s] verifyPackage refused: %v", name, verr)
			continue
		}
		t.Logf("[%s] verifyPackage ACCEPTED the container (declared totals and methods all check out)", name)

		dst := filepath.Join(dir, "out")
		exErr := extractRepository(path, dst, 1<<62)
		if exErr == nil {
			t.Errorf("J5 [%s]: extraction SUCCEEDED where verify accepted — unexpected on this platform", name)
			continue
		}
		if runtime.GOOS == "windows" && !strings.Contains(exErr.Error(), name[strings.LastIndex(name, "/")+1:]) {
			t.Logf("[%s] extraction refused (message does not name the entry): %v", name, exErr)
		} else {
			t.Logf("[%s] extraction refused: %v", name, exErr)
		}
		t.Errorf("J5 [%s]: verifyPackage accepted an entry name Windows can never create — the container "+
			"is declared structurally verified yet cannot extract on the primary supported platform "+
			"(verify/extract contract disagreement; refusal is loud but late and misattributed as an I/O error)", name)
	}
}

// J6 — case-collision containers. Two entries differing only by ASCII
// case (repo/data/Ab, repo/data/ab) are not duplicates to verifyPackage
// (exact-string dedup), and each name is individually portable, so the
// container verifies — but on a case-INSENSITIVE filesystem (default
// NTFS, live-probed: second O_EXCL create fails with "file exists") the
// extraction refuses at the second entry, while on Linux both extract.
// D028's own rule — "a capsule is judged identically on every platform"
// — is broken between verify (accepts) and extract (Windows refuses).
func TestJ6_CaseCollisionEntriesAcceptedAtVerifyDivergeAtExtract(t *testing.T) {
	dir := t.TempDir()
	entries := map[string]string{
		"bootstrap.json":  minimalBootstrap(),
		"repo/data/Ab":    "upper",
		"repo/data/ab":    "lower",
		"ebb-export.json": minimalExportDoc(2, int64(len("upper")+len("lower"))),
	}
	path := writeRawCapsule(t, dir, entries)

	if _, verr := verifyPackage(path); verr != nil {
		t.Fatalf("J6 harness: verifyPackage refused the case-collision container before the gate under test: %v", verr)
	}
	t.Log("J6: verifyPackage ACCEPTED the case-collision container (entries Ab + ab, declared totals match)")

	dst := filepath.Join(dir, "out")
	exErr := extractRepository(path, dst, 1<<62)
	switch runtime.GOOS {
	case "windows":
		if exErr == nil {
			t.Fatalf("J6: extraction of a case-collision container SUCCEEDED on Windows — expected the second O_EXCL create to collide")
		}
		if !strings.Contains(exErr.Error(), "ab") {
			t.Logf("(extraction refusal message: %v)", exErr)
		}
		t.Errorf("J6 CONFIRMED: the case-collision container verified clean and then failed deep inside extraction "+
			"on the case-insensitive filesystem (%v) — verify and extract disagree about the same container, "+
			"and the refusal names neither the collision nor the offending pair", exErr)
	case "linux", "darwin":
		if exErr != nil {
			t.Fatalf("J6: unexpected extraction failure on a case-sensitive filesystem: %v", exErr)
		}
		t.Log("J6 (case-sensitive host): both entries extracted as distinct files — the SAME container that " +
			"Windows refuses, demonstrating the platform-divergent judgment D028 said a capsule must not have")
	default:
		t.Skipf("J6: no case-sensitivity contract pinned for %s", runtime.GOOS)
	}
}

// J7 — the HI-2 byte-budget arithmetic overflows at maxBytes ==
// math.MaxInt64. `remaining := maxBytes - written + 1` wraps to
// MinInt64, the negative clamp sets it to 0, every io.Copy reads zero
// bytes, and `written > maxBytes` never fires: the ENTIRE repository
// extracts as zero-byte files with NO error — the budget that exists to
// make over-budget writes refuse instead silently truncates everything
// and reports success. Unreachable through today's callers (the budget
// is the verified actual byte sum, so MaxInt64 needs 8 EiB of entries
// in a verified container), but it is a real hole in the enforcement
// itself: the clamp converts an overflow into "budget exhausted →
// write nothing", which is indistinguishable from success.
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

	// Control: MaxInt64-1 (no overflow) extracts the real bytes.
	dst1 := filepath.Join(dir, "ok")
	if err := extractRepository(path, dst1, math.MaxInt64-1); err != nil {
		t.Fatalf("J7 control: extraction under MaxInt64-1 failed: %v", err)
	}
	for _, f := range []string{"data/a", "data/b"} {
		b, err := os.ReadFile(filepath.Join(dst1, filepath.FromSlash(f)))
		if err != nil || string(b) != body {
			t.Fatalf("J7 control: %s = %q (%v)", f, b, err)
		}
	}

	// The defect: MaxInt64 extracts everything as ZERO bytes, no error.
	dst2 := filepath.Join(dir, "overflow")
	if err := extractRepository(path, dst2, math.MaxInt64); err != nil {
		t.Fatalf("J7: expected silent success under MaxInt64, got error %v (defect shape changed)", err)
	}
	zeroed := 0
	for _, f := range []string{"data/a", "data/b"} {
		fi, err := os.Stat(filepath.Join(dst2, filepath.FromSlash(f)))
		if err != nil {
			t.Fatalf("J7: %s missing: %v", f, err)
		}
		if fi.Size() == 0 {
			zeroed++
		}
	}
	if zeroed != 2 {
		t.Fatalf("J7: expected both entries zero-byte under MaxInt64, got %d/2 (arithmetic changed)", zeroed)
	}
	t.Error("J7 CONFIRMED: extractRepository with a MaxInt64 budget silently extracted every entry as a " +
		"ZERO-BYTE file and returned nil — the `maxBytes - written + 1` overflow wraps to MinInt64, the " +
		"negative clamp zeroes the LimitReader, and the `written > maxBytes` check never fires; the byte " +
		"budget's enforcement converts an overflow into silent full truncation shaped like success")
}
