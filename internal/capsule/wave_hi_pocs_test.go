package capsule

// wave_hi_pocs_test.go â€” adversarial PoCs for the Wave H/I security
// review (lab/security-review/wave-HI/FINDINGS.md). Each test names the
// finding it demonstrates. A PoC that FAILS on current code marks a real
// defect (the assertion is the post-fix contract); when a fix lands the
// test flips green and stays as the regression guard.
//
// Run: go test -count=1 -run 'TestHI' ./internal/capsule/ -v

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRawCapsule builds a minimal container with caller-controlled
// entry names (bypassing the walk-based writer, which never produces
// hostile names) so the READER discipline is what is under test.
func writeRawCapsule(t *testing.T, dir string, names map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "hostile.ebb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func minimalBootstrap() string {
	return `{"schema_version":1,"producer":"poc","container_version":1,"backend_family":"restic","repo_root":"repo","min_reader_features":["zip64","zip-stored-entries","restic"]}` + "\n"
}
func minimalExportDoc(repoEntries, repoBytes int64) string {
	return `{"schema_version":1,"kind":"ebb-export","operation_id":"` + strings.Repeat("a", 32) +
		`","source_snapshot_id":"` + strings.Repeat("b", 32) +
		`","started_at":"2026-09-19T00:00:00Z","state":"verifying","container_version":1,` +
		`"repo_entries":` + itoa(repoEntries) + `,"repo_bytes":` + itoa(repoBytes) + `}` + "\n"
}
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// HI-1a: a colon later in a segment is accepted by validateEntryName and
// by verifyPackage, but on Windows "ab:cd" is an ALTERNATE DATA STREAM of
// file "ab", not a file named "ab:cd". The container is not refused; the
// import silently mis-extracts. Post-fix contract: verifyPackage REJECTS
// any segment containing ':'.
func TestHI1a_ADSLaterColonAccepted(t *testing.T) {
	dir := t.TempDir()
	body := "stream-bytes"
	entries := map[string]string{
		"bootstrap.json":  minimalBootstrap(),
		"repo/data/ab:cd": body,
		"ebb-export.json": minimalExportDoc(1, int64(len(body))),
	}
	path := writeRawCapsule(t, dir, entries)

	_, verr := verifyPackage(path)
	if verr == nil {
		t.Log("HI-1a: verifyPackage accepted entry repo/data/ab:cd (colon later in segment)")
	} else {
		t.Logf("verifyPackage rejected it: %v", verr)
	}

	dst := filepath.Join(dir, "out")
	exErr := extractRepository(path, dst, 1<<62) // budget unbounded; the name gate is under test
	if exErr != nil {
		t.Logf("extractRepository refused: %v", exErr)
		return
	}
	want := filepath.Join(dst, "data", "ab:cd")
	if _, err := os.Stat(want); err != nil {
		t.Logf("HI-1a consequence: %s does not exist as a file (%v)", want, err)
	} else {
		t.Logf("HI-1a: %s exists as a file", want)
	}
	if verr == nil {
		t.Error("HI-1a: colon later in a segment must be REJECTED at validateEntryName (ADS alias); it was accepted")
	}
}

// HI-1b: trailing-dot and trailing-space segments are accepted at verify
// but silently stripped by Windows on write (filepath semantics), so the
// extracted path differs from the capsule's declared name.
func TestHI1b_TrailingDotSpaceAccepted(t *testing.T) {
	dir := t.TempDir()
	for _, seg := range []string{"ab.", "ab "} {
		body := "x"
		entries := map[string]string{
			"bootstrap.json":   minimalBootstrap(),
			"repo/data/" + seg: body,
			"ebb-export.json":  minimalExportDoc(1, int64(len(body))),
		}
		path := writeRawCapsule(t, dir, entries)
		if _, verr := verifyPackage(path); verr == nil {
			t.Errorf("HI-1b: segment %q accepted at verify; Windows strips the trailing dot/space on write (mis-extraction, not refusal)", seg)
		} else {
			t.Logf("segment %q rejected: %v", seg, verr)
		}
	}
}

// HI-1c: the device-name check uses filepath.Ext, so "con.txt" is caught
// (base "con"), but "con.foo.bar" -> base "con.foo" is NOT. Confirm the
// single-ext device name is already refused (baseline) and record whether
// the multi-ext form slips.
func TestHI1c_DeviceNameMultiExt(t *testing.T) {
	dir := t.TempDir()
	body := "y"
	entries := map[string]string{
		"bootstrap.json":    minimalBootstrap(),
		"repo/data/con.txt": body,
		"ebb-export.json":   minimalExportDoc(1, int64(len(body))),
	}
	path := writeRawCapsule(t, dir, entries)
	if _, verr := verifyPackage(path); verr == nil {
		t.Error("HI-1c baseline broken: con.txt should already be rejected as a device name")
	} else {
		t.Logf("con.txt rejected (expected): %v", verr)
	}

	entries2 := map[string]string{
		"bootstrap.json":        minimalBootstrap(),
		"repo/data/con.foo.bar": body,
		"ebb-export.json":       minimalExportDoc(1, int64(len(body))),
	}
	path2 := writeRawCapsule(t, dir, entries2)
	if _, verr := verifyPackage(path2); verr == nil {
		t.Log("HI-1c: con.foo.bar accepted (multi-ext device basename slips the Ext-based check; Windows opens CON regardless of extension)")
	} else {
		t.Logf("con.foo.bar rejected: %v", verr)
	}
}

// HI-2 (fixed): extraction now enforces a caller-supplied byte budget.
// The headroom gate budgets against verifyPackage's declared totals; this
// test proves extractRepository REFUSES once cumulative writes exceed the
// budget, so a container swapped in between verify and extract (or any
// future caller that skips verify) cannot write beyond what was accounted.
func TestHI2_ExtractionEnforcesByteBudget(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("Z", 1<<20) // 1 MiB
	entries := map[string]string{
		"bootstrap.json":  minimalBootstrap(),
		"repo/data/a":     big,
		"repo/data/b":     big,
		"ebb-export.json": minimalExportDoc(2, 2*int64(len(big))),
	}
	path := writeRawCapsule(t, dir, entries)
	dst := filepath.Join(dir, "out")
	// Budget below the true content (2 MiB) must be enforced at write time.
	err := extractRepository(path, dst, 1<<20) // 1 MiB budget for 2 MiB of content
	if err == nil {
		t.Error("HI-2: extraction of 2 MiB under a 1 MiB budget succeeded; the budget is not enforced")
	} else {
		t.Logf("budget enforced: %v", err)
	}
	// A budget at/above the true size still extracts cleanly.
	dst2 := filepath.Join(dir, "out2")
	if err := extractRepository(path, dst2, 2*int64(len(big))); err != nil {
		t.Errorf("extraction within budget failed: %v", err)
	}
}

// Sanity: the strict doc decoder rejects unknown fields, so the public
// doc surface is not a smuggling vector.
func TestHI_StrictDocDecoder(t *testing.T) {
	var b bootstrapDoc
	err := decodeStrictDoc([]byte(`{"schema_version":1,"producer":"x","container_version":1,"backend_family":"restic","repo_root":"repo","min_reader_features":[],"unexpected_field":true}`), "bootstrap.json", &b)
	if err == nil {
		t.Error("decodeStrictDoc accepted an unknown field")
	}
}
