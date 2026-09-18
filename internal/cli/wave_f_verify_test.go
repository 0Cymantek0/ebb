// wave_f_verify_test.go: `ebb verify` coverage over the eHarness world
// (Wave F). Coverage-fresh pass (default scope), the scope split (a
// same-length content tamper passes coverage and fails only under
// --content), document tampering (exit 4), unknown id (exit 2) and the
// trim-kind scope refusal (exit 3).

package cli

import (
	"fmt"
	"strings"
	"testing"

	"ebb/internal/catalog"
)

// tamperPayloadFile reaches into the fake store's payload snapshot and
// rewrites one file's bytes (test-side corruption; the code under test
// only reads).
func tamperPayloadFile(t *testing.T, h *eHarness, payloadID, suffix string, mutate func([]byte) []byte) {
	t.Helper()
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	snap, ok := h.store.snaps[payloadID]
	if !ok {
		t.Fatalf("no payload %s in the fake store", payloadID)
	}
	var path string
	for p := range snap.files {
		if strings.HasSuffix(p, suffix) {
			path = p
			break
		}
	}
	if path == "" {
		t.Fatalf("no payload file ending in %q (have %v)", suffix, keysOf(snap.files))
	}
	snap.files[path] = mutate(snap.files[path])
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// flipSameLength returns a same-length mutation of b (content differs,
// coverage's size check cannot see it).
func flipSameLength(b []byte) []byte {
	out := append([]byte(nil), b...)
	for i := range out {
		out[i] ^= 0x5a
	}
	return out
}

func TestVerifyCoverageFreshPass(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot code = %d, stderr = %s", code, stderr)
	}
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)

	code, stdout, stderr := h.run("verify", string(snap.ID))
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{
		"verify snapshot of workspace \"cliws\" (coverage+documents): PASS",
		"check seal-receipt: pass",
		"check payload-documents: pass",
		"check coverage-complete: pass",
		"tools:",
		"seal recorded its verification at",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "content-readback") {
		t.Errorf("default scope must not claim content readback:\n%s", stderr)
	}
	assertNoSecrets(t, stderr)
}

func TestVerifyJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatal("snapshot failed")
	}
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)
	code, stdout, stderr := h.run("verify", "--json", string(snap.ID))
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || envString(t, env, "snapshot_id") != string(snap.ID) {
		t.Fatalf("envelope head = %v", env)
	}
	if !mustCondition(env, "scope:coverage+documents") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	checks := det["checks"].([]any)
	if len(checks) != 3 {
		t.Fatalf("checks = %v", checks)
	}
	for _, c := range checks {
		if c.(map[string]any)["status"] != "pass" {
			t.Errorf("check = %v", c)
		}
	}
	tv, ok := det["tool_versions"].(map[string]any)
	if !ok || tv["ebb"] == nil {
		t.Errorf("tool_versions = %v", det["tool_versions"])
	}
	if det["entries_retained"].(float64) <= 0 || det["preserved_bytes"].(float64) <= 0 {
		t.Errorf("retained-evidence facts missing: %v", det)
	}
}

func TestVerifyTamperedDocumentFails(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatal("snapshot failed")
	}
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)
	// Corrupt the retained inventory bytes: the digest gate (I12) must
	// fail the documents check.
	tamperPayloadFile(t, h, snap.PayloadBackendID, "/inventory.jsonl", func(b []byte) []byte {
		return append(b, []byte("{\"injected\":true}\n")...)
	})

	code, _, stderr := h.run("verify", string(snap.ID))
	if code != ExitCaptureVerify {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitCaptureVerify, stderr)
	}
	for _, want := range []string{
		"FAIL",
		"check payload-documents: FAIL",
		"digest",
		"keep the snapshot pinned",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestVerifyContentScopeCatchesSameLengthTamper(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatal("snapshot failed")
	}
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)
	// Same-length content corruption inside a preserved file: coverage
	// (names/kinds/sizes) cannot see it; only --content readback can.
	tamperPayloadFile(t, h, snap.PayloadBackendID, "/notes.md", flipSameLength)

	code, _, stderr := h.run("verify", string(snap.ID))
	if code != ExitOK {
		t.Fatalf("default scope code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "PASS") {
		t.Errorf("default scope must pass on a size-preserving tamper:\n%s", stderr)
	}

	code, _, stderr = h.run("verify", "--content", string(snap.ID))
	if code != ExitCaptureVerify {
		t.Fatalf("content scope code = %d, want %d (stderr %s)", code, ExitCaptureVerify, stderr)
	}
	for _, want := range []string{
		"content scope: full per-file readback",
		"check content-readback: FAIL",
		"readback digest",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestVerifyContentScopeFreshPass(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatal("snapshot failed")
	}
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)
	code, _, stderr := h.run("verify", "--content", string(snap.ID))
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"content scope: full per-file readback", "check content-readback: pass"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
}

func TestVerifyUnknownAndMalformedID(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("verify", strings.Repeat("cd", 16)); code != ExitUsage {
		t.Fatalf("unknown id code = %d, want %d", code, ExitUsage)
	}
	if code, _, _ := h.run("verify", "not-an-id"); code != ExitUsage {
		t.Fatalf("malformed id code = %d, want %d", code, ExitUsage)
	}
}

func TestVerifyTrimKindRefused(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("trim", "--groups", "deps", "--yes", h.wsRoot); code != ExitOK {
		t.Fatalf("trim code = %d, stderr = %s", code, stderr)
	}
	trim := latestSnapshotOf(t, h, catalog.SnapshotKindTrim)
	code, _, stderr := h.run("verify", string(trim.ID))
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, "EBB_E_NOT_OPENABLE") || !strings.Contains(stderr, "removal plan") {
		t.Errorf("stderr must name the trim-scope refusal:\n%s", stderr)
	}
}

func TestVerifyCoverageCatchesMissingTreeEntry(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatal("snapshot failed")
	}
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)
	// Remove a preserved file's bytes from the payload tree entirely:
	// coverage must fail with the missing-node detail.
	tamperPayloadFile(t, h, snap.PayloadBackendID, "/notes.md", func(b []byte) []byte {
		return []byte{}
	})
	// The fake store reports the zero-length file: coverage sees the size
	// mismatch instead of a missing node — either way it must FAIL.
	code, _, stderr := h.run("verify", string(snap.ID))
	if code != ExitCaptureVerify {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitCaptureVerify, stderr)
	}
	if !strings.Contains(stderr, "check coverage-complete: FAIL") {
		t.Errorf("stderr lacks the coverage failure:\n%s", stderr)
	}
	// And the failed check names the file.
	if !strings.Contains(stderr, "notes.md") {
		t.Errorf("failure detail must name the mismatching path:\n%s", stderr)
	}
}

func TestVerifyTamperedSealReceiptFails(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatal("snapshot failed")
	}
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)
	// Corrupt the SEAL snapshot's receipt bytes: loadSeal's strict parse
	// or cross-check must fail the seal-receipt check.
	h.store.mu.Lock()
	sealSnap, ok := h.store.snaps[snap.SealBackendID]
	if !ok {
		h.store.mu.Unlock()
		t.Fatal("no seal snapshot in the fake store")
	}
	for p := range sealSnap.files {
		sealSnap.files[p] = []byte(fmt.Sprintf("%s\n", "not json at all"))
	}
	h.store.mu.Unlock()

	code, _, stderr := h.run("verify", string(snap.ID))
	if code != ExitCaptureVerify {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitCaptureVerify, stderr)
	}
	if !strings.Contains(stderr, "check seal-receipt: FAIL") {
		t.Errorf("stderr lacks the seal failure:\n%s", stderr)
	}
}
