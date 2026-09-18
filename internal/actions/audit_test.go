package actions_test

import (
	"os"
	"strings"
	"testing"
)

// TestNoDeletionAuthority is the audit tripwire for the package's core
// safety contract (Foundation §9.5: "Actions cannot acquire the
// source-removal capability"): the actions package — the only code
// allowed to execute project-approved commands — must not remove or
// rename files anywhere in its source. If this test fails, someone added
// deletion authority to the execution subsystem; route removal through
// the lifecycle coordinator instead.
//
// Scope: every non-test .go file of package actions in this directory.
// Test files are excluded because test scaffolding legitimately cleans
// its own scratch directories (t.TempDir, TestMain). The approvalstore
// subpackage performs exactly one audited rename — the atomic
// replacement of its own approvals document — and a behavioral guard
// (approvalstore.TestStoreNeverTouchesSiblingFiles) proves it touches
// nothing else.
func TestNoDeletionAuthority(t *testing.T) {
	forbidden := []string{"os.Remove", "os.RemoveAll", "os.Rename"}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		checked++
		for _, pat := range forbidden {
			if strings.Contains(string(src), pat) {
				t.Errorf("%s contains %q: the actions package must never remove or rename files (Foundation \u00a79.5); removal authority belongs to the lifecycle coordinator", e.Name(), pat)
			}
		}
	}
	// The tripwire must actually audit the package, not pass vacuously
	// on an empty directory.
	required := []string{"doc.go", "defs.go", "approval.go", "run.go", "errors.go"}
	for _, name := range required {
		found := false
		for _, e := range entries {
			if e.Name() == name && !e.IsDir() {
				found = true
			}
		}
		if !found {
			t.Errorf("expected package source file %s is missing; the tripwire must cover the real package", name)
		}
	}
	if checked == 0 {
		t.Fatal("no non-test source files found to audit")
	}
	t.Logf("audit tripwire: %d source files clean of removal/rename APIs", checked)
}

// TestSelfAuditTripwirePoisonsCorrectly proves the grep itself has
// teeth: a string containing the forbidden patterns must be detected.
func TestSelfAuditTripwirePoisonsCorrectly(t *testing.T) {
	forbidden := []string{"os.Remove", "os.RemoveAll", "os.Rename"}
	clean := "ok, this file only calls os.Open and exec.CommandContext"
	for _, pat := range forbidden {
		if strings.Contains(clean, pat) {
			t.Errorf("pattern %q false-positive on clean source", pat)
		}
	}
	dirty := "os.Remove(target)"
	if !strings.Contains(dirty, "os.Remove") {
		t.Error("pattern failed to detect a poisoned source")
	}
}
