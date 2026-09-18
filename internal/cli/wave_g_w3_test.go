// wave_g_w3_test.go: CLI coverage for the Wave G security fixes (F7b
// trim writer-assertion passthrough; F5/F7 recover --cancel wiring),
// lab/security-review/wave-F/FINDINGS.md.

package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
)

// trimManifestOf dumps the trim capture's retained manifest.json from the
// fake store (the durable place the §17.2 assertion source is recorded).
func trimManifestOf(t *testing.T, h *eHarness) map[string]any {
	t.Helper()
	snap := latestSnapshotOf(t, h, catalog.SnapshotKindTrim)
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	s, ok := h.store.snaps[snap.PayloadBackendID]
	if !ok {
		t.Fatalf("no payload %s in the fake store", snap.PayloadBackendID)
	}
	for p, b := range s.files {
		if strings.HasSuffix(p, "manifest.json") && strings.Contains(p, ".ebb-op-") {
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatalf("manifest %s: %v", p, err)
			}
			return doc
		}
	}
	t.Fatal("no retained manifest.json in the trim payload")
	return nil
}

// TestTrimRecordsWriterAssertionSource (F7b): --assert-writers-stopped
// is recorded in the trim manifest's consistency source (the §17.2/§17.3
// discipline) and surfaced as an envelope condition.
func TestTrimRecordsWriterAssertionSource(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("trim", "--groups", "deps", "--yes", "--assert-writers-stopped", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	doc := trimManifestOf(t, h)
	contract, _ := doc["contract"].(map[string]any)
	if contract == nil {
		t.Fatal("manifest has no contract object")
	}
	if contract["consistency"] != "stopped-writers-asserted" {
		t.Fatalf("consistency = %v, want stopped-writers-asserted", contract["consistency"])
	}
	if contract["consistency_source"] != assertionFlagSource {
		t.Fatalf("consistency_source = %v, want %q", contract["consistency_source"], assertionFlagSource)
	}
	env := envelopeOf(t, stdout)
	if !mustCondition(env, "writer-assertion:"+assertionFlagSource) {
		t.Errorf("envelope conditions lack the writer assertion: %v", env["conditions"])
	}
	assertNoSecrets(t, stderr)
}

// TestTrimYesNeverSetsWriterAssertion (F7b): --yes acknowledges the group
// approval only — the manifest honestly records best-effort-live with no
// consistency source, and no writer-assertion condition is claimed.
func TestTrimYesNeverSetsWriterAssertion(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("trim", "--groups", "deps", "--yes", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	doc := trimManifestOf(t, h)
	contract, _ := doc["contract"].(map[string]any)
	if contract == nil {
		t.Fatal("manifest has no contract object")
	}
	if contract["consistency"] != "best-effort-live" {
		t.Fatalf("consistency = %v, want best-effort-live (--yes must never assert writers)", contract["consistency"])
	}
	if src, ok := contract["consistency_source"]; ok && src != "" {
		t.Fatalf("consistency_source = %v, want empty", src)
	}
	env := envelopeOf(t, stdout)
	for _, c := range conditionsOf(env) {
		if strings.HasPrefix(c, "writer-assertion:") {
			t.Errorf("envelope claims a writer assertion from --yes: %v", env["conditions"])
		}
	}
}

// TestRecoverCancelFlagWiring (F5): the --cancel verb parses, is mutually
// exclusive with --resume-removal, and reaches the coordinator (a
// mid-removal operation is refused by the coordinator's own phase rule,
// proving the dispatch is live).
func TestRecoverCancelFlagWiring(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("recover", strings.Repeat("f", 32), "--cancel", "--resume-removal"); code != ExitUsage {
		t.Fatalf("contradictory verbs code = %d, want %d", code, ExitUsage)
	}

	// An interrupted park at REMOVING: cancel must be REFUSED by the
	// coordinator (mid-removal phases require reconciliation), exit 5.
	var once bool
	h.probe.onProbeFile = func(path string) {
		if !once && strings.Contains(filepath.ToSlash(path), ".ebb-quarantine-") {
			once = true
			h.cancelSig()
		}
	}
	if code, _, _ := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitCancelled {
		t.Fatal("park was not interrupted")
	}
	h.resetSignalContext()
	op := activeParkOpOf(t, h)
	code, _, stderr := h.run("recover", string(op.ID), "--cancel")
	if code != ExitInterrupted {
		t.Fatalf("cancel on REMOVING code = %d, want %d (stderr %s)", code, ExitInterrupted, stderr)
	}
	if !strings.Contains(stderr, "cancel applies to phases before removal starts") {
		t.Errorf("stderr lacks the phase rule:\n%s", stderr)
	}
	// The report-only/plain recover path still completes REMOVING.
	if code, _, stderr := h.run("recover", string(op.ID)); code != ExitOK {
		t.Fatalf("plain recover code = %d, stderr = %s", code, stderr)
	}
}

// activeParkOpOf returns the workspace's single active operation.
func activeParkOpOf(t *testing.T, h *eHarness) catalog.Operation {
	t.Helper()
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces: %v (%v)", wss, err)
	}
	active, err := cat.ActiveOperations(wss[0].ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("active operations: %v (%v)", active, err)
	}
	return active[0]
}

// conditionsOf renders the envelope's conditions as strings.
func conditionsOf(env map[string]any) []string {
	raw, _ := env["conditions"].([]any)
	out := make([]string, 0, len(raw))
	for _, c := range raw {
		if s, ok := c.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
