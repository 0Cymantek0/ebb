// wave1_carveout_test.go: `ebb trim` / `ebb reclaim` carve-out approval
// surface (D034). No silent carve, ever: headless runs require
// --carve-out together with --yes; interactive runs get a separate
// typed confirmation listing every carved path; a declined carve leaves
// the group (and the whole tree) untouched.

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const carveCLIFix = "// vendor patch that must round-trip via the overlay\n"

// writeCarveCLIFixture turns the standard eHarness workspace into a
// carve-out case: a preserve rule covers a file inside node_modules,
// cancelling the deps group (F10/F53 shape).
func writeCarveCLIFixture(t *testing.T, h *eHarness) {
	t.Helper()
	ebbfile := `version = 1

[workspace]
name = "cliws"

[policy]
network = "approved-actions"
unknown = "preserve"

[[preserve]]
patterns = ["node_modules/kept/**"]
reason = "vendor patch inside the generated tree (D034 CLI fixture)"

[[regenerate]]
id = "deps"
adapter = "pnpm"
root = "."
outputs = ["node_modules"]
inputs = ["package.json", "pnpm-lock.yaml"]
network = "allowed"
`
	if err := os.WriteFile(filepath.Join(h.wsRoot, "Ebbfile.toml"), []byte(ebbfile), 0o644); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(h.wsRoot, "node_modules", "kept", "fix.js")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(carveCLIFix), 0o644); err != nil {
		t.Fatal(err)
	}
}

// cliOverlayPlan mirrors the removal manifest's carve-out fields
// (independent re-declaration of the frozen schema — the JSON contract,
// not lifecycle's Go types, is what restore will consume).
type cliOverlayPlan struct {
	Groups []struct {
		GroupID        string `json:"group_id"`
		OverlayPatches []struct {
			Path   string `json:"path"`
			Copy   string `json:"copy"`
			Digest string `json:"digest"`
			Kind   string `json:"kind"`
			Mode   uint32 `json:"mode"` // F9: source permission bits (0 = legacy/link)
		} `json:"overlay_patches"`
		RecreateLive []string `json:"recreate_live"`
	} `json:"groups"`
}

// latestTrimPlanOf reads the retained removal manifest out of the fake
// store's (single) payload snapshot, like an independent restore
// worker would.
func latestTrimPlanOf(t *testing.T, h *eHarness) cliOverlayPlan {
	t.Helper()
	ctx := context.Background()
	refs, err := h.store.List(ctx, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var payloadID string
	n := 0
	for _, r := range refs {
		if r.Tags["ebb-kind"] == "payload" {
			payloadID, n = r.BackendID, n+1
		}
	}
	if n != 1 {
		t.Fatalf("expected exactly one payload snapshot, got %d", n)
	}
	ls, err := h.store.Ls(ctx, "", "", payloadID)
	if err != nil {
		t.Fatal(err)
	}
	var manifestPath string
	for _, e := range ls {
		if strings.HasSuffix(e.Path, "/removal-manifest.json") {
			manifestPath = e.Path
		}
	}
	if manifestPath == "" {
		t.Fatal("payload carries no removal manifest")
	}
	raw, err := h.store.DumpFile(ctx, "", "", payloadID, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var plan cliOverlayPlan
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("removal manifest is not valid JSON for the frozen schema: %v", err)
	}
	return plan
}

func TestTrimHeadlessCarveNeedsFlag(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	code, stdout, stderr := h.run("trim", "--groups", "deps", "--yes", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (ExitBlocked); stderr = %s", code, ExitBlocked, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{"--carve-out"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	// Nothing removed.
	for _, kept := range []string{
		filepath.Join("node_modules", "kept", "fix.js"),
		filepath.Join("node_modules", "left-pad", "index.js"),
		"notes.md",
	} {
		if _, err := os.Stat(filepath.Join(h.wsRoot, filepath.FromSlash(kept))); err != nil {
			t.Fatalf("carve-eligible trim removed or disturbed %s: %v", kept, err)
		}
	}
}

func TestTrimHeadlessCarveOutExecutes(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	code, _, stderr := h.run("trim", "--groups", "deps", "--yes", "--carve-out", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// The carved file AND the bulk are gone; everything else stays.
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("node_modules still exists: %v", err)
	}
	for _, kept := range []string{"notes.md", ".env", "package.json", "pnpm-lock.yaml", "Ebbfile.toml", filepath.Join("src", "main.go")} {
		if _, err := os.Stat(filepath.Join(h.wsRoot, filepath.FromSlash(kept))); err != nil {
			t.Fatalf("retained path %s removed: %v", kept, err)
		}
	}
	if !strings.Contains(stderr, "carved 1 preserved") || !strings.Contains(stderr, "(D034)") {
		t.Errorf("stderr must report the carve in the human result:\n%s", stderr)
	}
	// The overlay survived into the retained snapshot (restore contract).
	plan := latestTrimPlanOf(t, h)
	if len(plan.Groups) != 1 || len(plan.Groups[0].OverlayPatches) != 1 ||
		plan.Groups[0].OverlayPatches[0].Path != "node_modules/kept/fix.js" {
		t.Fatalf("overlay patches wrong: %+v", plan.Groups[0].OverlayPatches)
	}
	rec := plan.Groups[0].OverlayPatches[0]
	if rec.Kind != "file" || rec.Copy != "overlay/deps/node_modules/kept/fix.js" || rec.Digest == "" {
		t.Fatalf("overlay record shape wrong: %+v", rec)
	}
	if strings.Join(plan.Groups[0].RecreateLive, " ") != "pnpm install" {
		t.Errorf("recreate_live = %v", plan.Groups[0].RecreateLive)
	}
}

func TestTrimInteractiveCarveConfirmDeclined(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	h.tty = true
	h.lines = []string{"yes", "no"} // group approval, then carve declined
	code, _, stderr := h.run("trim", "--groups", "deps", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d; stderr = %s", code, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, "carve out") || !strings.Contains(stderr, "declined") {
		t.Errorf("stderr must show the carve confirmation and the decline:\n%s", stderr)
	}
	if !strings.Contains(stderr, "captured to vault, then removed") {
		t.Errorf("the carve list must state the capture-then-remove treatment:\n%s", stderr)
	}
	if !strings.Contains(stderr, "node_modules/kept/fix.js") {
		t.Errorf("the carve list must name the carved path:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules", "kept", "fix.js")); err != nil {
		t.Fatalf("declined carve still removed something: %v", err)
	}
}

func TestTrimInteractiveCarveConfirmAccepted(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	h.tty = true
	h.lines = []string{"yes", "yes"} // group approval, then carve accepted
	code, _, stderr := h.run("trim", "--groups", "deps", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("node_modules still exists: %v", err)
	}
	if !strings.Contains(stderr, "carve out") {
		t.Errorf("stderr lacks the carve confirmation text:\n%s", stderr)
	}
}

func TestReclaimCarveStageHeadlessNeedsFlag(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	code, _, stderr := h.run("reclaim", "--yes", h.wsRoot)
	if code != ExitShortfall {
		t.Fatalf("code = %d, want %d (no safe gain); stderr = %s", code, ExitShortfall, stderr)
	}
	if !strings.Contains(stderr, "skipped group deps") || !strings.Contains(stderr, "--carve-out") {
		t.Errorf("stderr must report the skipped carve stage naming --carve-out:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules", "kept", "fix.js")); err != nil {
		t.Fatalf("reclaim without carve consent removed something: %v", err)
	}
}

func TestReclaimCarveStageHeadlessExecutes(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	code, _, stderr := h.run("reclaim", "--yes", "--carve-out", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("node_modules still exists: %v", err)
	}
	for _, want := range []string{"removed group deps", "carved 1 preserved"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "notes.md")); err != nil {
		t.Fatalf("retained path removed: %v", err)
	}
}

func TestReclaimDryRunMentionsCarveAvailability(t *testing.T) {
	h := newEHarness(t)
	writeCarveCLIFixture(t, h)
	code, _, stderr := h.run("reclaim", "--dry-run", h.wsRoot)
	if code != ExitShortfall && code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "carve-out available") || !strings.Contains(stderr, "deps") {
		t.Errorf("dry run must surface the carve option for the cancelled group:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules", "kept", "fix.js")); err != nil {
		t.Fatalf("dry run removed something: %v", err)
	}
}
