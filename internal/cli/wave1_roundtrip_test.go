package cli

// Wave 1 cross-worker integration: a carve-out trim (W2, lifecycle side)
// round-trips through `ebb restore` (W1, restore side) — the carved
// overlay survives in the sealed payload and is reapplied byte-exact on
// top of the freshly recreated outputs (D033 + D034 together).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const carveEbbfile = `version = 1

[workspace]
name = "cliws"

[policy]
network = "approved-actions"
unknown = "preserve"

[[preserve]]
patterns = ["node_modules/kept/**"]
reason = "custom debugging tweak inside the generated tree"

[[regenerate]]
id = "deps"
adapter = "pnpm"
root = "."
outputs = ["node_modules"]
inputs = ["package.json", "pnpm-lock.yaml"]
network = "allowed"
`

const carveTweak = "// local debugging tweak that must survive reclaim+restore\n"

func TestCarveOutTrimThenRestoreReappliesOverlay(t *testing.T) {
	h, _ := newRestoreHarness(t)
	// A preserved tweak inside the group's outputs: F53 material that the
	// carve-out isolates instead of cancelling the whole group.
	if err := os.WriteFile(filepath.Join(h.wsRoot, "Ebbfile.toml"), []byte(carveEbbfile), 0o644); err != nil {
		t.Fatal(err)
	}
	keptDir := filepath.Join(h.wsRoot, "node_modules", "kept")
	if err := os.MkdirAll(keptDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keptDir, "fix.js"), []byte(carveTweak), 0o644); err != nil {
		t.Fatal(err)
	}

	// Without consent the group is skipped honestly (no silent carve-out).
	if code, _, stderr := h.run("reclaim", "--target", "1KiB", "--yes", h.wsRoot); code == ExitOK {
		t.Fatalf("reclaim without --carve-out reported success:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules", "kept", "fix.js")); err != nil {
		t.Fatalf("unconsented run removed the preserved tweak: %v", err)
	}

	// The carve-out trim: bulk removed, tweak captured into the overlay.
	if code, _, stderr := h.run("trim", "--groups", "deps", "--yes", "--carve-out", h.wsRoot); code != ExitOK {
		t.Fatalf("carve-out trim code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("carve-out trim left node_modules behind: %v", err)
	}

	// Restore: the recipe recreates the outputs, then the overlay writes
	// the tweak back byte-exact on top of the downloaded tree.
	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("restore code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	details, _ := env["details"].(map[string]any)
	if details == nil {
		t.Fatalf("envelope lacks details: %v", env)
	}
	if details["protected_gate"] != "passed" {
		t.Fatalf("protected gate = %v", details["protected_gate"])
	}
	if b, err := os.ReadFile(filepath.Join(h.wsRoot, "node_modules", "built.txt")); err != nil || string(b) != "rebuilt\n" {
		t.Fatalf("recipe output missing after restore: %q %v", b, err)
	}
	got, err := os.ReadFile(filepath.Join(h.wsRoot, "node_modules", "kept", "fix.js"))
	if err != nil || string(got) != carveTweak {
		t.Fatalf("carved tweak not reapplied byte-exact: %q %v", got, err)
	}
	// The overlays applied are reported in the machine envelope.
	if !strings.Contains(stdout, "node_modules/kept/fix.js") {
		t.Errorf("envelope does not report the applied overlay:\n%s", stdout)
	}
}
