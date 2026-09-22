// state_dir_test.go pins the EBB_STATE_DIR override contract (the only
// environment knob for state isolation): the production state-dir
// wiring (RealDeps.StateDir -> vault.EnsureConfigDir -> DefaultConfigDir)
// must resolve to the override when set and to the documented
// os.UserConfigDir()/ebb default when unset. The override exists so
// automation, tests and cold-machine drills get a fully isolated
// install (catalog.db, vaults.json, locator.json, approvals.json)
// without touching the real per-user state directory.

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0Cymantek0/ebb/internal/vault"
)

// TestStateDirDefaultUnchanged pins the default path: with EBB_STATE_DIR
// unset, the config-dir authority is exactly os.UserConfigDir()/ebb and
// nothing is created by the resolution itself.
func TestStateDirDefaultUnchanged(t *testing.T) {
	t.Setenv(vault.EnvStateDir, "")
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skipf("no user config dir on this platform: %v", err)
	}
	got, err := vault.DefaultConfigDir()
	if err != nil {
		t.Fatalf("DefaultConfigDir: %v", err)
	}
	if want := filepath.Join(base, "ebb"); got != want {
		t.Fatalf("default state dir drifted: got %s, want %s", got, want)
	}
}

// TestStateDirOverrideHonored pins the override: EBB_STATE_DIR wins over
// the default, is absolutized, and the production RealDeps().StateDir
// seam creates and returns exactly that directory (so the whole session
// — catalog, registry, locator, approvals — lives inside it).
func TestStateDirOverrideHonored(t *testing.T) {
	dir := t.TempDir()
	// A relative spelling must absolutize against the process working
	// directory, not silently depend on it later.
	parent, rel := filepath.Dir(dir), filepath.Base(dir)
	t.Chdir(parent)
	t.Setenv(vault.EnvStateDir, rel)

	got, err := vault.DefaultConfigDir()
	if err != nil {
		t.Fatalf("DefaultConfigDir with override: %v", err)
	}
	if want := filepath.Join(parent, rel); got != want {
		t.Fatalf("override not absolutized: got %s, want %s", got, want)
	}

	stateDir, err := RealDeps().StateDir()
	if err != nil {
		t.Fatalf("RealDeps().StateDir() with override: %v", err)
	}
	if stateDir != got {
		t.Fatalf("production StateDir seam ignored the override: got %s, want %s", stateDir, got)
	}
	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		t.Fatalf("override state dir was not created by the seam: %v", err)
	}
	// The durable documents the session owns must resolve inside it.
	for _, name := range []string{vault.RegistryFile, vault.CatalogFile, vault.LocatorFile} {
		if p := filepath.Join(stateDir, name); filepath.Dir(p) != stateDir {
			t.Fatalf("document %s resolved outside the override: %s", name, p)
		}
	}
}
