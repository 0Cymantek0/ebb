// cmd_config_test.go: `ebb config` coverage over the eHarness world —
// each subcommand's happy path, the §17.2 envelope shape, the usage
// classes (unknown key, bad value, remove-absent), insertion-ordered
// add→list, and EBB_STATE_DIR isolation through the production wiring.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/config"
	"ebb/internal/vault"
)

func configFileOf(t *testing.T, dir string) string {
	t.Helper()
	return filepath.Join(dir, config.File)
}

func TestConfigAddThenListPreservesOrder(t *testing.T) {
	h := newEHarness(t)
	a, b := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")

	if code, _, stderr := h.run("config", "add", "projects_dir", a); code != ExitOK {
		t.Fatalf("add 1 code = %d, stderr = %s", code, stderr)
	}
	if code, _, stderr := h.run("config", "add", "projects_dir", b); code != ExitOK {
		t.Fatalf("add 2 code = %d, stderr = %s", code, stderr)
	}
	// The document lives in the state dir (EBB_STATE_DIR isolation at the
	// seam level: the harness state dir IS the override).
	if _, err := os.Stat(configFileOf(t, h.stateDir)); err != nil {
		t.Fatalf("config.json not in the state dir: %v", err)
	}

	code, _, stderr := h.run("config", "list")
	if code != ExitOK {
		t.Fatalf("list code = %d, stderr = %s", code, stderr)
	}
	aIdx, bIdx := strings.Index(stderr, a), strings.Index(stderr, b)
	if aIdx < 0 || bIdx < 0 || aIdx > bIdx {
		t.Fatalf("list lost insertion order:\n%s", stderr)
	}
	// A duplicate add (same root, different spelling) is a no-op.
	if code, _, stderr := h.run("config", "add", "projects_dir", strings.ToUpper(a)); code != ExitOK {
		t.Fatalf("case-variant add code = %d, stderr = %s", code, stderr)
	}
	c, err := config.Load(h.stateDir)
	if err != nil || len(c.ProjectsDirs()) != 2 {
		t.Fatalf("after case-variant add: %v (%v)", c.ProjectsDirs(), err)
	}
}

func TestConfigJSONEnvelopeShape(t *testing.T) {
	h := newEHarness(t)
	a := filepath.Join(t.TempDir(), "only-root")
	if code, _, stderr := h.run("config", "add", "projects_dir", a); code != ExitOK {
		t.Fatalf("add code = %d, stderr = %s", code, stderr)
	}

	code, stdout, _ := h.run("config", "--json", "list")
	if code != ExitOK {
		t.Fatalf("list --json code = %d", code)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "command") != "config" || envString(t, env, "outcome") != "ok" {
		t.Fatalf("envelope head = %v", env)
	}
	// operation_id is intentionally absent (config has no operation).
	if _, has := env["operation_id"]; has {
		t.Errorf("operation_id must be omitted: %v", env["operation_id"])
	}
	det := env["details"].(map[string]any)
	if det["schema_version"].(float64) != 1 {
		t.Errorf("schema_version = %v", det["schema_version"])
	}
	dirs, _ := det["projects_dir"].([]any)
	if len(dirs) != 1 || dirs[0].(string) != a {
		t.Errorf("details.projects_dir = %v, want [%s]", det["projects_dir"], a)
	}
	// get carries the same details contract.
	code, stdout, _ = h.run("config", "get", "--json", "projects_dir")
	if code != ExitOK {
		t.Fatalf("get --json code = %d", code)
	}
	env = envelopeOf(t, stdout)
	det = env["details"].(map[string]any)
	if dirs, _ := det["projects_dir"].([]any); len(dirs) != 1 {
		t.Errorf("get details = %v", det)
	}
}

func TestConfigSetReplacesWholeList(t *testing.T) {
	h := newEHarness(t)
	a, b, c := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b"), filepath.Join(t.TempDir(), "c")
	for _, p := range []string{a, b} {
		if code, _, stderr := h.run("config", "add", "projects_dir", p); code != ExitOK {
			t.Fatalf("add %s code = %d, stderr = %s", p, code, stderr)
		}
	}
	if code, _, stderr := h.run("config", "set", "projects_dir", c); code != ExitOK {
		t.Fatalf("set code = %d, stderr = %s", code, stderr)
	}
	cfg, err := config.Load(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.ProjectsDirs()
	if len(got) != 1 || got[0] != c {
		t.Fatalf("set must replace the whole list; got %v", got)
	}
	// A relative value is refused and changes nothing.
	code, _, stderr := h.run("config", "set", "projects_dir", "relative/path")
	if code != ExitUsage {
		t.Fatalf("relative set code = %d, want %d (stderr %s)", code, ExitUsage, stderr)
	}
	if !strings.Contains(stderr, CodeConfigBadValue) || !strings.Contains(stderr, "Safe action") {
		t.Errorf("relative set must carry the §5.5 shape:\n%s", stderr)
	}
	cfg, _ = config.Load(h.stateDir)
	if got := cfg.ProjectsDirs(); len(got) != 1 || got[0] != c {
		t.Fatalf("rejected set mutated the document: %v", got)
	}
}

func TestConfigRemoveHappyAndAbsent(t *testing.T) {
	h := newEHarness(t)
	a := filepath.Join(t.TempDir(), "root")
	if code, _, stderr := h.run("config", "add", "projects_dir", a); code != ExitOK {
		t.Fatalf("add code = %d, stderr = %s", code, stderr)
	}
	if code, _, stderr := h.run("config", "remove", "projects_dir", a); code != ExitOK {
		t.Fatalf("remove code = %d, stderr = %s", code, stderr)
	}
	cfg, _ := config.Load(h.stateDir)
	if len(cfg.ProjectsDirs()) != 0 {
		t.Fatalf("remove left entries: %v", cfg.ProjectsDirs())
	}
	code, _, stderr := h.run("config", "remove", "projects_dir", a)
	if code != ExitUsage {
		t.Fatalf("remove-absent code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, CodeConfigNotPresent) || !strings.Contains(stderr, "Safe action") {
		t.Errorf("remove-absent must carry the §5.5 shape:\n%s", stderr)
	}
}

func TestConfigUnknownKeyAndSubcommandUsage(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("config", "get", "auto_prune")
	if code != ExitUsage {
		t.Fatalf("unknown key code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, CodeConfigUnknownKey) {
		t.Errorf("unknown key must carry the stable code:\n%s", stderr)
	}
	if code, _, _ := h.run("config", "set", "bogus_key", "x"); code != ExitUsage {
		t.Fatalf("set unknown key code = %d, want %d", code, ExitUsage)
	}
	if code, _, _ := h.run("config", "frobnicate"); code != ExitUsage {
		t.Fatalf("unknown subcommand code = %d, want %d", code, ExitUsage)
	}
	if code, _, _ := h.run("config"); code != ExitUsage {
		t.Fatalf("bare config code = %d, want %d", code, ExitUsage)
	}
	if code, _, _ := h.run("config", "set", "projects_dir"); code != ExitUsage {
		t.Fatalf("missing value code = %d, want %d", code, ExitUsage)
	}
}

// TestConfigStateDirIsolationViaRealDeps pins that the PRODUCTION
// wiring (RealDeps().StateDir -> EnsureConfigDir -> DefaultConfigDir)
// places the document inside the EBB_STATE_DIR override, never the real
// per-user state.
func TestConfigStateDirIsolationViaRealDeps(t *testing.T) {
	override := t.TempDir()
	t.Setenv(vault.EnvStateDir, override)
	root := filepath.Join(t.TempDir(), "scanroot")

	var out, errb strings.Builder
	code := Main([]string{"config", "add", "projects_dir", root}, Streams{Out: &out, Err: &errb}, RealDeps())
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, errb.String())
	}
	if _, err := os.Stat(filepath.Join(override, config.File)); err != nil {
		t.Fatalf("config.json must live inside the EBB_STATE_DIR override: %v", err)
	}
	assertNoSecrets(t, errb.String())
	assertNoSecrets(t, out.String())
}

func TestConfigOutputsCarryNoSecrets(t *testing.T) {
	h := newEHarness(t)
	a := filepath.Join(t.TempDir(), "root")
	code, stdout, stderr := h.run("config", "--json", "add", "projects_dir", a)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	assertNoSecrets(t, stdout)
	assertNoSecrets(t, stderr)
}
