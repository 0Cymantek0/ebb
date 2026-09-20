// config_test.go pins the config document contract: missing file =
// zero config, atomic save, the add/dedup/case rule, the 32-entry cap,
// remove-absent, unknown keys, relative-path rejection, and
// EBB_STATE_DIR isolation through vault.DefaultConfigDir.

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/vault"
)

func mustAdd(t *testing.T, c *Config, path string) {
	t.Helper()
	if err := c.AddProjectsDir(path); err != nil {
		t.Fatalf("AddProjectsDir(%q): %v", path, err)
	}
}

func TestLoadMissingFileIsZeroConfig(t *testing.T) {
	dir := t.TempDir()
	c, err := Load(dir)
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if got := c.ProjectsDirs(); len(got) != 0 {
		t.Fatalf("want empty projects_dir, got %v", got)
	}
	if _, ok := c.Get(KeyProjectsDir); !ok {
		t.Fatal("projects_dir must be a KNOWN key even when empty")
	}
}

func TestSaveLoadRoundTripPreservesOrder(t *testing.T) {
	dir := t.TempDir()
	c := &Config{}
	first := filepath.Join(t.TempDir(), "alpha")
	second := filepath.Join(t.TempDir(), "beta")
	mustAdd(t, c, first)
	mustAdd(t, c, second)
	if err := c.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}

	back, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := back.ProjectsDirs()
	if len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("round trip lost insertion order: %v", got)
	}
	// The document is schema v1 with the documented field names.
	data, err := os.ReadFile(filepath.Join(dir, File))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"schema_version": 1`) ||
		!strings.Contains(string(data), `"projects_dir"`) {
		t.Fatalf("document shape drifted:\n%s", data)
	}
}

func TestSaveCreatesDirectoryAndIsAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	c := &Config{}
	mustAdd(t, c, filepath.Join(t.TempDir(), "root"))
	if err := c.Save(dir); err != nil {
		t.Fatalf("Save must create the directory: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dir, File)); err != nil || fi.Size() == 0 {
		t.Fatalf("config.json missing or empty: %v", err)
	}
	// No temp debris after a successful save.
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 || des[0].Name() != File {
		t.Fatalf("save left debris: %v", des)
	}
}

func TestSaveFailureLeavesNoPartialAndNoDebris(t *testing.T) {
	dir := t.TempDir()
	// config.json occupied by a DIRECTORY: write+rename must fail, and
	// the temp file must be cleaned up (no partial, no debris).
	if err := os.Mkdir(filepath.Join(dir, File), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &Config{}
	mustAdd(t, c, filepath.Join(t.TempDir(), "root"))
	err := c.Save(dir)
	if err == nil {
		t.Fatal("save over a directory must fail")
	}
	des, rerr := os.ReadDir(dir)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(des) != 1 || des[0].Name() != File {
		t.Fatalf("failed save left debris or a partial: %v", des)
	}
}

func TestAddAbsolutizesCleansAndDedups(t *testing.T) {
	c := &Config{}
	root := filepath.Join(t.TempDir(), "scan-root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// A RELATIVE spelling is accepted (Abs against the cwd) and stored
	// absolute + cleaned. Nonexistence on disk is accepted (offline
	// drives), so a nonexistent child works too.
	t.Chdir(filepath.Dir(root))
	mustAdd(t, c, filepath.Join(".", filepath.Base(root)))
	mustAdd(t, c, filepath.Join(root, "child", ".."))
	mustAdd(t, c, filepath.Join(filepath.Dir(root), strings.ToUpper(filepath.Base(root))))
	got := c.ProjectsDirs()
	if len(got) != 1 || got[0] != root {
		t.Fatalf("dedup/abs/clean rule: want [%s], got %v", root, got)
	}
	// The case tiebreaker: a case-variant spelling is a duplicate (the
	// documented Windows-semantics rule, applied host-agnostically).
	mustAdd(t, c, strings.ToUpper(root))
	if got := c.ProjectsDirs(); len(got) != 1 {
		t.Fatalf("case-variant duplicated: %v", got)
	}
}

func TestAddEnforcesCapOf32(t *testing.T) {
	c := &Config{}
	base := t.TempDir()
	for i := 0; i < MaxListValues; i++ {
		mustAdd(t, c, filepath.Join(base, "w", string(rune('a'+i/26))+string(rune('a'+i%26))))
	}
	if got := len(c.ProjectsDirs()); got != MaxListValues {
		t.Fatalf("setup: want %d entries, got %d", MaxListValues, got)
	}
	err := c.AddProjectsDir(filepath.Join(base, "one-too-many"))
	if !errors.Is(err, ErrTooManyValues) {
		t.Fatalf("33rd entry error = %v, want ErrTooManyValues", err)
	}
	if got := len(c.ProjectsDirs()); got != MaxListValues {
		t.Fatalf("rejected add still mutated the list: %d", got)
	}
}

func TestRemoveHappyAndAbsent(t *testing.T) {
	c := &Config{}
	root := filepath.Join(t.TempDir(), "gone")
	mustAdd(t, c, root)
	if err := c.RemoveProjectsDir(root); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	err := c.RemoveProjectsDir(root)
	if !errors.Is(err, ErrNotPresent) {
		t.Fatalf("remove-absent error = %v, want ErrNotPresent", err)
	}
	// Any spelling that Add would normalize matches for Remove too.
	mustAdd(t, c, root)
	if err := c.RemoveProjectsDir(strings.ToUpper(root)); err != nil {
		t.Fatalf("case-variant remove: %v", err)
	}
}

func TestUnknownKeyIsTyped(t *testing.T) {
	c := &Config{}
	if _, ok := c.Get("auto_prune"); ok {
		t.Fatal("unknown key must not resolve")
	}
	if err := c.Set("auto_prune", []string{"yes"}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("Set(unknown) = %v, want ErrUnknownKey", err)
	}
}

func TestSetReplacesWholeListAndValidates(t *testing.T) {
	c := &Config{}
	mustAdd(t, c, filepath.Join(t.TempDir(), "old"))
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	if err := c.Set(KeyProjectsDir, []string{a, b, a}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got := c.ProjectsDirs()
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("Set must replace and dedup: %v", got)
	}
	if err := c.Set(KeyProjectsDir, []string{"relative/path"}); !errors.Is(err, ErrRelativePath) {
		t.Fatalf("Set(relative) = %v, want ErrRelativePath", err)
	}
	// The rejected Set left the previous list intact.
	if got := c.ProjectsDirs(); len(got) != 2 {
		t.Fatalf("rejected Set mutated the list: %v", got)
	}
}

func TestLoadRejectsFutureSchemaAndBadValues(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, File),
		[]byte(`{"schema_version":2,"projects_dir":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("future schema error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, File),
		[]byte(`{"schema_version":1,"projects_dir":["relative"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); !errors.Is(err, ErrRelativePath) {
		t.Fatalf("hand-edited relative path error = %v", err)
	}
}

// TestEBBStateDirIsolation pins that the state-dir authority places the
// document inside the EBB_STATE_DIR override (config.json lives beside
// catalog.db).
func TestEBBStateDirIsolation(t *testing.T) {
	override := t.TempDir()
	t.Setenv(vault.EnvStateDir, override)
	dir, err := vault.DefaultConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if dir != override {
		t.Fatalf("override ignored: %s", dir)
	}
	c := &Config{}
	mustAdd(t, c, filepath.Join(t.TempDir(), "root"))
	if err := c.Save(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(override, File)); err != nil {
		t.Fatalf("config.json must live inside the override: %v", err)
	}
	back, err := Load(dir)
	if err != nil || len(back.ProjectsDirs()) != 1 {
		t.Fatalf("load from override: %v (%v)", back, err)
	}
}

// TestDocumentsContainNoSecretShape is a light tripwire: the only
// keys the document may carry are the schema v1 names.
func TestDocumentShapeIsPathsOnly(t *testing.T) {
	dir := t.TempDir()
	c := &Config{}
	mustAdd(t, c, filepath.Join(t.TempDir(), "root"))
	if err := c.Save(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, File))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, forbidden := range []string{"password", "token", "secret", "passphrase"} {
		if strings.Contains(strings.ToLower(s), forbidden) {
			t.Fatalf("document leaked a secret-shaped key:\n%s", s)
		}
	}
}
