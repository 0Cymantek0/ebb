package gitadapter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The child environment must be constructed, never inherited: every
// GIT_* spelling (including case-mangled Windows forms) is absent, the
// hardened variables are set, and nothing outside the minimal OS
// substrate leaks through (D004 rule 1; lab/git-probe H1/H2, O23).

func TestChildEnvScrubsAllGitSpellings(t *testing.T) {
	inherited := []string{
		"PATH=/usr/bin:/bin",
		"GIT_DIR=/evil/repo/.git",
		"git_dir=/evil/repo/.git",    // case-mangled (Windows lookup is case-insensitive)
		"Git_Index_File=/evil/index", // mixed case
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_0=core.fsmonitor",
		"GIT_CONFIG_VALUE_0=/evil/fsm",
		"GIT_EXTERNAL_DIFF=/evil/diff",
		"GIT_CONFIG=/evil/config",
		"HOME=/home/attacker",
		"XDG_CONFIG_HOME=/evil/xdg",
		"USERPROFILE=C:\\evil",
		"GIT_ALLOW_PROTOCOL=file",
	}
	env := childEnv(inherited, "/safe/home", "/safe/home/gitconfig", "/safe/parent")

	hardened := map[string]string{
		"GIT_CONFIG_NOSYSTEM":     "1",
		"GIT_CONFIG_GLOBAL":       "/safe/home/gitconfig",
		"GIT_TERMINAL_PROMPT":     "0",
		"GIT_OPTIONAL_LOCKS":      "0",
		"GIT_NO_LAZY_FETCH":       "1",
		"GIT_ALLOW_PROTOCOL":      "none",
		"GIT_ATTR_NOSYSTEM":       "1",
		"GIT_CEILING_DIRECTORIES": "/safe/parent",
		"GIT_PAGER":               "cat",
	}
	seenHardened := map[string]string{}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		up := strings.ToUpper(name)
		if strings.HasPrefix(up, "GIT_") {
			want, ok := hardened[up]
			if !ok {
				t.Errorf("unexpected GIT_* variable survived construction: %s", kv)
				continue
			}
			seenHardened[up] = value
			if value != want {
				t.Errorf("%s = %q, want %q", name, value, want)
			}
			continue
		}
		switch up {
		case "HOME":
			if value != "/safe/home" {
				t.Errorf("HOME = %q, want the Ebb-owned /safe/home", value)
			}
		case "PAGER":
			if value != "cat" {
				t.Errorf("PAGER = %q, want cat", value)
			}
		case "XDG_CONFIG_HOME", "USERPROFILE":
			t.Errorf("variable with global-config influence leaked: %s", kv)
		case "PATH":
			if value != "/usr/bin:/bin" {
				t.Errorf("PATH = %q, want inherited value", value)
			}
		}
	}
	for name := range hardened {
		if _, ok := seenHardened[name]; !ok {
			t.Errorf("hardened variable %s not set", name)
		}
	}
}

func TestEnvBoxCreatesEmptyGlobalConfigFile(t *testing.T) {
	root := t.TempDir()
	box, err := newEnvBox(root)
	if err != nil {
		t.Fatalf("newEnvBox: %v", err)
	}
	defer box.cleanup()

	fi, err := os.Stat(box.cfg)
	if err != nil {
		t.Fatalf("GIT_CONFIG_GLOBAL file missing: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("GIT_CONFIG_GLOBAL file is %d bytes, want empty", fi.Size())
	}
	// HOME must point at the private dir and the ceiling at the root's parent.
	for _, kv := range box.env {
		name, value, _ := strings.Cut(kv, "=")
		switch name {
		case "HOME":
			if value != box.dir {
				t.Errorf("HOME = %q, want %q", value, box.dir)
			}
		case "GIT_CONFIG_GLOBAL":
			if value != box.cfg {
				t.Errorf("GIT_CONFIG_GLOBAL = %q, want %q", value, box.cfg)
			}
		case "GIT_CEILING_DIRECTORIES":
			want := filepath.Dir(root)
			if value != want {
				t.Errorf("GIT_CEILING_DIRECTORIES = %q, want %q", value, want)
			}
		}
	}
	box.cleanup()
	if _, err := os.Stat(box.dir); !os.IsNotExist(err) {
		t.Errorf("private env dir survived cleanup: %v", err)
	}
}

// Integration: an inherited hostile GIT_DIR must not retarget Observe
// (lab/git-probe H1).
func TestObserveIgnoresInheritedGitDir(t *testing.T) {
	requireGit(t)
	benign := t.TempDir()
	initRepo(t, benign)
	writeAndCommit(t, benign, "benign.txt", "benign\n")

	hostile := t.TempDir()
	initRepo(t, hostile)
	writeAndCommit(t, hostile, "hostile.txt", "hostile\n")

	t.Setenv("GIT_DIR", filepath.Join(hostile, ".git"))
	obs, err := Observe(t.Context(), benign)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	if !obs.IsRepo {
		t.Fatal("benign repo not observed")
	}
	if !obs.AdminInsideRoot {
		t.Errorf("benign admin not inside root: gitdir=%s", obs.GitDir)
	}
	// Compare in git's canonical path form (t.TempDir may be 8.3-short).
	hostileCanon := canonicalToplevel(t, hostile)
	if samePath(obs.GitDir, filepath.Join(hostileCanon, ".git")) {
		t.Errorf("observation redirected to hostile repo: gitdir=%s", obs.GitDir)
	}
	if len(obs.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", obs.Warnings)
	}
}
