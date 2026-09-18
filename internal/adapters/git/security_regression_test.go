package gitadapter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Security regression tests for the lab/security-review findings that
// were fixed after the Wave C audit (see Learnings.md, security
// checkpoint 2026-09-18). Unlike the lab PoCs these run against the
// shipped code and stay green.

func gitSetup(t *testing.T, extraConfig string) string {
	t.Helper()
	return gitSetupAt(t, t.TempDir(), extraConfig)
}

func gitSetupAt(t *testing.T, repo, extraConfig string) string {
	t.Helper()
	cmd := exec.Command("git", "init", "-q", ".")
	cmd.Dir = repo
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if extraConfig != "" {
		f, err := os.OpenFile(filepath.Join(repo, ".git", "config"), os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(extraConfig); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	return repo
}

func gitConfigList(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "config", "--list", "--show-origin", "--show-scope")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_NOSYSTEM=1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git config --list: %v\n%s", err, out)
	}
	return string(out)
}

// GIT-NEUT-1: both case-variant spellings of a filter execution key
// must collect their own override; dedup is on the exact key.
func TestNeutralizationCollectsBothCaseVariants(t *testing.T) {
	repo := gitSetup(t, "[filter \"MiXeD\"]\n\tclean = x\n[filter \"mixed\"]\n\tclean = y\n")
	inv := parseConfigList(gitConfigList(t, repo))
	got := map[string]bool{}
	for _, k := range inv.overrideKeys {
		got[k] = true
	}
	if !got["filter.MiXeD.clean"] || !got["filter.mixed.clean"] {
		t.Fatalf("expected both exact spellings neutralized, got %v", inv.overrideKeys)
	}
}

// GIT-NEUT-2: an execution key whose subsection contains '=' cannot be
// neutralized by any -c spelling; parseConfigList must flag it so
// Observe refuses.
func TestNeutralizationFlagsEqualsSubsection(t *testing.T) {
	repo := gitSetup(t, "[filter \"a=b\"]\n\tclean = marker\n")
	inv := parseConfigList(gitConfigList(t, repo))
	if len(inv.unneutralizable) == 0 {
		t.Fatalf("expected unneutralizable flag for filter.\"a=b\".clean, overrides=%v", inv.overrideKeys)
	}
	// And Observe refuses on it.
	if _, err := Observe(context.Background(), repo); err == nil ||
		!strings.Contains(err.Error(), "cannot be neutralized") {
		t.Fatalf("expected refusal error, got %v", err)
	}
}

// A benign value containing '=' after a fully-formed execution key is
// NOT flagged (first-'='-split yields the exact key, which -c can
// address).
func TestNeutralizationBenignEqualsValueNotFlagged(t *testing.T) {
	repo := gitSetup(t, "[filter \"x\"]\n\tclean = a=b\n")
	inv := parseConfigList(gitConfigList(t, repo))
	if len(inv.unneutralizable) != 0 {
		t.Fatalf("false positive: %v", inv.unneutralizable)
	}
	if len(inv.overrideKeys) != 1 || inv.overrideKeys[0] != "filter.x.clean" {
		t.Fatalf("expected filter.x.clean collected, got %v", inv.overrideKeys)
	}
}

// GIT-WT-1: administration inside the root + work tree redirected to an
// ancestor must refuse observation before any status run. (A redirect to
// an unrelated directory makes --is-inside-work-tree false, status is
// skipped, and no escape occurs.)
func TestObserveRefusesWorktreeEscape(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real git observation")
	}
	parent := t.TempDir()
	repo := filepath.Join(parent, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	gitSetupAt(t, repo, "[core]\n\tworktree = "+filepath.ToSlash(parent)+"\n")
	_, err := Observe(context.Background(), repo)
	if err == nil || !strings.Contains(err.Error(), "work tree is") {
		t.Fatalf("expected worktree-escape refusal, got %v", err)
	}
}

// GIT-GM-1: with no work-tree toplevel, .gitmodules must not be probed
// via a process-CWD-relative path.
func TestObserveSkipsGitmodulesWithoutToplevel(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real git observation")
	}
	parent := t.TempDir()
	victim := filepath.Join(parent, "victim")
	if err := os.MkdirAll(victim, 0o700); err != nil {
		t.Fatal(err)
	}
	repo := gitSetup(t, "[core]\n\tworktree = "+filepath.ToSlash(victim)+"\n")
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, ".gitmodules"),
		[]byte("[submodule \"cwd-leak\"]\n\tpath = x\n\turl = https://evil.example/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	obs, err := Observe(context.Background(), repo)
	if err != nil {
		t.Fatalf("Observe: %v", err)
	}
	for _, s := range obs.Submodules {
		if strings.Contains(s, "cwd-leak") {
			t.Fatalf("GIT-GM-1 regression: submodule names attributed from process CWD: %v", obs.Submodules)
		}
	}
}
