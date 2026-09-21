package gitadapter

// Regression battery for MutatingSession (D004/D005 discipline applied
// to the user-consented `git worktree remove` behind `ebb analyse
// --prune-worktrees`). Same methodology as hostile_test.go: every attack
// is first reproduced by a CONTROL arm (plain git with the inherited
// environment — exactly what the pre-fix execution path ran), then the
// hardened arm proves the marker absent while the mutation still
// happens.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMutatingWorktreeRemoveNeutralizesFsmonitor: a repository whose
// config points core.fsmonitor at a marker script executes that script
// during a plain `git -C <main> worktree remove <path>` (the removal's
// dirty check walks the worktree's index, which carries the FSMN
// extension; plain `worktree add` fires it too, so fixtures are built
// while the config is still clean). The MutatingSession invocation must
// remove the worktree without ever firing the script.
func TestMutatingWorktreeRemoveNeutralizesFsmonitor(t *testing.T) {
	requireGit(t)
	tmp := t.TempDir()
	main := filepath.Join(tmp, "main")
	initRepo(t, main)
	writeAndCommit(t, main, "f.txt", "one\n")

	mark := t.TempDir()
	mk := filepath.Join(mark, "fsm.mk")
	script := markerScript(t, mark, "fsmhook", mk)

	// Both worktrees exist BEFORE any config is armed: with the repo
	// armed even fixture verbs (worktree add) execute the hook.
	wtCtl := filepath.Join(tmp, "ctl-wt")
	wtHard := filepath.Join(tmp, "hard-wt")
	runGit(t, main, "worktree", "add", "-q", "-b", "ctl", wtCtl)
	runGit(t, main, "worktree", "add", "-q", "-b", "hard", wtHard)

	// seedFSMN seeds the FSMN extension on one linked worktree's own
	// index (the index `worktree remove` consults) and stops the daemon
	// (probe F1 sequence).
	seedFSMN := func(wt string) {
		runGit(t, wt, "-c", "core.fsmonitor=true", "update-index", "--fsmonitor")
		stopFsmonitorDaemon(t, main)
	}
	seedFSMN(wtCtl)
	runGit(t, wtCtl, "config", "core.fsmonitor", gitConfigValue(script))

	// CONTROL: plain inherited-env git fires the repo-configured hook
	// during the user-consented removal.
	runPlainGit(t, main, nil, "-C", main, "worktree", "remove", wtCtl)
	assertMarkerFired(t, mk, "core.fsmonitor during plain worktree remove")

	// HARDENED: the same removal through MutatingSession executes no
	// repo-configured code while still removing the worktree.
	seedFSMN(wtHard) // config stays armed from the control arm
	resetMarker(t, mk)

	sess, err := NewMutatingSession(t.Context(), main)
	if err != nil {
		t.Fatalf("NewMutatingSession: %v", err)
	}
	cmd, cerr := sess.Command(t.Context(), "-C", main, "worktree", "remove", wtHard)
	if cerr != nil {
		sess.Cleanup()
		t.Fatalf("session Command: %v", cerr)
	}
	out, rerr := cmd.CombinedOutput()
	sess.Cleanup()
	if rerr != nil {
		t.Fatalf("hardened worktree remove failed: %v\n%s", rerr, out)
	}
	assertMarkerAbsent(t, mk, "core.fsmonitor during hardened worktree remove")
	if _, serr := os.Stat(wtHard); !os.IsNotExist(serr) {
		t.Errorf("hardened removal did not remove the worktree (stat err=%v)", serr)
	}
	// git's administrative state stays consistent.
	listing := runGit(t, main, "worktree", "list", "--porcelain")
	if containsStrFlags(splitLines(listing), filepath.Base(wtHard)) {
		t.Errorf("git still lists the removed worktree:\n%s", listing)
	}
}

// TestMutatingSessionArgvAllowlist: the mutating surface admits exactly
// the fixed `[-C dir] worktree remove <path>` shape; anything else —
// including option-shaped paths and other verbs — is refused before a
// process spawns.
func TestMutatingSessionArgvAllowlist(t *testing.T) {
	accepted := [][]string{
		{"worktree", "remove", `C:\x\wt`},
		{"worktree", "remove", "/home/u/wt"},
		{"-C", "/anchor", "worktree", "remove", "/home/u/wt"},
	}
	for _, argv := range accepted {
		if err := mutatingArgvCheck(argv); err != nil {
			t.Errorf("mutatingArgvCheck(%q) = %v, want accepted", argv, err)
		}
	}
	rejected := [][]string{
		{"worktree", "remove"},
		{"worktree", "remove", "--force", "/x"},
		{"worktree", "remove", "-"},
		{"worktree", "list", "--porcelain"},
		{"worktree", "prune"},
		{"status", "--porcelain=v2"},
		{"-C", "/anchor", "worktree", "add", "/x", "-b", "evil"},
		{"config", "--list", "--show-origin", "--show-scope"},
		{"worktree", "remove", "/x", "extra"},
		{"rm", "-rf", "/x"},
	}
	for _, argv := range rejected {
		if err := mutatingArgvCheck(argv); err == nil {
			t.Errorf("mutatingArgvCheck(%q) accepted, want rejected", argv)
		}
	}
	// The static prefix carries every neutralization key the fix named.
	for _, want := range []string{
		"core.fsmonitor=false", "core.untrackedCache=false",
		"gc.auto=0", "maintenance.auto=false", "diff.external=",
		"core.hooksPath=", "core.attributesfile=",
		"--no-optional-locks", "--no-pager",
	} {
		if !containsStrFlags(mutatingGitFlags, want) {
			t.Errorf("mutatingGitFlags missing %q: %v", want, mutatingGitFlags)
		}
	}
}

func containsStrFlags(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// splitLines splits trimmed non-empty lines of captured output.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
