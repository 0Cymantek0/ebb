package gitadapter

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The argv allowlist is the load-bearing regression net against unknown
// future config-execution knobs (D004 consequence). Non-builtins are the
// arbitrary-execution channel because aliases CAN shadow them
// (lab/git-probe O21); filter-applying commands (diff, add, ls-files -m)
// are the validated attack surface (C5-C7).

func TestAllowlistAcceptsExactShapes(t *testing.T) {
	for _, argv := range allowedArgv {
		if err := allowlistCheck(argv); err != nil {
			t.Errorf("allowlistCheck(%q) = %v, want accepted", argv, err)
		}
	}
}

func TestAllowlistRejectsHostileAndDriftedArgv(t *testing.T) {
	rejected := [][]string{
		nil,
		{"diff"},                            // runs diff.external (C5)
		{"diff", "--no-ext-diff"},           // still runs textconv (C6)
		{"add", "."},                        // runs clean filters (C7)
		{"ls-files", "-m"},                  // fires clean filters (FINDINGS §1)
		{"lfs", "fsck"},                     // non-builtin, mutation-capable
		{"probe-evil"},                      // alias-defined non-builtin (C9)
		{"stash", "push"},                   // mutation
		{"submodule", "update"},             // executes child git (C11)
		{"checkout", "--", "."},             // mutation
		{"gc", "--prune=now"},               // mutation
		{"fetch", "origin"},                 // network
		{"config", "--file", "/evil", "-l"}, // extra config surface
		{"rev-parse", "--absolute-git-dir", "--git-dir", "--git-common-dir"}, // reordered: not a validated shape
		{"rev-parse", "--git-dir"}, // partial
		{"status"},                 // unpinned format
		{"status", "--porcelain=v2", "--branch", "--ignore-submodules=all", "--extra"},
		{"symbolic-ref", "HEAD", "refs/heads/main"},
		{"worktree", "list"}, // human format
		{"--version", "--extra"},
	}
	for _, argv := range rejected {
		if err := allowlistCheck(argv); err == nil {
			t.Errorf("allowlistCheck(%q) accepted, want rejected", argv)
		}
	}
}

// Code-level guarantee: the runner refuses non-allowlisted argv before
// spawning any process, so no future call site can smuggle a hostile
// command through the hardened prefix.
func TestRunnerRefusesNonAllowlistedWithoutSpawning(t *testing.T) {
	requireGit(t)
	r := &runner{env: childEnv(nil, t.TempDir(), filepath.Join(t.TempDir(), "g"), t.TempDir())}
	// A nonexistent cwd proves no process was started: the allowlist
	// error must arrive without a chdir/spawn error.
	_, _, _, err := r.run(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"),
		time.Second, "probe-evil")
	if err == nil {
		t.Fatal("run(probe-evil) succeeded, want allowlist rejection")
	}
	if !strings.Contains(err.Error(), "not in observation allowlist") {
		t.Fatalf("run(probe-evil) error = %v, want allowlist rejection", err)
	}
}
