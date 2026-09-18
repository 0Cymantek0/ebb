package gitadapter

// Shared fixture helpers for the integration tests. Fixture SETUP may
// use plain inherited-environment git (it builds test state, never
// observes it); the observation under test is always Observe(), and
// control arms use runPlainGit explicitly to reproduce attacks
// (lab/git-probe methodology: an attack that cannot be reproduced cannot
// prove a defense).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ebb/internal/domain"
)

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not available on PATH: %v", err)
	}
}

// runGit runs fixture-setup git (inherited env; writes allowed).
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := tryGit(t, dir, args...)
	if err != nil {
		t.Fatalf("setup git %v (cwd %s): %v", args, dir, err)
	}
	return out
}

// tryGit runs git and reports failure instead of failing the test
// (expected-conflict and best-effort cleanup paths).
func tryGit(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return out.String() + errb.String(), fmt.Errorf("%v: %w\n%s", args, err, (out.String() + errb.String()))
	}
	return out.String(), nil
}

// runPlainGit is the CONTROL arm: git with the inherited environment
// (plus extras such as a hostile HOME). Observation code never calls it.
func runPlainGit(t *testing.T, dir string, extraEnv []string, args ...string) int {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = mergeEnv(os.Environ(), extraEnv)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		t.Fatalf("control git %v: %v", args, err)
	}
	return 0
}

// runEnvGit runs git with an explicitly constructed environment
// (control-arm variant for "hardened minus one layer" comparisons).
func runEnvGit(t *testing.T, dir string, env []string, args ...string) int {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		t.Fatalf("env git %v: %v", args, err)
	}
	return 0
}

// mergeEnv appends overrides, removing any inherited entry with the same
// name first (Windows env lookup is case-insensitive).
func mergeEnv(base, extra []string) []string {
	names := make([]string, len(extra))
	for i, kv := range extra {
		names[i] = kv[:strings.IndexByte(kv, '=')]
	}
	drop := func(n string) bool {
		for _, name := range names {
			if n == name || (runtime.GOOS == "windows" && strings.EqualFold(n, name)) {
				return true
			}
		}
		return false
	}
	var out []string
	for _, kv := range base {
		eq := strings.IndexByte(kv, '=')
		if eq > 0 && drop(kv[:eq]) {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

func initRepo(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "-c", "init.defaultBranch=main", "init", "-q", ".")
	runGit(t, dir, "config", "user.email", "ebb@test.local")
	runGit(t, dir, "config", "user.name", "Ebb Test")
	// Byte-deterministic fixtures regardless of the machine's system
	// config (this host's system core.autocrlf=true rewrites LF<->CRLF;
	// see Learnings). The observation itself never sees system config.
	runGit(t, dir, "config", "core.autocrlf", "false")
}

// canonicalToplevel returns the worktree root as git itself spells it
// (long-form), for test assertions against observation paths.
func canonicalToplevel(t *testing.T, dir string) string {
	t.Helper()
	return strings.TrimSpace(runGit(t, dir, "rev-parse", "--show-toplevel"))
}

func writeRepoFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func commitAll(t *testing.T, dir, msg string) {
	t.Helper()
	runGit(t, dir, "add", "-A")
	runGit(t, dir, "commit", "-qm", msg)
}

func writeAndCommit(t *testing.T, dir, rel, content string) {
	t.Helper()
	writeRepoFile(t, dir, rel, content)
	commitAll(t, dir, "commit "+rel)
}

// makeStatDirty forces a stat-dirty state with unchanged content and
// size (the precondition for git's content comparison, which is what
// runs clean filters / queries fsmonitor). The mtime is bumped into the
// future: setting it to "now" races with the index's own timestamp —
// a same-tick Chtimes leaves the entry clean and the control arm silent.
func makeStatDirty(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

// markerScript writes a POSIX-sh script that creates markerPath when
// executed and returns the script path. Git for Windows executes
// shebang scripts via its bundled sh — validated by every control arm in
// lab/git-probe (C1-C12) on this platform — so .sh is used everywhere.
func markerScript(t *testing.T, binDir, name, markerPath string) string {
	t.Helper()
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(binDir, name+".sh")
	content := "#!/bin/sh\ntouch '" + filepath.ToSlash(markerPath) + "'\nexit 0\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// gitConfigValue formats a path for use as a git config value
// (forward-slash C:/ form, as the probe's win() helper produced).
func gitConfigValue(path string) string { return filepath.ToSlash(path) }

func resetMarker(t *testing.T, marker string) {
	t.Helper()
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

// assertMarkerFired is the CONTROL-arm assertion: the attack must
// reproduce, or the methodology has a hole.
func assertMarkerFired(t *testing.T, marker, attack string) {
	t.Helper()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("control arm failed: attack %s did NOT fire (marker %s absent) — methodology hole", attack, marker)
	}
}

func assertMarkerAbsent(t *testing.T, marker, attack string) {
	t.Helper()
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("FORBIDDEN: attack %s executed under hardened observation (marker %s present)", attack, marker)
	}
}

// snapshotGitDir records every file under .git with its size, for the
// no-mutation watchdog (lab/git-probe O18).
func snapshotGitDir(t *testing.T, gitDir string) map[string]int64 {
	t.Helper()
	snap := map[string]int64{}
	err := filepath.Walk(gitDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.Mode().IsRegular() {
			rel, rerr := filepath.Rel(gitDir, path)
			if rerr != nil {
				return rerr
			}
			snap[rel] = fi.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", gitDir, err)
	}
	return snap
}

func sameSnapshot(a, b map[string]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return "" // missing index (e.g. unborn repo)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// stopFsmonitorDaemon stops any fsmonitor--daemon registered against the
// repository and removes its state directory (fixture lifecycle).
func stopFsmonitorDaemon(t *testing.T, dir string) {
	t.Helper()
	_, _ = tryGit(t, dir, "fsmonitor--daemon", "stop")
	state := filepath.Join(dir, ".git", "fsmonitor--daemon")
	for i := 0; i < 10; i++ {
		if err := os.RemoveAll(state); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func fileURL(path string) string { return "file://" + filepath.ToSlash(path) }

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

func observeOK(t *testing.T, root string) domain.GitObservation {
	t.Helper()
	obs, err := Observe(t.Context(), root)
	if err != nil {
		t.Fatalf("Observe(%s): %v", root, err)
	}
	if !obs.IsRepo {
		t.Fatalf("Observe(%s): IsRepo = false, want true (warnings: %v)", root, obs.Warnings)
	}
	return obs
}

func hasBlocker(obs domain.GitObservation, code string) bool {
	for _, b := range obs.DestructiveParkBlockers() {
		if b == code {
			return true
		}
	}
	return false
}

func isHexCommit(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	return isHexString(s)
}

// waitFor polls check until it returns true or the timeout elapses.
func waitFor(timeout time.Duration, check func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return check()
}
