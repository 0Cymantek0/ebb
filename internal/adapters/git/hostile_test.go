package gitadapter

// Hostile fixture battery, porting lab/git-probe's control/hardened arm
// methodology to Go (D004). Methodology rule: every attack must first be
// reproduced by a CONTROL arm (plain git, or git missing exactly one
// hardening layer) asserting the marker file appeared; only then does the
// hardened arm (Observe) prove the marker absent. A defense that cannot
// be attacked reproducibly proves nothing.
//
// Windows note: marker scripts are POSIX sh with a shebang. Git for
// Windows executes shebang scripts through its bundled sh regardless of
// the caller's shell — validated by every control arm here (and by
// lab/git-probe C1-C12 on this platform).

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// V1 (probe C1/C2): core.fsmonitor=<script> executes during status
// whenever the index carries an FSMN token; --no-optional-locks does NOT
// stop it — only -c core.fsmonitor=false does.
func TestHostileFsmonitorHook(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "tracked.txt", "hello\n")

	mark := t.TempDir()
	script := markerScript(t, mark, "fsmhook", filepath.Join(mark, "fsmhook.mk"))
	tracked := filepath.Join(repo, "tracked.txt")

	// Seed the FSMN extension via the builtin daemon, then stop it and arm
	// the hostile hook path (probe F1 sequence).
	runGit(t, repo, "-c", "core.fsmonitor=true", "update-index", "--fsmonitor")
	stopFsmonitorDaemon(t, repo)
	runGit(t, repo, "config", "core.fsmonitor", gitConfigValue(script))

	// Control C1: plain status executes the hook.
	makeStatDirty(t, tracked)
	runPlainGit(t, repo, nil, "status", "--porcelain=v2", "--branch")
	assertMarkerFired(t, filepath.Join(mark, "fsmhook.mk"), "core.fsmonitor hook on plain status")
	resetMarker(t, filepath.Join(mark, "fsmhook.mk"))

	// Control C2: --no-optional-locks does NOT stop the fsmonitor hook —
	// the static -c override is required (not just the lock flag).
	makeStatDirty(t, tracked)
	runPlainGit(t, repo, nil, "--no-optional-locks", "status", "--porcelain=v2")
	assertMarkerFired(t, filepath.Join(mark, "fsmhook.mk"), "core.fsmonitor hook vs --no-optional-locks")
	resetMarker(t, filepath.Join(mark, "fsmhook.mk"))

	// Hardened arm.
	makeStatDirty(t, tracked)
	obs := observeOK(t, repo)
	assertMarkerAbsent(t, filepath.Join(mark, "fsmhook.mk"), "core.fsmonitor hook")
	if !obs.IsRepo || obs.HeadBranch != "refs/heads/main" {
		t.Errorf("observation degraded: %+v", obs)
	}
}

// V2 (probe C3/O6b): clean filters execute on stat-dirty size-matching
// files during status; the two-pass per-key empty overrides are what
// stops them (static flags alone do not).
func TestHostileCleanFilter(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	// The filter must be declared by attributes BEFORE the arm; committing
	// with the filter configured would already run it during setup.
	writeRepoFile(t, repo, ".gitattributes", "*.txt filter=evil\n")
	writeRepoFile(t, repo, "tracked.txt", "hello\n")
	commitAll(t, repo, "one")

	mark := t.TempDir()
	script := markerScript(t, mark, "cleansmudge", filepath.Join(mark, "cleansmudge.mk"))
	tracked := filepath.Join(repo, "tracked.txt")
	runGit(t, repo, "config", "filter.evil.clean", gitConfigValue(script))
	runGit(t, repo, "config", "filter.evil.smudge", gitConfigValue(script))

	// Control C3: plain status runs the clean filter.
	makeStatDirty(t, tracked)
	runPlainGit(t, repo, nil, "status", "--porcelain=v2")
	assertMarkerFired(t, filepath.Join(mark, "cleansmudge.mk"), "clean filter on plain status")
	resetMarker(t, filepath.Join(mark, "cleansmudge.mk"))

	// Control O6b: hardened env + static prefix WITHOUT the pass-1 per-key
	// overrides still fires the filter — proving the two-pass
	// neutralization is load-bearing.
	home := t.TempDir()
	cfgFile := filepath.Join(home, "gitconfig")
	if err := os.WriteFile(cfgFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := childEnv(os.Environ(), home, cfgFile, filepath.Dir(repo))
	makeStatDirty(t, tracked)
	argv := append(append([]string{}, staticGitFlags...), "status", "--porcelain=v2", "--ignore-submodules=all")
	if rc := runEnvGit(t, repo, env, argv...); rc != 0 {
		t.Fatalf("hardened-minus-neutralization status rc=%d", rc)
	}
	assertMarkerFired(t, filepath.Join(mark, "cleansmudge.mk"), "clean filter vs static-prefix-only")
	resetMarker(t, filepath.Join(mark, "cleansmudge.mk"))

	// Hardened arm.
	makeStatDirty(t, tracked)
	obs := observeOK(t, repo)
	assertMarkerAbsent(t, filepath.Join(mark, "cleansmudge.mk"), "clean filter")
	if !obs.IsRepo {
		t.Error("IsRepo = false")
	}
}

// V3 (probe C4): core.hooksPath + post-index-change fires when status
// refreshes the index — the observer's --no-optional-locks +
// GIT_OPTIONAL_LOCKS=0 must prevent both the write and the hook.
func TestHostilePostIndexChangeHook(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "ok\n")

	mark := t.TempDir()
	hooks := filepath.Join(mark, "evil-hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	pic := filepath.Join(mark, "pic.mk")
	hook := "#!/bin/sh\ntouch '" + filepath.ToSlash(pic) + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(hooks, "post-index-change"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "config", "core.hooksPath", gitConfigValue(hooks))

	f := filepath.Join(repo, "f.txt")
	idx := filepath.Join(repo, ".git", "index")

	// Control C4: plain status rewrites the index AND runs the hook.
	makeStatDirty(t, f)
	before := fileSHA256(t, idx)
	runPlainGit(t, repo, nil, "status", "--porcelain=v2")
	assertMarkerFired(t, pic, "post-index-change hook on plain status")
	if fileSHA256(t, idx) == before {
		t.Fatal("control arm: index not rewritten — stat-dirty state not established")
	}
	resetMarker(t, pic)

	// Hardened arm: no hook, no index write.
	makeStatDirty(t, f)
	before = fileSHA256(t, idx)
	obs := observeOK(t, repo)
	assertMarkerAbsent(t, pic, "post-index-change hook")
	if after := fileSHA256(t, idx); after != before {
		t.Error("hardened observation rewrote .git/index")
	}
	if !obs.IsRepo {
		t.Error("IsRepo = false")
	}
}

// V4-descent (probe C11): parent status descends into a submodule and
// executes the child repository's hostile config; the observer's
// --ignore-submodules=all (plus propagated -c overrides) removes the
// descent entirely.
func TestHostileSubmoduleFsmonitor(t *testing.T) {
	requireGit(t)
	tmp := t.TempDir()
	childSrc := filepath.Join(tmp, "child-src")
	parent := filepath.Join(tmp, "subparent")
	initRepo(t, childSrc)
	writeAndCommit(t, childSrc, "c.txt", "c\n")
	initRepo(t, parent)
	writeAndCommit(t, parent, "p.txt", "p\n")
	runGit(t, parent, "-c", "protocol.file.allow=always", "submodule", "add", "-q", gitConfigValue(childSrc), "child")
	runGit(t, parent, "commit", "-qm", "submodule")

	mark := t.TempDir()
	script := markerScript(t, mark, "fsmhook", filepath.Join(mark, "fsmhook.mk"))

	// Arm the child repo: seed its index FSMN, stop the child daemon, then
	// point the child's fsmonitor at the hostile hook (probe F4).
	child := filepath.Join(parent, "child")
	runGit(t, child, "-c", "core.fsmonitor=true", "update-index", "--fsmonitor")
	_, _ = tryGit(t, filepath.Join(parent, ".git", "modules", "child"), "fsmonitor--daemon", "stop")
	runGit(t, child, "config", "core.fsmonitor", gitConfigValue(script))

	// Control C11: plain PARENT status executes the CHILD's hook.
	makeStatDirty(t, filepath.Join(child, "c.txt"))
	runPlainGit(t, parent, nil, "status", "--porcelain=v2")
	assertMarkerFired(t, filepath.Join(mark, "fsmhook.mk"), "submodule child fsmonitor via parent status")
	resetMarker(t, filepath.Join(mark, "fsmhook.mk"))

	// Hardened arm.
	makeStatDirty(t, filepath.Join(child, "c.txt"))
	obs := observeOK(t, parent)
	assertMarkerAbsent(t, filepath.Join(mark, "fsmhook.mk"), "submodule child fsmonitor")
	if len(obs.Submodules) != 1 || obs.Submodules[0] != "child" {
		t.Errorf("Submodules = %v, want [child]", obs.Submodules)
	}
}

// Alias shadowing (probe C9/O20/O21): aliases cannot shadow builtins but
// CAN shadow non-builtin names, which is why the adapter's allowlist
// admits builtins only. The allowlist unit tests prove the code-level
// guarantee; this test proves the behavioral one.
func TestHostileAliasesCannotShadowBuiltins(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")

	mark := t.TempDir()
	builtinMk := filepath.Join(mark, "alias-builtin.mk")
	nonbuiltinMk := filepath.Join(mark, "alias-nonbuiltin.mk")
	builtin := markerScript(t, mark, "alias-builtin", builtinMk)
	nonbuiltin := markerScript(t, mark, "alias-nonbuiltin", nonbuiltinMk)
	runGit(t, repo, "config", "alias.status", "!"+gitConfigValue(builtin))
	runGit(t, repo, "config", "alias.rev-parse", "!"+gitConfigValue(builtin))
	runGit(t, repo, "config", "alias.probe-evil", "!"+gitConfigValue(nonbuiltin))

	// Control C9: a non-builtin alias IS an execution channel.
	runPlainGit(t, repo, nil, "probe-evil")
	assertMarkerFired(t, nonbuiltinMk, "non-builtin alias execution")
	resetMarker(t, nonbuiltinMk)

	// Hardened arm: observation runs status/rev-parse (builtin dispatch
	// wins) and never touches any alias-defined command.
	obs := observeOK(t, repo)
	assertMarkerAbsent(t, builtinMk, "alias shadowing a builtin")
	assertMarkerAbsent(t, nonbuiltinMk, "any alias execution")
	if !isHexCommit(obs.HeadCommit) || obs.HeadBranch != "refs/heads/main" {
		t.Errorf("observation degraded: %+v", obs)
	}
}

// Hostile include.path (D004 battery item 6): config includes are file
// reads that never execute, but the included keys must still be seen by
// pass 1 (so their execution knobs are neutralized) without executing
// anything. No execution control exists for a pure read; the remote-name
// assertion instead proves the include chain was actually followed, so
// this test cannot pass by ignoring the file.
func TestHostileIncludePathReadOnly(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "one\n")

	mark := t.TempDir()
	cleanMk := filepath.Join(mark, "cleansmudge.mk")
	script := markerScript(t, mark, "cleansmudge", cleanMk)
	inc := filepath.Join(mark, "evil-included.conf")
	incContent := "[remote \"inc\"]\n\turl = https://example.com/inc.git\n" +
		"[filter \"inc\"]\n\tclean = " + gitConfigValue(script) + "\n" +
		"[alias]\n\tfrom-include = !" + gitConfigValue(script) + "\n" +
		"[core]\n\tpager = " + gitConfigValue(script) + "\n"
	if err := os.WriteFile(inc, []byte(incContent), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "config", "include.path", gitConfigValue(inc))

	obs := observeOK(t, repo)
	assertMarkerAbsent(t, cleanMk, "include.path chain execution")
	var sawInc bool
	for _, r := range obs.Remotes {
		if r.Name == "inc" {
			sawInc = true
		}
	}
	if !sawInc {
		t.Errorf("include chain not followed by pass 1: remotes = %+v", obs.Remotes)
	}
}

// Hostile global config (probe C10/O23): an inherited hostile HOME must
// contribute nothing — the observer's GIT_CONFIG_GLOBAL is its own empty
// file and HOME its own private dir.
func TestHostileGlobalConfigNeutralized(t *testing.T) {
	requireGit(t)
	benign := t.TempDir()
	initRepo(t, benign)
	writeAndCommit(t, benign, "f.txt", "ok\n")

	mark := t.TempDir()
	hooks := filepath.Join(mark, "evil-hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	pic := filepath.Join(mark, "pic.mk")
	hook := "#!/bin/sh\ntouch '" + filepath.ToSlash(pic) + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(hooks, "post-index-change"), []byte(hook), 0o755); err != nil {
		t.Fatal(err)
	}
	hostileHome := filepath.Join(mark, "home-hostile")
	if err := os.MkdirAll(hostileHome, 0o755); err != nil {
		t.Fatal(err)
	}
	// filter.lfs here would leak into observations if global config were
	// honored; HasLFS is the detector.
	gitconfig := "[core]\n\thooksPath = " + gitConfigValue(hooks) + "\n" +
		"\tpager = cat\n[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n"
	if err := os.WriteFile(filepath.Join(hostileHome, ".gitconfig"), []byte(gitconfig), 0o644); err != nil {
		t.Fatal(err)
	}

	// Control C10: with hostile HOME, plain status fires the global hook.
	f := filepath.Join(benign, "f.txt")
	makeStatDirty(t, f)
	runPlainGit(t, benign, []string{"HOME=" + hostileHome}, "status", "--porcelain=v2")
	assertMarkerFired(t, pic, "global hooksPath via hostile HOME")
	resetMarker(t, pic)

	// Hardened arm: inherited hostile HOME must be ignored entirely.
	t.Setenv("HOME", hostileHome)
	makeStatDirty(t, f)
	obs := observeOK(t, benign)
	assertMarkerAbsent(t, pic, "global hooksPath")
	if obs.HasLFS {
		t.Error("hostile global config leaked into observation (HasLFS true)")
	}
}

// V4-daemon (probe C8/O25): core.fsmonitor=true spawns the builtin
// fsmonitor--daemon (background process + .git state) on plain status;
// the hardened observer must not.
func TestHostileFsmonitorDaemonNotSpawned(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeAndCommit(t, repo, "f.txt", "x\n")
	runGit(t, repo, "config", "core.fsmonitor", "true")
	daemonState := filepath.Join(repo, ".git", "fsmonitor--daemon")

	// Control C8: plain status creates daemon state.
	makeStatDirty(t, filepath.Join(repo, "f.txt"))
	runPlainGit(t, repo, nil, "status", "--porcelain=v2")
	if !waitFor(5*time.Second, func() bool { _, err := os.Stat(daemonState); return err == nil }) {
		t.Fatal("control arm failed: core.fsmonitor=true status did not spawn the daemon")
	}
	stopFsmonitorDaemon(t, repo)

	// Hardened arm.
	makeStatDirty(t, filepath.Join(repo, "f.txt"))
	obs := observeOK(t, repo)
	if waitFor(2*time.Second, func() bool { _, err := os.Stat(daemonState); return err == nil }) {
		t.Error("hardened observation spawned .git/fsmonitor--daemon state")
	}
	if !obs.IsRepo {
		t.Error("IsRepo = false")
	}
	stopFsmonitorDaemon(t, repo)
}

// Full-recipe watchdog (probe O18/O19/O17): one repository carrying every
// attack at once. The control arm executes all marker attacks; the
// hardened observation must leave every marker untouched and .git
// byte-identical (file set + index hash), while still reading the
// in-progress operation markers by direct file reads.
func TestHostileFullRecipeNoWritesNoExecution(t *testing.T) {
	requireGit(t)
	repo := t.TempDir()
	initRepo(t, repo)
	writeRepoFile(t, repo, "tracked.txt", "hello\n")
	writeRepoFile(t, repo, "sub/b.txt", "x\n")
	commitAll(t, repo, "one")
	writeRepoFile(t, repo, "stashsrc.txt", "s1\n")
	commitAll(t, repo, "two")
	writeRepoFile(t, repo, "stashsrc.txt", "w1\n")
	runGit(t, repo, "stash", "-q")
	writeRepoFile(t, repo, "stashsrc.txt", "w2\n")
	runGit(t, repo, "stash", "-q")

	mark := t.TempDir()
	fsmMk := filepath.Join(mark, "fsmhook.mk")
	cleanMk := filepath.Join(mark, "cleansmudge.mk")
	picMk := filepath.Join(mark, "pic.mk")
	extMk := filepath.Join(mark, "extdiff.mk")
	aliasBuiltinMk := filepath.Join(mark, "alias-builtin.mk")
	aliasNonBuiltinMk := filepath.Join(mark, "alias-nonbuiltin.mk")

	fsmScript := markerScript(t, mark, "fsmhook", fsmMk)
	cleanScript := markerScript(t, mark, "cleansmudge", cleanMk)
	extScript := markerScript(t, mark, "extdiff", extMk)
	aliasBuiltinScript := markerScript(t, mark, "alias-builtin", aliasBuiltinMk)
	aliasNonBuiltinScript := markerScript(t, mark, "alias-nonbuiltin", aliasNonBuiltinMk)

	hooks := filepath.Join(mark, "evil-hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, "post-index-change"),
		[]byte("#!/bin/sh\ntouch '"+filepath.ToSlash(picMk)+"'\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	attrs := filepath.Join(mark, "evil-attributes")
	if err := os.WriteFile(attrs, []byte("*.txt filter=evil diff=evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inc := filepath.Join(mark, "evil-included.conf")
	incContent := "[remote \"inc\"]\n\turl = https://example.com/inc.git\n" +
		"[alias]\n\tfrom-include = !" + gitConfigValue(aliasNonBuiltinScript) + "\n"
	if err := os.WriteFile(inc, []byte(incContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Seed FSMN, stop the daemon, arm everything (probe F1 order).
	runGit(t, repo, "-c", "core.fsmonitor=true", "update-index", "--fsmonitor")
	stopFsmonitorDaemon(t, repo)
	runGit(t, repo, "config", "core.fsmonitor", gitConfigValue(fsmScript))
	runGit(t, repo, "config", "core.attributesfile", gitConfigValue(attrs))
	runGit(t, repo, "config", "core.hooksPath", gitConfigValue(hooks))
	runGit(t, repo, "config", "diff.external", gitConfigValue(extScript))
	runGit(t, repo, "config", "diff.evil.textconv", gitConfigValue(extScript))
	runGit(t, repo, "config", "filter.evil.clean", gitConfigValue(cleanScript))
	runGit(t, repo, "config", "filter.evil.smudge", gitConfigValue(cleanScript))
	runGit(t, repo, "config", "alias.status", "!"+gitConfigValue(aliasBuiltinScript))
	runGit(t, repo, "config", "alias.rev-parse", "!"+gitConfigValue(aliasBuiltinScript))
	runGit(t, repo, "config", "alias.probe-evil", "!"+gitConfigValue(aliasNonBuiltinScript))
	runGit(t, repo, "config", "include.path", gitConfigValue(inc))
	runGit(t, repo, "config", "remote.origin.url", "https://example.com/proj.git")

	// Unfinished-operation state (probe O17 setup): written directly so
	// the direct-read observations have something to see.
	head := runGit(t, repo, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(repo, ".git", "MERGE_HEAD"), []byte(head), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git", "rebase-merge"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "rebase-merge", "interactive"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Control: plain status fires fsmonitor hook + clean filter +
	// post-index-change hook simultaneously.
	for _, m := range []string{fsmMk, cleanMk, picMk} {
		resetMarker(t, m)
	}
	makeStatDirty(t, filepath.Join(repo, "tracked.txt"))
	runPlainGit(t, repo, nil, "status", "--porcelain=v2", "--branch")
	assertMarkerFired(t, fsmMk, "fsmonitor hook (full fixture)")
	assertMarkerFired(t, cleanMk, "clean filter (full fixture)")
	assertMarkerFired(t, picMk, "post-index-change hook (full fixture)")

	// Hardened arm: reset every marker, snapshot .git, observe.
	for _, m := range []string{fsmMk, cleanMk, picMk, extMk, aliasBuiltinMk, aliasNonBuiltinMk} {
		resetMarker(t, m)
	}
	gitDir := filepath.Join(repo, ".git")
	snap := snapshotGitDir(t, gitDir)
	idxHash := fileSHA256(t, filepath.Join(gitDir, "index"))

	obs := observeOK(t, repo)

	for _, m := range []string{fsmMk, cleanMk, picMk, extMk, aliasBuiltinMk, aliasNonBuiltinMk} {
		assertMarkerAbsent(t, m, "full hostile fixture")
	}
	if !sameSnapshot(snap, snapshotGitDir(t, gitDir)) {
		t.Error("hardened observation mutated .git (file set/sizes changed)")
	}
	if got := fileSHA256(t, filepath.Join(gitDir, "index")); got != idxHash {
		t.Error("hardened observation rewrote .git/index")
	}

	// Observation quality under full hostility.
	if obs.StashCount != 2 {
		t.Errorf("StashCount = %d, want 2", obs.StashCount)
	}
	if !obs.MergeInProgress || !obs.RebaseInProgress {
		t.Errorf("in-progress reads failed: merge=%v rebase=%v", obs.MergeInProgress, obs.RebaseInProgress)
	}
	if obs.HeadBranch != "refs/heads/main" || !isHexCommit(obs.HeadCommit) {
		t.Errorf("HEAD observation degraded: %+v", obs)
	}
	if !obs.AdminInsideRoot || obs.Detached || obs.Unborn {
		t.Errorf("topology degraded: %+v", obs)
	}
	var sawOrigin, sawInc bool
	for _, r := range obs.Remotes {
		if r.Name == "origin" {
			sawOrigin = true
		}
		if r.Name == "inc" {
			sawInc = true
		}
	}
	if !sawOrigin || !sawInc {
		t.Errorf("remotes = %+v, want origin + include-provided inc", obs.Remotes)
	}
	if b := obs.DestructiveParkBlockers(); len(b) != 0 {
		t.Errorf("blockers = %v, want none", b)
	}
}
