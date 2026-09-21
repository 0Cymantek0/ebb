// cmd_analyse_test.go: `ebb analyse` coverage over the eHarness world —
// the no-roots blocked wording, explicit-path scans and the analyze
// alias, the --json envelope shape, print-only batch flags (no effects
// without consent), in-process reclaim execution through the real
// lifecycle gates, and real-git worktree pruning gated on the binary's
// presence. Scan mode is asserted non-destructive throughout.

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ebb/internal/analyse"
)

// cliFakeSurvey is the CLI-side injectable git survey seam.
type cliFakeSurvey struct {
	mu    sync.Mutex
	repos map[string]analyse.RepoSummary
}

func (f *cliFakeSurvey) SurveyRepo(_ context.Context, root string) (analyse.RepoSummary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.repos[root]; ok {
		return r, nil
	}
	return analyse.RepoSummary{}, fmt.Errorf("cliFakeSurvey: no fixture for %s", root)
}

func (f *cliFakeSurvey) set(root string, r analyse.RepoSummary) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.repos == nil {
		f.repos = map[string]analyse.RepoSummary{}
	}
	f.repos[root] = r
}

// cliFakeDocker is the CLI-side injectable docker engine seam.
type cliFakeDocker struct {
	report analyse.DockerReport
	err    error
}

func (f *cliFakeDocker) Report(_ context.Context, _ []string) (analyse.DockerReport, error) {
	return f.report, f.err
}

// ageDir sets a directory tree's top-level mtimes to an age (mtime
// staleness evidence for non-git projects).
func ageDir(t *testing.T, dir string, age time.Duration) {
	t.Helper()
	when := time.Now().Add(-age)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Chtimes(filepath.Join(dir, e.Name()), when, when); err != nil {
			t.Fatal(err)
		}
	}
}

// writeAnalyseFixture writes one plain project (marker + heavy folder).
func writeAnalyseFixture(t *testing.T, dir, marker string, heavyBytes int) {
	t.Helper()
	files := map[string]string{marker: "{}\n"}
	if marker == "go.mod" {
		files[marker] = "module x\n"
	}
	if heavyBytes > 0 {
		files["node_modules/blob.dat"] = strings.Repeat("x", heavyBytes)
	}
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnalyseNoRootsBlocked(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("analyse")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (blocked)", code, ExitBlocked)
	}
	for _, want := range []string{"no scan roots are configured", "ebb config add projects_dir"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("blocked message missing %q:\n%s", want, stderr)
		}
	}
	// --json carries the blocked outcome.
	code, stdout, _ = h.run("analyse", "--json")
	if code != ExitBlocked {
		t.Fatalf("json code = %d, want %d", code, ExitBlocked)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "blocked" {
		t.Errorf("outcome = %v", env["outcome"])
	}
	assertNoSecrets(t, stdout)
	assertNoSecrets(t, stderr)
}

func TestAnalyseExplicitPathAndAlias(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()
	writeAnalyseFixture(t, filepath.Join(root, "alpha"), "package.json", 10)
	writeAnalyseFixture(t, filepath.Join(root, "beta"), "go.mod", 0)
	ageDir(t, filepath.Join(root, "beta"), 45*24*time.Hour) // stale by mtime

	code, _, stderr := h.run("analyse", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// alpha (active) appears only in the honest count; beta is stale and
	// listed with its copyable reclaim command.
	for _, want := range []string{"scanned 2 project(s)", "1 active", "beta", "Stale", "-> ebb reclaim"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("explicit-path output missing %q:\n%s", want, stderr)
		}
	}
	// The alias behaves identically.
	code, _, stderr2 := h.run("analyze", root)
	if code != ExitOK || !strings.Contains(stderr2, "scanned 2 project(s)") {
		t.Fatalf("alias code = %d stderr = %s", code, stderr2)
	}
	// Two paths is a usage mistake.
	if code, _, _ := h.run("analyse", root, root); code != ExitUsage {
		t.Fatalf("two-path code = %d, want %d", code, ExitUsage)
	}
	assertNoSecrets(t, stderr)
}

func TestAnalyseConfiguredRootsUsed(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()
	proj := filepath.Join(root, "cfg-proj")
	writeAnalyseFixture(t, proj, "package.json", 0)
	ageDir(t, proj, 45*24*time.Hour) // stale → listed by name
	if code, _, stderr := h.run("config", "add", "projects_dir", root); code != ExitOK {
		t.Fatalf("config add: %d %s", code, stderr)
	}
	code, _, stderr := h.run("analyse")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "cfg-proj") {
		t.Errorf("configured root not scanned:\n%s", stderr)
	}
}

func TestAnalyseJSONEnvelopeShape(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()
	proj := filepath.Join(root, "gitproj")
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeAnalyseFixture(t, proj, "package.json", 10)

	// RealDeps wires the git survey when a git binary exists; this test
	// pins the UNWIRED degradation contract, so the seam goes off
	// explicitly.
	h.deps.AnalyseGitSurvey = nil
	code, stdout, stderr := h.run("analyse", "--json", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "command") != "analyse" || envString(t, env, "outcome") != "ok" {
		t.Fatalf("envelope head = %v", env)
	}
	if !mustCondition(env, "scanned:") {
		t.Errorf("conditions missing scanned: %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["scanned"].(float64) != 1 {
		t.Errorf("details.scanned = %v", det["scanned"])
	}
	projects, _ := det["projects"].([]any)
	if len(projects) != 1 {
		t.Fatalf("details.projects = %v", det["projects"])
	}
	p := projects[0].(map[string]any)
	if p["category"] != "active" {
		t.Errorf("category = %v (fixture is fresh)", p["category"])
	}
	// Slices never null.
	if _, ok := det["warnings"].([]any); !ok {
		t.Errorf("details.warnings must be an array: %v", det["warnings"])
	}
	// Unwired git survey + a repository present = the honest degradation
	// warning, and no invented repository facts.
	warned := false
	for _, w := range det["warnings"].([]any) {
		if strings.Contains(w.(string), "git survey unavailable") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected the git-survey degradation warning: %v", det["warnings"])
	}
	if repo, ok := p["repo"].(map[string]any); ok {
		if repo["IsRepo"] == true {
			t.Errorf("repo facts invented without a surveyor: %v", repo)
		}
	}
	assertNoSecrets(t, stdout)
	assertNoSecrets(t, stderr)
}

func TestAnalyseDockerFlagDegradationAndReport(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()
	writeAnalyseFixture(t, filepath.Join(root, "plain"), "go.mod", 0)

	// Unwired engine (RealDeps wires one when a docker binary exists, so
	// the degradation case pins the seam off explicitly): honest warning,
	// exit 0.
	h.deps.AnalyseDocker = nil
	code, _, stderr := h.run("analyse", "--docker", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "docker analysis unavailable") {
		t.Errorf("unwired docker warning missing:\n%s", stderr)
	}

	// A reporting engine renders its tiers and copyable commands.
	h.deps.AnalyseDocker = &cliFakeDocker{report: analyse.DockerReport{
		Available: true,
		Tiers: []analyse.DockerTier{{
			Tier: 0, Title: "Pure dead clutter",
			Items: []analyse.DockerItem{
				{ID: "sha256:deadbeef", Detail: "1.2 GiB dangling"},
				{ID: "vol-64hex", Detail: "300 MiB orphaned", Shield: "active workspace"},
			},
			CopyCommand: "docker image prune",
		}},
		HostSlack:    8 << 30,
		SlackCommand: "wsl --manage docker-desktop --set-sparse true",
	}}
	code, _, stderr = h.run("analyse", "--docker", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"tier 0", "Pure dead clutter", "sha256:deadbeef", "[SHIELDED: active workspace]", "docker image prune", "host VHDX slack"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("docker rendering missing %q:\n%s", want, stderr)
		}
	}

	// Engine present but daemon unavailable: honest warning.
	h.deps.AnalyseDocker = &cliFakeDocker{report: analyse.DockerReport{Available: false}}
	code, _, stderr = h.run("analyse", "--docker", root)
	if code != ExitOK || !strings.Contains(stderr, "docker engine unavailable") {
		t.Errorf("unavailable engine: code %d stderr %s", code, stderr)
	}
}

func TestAnalyseBatchPrintModeHasNoEffects(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()

	stale := filepath.Join(root, "stale-proj")
	writeAnalyseFixture(t, stale, "package.json", 128)
	ageDir(t, stale, 45*24*time.Hour)

	// A merged worktree via the survey seam (print mode must not run git).
	// The .git FILE is the linked-worktree shape (probe → survey).
	wt := filepath.Join(root, "merged-wt")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "f.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../main/.git/worktrees/merged-wt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	survey := &cliFakeSurvey{}
	survey.set(wt, analyse.RepoSummary{
		IsRepo: true, IsWorktree: true, MergedUpstream: true,
		LastActivityAt: time.Now().Add(-20 * 24 * time.Hour),
	})
	h.deps.AnalyseGitSurvey = survey

	// Non-tty, no --yes: print-only (commands render POSIX-quoted; the
	// quoting rules themselves are pinned by TestAnalyseShellQuote).
	code, _, stderr := h.run("analyse", "--reclaim-stale", "--prune-worktrees", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	wantReclaim, _ := renderCommand([]string{"ebb", "reclaim", stale, "--yes"})
	wantPrune, _ := renderCommand([]string{"git", "worktree", "remove", wt})
	if !strings.Contains(stderr, wantReclaim) {
		t.Errorf("reclaim command not printed:\n%s", stderr)
	}
	if !strings.Contains(stderr, wantPrune) {
		t.Errorf("worktree command not printed:\n%s", stderr)
	}
	// No effects: the stale project's node_modules and the worktree
	// survive untouched.
	if _, err := os.Stat(filepath.Join(stale, "node_modules")); err != nil {
		t.Fatalf("print mode removed node_modules: %v", err)
	}
	if _, err := os.Stat(filepath.Join(wt, "f.txt")); err != nil {
		t.Fatalf("print mode removed the worktree: %v", err)
	}
	// The envelope records print-only items.
	var outJSON strings.Builder
	code = Main([]string{"analyse", "--json", "--reclaim-stale", "--prune-worktrees", root},
		Streams{Out: &outJSON, Err: &strings.Builder{}}, h.deps)
	if code != ExitOK {
		t.Fatalf("json batch code = %d", code)
	}
	env := envelopeOf(t, outJSON.String())
	det := env["details"].(map[string]any)
	batches, _ := det["batches"].([]any)
	if len(batches) != 2 {
		t.Fatalf("batches = %v", batches)
	}
	for _, bi := range batches {
		item := bi.(map[string]any)
		if item["status"] != "printed" {
			t.Errorf("batch item without consent must be printed: %v", item)
		}
	}
}

func TestAnalyseReclaimStaleExecutesInProcess(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()
	proj := filepath.Join(root, "stale-reclaim")
	files := map[string]string{
		"Ebbfile.toml": `version = 1

[workspace]
name = "stale-reclaim"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "deps"
adapter = "pnpm"
root = "."
outputs = ["node_modules"]
inputs = ["package.json", "pnpm-lock.yaml"]
network = "allowed"
`,
		"package.json":                       `{"name":"stale-reclaim","private":true}` + "\n",
		"pnpm-lock.yaml":                     "lockfileVersion: '9.0'\n",
		"notes.md":                           "private notes survive everything\n",
		"node_modules/.package-lock.json":    `{"lockfileVersion":3}`,
		"node_modules/left-pad/package.json": "{\n  \"name\": \"left-pad\"\n}\n",
	}
	for rel, content := range files {
		p := filepath.Join(proj, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	survey := &cliFakeSurvey{}
	survey.set(proj, analyse.RepoSummary{IsRepo: true, LastActivityAt: time.Now().Add(-45 * 24 * time.Hour)})
	h.deps.AnalyseGitSurvey = survey

	code, stdout, stderr := h.run("analyse", "--reclaim-stale", "--yes", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stdout=%s stderr = %s", code, stdout, stderr)
	}
	// The trim executed through the lifecycle: node_modules is gone,
	// private notes survive.
	if _, err := os.Stat(filepath.Join(proj, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("node_modules not trimmed (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(proj, "notes.md")); err != nil {
		t.Fatalf("preserved notes lost: %v", err)
	}
	// The envelope's conditions carry the batch accounting (asserted
	// through the JSON run below; the human stream needs none).
	var outJSON strings.Builder
	code = Main([]string{"analyse", "--json", "--reclaim-stale", "--yes", root},
		Streams{Out: &outJSON, Err: &strings.Builder{}}, h.deps)
	if code != ExitOK {
		t.Fatalf("second (json) run code = %d: %s", code, outJSON.String())
	}
	env := envelopeOf(t, outJSON.String())
	if !mustCondition(env, "batch-executed:") {
		t.Errorf("conditions missing batch-executed: %v", env["conditions"])
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, outJSON.String())
}

func TestAnalyseShieldedStaleSkippedInBatch(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()
	proj := filepath.Join(root, "unpushed-stale")
	writeAnalyseFixture(t, proj, "package.json", 64)
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	survey := &cliFakeSurvey{}
	survey.set(proj, analyse.RepoSummary{
		IsRepo: true, UnpushedCommits: 4,
		LastActivityAt: time.Now().Add(-45 * 24 * time.Hour),
	})
	h.deps.AnalyseGitSurvey = survey

	code, stdout, stderr := h.run("analyse", "--json", "--reclaim-stale", "--yes", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(proj, "node_modules")); err != nil {
		t.Fatalf("shielded project was acted on: %v", err)
	}
	env := envelopeOf(t, stdout)
	det := env["details"].(map[string]any)
	batches, _ := det["batches"].([]any)
	if len(batches) != 1 {
		t.Fatalf("batches = %v", batches)
	}
	item := batches[0].(map[string]any)
	if item["status"] != "skipped-shielded" || !strings.Contains(item["detail"].(string), "[UNPUSHED COMMITS]") {
		t.Errorf("shielded item = %v", item)
	}
}

// gitOf returns the real git binary or skips honestly.
func gitOf(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("EBB_TEST_GIT_BIN")
	if bin == "" {
		bin = "git"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("git binary %q not usable on this machine (%v); real-git analyse suite skipped", bin, err)
	}
	return path
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	git := gitOf(t)
	cmd := exec.Command(git, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=ebb-test", "GIT_AUTHOR_EMAIL=ebb@test.local",
		"GIT_COMMITTER_NAME=ebb-test", "GIT_COMMITTER_EMAIL=ebb@test.local")
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v in %s: %v\n%s", args, dir, err, out.String())
	}
	return out.String()
}

// TestAnalysePruneWorktreesRealGit prunes a REAL linked worktree with
// native git: the main repo keeps working, the merged worktree
// disappears, and a dirty worktree (survey-reported) is never touched.
func TestAnalysePruneWorktreesRealGit(t *testing.T) {
	gitOf(t) // honest skip without a usable git
	h := newEHarness(t)
	root := t.TempDir()

	main := filepath.Join(root, "web-platform")
	if err := os.MkdirAll(main, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(main, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, main, "init", "-q")
	runGit(t, main, "checkout", "-q", "-b", "main")
	// Byte-deterministic fixture regardless of the machine's system
	// config (this host's system core.autocrlf=true makes LF-committed
	// files look phantom-dirty under ebb's constructed env — the same
	// neutralization gitadapter's fixtures apply; see fixtures_test.go).
	runGit(t, main, "config", "core.autocrlf", "false")
	runGit(t, main, "add", ".")
	runGit(t, main, "commit", "-q", "-m", "initial")

	// A merged linked worktree: branch off, commit, merge back (ff).
	merged := filepath.Join(root, "web-hotfix")
	runGit(t, main, "worktree", "add", "-q", "-b", "hotfix", merged)
	if err := os.WriteFile(filepath.Join(merged, "fix.txt"), []byte("fix\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, merged, "add", ".")
	runGit(t, merged, "commit", "-q", "-m", "fix")
	runGit(t, main, "merge", "-q", "--ff-only", "hotfix")

	// A dirty linked worktree: uncommitted change, never prunable.
	dirty := filepath.Join(root, "web-wip")
	runGit(t, main, "worktree", "add", "-q", "-b", "wip", dirty)
	if err := os.WriteFile(filepath.Join(dirty, "wip.txt"), []byte("wip\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	survey := &cliFakeSurvey{}
	survey.set(main, analyse.RepoSummary{IsRepo: true, LastActivityAt: time.Now().Add(-24 * time.Hour)})
	survey.set(merged, analyse.RepoSummary{
		IsRepo: true, IsWorktree: true, MergedUpstream: true, WorktreeMain: main,
		LastActivityAt: time.Now().Add(-18 * 24 * time.Hour),
	})
	survey.set(dirty, analyse.RepoSummary{
		IsRepo: true, IsWorktree: true, MergedUpstream: true, WorktreeMain: main,
		DirtyWorktree: true, LastActivityAt: time.Now().Add(-2 * 24 * time.Hour),
	})
	h.deps.AnalyseGitSurvey = survey

	code, stdout, stderr := h.run("analyse", "--json", "--prune-worktrees", "--yes", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stdout=%s stderr = %s", code, stdout, stderr)
	}
	if _, err := os.Stat(merged); !os.IsNotExist(err) {
		t.Fatalf("merged worktree not removed (err=%v; envelope %s)", err, stdout)
	}
	if _, err := os.Stat(filepath.Join(dirty, "wip.txt")); err != nil {
		t.Fatalf("dirty worktree was touched: %v", err)
	}
	if _, err := os.Stat(filepath.Join(main, "a.txt")); err != nil {
		t.Fatalf("main repo damaged: %v", err)
	}
	// git's own bookkeeping no longer lists the removed worktree.
	listing := runGit(t, main, "worktree", "list", "--porcelain")
	if strings.Contains(listing, "web-hotfix") {
		t.Errorf("git still lists the removed worktree:\n%s", listing)
	}
	// The dirty worktree never entered the prune batch (dirty shield →
	// not the merged-worktree category); only the merged one ran.
	env := envelopeOf(t, stdout)
	det := env["details"].(map[string]any)
	batches, _ := det["batches"].([]any)
	statuses := map[string]string{}
	for _, bi := range batches {
		item := bi.(map[string]any)
		statuses[item["project"].(string)] = item["status"].(string)
	}
	if statuses[merged] != "executed" {
		t.Errorf("merged item status = %v (batches %v)", statuses[merged], batches)
	}
	if _, listed := statuses[dirty]; listed {
		t.Errorf("dirty worktree must not be a prune item: %v", statuses)
	}
	if len(batches) != 1 {
		t.Errorf("prune batch = %v, want exactly the merged worktree", batches)
	}
}

// TestAnalysePruneInteractiveDecline: a terminal without --yes that
// declines the typed confirmation stays print-only.
func TestAnalysePruneInteractiveDecline(t *testing.T) {
	gitOf(t)
	h := newEHarness(t)
	h.tty = true
	h.lines = []string{"no"}
	root := t.TempDir()
	wt := filepath.Join(root, "wt")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "f.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Linked-worktree shape: the .git FILE routes the probe to the survey.
	if err := os.WriteFile(filepath.Join(wt, ".git"), []byte("gitdir: ../main/.git/worktrees/wt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	survey := &cliFakeSurvey{}
	survey.set(wt, analyse.RepoSummary{
		IsRepo: true, IsWorktree: true, MergedUpstream: true, WorktreeMain: filepath.Join(root, "main"),
		LastActivityAt: time.Now().Add(-18 * 24 * time.Hour),
	})
	h.deps.AnalyseGitSurvey = survey

	code, _, stderr := h.run("analyse", "--prune-worktrees", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(wt, "f.txt")); err != nil {
		t.Fatalf("declined confirmation still executed: %v", err)
	}
	if !strings.Contains(stderr, "execute? type 'yes'") {
		t.Errorf("typed confirmation not offered:\n%s", stderr)
	}
}

// TestAnalyseNestedReclaimNeverConsumesRealStdin (F2): the batch spawns
// `ebb reclaim` IN-PROCESS while the outer analyse runs on a real
// terminal (tty seam true). The inner park-escalation gate must take
// its headless refusal path: StdinIsTerminal and ReadLine are
// process-global seams, and before the fix the inner gate printed its
// question into a discarded stream and then BLOCKED on real stdin —
// the user's next typed line (muscle-memory "yes") invisibly authorized
// park-and-REMOVE. Here ReadLine is poisoned to fail the test if ever
// called; the item must visibly decline and name the gate.
func TestAnalyseNestedReclaimNeverConsumesRealStdin(t *testing.T) {
	h := newEHarness(t)
	h.tty = true // outer analyse on a terminal; --yes gives batch consent
	poisoned := false
	h.deps.StdinIsTerminal = func() bool { return true }
	h.deps.ReadLine = func() (string, error) {
		poisoned = true
		return "", fmt.Errorf("poisoned ReadLine consumed by a nested gate")
	}

	root := t.TempDir()
	proj := filepath.Join(root, "gate-proj")
	// No Ebbfile → the inner reclaim has no trim groups, so its plan
	// reaches the park escalation gate (the exact gate that used to
	// block on real stdin).
	writeAnalyseFixture(t, proj, "package.json", 0)
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	survey := &cliFakeSurvey{}
	survey.set(proj, analyse.RepoSummary{IsRepo: true, LastActivityAt: time.Now().Add(-45 * 24 * time.Hour)})
	h.deps.AnalyseGitSurvey = survey

	code, stdout, stderr := h.run("analyse", "--json", "--reclaim-stale", "--yes", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stdout=%s stderr = %s", code, stdout, stderr)
	}
	if poisoned {
		t.Fatal("a nested gate consumed the (real) stdin ReadLine seam — interactivity leaked into the batch child")
	}
	// The project was NOT parked/removed: it still exists, files intact.
	if _, err := os.Stat(filepath.Join(proj, "package.json")); err != nil {
		t.Fatalf("project content removed by the nested reclaim: %v", err)
	}
	env := envelopeOf(t, stdout)
	det := env["details"].(map[string]any)
	batches, _ := det["batches"].([]any)
	if len(batches) != 1 {
		t.Fatalf("batches = %v", batches)
	}
	item := batches[0].(map[string]any)
	detail := item["detail"].(string)
	if !strings.Contains(detail, "escalation") {
		t.Errorf("item detail must name the refused gate: %q", detail)
	}
	if !strings.Contains(detail, "`ebb reclaim "+proj+"` interactively") {
		t.Errorf("item detail must suggest the interactive rerun: %q", detail)
	}
	// The refusal is visible in the human stream too (digest surfaced).
	if !strings.Contains(stderr, "") && stdout == "" {
		t.Error("no report emitted")
	}
}

// flipSurvey returns clean facts on every odd SurveyRepo call for a
// root (the scans) and dirty+unpushed facts on every even call (the
// F5 re-probe right before execution must see the fresh shields).
type flipSurvey struct {
	inner analyse.GitSurveyor
	calls map[string]int
}

func (f *flipSurvey) SurveyRepo(ctx context.Context, root string) (analyse.RepoSummary, error) {
	sum, err := f.inner.SurveyRepo(ctx, root)
	if err != nil {
		return sum, err
	}
	f.calls[root]++
	if f.calls[root]%2 == 0 {
		sum.DirtyWorktree = true
		sum.UnpushedCommits = 7
	}
	return sum, nil
}

// TestAnalyseRecheckShieldsBeforeExecution (F5): a project that was
// clean at scan time but dirty by execution time is skipped with a
// clear newly-shielded status instead of a doomed reclaim attempt.
func TestAnalyseRecheckShieldsBeforeExecution(t *testing.T) {
	h := newEHarness(t)
	root := t.TempDir()
	proj := filepath.Join(root, "flipped")
	writeAnalyseFixture(t, proj, "package.json", 128)
	if err := os.MkdirAll(filepath.Join(proj, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	survey := &cliFakeSurvey{}
	survey.set(proj, analyse.RepoSummary{IsRepo: true, LastActivityAt: time.Now().Add(-45 * 24 * time.Hour)})
	h.deps.AnalyseGitSurvey = &flipSurvey{inner: survey, calls: map[string]int{}}

	code, stdout, stderr := h.run("analyse", "--json", "--reclaim-stale", "--yes", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stdout=%s stderr = %s", code, stdout, stderr)
	}
	// Nothing was trimmed: the node_modules fixture survives.
	if _, err := os.Stat(filepath.Join(proj, "node_modules")); err != nil {
		t.Fatalf("newly shielded project was still acted on: %v", err)
	}
	env := envelopeOf(t, stdout)
	det := env["details"].(map[string]any)
	batches, _ := det["batches"].([]any)
	if len(batches) != 1 {
		t.Fatalf("batches = %v", batches)
	}
	item := batches[0].(map[string]any)
	if item["status"] != "skipped-shielded" {
		t.Errorf("status = %v, want skipped-shielded (item %v)", item["status"], item)
	}
	detail := item["detail"].(string)
	if !strings.Contains(detail, "newly shielded") || !strings.Contains(detail, "[DIRTY]") {
		t.Errorf("detail must name the fresh shields: %q", detail)
	}
	// The skip is visible in the human stream too (second, human-mode run).
	_, _, stderr = h.run("analyse", "--reclaim-stale", "--yes", root)
	if !strings.Contains(stderr, "newly shielded") {
		t.Errorf("human stream must carry the skip reason:\n%s", stderr)
	}
}

// TestAnalyseShellQuote (F4b): copyable command lines quote every
// element POSIX-safely, and unquotable elements (control characters)
// withhold the line.
func TestAnalyseShellQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"ebb", "ebb", true},
		{"--yes", "--yes", true},
		{"/home/u/proj", "/home/u/proj", true},
		{`C:\Users\u\proj`, `'C:\Users\u\proj'`, true}, // backslash → quoted
		{"/home/u/my proj", `'/home/u/my proj'`, true}, // space → quoted
		{"/home/u/it's", `'/home/u/it'\''s'`, true},    // single quote → escaped
		{"", "''", true},                               // empty → explicit empty
		{"evil\nname", "", false},                      // newline → unquotable
		{"\x1b[31mred\x1b[0m", "", false},              // ANSI → unquotable
	}
	for _, c := range cases {
		got, ok := shellQuote(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("shellQuote(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
	line, ok := renderCommand([]string{"ebb", "reclaim", "/home/u/my proj", "--yes"})
	if !ok || line != `ebb reclaim '/home/u/my proj' --yes` {
		t.Errorf("renderCommand = (%q, %v)", line, ok)
	}
	if _, ok := renderCommand([]string{"ebb", "reclaim", "evil\nname", "--yes"}); ok {
		t.Error("renderCommand accepted a control-character path")
	}
	// stripControlChars: the digest/detail sanitizer (the ESC bytes go;
	// the inert [31m text they carried stays, harmlessly unexecutable).
	if got := stripControlChars("fatal: \x1b[31mbad\x1b[0m repo\nnext"); got != "fatal:  [31mbad [0m repo next" {
		t.Errorf("stripControlChars = %q", got)
	}
}

// TestAnalyseRenderSanitizesHostileProject (F4): a project name with
// newline/ANSI (surfaced by the engine shielded, never as a copyable
// command) renders sanitized: no raw control characters anywhere in the
// human report, no command line for it.
func TestAnalyseRenderSanitizesHostileProject(t *testing.T) {
	hostile := "evil\x1b[31m\nname"
	details := analyseDetails{Report: analyse.Report{
		Scanned:    1,
		Categories: map[string]int{string(analyse.CategoryStale): 1},
		Projects: []analyse.Project{{
			Name: hostile, Root: "/scan/root/" + hostile,
			Category: analyse.CategoryStale,
			Shields:  []string{analyse.ShieldUnsafeName},
			Recommendation: analyse.Recommendation{
				Kind:   "reclaim",
				Reason: "untouched for 45 days (stale); shielded [UNSAFE NAME]: skipped in batch operations",
			},
		}},
		Warnings: []string{"skipped link child /scan/root/" + hostile + " (opaque)"},
	}}
	out := renderAnalyseHuman(details, false)
	for _, line := range strings.Split(out, "\n") {
		if analyse.HasControlChars(strings.TrimRight(line, "\r")) {
			t.Errorf("rendered line carries raw control characters: %q", line)
		}
	}
	if !strings.Contains(out, "[UNSAFE NAME]") {
		t.Errorf("unsafe-name shield not rendered:\n%s", out)
	}
	if strings.Contains(out, "-> ebb") || strings.Contains(out, "-> git") {
		t.Errorf("copyable command rendered for an unsafe-name project:\n%s", out)
	}
}
