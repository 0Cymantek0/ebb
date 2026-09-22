// integration_test.go drives the real Deps wiring (RealDeps) end to end
// against disposable temp fixtures: a Git repository with tracked,
// untracked, ignored and private files, a fake node_modules package
// tree, a nested repository inside node_modules (F53) and an Ebbfile
// declaring the regenerate group. Fixture SETUP calls git normally
// (test-only privilege); the code under test always goes through the
// hardened seams. Tests skip cleanly when git/restic are absent.

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// requireTool skips the test when bin is not on PATH.
func requireTool(t *testing.T, bin string) {
	t.Helper()
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("%s not available on PATH: %v", bin, err)
	}
}

// runReal executes Main with the production dependency set. Stats-event
// recording is unwired here: these runs drive the real state-dir seam
// and must never write telemetry into the developer's real state
// directory.
func runReal(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	deps := RealDeps()
	deps.RecordStatEvent = nil
	code = Main(args, Streams{Out: &out, Err: &errb}, deps)
	return code, out.String(), errb.String()
}

// fixtureOpts selects the fixture shape.
type fixtureOpts struct {
	Ebbfile    bool // write an Ebbfile.toml declaring node_modules
	NestedRepo bool // embed a second git repository inside node_modules (F53)
}

// ebbfileContent declares node_modules as a regenerate group.
const ebbfileContent = `version = 1

[workspace]
name = "fixture"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "node-dependencies"
adapter = "pnpm"
root = "."
outputs = ["node_modules"]
inputs = ["package.json", "pnpm-lock.yaml"]
network = "allowed"
`

// gitAt runs fixture-setup git (inherited environment; writes allowed).
func gitAt(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("setup git %v (cwd %s): %v\n%s", args, dir, err, buf.String())
	}
}

// buildWorkspace creates the shared disposable fixture and returns its
// root path.
func buildWorkspace(t *testing.T, opts fixtureOpts) string {
	t.Helper()
	requireTool(t, "git")
	root := t.TempDir()

	gitAt(t, root, "-c", "init.defaultBranch=main", "init", "-q", ".")
	gitAt(t, root, "config", "user.email", "ebb@test.local")
	gitAt(t, root, "config", "user.name", "Ebb Test")
	gitAt(t, root, "config", "core.autocrlf", "false")

	wf := func(rel, content string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Tracked source material.
	wf("README.md", "# fixture workspace\n")
	wf("src/main.go", "package main\n\nfunc main() { println(\"fixture\") }\n")
	wf("package.json", "{\n  \"name\": \"fixture\",\n  \"version\": \"1.0.0\",\n  \"private\": true\n}\n")
	wf("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      left-pad:\n        specifier: ^1.3.0\n        version: 1.3.0\n")
	wf(".gitignore", "ignored.txt\nnode_modules/\n")
	gitAt(t, root, "add", "-A")
	gitAt(t, root, "commit", "-qm", "base")

	// Private/untracked material (F01 class: preserved without prompts).
	wf("untracked.txt", "untracked private note\n")
	wf(".env", "SECRET_TOKEN=hunter2\n") // contents must never be printed
	wf("ignored.txt", "ignored but preserved\n")

	// Fake package tree (a few files, comfortably above 1 KiB).
	wf("node_modules/.package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"fixture"},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}`)
	wf("node_modules/left-pad/package.json", "{\n  \"name\": \"left-pad\",\n  \"version\": \"1.3.0\",\n  \"main\": \"index.js\"\n}\n")
	wf("node_modules/left-pad/index.js", strings.Repeat("module.exports = function leftPad(str, len) { /* fixture */ };\n", 30))

	// Nested empty directory (an inventory entry in its own right).
	if err := os.MkdirAll(filepath.Join(root, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A second git repository nested inside node_modules (F53).
	if opts.NestedRepo {
		nested := filepath.Join(root, "node_modules", "embedded-repo")
		if err := os.MkdirAll(nested, 0o755); err != nil {
			t.Fatal(err)
		}
		gitAt(t, nested, "-c", "init.defaultBranch=main", "init", "-q", ".")
		gitAt(t, nested, "config", "user.email", "ebb@test.local")
		gitAt(t, nested, "config", "user.name", "Ebb Test")
		if err := os.WriteFile(filepath.Join(nested, "notes.md"), []byte("# embedded original work\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitAt(t, nested, "add", "-A")
		gitAt(t, nested, "commit", "-qm", "embedded")
	}

	if opts.Ebbfile {
		wf("Ebbfile.toml", ebbfileContent)
	}
	return root
}

// inspectEnvelope mirrors the stable --json shape of inspect.
type inspectEnvelope struct {
	Command string `json:"command"`
	Outcome string `json:"outcome"`
	Details struct {
		Workspace string `json:"workspace"`
		Root      struct {
			Path     string `json:"path"`
			Identity struct {
				VolumeID string `json:"volume_id"`
				FileID   string `json:"file_id"`
			} `json:"identity"`
		} `json:"root"`
		Volume struct {
			Total    int64  `json:"total"`
			VolumeID string `json:"volume_id"`
		} `json:"volume"`
		Git struct {
			IsRepo          bool     `json:"is_repo"`
			Branch          string   `json:"branch"`
			AdminInsideRoot bool     `json:"admin_inside_root"`
			TrackedEvidence int      `json:"tracked_evidence_entries"`
			AdminEvidence   int      `json:"admin_evidence_entries"`
			Blockers        []string `json:"blockers"`
		} `json:"git"`
		Inventory struct {
			TotalEntries   int64            `json:"total_entries"`
			Preserved      int64            `json:"preserved"`
			PreservedBytes int64            `json:"preserved_bytes"`
			Routes         map[string]int64 `json:"routes"`
			Blocking       []string         `json:"blocking"`
		} `json:"inventory"`
		Groups []struct {
			ID         string `json:"id"`
			Applicable bool   `json:"applicable"`
			Cancelled  bool   `json:"cancelled"`
			Reason     string `json:"reason"`
			Canceller  string `json:"canceller"`
			Members    int    `json:"members"`
		} `json:"groups"`
		Plan struct {
			Result string `json:"result"`
			Steps  []struct {
				Kind        string           `json:"kind"`
				Groups      []string         `json:"groups"`
				Reclaimable map[string]int64 `json:"reclaimable"`
			} `json:"steps"`
			Achieved map[string]int64 `json:"achieved"`
		} `json:"plan"`
		Blockers []string `json:"blockers"`
	} `json:"details"`
	Warnings []string `json:"warnings"`
	Errors   []string `json:"errors"`
}

// TestInspectDefaultPolicyPreservesEverything: with no Ebbfile the
// conservative default policy preserves the whole workspace — private
// files, ignored files and even the node_modules tree (Foundation §7.1,
// F01, §7.4). A nested repo is present and must not change that.
func TestInspectDefaultPolicyPreservesEverything(t *testing.T) {
	root := buildWorkspace(t, fixtureOpts{NestedRepo: true})

	// --json machine view.
	code, stdout, stderr := runReal("inspect", "--json", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var env inspectEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout)
	}
	if env.Command != "inspect" || env.Outcome != "ok" {
		t.Fatalf("command/outcome = %q/%q", env.Command, env.Outcome)
	}
	if env.Details.Workspace != filepath.Base(filepath.Clean(root)) {
		t.Errorf("workspace = %q, want dir base name %q", env.Details.Workspace, filepath.Base(filepath.Clean(root)))
	}
	if env.Details.Root.Path != filepath.Clean(mustAbsPath(root)) {
		t.Errorf("root path = %q", env.Details.Root.Path)
	}
	if env.Details.Root.Identity.VolumeID == "" || env.Details.Root.Identity.FileID == "" {
		t.Errorf("root identity incomplete: %+v", env.Details.Root.Identity)
	}
	if env.Details.Volume.Total <= 0 {
		t.Errorf("volume total = %d, want > 0", env.Details.Volume.Total)
	}
	if !env.Details.Git.IsRepo || !env.Details.Git.AdminInsideRoot {
		t.Errorf("git = %+v", env.Details.Git)
	}
	if !strings.Contains(env.Details.Git.Branch, "main") {
		t.Errorf("branch = %q, want main", env.Details.Git.Branch)
	}
	// 5 tracked files: README.md, src/main.go, package.json,
	// pnpm-lock.yaml, .gitignore. git:tracked evidence applied.
	if want := 5; env.Details.Git.TrackedEvidence != want {
		t.Errorf("tracked evidence entries = %d, want %d", env.Details.Git.TrackedEvidence, want)
	}
	if env.Details.Git.AdminEvidence == 0 {
		t.Error("no git:admin evidence entries for .git/")
	}
	if len(env.Details.Git.Blockers) != 0 || len(env.Details.Blockers) != 0 {
		t.Errorf("blockers = %v / %v, want none", env.Details.Git.Blockers, env.Details.Blockers)
	}
	if len(env.Details.Inventory.Blocking) != 0 {
		t.Errorf("blocking entries = %v, want none", env.Details.Inventory.Blocking)
	}
	if len(env.Details.Inventory.Routes) != 1 {
		t.Fatalf("routes = %v, want only preserve", env.Details.Inventory.Routes)
	}
	if got := env.Details.Inventory.Routes["preserve"]; got != env.Details.Inventory.TotalEntries {
		t.Errorf("preserve route count = %d, want total %d", got, env.Details.Inventory.TotalEntries)
	}
	if env.Details.Inventory.Preserved != env.Details.Inventory.TotalEntries {
		t.Errorf("preserved = %d, want total %d", env.Details.Inventory.Preserved, env.Details.Inventory.TotalEntries)
	}
	if env.Details.Inventory.PreservedBytes <= 0 {
		t.Errorf("preserved bytes = %d, want > 0", env.Details.Inventory.PreservedBytes)
	}
	if len(env.Details.Groups) != 0 {
		t.Errorf("groups = %v, want none under default policy", env.Details.Groups)
	}

	// Human view: label + volume line, nothing on stdout.
	code, stdout, stderr = runReal("inspect", root)
	if code != ExitOK {
		t.Fatalf("human code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{
		"workspace: " + filepath.Base(filepath.Clean(root)),
		"scanning ",
		"volume ",
		"git: repository",
		"routes: preserve=",
		"regenerate groups: none declared",
		"blockers: none",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q\n--- stderr:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "SECRET_TOKEN") {
		t.Error("stderr leaked .env contents")
	}

	// plan with no declared groups is an honest no-gain (exit 8).
	code, _, stderr = runReal("plan", root)
	if code != ExitShortfall {
		t.Fatalf("plan code = %d, want %d (no-gain)", code, ExitShortfall)
	}
	if !strings.Contains(stderr, "no-gain") {
		t.Errorf("plan stderr lacks no-gain:\n%s", stderr)
	}
}

// TestInspectF53NestedRepoCancelsGroup: an Ebbfile declares node_modules
// reconstructible, but a nested repository inside it carries git:admin
// evidence — the whole group flips to preservation with a
// EBB_POLICY_REGEN_CANCELLED issue (Foundation §7.2, F53).
func TestInspectF53NestedRepoCancelsGroup(t *testing.T) {
	root := buildWorkspace(t, fixtureOpts{Ebbfile: true, NestedRepo: true})

	code, stdout, stderr := runReal("inspect", "--json", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var env inspectEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("bad json: %v\n%s", err, stdout)
	}
	if len(env.Details.Groups) != 1 {
		t.Fatalf("groups = %+v, want exactly node-dependencies", env.Details.Groups)
	}
	g := env.Details.Groups[0]
	if g.ID != "node-dependencies" || g.Applicable || !g.Cancelled {
		t.Fatalf("group decision = %+v", g)
	}
	if !strings.Contains(g.Reason, "F53") || !strings.Contains(g.Reason, "git:admin") {
		t.Errorf("cancel reason = %q, want F53 with git:admin evidence", g.Reason)
	}
	if !strings.HasPrefix(g.Canceller, "node_modules/embedded-repo/.git") {
		t.Errorf("canceller = %q, want a path inside the nested repo admin", g.Canceller)
	}
	// The cancellation is data, not a failure: exit 0, no blockers.
	if code != ExitOK || len(env.Details.Blockers) != 0 {
		t.Errorf("cancelled group must not fail inspection: code=%d blockers=%v", code, env.Details.Blockers)
	}
	// Everything stays preserved.
	if got := env.Details.Inventory.Routes["preserve"]; got != env.Details.Inventory.TotalEntries {
		t.Errorf("preserve route count = %d, want total %d", got, env.Details.Inventory.TotalEntries)
	}
	cancelled := false
	for _, w := range env.Warnings {
		if strings.Contains(w, "EBB_POLICY_REGEN_CANCELLED") {
			cancelled = true
		}
	}
	if !cancelled {
		t.Errorf("warnings lack EBB_POLICY_REGEN_CANCELLED: %v", env.Warnings)
	}
	if env.Details.Plan.Result != "no-gain" || len(env.Details.Plan.Steps) != 0 {
		t.Errorf("plan preview = %s with %d steps, want no-gain/0", env.Details.Plan.Result, len(env.Details.Plan.Steps))
	}

	// Human output names the cancellation.
	code, stdout, stderr = runReal("inspect", root)
	if code != ExitOK {
		t.Fatalf("human code = %d", code)
	}
	if !strings.Contains(stderr, "cancelled:") || !strings.Contains(stderr, "canceller: node_modules/embedded-repo/.git") {
		t.Errorf("human output lacks cancellation detail:\n%s", stderr)
	}
}

// TestInspectReconstructibleGroup: a clean node_modules (no nested repo)
// with a declaring Ebbfile routes the tree reconstruct and the plan
// preview carries a trim step with measurable bytes.
func TestInspectReconstructibleGroup(t *testing.T) {
	root := buildWorkspace(t, fixtureOpts{Ebbfile: true})

	code, stdout, stderr := runReal("inspect", "--json", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var env inspectEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(env.Details.Groups) != 1 || !env.Details.Groups[0].Applicable || env.Details.Groups[0].Cancelled {
		t.Fatalf("groups = %+v", env.Details.Groups)
	}
	if env.Details.Groups[0].Members == 0 {
		t.Error("group has no reconstruct members")
	}
	if env.Details.Inventory.Routes["reconstruct"] == 0 {
		t.Errorf("routes = %v, want reconstruct > 0", env.Details.Inventory.Routes)
	}
	if env.Details.Plan.Result != "sufficient" || len(env.Details.Plan.Steps) != 1 ||
		env.Details.Plan.Steps[0].Kind != "trim" || env.Details.Plan.Steps[0].Groups[0] != "node-dependencies" {
		t.Fatalf("plan preview = %+v", env.Details.Plan)
	}
	for _, bytes := range env.Details.Plan.Steps[0].Reclaimable {
		if bytes <= 0 {
			t.Errorf("trim reclaimable = %d, want > 0", bytes)
		}
	}
}

// TestPlanTargetTrimOnly: --target smaller than the node_modules group
// yields a trim-only plan (one step, no park), exit 0.
func TestPlanTargetTrimOnly(t *testing.T) {
	root := buildWorkspace(t, fixtureOpts{Ebbfile: true})

	code, stdout, stderr := runReal("plan", "--json", "--target", "1KB", root)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var env struct {
		Outcome string `json:"outcome"`
		Details struct {
			Plan struct {
				Result string `json:"result"`
				Steps  []struct {
					Kind   string   `json:"kind"`
					Groups []string `json:"groups"`
				} `json:"steps"`
				Achieved map[string]int64 `json:"achieved"`
			} `json:"plan"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("bad json: %v\n%s", err, stdout)
	}
	if env.Outcome != "ok" || env.Details.Plan.Result != "sufficient" {
		t.Fatalf("outcome/result = %s/%s", env.Outcome, env.Details.Plan.Result)
	}
	if len(env.Details.Plan.Steps) != 1 {
		t.Fatalf("steps = %+v, want exactly one", env.Details.Plan.Steps)
	}
	if env.Details.Plan.Steps[0].Kind != "trim" {
		t.Errorf("step kind = %s, want trim", env.Details.Plan.Steps[0].Kind)
	}
	var total int64
	for _, v := range env.Details.Plan.Achieved {
		total += v
	}
	if total <= 1000 {
		t.Errorf("achieved = %d, want > 1000 (the target)", total)
	}

	// Human mode: one step line, no park.
	code, stdout, stderr = runReal("plan", "--target", "1KB", root)
	if code != ExitOK {
		t.Fatalf("human code = %d, stderr = %s", code, stderr)
	}
	if strings.Count(stderr, "step ") != 1 {
		t.Errorf("expected exactly one step line:\n%s", stderr)
	}
	if strings.Contains(stderr, "park") {
		t.Errorf("trim-only plan must not contain a park step:\n%s", stderr)
	}
}

// TestInspectExitCodes pins the inspect exit contract: 3 for a missing
// path, 2 for usage errors, 0 for a completed inspection.
func TestInspectExitCodes(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "definitely-absent")
	if code, _, stderr := runReal("inspect", missing); code != ExitBlocked {
		t.Fatalf("missing path code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	if code, _, _ := runReal("inspect", "--nope"); code != ExitUsage {
		t.Fatalf("bad flag code = %d, want %d", code, ExitUsage)
	}
	if code, _, _ := runReal("inspect", "a", "b"); code != ExitUsage {
		t.Fatalf("too many paths code = %d, want %d", code, ExitUsage)
	}
	root := buildWorkspace(t, fixtureOpts{})
	if code, _, _ := runReal("inspect", root); code != ExitOK {
		t.Fatalf("healthy fixture code != %d", ExitOK)
	}
	// plan live scan on a missing path is also blocked (3).
	if code, _, _ := runReal("plan", missing); code != ExitBlocked {
		t.Fatalf("plan missing path code = %d, want %d", code, ExitBlocked)
	}
}

// TestDoctor: capability report via the real binary probes. Guarded on
// restic presence; exit 0 when no hard prerequisite is missing.
func TestDoctor(t *testing.T) {
	requireTool(t, "restic")

	code, stdout, stderr := runReal("doctor")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{"ebb doctor:", "restic: pass", "git: pass"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}

	code, stdout, _ = runReal("doctor", "--json")
	if code != ExitOK {
		t.Fatalf("json code = %d", code)
	}
	var env struct {
		Command string `json:"command"`
		Outcome string `json:"outcome"`
		Details struct {
			Checks []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"checks"`
		} `json:"details"`
		Warnings []string `json:"warnings"`
		Errors   []string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("bad json: %v\n%s", err, stdout)
	}
	if env.Command != "doctor" || env.Outcome != "ok" {
		t.Fatalf("command/outcome = %q/%q", env.Command, env.Outcome)
	}
	if len(env.Details.Checks) < 6 {
		t.Fatalf("checks = %+v, want at least 6", env.Details.Checks)
	}
	// Status contract (doctorCheck): pass | warn | fail | n/a. With
	// restic present nothing may be fail on ANY platform. The two probes
	// whose contract declares them Windows-only (windows-devmode,
	// wsl-vhdx — devModeProbeCheck/wslVhdxProbeCheck in doctor.go)
	// report exactly "n/a" off-Windows (the no-fake-parity principle)
	// and pass/warn on Windows. Assert each platform's real contract
	// instead of one lax set: n/a is REQUIRED on non-Windows for these
	// two, and forbidden everywhere else (a fail means something broke;
	// an unexpected n/a elsewhere would mean a check silently opted
	// out).
	windowsOnly := map[string]bool{"windows-devmode": true, "wsl-vhdx": true}
	for _, c := range env.Details.Checks {
		if windowsOnly[c.Name] {
			if runtime.GOOS == "windows" {
				if c.Status != "pass" && c.Status != "warn" {
					t.Errorf("check %s status %q (a Windows probe must report pass/warn on Windows)", c.Name, c.Status)
				}
			} else if c.Status != "n/a" {
				t.Errorf("check %s status %q (a Windows-only probe must report n/a on %s)", c.Name, c.Status, runtime.GOOS)
			}
			continue
		}
		switch c.Status {
		case "pass", "warn":
		default:
			t.Errorf("check %s status %q (with restic present nothing may fail)", c.Name, c.Status)
		}
	}
}

func mustAbsPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return abs
}

// TestUnderGitAdmin pins the admin-directory containment rule,
// including the AdminInsideRoot gate for the top-level .git.
func TestUnderGitAdmin(t *testing.T) {
	tests := []struct {
		p               string
		rootAdminInside bool
		want            bool
	}{
		{".git", true, true},
		{".git/HEAD", true, true},
		{".git/objects/ab/cdef", true, true},
		{".git", false, false},
		{".git/config", false, false},
		{"node_modules/x/.git", false, true}, // nested repo: always inside
		{"node_modules/x/.git/HEAD", false, true},
		{"node_modules/x/.git", true, true},
		{"src/main.go", true, false},
		{".github/workflows/ci.yml", true, false}, // .github is not .git
		{"gitignore", true, false},                // no leading dot segment match
		{"a/.gitx/b", true, false},                // segment must equal .git
		{"", true, false},
	}
	for _, tt := range tests {
		if got := underGitAdmin(tt.p, tt.rootAdminInside); got != tt.want {
			t.Errorf("underGitAdmin(%q, %v) = %v, want %v", tt.p, tt.rootAdminInside, got, tt.want)
		}
	}
}

// TestAnnotateGitEvidence verifies the F53 token application on real
// domain entries, without mutating the caller's evidence backing
// arrays.
func TestAnnotateGitEvidence(t *testing.T) {
	base := []string{"inventory.scan"}
	paths := []string{"src/main.go", ".git/HEAD", "node_modules/x/.git/HEAD", "untracked.txt"}
	entries := make([]domain.Entry, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, domain.Entry{
			Root:     domain.RootMain,
			Path:     p,
			Kind:     domain.KindFile,
			Route:    domain.RoutePreserve,
			Evidence: append([]string(nil), base...),
		})
	}
	tracked := map[string]bool{"src/main.go": true}

	trackedN, adminN := annotateGitEvidence(entries, tracked, true)
	if trackedN != 1 || adminN != 2 {
		t.Fatalf("counts = %d/%d, want 1 tracked and 2 admin", trackedN, adminN)
	}
	if got := entries[0].Evidence; len(got) != 2 || got[1] != "git:tracked" {
		t.Errorf("tracked evidence = %v", got)
	}
	if got := entries[1].Evidence; len(got) != 2 || got[1] != "git:admin" {
		t.Errorf("admin evidence = %v", got)
	}
	if got := entries[2].Evidence; len(got) != 2 || got[1] != "git:admin" {
		t.Errorf("nested admin evidence = %v", got)
	}
	if got := entries[3].Evidence; len(got) != 1 {
		t.Errorf("untracked entry must stay untouched: %v", got)
	}
	if len(base) != 1 {
		t.Error("caller's backing array mutated")
	}

	// AdminInsideRoot=false must gate the top-level .git but not the
	// nested repository.
	entries[1].Evidence = append([]string(nil), base...)
	entries[2].Evidence = append([]string(nil), base...)
	_, adminN = annotateGitEvidence(entries, tracked, false)
	if adminN != 1 {
		t.Fatalf("nested-only admin count = %d, want 1", adminN)
	}
}

// TestHumanBytes pins the display formatting.
func TestHumanBytes(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1 KiB"},
		{1536, "1.5 KiB"},
		{2048, "2 KiB"},
		{5 << 20, "5 MiB"},
		{(int64(3) << 30) + (600 << 20), "3.6 GiB"},
		{-5, "-5 B"},
	}
	for _, tt := range tests {
		if got := HumanBytes(tt.n); got != tt.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
