// wave_f_reclaim_test.go: `ebb reclaim` coverage over the eHarness world
// (Wave F). Dry-run shapes (target met by trim / escalation required /
// no-gain), execution (trim runs under the shared approval UX, park
// escalation gated behind its own terminal confirmation, achieved
// reporting, exit 8), and the blocked/declined-group-routes-around rule
// (§17.4 F10/F11).

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReclaimDryRunTargetMetByTrim(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("reclaim", "--dry-run", "--target", "1", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{
		"dry run: nothing will be removed",
		"stage 1 trim deps",
		"outputs: node_modules",
		"recreate: pnpm install --frozen-lockfile",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "park escalation stage") {
		t.Errorf("preview must not propose the escalation when trim reaches the target:\n%s", stderr)
	}
	// No effects: the group is intact and nothing was captured (a dry
	// run creates neither a workspace row nor a snapshot row).
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); err != nil {
		t.Fatalf("dry run removed content: %v", err)
	}
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range wss {
		snaps, serr := cat.ListSnapshots(w.ID)
		if serr != nil {
			t.Fatal(serr)
		}
		if len(snaps) > 0 {
			t.Fatalf("dry run created snapshot rows: %+v", snaps)
		}
	}
}

func TestReclaimDryRunEscalationRequiredShortfall(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("reclaim", "--dry-run", "--target", "1PiB", h.wsRoot)
	if code != ExitShortfall {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitShortfall, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{
		"park escalation stage",
		"would REMOVE the workspace",
		"needs its own confirmation and a stopped-writers assertion",
		"shortfall",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); err != nil {
		t.Fatalf("dry run removed content: %v", err)
	}
}

func TestReclaimDryRunNoGain(t *testing.T) {
	h := newEHarness(t)
	empty := t.TempDir()
	code, _, stderr := h.run("reclaim", "--dry-run", "--target", "1MiB", empty)
	if code != ExitShortfall {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitShortfall, stderr)
	}
	if !strings.Contains(stderr, "no-gain") {
		t.Errorf("stderr must carry the no-gain result:\n%s", stderr)
	}
}

func TestReclaimTargetMetByTrimOnlyExecution(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("reclaim", "--target", "1", "--yes", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("node_modules still exists: %v", err)
	}
	for _, kept := range []string{"notes.md", ".env", "package.json", "pnpm-lock.yaml", "Ebbfile.toml", "src/main.go"} {
		if _, err := os.Stat(filepath.Join(h.wsRoot, filepath.FromSlash(kept))); err != nil {
			t.Fatalf("retained path %s removed: %v", kept, err)
		}
	}
	for _, want := range []string{
		"removed group deps",
		"recreate with: pnpm install --frozen-lockfile",
		"achieved (estimated)",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	// The staged plan reached the target: no park stage is proposed at
	// all (§17.4: reclaim stops at trim and leaves the workspace live).
	if strings.Contains(stderr, "park escalation") {
		t.Errorf("a met target must not carry a park stage:\n%s", stderr)
	}
	assertNoSecrets(t, stderr)
}

func TestReclaimJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("reclaim", "--json", "--target", "1", "--yes", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "command") != "reclaim" || envString(t, env, "outcome") != "ok" {
		t.Fatalf("envelope head = %v", env)
	}
	if !mustCondition(env, "trim:deps") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	if b, ok := env["bytes"].(map[string]any); !ok || b["freed_estimated"].(float64) <= 0 {
		t.Errorf("bytes.freed_estimated missing or zero: %v", env["bytes"])
	}
	det := env["details"].(map[string]any)
	trims := det["trims"].([]any)
	if len(trims) != 1 || trims[0].(map[string]any)["status"] != "removed" {
		t.Errorf("trims = %v", trims)
	}
	if det["park"] != nil {
		t.Errorf("a met target must not carry a park stage: %v", det["park"])
	}
	if _, err := os.Stat(h.wsRoot); err != nil {
		t.Fatalf("workspace root removed: %v", err)
	}
	assertNoSecrets(t, stdout)
}

func TestReclaimNoTargetStopsAtTrim(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("reclaim", "--yes", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(h.wsRoot); err != nil {
		t.Fatalf("no-target reclaim removed the root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatal("trim stage did not run")
	}
	if !strings.Contains(stderr, "park escalation not needed") {
		t.Errorf("stderr lacks the not-needed escalation note:\n%s", stderr)
	}
}

func TestReclaimEscalationRefusedWithoutTerminalExit8(t *testing.T) {
	h := newEHarness(t)
	h.tty = false
	// --yes approves the trim stage but can NEVER answer the escalation.
	code, stdout, stderr := h.run("reclaim", "--target", "1PiB", "--yes", h.wsRoot)
	if code != ExitShortfall {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitShortfall, stderr)
	}
	// The trim stage DID run and route around to reporting.
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatal("trim stage did not run before the escalation gate")
	}
	if _, err := os.Stat(h.wsRoot); err != nil {
		t.Fatalf("workspace was removed without an escalation confirmation: %v", err)
	}
	assertBlocker(t, stderr, CodeEscalationUnconfirmed, "terminal")
	if !strings.Contains(stderr, "shortfall") {
		t.Errorf("stderr must report the shortfall breakdown:\n%s", stderr)
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, stdout)
}

func TestReclaimNonInteractiveWithoutYesSkipsTrimsAndReports(t *testing.T) {
	h := newEHarness(t)
	h.tty = false
	code, _, stderr := h.run("reclaim", "--target", "1", h.wsRoot)
	if code != ExitShortfall {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitShortfall, stderr)
	}
	// The unapprovable trim stage is skipped and REPORTED, never fatal;
	// nothing was removed.
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); err != nil {
		t.Fatal("trim removed the group without any approval")
	}
	if !strings.Contains(stderr, "skipped group deps") || !strings.Contains(stderr, "approval unavailable") {
		t.Errorf("stderr must report the skipped group and why:\n%s", stderr)
	}
}

func TestReclaimInteractiveDeclineRoutesAround(t *testing.T) {
	h := newEHarness(t)
	h.tty = true
	// Second applicable group: a uv venv.
	h.writeTwoGroupFixture()
	// Plan order is estimate-desc: deps (3 files) before venv (1 file).
	// Decline deps, approve venv: the declined group must not block the
	// rest (§17.4 F10/F11).
	h.lines = []string{"no", "yes"}
	code, _, stderr := h.run("reclaim", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); err != nil {
		t.Fatalf("declined group was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, ".venv")); !os.IsNotExist(err) {
		t.Fatalf("approved group was not removed: %v", err)
	}
	if !strings.Contains(stderr, "skipped group deps") || !strings.Contains(stderr, "confirmation was declined") {
		t.Errorf("stderr must report the declined group:\n%s", stderr)
	}
	if !strings.Contains(stderr, "removed group venv") {
		t.Errorf("stderr lacks the executed group:\n%s", stderr)
	}
}

func TestReclaimInteractiveEscalationExecutesPark(t *testing.T) {
	h := newEHarness(t)
	h.tty = true
	// Approve the trim stage, then the escalation. The target is
	// physically unreachable, so the honest terminal outcome is exit 8
	// WITH the park executed and the shortfall named.
	h.lines = []string{"yes", "yes"}
	code, _, stderr := h.run("reclaim", "--target", "1PiB", h.wsRoot)
	if code != ExitShortfall {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitShortfall, stderr)
	}
	if _, err := os.Stat(h.wsRoot); !os.IsNotExist(err) {
		t.Fatalf("confirmed escalation did not park the workspace: %v", err)
	}
	for _, want := range []string{
		"park escalation executed",
		"writer assertion: interactive-confirm",
		"shortfall",
		"reopen later with: ebb open cliws",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)
}

func TestReclaimNoTargetNothingToReleaseExit8(t *testing.T) {
	h := newEHarness(t)
	// The group's output is absent: no trim step, nothing released; the
	// escalation is offered and (non-terminal) declined — no useful gain.
	if err := os.RemoveAll(filepath.Join(h.wsRoot, "node_modules")); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("reclaim", "--yes", h.wsRoot)
	if code != ExitShortfall {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitShortfall, stderr)
	}
	if !strings.Contains(stderr, "no-useful-gain") && !strings.Contains(stderr, "no useful gain") {
		t.Errorf("stderr must name the no-useful-gain outcome:\n%s", stderr)
	}
	if _, err := os.Stat(h.wsRoot); err != nil {
		t.Fatalf("workspace removed: %v", err)
	}
}

func TestReclaimBadTargetUsage(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("reclaim", "--target", "nan", h.wsRoot); code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

// writeTwoGroupFixture rewrites the fixture Ebbfile with a second
// regenerate group (uv venv) and creates its output.
func (h *eHarness) writeTwoGroupFixture() {
	h.t.Helper()
	ebbfile := `version = 1

[workspace]
name = "cliws"

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

[[regenerate]]
id = "venv"
adapter = "uv"
root = "."
outputs = [".venv"]
inputs = ["pyproject.toml"]
network = "allowed"
`
	files := map[string]string{
		"Ebbfile.toml":     ebbfile,
		"pyproject.toml":   "[project]\nname = \"cliws\"\nversion = \"1.0\"\n",
		".venv/pyvenv.cfg": "home = /usr/bin\n",
	}
	for rel, content := range files {
		p := filepath.Join(h.wsRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			h.t.Fatal(err)
		}
	}
}
