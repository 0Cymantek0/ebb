package cli

// cmd_freeze_test.go drives `ebb freeze` end to end through the env
// seams the command honors (EBB_TEST_DOCKER_BIN / EBB_TEST_RESTIC_BIN,
// the same fake binaries the freezer package compiles from its testdata)
// plus the in-package Deps harness: dispatch, the §17.2 envelope shape,
// --dry-run no-effects, the fail-closed confirmation discipline, the
// separate removal confirmation, restore verify-before-load, and the
// Wave 2 doctor probes' unit contracts.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// ---- fake binary management (mirrors internal/freezer/freeze_test.go) ----

var cliFakeBin = struct {
	once sync.Once
	dir  string
	err  error
}{}

func buildCLIFakes(t *testing.T) string {
	t.Helper()
	cliFakeBin.once.Do(func() {
		dir, err := os.MkdirTemp("", "ebb-cli-freeze-fakebin-")
		if err != nil {
			cliFakeBin.err = err
			return
		}
		src := "github.com/0Cymantek0/ebb/internal/freezer/testdata"
		for _, name := range []string{"fakedocker", "fakerestic"} {
			suffix := ""
			if os.PathSeparator == '\\' {
				suffix = ".exe"
			}
			if out, berr := exec.Command("go", "build", "-o",
				filepath.Join(dir, name+suffix), src+"/"+name).CombinedOutput(); berr != nil {
				cliFakeBin.err = fmt.Errorf("building fake %s: %v: %s", name, berr, out)
				return
			}
		}
		cliFakeBin.dir = dir
	})
	if cliFakeBin.err != nil {
		t.Skipf("fake binaries unavailable (%v); CLI freeze suite skipped", cliFakeBin.err)
	}
	return cliFakeBin.dir
}

func cliExeSuffix() string {
	if os.PathSeparator == '\\' {
		return ".exe"
	}
	return ""
}

// ---- harness ---------------------------------------------------------------

type freezeHarness struct {
	t         *testing.T
	stateDir  string
	repoDir   string
	ctlDir    string
	deps      Deps
	store     *eFakeStore
	imageID   string
	ctx       context.Context
	cancelSig context.CancelFunc
}

func newFreezeHarness(t *testing.T) *freezeHarness {
	t.Helper()
	binDir := buildCLIFakes(t)
	base := t.TempDir()
	h := &freezeHarness{
		t:        t,
		stateDir: filepath.Join(base, "state"),
		repoDir:  filepath.Join(base, "vault"),
		ctlDir:   filepath.Join(base, "ctl"),
		imageID:  "sha256:" + strings.Repeat("fe", 32),
	}
	for _, d := range []string{h.stateDir, h.ctlDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The fake restic repository behind the registered vault.
	if out, err := exec.Command(filepath.Join(binDir, "fakerestic"+cliExeSuffix()),
		"--repo", h.repoDir, "init").CombinedOutput(); err != nil {
		t.Fatalf("fake restic init: %v: %s", err, out)
	}

	t.Setenv(vault.EnvPassword, "cli-freeze-secret")
	if _, err := vault.New(filepath.Join(h.stateDir, vault.RegistryFile)).
		Register("main", h.repoDir, "cli-fake-repo"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EBB_TEST_DOCKER_BIN", filepath.Join(binDir, "fakedocker"+cliExeSuffix()))
	t.Setenv("EBB_TEST_RESTIC_BIN", filepath.Join(binDir, "fakerestic"+cliExeSuffix()))
	t.Setenv("FAKE_BIN_DIR", h.ctlDir)

	h.store = newEFakeStore()
	h.ctx, h.cancelSig = context.WithCancel(context.Background())
	deps := RealDeps()
	deps.StateDir = func() (string, error) { return h.stateDir, nil }
	deps.OpenCatalog = catalog.Open
	deps.NewStore = func() (domain.SnapshotStore, func(), error) { return h.store, func() {}, nil }
	deps.StdinIsTerminal = func() bool { return false } // headless default; tests flip it
	deps.ReadLine = func() (string, error) { return "yes\n", nil }
	deps.NewSignalContext = func() (context.Context, func()) { return h.ctx, func() {} }
	h.deps = deps
	return h
}

func (h *freezeHarness) run(args ...string) (int, string, string) {
	h.t.Helper()
	var out, errb strings.Builder
	code := Main(append([]string{"freeze"}, args...), Streams{Out: &out, Err: &errb}, h.deps)
	return code, out.String(), errb.String()
}

func (h *freezeHarness) cat() *catalog.Catalog {
	h.t.Helper()
	c, err := catalog.Open(filepath.Join(h.stateDir, vault.CatalogFile))
	if err != nil {
		h.t.Fatalf("open catalog: %v", err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

func (h *freezeHarness) dockerLog() string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.ctlDir, "docker.log"))
	if err != nil {
		return ""
	}
	return string(b)
}

func (h *freezeHarness) setCTL(name, content string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.ctlDir, name), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *freezeHarness) setResticCTL(name, content string) {
	h.t.Helper()
	dir := filepath.Join(h.repoDir, "fake-control")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

func (h *freezeHarness) freezeEntries() []catalog.DockerImage {
	h.t.Helper()
	rows, err := h.cat().FindDockerImages(h.imageID)
	if err != nil {
		h.t.Fatalf("find docker images: %v", err)
	}
	return rows
}

// ---- freeze command tests ---------------------------------------------------

func TestFreezeCLIDryRunHasNoEffects(t *testing.T) {
	h := newFreezeHarness(t)
	h.setCTL("size", "1048576")

	code, stdout, stderr := h.run("--dry-run", "--json", h.imageID)
	if code != ExitOK {
		t.Fatalf("dry-run code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" {
		t.Fatalf("outcome = %q", envString(t, env, "outcome"))
	}
	details, _ := env["details"].(map[string]any)
	if details == nil || details["mode"] != "dry-run" || details["size_estimate"] != float64(1048576) {
		t.Fatalf("details = %v", details)
	}
	// No effects: no catalog row, no save stream.
	if rows := h.freezeEntries(); len(rows) != 0 {
		t.Fatalf("dry-run recorded rows: %+v", rows)
	}
	if log := h.dockerLog(); strings.Contains(log, "start save") {
		t.Fatalf("dry-run streamed a save:\n%s", log)
	}
	// A dry-run needs NO confirmation even headlessly (nothing happens).
}

func TestFreezeCLIConfirmationFailsClosed(t *testing.T) {
	h := newFreezeHarness(t)

	// Headless without --yes: blocked before any stream.
	code, stdout, _ := h.run("--json", h.imageID)
	if code != ExitBlocked {
		t.Fatalf("headless without --yes code = %d, stdout = %s", code, stdout)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "blocked" ||
		!strings.Contains(strings.Join(envStrings(t, env, "errors"), " "), CodeFreezeUnconfirmed) {
		t.Fatalf("envelope = %v", env)
	}
	if rows := h.freezeEntries(); len(rows) != 0 {
		t.Fatalf("blocked confirmation still recorded rows: %+v", rows)
	}
	if log := h.dockerLog(); strings.Contains(log, "start save") {
		t.Fatalf("a blocked freeze streamed a save:\n%s", log)
	}

	// Interactive decline.
	h.deps.StdinIsTerminal = func() bool { return true }
	h.deps.ReadLine = func() (string, error) { return "no\n", nil }
	code, _, stderr := h.run(h.imageID)
	if code != ExitBlocked || !strings.Contains(stderr, "declined") {
		t.Fatalf("declined code = %d stderr = %s", code, stderr)
	}
}

func TestFreezeCLIHappyFreezeEnvelope(t *testing.T) {
	h := newFreezeHarness(t)
	h.setCTL("save-bytes", fmt.Sprintf("%d", 96*1024))

	code, stdout, stderr := h.run("--json", "--yes", h.imageID)
	if code != ExitOK {
		t.Fatalf("freeze code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" {
		t.Fatalf("outcome = %q: %v", envString(t, env, "outcome"), env)
	}
	details, _ := env["details"].(map[string]any)
	for _, key := range []string{"image_id", "entry_id", "snapshot_id", "sha256", "bytes", "filename", "vault"} {
		if _, ok := details[key]; !ok {
			t.Fatalf("details lacks %q: %v", key, details)
		}
	}
	if details["verified"] != true {
		t.Fatalf("verified = %v", details["verified"])
	}
	if details["daemon_image_removed"] != nil {
		t.Fatalf("removal must not appear without --remove: %v", details)
	}
	// bytes summary rides the §17.2 envelope.
	if env["bytes"] == nil {
		t.Fatalf("envelope lacks bytes summary: %v", env)
	}
	rows := h.freezeEntries()
	if len(rows) != 1 || !rows[0].Pinned || rows[0].VerifiedAt == "" {
		t.Fatalf("rows = %+v", rows)
	}
	if log := h.dockerLog(); !strings.Contains(log, "save-complete") || strings.Contains(log, "rmi") {
		t.Fatalf("docker log discipline broken:\n%s", log)
	}
}

func TestFreezeCLITamperedReadbackReportsUnverified(t *testing.T) {
	h := newFreezeHarness(t)
	h.setCTL("save-bytes", "32768")
	h.setResticCTL("tamper", "1")

	code, stdout, _ := h.run("--json", "--yes", h.imageID)
	if code != ExitCaptureVerify {
		t.Fatalf("tampered code = %d, stdout = %s", code, stdout)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "verification-failed" {
		t.Fatalf("outcome = %q", envString(t, env, "outcome"))
	}
	details, _ := env["details"].(map[string]any)
	if details["verified"] != false {
		t.Fatalf("verified = %v", details["verified"])
	}
	rows := h.freezeEntries()
	if len(rows) != 1 || rows[0].VerifiedAt != "" || !rows[0].Pinned {
		t.Fatalf("retained row = %+v (want unverified+pinned)", rows)
	}
	if strings.Contains(h.dockerLog(), "rmi") {
		t.Fatalf("tampered freeze removed the daemon image:\n%s", h.dockerLog())
	}
}

func TestFreezeCLIRemovalNeedsItsOwnConfirmation(t *testing.T) {
	h := newFreezeHarness(t)
	h.setCTL("save-bytes", "16384")

	// --remove WITHOUT --yes-removal, headless: the freeze stands, the
	// removal is declined with a warning, docker rmi never runs.
	code, stdout, stderr := h.run("--json", "--yes", "--remove", h.imageID)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	details, _ := env["details"].(map[string]any)
	if details["daemon_image_removed"] != nil {
		t.Fatalf("headless removal without --yes-removal must not remove: %v", details)
	}
	warnings := envStrings(t, env, "warnings")
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, CodeRemovalUnconfirmed) {
		t.Fatalf("warnings lack the removal-unconfirmed code: %v", warnings)
	}
	if strings.Contains(h.dockerLog(), "rmi") {
		t.Fatalf("docker rmi ran without the removal confirmation:\n%s", h.dockerLog())
	}

	// The explicit pair removes and records the audit.
	code, stdout, stderr = h.run("--json", "--yes", "--remove", "--yes-removal", h.imageID)
	if code != ExitOK {
		t.Fatalf("removal run code = %d, stderr = %s", code, stderr)
	}
	env = envelopeOf(t, stdout)
	details, _ = env["details"].(map[string]any)
	if details["daemon_image_removed"] != true || details["daemon_removed_at"] == nil {
		t.Fatalf("removal audit missing: %v", details)
	}
	if !strings.Contains(h.dockerLog(), "rmi-done "+h.imageID) {
		t.Fatalf("docker log lacks the audited rmi:\n%s", h.dockerLog())
	}
	// The removal is recorded on the LATEST entry row.
	rows := h.freezeEntries()
	if len(rows) != 2 || rows[1].DaemonRemovedAt == "" {
		t.Fatalf("rows = %+v (second freeze's removal audit missing)", rows)
	}

	// --yes-removal alone is an argument mistake.
	if code, _, _ := h.run("--yes", "--yes-removal", h.imageID); code != ExitUsage {
		t.Fatalf("--yes-removal without --remove code = %d, want usage", code)
	}
}

func TestFreezeCLIRestoreVerifyBeforeLoad(t *testing.T) {
	h := newFreezeHarness(t)
	h.setCTL("save-bytes", "65536")
	if code, _, stderr := h.run("--yes", h.imageID); code != ExitOK {
		t.Fatalf("freeze code stderr = %s", stderr)
	}
	rows := h.freezeEntries()
	entryID := string(rows[0].ID)

	// Restore by entry id.
	code, stdout, stderr := h.run("--json", "--restore", entryID)
	if code != ExitOK {
		t.Fatalf("restore code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	details, _ := env["details"].(map[string]any)
	if details["mode"] != "restore" || details["load_output"] == nil || details["bytes"] == nil {
		t.Fatalf("restore details = %v", details)
	}
	if !strings.Contains(h.dockerLog(), "load bytes=65536") {
		t.Fatalf("docker log lacks the verified load:\n%s", h.dockerLog())
	}

	// Restore by image id with a tampered vault: exit 4 and docker load
	// NEVER receives a byte (no load process at all beyond the one above).
	before := h.dockerLog()
	h.setResticCTL("tamper", "1")
	code, stdout, _ = h.run("--json", "--restore", h.imageID)
	if code != ExitCaptureVerify {
		t.Fatalf("tampered restore code = %d, stdout = %s", code, stdout)
	}
	after := h.dockerLog()
	if strings.Count(after, "load bytes=") != strings.Count(before, "load bytes=") {
		t.Fatalf("docker load ran despite the tampered vault:\n%s", after)
	}

	// Unknown entry/image ids are usage mistakes.
	if code, _, _ := h.run("--restore", "sha256:"+strings.Repeat("00", 32)); code != ExitUsage {
		t.Fatalf("unknown image code = %d, want usage", code)
	}
	if code, _, _ := h.run("--restore", strings.Repeat("q", 32)); code != ExitUsage {
		t.Fatalf("unknown entry code = %d, want usage", code)
	}
}

// TestFreezeRestoreUnknownEntrySafeActionIsHonest pins the safe-action
// text of the entry-id miss (W2-4): `ebb status` renders nothing about
// freezes and no freeze list command exists, so the guidance may only
// name the real command surface — resolve by image id, re-freeze, and
// `ebb doctor` for the catalog's frozen-image row count.
func TestFreezeRestoreUnknownEntrySafeActionIsHonest(t *testing.T) {
	h := newFreezeHarness(t)

	code, _, stderr := h.run("--restore", strings.Repeat("0", 32))
	if code != ExitUsage {
		t.Fatalf("unknown entry code = %d, stderr = %s", code, stderr)
	}
	if strings.Contains(stderr, "ebb status") {
		t.Fatalf("safe action still points at `ebb status`, which renders nothing about freezes: %s", stderr)
	}
	if strings.Contains(stderr, "--list") {
		t.Fatalf("safe action points at a nonexistent list command: %s", stderr)
	}
	for _, want := range []string{"image id", "re-freeze", "`ebb freeze", "`ebb doctor`"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("safe action lacks %q: %s", want, stderr)
		}
	}
}

func TestFreezeCLIUnknownImageAndBadArgs(t *testing.T) {
	h := newFreezeHarness(t)
	h.setCTL("inspect-missing", "1")
	code, _, stderr := h.run("--yes", h.imageID)
	if code != ExitUsage || !strings.Contains(stderr, "does not know image") {
		t.Fatalf("unknown image code = %d stderr = %s", code, stderr)
	}

	if code, _, _ := h.run(); code != ExitUsage {
		t.Fatalf("no argument code = %d", code)
	}
	if code, _, _ := h.run("--restore", "x", "y"); code != ExitUsage {
		t.Fatalf("restore+positional code = %d", code)
	}
	if code, _, _ := h.run("--dry-run", "--remove", h.imageID); code != ExitUsage {
		t.Fatalf("conflicting flags code = %d", code)
	}
	if code, _, stderr := h.run("--yes", "bad image"); code != ExitUsage || !strings.Contains(stderr, "image id") {
		t.Fatalf("bad spelling code = %d stderr = %s", code, stderr)
	}
}

func TestFreezeCLIDockerUnreachableBlocked(t *testing.T) {
	h := newFreezeHarness(t)
	h.setCTL("version-fail", "1")
	code, stdout, _ := h.run("--json", "--yes", h.imageID)
	if code != ExitBlocked {
		t.Fatalf("unreachable daemon code = %d, stdout = %s", code, stdout)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "blocked" {
		t.Fatalf("outcome = %q", envString(t, env, "outcome"))
	}
	if rows := h.freezeEntries(); len(rows) != 0 {
		t.Fatalf("rows recorded against a dead daemon: %+v", rows)
	}
}

func envStrings(t *testing.T, env map[string]any, key string) []string {
	t.Helper()
	raw, ok := env[key].([]any)
	if !ok {
		t.Fatalf("envelope field %q missing or not an array: %v", key, env[key])
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---- Wave 2 doctor probe contracts -------------------------------------------

// linkPrivErr is the structural privilege marker the doctor detects
// without importing platform's concrete type.
type linkPrivErr struct{ detail string }

func (e *linkPrivErr) Error() string              { return e.detail }
func (e *linkPrivErr) LinkPrivilegeBlocked() bool { return true }

func TestDoctorDevModeProbe(t *testing.T) {
	regOn := func() (uint32, bool, error) { return 1, true, nil }
	regOff := func() (uint32, bool, error) { return 0, false, nil }
	regBroken := func() (uint32, bool, error) { return 0, false, fmt.Errorf("denied") }
	okSymlink := func() error { return nil }

	if c := devModeProbeCheck("linux", regOn, okSymlink); c.Status != "n/a" {
		t.Fatalf("non-windows = %+v, want n/a", c)
	}
	if c := devModeProbeCheck("windows", regOn, okSymlink); c.Status != "pass" {
		t.Fatalf("dev mode on + live ok = %+v", c)
	}
	if c := devModeProbeCheck("windows", regOff, okSymlink); c.Status != "pass" {
		t.Fatalf("elevated live ok = %+v", c)
	}
	privBlocked := func() error { return &linkPrivErr{"errno 1314"} }
	c := devModeProbeCheck("windows", regOff, privBlocked)
	if c.Status != "warn" || !strings.Contains(c.Detail, "Developer Mode is OFF") {
		t.Fatalf("privilege-blocked = %+v", c)
	}
	c = devModeProbeCheck("windows", regOn, privBlocked)
	if c.Status != "warn" || !strings.Contains(c.Detail, "live probe was refused") {
		t.Fatalf("lying registry = %+v", c)
	}
	if c := devModeProbeCheck("windows", regBroken, okSymlink); c.Status != "warn" || !strings.Contains(c.Detail, "registry unreadable") {
		t.Fatalf("broken registry = %+v", c)
	}
}

func TestDoctorWslVhdxProbe(t *testing.T) {
	none := func() []string { return nil }
	one := func() []string { return []string{`C:\u\Docker\wsl\disk\docker_data.vhdx`} }
	wslErr := func() ([]string, error) { return nil, fmt.Errorf("wsl.exe not found") }
	wslOK := func() ([]string, error) { return []string{"docker-desktop", "Ubuntu"}, nil }

	if c := wslVhdxProbeCheck("linux", one, nil, nil); c.Status != "n/a" {
		t.Fatalf("non-windows = %+v", c)
	}
	if c := wslVhdxProbeCheck("windows", none, nil, nil); c.Status != "warn" ||
		!strings.Contains(c.Detail, "no docker-desktop virtual disk") {
		t.Fatalf("no vhdx = %+v", c)
	}
	// Sparse disk with wsl ABSENT: still a pass — non-fatal by contract.
	sparse := func(string) (int64, int64, bool, error) { return 10 << 30, 2 << 30, true, nil }
	c := wslVhdxProbeCheck("windows", one, sparse, wslErr)
	if c.Status != "pass" || strings.Contains(c.Detail, "distro") {
		t.Fatalf("sparse + wsl absent = %+v", c)
	}
	// Fully allocated big disk: warn with the copy-pasteable commands.
	full := func(string) (int64, int64, bool, error) { return 10 << 30, 10 << 30, true, nil }
	c = wslVhdxProbeCheck("windows", one, full, wslOK)
	if c.Status != "warn" || !strings.Contains(c.Detail, "set-sparse true") || !strings.Contains(c.Detail, "docker-desktop WSL distro is installed") {
		t.Fatalf("fully allocated = %+v", c)
	}
	// Allocation unobservable: honest warn, no invented numbers.
	unknown := func(string) (int64, int64, bool, error) { return 10 << 30, 0, false, nil }
	if c := wslVhdxProbeCheck("windows", one, unknown, wslErr); c.Status != "warn" || !strings.Contains(c.Detail, "not observable") {
		t.Fatalf("unknown allocation = %+v", c)
	}
}

func TestDoctorDockerProbe(t *testing.T) {
	missing := func(string) (string, error) { return "", fmt.Errorf("not found") }
	found := func(string) (string, error) { return `C:\docker.exe`, nil }
	dead := func(context.Context, string) (string, error) {
		return "", fmt.Errorf("Cannot connect to the Docker daemon")
	}
	alive := func(context.Context, string) (string, error) {
		return "Docker version 27.5.1, build abc", nil
	}

	if c := dockerProbeCheck(missing, dead); c.Status != "warn" || !strings.Contains(c.Detail, "not found on PATH") {
		t.Fatalf("absent docker = %+v", c)
	}
	c := dockerProbeCheck(found, dead)
	if c.Status != "warn" || !strings.Contains(c.Detail, "did not answer") {
		t.Fatalf("dead daemon = %+v", c)
	}
	if c := dockerProbeCheck(found, alive); c.Status != "pass" || !strings.Contains(c.Detail, "27.5.1") {
		t.Fatalf("healthy docker = %+v", c)
	}
}
