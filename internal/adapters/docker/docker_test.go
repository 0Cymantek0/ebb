package dockeradapter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mergeScenario returns base with override entries prepended (the
// fake's first-prefix-match-wins rule makes the override effective).
func mergeScenario(base map[string]any, overrides ...map[string]any) map[string]any {
	list := make([]any, 0, len(overrides)+4)
	for _, o := range overrides {
		list = append(list, o)
	}
	if baseCmds, ok := base["cmds"].([]any); ok {
		list = append(list, baseCmds...)
	}
	return map[string]any{"cmds": list}
}

func TestProbeReachable(t *testing.T) {
	e, _ := newTestEngine(t, baseScenario())
	if err := e.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestProbeDaemonUnreachable(t *testing.T) {
	scenario := withCmds(
		fakeCmd([]string{"version"}, map[string]any{
			"rc": 1, "stderr": "Cannot connect to the Docker daemon at npipe:////./pipe/docker_engine\n"}),
		fakeCmd([]string{"info"}, map[string]any{
			"rc": 1, "stderr": "Cannot connect to the Docker daemon at npipe:////./pipe/docker_engine\n"}),
	)
	e, _ := newTestEngine(t, scenario)
	err := e.Probe(context.Background())
	if !errors.Is(err, ErrDaemonUnreachable) {
		t.Fatalf("Probe error = %v, want ErrDaemonUnreachable", err)
	}
	if !strings.Contains(err.Error(), "Cannot connect") {
		t.Fatalf("Probe error should carry the daemon-down detail: %v", err)
	}
}

func TestProbeAbsentBinary(t *testing.T) {
	if err := New("").Probe(context.Background()); !errors.Is(err, ErrBinaryAbsent) {
		t.Fatalf("Probe on empty bin = %v, want ErrBinaryAbsent", err)
	}
}

func TestProbeSpawnFailure(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-docker.exe")
	if err := New(missing).Probe(context.Background()); !errors.Is(err, ErrBinaryAbsent) {
		t.Fatalf("Probe on missing binary = %v, want ErrBinaryAbsent", err)
	}
}

func TestProbeInfoFallback(t *testing.T) {
	// `docker version` fails (some broken builds) but `docker info`
	// answers: the daemon is reachable through the fallback.
	scenario := withCmds(
		fakeCmd([]string{"version"}, map[string]any{"rc": 1, "stderr": "incompatible server\n"}),
		fakeCmd([]string{"info"}, map[string]any{"rc": 0, "stdout": "27.5.1\n"}),
	)
	e, _ := newTestEngine(t, scenario)
	if err := e.Probe(context.Background()); err != nil {
		t.Fatalf("Probe via info fallback: %v", err)
	}
}

func TestReportHonestWhenBinaryAbsent(t *testing.T) {
	rep, err := New("").Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.Available {
		t.Fatal("Available must be false without a binary")
	}
	if len(rep.Tiers) != 0 {
		t.Fatalf("Tiers must be empty when unavailable, got %d", len(rep.Tiers))
	}
	if len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "unavailable") {
		t.Fatalf("expected one honest unavailable warning, got %v", rep.Warnings)
	}
}

func TestReportHonestWhenDaemonDown(t *testing.T) {
	scenario := withCmds(
		fakeCmd([]string{"version"}, map[string]any{"rc": 1, "stderr": "Cannot connect\n"}),
		fakeCmd([]string{"info"}, map[string]any{"rc": 1, "stderr": "Cannot connect\n"}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("daemon-down must degrade, not error: %v", err)
	}
	if rep.Available || rep.Tiers != nil {
		t.Fatalf("daemon-down report must be empty/unavailable: %+v", rep)
	}
	if len(rep.Warnings) == 0 || !strings.Contains(strings.Join(rep.Warnings, "; "), "daemon unreachable") {
		t.Fatalf("expected daemon-unreachable warning, got %v", rep.Warnings)
	}
}

func TestChildEnvPassthroughAndScrub(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
	t.Setenv("EBB_TEST_SHOULD_NOT_PASS", "leak")
	t.Setenv("HOME", "/home/someone")
	scenario := withCmds(
		fakeCmd([]string{"version"}, map[string]any{
			"rc": 0, "stdout": "27.5.1\n",
			"env_dump": []any{"DOCKER_HOST", "EBB_TEST_SHOULD_NOT_PASS", "HOME"},
		}),
	)
	e, _ := newTestEngine(t, scenario)
	out, _, rc, err := e.run(context.Background(), time.Second,
		"version", "--format", serverVersionFormat)
	if err != nil || rc != 0 {
		t.Fatalf("run: err=%v rc=%d", err, rc)
	}
	got := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "ENV ") {
			k, v, _ := strings.Cut(strings.TrimPrefix(line, "ENV "), "=")
			got[k] = v
		}
	}
	if got["DOCKER_HOST"] != "tcp://127.0.0.1:2375" {
		t.Fatalf("DOCKER_HOST must pass through, got %q", got["DOCKER_HOST"])
	}
	if got["HOME"] != "/home/someone" {
		t.Fatalf("HOME must pass through, got %q", got["HOME"])
	}
	if got["EBB_TEST_SHOULD_NOT_PASS"] != "" {
		t.Fatalf("unrelated env var leaked into the docker child: %q", got["EBB_TEST_SHOULD_NOT_PASS"])
	}
}

func TestMalformedLinesSkippedNeverFatal(t *testing.T) {
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": "not json at all\n" +
			ndjson(map[string]any{
				"ID":         "sha256:" + strings.Repeat("a", 64),
				"Repository": "<none>", "Tag": "<none>",
				"Size": float64(1 << 20), "CreatedAt": "2020-01-01T00:00:00Z",
			}) +
			"{broken json\n"}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("malformed JSON must not error: %v", err)
	}
	if !rep.Available {
		t.Fatal("report must stay available")
	}
	t0 := tierOf(t, rep, 0)
	if len(t0.Items) != 1 {
		t.Fatalf("tier 0 items = %d, want 1 (the one parsable dangling row)", len(t0.Items))
	}
	joined := strings.Join(rep.Warnings, "; ")
	if !strings.Contains(joined, "malformed line") {
		t.Fatalf("expected malformed-line warning, got %v", rep.Warnings)
	}
}

func TestBuildxDegradationNonFatal(t *testing.T) {
	// Both buildx spellings fail: tier 1 degrades to empty with a
	// warning; the rest of the report is unaffected.
	e, _ := newTestEngine(t, baseScenario())
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t1 := tierOf(t, rep, 1)
	if len(t1.Items) != 0 || t1.CopyCommand != "" {
		t.Fatalf("tier 1 must be empty under buildx degradation: %+v", t1)
	}
	joined := strings.Join(rep.Warnings, "; ")
	if !strings.Contains(joined, "buildx") {
		t.Fatalf("expected buildx degradation warning, got %v", rep.Warnings)
	}
}

func TestBuildxRecordsParsed(t *testing.T) {
	old := time.Now().Add(-21 * 24 * time.Hour).UTC().Format(time.RFC3339)
	fresh := time.Now().Add(-2 * 24 * time.Hour).UTC().Format(time.RFC3339)
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"buildx", "du"}, map[string]any{
			"rc": 0,
			"stdout": `{"TotalSize":` + "3000000000" + `,"Records":[` +
				`{"ID":"sha256:` + strings.Repeat("c", 64) + `","LastUsedAt":"` + old + `","RecordType":"exec.cachemount","Usage":{"Size":2000000000}},` +
				`{"ID":"sha256:` + strings.Repeat("d", 64) + `","LastUsedAt":"` + fresh + `","RecordType":"source.local","Usage":{"Size":1000000000}}]}`,
		}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t1 := tierOf(t, rep, 1)
	if len(t1.Items) != 1 {
		t.Fatalf("tier 1 items = %d, want 1 (only the 21d-old record)", len(t1.Items))
	}
	if !strings.Contains(t1.Items[0].Detail, "exec.cachemount") {
		t.Fatalf("tier 1 detail should carry the record type: %s", t1.Items[0].Detail)
	}
	if t1.CopyCommand != cmdBuilderPrune {
		t.Fatalf("tier 1 command = %q, want %q", t1.CopyCommand, cmdBuilderPrune)
	}
}

func TestTruncationAt500(t *testing.T) {
	rows := make([]map[string]any, 0, 600)
	for i := 0; i < 600; i++ {
		rows = append(rows, map[string]any{
			"ID":         "sha256:" + hex64(i),
			"Repository": "<none>", "Tag": "<none>",
			"Size": float64(1 << 20), "CreatedAt": "2020-01-01T00:00:00Z",
		})
	}
	scenario := mergeScenario(baseScenario(),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(rows...)}),
	)
	e, _ := newTestEngine(t, scenario)
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	t0 := tierOf(t, rep, 0)
	if len(t0.Items) != 500 {
		t.Fatalf("tier 0 items = %d, want capped at 500", len(t0.Items))
	}
	joined := strings.Join(rep.Warnings, "; ")
	if !strings.Contains(joined, "truncated from 600 to 500") {
		t.Fatalf("expected truncation warning, got %v", rep.Warnings)
	}
}

func TestHostSlackHonestZeroWithoutProbe(t *testing.T) {
	// A nil allocation probe (or a non-Windows build) must yield an
	// honest zero: no tier 5 row, no slack claimed.
	e, _ := newTestEngine(t, baseScenario())
	rep, err := e.Report(context.Background(), nil)
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.HostSlack != 0 || rep.SlackCommand != "" {
		t.Fatalf("host slack must be zero/unclaimed without a probe: %d %q", rep.HostSlack, rep.SlackCommand)
	}
	for _, tier := range rep.Tiers {
		if tier.Tier == TierHostVHDXSlack {
			t.Fatal("tier 5 must be absent without the allocation capability")
		}
	}
}

// ---- read-only tripwire -------------------------------------------------

// mutatingVerbs is the denylist the engine's argv must never contain
// (mirrors internal/actions' NoDeletionVerbs pattern; here the stakes
// are daemon mutations, not filesystem ones).
var mutatingVerbs = map[string]bool{
	"prune": true, "rm": true, "rmi": true, "save": true, "load": true,
	"build": true, "run": true, "create": true, "kill": true, "stop": true,
	"start": true, "restart": true, "pause": true, "unpause": true,
	"exec": true, "cp": true, "commit": true, "push": true, "pull": true,
	"tag": true, "import": true, "export": true, "down": true, "up": true,
	"update": true, "wait": true, "attach": true,
}

func TestStaticAllowlistHasNoMutatingVerb(t *testing.T) {
	for _, rule := range allowedArgv {
		for _, tok := range rule.tokens {
			if mutatingVerbs[tok] {
				t.Errorf("allowlist argv %q contains mutating verb %q", rule.tokens, tok)
			}
		}
	}
}

func TestRunnerRefusesNonAllowlistedArgv(t *testing.T) {
	e, _ := newTestEngine(t, baseScenario())
	cases := [][]string{
		{"system", "prune", "-af"},
		{"image", "rm", "sha256:abc"},
		{"rmi", "postgres:14"},
		{"volume", "rm", "vol"},
		{"builder", "prune"},
		{"rm", "container"},
		{"container", "kill", "c"},
		{"save", "img", "-o", "x.tar"},
		{"load", "-i", "x.tar"},
		{"buildx", "build", "."},
		// Benign-but-unknown shapes are refused too (no widening).
		{"ps"},
		{"image", "ls"},
		{"version"},
		{"volume", "inspect", "ok-name;rm -rf /"},
		{"volume", "inspect", "../escape"},
	}
	for _, argv := range cases {
		_, _, _, err := e.run(context.Background(), time.Second, argv...)
		if !errors.Is(err, errNotAllowlisted) {
			t.Errorf("run(%q) error = %v, want errNotAllowlisted", argv, err)
		}
	}
}

func TestRunnerAcceptsVolumeInspectNames(t *testing.T) {
	scenario := withCmds(
		fakeCmd([]string{"volume", "inspect"}, map[string]any{
			"rc": 0, "volume_inspect": map[string]any{},
		}),
	)
	e, _ := newTestEngine(t, scenario)
	name64 := hex64(0)
	_, _, rc, err := e.run(context.Background(), time.Second,
		"volume", "inspect", "proj_db-data", name64)
	if err != nil || rc != 0 {
		t.Fatalf("charset-valid volume names must run: err=%v rc=%d", err, rc)
	}
}

func TestEveryExecutedArgvIsReadOnly(t *testing.T) {
	// Integration tripwire: run a full report against a rich fake and
	// verify every argv the engine actually executed is allowlisted and
	// free of mutating verbs.
	old := time.Now().Add(-90 * 24 * time.Hour).UTC().Format(time.RFC3339)
	scenario := richScenario(t, old)
	e, fe := newTestEngine(t, scenario)
	if _, err := e.Report(context.Background(), []string{t.TempDir()}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	invocations := fe.invocations(t)
	if len(invocations) == 0 {
		t.Fatal("expected docker invocations to be logged")
	}
	for _, argv := range invocations {
		if err := allowlistCheck(argv); err != nil {
			t.Errorf("executed argv %q is not allowlisted: %v", argv, err)
		}
		for _, tok := range argv {
			if mutatingVerbs[tok] {
				t.Errorf("executed argv %q contains mutating verb %q", argv, tok)
			}
		}
	}
}

// ---- opt-in real daemon round-trip --------------------------------------

func TestRealDockerRoundTrip(t *testing.T) {
	if os.Getenv("EBB_TEST_DOCKER_REAL") != "1" {
		t.Skip("EBB_TEST_DOCKER_REAL != 1: live docker round-trip not requested (the engine is read-only by design; this test performs no mutations)")
	}
	path, err := exec.LookPath("docker")
	if err != nil {
		t.Skipf("docker not on PATH: %v", err)
	}
	e := New(path)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := e.Probe(ctx); err != nil {
		// Opt-in means "I have a live daemon"; an unreachable one is a
		// precondition miss, not an engine defect — skip with the real
		// CLI's reason.
		t.Skipf("docker daemon not reachable, live round-trip skipped: %v", err)
	}
	rep, err := e.Report(ctx, []string{mustCwd(t)})
	if err != nil {
		t.Fatalf("real daemon report: %v", err)
	}
	if !rep.Available {
		t.Fatal("report must be available after a successful probe")
	}
	if len(rep.Tiers) == 0 {
		t.Fatal("expected tier rows")
	}
	for _, tier := range rep.Tiers {
		switch tier.CopyCommand {
		case "", cmdImagePrune, cmdVolumePrune, cmdImagePrune + " && " + cmdVolumePrune,
			cmdBuilderPrune, cmdHostSlack, freezePlaceholder:
		default:
			if !strings.HasPrefix(tier.CopyCommand, "docker rm ") &&
				!strings.HasPrefix(tier.CopyCommand, "docker rmi ") &&
				!strings.HasPrefix(tier.CopyCommand, "docker volume rm ") &&
				!strings.HasPrefix(tier.CopyCommand, freezePlaceholder+" ") {
				t.Errorf("tier %d: unexpected command %q", tier.Tier, tier.CopyCommand)
			}
		}
	}
}

func mustCwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

// ---- shared fixtures -----------------------------------------------------

// hex64 builds a distinct 64-hex identifier per seed whose FIRST 12
// chars (docker's short-id window) are unique: a zero-padded decimal
// prefix plus a hex tail. Only [0-9a-f] appears, so the values double
// as anonymous volume names.
func hex64(seed int) string {
	return fmt.Sprintf("%012d%052x", seed, seed)
}

// richScenario exercises every collection path once (for the
// read-only-argv integration test).
func richScenario(t *testing.T, oldISO string) map[string]any {
	t.Helper()
	return mergeScenario(baseScenario(),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(1), "Repository": "<none>", "Tag": "<none>",
				"Size": float64(1 << 20), "CreatedAt": oldISO},
			map[string]any{"ID": "sha256:" + hex64(2), "Repository": "postgres", "Tag": "14",
				"Size": float64(400 << 20), "CreatedAt": oldISO},
		)}),
		fakeCmd([]string{"ps", "-a"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"ID": "sha256:" + hex64(3), "Names": "old-1", "Image": "postgres:14",
				"State": "exited", "Status": "Exited (0) 3 weeks ago", "Labels": map[string]any{}})}),
		fakeCmd([]string{"volume", "ls"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"Name": hex64(9), "Driver": "local", "Labels": nil, "Links": float64(0)})}),
		fakeCmd([]string{"buildx", "du"}, map[string]any{"rc": 0, "stdout": "{}"}),
	)
}
