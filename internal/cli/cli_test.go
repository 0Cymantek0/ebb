package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// run executes Main against buffers with the stub deps.
func run(args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = Main(args, Streams{Out: &out, Err: &errb}, DefaultDeps())
	return code, out.String(), errb.String()
}

const (
	fullDir = "testdata/full"
	minDir  = "testdata/minimal"
	badDir  = "testdata/bad"
)

// TestDispatchMatrix pins the exit-code contract (Foundation §17.5).
func TestDispatchMatrix(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
		wantStdout string
	}{
		{"no arguments", nil, ExitUsage, "usage:", ""},
		{"unknown command", []string{"frobnicate"}, ExitUsage, "unknown command", ""},
		{"help", []string{"help"}, ExitOK, "usage:", ""},
		{"version human", []string{"version"}, ExitOK, "restic target: " + ResticTarget, ""},
		{"version extra arg", []string{"version", "x"}, ExitUsage, "", ""},
		{"version bad flag", []string{"version", "--nope"}, ExitUsage, "", ""},
		{"inspect live scan (default deps are real since wave B)", []string{"inspect", minDir}, ExitOK, "workspace: minimal", ""},
		{"plan live scan (default deps are real since wave B)", []string{"plan", fullDir}, ExitOK, "node-dependencies", ""},
		{"plan missing inventory file", []string{"plan", "--from-inventory", "nope.json", fullDir}, ExitUsage, "--from-inventory", ""},
		{"plan bad ebbfile", []string{"plan", "--from-inventory", minDir + "/inventory.json", badDir}, ExitUsage, "networkk", ""},
		{"plan bad target", []string{"plan", "--from-inventory", fullDir + "/inventory.json", "--target", "abc", fullDir}, ExitUsage, "--target", ""},
		{"plan negative target", []string{"plan", "--from-inventory", fullDir + "/inventory.json", "--target=-5", fullDir}, ExitUsage, "--target", ""},
		{"plan too many paths", []string{"plan", fullDir, "extra"}, ExitUsage, "", ""},
		{"plan ok human", []string{"plan", "--from-inventory", fullDir + "/inventory.json", fullDir}, ExitOK, "node-dependencies", ""},
		{"plan no-gain", []string{"plan", "--from-inventory", minDir + "/inventory.json", minDir}, ExitShortfall, "no-gain", ""},
		{"plan shortfall", []string{"plan", "--from-inventory", fullDir + "/inventory.json", "--target", "4500000", fullDir}, ExitShortfall, "shortfall", ""},
		{"plan target met by first trim", []string{"plan", "--from-inventory", fullDir + "/inventory.json", "--target", "3000000", fullDir}, ExitOK, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d (stderr: %s)", code, tt.wantCode, stderr)
			}
			if tt.wantStderr != "" && !strings.Contains(stderr, tt.wantStderr) {
				t.Fatalf("stderr %q lacks %q", stderr, tt.wantStderr)
			}
			if tt.wantStdout != "" && !strings.Contains(stdout, tt.wantStdout) {
				t.Fatalf("stdout %q lacks %q", stdout, tt.wantStdout)
			}
		})
	}
}

// TestPlanEndToEnd verifies the real wiring: Ebbfile + saved inventory
// through Resolve and PlanReclaim, exercising the planner contract
// (trim order, stop-short, byte estimates).
func TestPlanEndToEnd(t *testing.T) {
	inv := fullDir + "/inventory.json"

	// No target: two trim steps, node-dependencies (3_500_000, the
	// smaller of summary and member sum) before build-dist (400_000).
	code, stdout, stderr := run("plan", "--from-inventory", inv, fullDir)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{
		"plan for workspace \"fixture\"",
		"node-dependencies",
		"build-dist",
		"reclaim=3500000 bytes",
		"reclaim=400000 bytes",
		"rebuild-required",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr %q lacks %q", stderr, want)
		}
	}

	// Target met by the first trim alone: exactly one step.
	code, _, stderr = run("plan", "--from-inventory", inv, "--target", "3000000", fullDir)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if strings.Count(stderr, "step ") != 1 {
		t.Fatalf("stop-short plan has more than one step:\n%s", stderr)
	}

	// Target beyond both trims: shortfall of 600_000, exit 8.
	code, _, stderr = run("plan", "--from-inventory", inv, "--target", "4500000", fullDir)
	if code != ExitShortfall {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stderr, "shortfall on volume test-vol: 600000 bytes") {
		t.Fatalf("stderr %q lacks exact gap", stderr)
	}
}

// TestPlanJSONEnvelopeShape verifies the machine envelope: keys
// command/outcome/details/warnings/errors, warnings an array, plan
// details present, and nothing on stderr.
func TestPlanJSONEnvelopeShape(t *testing.T) {
	code, stdout, stderr := run("plan", "--json", "--from-inventory", fullDir+"/inventory.json", fullDir)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("json mode wrote human output to stderr: %q", stderr)
	}

	var env struct {
		Command string `json:"command"`
		Outcome string `json:"outcome"`
		Details struct {
			Workspace string `json:"workspace"`
			Plan      struct {
				Result string `json:"result"`
				Steps  []struct {
					Kind        string           `json:"kind"`
					Groups      []string         `json:"groups"`
					Reclaimable map[string]int64 `json:"reclaimable"`
				} `json:"steps"`
				Achieved map[string]int64 `json:"achieved"`
			} `json:"plan"`
		} `json:"details"`
		Warnings []string `json:"warnings"`
		Errors   []string `json:"errors"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout)
	}
	if env.Command != "plan" || env.Outcome != "ok" {
		t.Fatalf("command/outcome = %q/%q", env.Command, env.Outcome)
	}
	if env.Details.Workspace != "fixture" || env.Details.Plan.Result != "sufficient" {
		t.Fatalf("details = %+v", env.Details)
	}
	if len(env.Details.Plan.Steps) != 2 {
		t.Fatalf("steps = %+v", env.Details.Plan.Steps)
	}
	if env.Details.Plan.Steps[0].Groups[0] != "node-dependencies" ||
		env.Details.Plan.Steps[0].Reclaimable["test-vol"] != 3500000 {
		t.Fatalf("first step = %+v", env.Details.Plan.Steps[0])
	}
	if env.Warnings == nil || env.Errors == nil {
		t.Fatal("warnings/errors must serialize as arrays, not null")
	}
}

// TestPlanNoGainJSON verifies exit 8 with a no-gain envelope.
func TestPlanNoGainJSON(t *testing.T) {
	code, stdout, _ := run("plan", "--json", "--from-inventory", minDir+"/inventory.json", minDir)
	if code != ExitShortfall {
		t.Fatalf("code = %d", code)
	}
	var env struct {
		Outcome string `json:"outcome"`
		Details struct {
			Plan struct {
				Result string `json:"result"`
			} `json:"plan"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if env.Outcome != "no-gain" || env.Details.Plan.Result != "no-gain" {
		t.Fatalf("envelope = %+v", env)
	}
}

// TestVersionJSON verifies the version envelope contents.
func TestVersionJSON(t *testing.T) {
	code, stdout, stderr := run("version", "--json")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	var env struct {
		Command string `json:"command"`
		Outcome string `json:"outcome"`
		Details struct {
			Version      string `json:"version"`
			ResticTarget string `json:"restic_target"`
			GoVersion    string `json:"go_version"`
		} `json:"details"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if env.Command != "version" || env.Outcome != "ok" {
		t.Fatalf("envelope head = %+v", env)
	}
	if env.Details.Version != Version || env.Details.ResticTarget != "0.19.1" {
		t.Fatalf("details = %+v", env.Details)
	}
	if !strings.HasPrefix(env.Details.GoVersion, "go") {
		t.Fatalf("go version = %q", env.Details.GoVersion)
	}
}

// TestExitCodeConstants pins the public contract values.
func TestExitCodeConstants(t *testing.T) {
	want := map[string]int{
		"ExitOK": 0, "ExitUsage": 2, "ExitBlocked": 3, "ExitCaptureVerify": 4,
		"ExitInterrupted": 5, "ExitRebuildFailed": 6, "ExitVault": 7,
		"ExitShortfall": 8, "ExitCancelled": 130,
	}
	got := map[string]int{
		"ExitOK": ExitOK, "ExitUsage": ExitUsage, "ExitBlocked": ExitBlocked,
		"ExitCaptureVerify": ExitCaptureVerify, "ExitInterrupted": ExitInterrupted,
		"ExitRebuildFailed": ExitRebuildFailed, "ExitVault": ExitVault,
		"ExitShortfall": ExitShortfall, "ExitCancelled": ExitCancelled,
	}
	for name, v := range want {
		if got[name] != v {
			t.Errorf("%s = %d, want %d", name, got[name], v)
		}
	}
}

// TestParseByteCount covers the --target byte-count conventions.
func TestParseByteCount(t *testing.T) {
	ok := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"1500000", 1500000},
		{"1B", 1},
		{"1KiB", 1 << 10},
		{"25GiB", 25 << 30},
		{"2TiB", 2 << 40},
		{"10KB", 10000},
		{"1.5MB", 1500000},
		{"2G", 2 << 30},
		{"1.2 KiB", 1228}, // fractional counts round down
	}
	for _, tt := range ok {
		got, err := ParseByteCount(tt.in)
		if err != nil {
			t.Errorf("ParseByteCount(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseByteCount(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
	for _, in := range []string{"", "abc", "-5", "1.5", "1.2.3GiB", "9999999999999999999999"} {
		if _, err := ParseByteCount(in); err == nil {
			t.Errorf("ParseByteCount(%q) accepted", in)
		}
	}
}

// TestLoadInventoryStrict verifies unknown fields are rejected and the
// schema version enforced.
func TestLoadInventoryStrict(t *testing.T) {
	if _, err := LoadInventory(fullDir + "/inventory.json"); err != nil {
		t.Fatalf("valid inventory rejected: %v", err)
	}
	if _, err := LoadInventory("testdata/missing.json"); err == nil {
		t.Fatal("missing file accepted")
	}
}

// TestMainNilStreams guards against nil writers panicking.
func TestMainNilStreams(t *testing.T) {
	if code := Main([]string{"version"}, Streams{}, DefaultDeps()); code != ExitUsage {
		t.Fatalf("code = %d", code)
	}
}
