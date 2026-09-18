package actions_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ebb/internal/actions"
)

// helperExe is a tiny Go tool built once in TestMain. Using a real
// compiled binary keeps the tests off cmd.exe/scripts, so shell
// detection never fires incidentally (Argv[0] is not a shell name).
var helperExe string

// helperSource is the single-file source of the test helper. Modes:
//
//	emit <path> <text>     create parent dirs, write text, print CWD=
//	probe [outpath]        write "probed" to outpath if given; report env
//	linger <s> <a> <b>     write marker a, sleep s seconds, write marker b
//	flood <n> [outpath]     print FLOOD-HEAD, ~n bytes, FLOOD-TAIL
//	fail                   exit with code 7
const helperSource = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: helper <mode> [args...]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "emit":
		if len(os.Args) != 4 {
			fail(fmt.Errorf("emit wants path and text"))
		}
		mustWrite(os.Args[2], []byte(os.Args[3]))
		wd, err := os.Getwd()
		if err != nil {
			fail(err)
		}
		fmt.Printf("CWD=%s\n", wd)
	case "probe":
		if len(os.Args) == 3 {
			mustWrite(os.Args[2], []byte("probed"))
		}
		fmt.Printf("SECRET_PRESENT=%t\n", hasEnv("EBB_TEST_SECRET"))
		fmt.Printf("PUBLIC_VALUE=%s\n", os.Getenv("EBB_TEST_PUBLIC"))
		fmt.Printf("PATH_PRESENT=%t\n", os.Getenv("PATH") != "")
	case "linger":
		if len(os.Args) != 5 {
			fail(fmt.Errorf("linger wants seconds and two marker paths"))
		}
		secs, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fail(err)
		}
		mustWrite(os.Args[3], []byte("start"))
		time.Sleep(time.Duration(secs) * time.Second)
		mustWrite(os.Args[4], []byte("end"))
	case "flood":
		if len(os.Args) < 3 {
			fail(fmt.Errorf("flood wants a byte count"))
		}
		n, err := strconv.Atoi(os.Args[2])
		if err != nil {
			fail(err)
		}
		if len(os.Args) == 4 {
			mustWrite(os.Args[3], []byte("flooded"))
		}
		fmt.Println("FLOOD-HEAD")
		line := strings.Repeat("x", 64)
		for written := 0; written < n; written += len(line) + 1 {
			fmt.Println(line)
		}
		fmt.Println("FLOOD-TAIL")
	case "fail":
		os.Exit(7)
	default:
		fail(fmt.Errorf("unknown mode %q", os.Args[1]))
	}
}

func hasEnv(key string) bool {
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, key+"=") {
			return true
		}
	}
	return false
}

func mustWrite(path string, content []byte) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fail(err)
		}
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "helper:", err)
	os.Exit(1)
}
`

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ebb-actions-helper-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "actions test: temp dir:", err)
		os.Exit(1)
	}
	exe, err := buildHelper(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "actions test: build helper:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	helperExe = exe
	code := m.Run()
	// Test-only cleanup of our own scratch directory; the shipped
	// package has no removal API (see audit_test.go).
	os.RemoveAll(dir)
	os.Exit(code)
}

// buildHelper compiles the inline helper source once. It lives in its
// own tiny module so the build cannot depend on this repository's
// module graph.
func buildHelper(dir string) (string, error) {
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(helperSource), 0o644); err != nil {
		return "", err
	}
	goMod := "module ebb-action-test-helper\n\ngo 1.27\n"
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte(goMod), 0o644); err != nil {
		return "", err
	}
	exe := filepath.Join(dir, "helper")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Dir = src
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build: %w\n%s", err, out)
	}
	return exe, nil
}

func isWindows() bool { return runtime.GOOS == "windows" }

func pathEqual(a, b string) bool {
	if isWindows() {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// stubApprover implements actions.Approver with canned results.
type stubApprover struct {
	approval *actions.Approval
	err      error
}

func (s stubApprover) Matches(actions.Definition, actions.ToolIdentity, map[string]string) (*actions.Approval, error) {
	return s.approval, s.err
}

// buildApproval records what an honest approval flow would pin for def:
// the resolved tool identity and the digests of the current inputs.
func buildApproval(t *testing.T, def actions.Definition, wsRoot string) *actions.Approval {
	t.Helper()
	tool, err := actions.ResolveTool(def.Argv[0])
	if err != nil {
		t.Fatal(err)
	}
	digests := make(map[string]string, len(def.Inputs))
	for _, rel := range def.Inputs {
		d, err := actions.DigestFile(filepath.Join(wsRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		digests[rel] = d
	}
	return &actions.Approval{
		ActionID:     def.ID,
		ArgvDigest:   actions.ArgvDigest(def.Argv),
		Tool:         tool,
		InputDigests: digests,
		EnvAllow:     actions.CanonicalEnvAllow(def.EnvAllow),
		Network:      def.Network,
		ApprovedBy:   "test",
		ApprovedAt:   time.Now().UTC().Format(time.RFC3339),
	}
}

// emitDef returns a definition whose helper run creates marker at the
// root-relative path markerRel (always under the working root "sub" so
// the test also proves WorkingRoot handling) and reports its cwd.
func emitDef(markerRel string, inputs ...string) actions.Definition {
	return actions.Definition{
		ID:          "emit-action",
		Argv:        []string{helperExe, "emit", markerRel, "written"},
		WorkingRoot: "sub",
		Inputs:      inputs,
		Outputs:     []string{filepath.ToSlash(filepath.Join("sub", markerRel))},
		Network:     actions.NetworkNone,
		Timeout:     30 * time.Second,
	}
}

// setupEmitWS returns a workspace whose "sub" working root exists.
func setupEmitWS(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	return ws
}

func writeFileT(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunApprovedSucceeds(t *testing.T) {
	ws := setupEmitWS(t)
	writeFileT(t, filepath.Join(ws, "in.txt"), "input v1")
	def := emitDef("out/stamp.txt", "in.txt")

	res, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	if err != nil {
		t.Fatalf("approved run failed: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (excerpt: %q)", res.ExitCode, res.OutputExcerpt)
	}
	b, err := os.ReadFile(filepath.Join(ws, "sub", "out", "stamp.txt"))
	if err != nil || string(b) != "written" {
		t.Fatalf("marker not written by helper: %q, %v", b, err)
	}
	if !pathEqual(res.ToolUsed.ResolvedPath, helperExe) {
		t.Fatalf("ToolUsed.ResolvedPath = %q, want helper %q", res.ToolUsed.ResolvedPath, helperExe)
	}
	if res.Duration <= 0 {
		t.Error("duration must be positive")
	}
	if res.ShellWarning {
		t.Error("non-shell action must not carry the shell warning")
	}
	if !strings.Contains(res.OutputExcerpt, "CWD=") {
		t.Errorf("output excerpt lost the helper report: %q", res.OutputExcerpt)
	}
	// Working directory must be wsRoot/WorkingRoot.
	if !pathContainsFold(res.OutputExcerpt, "CWD="+filepath.Join(ws, "sub")) {
		t.Errorf("helper cwd %q not under working root %q", res.OutputExcerpt, filepath.Join(ws, "sub"))
	}
}

func pathContainsFold(haystack, needle string) bool {
	if !isWindows() {
		return strings.Contains(haystack, needle)
	}
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func TestRunUnapprovedNeverExecutes(t *testing.T) {
	ws := t.TempDir()
	def := emitDef("out/marker.txt")

	appr := stubApprover{err: &actions.ErrApprovalRequired{ActionID: def.ID}}
	_, err := actions.New().Run(context.Background(), def, ws, appr, nil)
	var req *actions.ErrApprovalRequired
	if !errors.As(err, &req) {
		t.Fatalf("expected *ErrApprovalRequired, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "sub")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("unapproved action executed: working root was created")
	}
}

func TestRunStaleNeverExecutes(t *testing.T) {
	ws := t.TempDir()
	def := emitDef("out/marker.txt")

	appr := stubApprover{err: &actions.ErrApprovalStale{Diff: []string{"tool sha256: changed"}}}
	_, err := actions.New().Run(context.Background(), def, ws, appr, nil)
	var stale *actions.ErrApprovalStale
	if !errors.As(err, &stale) || len(stale.Diff) != 1 {
		t.Fatalf("expected *ErrApprovalStale with one diff, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "sub")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("stale action executed: working root was created")
	}
}

func TestRunNilApproverRefused(t *testing.T) {
	ws := t.TempDir()
	def := emitDef("out/marker.txt")
	_, err := actions.New().Run(context.Background(), def, ws, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "nil approver") {
		t.Fatalf("nil approver must be refused, got: %v", err)
	}
}

func TestRunApproverNilApprovalRefused(t *testing.T) {
	ws := t.TempDir()
	def := emitDef("out/marker.txt")
	_, err := actions.New().Run(context.Background(), def, ws, stubApprover{}, nil)
	if err == nil || !strings.Contains(err.Error(), "neither an approval nor an error") {
		t.Fatalf("silent-nil approver must be refused, got: %v", err)
	}
}

func TestRunInvalidDefinitionNeverResolves(t *testing.T) {
	ws := t.TempDir()
	def := emitDef("out/marker.txt")
	def.Inputs = []string{"../outside.txt"}
	// The approval stub is irrelevant: validation must refuse before any
	// resolution or digestion happens.
	_, err := actions.New().Run(context.Background(), def, ws, stubApprover{}, nil)
	if err == nil || !strings.Contains(err.Error(), "..") {
		t.Fatalf("invalid definition must be rejected before exec, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "sub")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("invalid definition executed")
	}
}

func TestRunMissingInput(t *testing.T) {
	ws := t.TempDir()
	def := emitDef("out/marker.txt", "absent.txt")

	// An approving stub proves the refusal happens before approval even
	// matters: the input cannot be digested, so no process is spawned.
	_, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: nil}, nil)
	var missing *actions.ErrInputMissing
	if !errors.As(err, &missing) || missing.Path != "absent.txt" {
		t.Fatalf("expected *ErrInputMissing for absent.txt, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "sub")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("action with missing input executed")
	}
}

func TestRunMissingWorkingDir(t *testing.T) {
	ws := t.TempDir()
	def := emitDef("out/marker.txt")
	def.WorkingRoot = "ghost/dir"
	def.Outputs = []string{"ghost/dir/out/marker.txt"}

	_, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	if err == nil || !strings.Contains(err.Error(), "working dir") {
		t.Fatalf("missing working dir must fail, got: %v", err)
	}
}

func TestRunMissingOutputDetected(t *testing.T) {
	ws := setupEmitWS(t)
	writeFileT(t, filepath.Join(ws, "in.txt"), "v1")
	def := emitDef("out/stamp.txt", "in.txt")
	def.Argv = []string{helperExe, "emit", "out/real.txt", "x"} // writes a different path
	def.Outputs = []string{"sub/out/real.txt", "sub/out/never.txt"}

	res, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	var missing *actions.ErrOutputMissing
	if !errors.As(err, &missing) {
		t.Fatalf("expected *ErrOutputMissing, got: %v (result %+v)", err, res)
	}
	if len(missing.Outputs) != 1 || missing.Outputs[0] != "sub/out/never.txt" {
		t.Fatalf("ErrOutputMissing must name the absent output, got: %v", missing.Outputs)
	}
	if res.ExitCode != 0 {
		t.Fatalf("the helper itself succeeded; exit = %d", res.ExitCode)
	}
}

func TestRunNonZeroExitIsResultNotError(t *testing.T) {
	ws := setupEmitWS(t)
	def := emitDef("out/stamp.txt")
	def.Argv = []string{helperExe, "fail"}

	res, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	if err != nil {
		t.Fatalf("non-zero exit is a result, not an error: %v", err)
	}
	if res.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", res.ExitCode)
	}
}

func TestRunEnvAllowEnforcement(t *testing.T) {
	ws := setupEmitWS(t)
	t.Setenv("EBB_TEST_SECRET", "leak-me")
	t.Setenv("EBB_TEST_PUBLIC", "42")

	def := emitDef("out/probe.txt")
	def.Argv = []string{helperExe, "probe", "out/probe.txt"}
	def.EnvAllow = []string{"EBB_TEST_PUBLIC"}

	res, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ex := res.OutputExcerpt
	if !strings.Contains(ex, "SECRET_PRESENT=false") {
		t.Errorf("secret env var leaked into the child environment: %q", ex)
	}
	if !strings.Contains(ex, "PUBLIC_VALUE=42") {
		t.Errorf("allowlisted env var was not passed: %q", ex)
	}
	if !strings.Contains(ex, "PATH_PRESENT=true") {
		t.Errorf("substrate PATH missing from child environment: %q", ex)
	}
}

func TestRunTimeoutKillsChild(t *testing.T) {
	ws := t.TempDir()
	def := actions.Definition{
		ID:      "linger-action",
		Argv:    []string{helperExe, "linger", "15", "start.txt", "end.txt"},
		Outputs: []string{"end.txt"},
		Network: actions.NetworkNone,
		Timeout: 800 * time.Millisecond,
	}

	start := time.Now()
	res, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	elapsed := time.Since(start)
	var timeout *actions.ErrTimeout
	if !errors.As(err, &timeout) {
		t.Fatalf("expected *ErrTimeout, got: %v (result %+v)", err, res)
	}
	if timeout.ActionID != def.ID || timeout.Timeout != def.Timeout {
		t.Fatalf("timeout error detail wrong: %+v", timeout)
	}
	if elapsed > 10*time.Second {
		t.Fatalf("timeout enforcement stalled: %s", elapsed)
	}
	if b, err := os.ReadFile(filepath.Join(ws, "start.txt")); err != nil || string(b) != "start" {
		t.Fatalf("child should have started (start marker): %q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(ws, "end.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("child was not killed before finishing")
	}
}

func TestRunBoundedCaptureAndSink(t *testing.T) {
	ws := setupEmitWS(t)
	def := emitDef("out/stamp.txt")
	def.Argv = []string{helperExe, "flood", "300000", "out/stamp.txt"}

	var buf bytes.Buffer
	res, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, actions.WriterSink(&buf))
	if err != nil {
		t.Fatal(err)
	}
	// The live sink sees everything...
	if buf.Len() < 290_000 {
		t.Fatalf("sink lost output: %d bytes", buf.Len())
	}
	// ...while the captured excerpt is bounded to first+last 64 KiB.
	if len(res.OutputExcerpt) > 140_000 {
		t.Fatalf("excerpt not bounded: %d bytes", len(res.OutputExcerpt))
	}
	if !strings.Contains(res.OutputExcerpt, "FLOOD-HEAD") {
		t.Error("excerpt lost the head of the output")
	}
	if !strings.Contains(res.OutputExcerpt, "FLOOD-TAIL") {
		t.Error("excerpt lost the tail of the output")
	}
	if !strings.Contains(res.OutputExcerpt, "bytes dropped") {
		t.Error("excerpt did not mark the dropped middle")
	}
}

func TestRunShellWarningSurfaces(t *testing.T) {
	if !isWindows() {
		t.Skip("cmd.exe shell test is windows-only")
	}
	ws := t.TempDir()
	def := actions.Definition{
		ID:      "shell-action",
		Argv:    []string{"cmd.exe", "/c", "echo shell-ok > shell-out.txt"},
		Outputs: []string{"shell-out.txt"},
		Network: actions.NetworkNone,
		Timeout: 30 * time.Second,
	}
	if !def.IsShell() || def.ShellWarning() != actions.ShellWarningMarker {
		t.Fatal("cmd.exe action must be detected as a shell action")
	}

	res, err := actions.New().Run(context.Background(), def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ShellWarning {
		t.Error("Result.ShellWarning must be set for shell actions")
	}
	b, err := os.ReadFile(filepath.Join(ws, "shell-out.txt"))
	if err != nil || !strings.Contains(string(b), "shell-ok") {
		t.Fatalf("shell action output missing: %q %v", b, err)
	}
}

func TestRunCancellationPropagates(t *testing.T) {
	ws := t.TempDir()
	def := actions.Definition{
		ID:      "linger-action",
		Argv:    []string{helperExe, "linger", "15", "start.txt", "end.txt"},
		Outputs: []string{"end.txt"},
		Network: actions.NetworkNone,
		Timeout: time.Minute,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(500 * time.Millisecond)
		cancel()
	}()
	_, err := actions.New().Run(ctx, def, ws, stubApprover{approval: buildApproval(t, def, ws)}, nil)
	if err == nil || !strings.Contains(err.Error(), "canceled by caller") {
		t.Fatalf("caller cancellation must surface as an error, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "end.txt")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("canceled child kept running to completion")
	}
}
