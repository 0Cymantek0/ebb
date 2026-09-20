package dockeradapter

// Fake docker CLI harness. The fake is a real Go binary compiled once
// per test run from inline source in its own tiny module (the same
// pattern as internal/actions/run_test.go — no shell scripts, no
// CRLF/heredoc hazards, works on Windows and POSIX).
//
// The fake is steered through DOCKER_* environment variables, which the
// engine's constructed child environment passes through by design — so
// the seam doubles as a live check that DOCKER_* passthrough works:
//
//	DOCKER_EBB_FAKE_SCRIPT  path to a JSON scenario (see below)
//	DOCKER_EBB_FAKE_LOG     path to the invocation log (JSON lines)
//
// Scenario shape (all fields optional unless noted):
//
//	{"cmds": [
//	   {"argv_prefix": ["version"], "rc": 0, "stdout": "27.5.1\n",
//	    "stderr": "...", "env_dump": ["DOCKER_HOST"],
//	    "volume_inspect": {"<volume name>": {"Name": ..., "Labels": {...}}}}
//	]}
//
// The first entry whose argv_prefix prefixes the invocation's argv
// wins. volume_inspect makes the fake answer `docker volume inspect
// <names...>` with a JSON array built from the requested names.
// Every invocation is appended to the log as {"argv":[...]} so tests
// can assert exactly what the engine executed (the no-mutation
// tripwire).

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

const fakeDockerSource = `package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func main() {
	argv := os.Args[1:]
	if log := os.Getenv("DOCKER_EBB_FAKE_LOG"); log != "" {
		entry, _ := json.Marshal(map[string]any{"argv": argv})
		f, err := os.OpenFile(log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err == nil {
			f.Write(append(entry, '\n'))
			f.Close()
		}
	}
	script := os.Getenv("DOCKER_EBB_FAKE_SCRIPT")
	if script == "" {
		fmt.Fprintln(os.Stderr, "fake docker: DOCKER_EBB_FAKE_SCRIPT not set")
		os.Exit(3)
	}
	raw, err := os.ReadFile(script)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake docker: read scenario:", err)
		os.Exit(3)
	}
	var sc map[string]any
	if err := json.Unmarshal(raw, &sc); err != nil {
		fmt.Fprintln(os.Stderr, "fake docker: bad scenario:", err)
		os.Exit(3)
	}
	for _, c := range asList(sc["cmds"]) {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		prefix := asList(m["argv_prefix"])
		if !matchesPrefix(argv, prefix) {
			continue
		}
		if inspect, ok := m["volume_inspect"].(map[string]any); ok {
			names := argv[len(prefix):]
			fmt.Println(marshalInspect(inspect, names))
		}
		if out, ok := m["stdout"].(string); ok && out != "" {
			fmt.Print(out)
		}
		for _, name := range asList(m["env_dump"]) {
			if s, ok := name.(string); ok {
				fmt.Printf("ENV %s=%s\n", s, os.Getenv(s))
			}
		}
		if errOut, ok := m["stderr"].(string); ok && errOut != "" {
			fmt.Fprint(os.Stderr, errOut)
		}
		rc := 0
		if v, ok := m["rc"].(float64); ok {
			rc = int(v)
		}
		os.Exit(rc)
	}
	fmt.Fprintln(os.Stderr, "fake docker: no scenario entry for argv:", strings.Join(argv, " "))
	os.Exit(4)
}

func matchesPrefix(argv []string, prefix []any) bool {
	if len(prefix) > len(argv) {
		return false
	}
	for i, p := range prefix {
		s, ok := p.(string)
		if !ok || argv[i] != s {
			return false
		}
	}
	return true
}

func marshalInspect(inspect map[string]any, names []string) string {
	recs := make([]any, 0, len(names))
	for _, name := range names {
		if rec, ok := inspect[name]; ok {
			recs = append(recs, rec)
		} else {
			recs = append(recs, map[string]any{"Name": name})
		}
	}
	out, _ := json.Marshal(recs)
	return string(out)
}

func asList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}
`

var fakeDockerExe string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ebb-docker-fake-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "docker adapter test: temp dir:", err)
		os.Exit(1)
	}
	exe, err := buildFakeDocker(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "docker adapter test: build fake docker:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	fakeDockerExe = exe
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// buildFakeDocker compiles the inline fake once, in its own tiny module
// so the build cannot depend on this repository's module graph.
func buildFakeDocker(dir string) (string, error) {
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(fakeDockerSource), 0o644); err != nil {
		return "", err
	}
	goMod := "module ebb-docker-fake-cli\n\ngo 1.27\n"
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte(goMod), 0o644); err != nil {
		return "", err
	}
	exe := filepath.Join(dir, "docker-fake")
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

// fakeEnv is one wired fake daemon scenario.
type fakeEnv struct {
	exe string
	log string
}

// startFake writes the scenario and points the engine's DOCKER_*
// passthrough at it.
func startFake(t *testing.T, scenario map[string]any) *fakeEnv {
	t.Helper()
	raw, err := json.Marshal(scenario)
	if err != nil {
		t.Fatalf("marshal scenario: %v", err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "scenario.json")
	if err := os.WriteFile(script, raw, 0o600); err != nil {
		t.Fatalf("write scenario: %v", err)
	}
	log := filepath.Join(dir, "invocations.jsonl")
	t.Setenv("DOCKER_EBB_FAKE_SCRIPT", script)
	t.Setenv("DOCKER_EBB_FAKE_LOG", log)
	return &fakeEnv{exe: fakeDockerExe, log: log}
}

// invocations returns every argv the engine executed against the fake.
func (f *fakeEnv) invocations(t *testing.T) [][]string {
	t.Helper()
	raw, err := os.ReadFile(f.log)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read invocation log: %v", err)
	}
	var out [][]string
	for _, line := range splitLines(string(raw)) {
		var rec struct {
			Argv []string `json:"argv"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad invocation log line %q: %v", line, err)
		}
		out = append(out, rec.Argv)
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	for _, line := range splitRaw(s) {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func splitRaw(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, trimCR(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, trimCR(s[start:]))
	}
	return out
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}

// ---- scenario helpers --------------------------------------------------

// fakeCmd builds one scenario entry.
func fakeCmd(prefix []string, fields map[string]any) map[string]any {
	m := map[string]any{"argv_prefix": prefix}
	for k, v := range fields {
		m[k] = v
	}
	return m
}

// ndjson renders rows as one JSON object per line.
func ndjson(rows ...map[string]any) string {
	out := ""
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			panic(err)
		}
		out += string(raw) + "\n"
	}
	return out
}

// baseScenario is a reachable daemon with empty collections; callers
// override the entries they care about by prepending their own (the
// first prefix match wins).
func baseScenario() map[string]any {
	return map[string]any{"cmds": []any{
		fakeCmd([]string{"version"}, map[string]any{"rc": 0, "stdout": "27.5.1\n"}),
		fakeCmd([]string{"info"}, map[string]any{"rc": 0, "stdout": "27.5.1\n"}),
		fakeCmd([]string{"image", "ls"}, map[string]any{"rc": 0, "stdout": ""}),
		fakeCmd([]string{"ps", "-a"}, map[string]any{"rc": 0, "stdout": ""}),
		fakeCmd([]string{"volume", "ls"}, map[string]any{"rc": 0, "stdout": ""}),
		fakeCmd([]string{"buildx", "du"}, map[string]any{"rc": 1, "stderr": "unknown flag: --json\n"}),
		fakeCmd([]string{"system", "df"}, map[string]any{"rc": 0, "stdout": ndjson(
			map[string]any{"Type": "Images", "Size": float64(1 << 30)},
			map[string]any{"Type": "Containers", "Size": float64(64 << 20)},
		)}),
	}}
}

// withCmds returns a scenario whose command list is cmds.
func withCmds(cmds ...map[string]any) map[string]any {
	list := make([]any, 0, len(cmds))
	for _, c := range cmds {
		list = append(list, c)
	}
	return map[string]any{"cmds": list}
}

// newTestEngine returns an engine on the fake with the allocation probe
// disabled, so tests are deterministic regardless of the host's real
// %LOCALAPPDATA%\Docker state.
func newTestEngine(t *testing.T, scenario map[string]any) (*Engine, *fakeEnv) {
	t.Helper()
	fe := startFake(t, scenario)
	return NewWithAllocationProbe(fe.exe, nil), fe
}
