package actions_test

import (
	"strings"
	"testing"
	"time"

	"ebb/internal/actions"
)

// validDef is the baseline used by the validation table; each case
// mutates one field.
func validDef() actions.Definition {
	return actions.Definition{
		ID:          "node-deps",
		Argv:        []string{"pnpm", "install", "--frozen-lockfile"},
		WorkingRoot: "",
		Inputs:      []string{"package.json", "pnpm-lock.yaml"},
		Outputs:     []string{"node_modules"},
		EnvAllow:    []string{"NODE_ENV"},
		Network:     actions.NetworkAllowed,
		Timeout:     10 * time.Minute,
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*actions.Definition)
		wantErr string // "" means the definition must validate
	}{
		{name: "baseline valid", mutate: func(d *actions.Definition) {}, wantErr: ""},
		{name: "working root dot valid", mutate: func(d *actions.Definition) { d.WorkingRoot = "." }, wantErr: ""},
		{name: "working root subdir valid", mutate: func(d *actions.Definition) { d.WorkingRoot = "sub/dir" }, wantErr: ""},
		{name: "empty id", mutate: func(d *actions.Definition) { d.ID = "" }, wantErr: "ID must not be empty"},
		{name: "empty argv", mutate: func(d *actions.Definition) { d.Argv = nil }, wantErr: "non-empty literal argument vector"},
		{name: "empty argv0", mutate: func(d *actions.Definition) { d.Argv = []string{"", "x"} }, wantErr: "non-empty literal argument vector"},
		{name: "no outputs", mutate: func(d *actions.Definition) { d.Outputs = nil }, wantErr: "at least one output root"},
		{name: "input backslash", mutate: func(d *actions.Definition) { d.Inputs[0] = `a\b.json` }, wantErr: "backslash"},
		{name: "input parent segment", mutate: func(d *actions.Definition) { d.Inputs[0] = "../secret.json" }, wantErr: "'..' segment"},
		{name: "input absolute", mutate: func(d *actions.Definition) { d.Inputs[0] = "/etc/passwd" }, wantErr: "absolute path"},
		{name: "input drive prefix", mutate: func(d *actions.Definition) { d.Inputs[0] = "C:/x.json" }, wantErr: "drive prefix"},
		{name: "output backslash", mutate: func(d *actions.Definition) { d.Outputs[0] = `out\bin` }, wantErr: "backslash"},
		{name: "output dot whole-root ownership", mutate: func(d *actions.Definition) { d.Outputs[0] = "." }, wantErr: "'.' segment"},
		{name: "duplicate input", mutate: func(d *actions.Definition) { d.Inputs = []string{"a.txt", "a.txt"} }, wantErr: "duplicate input path"},
		{name: "duplicate output", mutate: func(d *actions.Definition) { d.Outputs = []string{"a", "a"} }, wantErr: "duplicate output path"},
		{
			name:    "input equals output",
			mutate:  func(d *actions.Definition) { d.Inputs[0] = "node_modules"; d.Outputs[0] = "node_modules" },
			wantErr: "must not consume what it owns",
		},
		{
			name:    "input nested under output",
			mutate:  func(d *actions.Definition) { d.Inputs[0] = "node_modules/.pnpm/state.json" },
			wantErr: "must not consume what it owns",
		},
		{
			name:    "output nested under input",
			mutate:  func(d *actions.Definition) { d.Inputs[0] = "build"; d.Outputs[0] = "build/dist" },
			wantErr: "must not consume what it owns",
		},
		{
			name:    "adjacent paths are not overlap",
			mutate:  func(d *actions.Definition) { d.Inputs[0] = "node_modules_extra/manifest" },
			wantErr: "",
		},
		{name: "empty network", mutate: func(d *actions.Definition) { d.Network = "" }, wantErr: "network must be one of"},
		{name: "unknown network", mutate: func(d *actions.Definition) { d.Network = "sometimes" }, wantErr: `got "sometimes"`},
		{name: "zero timeout", mutate: func(d *actions.Definition) { d.Timeout = 0 }, wantErr: "timeout must be positive"},
		{name: "negative timeout", mutate: func(d *actions.Definition) { d.Timeout = -time.Second }, wantErr: "timeout must be positive"},
		{name: "self dependency", mutate: func(d *actions.Definition) { d.DependsOn = []string{"node-deps"} }, wantErr: "depends on itself"},
		{name: "env key empty", mutate: func(d *actions.Definition) { d.EnvAllow = []string{""} }, wantErr: "must not be empty"},
		{name: "env key with equals", mutate: func(d *actions.Definition) { d.EnvAllow = []string{"EVIL=PATH"} }, wantErr: "must not contain"},
		{name: "env key exact duplicate", mutate: func(d *actions.Definition) { d.EnvAllow = []string{"A", "A"} }, wantErr: "duplicate env allowlist key"},
		{name: "env key substrate path", mutate: func(d *actions.Definition) { d.EnvAllow = []string{"PATH"} }, wantErr: "OS substrate"},
		{name: "working root parent", mutate: func(d *actions.Definition) { d.WorkingRoot = "../out" }, wantErr: "working root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := validDef()
			tc.mutate(&d)
			err := d.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateEnvKeyCaseFoldDuplicate(t *testing.T) {
	d := validDef()
	d.EnvAllow = []string{"NODE_ENV", "node_env"}
	err := d.Validate()
	// Windows env matching is case-insensitive, so this is a duplicate
	// there and two distinct keys elsewhere.
	if isWindows() && err == nil {
		t.Fatal("expected case-folded duplicate env key to be rejected on windows")
	}
	if !isWindows() && err != nil {
		t.Fatalf("expected distinct-case env keys to be accepted on non-windows, got: %v", err)
	}
}

func TestValidateGraph(t *testing.T) {
	// mk gives each definition its own output root (overlapping outputs
	// across definitions are a graph-level rejection of their own — see
	// the overlap subtests below).
	mk := func(id string, deps ...string) actions.Definition {
		d := validDef()
		d.ID = id
		d.Outputs = []string{"out-" + id}
		d.DependsOn = deps
		return d
	}
	t.Run("acyclic", func(t *testing.T) {
		defs := []actions.Definition{mk("a", "b", "c"), mk("b", "c"), mk("c")}
		if err := actions.ValidateGraph(defs); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("empty graph", func(t *testing.T) {
		if err := actions.ValidateGraph(nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("cycle", func(t *testing.T) {
		defs := []actions.Definition{mk("a", "b"), mk("b", "c"), mk("c", "a")}
		err := actions.ValidateGraph(defs)
		if err == nil {
			t.Fatal("expected cycle error")
		}
		if !strings.Contains(err.Error(), "cycle") || !strings.Contains(err.Error(), "a -> b -> c -> a") {
			t.Fatalf("cycle error does not name the path: %v", err)
		}
	})
	t.Run("two node cycle", func(t *testing.T) {
		defs := []actions.Definition{mk("a", "b"), mk("b", "a")}
		if err := actions.ValidateGraph(defs); err == nil || !strings.Contains(err.Error(), "cycle") {
			t.Fatalf("expected cycle error, got: %v", err)
		}
	})
	t.Run("unknown dependency", func(t *testing.T) {
		defs := []actions.Definition{mk("a", "ghost")}
		err := actions.ValidateGraph(defs)
		if err == nil || !strings.Contains(err.Error(), `unknown action "ghost"`) {
			t.Fatalf("expected unknown-dependency error, got: %v", err)
		}
	})
	t.Run("duplicate id", func(t *testing.T) {
		defs := []actions.Definition{mk("a"), mk("a")}
		err := actions.ValidateGraph(defs)
		if err == nil || !strings.Contains(err.Error(), "duplicate action id") {
			t.Fatalf("expected duplicate-id error, got: %v", err)
		}
	})
	t.Run("invalid member propagates", func(t *testing.T) {
		bad := validDef()
		bad.Timeout = 0
		if err := actions.ValidateGraph([]actions.Definition{mk("a"), bad}); err == nil {
			t.Fatal("expected member validation error")
		}
	})
	// G1 amplifier regression: two definitions in one graph whose
	// declared outputs overlap (same path OR containment) race for the
	// same tree and each silently widens the other's F36 exclusion —
	// the reader-side twin of policy's capture-time output-conflict
	// rule.
	t.Run("cross-definition same output", func(t *testing.T) {
		a, b := mk("a"), mk("b")
		b.Outputs = []string{"out-a"}
		err := actions.ValidateGraph([]actions.Definition{a, b})
		if err == nil || !strings.Contains(err.Error(), `definitions "a" and "b" declare overlapping outputs ("out-a" and "out-a")`) {
			t.Fatalf("expected cross-definition output-overlap error, got: %v", err)
		}
	})
	t.Run("cross-definition nested output", func(t *testing.T) {
		a, b := mk("a"), mk("b")
		b.Outputs = []string{"out-a/dist"}
		err := actions.ValidateGraph([]actions.Definition{a, b})
		if err == nil || !strings.Contains(err.Error(), "declare overlapping outputs") {
			t.Fatalf("expected containment overlap error, got: %v", err)
		}
	})
	t.Run("disjoint outputs accepted", func(t *testing.T) {
		a, b := mk("a"), mk("b")
		b.Outputs = []string{"out-a-extra"} // adjacent spelling, NOT under out-a
		if err := actions.ValidateGraph([]actions.Definition{a, b}); err != nil {
			t.Fatalf("disjoint output roots must validate: %v", err)
		}
	})
}

func TestShellDetection(t *testing.T) {
	cases := []struct {
		arg0 string
		want bool
	}{
		{"cmd.exe", true},
		{"CMD.EXE", true},
		{"cmd", true},
		{`C:\Windows\System32\cmd.exe`, true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, true},
		{"powershell.exe", true},
		{"powershell", true},
		{"pwsh", true},
		{"pwsh.exe", true},
		{"sh", true},
		{"sh.exe", true},
		{"bash", true},
		{"/usr/bin/bash", true},
		{"git", false},
		{"go", false},
		{"pnpm", false},
		{"cmdshell", false},
		{"mycmd", false},
		{"", false},
	}
	for _, tc := range cases {
		d := actions.Definition{Argv: []string{tc.arg0, "arg"}}
		if got := d.IsShell(); got != tc.want {
			t.Errorf("IsShell(%q) = %v, want %v", tc.arg0, got, tc.want)
		}
	}
	empty := actions.Definition{}
	if empty.IsShell() {
		t.Error("zero Definition must not be a shell action")
	}
	if empty.ShellWarning() != "" {
		t.Error("non-shell definition must carry no shell warning")
	}
	shellDef := actions.Definition{Argv: []string{"bash", "-c", "true"}}
	if shellDef.ShellWarning() != actions.ShellWarningMarker {
		t.Errorf("shell definition must carry the marker, got %q", shellDef.ShellWarning())
	}
}

func TestCanonicalEnvAllow(t *testing.T) {
	got := actions.CanonicalEnvAllow([]string{"C", "A", "B"})
	want := []string{"A", "B", "C"}
	if len(got) != len(want) || got[0] != "A" || got[1] != "B" || got[2] != "C" {
		t.Fatalf("CanonicalEnvAllow = %v, want %v", got, want)
	}
	// The input must not be mutated.
	in := []string{"B", "A"}
	_ = actions.CanonicalEnvAllow(in)
	if in[0] != "B" || in[1] != "A" {
		t.Fatalf("CanonicalEnvAllow mutated its input: %v", in)
	}
}
