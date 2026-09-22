package ecosystem

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/policy"
)

func TestRecipeTable(t *testing.T) {
	cases := []struct {
		name     string
		g        GroupSuggestion
		wantArgv []string
		wantEnv  []string
	}{
		{
			name: "pnpm",
			g: GroupSuggestion{
				GroupID: "pnpm",
				Adapter: AdapterPNPM,
				Outputs: []string{"node_modules"},
				Inputs:  []string{"package.json", "pnpm-lock.yaml", "patches/fix.patch", ".npmrc", "pnpm-workspace.yaml"},
			},
			wantArgv: []string{"pnpm", "install", "--frozen-lockfile"},
			wantEnv:  []string{"PNPM_HOME"},
		},
		{
			name: "npm",
			g: GroupSuggestion{
				GroupID: "npm",
				Adapter: AdapterNPM,
				Outputs: []string{"node_modules"},
				Inputs:  []string{"package.json", "package-lock.json", ".npmrc"},
			},
			wantArgv: []string{"npm", "ci"},
			wantEnv:  nil,
		},
		{
			name: "uv",
			g: GroupSuggestion{
				GroupID: "uv",
				Adapter: AdapterUV,
				Outputs: []string{".venv"},
				Inputs:  []string{"pyproject.toml", "uv.lock", ".python-version"},
			},
			wantArgv: []string{"uv", "sync", "--locked"},
			wantEnv:  []string{"UV_PYTHON"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, in := range tc.g.Inputs {
				writeFile(t, dir, in, "fixture")
			}

			def, err := Recipe(tc.g, dir)
			if err != nil {
				t.Fatalf("Recipe: unexpected error: %v", err)
			}
			if def.ID != tc.g.GroupID {
				t.Errorf("ID = %q, want %q", def.ID, tc.g.GroupID)
			}
			if !slices.Equal(def.Argv, tc.wantArgv) {
				t.Errorf("Argv = %v, want exactly %v", def.Argv, tc.wantArgv)
			}
			if def.WorkingRoot != "." {
				t.Errorf("WorkingRoot = %q, want %q", def.WorkingRoot, ".")
			}
			if !slices.Equal(def.Inputs, tc.g.Inputs) {
				t.Errorf("Inputs = %v, want %v", def.Inputs, tc.g.Inputs)
			}
			if !slices.Equal(def.Outputs, tc.g.Outputs) {
				t.Errorf("Outputs = %v, want %v", def.Outputs, tc.g.Outputs)
			}
			if !slices.Equal(def.EnvAllow, tc.wantEnv) {
				t.Errorf("EnvAllow = %v, want exactly %v", def.EnvAllow, tc.wantEnv)
			}
			if def.Network != actions.NetworkAllowed {
				t.Errorf("Network = %q, want allowed", def.Network)
			}
			if def.Timeout != 15*time.Minute {
				t.Errorf("Timeout = %s, want 15m", def.Timeout)
			}
			if len(def.DependsOn) != 0 {
				t.Errorf("DependsOn = %v, want none", def.DependsOn)
			}
			if err := def.Validate(); err != nil {
				t.Errorf("generated Definition fails Validate: %v", err)
			}
		})
	}
}

// TestRecipeFromDetection closes the loop: what Detect produced must
// survive Recipe and Validate unchanged.
func TestRecipeFromDetection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "pnpm-lock.yaml", "lock")
	writeFile(t, dir, "patches/fix.patch", "p")

	det := mustDetect(t, dir)
	if len(det.Suggestions) != 1 {
		t.Fatalf("suggestions = %d, want 1", len(det.Suggestions))
	}
	def, err := Recipe(det.Suggestions[0], dir)
	if err != nil {
		t.Fatalf("Recipe(detect output): %v", err)
	}
	if err := def.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if want := []string{"package.json", "pnpm-lock.yaml", "patches/fix.patch"}; !slices.Equal(def.Inputs, want) {
		t.Errorf("Inputs = %v, want %v", def.Inputs, want)
	}
}

func TestRecipePipRefused(t *testing.T) {
	g := GroupSuggestion{
		GroupID: "pip",
		Adapter: AdapterPip,
		Outputs: []string{".venv"},
		Inputs:  []string{"requirements.txt"},
	}
	_, err := Recipe(g, "")
	if err == nil {
		t.Fatal("Recipe(pip): want error, got nil")
	}
	if !errors.Is(err, ErrPipPreserveDefault) {
		t.Fatalf("error = %v, want ErrPipPreserveDefault", err)
	}
	if !strings.Contains(err.Error(), "preserve-default") {
		t.Errorf("error text must name the preserve-default rule: %v", err)
	}
}

func TestRecipeUnknownAdapter(t *testing.T) {
	g := GroupSuggestion{
		GroupID: "yarn",
		Adapter: "yarn",
		Outputs: []string{"node_modules"},
		Inputs:  []string{"package.json", "yarn.lock"},
	}
	_, err := Recipe(g, "")
	if err == nil || !strings.Contains(err.Error(), "unknown adapter") {
		t.Fatalf("error = %v, want unknown-adapter error", err)
	}
}

func TestRecipeMissingInputOnDisk(t *testing.T) {
	g := GroupSuggestion{
		GroupID: "npm",
		Adapter: AdapterNPM,
		Outputs: []string{"node_modules"},
		Inputs:  []string{"package.json", "package-lock.json"},
	}
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}") // lockfile deliberately absent
	_, err := Recipe(g, dir)
	if err == nil || !strings.Contains(err.Error(), "package-lock.json") {
		t.Fatalf("error = %v, want missing-input error naming package-lock.json", err)
	}
}

func TestRecipeEmptyWSRootSkipsInputCheck(t *testing.T) {
	g := GroupSuggestion{
		GroupID: "npm",
		Adapter: AdapterNPM,
		Outputs: []string{"node_modules"},
		Inputs:  []string{"package.json", "package-lock.json"},
	}
	if _, err := Recipe(g, ""); err != nil {
		t.Fatalf("Recipe with empty root: unexpected error: %v", err)
	}
}

// deletionVerbs is the denylist for the argv tripwire: no generated
// recipe may contain a deletion or cleanup subcommand anywhere in its
// argument vector (Foundation §9.5 — actions cannot acquire the
// source-removal capability).
var deletionVerbs = []string{
	"rm", "del", "rmdir", "unlink", "remove", "uninstall",
	"prune", "purge", "clean", "cleanall", "cache", "gc",
	"reset", "clear", "drop", "delete", "truncate", "vacuum",
}

func TestNoDeletionVerbs(t *testing.T) {
	suggestions := []GroupSuggestion{
		{GroupID: "pnpm", Adapter: AdapterPNPM, Outputs: []string{"node_modules"}, Inputs: []string{"package.json", "pnpm-lock.yaml"}},
		{GroupID: "npm", Adapter: AdapterNPM, Outputs: []string{"node_modules"}, Inputs: []string{"package.json", "package-lock.json"}},
		{GroupID: "uv", Adapter: AdapterUV, Outputs: []string{".venv"}, Inputs: []string{"pyproject.toml", "uv.lock"}},
	}
	for _, g := range suggestions {
		def, err := Recipe(g, "")
		if err != nil {
			t.Fatalf("Recipe(%s): %v", g.Adapter, err)
		}
		if def.Argv[0] != g.Adapter {
			t.Errorf("%s: argv[0] = %q, want the adapter tool %q", g.Adapter, def.Argv[0], g.Adapter)
		}
		for _, tok := range def.Argv {
			for _, verb := range deletionVerbs {
				if strings.EqualFold(tok, verb) {
					t.Errorf("%s: argv contains deletion verb %q: %v", g.Adapter, tok, def.Argv)
				}
			}
		}
	}
}

func TestMarries(t *testing.T) {
	npmSug := GroupSuggestion{Adapter: AdapterNPM, Outputs: []string{"node_modules"}}
	cases := []struct {
		name string
		g    GroupSuggestion
		pol  policy.Policy
		want bool
	}{
		{
			name: "empty policy",
			g:    npmSug,
			pol:  policy.Policy{},
			want: false,
		},
		{
			name: "same adapter same output",
			g:    npmSug,
			pol: policy.Policy{Regenerate: []policy.Regenerate{{
				ID: "node", Adapter: policy.AdapterNPM, Outputs: []string{"node_modules"},
			}}},
			want: true,
		},
		{
			name: "same adapter overlapping subtree",
			g:    npmSug,
			pol: policy.Policy{Regenerate: []policy.Regenerate{{
				ID: "node", Adapter: policy.AdapterNPM, Outputs: []string{"node_modules/pkg"},
			}}},
			want: true,
		},
		{
			name: "different adapter same output",
			g:    npmSug,
			pol: policy.Policy{Regenerate: []policy.Regenerate{{
				ID: "x", Adapter: policy.AdapterPNPM, Outputs: []string{"node_modules"},
			}}},
			want: false,
		},
		{
			name: "same adapter disjoint output",
			g:    npmSug,
			pol: policy.Policy{Regenerate: []policy.Regenerate{{
				ID: "x", Adapter: policy.AdapterNPM, Outputs: []string{"other_modules"},
			}}},
			want: false,
		},
		{
			name: "uv group matches uv policy",
			g:    GroupSuggestion{Adapter: AdapterUV, Outputs: []string{".venv"}},
			pol: policy.Policy{Regenerate: []policy.Regenerate{{
				ID: "py", Adapter: policy.AdapterUV, Outputs: []string{".venv"},
			}}},
			want: true,
		},
		{
			name: "pip without outputs cannot confirm coverage",
			g:    GroupSuggestion{Adapter: AdapterPip, Outputs: nil},
			pol: policy.Policy{Regenerate: []policy.Regenerate{{
				ID: "py", Adapter: policy.AdapterPip, Outputs: []string{".venv"},
			}}},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Marries(tc.g, tc.pol); got != tc.want {
				t.Errorf("Marries = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMarriesAgreesWithHandWrittenPolicy parses a realistic hand-written
// Ebbfile and confirms detection output marries it instead of fighting
// it (the §9.3 agreement contract).
func TestMarriesAgreesWithHandWrittenPolicy(t *testing.T) {
	const ebbfile = `
version = 1
[workspace]
name = "demo"
[policy]
network = "approved-actions"
unknown = "preserve"
[[regenerate]]
id = "node-deps"
adapter = "npm"
root = "."
outputs = ["node_modules"]
inputs = ["package.json", "package-lock.json"]
network = "allowed"
`
	pol, err := policy.Parse([]byte(ebbfile))
	if err != nil {
		t.Fatalf("policy.Parse: %v", err)
	}

	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "package-lock.json", "{}")
	det := mustDetect(t, dir)
	if len(det.Suggestions) != 1 {
		t.Fatalf("suggestions = %d, want 1", len(det.Suggestions))
	}
	if !Marries(det.Suggestions[0], pol) {
		t.Errorf("detected npm group must marry the hand-written [[regenerate]] group")
	}
}
