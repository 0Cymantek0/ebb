package ecosystem

// recipe_workingroot_test.go pins wave-5 E04: a built-in ecosystem
// recipe carries the group's DECLARED logical root as its working root
// (exactly like a custom command), never a hardcoded ".".

import (
	"strings"
	"testing"
)

// TestRecipeCarriesDeclaredWorkingRoot: the suggestion's declared root
// becomes the definition's working root; the workspace-root shape (""
// or unset) keeps ".".
func TestRecipeCarriesDeclaredWorkingRoot(t *testing.T) {
	dir := t.TempDir()
	for _, in := range []string{"package.json", "wavebox/pyproject.toml", "wavebox/uv.lock"} {
		writeFile(t, dir, in, "fixture")
	}

	def, err := Recipe(GroupSuggestion{
		GroupID:     "pydeps",
		Adapter:     AdapterUV,
		Outputs:     []string{"wavebox/.venv"},
		Inputs:      []string{"wavebox/pyproject.toml", "wavebox/uv.lock"},
		WorkingRoot: "wavebox",
	}, dir)
	if err != nil {
		t.Fatalf("Recipe: %v", err)
	}
	if def.WorkingRoot != "wavebox" {
		t.Fatalf("WorkingRoot = %q, want the declared %q (E04: built-in recipes carry the group's root)", def.WorkingRoot, "wavebox")
	}
	if !strings.Contains(strings.Join(def.Argv, " "), "--locked") {
		t.Fatalf("argv = %v, want the pinned uv recipe (--locked)", def.Argv)
	}
	if err := def.Validate(); err != nil {
		t.Fatalf("definition invalid: %v", err)
	}

	// Workspace-root suggestion (""): the historical default keeps ".".
	rooted, err := Recipe(GroupSuggestion{
		GroupID: "pnpm",
		Adapter: AdapterPNPM,
		Outputs: []string{"node_modules"},
		Inputs:  []string{"package.json"},
	}, dir)
	if err != nil {
		t.Fatalf("Recipe (root): %v", err)
	}
	if rooted.WorkingRoot != "." {
		t.Fatalf("WorkingRoot = %q, want \".\" for a workspace-root suggestion", rooted.WorkingRoot)
	}
}
