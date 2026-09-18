package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validBody is the minimal valid document used as the base for invalid
// variants.
const validBody = `
version = 1

[workspace]
name = "renderer"

[policy]
network = "approved-actions"
unknown = "preserve"
`

// TestParseValidFullFile parses the Foundation §7.1 extended example.
func TestParseValidFullFile(t *testing.T) {
	p, err := ParseFile(filepath.Join("testdata", "full.toml"))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if p.Version != 1 || p.Workspace.Name != "renderer" {
		t.Fatalf("version/workspace not decoded: %+v", p)
	}
	if p.Rules.Network != NetworkApprovedActions || p.Rules.Unknown != UnknownPreserve {
		t.Fatalf("rules not decoded: %+v", p.Rules)
	}
	if len(p.Preserve) != 1 || len(p.Preserve[0].Patterns) != 2 || p.Preserve[0].Reason != "Original material" {
		t.Fatalf("preserve not decoded: %+v", p.Preserve)
	}
	if len(p.Sensitive) != 1 || len(p.Sensitive[0].Paths) != 1 || len(p.Sensitive[0].Patterns) != 2 {
		t.Fatalf("sensitive not decoded: %+v", p.Sensitive)
	}
	if len(p.Regenerate) != 2 {
		t.Fatalf("regenerate not decoded: %+v", p.Regenerate)
	}
	if p.Regenerate[1].Adapter != AdapterCustom || len(p.Regenerate[1].Command) != 2 {
		t.Fatalf("custom group not decoded: %+v", p.Regenerate[1])
	}
	if len(p.External) != 2 || p.External[0].Ownership != "shared" || !p.External[0].Required {
		t.Fatalf("external not decoded: %+v", p.External)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate on parsed file: %v", err)
	}
}

// TestParseDefaultRootApplied verifies the regenerate root "." default.
func TestParseDefaultRootApplied(t *testing.T) {
	p, err := Parse([]byte(validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
outputs = ["node_modules"]
inputs = ["package.json"]
network = "allowed"
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Regenerate[0].Root != "." {
		t.Fatalf("root default not applied: %q", p.Regenerate[0].Root)
	}
}

// TestParseInvalidVariants covers every v1 rejection with an error that
// names the offending field.
func TestParseInvalidVariants(t *testing.T) {
	tests := []struct {
		name string
		toml string
		want string // substring the error must contain
	}{
		{"version missing", `
[workspace]
name = "x"
[policy]
network = "approved-actions"
unknown = "preserve"
`, "version"},
		{"version 2", validBody + "xx", "toml"}, // trailing junk is a parse error
		{"version wrong value", `
version = 2

[workspace]
name = "x"

[policy]
network = "approved-actions"
unknown = "preserve"
`, "version"},
		{"workspace name missing", `
version = 1

[workspace]

[policy]
network = "approved-actions"
unknown = "preserve"
`, "name"},
		{"network wrong value", `
version = 1
[workspace]
name = "x"
[policy]
network = "open"
unknown = "preserve"
`, "network"},
		{"unknown not preserve (invariant)", `
version = 1
[workspace]
name = "x"
[policy]
network = "approved-actions"
unknown = "discard"
`, "unknown"},
		{"unknown top-level field", `
versio = 1

[workspace]
name = "x"

[policy]
network = "approved-actions"
unknown = "preserve"
`, "versio"},
		{"misspelled policy key", `
version = 1
[workspace]
name = "x"
[policy]
networkk = "approved-actions"
unknown = "preserve"
`, "networkk"},
		{"preserve no patterns", validBody + `
[[preserve]]
reason = "why"
`, "patterns"},
		{"preserve empty patterns array", validBody + `
[[preserve]]
patterns = []
reason = "why"
`, "patterns"},
		{"preserve missing reason", validBody + `
[[preserve]]
patterns = ["a/**"]
`, "reason"},
		{"preserve misspelled patterns", validBody + `
[[preserve]]
paterns = ["a/**"]
reason = "why"
`, "paterns"},
		{"preserve bad glob mid-segment **", validBody + `
[[preserve]]
patterns = ["a**b"]
reason = "why"
`, "patterns[0]"},
		{"preserve glob bracket syntax", validBody + `
[[preserve]]
patterns = ["[ab]/**"]
reason = "why"
`, "patterns[0]"},
		{"preserve glob absolute", validBody + `
[[preserve]]
patterns = ["/abs/**"]
reason = "why"
`, "patterns[0]"},
		{"sensitive neither paths nor patterns", validBody + `
[[sensitive]]
`, "sensitive[0]"},
		{"sensitive literal absolute", validBody + `
[[sensitive]]
paths = ["/etc/passwd"]
`, "paths[0]"},
		{"sensitive literal dotdot", validBody + `
[[sensitive]]
paths = ["a/../b"]
`, "paths[0]"},
		{"sensitive literal backslash", validBody + `
[[sensitive]]
paths = ["a\\b"]
`, "paths[0]"},
		{"sensitive literal drive prefix", validBody + `
[[sensitive]]
paths = ["C:secrets"]
`, "paths[0]"},
		{"sensitive literal NUL", validBody + `
[[sensitive]]
paths = ["a\u0000b"]
`, "paths[0]"},
		{"regenerate id missing", validBody + `
[[regenerate]]
adapter = "pnpm"
outputs = ["node_modules"]
inputs = ["package.json"]
network = "allowed"
`, "id"},
		{"regenerate duplicate id", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
outputs = ["node_modules"]
inputs = ["a"]
network = "allowed"
[[regenerate]]
id = "g"
adapter = "npm"
outputs = ["other"]
inputs = ["a"]
network = "allowed"
`, "duplicate id"},
		{"regenerate bad adapter", validBody + `
[[regenerate]]
id = "g"
adapter = "yarn"
outputs = ["node_modules"]
inputs = ["a"]
network = "allowed"
`, "adapter"},
		{"regenerate root absolute", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
root = "/abs"
outputs = ["node_modules"]
inputs = ["a"]
network = "allowed"
`, "root"},
		{"regenerate root dotdot", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
root = "a/.."
outputs = ["node_modules"]
inputs = ["a"]
network = "allowed"
`, "root"},
		{"regenerate no outputs", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
outputs = []
inputs = ["a"]
network = "allowed"
`, "outputs"},
		{"regenerate duplicate output", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
outputs = ["node_modules", "node_modules"]
inputs = ["a"]
network = "allowed"
`, "duplicate output"},
		{"regenerate no inputs", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
outputs = ["node_modules"]
inputs = []
network = "allowed"
`, "inputs"},
		{"regenerate bad network", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
outputs = ["node_modules"]
inputs = ["a"]
network = "sometimes"
`, "network"},
		{"regenerate command on non-custom", validBody + `
[[regenerate]]
id = "g"
adapter = "pnpm"
outputs = ["node_modules"]
inputs = ["a"]
network = "allowed"
command = ["pnpm", "install"]
`, "command"},
		{"custom without command", validBody + `
[[regenerate]]
id = "g"
adapter = "custom"
outputs = ["gen"]
inputs = ["a"]
network = "allowed"
`, "command"},
		{"external id missing", validBody + `
[[external]]
kind = "directory"
location = "binding"
ownership = "shared"
required = true
`, "id"},
		{"external duplicate id", validBody + `
[[external]]
id = "e"
kind = "directory"
location = "b1"
ownership = "shared"
required = true
[[external]]
id = "e"
kind = "file"
location = "b2"
ownership = "owned"
required = false
`, "duplicate id"},
		{"external bad kind", validBody + `
[[external]]
id = "e"
kind = "database"
location = "binding"
ownership = "shared"
required = true
`, "kind"},
		{"external bad ownership", validBody + `
[[external]]
id = "e"
kind = "directory"
location = "binding"
ownership = "public"
required = true
`, "ownership"},
		{"external location missing", validBody + `
[[external]]
id = "e"
kind = "directory"
ownership = "shared"
required = true
`, "location"},
		{"external location is a path", validBody + `
[[external]]
id = "e"
kind = "directory"
location = "C:\\Users\\me\\secrets"
ownership = "shared"
required = true
`, "location"},
		{"external location has slash", validBody + `
[[external]]
id = "e"
kind = "directory"
location = "a/b"
ownership = "shared"
required = true
`, "location"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.toml))
			if err == nil {
				t.Fatalf("Parse accepted invalid document:\n%s", tt.toml)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not name %q", err.Error(), tt.want)
			}
		})
	}
}

// TestVersionExactly2Rejected guards against accepting a future schema
// silently (F46 direction).
func TestVersionExactly2Rejected(t *testing.T) {
	_, err := Parse([]byte("version = 2\n\n[workspace]\nname = \"x\"\n"))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("want version error, got %v", err)
	}
}

// TestDuplicateKeyRejected verifies the TOML parser rejects duplicate
// keys by itself (D002).
func TestDuplicateKeyRejected(t *testing.T) {
	tests := []string{
		"version = 1\nversion = 2\n",
		validBody + "\nname = \"other\"\n",
		validBody + "[[preserve]]\npatterns = [\"a\"]\nreason = \"r\"\nreason = \"r2\"\n",
	}
	for i, doc := range tests {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("case %d: duplicate key accepted", i)
		}
	}
}

// TestDefaultPolicyValidate checks the no-Ebbfile conservative default.
func TestDefaultPolicyValidate(t *testing.T) {
	p := Default("")
	if err := p.Validate(); err != nil {
		t.Fatalf("Default policy invalid: %v", err)
	}
	if p.Workspace.Name != "workspace" {
		t.Fatalf("fallback workspace name: %q", p.Workspace.Name)
	}
	if len(p.Regenerate) != 0 || len(p.Preserve) != 0 {
		t.Fatalf("default policy must not declare groups")
	}
}

// TestParseFileMissing verifies the os error is wrapped, not hidden.
func TestParseFileMissing(t *testing.T) {
	_, err := ParseFile(filepath.Join("testdata", "does-not-exist.toml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want not-exist error, got %v", err)
	}
}
