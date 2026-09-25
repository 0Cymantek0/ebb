package cli

// wave5_custody_test.go pins the wave-5 CLI-side custody contract:
//
//   - T1b: deriveGroupDef builds the exact frozen contract per group —
//     ecosystem recipes carry the DECLARED root as WorkingRoot (E04),
//     the pinned recipe argv, the DECLARED network (E07) and the env
//     allowlist.
//   - T1b-bis: recordTrimApprovals persists the trim-time approval into
//     the session's approvalstore, and a restore-time resolution against
//     the SAME definition matches exactly (the D033 silent replay).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/policy"
)

func waveboxRegenPolicy() policy.Policy {
	pol, err := policy.Parse([]byte(`
version = 1

[workspace]
name = "wavebox"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "pydeps"
adapter = "uv"
root = "wavebox"
outputs = ["wavebox/.venv"]
inputs = ["wavebox/pyproject.toml", "wavebox/uv.lock"]
network = "offline-artifacts"

[[regenerate]]
id = "build"
adapter = "custom"
root = "tools"
outputs = ["tools/dist"]
inputs = ["tools/build.sh"]
network = "allowed"
command = ["go", "version"]
`))
	if err != nil {
		panic(err)
	}
	return pol
}

// TestDeriveGroupDefCarriesDeclaredRoot: the frozen contract per group.
func TestDeriveGroupDefCarriesDeclaredRoot(t *testing.T) {
	pol := waveboxRegenPolicy()
	py, ok, err := deriveGroupDef(pol.Regenerate[0])
	if err != nil || !ok {
		t.Fatalf("deriveGroupDef(pydeps) = %v, %v; want a definition", py, err)
	}
	if py.WorkingRoot != "wavebox" {
		t.Errorf("uv recipe WorkingRoot = %q, want the declared %q (E04)", py.WorkingRoot, "wavebox")
	}
	if strings.Join(py.Argv, " ") != "uv sync --locked" {
		t.Errorf("uv argv = %v, want the pinned recipe verbatim", py.Argv)
	}
	if py.Network != actions.NetworkOfflineArtifacts {
		t.Errorf("uv network = %q, want the DECLARED %q (E07: no hardcoded allowed)", py.Network, actions.NetworkOfflineArtifacts)
	}
	if strings.Join(py.EnvAllow, ",") != "UV_PYTHON" {
		t.Errorf("uv env allow = %v, want [UV_PYTHON]", py.EnvAllow)
	}
	if py.Timeout != 15*time.Minute {
		t.Errorf("uv timeout = %s, want 15m", py.Timeout)
	}

	custom, ok, err := deriveGroupDef(pol.Regenerate[1])
	if err != nil || !ok {
		t.Fatalf("deriveGroupDef(build) = %v, %v; want a definition", custom, err)
	}
	if custom.WorkingRoot != "tools" {
		t.Errorf("custom WorkingRoot = %q, want the declared %q", custom.WorkingRoot, "tools")
	}
	if custom.Network != actions.NetworkAllowed {
		t.Errorf("custom network = %q, want allowed", custom.Network)
	}
}

// TestTrimApprovalMatchesRestoreResolution: the approval recorded
// trim-side (D3) matches a restore-time resolution of the SAME frozen
// definition exactly, and refuses a different tool — the D4 contract on
// real store machinery.
func TestTrimApprovalMatchesRestoreResolution(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "wavebox", "pyproject.toml"), []byte("[project]\n"))
	writeFile(t, filepath.Join(dir, "wavebox", "uv.lock"), []byte("version = 1\n"))

	pol := waveboxRegenPolicy()
	def, ok, err := deriveGroupDef(pol.Regenerate[0])
	if err != nil || !ok {
		t.Fatalf("deriveGroupDef: %v, %v", ok, err)
	}
	tool, err := actions.ResolveTool(def.Argv[0])
	if err != nil {
		t.Skipf("fixture tool %q not resolvable on this host: %v", def.Argv[0], err)
	}
	digests := map[string]string{}
	for _, rel := range def.Inputs {
		d, derr := actions.DigestFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if derr != nil {
			t.Fatal(derr)
		}
		digests[rel] = d
	}

	store := approvalstore.New(filepath.Join(dir, "approvals.json"))
	if _, aerr := store.Approve(def, tool, digests, "trim:interactive-confirm"); aerr != nil {
		t.Fatalf("Approve: %v", aerr)
	}

	// Restore-side: the same resolution matches silently.
	if _, merr := store.Matches(def, tool, digests); merr != nil {
		t.Fatalf("trim approval must match the same restore-time resolution: %v", merr)
	}
	// A drifted tool (different hash) is stale, never honored.
	drifted := actions.ToolIdentity{Name: tool.Name, ResolvedPath: tool.ResolvedPath, SHA256: strings.Repeat("ab", 32)}
	var stale *actions.ErrApprovalStale
	if _, merr := store.Matches(def, drifted, digests); !errors.As(merr, &stale) {
		t.Fatalf("a drifted tool must be stale, got %v", merr)
	}
	// A missing approval is required, never fabricated.
	empty := approvalstore.New(filepath.Join(dir, "empty.json"))
	var req *actions.ErrApprovalRequired
	if _, merr := empty.Matches(def, tool, digests); !errors.As(merr, &req) {
		t.Fatalf("a missing approval must be ErrApprovalRequired, got %v", merr)
	}
}

// writeFile is the cli-package test helper (same shape as the other
// packages' helpers).
func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}
