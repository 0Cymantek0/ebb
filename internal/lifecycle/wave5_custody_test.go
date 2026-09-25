package lifecycle

// wave5_custody_test.go pins the wave-5 "freeze and replay one exact
// action contract" workstream:
//
//   - TestTrimFreezesExactActionDefinition (E04/E05/E07): a trim freezes
//     the group's exact actions.Definition into its removal-plan
//     manifest — the ecosystem argv, the group's declared logical root
//     as working_root, the DECLARED network and the env allowlist.
//   - TestTrimWorkingRootJunctionEscapeRefused (D7): a requested group
//     whose root resolves (junction/symlink-aware) outside the workspace
//     refuses the trim before any effect.

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/policy"
)

// waveboxPolicyTOML declares a uv group rooted at the nested "wavebox"
// directory, offline-artifacts network.
const waveboxPolicyTOML = `
version = 1

[workspace]
name = "wavebox-fixture"

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
`

// writeWaveboxFixture builds a workspace with a nested wavebox project.
func writeWaveboxFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"wavebox/pyproject.toml":   "[project]\nname = \"wb\"\n",
		"wavebox/uv.lock":          "version = 1\n",
		"wavebox/.venv/pyvenv.cfg": "home = python\n",
		"wavebox/.venv/lib/uv.py":  "# venv content\n",
		"wavebox/src/main.py":      "print('hi')\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// waveboxActionDef is the exact definition the fixed CLI derivation
// (deriveGroupDef -> ecosystem.Recipe) produces for the wavebox group.
func waveboxActionDef() actions.Definition {
	return actions.Definition{
		ID:          "pydeps",
		Argv:        []string{"uv", "sync", "--locked"},
		WorkingRoot: "wavebox",
		Inputs:      []string{"wavebox/pyproject.toml", "wavebox/uv.lock"},
		Outputs:     []string{"wavebox/.venv"},
		EnvAllow:    []string{"UV_PYTHON"},
		Network:     actions.NetworkOfflineArtifacts,
		Timeout:     15 * time.Minute,
	}
}

// TestTrimFreezesExactActionDefinition: the removal-plan manifest of a
// trim carries the frozen actionDefDoc (working_root "wavebox", the
// ecosystem `uv sync --locked` argv, the DECLARED offline-artifacts
// network, the env allowlist) — the single source the restore driver
// must replay verbatim.
func TestTrimFreezesExactActionDefinition(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("wavebox-ws")
	writeWaveboxFixture(t, root)

	pol, err := policy.Parse([]byte(waveboxPolicyTOML))
	if err != nil {
		t.Fatal(err)
	}
	opts := CaptureOptions{
		WorkspaceName: "wavebox-fixture", WorkspaceID: ws,
		Policy: pol, DoTrim: []string{"pydeps"},
		ActionDefs:    []actions.Definition{waveboxActionDef()},
		ApprovalReady: func(groupID string) error { return nil },
	}
	res, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	if err != nil {
		t.Fatalf("trim: %v", err)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "pydeps" {
		t.Fatalf("groups = %v, want [pydeps]", res.Groups)
	}

	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	if len(snaps) != 1 || snaps[0].Kind != catalog.SnapshotKindTrim {
		t.Fatalf("trim snapshot row wrong: %+v", snaps)
	}
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	raw, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile,
		snaps[0].PayloadBackendID, prefix+"/"+removalManifestName)
	if err != nil {
		t.Fatalf("dump removal manifest: %v", err)
	}
	// Parse generically: the frozen `definition` extension object must
	// exist on the group record.
	var plan struct {
		Groups []map[string]json.RawMessage `json:"groups"`
	}
	if err := json.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("removal manifest parse: %v", err)
	}
	if len(plan.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(plan.Groups))
	}
	defRaw, ok := plan.Groups[0]["definition"]
	if !ok {
		t.Fatalf("removal manifest carries NO frozen definition for group pydeps; got:\n%s", raw)
	}
	var def struct {
		ID          string   `json:"id"`
		Argv        []string `json:"argv"`
		WorkingRoot string   `json:"working_root"`
		Inputs      []string `json:"inputs"`
		Outputs     []string `json:"outputs"`
		EnvAllow    []string `json:"env_allow"`
		Network     string   `json:"network"`
		TimeoutNS   int64    `json:"timeout_ns"`
	}
	if err := json.Unmarshal(defRaw, &def); err != nil {
		t.Fatalf("definition parse: %v", err)
	}
	want := waveboxActionDef()
	if def.ID != want.ID {
		t.Errorf("definition id = %q, want %q", def.ID, want.ID)
	}
	if strings.Join(def.Argv, " ") != strings.Join(want.Argv, " ") {
		t.Errorf("definition argv = %v, want %v (the ecosystem recipe verbatim)", def.Argv, want.Argv)
	}
	if def.WorkingRoot != "wavebox" {
		t.Errorf("definition working_root = %q, want %q (the group's declared logical root)", def.WorkingRoot, "wavebox")
	}
	if strings.Join(def.EnvAllow, ",") != "UV_PYTHON" {
		t.Errorf("definition env_allow = %v, want [UV_PYTHON]", def.EnvAllow)
	}
	if def.Network != string(actions.NetworkOfflineArtifacts) {
		t.Errorf("definition network = %q, want the DECLARED %q (never a hardcoded allowed)", def.Network, want.Network)
	}
	if def.TimeoutNS != int64(want.Timeout) {
		t.Errorf("definition timeout_ns = %d, want %d", def.TimeoutNS, want.Timeout)
	}
}

// TestTrimWorkingRootJunctionEscapeRefused: a requested group whose root
// is a junction/symlink resolving OUTSIDE the workspace refuses the trim
// before any effect (D7). The refusal names the resolved outside path.
func TestTrimWorkingRootJunctionEscapeRefused(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("escape-ws")

	// The escape target lives inside the harness base but OUTSIDE the
	// workspace root.
	outside := filepath.Join(h.base, "outside-target")
	if err := os.MkdirAll(filepath.Join(outside, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "out", "gen.js"), []byte("// gen\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// sub -> outside (symlink where permitted, unprivileged junction on
	// Windows — the same creator discipline the carve-out tests use).
	linkPath := filepath.Join(root, "sub")
	if serr := os.Symlink(outside, linkPath); serr != nil {
		out, jerr := exec.Command("cmd", "/c", "mklink", "/J", linkPath, outside).CombinedOutput()
		if jerr != nil {
			t.Skipf("cannot create the escape link fixture (symlink %v; junction %v: %s)", serr, jerr, out)
		}
	}

	pol, err := policy.Parse([]byte(`
version = 1

[workspace]
name = "escape-ws"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "esc"
adapter = "custom"
root = "sub"
outputs = ["sub"]
inputs = ["package.json"]
network = "allowed"
command = ["go", "version"]
`))
	if err != nil {
		t.Fatal(err)
	}
	opts := CaptureOptions{
		WorkspaceName: "escape-ws", WorkspaceID: ws,
		Policy: pol, DoTrim: []string{"esc"},
		ApprovalReady: func(groupID string) error { return nil },
	}
	_, err = h.coord().Trim(context.Background(), h.vault, root, opts)
	if err == nil {
		t.Fatalf("trim with a group root resolving outside the workspace must be refused (D7)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "sub") || !strings.Contains(msg, "outside") {
		t.Fatalf("refusal must name the root and the escape: %v", err)
	}
	// Nothing was removed from the escape target.
	if _, serr := os.Stat(filepath.Join(outside, "out", "gen.js")); serr != nil {
		t.Fatalf("outside target must be untouched: %v", serr)
	}
	// The refused trim's operation must be canceled (never left active).
	c := h.coord()
	ops, lerr := c.cat.ListOperations(ws)
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, op := range ops {
		if op.Kind == catalog.OpKindTrim && op.Phase != catalog.PhaseCanceled {
			t.Errorf("a refused trim must leave the operation canceled, got %q", op.Phase)
		}
	}
}
