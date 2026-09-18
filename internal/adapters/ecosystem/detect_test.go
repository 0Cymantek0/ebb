package ecosystem

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// writeFile creates a fixture file (and any parent directories) under
// dir with '/'-separated rel.
func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("fixture: mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("fixture: write %s: %v", rel, err)
	}
}

func mustDetect(t *testing.T, dir string) Detection {
	t.Helper()
	det, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect(%s): unexpected error: %v", dir, err)
	}
	return det
}

func adapters(det Detection) []string {
	out := make([]string, len(det.Suggestions))
	for i, g := range det.Suggestions {
		out[i] = g.Adapter
	}
	return out
}

func hasNote(det Detection, substr string) bool {
	for _, n := range det.Notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

func TestDetectPnpmFull(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "pnpm-lock.yaml", "lock")
	writeFile(t, dir, ".npmrc", "registry=https://example.invalid")
	writeFile(t, dir, "pnpm-workspace.yaml", "packages:\n  - apps/*\n")
	writeFile(t, dir, "patches/fix.patch", "diff --git")
	writeFile(t, dir, "patches/nested/other.patch", "diff --git")
	writeFile(t, dir, "node_modules/left-pad/index.js", "12345")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterPNPM}) {
		t.Fatalf("adapters = %v, want [pnpm]", got)
	}
	g := det.Suggestions[0]
	wantInputs := []string{
		"package.json",
		"pnpm-lock.yaml",
		"patches/fix.patch",
		"patches/nested/other.patch",
		".npmrc",
		"pnpm-workspace.yaml",
	}
	if !slices.Equal(g.Inputs, wantInputs) {
		t.Errorf("Inputs = %v, want %v", g.Inputs, wantInputs)
	}
	if want := []string{"node_modules"}; !slices.Equal(g.Outputs, want) {
		t.Errorf("Outputs = %v, want %v", g.Outputs, want)
	}
	if g.GroupID != "pnpm" {
		t.Errorf("GroupID = %q, want %q", g.GroupID, "pnpm")
	}
	if !g.Present {
		t.Errorf("Present = false, want true (node_modules exists)")
	}
	if g.ApproxBytes != 5 {
		t.Errorf("ApproxBytes = %d, want 5 (logical size of the one fixture file)", g.ApproxBytes)
	}
	if g.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want high", g.Confidence)
	}
	if g.HumanReason == "" {
		t.Errorf("HumanReason must not be empty")
	}
	if len(det.Notes) != 0 {
		t.Errorf("Notes = %v, want none", det.Notes)
	}
}

func TestDetectPnpmMinimal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "pnpm-lock.yaml", "lock")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterPNPM}) {
		t.Fatalf("adapters = %v, want [pnpm]", got)
	}
	g := det.Suggestions[0]
	if want := []string{"package.json", "pnpm-lock.yaml"}; !slices.Equal(g.Inputs, want) {
		t.Errorf("Inputs = %v, want %v (no optional markers present)", g.Inputs, want)
	}
	if g.Present {
		t.Errorf("Present = true, want false (no node_modules)")
	}
	if g.ApproxBytes != 0 {
		t.Errorf("ApproxBytes = %d, want 0", g.ApproxBytes)
	}
}

func TestDetectPnpmEmptyPatchesDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "pnpm-lock.yaml", "lock")
	if err := os.Mkdir(filepath.Join(dir, "patches"), 0o755); err != nil {
		t.Fatal(err)
	}

	det := mustDetect(t, dir)
	g := det.Suggestions[0]
	if want := []string{"package.json", "pnpm-lock.yaml"}; !slices.Equal(g.Inputs, want) {
		t.Errorf("Inputs = %v, want %v (empty patches/ contributes nothing)", g.Inputs, want)
	}
}

func TestDetectNpmFull(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "package-lock.json", "{}")
	writeFile(t, dir, ".npmrc", "save-exact=true")
	writeFile(t, dir, "node_modules/left-pad/index.js", "1234567890")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterNPM}) {
		t.Fatalf("adapters = %v, want [npm]", got)
	}
	g := det.Suggestions[0]
	if want := []string{"package.json", "package-lock.json", ".npmrc"}; !slices.Equal(g.Inputs, want) {
		t.Errorf("Inputs = %v, want %v", g.Inputs, want)
	}
	if want := []string{"node_modules"}; !slices.Equal(g.Outputs, want) {
		t.Errorf("Outputs = %v, want %v", g.Outputs, want)
	}
	if g.GroupID != "npm" {
		t.Errorf("GroupID = %q, want %q", g.GroupID, "npm")
	}
	if !g.Present {
		t.Errorf("Present = false, want true")
	}
	if g.ApproxBytes != 10 {
		t.Errorf("ApproxBytes = %d, want 10", g.ApproxBytes)
	}
	if g.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want high", g.Confidence)
	}
}

func TestDetectNpmMinimal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "package-lock.json", "{}")

	det := mustDetect(t, dir)
	g := det.Suggestions[0]
	if want := []string{"package.json", "package-lock.json"}; !slices.Equal(g.Inputs, want) {
		t.Errorf("Inputs = %v, want %v (no .npmrc present)", g.Inputs, want)
	}
	if g.Present {
		t.Errorf("Present = true, want false")
	}
}

func TestDetectBothLockfilesPreferPnpm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "package-lock.json", "{}")
	writeFile(t, dir, "pnpm-lock.yaml", "lock")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterPNPM}) {
		t.Fatalf("adapters = %v, want [pnpm] only (pnpm wins over npm)", got)
	}
	if !slices.Equal(det.Suggestions[0].Inputs, []string{"package.json", "pnpm-lock.yaml"}) {
		t.Errorf("package-lock.json must not be an input of the pnpm group: %v", det.Suggestions[0].Inputs)
	}
	if !hasNote(det, "package-lock.json") {
		t.Errorf("Notes = %v, want one explaining the ignored package-lock.json", det.Notes)
	}
}

func TestDetectUvFull(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml", "[project]\nname = 'x'\n")
	writeFile(t, dir, "uv.lock", "")
	writeFile(t, dir, ".python-version", "3.12")
	writeFile(t, dir, ".venv/lib/python/x.py", "12345678")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterUV}) {
		t.Fatalf("adapters = %v, want [uv]", got)
	}
	g := det.Suggestions[0]
	if want := []string{"pyproject.toml", "uv.lock", ".python-version"}; !slices.Equal(g.Inputs, want) {
		t.Errorf("Inputs = %v, want %v", g.Inputs, want)
	}
	if want := []string{".venv"}; !slices.Equal(g.Outputs, want) {
		t.Errorf("Outputs = %v, want %v", g.Outputs, want)
	}
	if g.GroupID != "uv" {
		t.Errorf("GroupID = %q, want %q", g.GroupID, "uv")
	}
	if !g.Present {
		t.Errorf("Present = false, want true")
	}
	if g.ApproxBytes != 8 {
		t.Errorf("ApproxBytes = %d, want 8", g.ApproxBytes)
	}
	if g.Confidence != ConfidenceHigh {
		t.Errorf("Confidence = %q, want high", g.Confidence)
	}
}

func TestDetectUvMinimal(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml", "")
	writeFile(t, dir, "uv.lock", "")

	det := mustDetect(t, dir)
	g := det.Suggestions[0]
	if want := []string{"pyproject.toml", "uv.lock"}; !slices.Equal(g.Inputs, want) {
		t.Errorf("Inputs = %v, want %v", g.Inputs, want)
	}
}

func TestDetectPipFull(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask\n")
	writeFile(t, dir, ".venv/lib/site/x.py", "1234")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterPip}) {
		t.Fatalf("adapters = %v, want [pip]", got)
	}
	g := det.Suggestions[0]
	if want := []string{"requirements.txt"}; !slices.Equal(g.Inputs, want) {
		t.Errorf("Inputs = %v, want %v", g.Inputs, want)
	}
	if want := []string{".venv"}; !slices.Equal(g.Outputs, want) {
		t.Errorf("Outputs = %v, want %v (conventional venv dir found)", g.Outputs, want)
	}
	if !g.Present {
		t.Errorf("Present = false, want true")
	}
	if g.ApproxBytes != 4 {
		t.Errorf("ApproxBytes = %d, want 4", g.ApproxBytes)
	}
	if g.Confidence != ConfidenceLow {
		t.Errorf("Confidence = %q, want low (pip is preserve-default)", g.Confidence)
	}
	if !strings.Contains(g.HumanReason, "unpinned") {
		t.Errorf("HumanReason must note the unpinned-requirements risk: %q", g.HumanReason)
	}
}

func TestDetectPipAltVenvName(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask\n")
	writeFile(t, dir, "venv/lib/x.py", "12")

	det := mustDetect(t, dir)
	g := det.Suggestions[0]
	if want := []string{"venv"}; !slices.Equal(g.Outputs, want) {
		t.Errorf("Outputs = %v, want %v (second conventional name)", g.Outputs, want)
	}
}

func TestDetectPipNoVenv(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask\n")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterPip}) {
		t.Fatalf("adapters = %v, want [pip] even without a venv on disk", got)
	}
	g := det.Suggestions[0]
	if len(g.Outputs) != 0 {
		t.Errorf("Outputs = %v, want none (no conventional venv dir found)", g.Outputs)
	}
	if g.Present {
		t.Errorf("Present = true, want false")
	}
	if g.ApproxBytes != 0 {
		t.Errorf("ApproxBytes = %d, want 0", g.ApproxBytes)
	}
}

func TestDetectPipSuppressedByPyproject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt", "flask\n")
	writeFile(t, dir, "pyproject.toml", "")

	det := mustDetect(t, dir)
	if len(det.Suggestions) != 0 {
		t.Fatalf("suggestions = %v, want none (pyproject.toml excludes the pip group)", det.Suggestions)
	}
	if !hasNote(det, "pyproject.toml present without uv.lock") {
		t.Errorf("Notes = %v, want the unpinned pyproject note", det.Notes)
	}
}

func TestDetectNodePlusPython(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "package-lock.json", "{}")
	writeFile(t, dir, "pyproject.toml", "")
	writeFile(t, dir, "uv.lock", "")

	det := mustDetect(t, dir)
	if got, want := adapters(det), []string{AdapterNPM, AdapterUV}; !slices.Equal(got, want) {
		t.Fatalf("adapters = %v, want %v (fixed order, node and python coexist)", got, want)
	}
	if len(det.Notes) != 0 {
		t.Errorf("Notes = %v, want none", det.Notes)
	}
}

func TestDetectPackageJSONWithoutLockfile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "node_modules/left-pad/index.js", "12345")

	det := mustDetect(t, dir)
	if len(det.Suggestions) != 0 {
		t.Fatalf("suggestions = %v, want none (unpinned tree: preserve default)", det.Suggestions)
	}
	if !hasNote(det, "package.json present without package-lock.json or pnpm-lock.yaml") {
		t.Errorf("Notes = %v, want one explaining the missing lockfile", det.Notes)
	}
}

func TestDetectPyprojectWithoutLock(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml", "")

	det := mustDetect(t, dir)
	if len(det.Suggestions) != 0 {
		t.Fatalf("suggestions = %v, want none", det.Suggestions)
	}
	if !hasNote(det, "pyproject.toml present without uv.lock") {
		t.Errorf("Notes = %v, want the unpinned pyproject note", det.Notes)
	}
}

func TestDetectLockfileWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pnpm-lock.yaml", "lock")

	det := mustDetect(t, dir)
	if got := adapters(det); !slices.Equal(got, []string{AdapterPNPM}) {
		t.Fatalf("adapters = %v, want [pnpm] (lockfile is the marker)", got)
	}
	if !slices.Equal(det.Suggestions[0].Inputs, []string{"package.json", "pnpm-lock.yaml"}) {
		t.Errorf("package.json stays a required input: %v", det.Suggestions[0].Inputs)
	}
	if !hasNote(det, "without package.json") {
		t.Errorf("Notes = %v, want one flagging the missing manifest", det.Notes)
	}
}

func TestDetectEmptyDir(t *testing.T) {
	det := mustDetect(t, t.TempDir())
	if len(det.Suggestions) != 0 || len(det.Notes) != 0 {
		t.Fatalf("Detection = %+v, want empty (no markers, no notes)", det)
	}
}

func TestDetectBadRoot(t *testing.T) {
	if _, err := Detect(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Errorf("Detect(nonexistent): want error, got nil")
	}
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Detect(f); err == nil {
		t.Errorf("Detect(file): want error, got nil")
	}
}

func TestDetectDeterministic(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", "{}")
	writeFile(t, dir, "package-lock.json", "{}")
	writeFile(t, dir, ".npmrc", "x")
	writeFile(t, dir, "pyproject.toml", "")
	writeFile(t, dir, "uv.lock", "")
	writeFile(t, dir, ".python-version", "3.12")
	writeFile(t, dir, "node_modules/a/b.js", "123")
	writeFile(t, dir, ".venv/lib/x.py", "12345")

	first := mustDetect(t, dir)
	second := mustDetect(t, dir)
	if !reflect.DeepEqual(first, second) {
		t.Errorf("Detect is not deterministic:\nfirst:  %+v\nsecond: %+v", first, second)
	}
}
