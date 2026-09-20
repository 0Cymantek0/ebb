package dockeradapter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func windowsHostCheck() bool { return runtime.GOOS == "windows" }

// toWSLPath renders a native Windows path in the WSL /mnt/<drive> form
// Docker Desktop compose records when it runs inside the guest.
func toWSLPath(t *testing.T, native string) string {
	t.Helper()
	vol := filepath.VolumeName(native) // "C:"
	drive := strings.ToLower(strings.TrimSuffix(vol, ":"))
	rest := strings.ReplaceAll(strings.TrimPrefix(native, vol), string(filepath.Separator), "/")
	return "/mnt/" + drive + rest
}

// ---- normalization matrix -------------------------------------------------

func TestPathKeyNormalizationMatrix(t *testing.T) {
	if runtime.GOOS == "windows" {
		base := t.TempDir() // canonical true-case spelling
		variants := []string{
			base,
			strings.ReplaceAll(base, "\\", "/"), // forward slashes
			toWSLPath(t, base),                  // /mnt/c/... WSL label form
			"/" + strings.ToLower(strings.TrimSuffix(filepath.VolumeName(base), ":")) +
				strings.ReplaceAll(strings.TrimPrefix(base, filepath.VolumeName(base)), "\\", "/"), // /c/... git-bash form
			strings.ToLower(base),             // case divergence (NTFS is case-insensitive)
			base + string(filepath.Separator), // trailing separator
		}
		want := pathKey(base)
		for _, v := range variants {
			if got := pathKey(v); got != want {
				t.Errorf("pathKey(%q) = %q, want %q", v, got, want)
			}
		}
		// A different directory must NOT fold onto the same key.
		other := filepath.Join(filepath.Dir(base), "sibling-"+filepath.Base(base))
		if err := os.MkdirAll(other, 0o755); err != nil {
			t.Fatal(err)
		}
		if pathKey(other) == want {
			t.Errorf("sibling directory %q folded onto %q", other, base)
		}
		return
	}
	// POSIX: separators and dot segments normalize; case does NOT fold.
	base := t.TempDir()
	same := []string{base, base + "/", base + "/.", base + "//"}
	want := pathKey(base)
	for _, v := range same {
		if got := pathKey(v); got != want {
			t.Errorf("pathKey(%q) = %q, want %q", v, got, want)
		}
	}
	if got := pathKey(strings.ToUpper(base)); got == want && base != strings.ToUpper(base) {
		t.Errorf("POSIX path keys must be case-sensitive: %q folded", base)
	}
}

func TestNormalizeDockerPathWindowsForms(t *testing.T) {
	if runtime.GOOS != "windows" {
		// On POSIX the WSL/git-bash spellings are real paths and must be
		// left alone (documented rule step 2).
		if got := normalizeDockerPath("/mnt/c/Users/x"); got != "/mnt/c/Users/x" {
			t.Fatalf("POSIX normalize(/mnt/c/Users/x) = %q, want unchanged", got)
		}
		return
	}
	cases := map[string]string{
		`/mnt/c/Users/x`:                 `C:\Users\x`,
		`/mnt/f/data`:                    `F:\data`,
		`/c/Users/x`:                     `C:\Users\x`,
		`C:/Users/x`:                     `C:\Users\x`,
		`C:\Users\x`:                     `C:\Users\x`,
		"\\wsl$\\docker-desktop\\mnt\\c": "\\wsl$\\docker-desktop\\mnt\\c", // UNC untouched
	}
	for in, want := range cases {
		if got := normalizeDockerPath(in); got != want {
			t.Errorf("normalizeDockerPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- workspace index ------------------------------------------------------

func TestWorkspaceIndexDedupAndActivity(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "proj")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	touchAge(t, root, 30*24*time.Hour) // dormant

	now := time.Now()
	ix := buildWorkspaceIndex([]string{
		root,
		strings.ReplaceAll(root, "\\", "/"), // same root, different spelling
		filepath.Join(base, "missing-root"), // nonexistent: kept but never active
	}, now)
	if len(ix.entries) != 2 {
		t.Fatalf("index entries = %d, want 2 (deduped spelling + kept missing root)", len(ix.entries))
	}
	for _, e := range ix.entries {
		if e.Active {
			t.Fatalf("30d-old root must not be active: %+v", e)
		}
	}

	// A fresh child file makes the workspace active (depth-1 scan).
	newFile := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(newFile, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	ix2 := buildWorkspaceIndex([]string{root}, time.Now())
	if !ix2.entries[0].Active {
		t.Fatalf("root with a fresh child must be active: %+v", ix2.entries[0])
	}
}

func TestWorkspaceActivityEmptyOldRoot(t *testing.T) {
	root := t.TempDir()
	touchAge(t, root, 200*24*time.Hour)
	when, ok := workspaceActivity(root)
	if !ok {
		t.Fatal("activity expected for existing root")
	}
	if time.Since(when) < 100*24*time.Hour {
		t.Fatalf("activity = %v, want ~200d old", time.Since(when))
	}
}

func TestMatchPathUnderRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "proj")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ix := buildWorkspaceIndex([]string{root}, time.Now())
	if _, ok := ix.matchPath(filepath.Join(root, "sub", "dir")); !ok {
		t.Fatal("path under the root must match")
	}
	if _, ok := ix.matchPath(filepath.Join(base, "other")); ok {
		t.Fatal("unrelated path must not match")
	}
	if _, ok := ix.matchPath(""); ok {
		t.Fatal("empty path must not match")
	}
}

func TestMatchNameComposeForms(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "Restore") // mixed case on purpose
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	ix := buildWorkspaceIndex([]string{root}, time.Now())
	for _, repo := range []string{"restore", "restore-web", "restore_api", "RESTORE-WEB"} {
		if _, ok := ix.matchName(repo); !ok {
			t.Errorf("matchName(%q) should match root base %q", repo, "restore")
		}
	}
	for _, repo := range []string{"restores", "res", "unrelated", ""} {
		if _, ok := ix.matchName(repo); ok {
			t.Errorf("matchName(%q) must not match", repo)
		}
	}
}

func TestCorrelateDockerPathThreeWay(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "proj")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	deleted := filepath.Join(base, "deleted")
	underRoot := filepath.Join(root, "svc")
	if err := os.MkdirAll(underRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	ix := buildWorkspaceIndex([]string{root}, time.Now())

	entry, matched, exists := ix.correlateDockerPath(underRoot)
	if !matched || !exists || entry.Root != root {
		t.Fatalf("under-root: matched=%v exists=%v entry=%+v", matched, exists, entry)
	}
	_, matched, exists = ix.correlateDockerPath(outside)
	if matched || !exists {
		t.Fatalf("outside: matched=%v exists=%v, want false/true", matched, exists)
	}
	_, matched, exists = ix.correlateDockerPath(deleted)
	if matched || exists {
		t.Fatalf("deleted: matched=%v exists=%v, want false/false", matched, exists)
	}
}

// ---- small predicates -----------------------------------------------------

func TestIsAnonymousVolumeName(t *testing.T) {
	anon := strings.Repeat("ab", 32) // 64 hex chars
	if !isAnonymousVolumeName(anon) {
		t.Fatal("64-hex name must be anonymous")
	}
	for _, name := range []string{
		strings.Repeat("ab", 31) + "x", // 63 chars
		"proj_db-data",
		strings.ToUpper(anon), // docker anonymous names are lowercase
		"",
	} {
		if isAnonymousVolumeName(name) {
			t.Errorf("isAnonymousVolumeName(%q) must be false", name)
		}
	}
}

func TestShortID(t *testing.T) {
	if got := shortID("sha256:" + strings.Repeat("a", 64)); got != strings.Repeat("a", 12) {
		t.Fatalf("shortID sha form = %q", got)
	}
	if got := shortID(strings.Repeat("b", 8)); got != strings.Repeat("b", 8) {
		t.Fatalf("shortID short form = %q", got)
	}
}

func TestUpstreamShaped(t *testing.T) {
	yes := []string{
		"postgres", "redis", "node", "library/postgres", "docker.io/postgres",
		"ghcr.io/acme/api", "registry.corp:5000/team/app", "localhost/dev/api",
	}
	no := []string{
		"", "<none>", "myuser/myapp", "myproj-web", "some-random-local-build",
	}
	for _, repo := range yes {
		if !upstreamShaped(repo) {
			t.Errorf("upstreamShaped(%q) should be true", repo)
		}
	}
	for _, repo := range no {
		if upstreamShaped(repo) {
			t.Errorf("upstreamShaped(%q) should be false", repo)
		}
	}
}

func TestParseDockerTimeAndSince(t *testing.T) {
	if _, ok := parseDockerTime("2026-01-02T15:04:05Z"); !ok {
		t.Fatal("RFC3339 must parse")
	}
	if _, ok := parseDockerTime("2026-01-02 15:04:05 +0000 UTC"); !ok {
		t.Fatal("docker ls CreatedAt form must parse")
	}
	if _, ok := parseDockerTime("not a time"); ok {
		t.Fatal("garbage must not parse")
	}
	if d, ok := parseSince("2 months ago"); !ok || d < 55*24*time.Hour || d > 65*24*time.Hour {
		t.Fatalf("parseSince(2 months ago) = %v ok=%v", d, ok)
	}
	if _, ok := parseSince("nope"); ok {
		t.Fatal("parseSince(nope) must fail")
	}
}

func TestFlexIntAndLabels(t *testing.T) {
	var rows []dfRow
	skipped := decodeLines(
		`{"Type":"Images","Size":1048576}`+"\n"+
			`{"Type":"Containers","Size":"412MB"}`+"\n"+
			`{bad}`+"\n", func(line []byte) error {
			var r dfRow
			if err := json.Unmarshal(line, &r); err != nil {
				return err
			}
			rows = append(rows, r)
			return nil
		})
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if len(rows) != 2 || int64(rows[0].Size) != 1<<20 || int64(rows[1].Size) != 412*1000*1000 {
		t.Fatalf("rows = %+v", rows)
	}
	var c containerRec
	if err := json.Unmarshal([]byte(`{"Labels":"a=1,b=2"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Labels["a"] != "1" || c.Labels["b"] != "2" {
		t.Fatalf("legacy string labels = %v", c.Labels)
	}
}
