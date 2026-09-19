package capsule

// container_test.go — unit tests for the ZIP64 stored-entry transport:
// round trip with many entries, the §15.3 hostile-name discipline, the
// §15.1 public-descriptor shape, declared-length/total gates, and the
// stale-partial identification reader.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildFakeRepo writes a restic-shaped tree: data/<xx>/<hex>, index/,
// keys/, config — regular files and directories only.
func buildFakeRepo(t *testing.T, nFiles int) string {
	t.Helper()
	root := t.TempDir()
	for i := 0; i < nFiles; i++ {
		rel := filepath.FromSlash(strings.ToLower(hexOf(i, 64)))
		p := filepath.Join(root, "data", rel[:2], rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(strings.Repeat("x", 1+(i%97))), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "config"), []byte("opaque"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func hexOf(v, n int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[(v+i)%16]
	}
	return string(b)
}

func TestPackageRoundTripManyEntries(t *testing.T) {
	repo := buildFakeRepo(t, 300)
	out := filepath.Join(t.TempDir(), "capsule.partial")
	size, err := writePackage(out, repo, "2026-09-19T00:00:00Z", "op123", "snap456", "ebb test")
	if err != nil {
		t.Fatalf("writePackage: %v", err)
	}
	if size <= 0 {
		t.Fatalf("size = %d", size)
	}
	check, err := verifyPackage(out)
	if err != nil {
		t.Fatalf("verifyPackage: %v", err)
	}
	if check.Bootstrap.BackendFamily != "restic" || check.Bootstrap.RepoRoot != "repo" {
		t.Errorf("bootstrap = %+v", check.Bootstrap)
	}
	if check.ExportDoc.OperationID != "op123" || check.ExportDoc.SourceSnapshotID != "snap456" {
		t.Errorf("export doc = %+v", check.ExportDoc)
	}
	files, err := walkRepoFiles(repo)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(files)) != check.ExportDoc.RepoEntries {
		t.Errorf("declared entries = %d, walked %d", check.ExportDoc.RepoEntries, len(files))
	}

	// Extraction round trip: every file byte-identical. The budget is the
	// package's own verified repo total (unbounded for the round trip).
	extract := t.TempDir()
	if err := extractRepository(out, extract, check.ExportDoc.RepoBytes); err != nil {
		t.Fatalf("extractRepository: %v", err)
	}
	for _, rel := range files {
		a, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(extract, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("extracted %s missing: %v", rel, err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs after round trip", rel)
		}
	}
}

func TestBootstrapShapeIsPublicOnly(t *testing.T) {
	// §15.1: the descriptor exposes ONLY container version, backend
	// family, repo-relative root, minimum reader feature set (plus the
	// §16.1 schema_version/producer). No workspace names, paths,
	// inventory data, or secrets may ever be added.
	b := bootstrapDoc{
		SchemaVersion: 1, Producer: "ebb test", ContainerVersion: 1,
		BackendFamily: "restic", RepoRoot: "repo",
		MinReaderFeatures: []string{"zip64", "zip-stored-entries", "restic"},
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"schema_version": true, "producer": true, "container_version": true,
		"backend_family": true, "repo_root": true, "min_reader_features": true,
	}
	for k := range got {
		if !want[k] {
			t.Errorf("bootstrap carries unexpected public field %q", k)
		}
	}
	if err := checkBootstrap(b); err != nil {
		t.Errorf("checkBootstrap: %v", err)
	}
	// Unknown features / wrong family / wrong root are refused.
	for _, bad := range []bootstrapDoc{
		{SchemaVersion: 2, BackendFamily: "restic", RepoRoot: "repo", MinReaderFeatures: []string{"zip64"}},
		{SchemaVersion: 1, BackendFamily: "borg", RepoRoot: "repo", MinReaderFeatures: []string{"zip64"}},
		{SchemaVersion: 1, BackendFamily: "restic", RepoRoot: "elsewhere", MinReaderFeatures: []string{"zip64"}},
		{SchemaVersion: 1, BackendFamily: "restic", RepoRoot: "repo"},
	} {
		if err := checkBootstrap(bad); err == nil {
			t.Errorf("bootstrap %+v accepted", bad)
		}
	}
	// Strict parse: unknown fields rejected.
	var b2 bootstrapDoc
	if err := decodeStrictDoc([]byte(`{"schema_version":1,"container_version":1,"backend_family":"restic","repo_root":"repo","min_reader_features":["zip64"],"workspace_name":"leak"}`), bootstrapName, &b2); err == nil {
		t.Error("strict parse accepted an unknown (leaking) field")
	}
}

func TestValidateEntryNameHostileSet(t *testing.T) {
	reject := []string{
		"",                 // empty
		"/etc/passwd",      // absolute
		"repo/../secret",   // traversal
		"repo/..",          // traversal final segment
		"repo/a/./b",       // dot segment
		`repo\backslash`,   // windows separator
		"C:/repo/config",   // drive alias
		"repo/config\x00",  // NUL
		"repo//double",     // empty segment
		"repo/CON",         // device name
		"repo/con.txt",     // device name with extension
		"repo/lpt1.config", // device name with extension
	}
	for _, name := range reject {
		if err := validateEntryName(name, true); err == nil {
			t.Errorf("hostile name %q accepted", name)
		}
	}
	accept := []string{
		"bootstrap.json",
		"ebb-export.json",
		"repo/config",
		"repo/data/ab/deadbeef",
		"repo/keys/regular-name",
	}
	for _, name := range accept {
		wantRepo := strings.HasPrefix(name, "repo/")
		if err := validateEntryName(name, wantRepo); err != nil {
			t.Errorf("legitimate name %q rejected: %v", name, err)
		}
	}
	// A repo file at top level (outside repo/) is rejected even with a
	// benign name; a known top-level doc is not a repo entry.
	if err := validateEntryName("config", true); err == nil {
		t.Error("repo-prefixed validation accepted a top-level name")
	}
	if err := validateEntryName("repo/extra.txt", false); err == nil {
		t.Error("non-repo validation accepted a repo path")
	}
}

// craftZip writes a zip with the given entries (method configurable,
// duplicate names appended after the sorted declared ones) — the
// hostile-crafting helper for reader-side tests.
func craftZip(t *testing.T, path string, entries map[string][]byte, method uint16, duplicates []string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range sortedNames(entries) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entries[n]); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range duplicates {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("dup")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sortedNames(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func validDocs(repoEntries int64, repoBytes int64) map[string][]byte {
	boot, _ := json.Marshal(bootstrapDoc{
		SchemaVersion: 1, Producer: "ebb test", ContainerVersion: 1,
		BackendFamily: "restic", RepoRoot: "repo", MinReaderFeatures: []string{"zip64"},
	})
	exp, _ := json.Marshal(exportManifestDoc{
		SchemaVersion: 1, Kind: "ebb-export", OperationID: "op", SourceSnapshotID: "snap",
		StartedAt: "t", State: exportStateRun, ContainerVersion: 1,
		RepoEntries: repoEntries, RepoBytes: repoBytes,
	})
	return map[string][]byte{
		"bootstrap.json":  append(boot, '\n'),
		"ebb-export.json": append(exp, '\n'),
	}
}

func TestVerifyPackageRejectsHostileContainers(t *testing.T) {
	t.Run("duplicate names", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "x.zip")
		docs := validDocs(1, 4)
		docs["repo/config"] = []byte("ab")
		craftZip(t, path, docs, zip.Store, []string{"repo/config"})
		if _, err := verifyPackage(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("duplicate names: err = %v", err)
		}
	})
	t.Run("traversal name", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "x.zip")
		docs := validDocs(1, 2)
		docs["repo/../escape"] = []byte("ab")
		craftZip(t, path, docs, zip.Store, nil)
		if _, err := verifyPackage(path); err == nil {
			t.Error("traversal entry accepted")
		}
	})
	t.Run("compressed method", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "x.zip")
		docs := validDocs(1, 2)
		docs["repo/config"] = []byte("ab")
		craftZip(t, path, docs, zip.Deflate, nil)
		if _, err := verifyPackage(path); err == nil || !strings.Contains(err.Error(), "STORED") {
			t.Errorf("deflated entry: err = %v", err)
		}
	})
	t.Run("declared totals mismatch (bomb shape)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "x.zip")
		docs := validDocs(99, 9999) // declares far more than present
		docs["repo/config"] = []byte("ab")
		craftZip(t, path, docs, zip.Store, nil)
		if _, err := verifyPackage(path); err == nil || !strings.Contains(err.Error(), "totals disagree") {
			t.Errorf("declared totals: err = %v", err)
		}
	})
	t.Run("corrupt bytes", func(t *testing.T) {
		repo := buildFakeRepo(t, 20)
		path := filepath.Join(t.TempDir(), "x.partial")
		if _, err := writePackage(path, repo, "t", "op", "snap", "ebb test"); err != nil {
			t.Fatal(err)
		}
		// Flip bytes in the middle of the stored payload area.
		raw, _ := os.ReadFile(path)
		for i := len(raw) / 2; i < len(raw)/2+64 && i < len(raw); i++ {
			raw[i] ^= 0xFF
		}
		os.WriteFile(path, raw, 0o600)
		if _, err := verifyPackage(path); err == nil {
			t.Error("corrupted container accepted")
		}
	})
	t.Run("missing identification doc", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "x.zip")
		docs := validDocs(1, 2)
		delete(docs, "ebb-export.json")
		docs["repo/config"] = []byte("ab")
		craftZip(t, path, docs, zip.Store, nil)
		if _, err := verifyPackage(path); err == nil {
			t.Error("container without ebb-export.json accepted")
		}
	})
}

func TestReadPartialManifest(t *testing.T) {
	repo := buildFakeRepo(t, 5)
	path := filepath.Join(t.TempDir(), "stale.partial")
	if _, err := writePackage(path, repo, "2026-09-19T01:02:03Z", "the-op", "the-snap", "ebb test"); err != nil {
		t.Fatal(err)
	}
	doc, err := readPartialManifest(path)
	if err != nil {
		t.Fatalf("readPartialManifest: %v", err)
	}
	if doc.OperationID != "the-op" || doc.SourceSnapshotID != "the-snap" {
		t.Errorf("doc = %+v", doc)
	}
	// A non-zip file is reported as unrecognized, not as an empty doc.
	junk := filepath.Join(t.TempDir(), "junk.partial")
	os.WriteFile(junk, []byte("not a zip at all"), 0o600)
	if _, err := readPartialManifest(junk); err == nil {
		t.Error("junk partial accepted")
	}
}

func TestWalkRepoFilesRejectsLinks(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "data"), 0o755)
	os.WriteFile(filepath.Join(root, "data", "real"), []byte("x"), 0o600)
	// A link inside the repo must abort the walk (§15.2: never follow).
	link := filepath.Join(root, "data", "link")
	if err := os.Symlink(filepath.Join(root, "data", "real"), link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := walkRepoFiles(root); err == nil {
		t.Error("link inside repo accepted by the walk")
	}
}
