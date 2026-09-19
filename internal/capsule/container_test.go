package capsule

// container_test.go — unit tests for the ZIP64 stored-entry transport:
// round trip with many entries, the §15.3 hostile-name discipline, the
// §15.1 public-descriptor shape, declared-length/total gates, and the
// stale-partial identification reader.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
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

// ---- wave-J fix regressions (default suite) ----------------------------

// TestValidateEntryNameRejectsWin32IllegalChars guards the J5 fix: the
// full Win32 illegal-character class — `* ? < > | "` and every C0
// control character — is refused host-agnostically, with the error
// naming the character class, because such a name can never be created
// on the primary supported platform and must not pass the verify gate.
func TestValidateEntryNameRejectsWin32IllegalChars(t *testing.T) {
	for _, c := range []string{"*", "?", "<", ">", "|", `"`} {
		name := "repo/data/ab" + c + "c"
		err := validateEntryName(name, true)
		if err == nil || !strings.Contains(err.Error(), "illegal filename character") {
			t.Errorf("illegal char %q: err = %v (must refuse and name the class)", c, err)
		}
	}
	for c := byte(0x01); c < 0x20; c++ { // 0x00 is caught by the whole-name NUL check
		name := "repo/data/ab" + string(rune(c)) + "c"
		err := validateEntryName(name, true)
		if err == nil || !strings.Contains(err.Error(), "C0 control character") {
			t.Errorf("C0 control %#04x: err = %v (must refuse and name the class)", c, err)
		}
	}
	// The same class is refused in non-repo (top-level) names too.
	for _, name := range []string{"bo*otstrap.json", "ebb-\x1fexport.json"} {
		if err := validateEntryName(name, false); err == nil {
			t.Errorf("top-level name %q with illegal character accepted", name)
		}
	}
	// Adjacent benign names stay accepted (no over-rejection).
	for _, name := range []string{"repo/data/ab'c", "repo/data/ab;c", "repo/data/ab=c"} {
		if err := validateEntryName(name, true); err != nil {
			t.Errorf("benign name %q rejected: %v", name, err)
		}
	}
}

// TestValidateEntryNameSegmentUTF16Limit guards the hardening-note-3 fix:
// a single path segment longer than 255 UTF-16 code units (the NTFS
// per-component limit) is refused at verify with the limit named. The
// length is judged in UTF-16 units, not bytes, so non-ASCII segments
// near the limit are judged correctly.
func TestValidateEntryNameSegmentUTF16Limit(t *testing.T) {
	// Boundary: exactly 255 units passes, 256 ASCII refuses.
	if err := validateEntryName("repo/data/"+strings.Repeat("a", 255), true); err != nil {
		t.Errorf("255-unit segment rejected: %v", err)
	}
	err := validateEntryName("repo/data/"+strings.Repeat("a", 256), true)
	if err == nil || !strings.Contains(err.Error(), "255") {
		t.Errorf("256-unit segment: err = %v (must refuse and name the 255-unit limit)", err)
	}
	// Astral characters occupy TWO UTF-16 units each: 127 of them are
	// 508 bytes but only 254 units (must PASS — byte length is not the
	// limit), while 128 are 256 units (must REFUSE).
	if err := validateEntryName("repo/data/"+strings.Repeat("\U0001F600", 127), true); err != nil {
		t.Errorf("508-byte/254-unit segment rejected: %v", err)
	}
	if err := validateEntryName("repo/data/"+strings.Repeat("\U0001F600", 128), true); err == nil {
		t.Error("256-unit astral segment accepted (UTF-16 length not enforced)")
	}
	// The limit applies per SEGMENT: a long full name of short segments
	// stays portable.
	if err := validateEntryName("repo/"+strings.Repeat("d/", 200)+"f", true); err != nil {
		t.Errorf("long name of short segments rejected: %v", err)
	}
}

// TestVerifyPackageRejectsCaseCollisions guards the J6 fix: a container
// holding two entry names that differ only by case is refused at verify
// on EVERY platform, with the colliding pair named, because the
// case-insensitive primary platform cannot hold both files.
func TestVerifyPackageRejectsCaseCollisions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.zip")
	docs := validDocs(2, 10)
	docs["repo/data/Ab"] = []byte("upper")
	docs["repo/data/ab"] = []byte("lower")
	craftZip(t, path, docs, zip.Store, nil)
	_, err := verifyPackage(path)
	if err == nil {
		t.Fatal("case-collision container accepted at verify")
	}
	for _, want := range []string{"repo/data/Ab", "repo/data/ab", "case-collision"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	// No over-rejection: mixed-case names WITHOUT a collision verify
	// fine, in the same directory and across segments.
	path2 := filepath.Join(t.TempDir(), "ok.zip")
	docs2 := validDocs(2, 4)
	docs2["repo/Data/Ab"] = []byte("xy")
	docs2["repo/Data/cd"] = []byte("zw")
	craftZip(t, path2, docs2, zip.Store, nil)
	if _, err := verifyPackage(path2); err != nil {
		t.Errorf("mixed-case but collision-free container refused: %v", err)
	}
}

// TestVerifyPackageRejectsAbsurdDeclaredRepoBytes guards the J7
// companion gate: a declared repository byte total at or above 2^62 is
// refused at verify ("not a real repository") so the import preflight's
// `2 * RepoBytes` headroom arithmetic can never overflow.
func TestVerifyPackageRejectsAbsurdDeclaredRepoBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.zip")
	boot, _ := json.Marshal(bootstrapDoc{
		SchemaVersion: 1, Producer: "ebb test", ContainerVersion: 1,
		BackendFamily: "restic", RepoRoot: "repo", MinReaderFeatures: []string{"zip64"},
	})
	exp, _ := json.Marshal(exportManifestDoc{
		SchemaVersion: 1, Kind: exportDocKind, OperationID: "op", SourceSnapshotID: "snap",
		StartedAt: "t", State: exportStateRun, ContainerVersion: 1,
		RepoEntries: 1, RepoBytes: int64(1) << 62,
	})
	docs := map[string][]byte{
		"bootstrap.json":  append(boot, '\n'),
		"ebb-export.json": append(exp, '\n'),
		"repo/config":     []byte("ab"),
	}
	craftZip(t, path, docs, zip.Store, nil)
	_, err := verifyPackage(path)
	if err == nil || !strings.Contains(err.Error(), "not a real repository") {
		t.Errorf("absurd declared repo_bytes: err = %v (must refuse at the plausibility ceiling)", err)
	}
	// Just below the ceiling the gate stays open (the totals cross-check
	// is what refuses the mismatch — not the ceiling).
	exp2, _ := json.Marshal(exportManifestDoc{
		SchemaVersion: 1, Kind: exportDocKind, OperationID: "op", SourceSnapshotID: "snap",
		StartedAt: "t", State: exportStateRun, ContainerVersion: 1,
		RepoEntries: 1, RepoBytes: int64(1)<<62 - 1,
	})
	docs["ebb-export.json"] = append(exp2, '\n')
	path2 := filepath.Join(t.TempDir(), "y.zip")
	craftZip(t, path2, docs, zip.Store, nil)
	if _, err := verifyPackage(path2); err == nil || strings.Contains(err.Error(), "not a real repository") {
		t.Errorf("boundary declared repo_bytes: err = %v (must refuse on totals, not on the ceiling)", err)
	}
}

// TestVerifyPackageRejectsFileVersusImpliedDirectoryConflict guards the
// J6 residual fix: an entry naming a FILE at a path another entry's path
// passes through as a DIRECTORY (repo/data/ab + repo/data/ab/x) was
// accepted by verifyPackage pre-fix and failed only at extraction, on
// EVERY platform, with an opaque order-dependent error naming neither
// the defect class nor the pair (live-probed on Win11 26200: file-first
// gives `mkdir ...: The system cannot find the path specified`, dir-first
// gives `open ...: is a directory`). The refusal is now explicit, at
// verify and at the skip-verify extraction defense, with the pair named.
func TestVerifyPackageRejectsFileVersusImpliedDirectoryConflict(t *testing.T) {
	// Order 1: the file entry sorts before the deep entry.
	path := filepath.Join(t.TempDir(), "x.zip")
	docs := validDocs(2, 9)
	docs["repo/data/ab"] = []byte("file!")
	docs["repo/data/ab/x"] = []byte("deep")
	craftZip(t, path, docs, zip.Store, nil)
	_, err := verifyPackage(path)
	if err == nil || !strings.Contains(err.Error(), "file/directory conflict") {
		t.Fatalf("file-vs-implied-directory (file first): err = %v (must refuse with the class named)", err)
	}
	for _, want := range []string{"repo/data/ab", "repo/data/ab/x"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	// Defense in depth: skipping verify gets the same named refusal.
	if exErr := extractRepository(path, filepath.Join(t.TempDir(), "out"), 1<<62); exErr == nil ||
		!strings.Contains(exErr.Error(), "file/directory conflict") ||
		!strings.Contains(exErr.Error(), "repo/data/ab") {
		t.Errorf("extraction defense: err = %v (must refuse with the pair named)", exErr)
	}
	// Order 2: the file entry comes AFTER the entry that implies the
	// directory (appended past the sorted names) — same refusal.
	path2 := filepath.Join(t.TempDir(), "y.zip")
	docs2 := validDocs(2, 7) // "deep" (4) + appended duplicate body "dup" (3)
	docs2["repo/data/ab/x"] = []byte("deep")
	craftZip(t, path2, docs2, zip.Store, []string{"repo/data/ab"})
	if _, err := verifyPackage(path2); err == nil || !strings.Contains(err.Error(), "file/directory conflict") {
		t.Errorf("file-vs-implied-directory (file last): err = %v (order must not decide the verdict)", err)
	}
}

// TestVerifyPackageRejectsEntryCaseCollisionWithImpliedDirectory guards
// the J6 residual fix: an entry file whose name differs only by case
// from another entry's IMPLIED directory (repo/data/Ab file +
// repo/data/ab/x file) verified clean pre-fix, then the case-insensitive
// primary platform failed the second operation with the same opaque
// order-dependent error as the exact conflict while a case-sensitive
// platform extracted both — the J6 divergence one level up, refused on
// every platform with the pair named.
func TestVerifyPackageRejectsEntryCaseCollisionWithImpliedDirectory(t *testing.T) {
	// Order 1: the colliding file entry sorts first.
	path := filepath.Join(t.TempDir(), "x.zip")
	docs := validDocs(2, 9)
	docs["repo/data/Ab"] = []byte("upper")
	docs["repo/data/ab/x"] = []byte("deep")
	craftZip(t, path, docs, zip.Store, nil)
	_, err := verifyPackage(path)
	if err == nil || !strings.Contains(err.Error(), "case-collision") {
		t.Fatalf("entry-vs-implied-directory case collision (file first): err = %v (must refuse with the class named)", err)
	}
	for _, want := range []string{"repo/data/Ab", "repo/data/ab"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	if exErr := extractRepository(path, filepath.Join(t.TempDir(), "out"), 1<<62); exErr == nil ||
		!strings.Contains(exErr.Error(), "repo/data/Ab") {
		t.Errorf("extraction defense: err = %v (must refuse with the pair named)", exErr)
	}
	// Order 2: the implied directory is created first (its entry sorts
	// before the colliding file) — same refusal, proving the verdict is
	// not extraction-order-dependent.
	path2 := filepath.Join(t.TempDir(), "y.zip")
	docs2 := validDocs(2, 9)
	docs2["repo/data/Ab/x"] = []byte("deep")
	docs2["repo/data/ab"] = []byte("lower")
	craftZip(t, path2, docs2, zip.Store, nil)
	if _, err := verifyPackage(path2); err == nil || !strings.Contains(err.Error(), "case-collision") {
		t.Errorf("entry-vs-implied-directory case collision (dir first): err = %v", err)
	}
}

// TestVerifyPackageRejectsImpliedDirectoryCaseMerge guards the J6
// residual fix's subtlest class: two entries implying directories that
// differ only by case (repo/data/Ab/x + repo/data/ab/y). Live-probed,
// extraction of this shape returns a NIL error on both platform
// families — but the case-insensitive primary platform MERGES the
// directories (one `data/Ab` holding both files) while a case-sensitive
// one keeps both (WSL ext4 probe: `Ab` and `ab` coexist). No error fires
// anywhere, so the pre-fix gates were blind to it; the resulting
// extracted tree shape depends on the host, which D028 refuses.
func TestVerifyPackageRejectsImpliedDirectoryCaseMerge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.zip")
	docs := validDocs(2, 6)
	docs["repo/data/Ab/x"] = []byte("one")
	docs["repo/data/ab/y"] = []byte("two")
	craftZip(t, path, docs, zip.Store, nil)
	_, err := verifyPackage(path)
	if err == nil || !strings.Contains(err.Error(), "tree-shape divergence") {
		t.Fatalf("implied-directory case merge: err = %v (must refuse with the class named)", err)
	}
	for _, want := range []string{"repo/data/Ab/x", "repo/data/ab/y", "repo/data/Ab", "repo/data/ab"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not name %q: %v", want, err)
		}
	}
	// Defense in depth: the skip-verify extraction refuses with the pair
	// named instead of silently producing a platform-shaped tree.
	if exErr := extractRepository(path, filepath.Join(t.TempDir(), "out"), 1<<62); exErr == nil ||
		!strings.Contains(exErr.Error(), "tree-shape divergence") {
		t.Errorf("extraction defense: err = %v (must refuse, not silently merge or split)", exErr)
	}
}

// TestVerifyPackageImpliedDirectoryNamespaceNoOverRejection proves the
// implied-directory namespace checks do not refuse collision-free
// containers: mixed-case directory names that never fold-collide verify
// AND extract cleanly — including the same SEGMENT spelling at different
// paths (repo/A/x + repo/B/a/y share no path prefix, so `A` and `a`
// never meet), fold-distinct directories, and shared exact spellings.
func TestVerifyPackageImpliedDirectoryNamespaceNoOverRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.zip")
	entries := map[string][]byte{
		"repo/Data/Ab": []byte("shared-dir-mixed-case"),
		"repo/Data/cd": []byte("same-parent"),
		"repo/A/x":     []byte("seg-a-upper"),
		"repo/B/a/y":   []byte("seg-a-lower"),
		"repo/Keys/k1": []byte("fold-distinct"),
		"repo/index/1": []byte("lowercase-sibling"),
	}
	var total int64
	for _, b := range entries {
		total += int64(len(b))
	}
	docs := validDocs(int64(len(entries)), total)
	for k, v := range entries {
		docs[k] = v
	}
	craftZip(t, path, docs, zip.Store, nil)
	if _, err := verifyPackage(path); err != nil {
		t.Fatalf("collision-free mixed-case container refused: %v", err)
	}
	dst := t.TempDir()
	if err := extractRepository(path, dst, total); err != nil {
		t.Fatalf("collision-free mixed-case container does not extract: %v", err)
	}
	for name, body := range entries {
		b, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(strings.TrimPrefix(name, "repo/"))))
		if err != nil || !bytes.Equal(b, body) {
			t.Errorf("extracted %s = %q (%v) — must round trip byte-identical", name, b, err)
		}
	}
}

// TestExtractRepositorySaturatingBudget guards the J7 fix: the remaining
// allowance saturates instead of overflowing, so a MaxInt64 budget
// extracts the REAL bytes exactly like the MaxInt64-1 control (pre-fix
// it silently truncated every entry to zero bytes with a nil error),
// while over-budget and negative budgets still refuse.
func TestExtractRepositorySaturatingBudget(t *testing.T) {
	dir := t.TempDir()
	body := "hello"
	path := writeRawCapsule(t, dir, map[string]string{
		"bootstrap.json":  minimalBootstrap(),
		"repo/data/a":     body,
		"repo/data/b":     body,
		"ebb-export.json": minimalExportDoc(2, 2*int64(len(body))),
	})
	for _, budget := range []int64{math.MaxInt64 - 1, math.MaxInt64} {
		dst := filepath.Join(dir, fmt.Sprintf("out-%d", budget))
		if err := extractRepository(path, dst, budget); err != nil {
			t.Fatalf("budget %d: %v", budget, err)
		}
		for _, f := range []string{"data/a", "data/b"} {
			b, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(f)))
			if err != nil || string(b) != body {
				t.Errorf("budget %d: %s = %q (%v) — real bytes must extract", budget, f, b, err)
			}
		}
	}
	// Over-budget detection is intact: a budget below the true content
	// refuses with the named budget error.
	dst := filepath.Join(dir, "over")
	if err := extractRepository(path, dst, int64(len(body))); err == nil ||
		!strings.Contains(err.Error(), "exceeded the verified byte budget") {
		t.Errorf("over-budget: err = %v (must refuse with the named budget error)", err)
	}
	// A negative budget is refused outright instead of silently writing
	// nothing.
	if err := extractRepository(path, filepath.Join(dir, "neg"), -1); err == nil {
		t.Error("negative budget accepted")
	}
}
