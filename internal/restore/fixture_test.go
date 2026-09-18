package restore

// Test fixtures that mirror the frozen capture layout EXACTLY as
// internal/lifecycle/manifest.go writes it:
//
//   - a payload snapshot tree with /<opdir>/manifest.json,
//     /<opdir>/inventory.jsonl, /<opdir>/policy.toml and the workspace
//     files under /<wsprefix>/...;
//   - a seal snapshot with /<.ebb-seal-<opID>>/receipt.json;
//   - a real catalog row for the retained P/S pair.
//
// The manifest and receipt are minted BY HAND with correct digests
// (digest = SHA-256 over the exact bytes served from DumpFile), so the
// fixtures do not depend on lifecycle's writers — only on its frozen
// format. The workspace tree is a real on-disk fixture scanned with the
// native platform probe, so expected inventory facts (kinds, digests,
// link texts) are observed, not invented.

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/inventory"
	"ebb/internal/platform"
)

// fixtureSpec knobs for the fault/shape cases each test needs.
type fixtureSpec struct {
	kind            string   // catalog snapshot kind; default "park"
	omitPayloadID   bool     // catalog row without a payload backend id
	noSealID        bool     // catalog row without a seal backend id
	receiptPayload  string   // override receipt.PayloadBackendID
	extraReceiptFld bool     // inject an unknown field into the receipt JSON
	extraInvLine    bool     // inject an unknown field into inventory line 1
	recipeGroup     bool     // add a reconstruct action + scope exclusion
	customCommand   []string // action command override (recipeGroup)
}

type fixture struct {
	t         *testing.T
	parent    string
	wsPrefix  string
	srcRoot   string
	opID      domain.OperationID
	opDirName string

	manifestBytes   []byte
	manifestDigest  string
	inventoryBytes  []byte
	inventoryDigest string
	entries         []domain.Entry // native-probe scan of srcRoot (all preserve)

	snapID    domain.SnapshotID
	wsID      domain.WorkspaceID
	payloadID string
	sealID    string

	cat   *catalog.Catalog
	store *fakeStore
	vault VaultRef
	probe domain.PlatformProbe
}

const fxPassfileContent = "fixpass"

func buildFixture(t *testing.T, spec fixtureSpec) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{
		t:        t,
		parent:   t.TempDir(),
		wsPrefix: "renderer",
		opID:     domain.OperationID(domain.NewID()),
		snapID:   domain.SnapshotID(domain.NewID()),
		wsID:     domain.WorkspaceID(domain.NewID()),
		probe:    platform.New(),
	}
	f.opDirName = opPrefix + string(f.opID)
	f.srcRoot = filepath.Join(f.parent, f.wsPrefix)

	// ---- the "original workspace" tree --------------------------------
	mustMkdir(t, f.srcRoot)
	writeFile(t, filepath.Join(f.srcRoot, "a.txt"), []byte("alpha\n"))
	writeFile(t, filepath.Join(f.srcRoot, ".env"), []byte("SECRET=roundtrip\n"))
	writeFile(t, filepath.Join(f.srcRoot, "sub", "b.txt"), bytes.Repeat([]byte("beta-"), 64))
	writeFile(t, filepath.Join(f.srcRoot, "sub", "nested", "c.txt"), []byte("gamma"))
	mustMkdir(t, filepath.Join(f.srcRoot, "emptydir"))
	// Link fixture: real symlink where the platform allows; junction via
	// the unprivileged mklink /J on Windows; otherwise the test is
	// skipped with a clear reason (no faked coverage).
	target := filepath.Join(f.parent, "linked-target")
	mustMkdir(t, target)
	writeFile(t, filepath.Join(target, "inside.txt"), []byte("target content\n"))
	makeLink(t, filepath.Join(f.srcRoot, "link"), target)

	// ---- expected inventory: a real scan of the fixture ---------------
	scan := inventory.Scan(ctx, f.probe, f.srcRoot, inventory.Options{Hash: true})
	if scan.Err != nil {
		t.Fatalf("fixture scan: %v", scan.Err)
	}
	f.entries = scan.Entries

	// ---- inventory.jsonl (exact lifecycle serialization) --------------
	var inv bytes.Buffer
	for _, e := range f.entries {
		line, err := json.Marshal(inventoryRecord{Entry: e})
		if err != nil {
			t.Fatalf("marshal inventory record %s: %v", e.Path, err)
		}
		inv.Write(line)
		inv.WriteByte('\n')
	}
	f.inventoryBytes = inv.Bytes()
	if spec.extraInvLine {
		// Valid JSON, digest-consistent (digests are recomputed below),
		// but carrying a field the strict reader must reject.
		lines := strings.Split(strings.TrimSuffix(string(f.inventoryBytes), "\n"), "\n")
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
			t.Fatalf("unmarshal inventory line: %v", err)
		}
		m["unexpected_field"] = true
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		lines[0] = string(b)
		f.inventoryBytes = []byte(strings.Join(lines, "\n") + "\n")
	}
	f.inventoryDigest = digestBytes(f.inventoryBytes)

	// ---- manifest.json (complete §16.2 field set) ----------------------
	manifest := f.buildManifestDoc(spec)
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.manifestBytes = append(mb, '\n')
	f.manifestDigest = digestBytes(f.manifestBytes)

	// ---- op dir on disk, then the payload snapshot --------------------
	opDir := filepath.Join(f.parent, f.opDirName)
	mustMkdir(t, opDir)
	writeFile(t, filepath.Join(opDir, manifestName), f.manifestBytes)
	writeFile(t, filepath.Join(opDir, inventoryName), f.inventoryBytes)
	writeFile(t, filepath.Join(opDir, "policy.toml"), []byte("# frozen policy v1\n"))

	f.store = newFakeStore()
	f.vault = VaultRef{RepoDir: filepath.Join(f.parent, "repo"), Passfile: filepath.Join(f.parent, "pass")}
	writeFile(t, f.vault.Passfile, []byte(fxPassfileContent))

	payload, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent,
		[]string{f.opDirName, f.wsPrefix}, f.vault.Passfile, map[string]string{"ebb-kind": "payload"})
	if err != nil {
		t.Fatalf("fixture payload snapshot: %v", err)
	}
	f.payloadID = payload.BackendID

	// ---- receipt + seal snapshot ---------------------------------------
	receipt := receiptDoc{
		SchemaVersion: schemaVersionCurrent,
		SnapshotID:    string(f.snapID),
		WorkspaceID:   string(f.wsID),
		BackendRepoID: "fake-repo-id",
		PayloadBackendID: func() string {
			if spec.receiptPayload != "" {
				return spec.receiptPayload
			}
			return f.payloadID
		}(),
		ManifestDigest:   f.manifestDigest,
		InventoryDigest:  f.inventoryDigest,
		RequiredFeatures: []string{},
		Verification: receiptVerification{
			Checks:       []string{"coverage-complete", "payload-readback-complete"},
			Scope:        "single-owned-root",
			Time:         domain.FormatTime(time.Now()),
			ToolVersions: map[string]string{"ebb": "fixture", "backend": "fakeStore"},
		},
		OperationID: string(f.opID),
		Retention:   "pinned",
	}
	rb, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rb = append(rb, '\n')
	if spec.extraReceiptFld {
		trim := bytes.TrimSuffix(rb, []byte("}\n"))
		rb = append(trim, []byte(",\n  \"unexpected_field\": 1\n}\n")...)
	}
	sealDirName := sealPrefix + string(f.opID)
	sealDir := filepath.Join(f.parent, sealDirName)
	mustMkdir(t, sealDir)
	writeFile(t, filepath.Join(sealDir, receiptName), rb)
	seal, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent,
		[]string{sealDirName}, f.vault.Passfile, map[string]string{"ebb-kind": "seal"})
	if err != nil {
		t.Fatalf("fixture seal snapshot: %v", err)
	}
	f.sealID = seal.BackendID

	// ---- catalog rows ---------------------------------------------------
	f.cat = openCatalog(t, filepath.Join(f.parent, "catalog.db"))
	if err := f.cat.UpsertWorkspace(catalog.Workspace{
		ID: f.wsID, Name: f.wsPrefix, Status: catalog.WorkspaceParked,
	}); err != nil {
		t.Fatalf("fixture workspace row: %v", err)
	}
	payloadRef, sealRef := f.payloadID, f.sealID
	if spec.omitPayloadID {
		payloadRef = ""
	}
	if spec.noSealID {
		sealRef = ""
	}
	if _, err := f.cat.RecordSnapshot(catalog.Snapshot{
		ID: f.snapID, WorkspaceID: f.wsID,
		PayloadBackendID: payloadRef, SealBackendID: sealRef,
		ManifestDigest: f.manifestDigest, InventoryDigest: f.inventoryDigest,
		Kind: f.snapshotKind(spec),
	}); err != nil {
		t.Fatalf("fixture snapshot row: %v", err)
	}
	return f
}

func (f *fixture) snapshotKind(spec fixtureSpec) string {
	if spec.kind != "" {
		return spec.kind
	}
	return catalog.SnapshotKindPark
}

// buildManifestDoc assembles the complete §16.2 field set with the
// values restore depends on (roots bijection, inventory ref).
func (f *fixture) buildManifestDoc(spec fixtureSpec) manifestDoc {
	ident := f.rootIdentity()
	m := manifestDoc{
		SchemaVersion: schemaVersionCurrent,
		SnapshotID:    string(f.snapID),
		WorkspaceID:   string(f.wsID),
		CreatedAt:     domain.FormatTime(time.Now()),
		Producer:      "fixture",
		Contract: contractDoc{
			Scope: "single-owned-root", Consistency: "stopped-writers-asserted",
			ConsistencySource: "test", Fidelity: []string{"file-bytes", "paths"},
			Network: "approved-actions", TargetCompatibility: "native-v1",
		},
		Roots: []manifestRoot{
			{ID: "main", Ownership: "owned", SourcePath: f.srcRoot,
				SourceIdentity: ident, BackendPrefix: f.wsPrefix},
			{ID: "meta", Ownership: "owned", BackendPrefix: f.opDirName},
		},
		Inventory: manifestInventoryRef{
			Path: inventoryName, Digest: f.inventoryDigest,
			Count: int64(len(f.entries)), Bytes: int64(len(f.inventoryBytes)),
		},
		Policy:           manifestPolicy{Frozen: "# frozen policy v1\n", FrozenDigest: digestBytes([]byte("# frozen policy v1\n")), ResolvedDigest: "fixture"},
		Externals:        []manifestExternal{},
		Capabilities:     manifestCapabilities{Captured: []string{"file-bytes"}, NotPromised: []string{"acls"}},
		ManagedOutputs:   []manifestManagedOut{},
		ScopeExclusions:  []manifestExclusion{},
		RequiredFeatures: []string{},
	}
	if spec.recipeGroup {
		m.Actions = []manifestAction{{
			ID: "node-dependencies", Adapter: "pnpm", Root: ".",
			Outputs: []string{"node_modules"},
			Inputs:  []string{"package.json", "pnpm-lock.yaml"},
			Network: "allowed", Command: spec.customCommand, Ownership: "owned",
		}}
		m.ScopeExclusions = []manifestExclusion{{
			Path: "node_modules", Route: "reconstruct", Group: "node-dependencies",
			Note: "omitted with recorded route (I02)",
		}}
	}
	return m
}

func (f *fixture) rootIdentity() string {
	ident, err := f.probe.RootIdentity(f.srcRoot)
	if err != nil {
		f.t.Fatalf("fixture root identity: %v", err)
	}
	return ident.String()
}

// preservedBytes sums the fixture's preserved file sizes (the number the
// peak-space check uses).
func (f *fixture) preservedBytes() int64 {
	var n int64
	for _, e := range f.entries {
		if e.Kind == domain.KindFile {
			n += e.LogicalSize
		}
	}
	return n
}

// ---- small helpers ------------------------------------------------------

func openCatalog(t *testing.T, path string) *catalog.Catalog {
	t.Helper()
	c, err := catalog.Open(path)
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	mustMkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// makeLink creates the link fixture: a real symlink where allowed, else
// an unprivileged Windows junction (cmd /c mklink /J). If neither works
// the test is skipped with a clear reason — coverage is never faked.
func makeLink(t *testing.T, linkPath, target string) {
	t.Helper()
	if err := os.Symlink(target, linkPath); err == nil {
		return
	}
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", linkPath, target).CombinedOutput(); err == nil {
			return
		} else {
			t.Skipf("cannot create link fixture (symlink: %v; mklink: %v: %s); skipping link coverage",
				os.Symlink(target, linkPath), err, strings.TrimSpace(string(out)))
		}
	}
	t.Skipf("cannot create symlink fixture: %v; skipping link coverage", os.Symlink(target, linkPath))
}

// stageDirs lists leftover .ebb-stage-* directories next to a path.
func stageDirs(t *testing.T, parent string) []string {
	t.Helper()
	des, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("readdir %s: %v", parent, err)
	}
	var out []string
	for _, de := range des {
		if strings.HasPrefix(de.Name(), stagePrefix) {
			out = append(out, de.Name())
		}
	}
	return out
}

func assertNoStageDirs(t *testing.T, parent string) {
	t.Helper()
	if left := stageDirs(t, parent); len(left) > 0 {
		t.Fatalf("expected no staging leftovers in %s, found %v", parent, left)
	}
}

// assertTreesByteEqual independently compares two on-disk trees: the
// same set of files with identical bytes, the same directories (empty
// ones included), and links with identical text. This is the TEST's own
// oracle, separate from the implementation's inventory comparison.
func assertTreesByteEqual(t *testing.T, wantRoot, gotRoot string) {
	t.Helper()
	want := walkTree(t, wantRoot)
	got := walkTree(t, gotRoot)
	var wantPaths, gotPaths []string
	for p := range want {
		wantPaths = append(wantPaths, p)
	}
	for p := range got {
		gotPaths = append(gotPaths, p)
	}
	sort.Strings(wantPaths)
	sort.Strings(gotPaths)
	if strings.Join(wantPaths, "\n") != strings.Join(gotPaths, "\n") {
		t.Fatalf("tree shapes differ.\nwant paths: %v\ngot paths:  %v", wantPaths, gotPaths)
	}
	for _, p := range wantPaths {
		if want[p] != got[p] {
			t.Fatalf("%s: content/kind mismatch\nwant: %q\ngot:  %q", p, want[p], got[p])
		}
	}
}

// walkTree returns relpath -> "dir", "file:<sha>" or "link:<text>" for
// every node under root. Links are observed with Lstat/Readlink only
// (never followed); junctions surface as links on Windows.
func walkTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	var walk func(rel string)
	walk = func(rel string) {
		abs := filepath.Join(root, rel)
		des, err := os.ReadDir(abs)
		if err != nil {
			t.Fatalf("readdir %s: %v", abs, err)
		}
		for _, de := range des {
			child := de.Name()
			if rel != "" {
				child = rel + "/" + de.Name()
			}
			fi, err := os.Lstat(filepath.Join(root, child))
			if err != nil {
				t.Fatalf("lstat %s: %v", child, err)
			}
			switch {
			case fi.Mode().IsRegular():
				b, err := os.ReadFile(filepath.Join(root, child))
				if err != nil {
					t.Fatalf("read %s: %v", child, err)
				}
				out[child] = "file:" + digestBytes(b)
			case fi.IsDir():
				out[child] = "dir"
				walk(child)
			case fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
				txt, err := os.Readlink(filepath.Join(root, child))
				if err != nil {
					t.Fatalf("readlink %s: %v", child, err)
				}
				out[child] = "link:" + txt
			default:
				t.Fatalf("unexpected object kind at %s (%s)", child, fi.Mode())
			}
		}
	}
	walk("")
	return out
}

// newOpener wires the production-shaped seams, including the platform
// link creator the CLI will inject in the Wave F integration (mirrors
// the wiring note in links.go: restore itself cannot import platform).
func newOpener(f *fixture) *Opener {
	return newOpenerWithCreator(f, platform.CreateLink)
}

func newOpenerWithCreator(f *fixture, creator LinkCreator) *Opener {
	o, err := New(Dependencies{Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: creator})
	if err != nil {
		f.t.Fatalf("New: %v", err)
	}
	return o
}

func (f *fixture) open(ctx context.Context, o *Opener, opts Options) (Result, error) {
	f.t.Helper()
	return o.Open(ctx, f.vault, f.snapID, opts)
}
