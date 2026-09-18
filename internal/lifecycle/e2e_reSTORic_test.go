package lifecycle

// Product-level acceptance tests: a full park→open round trip through the
// REAL restic 0.19.1 binary (internal/storage/restic.Store), crossing
// lifecycle + storage/restic + restore on real NTFS. Until this file, both
// lifecycle and restore were verified only against filesystem fakes; here
// the whole stack — inventory scan, policy resolve, §11.2 selection,
// restic capture, §11.4 coverage/readback, seal, quarantine removal,
// §12.5 seal validation, restic restore, oracle verification, publish —
// runs end to end with no fault-injection doubles.
//
// Every test skips with a clear reason when restic is not usable (the
// suite must stay green without the binary; restic 0.19.1 IS installed on
// the dev machine via scoop). Set EBB_TEST_RESTIC_BIN to a bogus name to
// exercise the skip path deterministically.
//
// Known real-stack platform gap pinned here (first surfaced by this
// suite): restic cannot materialize a reparse point (junction/symlink)
// during `restic restore` without SeCreateSymbolicLinkPrivilege — the
// link WORKSPACE parks perfectly (stored as a link node, never followed)
// but its open fails with the adapter's typed content failure on an
// unprivileged machine. TestE2EResticJunctionWorkspace asserts BOTH
// outcomes honestly instead of faking coverage.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	"ebb/internal/platform"
	"ebb/internal/policy"
	"ebb/internal/restore"
	resticstore "ebb/internal/storage/restic"
)

// ---- skip guard + real-stack harness ----------------------------------

// e2eResticBin resolves the restic binary exactly the way the storage
// adapter's own conformance tests do (exec.LookPath). EBB_TEST_RESTIC_BIN
// overrides the lookup target so the skip path can be proven on a machine
// that has restic installed.
func e2eResticBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("EBB_TEST_RESTIC_BIN")
	if bin == "" {
		bin = "restic"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("restic binary %q not usable on this machine (%v); real-backend acceptance suite skipped", bin, err)
	}
	return path
}

// e2eEnv is the real-stack harness: one restic-backed vault repository,
// one real SQLite catalog, the real platform probe, and fresh
// coordinator/opener factories that open a FRESH catalog handle per call
// (new-process simulation — no in-memory carryover is possible).
type e2eEnv struct {
	t       *testing.T
	store   *resticstore.Store
	probe   domain.PlatformProbe
	vault   VaultRef
	catPath string
	opened  []*catalog.Catalog
}

func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	store := resticstore.New(e2eResticBin(t))
	t.Cleanup(store.Close) // removes the private restic cache dir

	vaultBase := t.TempDir()
	e := &e2eEnv{
		t:       t,
		store:   store,
		probe:   platform.New(),
		vault:   VaultRef{RepoDir: filepath.Join(vaultBase, "repo"), Passfile: filepath.Join(vaultBase, "repo.pass")},
		catPath: filepath.Join(vaultBase, "catalog.db"),
	}
	if err := os.WriteFile(e.vault.Passfile, []byte("e2e-restic-suite-password"), 0o600); err != nil {
		t.Fatalf("passfile: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Init(ctx, e.vault.RepoDir, e.vault.Passfile); err != nil {
		t.Fatalf("restic init: %v", err)
	}
	// Windows teardown: t.TempDir cannot delete the catalog while a pooled
	// connection holds it; close every handle the env opened (LIFO).
	t.Cleanup(func() {
		for _, cat := range e.opened {
			_ = cat.Close()
		}
	})
	return e
}

// newCat opens a FRESH catalog handle over the shared database and tracks
// it for teardown.
func (e *e2eEnv) newCat() *catalog.Catalog {
	e.t.Helper()
	cat, err := catalog.Open(e.catPath)
	if err != nil {
		e.t.Fatalf("open catalog: %v", err)
	}
	e.opened = append(e.opened, cat)
	return cat
}

// coord builds a lifecycle Coordinator over a fresh catalog handle. probe
// nil means the real platform probe; a wrapper (crash-cancel injection)
// can be supplied without losing verified-dir descent (the wrapper embeds
// the interface, so OpenDirVerified is promoted).
func (e *e2eEnv) coord(probe domain.PlatformProbe) *Coordinator {
	e.t.Helper()
	if probe == nil {
		probe = e.probe
	}
	c, err := New(Dependencies{Store: e.store, Cat: e.newCat(), Probe: probe})
	if err != nil {
		e.t.Fatalf("new coordinator: %v", err)
	}
	return c
}

// opener builds a restore Opener over a fresh catalog view of the same
// catalog database and the same real restic store.
func (e *e2eEnv) opener() *restore.Opener {
	e.t.Helper()
	o, err := restore.New(restore.Dependencies{Store: e.store, Cat: e.newCat(), Probe: platform.New()})
	if err != nil {
		e.t.Fatalf("new opener: %v", err)
	}
	return o
}

// rvault is the restore-package spelling of the vault reference.
func (e *e2eEnv) rvault() restore.VaultRef {
	return restore.VaultRef{RepoDir: e.vault.RepoDir, Passfile: e.vault.Passfile}
}

// opCtx bounds one full lifecycle/restore operation. restic subprocesses
// additionally carry the store's own default timeout; the pattern mirrors
// the storage adapter's conformance tests (context deadlines, no
// SetTimeout override).
func (e *e2eEnv) opCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

// opIDOfPayload resolves the operation id recorded in the backend tags of
// one payload snapshot (the same discovery binding Recover relies on).
func (e *e2eEnv) opIDOfPayload(t *testing.T, payloadID string) domain.OperationID {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	refs, err := e.store.List(ctx, e.vault.RepoDir, e.vault.Passfile)
	if err != nil {
		t.Fatalf("restic snapshots: %v", err)
	}
	for _, r := range refs {
		if r.BackendID == payloadID {
			if op := r.Tags["ebb-op"]; op != "" {
				return domain.OperationID(op)
			}
		}
	}
	t.Fatalf("no ebb-op tag found on payload snapshot %s", payloadID)
	return ""
}

// phaseOf reads an operation's current phase straight from the journal
// through a fresh catalog view.
func (e *e2eEnv) phaseOf(t *testing.T, opID domain.OperationID) string {
	t.Helper()
	op, err := e.newCat().GetOperation(opID)
	if err != nil {
		t.Fatalf("get operation %s: %v", opID, err)
	}
	return op.Phase
}

// ---- independent test-side walker --------------------------------------

// e2eNode is one observed object of the TEST's own tree walk. This walker
// is deliberately independent of the scanner under test (never reuse
// inventory.Scan as an oracle for both sides of a comparison).
type e2eNode struct {
	IsDir  bool
	Size   int64
	Digest string // sha256 over the exact bytes (regular files)
	Link   string // literal link text (symlinks and junctions)
}

// e2eWalkTree walks root without following links and maps every
// slash-relative path to its observed node. All opened files are closed
// (a leaked handle would block the lifecycle's own renames/removals on
// Windows — Learnings).
func e2eWalkTree(t *testing.T, root string) map[string]e2eNode {
	t.Helper()
	out := map[string]e2eNode{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		fi, ierr := d.Info() // lstat-based for children
		if ierr != nil {
			return ierr
		}
		switch {
		case fi.Mode().IsRegular():
			f, oerr := os.Open(p)
			if oerr != nil {
				return oerr
			}
			h := sha256.New()
			_, cerr := io.Copy(h, f)
			f.Close() // before anything else: never leak onto the fixture
			if cerr != nil {
				return cerr
			}
			out[rel] = e2eNode{Size: fi.Size(), Digest: hex.EncodeToString(h.Sum(nil))}
		case fi.IsDir():
			out[rel] = e2eNode{IsDir: true}
		case fi.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
			txt, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			out[rel] = e2eNode{Link: txt}
		default:
			return fmt.Errorf("e2e walk: unmodeled object %s (%s)", rel, fi.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("e2e walk %s: %v", root, err)
	}
	return out
}

// e2eSameTree asserts two walks describe exactly the same tree (both
// directions, with per-path diagnostics).
func e2eSameTree(t *testing.T, want, got map[string]e2eNode) {
	t.Helper()
	var missing, extra, changed []string
	for p, w := range want {
		g, ok := got[p]
		if !ok {
			missing = append(missing, p)
			continue
		}
		if g != w {
			changed = append(changed, fmt.Sprintf("%s: want %+v got %+v", p, w, g))
		}
	}
	for p := range got {
		if _, ok := want[p]; !ok {
			extra = append(extra, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("entries missing from the walked tree: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("entries appearing unexpectedly: %v", extra)
	}
	if len(changed) > 0 {
		t.Errorf("entries differing:\n\t%s", strings.Join(changed, "\n\t"))
	}
}

// e2eNoScratch asserts no .ebb-* sibling scratch objects remain under dir.
func e2eNoScratch(t *testing.T, dir, what string) {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-") {
			t.Errorf("%s: scratch object %s left behind", what, d.Name())
		}
	}
}

// ---- fixtures -----------------------------------------------------------

const (
	// e2eMainPolicyTOML is the Ebbfile of the main acceptance workspace:
	// one small regenerate group (npm adapter) so trim coverage exists and
	// the open reports a rebuild hint for the omitted group.
	e2eMainPolicyTOML = `
version = 1

[workspace]
name = "e2e-main"

[policy]
network = "approved-actions"
unknown = "preserve"

[[regenerate]]
id = "gen"
adapter = "npm"
root = "."
outputs = ["gen"]
inputs = ["package.json"]
network = "allowed"
`
	e2eMainPackageJSON = `{"name":"e2e-main","version":"0.1.0","private":true}` + "\n"
	e2eMainGitHead     = "ref: refs/heads/main\n"
	e2eMainGitConfig   = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n"
	e2eMainREADME      = "# e2e acceptance workspace\n"
	e2eMainNotes       = "notes that must survive the park/open round trip\n"
	e2eMainLogo        = "\x89PNG e2e stand-in payload\n"
	e2eMainDeep        = "deeply nested file\n"
	e2eMainGenBundle   = "// generated bundle — reconstruct route, omitted from capture\n"
	e2eMainGenChunk    = "// generated chunk\n"

	// e2eBigSize gives realistic restic chunking (~1.5 MiB, several
	// 512KiB/1MiB chunks) without slowing the suite.
	e2eBigSize = 1<<20 + 512*1024
)

// e2eBigFile builds deterministic, poorly-compressible content (same LCG
// family as the restic adapter's own conformance fixture).
func e2eBigFile() []byte {
	b := make([]byte, e2eBigSize)
	next := uint32(0x9E3779B9)
	for i := range b {
		next = next*1664525 + 1013904223
		b[i] = byte(next >> 23)
	}
	return b
}

func e2eWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// buildMainWorkspace creates the main acceptance fixture: nested dirs, an
// empty dir, a fake .git (HEAD + config), an Ebbfile.toml declaring the
// "gen" regenerate group, generated output under gen/, and one ~1.5MiB
// file for realistic chunking. It deliberately contains NO links — the
// link workspace is separate (see TestE2EResticJunctionWorkspace).
func (e *e2eEnv) buildMainWorkspace(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "ws-main")
	text := map[string]string{
		"package.json":           e2eMainPackageJSON,
		"Ebbfile.toml":           e2eMainPolicyTOML,
		"README.md":              e2eMainREADME,
		"notes.md":               e2eMainNotes,
		"assets/logo.png":        e2eMainLogo,
		"assets/nested/deep.txt": e2eMainDeep,
		".git/HEAD":              e2eMainGitHead,
		".git/config":            e2eMainGitConfig,
		"gen/bundle.js":          e2eMainGenBundle,
		"gen/sub/chunk.js":       e2eMainGenChunk,
	}
	for rel, content := range text {
		e2eWriteFile(t, filepath.Join(root, filepath.FromSlash(rel)), []byte(content))
	}
	e2eWriteFile(t, filepath.Join(root, "assets", "big.bin"), e2eBigFile())
	if err := os.MkdirAll(filepath.Join(root, "emptydir"), 0o755); err != nil {
		t.Fatalf("emptydir: %v", err)
	}
	return root
}

// e2eIsGenOmitted reports whether a walk path belongs to the omitted
// regenerate group of the main workspace.
func e2eIsGenOmitted(p string) bool {
	return p == "gen" || strings.HasPrefix(p, "gen/")
}

// e2eMakeLink creates the link fixture: a true symlink where the platform
// allows it, else an unprivileged Windows junction (cmd /c mklink /J).
// If neither works the test skips with a clear reason — coverage is never
// faked.
func e2eMakeLink(t *testing.T, link, target string) {
	t.Helper()
	symErr := os.Symlink(target, link)
	if symErr == nil {
		return
	}
	if runtime.GOOS != "windows" {
		t.Skipf("cannot create symlink fixture on this platform: %v; skipping link coverage", symErr)
	}
	out, merr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if merr != nil {
		t.Skipf("cannot create link fixture (symlink: %v; mklink /J: %v: %s); skipping link coverage",
			symErr, merr, strings.TrimSpace(string(out)))
	}
	if _, lerr := os.Lstat(link); lerr != nil {
		t.Skipf("link %s did not materialize (%v); skipping link coverage", link, lerr)
	}
}

// e2eCancelProbe wraps the real platform probe (interface embedding, so
// verified-dir descent stays promoted) and fires a hook on every
// ProbeFile call — the crash test cancels the context from it at an exact
// sequence point inside the removal walk.
type e2eCancelProbe struct {
	domain.PlatformProbe
	onProbeFile func(path string)
}

func (p *e2eCancelProbe) ProbeFile(path string) (domain.FileFacts, error) {
	if p.onProbeFile != nil {
		p.onProbeFile(path)
	}
	return p.PlatformProbe.ProbeFile(path)
}

// ---- scenario 1: full park→open round trip through real restic --------

// TestE2EResticParkOpenRoundTrip is THE core acceptance: snapshot (source
// byte-identical before/after), park (root gone, snapshot pinned) and
// open through internal/restore to a fresh destination (byte-identical
// preserved set, empty dir, git admin files, rebuild hints, pin intact).
func TestE2EResticParkOpenRoundTrip(t *testing.T) {
	e := newE2EEnv(t)
	root := e.buildMainWorkspace(t)
	ws := newWSID()
	pol, err := policy.Parse([]byte(e2eMainPolicyTOML))
	if err != nil {
		t.Fatalf("parse Ebbfile: %v", err)
	}

	// before is the INDEPENDENT pre-park digest map every later byte
	// comparison derives from (never the scanner under test).
	before := e2eWalkTree(t, root)
	var preserved, omitted, preservedBytes int64
	for p, n := range before {
		if e2eIsGenOmitted(p) {
			omitted++
			continue
		}
		preserved++
		if !n.IsDir && n.Link == "" {
			preservedBytes += n.Size
		}
	}
	if preserved == 0 || omitted == 0 {
		t.Fatalf("fixture wiring wrong: preserved=%d omitted=%d", preserved, omitted)
	}

	t.Run("snapshot leaves the source byte-identical", func(t *testing.T) {
		ctx, cancel := e.opCtx()
		defer cancel()
		res, err := e.coord(nil).Snapshot(ctx, e.vault, root, CaptureOptions{
			WorkspaceName: "e2e-main", WorkspaceID: ws, Policy: pol,
		})
		if err != nil {
			t.Fatalf("snapshot through the real restic backend: %v", err)
		}
		if res.SnapshotID == "" || res.BackendIDs[0] == "" || res.BackendIDs[1] == "" {
			t.Fatalf("snapshot result incomplete: %+v", res)
		}
		if res.EntriesPreserved != preserved || res.EntriesOmitted != omitted {
			t.Errorf("preserved/omitted = %d/%d, want %d/%d",
				res.EntriesPreserved, res.EntriesOmitted, preserved, omitted)
		}
		if len(res.Warnings) != 0 {
			t.Errorf("unexpected capture warnings: %v", res.Warnings)
		}

		// Source untouched: independent walker, both directions.
		e2eSameTree(t, before, e2eWalkTree(t, root))

		// Durable state: op DONE, retained snapshot row kind "snapshot",
		// pinned (I07).
		opID := e.opIDOfPayload(t, res.BackendIDs[0])
		if got := e.phaseOf(t, opID); got != catalog.PhaseDone {
			t.Errorf("snapshot op phase = %q, want DONE", got)
		}
		snap, err := e.newCat().GetSnapshot(res.SnapshotID)
		if err != nil {
			t.Fatalf("get snapshot row: %v", err)
		}
		if !snap.Pinned || snap.Kind != catalog.SnapshotKindSnapshot ||
			snap.PayloadBackendID != res.BackendIDs[0] || snap.SealBackendID != res.BackendIDs[1] {
			t.Errorf("snapshot row wrong: %+v", snap)
		}
	})

	var parkSnapID domain.SnapshotID
	var parkPayload string

	t.Run("park removes the root and pins the snapshot", func(t *testing.T) {
		ctx, cancel := e.opCtx()
		defer cancel()
		res, err := e.coord(nil).Park(ctx, e.vault, root, CaptureOptions{
			WorkspaceName:   "e2e-main",
			WorkspaceID:     ws,
			Policy:          pol,
			Park:            true,
			WriterAssertion: "e2e-acceptance: writers asserted stopped",
		})
		if err != nil {
			t.Fatalf("park through the real restic backend: %v", err)
		}
		parkSnapID, parkPayload = res.Snapshot.SnapshotID, res.Snapshot.BackendIDs[0]

		mustLstatErrNotExist(t, root)
		opID := e.opIDOfPayload(t, parkPayload)
		if got := e.phaseOf(t, opID); got != catalog.PhaseDone {
			t.Errorf("park op phase = %q, want DONE (PARKED must not block the workspace)", got)
		}
		cat := e.newCat()
		w, err := cat.GetWorkspace(ws)
		if err != nil {
			t.Fatal(err)
		}
		if w.Status != catalog.WorkspaceParked || w.RootPath != "" {
			t.Errorf("workspace after park = %q rooted at %q, want parked/unbound", w.Status, w.RootPath)
		}
		snaps, _ := cat.ListSnapshots(ws)
		if len(snaps) != 2 {
			t.Fatalf("snapshot rows = %d, want 2 (snapshot + park)", len(snaps))
		}
		kinds := map[string]bool{}
		for _, s := range snaps {
			kinds[s.Kind] = true
			if !s.Pinned {
				t.Errorf("snapshot %s not pinned after park (I07)", s.ID)
			}
		}
		if !kinds[catalog.SnapshotKindSnapshot] || !kinds[catalog.SnapshotKindPark] {
			t.Errorf("snapshot kinds = %v, want both snapshot and park", kinds)
		}
		e2eNoScratch(t, filepath.Dir(root), "park parent")
	})

	t.Run("open restores the preserved set to a fresh destination", func(t *testing.T) {
		destParent := t.TempDir()
		dest := filepath.Join(destParent, "ws-main-restored")

		ctx, cancel := e.opCtx()
		defer cancel()
		res, err := e.opener().Open(ctx, e.rvault(), parkSnapID, restore.Options{
			Destination: dest, FilesOnly: true,
		})
		if err != nil {
			t.Fatalf("open through the real restic backend: %v", err)
		}

		// Byte-identical PRESERVED set (omitted group excluded, both
		// directions): the pre-park independent walker is the oracle.
		wantPreserved := map[string]e2eNode{}
		for p, n := range before {
			if !e2eIsGenOmitted(p) {
				wantPreserved[p] = n
			}
		}
		e2eSameTree(t, wantPreserved, e2eWalkTree(t, dest))

		// Explicit pins for the mission's named invariants.
		if fi, err := os.Lstat(filepath.Join(dest, "emptydir")); err != nil || !fi.IsDir() {
			t.Errorf("empty dir not restored: %v", err)
		}
		gotHead, err := os.ReadFile(filepath.Join(dest, ".git", "HEAD"))
		if err != nil || string(gotHead) != e2eMainGitHead {
			t.Errorf(".git/HEAD bytes differ after round trip: %q (%v)", gotHead, err)
		}
		if _, err := os.Lstat(filepath.Join(dest, "gen")); !os.IsNotExist(err) {
			t.Errorf("omitted group gen/ must not be restored (stat err = %v)", err)
		}

		// Rebuild hints: the omitted group with its literal recipe command.
		if len(res.RebuildHints) != 1 {
			t.Fatalf("rebuild hints = %+v, want exactly the gen group", res.RebuildHints)
		}
		h := res.RebuildHints[0]
		if h.GroupID != "gen" || strings.Join(h.Command, " ") != "npm ci" ||
			strings.Join(h.Inputs, ",") != "package.json" || h.Network != "allowed" {
			t.Errorf("unexpected rebuild hint: %+v", h)
		}

		if res.Destination != dest || res.SnapshotID != parkSnapID || res.WorkspaceID != ws {
			t.Errorf("result identity fields wrong: %+v", res)
		}
		if res.EntriesRestored != preserved || res.BytesRestored != preservedBytes {
			t.Errorf("restored = %d entries / %d bytes, want %d / %d",
				res.EntriesRestored, res.BytesRestored, preserved, preservedBytes)
		}

		// Durable state: op FILES_READY, workspace live at the destination
		// with a FRESH identity (I13 — compare via the probe, not path
		// strings), snapshot STILL pinned (I07), staging cleaned.
		cat := e.newCat()
		op, err := cat.GetOperation(res.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if op.Phase != catalog.PhaseFilesReady || op.Kind != catalog.OpKindOpen {
			t.Errorf("open op = %s/%s, want open/FILES_READY", op.Kind, op.Phase)
		}
		w, err := cat.GetWorkspace(ws)
		if err != nil {
			t.Fatal(err)
		}
		if w.Status != catalog.WorkspaceLive || w.RootPath != filepath.Clean(dest) {
			t.Errorf("workspace after open = %q at %q, want live at %q", w.Status, w.RootPath, dest)
		}
		ident, err := e.probe.RootIdentity(dest)
		if err != nil {
			t.Fatalf("probe identity of restored root: %v", err)
		}
		if w.RootIdentity != ident.String() {
			t.Errorf("workspace identity %q is not the freshly probed identity %q (I13 re-bind)", w.RootIdentity, ident.String())
		}
		snap, err := cat.GetSnapshot(parkSnapID)
		if err != nil {
			t.Fatal(err)
		}
		if !snap.Pinned {
			t.Error("snapshot must stay pinned after opening (I07)")
		}
		e2eNoScratch(t, destParent, "destination parent")
	})
}

// ---- scenario 1b: link (junction) workspace ------------------------------

// TestE2EResticJunctionWorkspace parks a workspace containing a junction
// (or true symlink where allowed) through the real backend and then opens
// it. Capture side: the link is stored as a link node and NEVER followed.
// Open side: environment-conditional, because restic cannot materialize
// reparse points without SeCreateSymbolicLinkPrivilege (a real-stack gap
// the filesystem fakes masked — the junction round-tripped fine there).
func TestE2EResticJunctionWorkspace(t *testing.T) {
	e := newE2EEnv(t)
	parent := t.TempDir()
	root := filepath.Join(parent, "ws-link")
	// The link target lives OUTSIDE the workspace root (a separate temp
	// root); a file inside it proves the capture never followed the link.
	target := filepath.Join(t.TempDir(), "link-target")
	e2eWriteFile(t, filepath.Join(target, "inside.txt"), []byte("target content\n"))
	e2eWriteFile(t, filepath.Join(root, "keep.txt"), []byte("link workspace content\n"))
	e2eMakeLink(t, filepath.Join(root, "link-out"), target)

	before := e2eWalkTree(t, root)
	linkText, err := os.Readlink(filepath.Join(root, "link-out"))
	if err != nil {
		t.Fatalf("capture fixture link text before park: %v", err)
	}
	ws := newWSID()

	ctx, cancel := e.opCtx()
	defer cancel()
	res, err := e.coord(nil).Park(ctx, e.vault, root, CaptureOptions{
		WorkspaceName:   "ws-link",
		WorkspaceID:     ws,
		Policy:          policy.Default("ws-link"),
		Park:            true,
		WriterAssertion: "e2e-acceptance: writers asserted stopped",
	})
	if err != nil {
		t.Fatalf("park of a link workspace through the real restic backend: %v", err)
	}
	mustLstatErrNotExist(t, root)
	if got := e.phaseOf(t, e.opIDOfPayload(t, res.Snapshot.BackendIDs[0])); got != catalog.PhaseDone {
		t.Errorf("park op phase = %q, want DONE", got)
	}

	// The link round-tripped into P as a link node; the target tree did
	// NOT ride along (verified through the backend itself).
	entries := map[string]domain.TreeEntry{}
	nodes, err := e.store.Ls(ctx, e.vault.RepoDir, e.vault.Passfile, res.Snapshot.BackendIDs[0])
	if err != nil {
		t.Fatalf("restic ls of payload: %v", err)
	}
	for _, n := range nodes {
		entries[n.Path] = n
	}
	link := entries["/ws-link/link-out"]
	if link.Path == "" || link.Kind != domain.KindSymlink {
		t.Errorf("junction node in payload tree = %+v, want a symlink-kind node", link)
	}
	for p := range entries {
		if strings.HasPrefix(p, "/ws-link/link-out/") {
			t.Errorf("restic followed the junction: %s in the payload tree", p)
		}
	}
	if _, ok := entries["/ws-link/keep.txt"]; !ok {
		t.Error("regular file missing from the payload tree")
	}
	for p := range entries {
		if strings.HasSuffix(p, "inside.txt") {
			t.Errorf("link target content leaked into the payload via %s", p)
		}
	}

	// Open the parked link workspace to a fresh destination. Both outcomes
	// are real, pinned behaviors of the stack on this machine class:
	//
	//   - privileged (admin / Developer Mode / linux): full round trip,
	//     link text byte-equal;
	//   - unprivileged Windows: restic restore cannot materialize the
	//     reparse point; the adapter fails the restore as a CONTENT
	//     failure, nothing is published, no staging remains.
	destParent := t.TempDir()
	dest := filepath.Join(destParent, "ws-link-restored")
	octx, ocancel := e.opCtx()
	defer ocancel()
	ores, oerr := e.opener().Open(octx, e.rvault(), res.Snapshot.SnapshotID, restore.Options{
		Destination: dest, FilesOnly: true,
	})
	switch {
	case oerr == nil:
		gotLink, lerr := os.Readlink(filepath.Join(dest, "link-out"))
		if lerr != nil || gotLink != linkText {
			t.Errorf("restored link text = %q (%v), want the captured %q", gotLink, lerr, linkText)
		}
		e2eSameTree(t, before, e2eWalkTree(t, dest))
		e2eNoScratch(t, destParent, "destination parent")
		t.Log("link materialization succeeded on this privileged environment")
	default:
		if !strings.Contains(oerr.Error(), "materialize") {
			t.Fatalf("open failed for an unexpected reason (not the known link-materialization gap): %v", oerr)
		}
		if _, serr := os.Lstat(dest); !os.IsNotExist(serr) {
			t.Errorf("nothing may be published on a failed materialization (stat err = %v)", serr)
		}
		e2eNoScratch(t, destParent, "destination parent")
		// The failed open is journaled for recovery, never lost.
		cat := e.newCat()
		active, aerr := cat.ActiveOperations(ws)
		if aerr != nil || len(active) != 1 || active[0].Phase != catalog.PhaseRestoring {
			t.Errorf("failed materialization must leave one RESTORING op, got %d (%v)", len(active), aerr)
		}
		if snap, serr := cat.GetSnapshot(res.Snapshot.SnapshotID); serr != nil || !snap.Pinned {
			t.Errorf("snapshot must stay pinned after a failed open: %+v (%v)", snap, serr)
		}
		_ = ores
		t.Log("unprivileged environment: link materialization failed with the pinned typed error (nothing published)")
	}
}

// ---- scenario 2: trim against the real backend ---------------------------

// TestE2EResticTrim trims the declared pnpm group of the standard fixture
// through the real backend: outputs gone, inputs intact, TRIM_DONE, and
// the removal-manifest plus byte-exact recipe-input copies are retrievable
// from the retained snapshot via restic dump.
func TestE2EResticTrim(t *testing.T) {
	e := newE2EEnv(t)
	root := filepath.Join(t.TempDir(), "ws-trim")
	writeStdFixture(t, root)
	ws := newWSID()

	ctx, cancel := e.opCtx()
	defer cancel()
	res, err := e.coord(nil).Trim(ctx, e.vault, root, CaptureOptions{
		WorkspaceName: "fixture",
		WorkspaceID:   ws,
		Policy:        trimPolicy(t),
		DoTrim:        []string{"deps"},
		ApprovalReady: func(string) error { return nil },
	})
	if err != nil {
		t.Fatalf("trim through the real restic backend: %v", err)
	}

	// Live-root effects: group outputs removed (empty parents cleaned),
	// everything else intact, workspace stays live.
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
	mustLstatErrNotExist(t, filepath.Join(root, "vendor", "dist"))
	mustExist(t, filepath.Join(root, "vendor", "LICENSE.txt"))
	mustExist(t, filepath.Join(root, "package.json"))
	mustExist(t, filepath.Join(root, "pnpm-lock.yaml"))
	mustExist(t, filepath.Join(root, "notes.md"))
	w, err := e.newCat().GetWorkspace(ws)
	if err != nil || w.Status != catalog.WorkspaceLive {
		t.Errorf("workspace must stay live after trim: %+v (%v)", w, err)
	}

	opID := e.opIDOfPayload(t, res.Snapshot.BackendIDs[0])
	if got := e.phaseOf(t, opID); got != catalog.PhaseTrimDone {
		t.Errorf("trim op phase = %q, want TRIM_DONE", got)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "deps" {
		t.Errorf("groups = %v, want [deps]", res.Groups)
	}
	if len(res.ReclaimCommands) != 1 || !equalStrings(res.ReclaimCommands[0], []string{"pnpm", "install", "--frozen-lockfile"}) {
		t.Errorf("reclaim commands = %v", res.ReclaimCommands)
	}
	if res.EntriesRemoved != 7 {
		t.Errorf("entries removed = %d, want 7", res.EntriesRemoved)
	}
	e2eNoScratch(t, filepath.Dir(root), "trim parent")

	// Retained evidence retrievable from the REAL backend via DumpFile:
	// the removal manifest and byte-exact copies of the recipe inputs.
	prefix := "/" + opDirName(opID)
	raw, err := e.store.DumpFile(ctx, e.vault.RepoDir, e.vault.Passfile, res.Snapshot.BackendIDs[0], prefix+"/"+removalManifestName)
	if err != nil {
		t.Fatalf("restic dump of the retained removal manifest: %v", err)
	}
	var plan trimPlanDoc
	if err := decodeStrictJSON(raw, &plan); err != nil {
		t.Fatalf("retained removal manifest: %v", err)
	}
	if len(plan.Groups) != 1 || plan.Groups[0].GroupID != "deps" || len(plan.Groups[0].Members) != 7 {
		t.Fatalf("retained plan groups = %+v", plan.Groups)
	}
	for _, in := range plan.Groups[0].RecipeInputs {
		if in.Missing {
			t.Errorf("input %s recorded missing though present", in.Path)
			continue
		}
		got, derr := e.store.DumpFile(ctx, e.vault.RepoDir, e.vault.Passfile, res.Snapshot.BackendIDs[0], prefix+"/"+in.Copy)
		if derr != nil {
			t.Fatalf("restic dump of the retained input copy %s: %v", in.Copy, derr)
		}
		orig := map[string]string{
			"package.json":   fixturePackageJSON,
			"pnpm-lock.yaml": fixtureLock,
		}[in.Path]
		if string(got) != orig {
			t.Errorf("retained input copy %s differs from the original bytes", in.Path)
		}
	}
}

// ---- scenarios 3+4: crash recovery against the real backend, reopen in
// place ---------------------------------------------------------------

// TestE2EResticCrashRecoverAndReopenOriginalPath parks with the context
// canceled mid-removal (after the first authorized entry is gone), then a
// FRESH Coordinator reconciles via Recover and completes the park; the
// parked workspace is then reopened at its ORIGINAL root path (the §5.3
// default-destination behavior — restore takes the destination
// explicitly, so the test passes the manifest's original path, which is
// exactly what the CLI will default to).
func TestE2EResticCrashRecoverAndReopenOriginalPath(t *testing.T) {
	e := newE2EEnv(t)
	parent := t.TempDir()
	root := filepath.Join(parent, "ws-crash")
	writeStdFixture(t, root)
	before := e2eWalkTree(t, root)
	ws := newWSID()

	// Cancel after the removal STARTS: the wrapper counts ProbeFile calls
	// on entries inside the quarantine sibling; the second such call fires
	// with the first entry already removed, so cancel() interrupts the
	// walk mid-flight with authorized entries still on disk.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probed := 0
	canceling := &e2eCancelProbe{PlatformProbe: platform.New()}
	quarPrefix := filepath.Join(parent, quarantinePrefix)
	canceling.onProbeFile = func(path string) {
		if strings.HasPrefix(filepath.Clean(path), quarPrefix) {
			probed++
			if probed == 2 {
				cancel()
			}
		}
	}

	opts := CaptureOptions{
		WorkspaceName:   "ws-crash",
		WorkspaceID:     ws,
		Policy:          policy.Default("ws-crash"),
		Park:            true,
		WriterAssertion: "e2e-acceptance: writers asserted stopped",
	}
	_, err := e.coord(canceling).Park(ctx, e.vault, root, opts)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted park must surface context.Canceled, got %v", err)
	}

	// Partial state: root renamed away, quarantine present and still
	// holding authorized entries, op REMOVING (the last durable phase —
	// §17.5 exit-130 semantics), P/S retained and pinned.
	cat := e.newCat()
	active, err := cat.ActiveOperations(ws)
	if err != nil || len(active) != 1 {
		t.Fatalf("expected exactly one active operation after the crash, got %d (%v)", len(active), err)
	}
	opID := active[0].ID
	if active[0].Phase != catalog.PhaseRemoving {
		t.Errorf("crashed op phase = %q, want REMOVING", active[0].Phase)
	}
	mustLstatErrNotExist(t, root)
	quar := quarantinePath(parent, opID)
	mustExist(t, quar)
	if left := e2eWalkTree(t, quar); len(left) == 0 {
		t.Error("quarantine is empty; the crash must interrupt BEFORE full removal")
	}
	recs, jerr := readJournal(parent, opID)
	if jerr != nil {
		t.Logf("progress journal unreadable (%v); catalog phases remain authoritative", jerr)
	}
	if _, removedCount := lastRemoved(recs); removedCount < 1 {
		t.Errorf("progress journal shows %d removals; the removal must have started before the cancel", removedCount)
	}
	snaps, _ := cat.ListSnapshots(ws)
	if len(snaps) != 1 || !snaps[0].Pinned {
		t.Fatalf("retained P/S must exist and stay pinned across the crash: %+v", snaps)
	}
	snapID := snaps[0].ID

	// Fresh Coordinator (fresh catalog handle — new-process simulation)
	// reconciles and completes the park to DONE.
	rctx, rcancel := e.opCtx()
	defer rcancel()
	rep, rerr := e.coord(nil).Recover(rctx, e.vault, opID)
	if rerr != nil {
		t.Fatalf("recover through the real backend: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseAfter != catalog.PhaseDone {
		t.Errorf("phase after recover = %q, want DONE", rep.PhaseAfter)
	}
	mustLstatErrNotExist(t, quar)
	if got := e.phaseOf(t, opID); got != catalog.PhaseDone {
		t.Errorf("recovered op phase = %q, want DONE", got)
	}
	fresh := e.newCat()
	w, err := fresh.GetWorkspace(ws)
	if err != nil || w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace after recovery = %+v (%v), want parked", w, err)
	}
	e2eNoScratch(t, parent, "recovered parent")

	// Reopen at the ORIGINAL root path (absent since the park): the §5.3
	// default destination. Every preserved byte returns, the workspace is
	// live again at the original path, and the snapshot stays pinned.
	octx, ocancel := e.opCtx()
	defer ocancel()
	res, oerr := e.opener().Open(octx, e.rvault(), snapID, restore.Options{
		Destination: root, FilesOnly: true,
	})
	if oerr != nil {
		t.Fatalf("reopen at the original path through the real backend: %v", oerr)
	}
	if res.Destination != root {
		t.Errorf("result destination = %q, want the original root %q", res.Destination, root)
	}
	e2eSameTree(t, before, e2eWalkTree(t, root))
	final := e.newCat()
	op, err := final.GetOperation(res.OperationID)
	if err != nil || op.Phase != catalog.PhaseFilesReady {
		t.Errorf("reopen op phase: %v %q, want FILES_READY", err, op.Phase)
	}
	w2, err := final.GetWorkspace(ws)
	if err != nil || w2.Status != catalog.WorkspaceLive || w2.RootPath != filepath.Clean(root) {
		t.Errorf("workspace after reopen = %+v (%v), want live at the original root", w2, err)
	}
	ident, err := e.probe.RootIdentity(root)
	if err != nil {
		t.Fatalf("probe identity of reopened root: %v", err)
	}
	if w2.RootIdentity != ident.String() {
		t.Errorf("workspace identity %q is not the freshly probed identity %q (I13 re-bind)", w2.RootIdentity, ident.String())
	}
	if snap, serr := final.GetSnapshot(snapID); serr != nil || !snap.Pinned {
		t.Errorf("snapshot must remain pinned after reopening in place: %+v (%v)", snap, serr)
	}
}
