package capsule

// e2e_import_reSTORic_test.go — the import half of the product-level
// acceptance suite (Foundation §15.3, the D013-precedent discipline:
// prove the protocol against the REAL restic 0.19.1 binary, no
// fault-injection doubles). Every scenario starts from a real capture
// (the shared e2e_reSTORic_test.go world) and a real Export, then
// exercises Import against a SECOND fresh restic vault:
//
//	1. the flagship round trip: capture → export → import into a fresh
//	   vault → result facts equal the ORIGINAL capture's (logical ids,
//	   digests, kind) → the product's own verification path
//	   (restore.LoadRetainedEvidence over a hand-built catalog row with
//	   the D017 witness cross-check) accepts it → a full open through
//	   internal/restore's Opener publishes the imported snapshot into a
//	   fresh directory, compared against an INDEPENDENT test-side walker
//	   oracle over the original workspace files (E10);
//	2. a wrong capsule passphrase refuses with *ErrCapsuleUnlock and
//	   never touches the destination vault;
//	3. a container tampered AFTER export (byte flip inside a repo/
//	   entry's stored payload, and truncation) refuses at the §15.3
//	   container gate with *ErrNotACapsule, destination untouched;
//	4. the CLI-owned duplicate gate: Known → (true, nil) returns
//	   AlreadyKnown with ZERO destination-vault calls; Known → error
//	   (same id, different digest) refuses with zero mutations;
//	5. restic's silent copy skips (probe C10 family) against the REAL
//	   binary: Store.Copy of a nonexistent id is the TYPED form (the
//	   binary exits 0 with an Ignoring line; the adapter converts it),
//	   while the already-copied skip — a second copy of a snapshot whose
//	   original id exists in the destination — produces NO Ignoring line
//	   and is caught ONLY by the import's List-diff discovery, which
//	   refuses with *ErrCopyIntegrity (reproduced end to end by
//	   importing the same capsule twice without the duplicate gate).
//
// KNOWN FINDING this suite pinned (now FIXED in this branch): the
// flagship's "product verification path" and "full open" subtests
// failed because the import's local seal recorded the IMPORT's
// operation id while every lifecycle-shaped receipt consumer
// (restore's loadSeal→loadDocuments, discovery's requireOpDir) derives
// the payload's frozen .ebb-op-<32hex> dir from the RECEIPT's operation
// id — which belongs to the original capture, not to the import. The
// subtests assert the §15.3 contract as specified (unmodified) and
// pass since writeImportSeal derives the seal's dir name, operation_id
// field and ebb-op tag from the CAPTURE's op id (ev.OpDirName).
//
// Skips with a reason when restic is not usable (EBB_TEST_RESTIC_BIN
// overrides the lookup target — the shared e2eBin seam).

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/platform"
	"ebb/internal/restore"
)

// ---- second-vault harness ----------------------------------------------

// e2eDestVault is a second, FRESH restic vault initialized through the
// real store exactly the way the CLI's `ebb init` would (Init + RepoID
// resolution) — the import destination.
type e2eDestVault struct {
	repoDir  string
	passfile string
	repoID   string
}

func newE2EDestVault(t *testing.T, store Store) *e2eDestVault {
	t.Helper()
	base := t.TempDir()
	d := &e2eDestVault{
		repoDir:  filepath.Join(base, "vault"),
		passfile: filepath.Join(base, "vault.pass"),
	}
	if err := os.WriteFile(d.passfile, []byte("capsule-e2e-dest-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Init(ctx, d.repoDir, d.passfile); err != nil {
		t.Fatalf("restic init destination vault: %v", err)
	}
	repoID, err := store.RepoID(ctx, d.repoDir, d.passfile)
	if err != nil {
		t.Fatalf("destination vault repo id: %v", err)
	}
	d.repoID = repoID
	return d
}

// vault is the restore-package spelling of the destination vault.
func (d *e2eDestVault) vault() restore.VaultRef {
	return restore.VaultRef{RepoDir: d.repoDir, Passfile: d.passfile}
}

// importCapsule drives one real Import of capsulePath into the second
// vault through the world's real store (a mut may swap the Store seam
// for an observing wrapper or bend single params).
func (w *e2eWorld) importCapsule(t *testing.T, dest *e2eDestVault, capsulePath, passphrase string, mut func(*ImportParams)) (ImportResult, error) {
	w.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	params := ImportParams{
		Store:        w.store,
		CapsulePath:  capsulePath,
		Passphrase:   passphrase,
		DestRepoDir:  dest.repoDir,
		DestPassfile: dest.passfile,
		DestRepoID:   dest.repoID,
		OperationID:  newImportOpID(t),
		EbbVersion:   "e2e-test",
		Progress:     os.Stderr,
	}
	if mut != nil {
		mut(&params)
	}
	t0 := time.Now()
	res, err := Import(ctx, params)
	w.t.Logf("import %s of %s finished in %s (err=%v)",
		params.OperationID, filepath.Base(capsulePath), time.Since(t0).Round(time.Millisecond), err)
	return res, err
}

// e2eVaultListing is a canonical, order-independent snapshot of one
// vault's backend state: one "id k=v,..." line per snapshot (tags
// sorted), the whole list sorted. Identical listings before and after a
// refused operation prove the vault was not mutated — the List-diff
// discipline the product itself uses (D015: exit codes prove nothing).
func e2eVaultListing(t *testing.T, store Store, repoDir, passfile string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	refs, err := store.List(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("list vault %s: %v", repoDir, err)
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		keys := make([]string, 0, len(r.Tags))
		for k := range r.Tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString(r.BackendID)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%s", k, r.Tags[k])
		}
		out = append(out, b.String())
	}
	sort.Strings(out)
	return out
}

// e2eAssertNoImportScratch asserts no .ebb-import-* working directory
// remains beside the destination repository (the owned-artifact
// contract: removed on every return).
func e2eAssertNoImportScratch(t *testing.T, destRepoDir string) {
	t.Helper()
	des, err := os.ReadDir(filepath.Dir(destRepoDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-import-") {
			t.Errorf("import scratch dir %s left behind beside %s", d.Name(), destRepoDir)
		}
	}
}

// ---- an observing wrapper around the real store -------------------------

// e2eWrappedStore wraps the real restic store for observation: it counts
// every call that touches the DESTINATION vault (the duplicate gate must
// make zero such calls — the count is the proof, the List comparison the
// confirmation). The capsule.Store interface is embedded so every seam
// stays delegated, and DumpTreeTar is re-exposed explicitly so the D019
// tar fast path survives wrapping (the Wave H decorator lesson: a
// wrapper that hides TreeTarDumper silently falls back to per-file
// readback).
type e2eWrappedStore struct {
	Store
	dest     string
	destHits int
}

func (s *e2eWrappedStore) note(repoDir string) {
	if repoDir == s.dest {
		s.destHits++
	}
}

func (s *e2eWrappedStore) Init(ctx context.Context, dir string, passfile string) error {
	s.note(dir)
	return s.Store.Init(ctx, dir, passfile)
}

func (s *e2eWrappedStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	s.note(repoDir)
	return s.Store.RepoID(ctx, repoDir, passfile)
}

func (s *e2eWrappedStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	s.note(repoDir)
	return s.Store.Snapshot(ctx, repoDir, baseDir, relPaths, passfile, tags)
}

func (s *e2eWrappedStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	s.note(repoDir)
	return s.Store.List(ctx, repoDir, passfile)
}

func (s *e2eWrappedStore) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	s.note(repoDir)
	return s.Store.Ls(ctx, repoDir, passfile, snapID)
}

func (s *e2eWrappedStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	s.note(repoDir)
	return s.Store.DumpFile(ctx, repoDir, passfile, snapID, path)
}

func (s *e2eWrappedStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	s.note(repoDir)
	return s.Store.Restore(ctx, repoDir, passfile, snapID, subtree, dest)
}

func (s *e2eWrappedStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	s.note(repoDir)
	return s.Store.Forget(ctx, repoDir, passfile, snapIDs)
}

func (s *e2eWrappedStore) Copy(ctx context.Context, srcRepoDir, srcPassfile, dstRepoDir, dstPassfile string, snapIDs []string) error {
	s.note(dstRepoDir)
	return s.Store.Copy(ctx, srcRepoDir, srcPassfile, dstRepoDir, dstPassfile, snapIDs)
}

func (s *e2eWrappedStore) DumpTreeTar(ctx context.Context, repoDir, passfile, snapID, treePath string) (io.ReadCloser, error) {
	s.note(repoDir)
	dumper, ok := s.Store.(domain.TreeTarDumper)
	if !ok {
		return nil, fmt.Errorf("e2e: wrapped store does not implement domain.TreeTarDumper")
	}
	return dumper.DumpTreeTar(ctx, repoDir, passfile, snapID, treePath)
}

// ---- independent test-side walker oracle (E10) ---------------------------

// e2eImpNode is one observed object of the TEST's own tree walk — an
// oracle deliberately independent of the scanner under test (never reuse
// inventory.Scan or ebb's loaded evidence as the expectation for both
// sides of a comparison). The capsule fixture carries no links; an
// unmodeled object is a wiring error, not a pass.
type e2eImpNode struct {
	IsDir  bool
	Size   int64
	Digest string // sha256 over the exact bytes (regular files)
}

// e2eImpWalk walks root without following links and maps every
// slash-relative path to its observed node. All handles are closed
// before anything else runs (a leaked handle would block later
// renames/removals on Windows).
func e2eImpWalk(t *testing.T, root string) map[string]e2eImpNode {
	t.Helper()
	out := map[string]e2eImpNode{}
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
			f.Close() // first: never leak onto the fixture
			if cerr != nil {
				return cerr
			}
			out[rel] = e2eImpNode{Size: fi.Size(), Digest: hex.EncodeToString(h.Sum(nil))}
		case fi.IsDir():
			out[rel] = e2eImpNode{IsDir: true}
		default:
			return fmt.Errorf("e2e import walk: unmodeled object %s (%s)", rel, fi.Mode())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("e2e import walk %s: %v", root, err)
	}
	return out
}

// e2eImpSameTree asserts two walks describe exactly the same tree (both
// directions, with per-path diagnostics).
func e2eImpSameTree(t *testing.T, want, got map[string]e2eImpNode) {
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
		t.Errorf("entries missing from the opened tree: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("entries appearing unexpectedly in the opened tree: %v", extra)
	}
	if len(changed) > 0 {
		t.Errorf("entries differing:\n\t%s", strings.Join(changed, "\n\t"))
	}
}

// ---- scenario 1: the flagship round trip --------------------------------

// TestE2EResticExportImportRoundTrip is THE import acceptance: a real
// workspace captured into vault A, exported to a real capsule, IMPORTED
// into a second fresh vault, and then verified the way the product
// would — the evidence loader `ebb verify` drives, and a full `ebb
// open`-shaped publish into a fresh directory compared against an
// independent walker oracle over the original workspace files.
func TestE2EResticExportImportRoundTrip(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "roundtrip.ebb")
	exp, err := w.export(out, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	// The independent oracle: walked from the ORIGINAL workspace files
	// (which capture leaves in place), never from ebb's own inventory.
	wantTree := e2eImpWalk(t, w.wsRoot)

	dest := newE2EDestVault(t, w.store)
	seed := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)

	var phases []string
	imp, err := w.importCapsule(t, dest, out, exp.Passphrase, func(p *ImportParams) {
		p.Phase = func(step string) error {
			phases = append(phases, step)
			return nil
		}
	})
	if err != nil {
		t.Fatalf("import into the second vault: %v", err)
	}

	t.Run("result facts match the original capture", func(t *testing.T) {
		if imp.AlreadyKnown {
			t.Error("AlreadyKnown = true on a fresh import")
		}
		if imp.LogicalSnapshotID != w.snap.ID {
			t.Errorf("LogicalSnapshotID = %s, want the original capture's %s", imp.LogicalSnapshotID, w.snap.ID)
		}
		if imp.WorkspaceID != w.snap.WorkspaceID {
			t.Errorf("WorkspaceID = %s, want %s", imp.WorkspaceID, w.snap.WorkspaceID)
		}
		if imp.Kind != w.snap.Kind {
			t.Errorf("Kind = %q, want the original capture's %q", imp.Kind, w.snap.Kind)
		}
		if imp.ManifestDigest != w.ev.Manifest.ManifestDigest || imp.InventoryDigest != w.ev.Manifest.InventoryDigest {
			t.Errorf("digests = %s/%s, want the ORIGINAL capture's %s/%s",
				imp.ManifestDigest, imp.InventoryDigest, w.ev.Manifest.ManifestDigest, w.ev.Manifest.InventoryDigest)
		}
		if imp.CreatedAt != w.ev.Manifest.CreatedAt {
			t.Errorf("CreatedAt = %q, want the manifest's %q", imp.CreatedAt, w.ev.Manifest.CreatedAt)
		}
		if imp.WorkspaceName != w.ev.WsPrefix {
			t.Errorf("WorkspaceName = %q, want the main-root backend prefix %q", imp.WorkspaceName, w.ev.WsPrefix)
		}
		if imp.CapsuleRepoID != exp.DestinationRepoID {
			t.Errorf("CapsuleRepoID = %s, want the capsule repository's %s", imp.CapsuleRepoID, exp.DestinationRepoID)
		}
		if imp.DestinationPayload == "" || imp.DestinationSeal == "" {
			t.Fatalf("destination identities incomplete: %+v", imp)
		}
		if imp.PreservedEntries != w.ev.PreservedEntries || imp.PreservedBytes != w.ev.PreservedBytes {
			t.Errorf("preserved = %d entries / %d bytes, want the capsule evidence's %d / %d",
				imp.PreservedEntries, imp.PreservedBytes, w.ev.PreservedEntries, w.ev.PreservedBytes)
		}
		check, cerr := verifyPackage(out)
		if cerr != nil {
			t.Fatalf("verifyPackage on the pristine capsule: %v", cerr)
		}
		if imp.RepoBytes != check.ExportDoc.RepoBytes {
			t.Errorf("RepoBytes = %d, want the container-declared %d", imp.RepoBytes, check.ExportDoc.RepoBytes)
		}
		want := []string{PhaseExtracting, PhaseCopying, PhaseVerifying}
		if strings.Join(phases, ",") != strings.Join(want, ",") {
			t.Errorf("phase steps = %v, want %v", phases, want)
		}
	})

	t.Run("destination vault state", func(t *testing.T) {
		refs := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)
		if len(refs) != len(seed)+2 {
			t.Fatalf("destination holds %d snapshots, want seed + payload + seal (%d): %v", len(refs), len(seed)+2, refs)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		all, err := w.store.List(ctx, dest.repoDir, dest.passfile)
		if err != nil {
			t.Fatal(err)
		}
		var payloadTags, sealTags map[string]string
		for _, r := range all {
			switch r.BackendID {
			case imp.DestinationPayload:
				payloadTags = r.Tags
			case imp.DestinationSeal:
				sealTags = r.Tags
			}
		}
		if payloadTags["ebb-kind"] != "payload" {
			t.Errorf("destination payload tags = %v, want ebb-kind=payload", payloadTags)
		}
		// The local seal records the CAPTURE's operation id (the payload's
		// frozen op dir id), not the import's transport op id — the I13
		// dir==receipt rule every lifecycle consumer applies.
		wantOpTag := strings.TrimPrefix(w.ev.OpDirName, ".ebb-op-")
		if sealTags["ebb-kind"] != "seal" || sealTags["ebb-op"] != wantOpTag || sealTags["ws"] != string(imp.WorkspaceID) {
			t.Errorf("destination seal tags = %v, want ebb-kind=seal ebb-op=%s ws=%s", sealTags, wantOpTag, imp.WorkspaceID)
		}
		if imp.DestinationPayload == exp.DestinationPayload {
			t.Logf("NOTE: the destination payload id equals the capsule-internal id (ids CAN survive cross-repository copy; discovery did not rely on it)")
		}
		e2eAssertNoImportScratch(t, dest.repoDir)
	})

	t.Run("content readable from the destination vault against the oracle", func(t *testing.T) {
		// The payload itself is complete and openable in the destination
		// vault regardless of the seal: every oracle file dumps through
		// the backend and hashes to the independently walked digest.
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		for rel, node := range wantTree {
			if node.IsDir {
				continue
			}
			raw, derr := w.store.DumpFile(ctx, dest.repoDir, dest.passfile,
				imp.DestinationPayload, "/"+imp.WorkspaceName+"/"+rel)
			if derr != nil {
				t.Fatalf("dump %s from the destination vault: %v", rel, derr)
			}
			if got := digestOf(raw); got != node.Digest {
				t.Errorf("destination content %s digest %s != oracle %s", rel, got, node.Digest)
			}
		}
		// The empty dir and the nesting survived as tree nodes.
		ls, lerr := w.store.Ls(ctx, dest.repoDir, dest.passfile, imp.DestinationPayload)
		if lerr != nil {
			t.Fatal(lerr)
		}
		nodes := map[string]domain.TreeEntry{}
		for _, e := range ls {
			nodes[e.Path] = e
		}
		if e, ok := nodes["/"+imp.WorkspaceName+"/emptydir"]; !ok || e.Kind != domain.KindDir {
			t.Errorf("emptydir node in the destination payload = %+v (present=%v), want a dir node", e, ok)
		}
		if e, ok := nodes["/"+imp.WorkspaceName+"/src/deep/main.go"]; !ok || e.Kind != domain.KindFile {
			t.Errorf("nested file node in the destination payload = %+v (present=%v)", e, ok)
		}
	})

	t.Run("product verification path accepts it", func(t *testing.T) {
		// The hand-built catalog row is exactly what the future `ebb
		// import` CLI will register (payload/seal ids from the result,
		// digests from the result); LoadRetainedEvidence then runs the
		// FULL §12.5 steps 2-3 chain — seal validation INCLUDING the
		// catalog-row digest witness cross-check (D017) and payload
		// document readback. This is the proof that `ebb verify` (and
		// open's step 2-3) will accept the imported snapshot.
		row := catalog.Snapshot{
			ID:               imp.LogicalSnapshotID,
			WorkspaceID:      imp.WorkspaceID,
			PayloadBackendID: imp.DestinationPayload,
			SealBackendID:    imp.DestinationSeal,
			ManifestDigest:   imp.ManifestDigest,
			InventoryDigest:  imp.InventoryDigest,
			Kind:             imp.Kind,
			CreatedAt:        imp.CreatedAt,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		ev2, err := restore.LoadRetainedEvidence(ctx, w.store, dest.vault(), imp.LogicalSnapshotID, row)
		if err != nil {
			t.Fatalf("LoadRetainedEvidence over the imported pair (the ebb verify path): %v", err)
		}
		if ev2.Manifest.ManifestDigest != w.ev.Manifest.ManifestDigest ||
			ev2.Manifest.InventoryDigest != w.ev.Manifest.InventoryDigest {
			t.Errorf("re-loaded digests = %s/%s, want the original capture's %s/%s",
				ev2.Manifest.ManifestDigest, ev2.Manifest.InventoryDigest,
				w.ev.Manifest.ManifestDigest, w.ev.Manifest.InventoryDigest)
		}
		if ev2.PreservedEntries != w.ev.PreservedEntries {
			t.Errorf("re-loaded preserved entries = %d, want %d", ev2.PreservedEntries, w.ev.PreservedEntries)
		}
	})

	t.Run("full open into a fresh destination", func(t *testing.T) {
		// Register the import the way the CLI would (catalog's import
		// vocabulary — vault row + ImportDiscoveredSnapshot), then drive
		// restore's Opener end to end and compare the published tree
		// against the independent walker oracle over the ORIGINAL
		// workspace files (E10: the oracle never derives from ebb's
		// inventory).
		base := t.TempDir()
		catPath := filepath.Join(base, "dest-catalog.db")
		cat, err := catalog.Open(catPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cat.Close() })
		vaultID := domain.VaultID(domain.NewID())
		if err := cat.RegisterVault(catalog.Vault{ID: vaultID, Path: dest.repoDir, RepoID: dest.repoID}); err != nil {
			t.Fatalf("register destination vault row: %v", err)
		}
		if err := cat.ImportDiscoveredSnapshot(imp.WorkspaceID, imp.WorkspaceName, catalog.Snapshot{
			ID:               imp.LogicalSnapshotID,
			WorkspaceID:      imp.WorkspaceID,
			CreatedAt:        imp.CreatedAt,
			PayloadBackendID: imp.DestinationPayload,
			SealBackendID:    imp.DestinationSeal,
			VaultID:          vaultID,
			ManifestDigest:   imp.ManifestDigest,
			InventoryDigest:  imp.InventoryDigest,
			Kind:             imp.Kind,
		}); err != nil {
			t.Fatalf("register the imported snapshot: %v", err)
		}
		opener, err := restore.New(restore.Dependencies{
			Store: w.store, Cat: cat, Probe: platform.New(), CreateLink: platform.CreateLink,
		})
		if err != nil {
			t.Fatal(err)
		}
		openDest := filepath.Join(t.TempDir(), "ws-imported-restored")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		ores, oerr := opener.Open(ctx, dest.vault(), imp.LogicalSnapshotID, restore.Options{
			Destination: openDest, FilesOnly: true,
		})
		if oerr != nil {
			t.Fatalf("open of the imported snapshot through the real backend: %v", oerr)
		}
		e2eImpSameTree(t, wantTree, e2eImpWalk(t, openDest))
		if ores.EntriesRestored != imp.PreservedEntries || ores.BytesRestored != imp.PreservedBytes {
			t.Errorf("restored = %d entries / %d bytes, want the import's %d / %d",
				ores.EntriesRestored, ores.BytesRestored, imp.PreservedEntries, imp.PreservedBytes)
		}
		if ores.WorkspaceID != imp.WorkspaceID || ores.SnapshotID != imp.LogicalSnapshotID {
			t.Errorf("open result identity fields wrong: %+v", ores)
		}
	})
}

// ---- scenario 2: wrong capsule passphrase --------------------------------

// TestE2EResticImportWrongPassphrase: the recovery secret is the only
// key; a wrong one fails at the REAL backend's auth gate, is re-typed
// to name the capsule file, and the destination vault is never touched
// (identical List before/after) — no registration is possible.
func TestE2EResticImportWrongPassphrase(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "wrongpass.ebb")
	exp, err := w.export(out, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dest := newE2EDestVault(t, w.store)
	before := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)
	capsuleBefore, _ := os.ReadFile(out)

	_, err = w.importCapsule(t, dest, out, "not-the-recovery-secret", nil)
	var unlock *ErrCapsuleUnlock
	if !errors.As(err, &unlock) {
		t.Fatalf("err = %v, want *ErrCapsuleUnlock", err)
	}
	if unlock.Path != out {
		t.Errorf("unlock error names %q, want the capsule path %q", unlock.Path, out)
	}
	var se *domain.StoreError
	if !errors.As(err, &se) || se.Class != domain.StoreErrAuth {
		t.Errorf("underlying error class = %v, want the real backend's auth failure (store auth)", err)
	}

	after := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)
	if strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Errorf("destination vault mutated by a refused import:\n\tbefore: %v\n\tafter:  %v", before, after)
	}
	capsuleAfter, _ := os.ReadFile(out)
	if !bytes.Equal(capsuleBefore, capsuleAfter) {
		t.Error("the capsule file was modified by the refused import")
	}
	e2eAssertNoImportScratch(t, dest.repoDir)

	// Positive control: the very same capsule and destination import
	// cleanly with the CORRECT secret — the refusal above was the wrong
	// passphrase, not a broken capsule.
	res, err := w.importCapsule(t, dest, out, exp.Passphrase, nil)
	if err != nil {
		t.Fatalf("positive control import with the correct secret: %v", err)
	}
	if res.AlreadyKnown || res.DestinationPayload == "" {
		t.Errorf("positive control result incomplete: %+v", res)
	}
	if got := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile); len(got) != len(before)+2 {
		t.Errorf("destination holds %d snapshots after the control import, want %d (seed + payload + seal)", len(got), len(before)+2)
	}
}

// ---- scenario 3: container tampered after export --------------------------

// e2eFlipStoredRepoByte flips one byte inside a repo/ entry's PAYLOAD
// region of the capsule: STORED entries appear verbatim in the file, so
// the entry's own leading bytes locate its data offset; flipping a byte
// there breaks the entry's CRC32, which the container gate reads to
// EOF (verifyPackage) — the structural §15.1/§15.3 refusal, not a
// restic-level one.
func e2eFlipStoredRepoByte(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatalf("reopen capsule for tampering: %v", err)
	}
	var probe []byte
	var name string
	for _, zf := range zr.File {
		if !strings.HasPrefix(zf.Name, "repo/") || zf.UncompressedSize64 < 256 {
			continue
		}
		rc, oerr := zf.Open()
		if oerr != nil {
			t.Fatal(oerr)
		}
		probe = make([]byte, 32)
		if _, rerr := io.ReadFull(rc, probe); rerr != nil {
			t.Fatal(rerr)
		}
		rc.Close()
		name = zf.Name
		break
	}
	if probe == nil {
		t.Fatal("no repo/ entry large enough to tamper")
	}
	off := bytes.Index(raw, probe)
	if off < 0 {
		t.Fatal("STORED entry data not found verbatim in the container")
	}
	raw[off+16] ^= 0xFF
	if werr := os.WriteFile(path, raw, 0o600); werr != nil {
		t.Fatal(werr)
	}
	t.Logf("tampered: flipped one byte at file offset %d inside %s's stored payload", off+16, name)
}

// TestE2EResticImportTamperedContainer: a capsule corrupted AFTER export
// refuses at the container gate (ErrNotACapsule) with the destination
// vault untouched. Two tamper forms, both asserted at the same typed
// class: a byte flip inside a repo/ entry's stored payload (breaks the
// CRC/length gate — the documented form this tamper produces) and a
// truncation (breaks central-directory readability).
func TestE2EResticImportTamperedContainer(t *testing.T) {
	w := newE2EWorld(t)
	pristine := filepath.Join(w.outDir, "tamper-source.ebb")
	exp, err := w.export(pristine, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dest := newE2EDestVault(t, w.store)
	before := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)

	t.Run("byte flipped inside a stored repo entry", func(t *testing.T) {
		tampered := filepath.Join(t.TempDir(), "flipped.ebb")
		base, _ := os.ReadFile(pristine)
		if err := os.WriteFile(tampered, base, 0o600); err != nil {
			t.Fatal(err)
		}
		e2eFlipStoredRepoByte(t, tampered)

		_, err := w.importCapsule(t, dest, tampered, exp.Passphrase, nil)
		var na *ErrNotACapsule
		if !errors.As(err, &na) {
			t.Fatalf("err = %v, want *ErrNotACapsule", err)
		}
		if !strings.Contains(strings.Join(na.Details, "; "), "CRC/length gate") {
			t.Errorf("refusal details = %v, want the CRC/length gate (this tamper breaks the entry checksum)", na.Details)
		}
		if after := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile); strings.Join(after, "\n") != strings.Join(before, "\n") {
			t.Errorf("destination vault mutated:\n\tbefore: %v\n\tafter:  %v", before, after)
		}
		e2eAssertNoImportScratch(t, dest.repoDir)
	})

	t.Run("truncated container", func(t *testing.T) {
		base, _ := os.ReadFile(pristine)
		tampered := filepath.Join(t.TempDir(), "truncated.ebb")
		if err := os.WriteFile(tampered, base[:len(base)*3/5], 0o600); err != nil {
			t.Fatal(err)
		}

		_, err := w.importCapsule(t, dest, tampered, exp.Passphrase, nil)
		var na *ErrNotACapsule
		if !errors.As(err, &na) {
			t.Fatalf("err = %v, want *ErrNotACapsule", err)
		}
		if after := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile); strings.Join(after, "\n") != strings.Join(before, "\n") {
			t.Errorf("destination vault mutated:\n\tbefore: %v\n\tafter:  %v", before, after)
		}
		e2eAssertNoImportScratch(t, dest.repoDir)
	})
}

// ---- scenario 4: the CLI-owned duplicate gate -----------------------------

// TestE2EResticImportDuplicateGate: importing the same capsule twice
// into the same vault. With Known returning (true, nil) the second time
// (already registered with THIS manifest digest), the import returns
// AlreadyKnown having made ZERO destination-vault calls (counted through
// an observing wrapper around the real store, and confirmed by
// List-compare); with Known returning an error (the same-id-different-
// digest shape), the import refuses having mutated nothing.
func TestE2EResticImportDuplicateGate(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "dupe.ebb")
	exp, err := w.export(out, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dest := newE2EDestVault(t, w.store)

	// First import: a real, complete registration.
	first, err := w.importCapsule(t, dest, out, exp.Passphrase, func(p *ImportParams) {
		p.Known = func(snapshotID, manifestDigest string) (bool, error) {
			return false, nil
		}
	})
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if first.AlreadyKnown {
		t.Fatal("first import reported AlreadyKnown")
	}
	stateAfterFirst := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)

	t.Run("already known makes no destination-vault calls", func(t *testing.T) {
		wrapped := &e2eWrappedStore{Store: w.store, dest: dest.repoDir}
		second, err := w.importCapsule(t, dest, out, exp.Passphrase, func(p *ImportParams) {
			p.Store = wrapped
			p.Known = func(snapshotID, manifestDigest string) (bool, error) {
				if snapshotID != string(first.LogicalSnapshotID) || manifestDigest != first.ManifestDigest {
					t.Errorf("Known args = %s/%s, want %s/%s", snapshotID, manifestDigest, first.LogicalSnapshotID, first.ManifestDigest)
				}
				return true, nil
			}
		})
		if err != nil {
			t.Fatalf("second import: %v", err)
		}
		if !second.AlreadyKnown {
			t.Fatal("AlreadyKnown = false despite the Known gate's hit")
		}
		if second.DestinationPayload != "" || second.DestinationSeal != "" {
			t.Errorf("destination ids = %s/%s, want none (no mutation)", second.DestinationPayload, second.DestinationSeal)
		}
		if second.LogicalSnapshotID != first.LogicalSnapshotID || second.ManifestDigest != first.ManifestDigest {
			t.Errorf("AlreadyKnown facts not filled: %+v", second)
		}
		if wrapped.destHits != 0 {
			t.Errorf("the already-known import made %d destination-vault call(s); the gate must fire before ANY vault mutation", wrapped.destHits)
		}
		if got := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile); strings.Join(got, "\n") != strings.Join(stateAfterFirst, "\n") {
			t.Errorf("destination vault mutated by an already-known import:\n\tbefore: %v\n\tafter:  %v", stateAfterFirst, got)
		}
		e2eAssertNoImportScratch(t, dest.repoDir)
	})

	t.Run("gate error refuses with zero mutations", func(t *testing.T) {
		wrapped := &e2eWrappedStore{Store: w.store, dest: dest.repoDir}
		gateErr := errors.New("catalog: snapshot registered with a different manifest digest (same id, different digest)")
		_, err := w.importCapsule(t, dest, out, exp.Passphrase, func(p *ImportParams) {
			p.Store = wrapped
			p.Known = func(snapshotID, manifestDigest string) (bool, error) {
				// The same-id-different-digest shape: the catalog knows
				// this snapshot under another manifest digest.
				return false, gateErr
			}
		})
		if err == nil || !strings.Contains(err.Error(), "duplicate gate refused") {
			t.Fatalf("err = %v, want the duplicate-gate refusal", err)
		}
		if !errors.Is(err, gateErr) {
			t.Errorf("the gate's own error must surface wrapped, not swallowed: %v", err)
		}
		if wrapped.destHits != 0 {
			t.Errorf("the refused import made %d destination-vault call(s)", wrapped.destHits)
		}
		if got := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile); strings.Join(got, "\n") != strings.Join(stateAfterFirst, "\n") {
			t.Errorf("destination vault mutated by the refused import:\n\tbefore: %v\n\tafter:  %v", stateAfterFirst, got)
		}
		e2eAssertNoImportScratch(t, dest.repoDir)
	})
}

// ---- scenario 5: restic's silent copy skip against the real binary --------

// TestE2EResticImportSilentSkipIntegrity pins restic 0.19.1's silent
// copy skips LIVE (probe C10 family) and proves the two client-side
// gates that answer them. Restic 0.19.1 has TWO forms:
//
//	(a) a nonexistent source id: `restic copy` exits 0 with an
//	    `Ignoring "<id>"` line — the storage adapter converts that line
//	    into a typed source failure, pinned here by calling Store.Copy
//	    directly with a bogus (valid 64-hex) id from the REAL extracted
//	    capsule repository into the REAL destination vault;
//	(b) the already-copied skip (the one NO stderr gate can see): a
//	    second copy of a snapshot whose original id already exists in
//	    the destination is skipped WITHOUT an Ignoring line and still
//	    exits 0 — only the destination listing proves nothing landed.
//	    This is reproduced end to end by importing the SAME capsule a
//	    second time into the SAME vault with no Known gate: every step
//	    real (real extraction, unlock, classification, before/after
//	    listings), the copy silently skips, and discoverCopiedPayload's
//	    zero-new-ids branch refuses with *ErrCopyIntegrity.
func TestE2EResticImportSilentSkipIntegrity(t *testing.T) {
	w := newE2EWorld(t)
	out := filepath.Join(w.outDir, "silentskip.ebb")
	exp, err := w.export(out, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	dest := newE2EDestVault(t, w.store)
	empty := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)

	// The capsule's own repository, extracted exactly the way Import
	// extracts it, unlocked with the real generated passphrase.
	extracted := filepath.Join(t.TempDir(), "repo")
	if err := extractRepository(out, extracted, 1<<62); err != nil {
		t.Fatalf("extract the capsule repository for the direct probe: %v", err)
	}
	capsulePassfile := passfileOf(exp.Passphrase, t)
	bogus := strings.Repeat("de", 32) // valid 64-hex, absent from every repo

	t.Run("adapter gate: nonexistent id is typed, not silent", func(t *testing.T) {
		// The RAW binary exits 0 here (probe C10); the adapter scans for
		// the `Ignoring "` line and surfaces it typed — the error text
		// carries restic's own line verbatim, which is the live pin.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cerr := w.store.Copy(ctx, extracted, capsulePassfile, dest.repoDir, dest.passfile, []string{bogus})
		if cerr == nil {
			t.Fatal("copy of a nonexistent id passed silently through the adapter — the Ignoring gate regressed; re-pin probe C10")
		}
		var se *domain.StoreError
		if !errors.As(cerr, &se) || se.Class != domain.StoreErrSource {
			t.Errorf("copy error class = %v, want the typed source failure (got: %v)", cerr, se)
		}
		if !strings.Contains(cerr.Error(), "Ignoring") || !strings.Contains(cerr.Error(), "nothing was transferred") {
			t.Errorf("copy error %q does not carry restic's Ignoring line / the nothing-transferred conversion", cerr)
		}
		if got := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile); strings.Join(got, "\n") != strings.Join(empty, "\n") {
			t.Fatalf("the skipped copy created something:\n\tbefore: %v\n\tafter:  %v", empty, got)
		}
	})

	// A complete first import (the silent skip is only provable against
	// a destination that already holds the payload's original id).
	if _, err := w.importCapsule(t, dest, out, exp.Passphrase, nil); err != nil {
		t.Fatalf("first import: %v", err)
	}
	afterFirst := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile)

	t.Run("list-diff gate: the already-copied skip refuses with ErrCopyIntegrity", func(t *testing.T) {
		second, err := w.importCapsule(t, dest, out, exp.Passphrase, nil)
		var ci *ErrCopyIntegrity
		if !errors.As(err, &ci) {
			t.Fatalf("err = %v, want *ErrCopyIntegrity (result %+v)", err, second)
		}
		if !strings.Contains(ci.Error(), "no new snapshot") || !strings.Contains(ci.Error(), "skip silently") {
			t.Errorf("error %q does not name the zero-new-ids / silent-skip finding", ci.Error())
		}
		if strings.Contains(err.Error(), "ROLLBACK") {
			t.Errorf("a copy that created nothing must not report rollback activity: %v", err)
		}
		// The destination still holds EXACTLY the first import's pair:
		// no second payload, no second seal.
		if got := e2eVaultListing(t, w.store, dest.repoDir, dest.passfile); strings.Join(got, "\n") != strings.Join(afterFirst, "\n") {
			t.Errorf("destination vault mutated by the silently-skipped import:\n\tbefore: %v\n\tafter:  %v", afterFirst, got)
		}
		if len(afterFirst) != len(empty)+2 {
			t.Fatalf("wiring: first import left %d snapshots, want %d", len(afterFirst), len(empty)+2)
		}
		e2eAssertNoImportScratch(t, dest.repoDir)
	})
}
