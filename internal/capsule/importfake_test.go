package capsule

// importfake_test.go — the default-suite test doubles for §15.3 import:
// a REPO-AWARE fake capsule.Store (per-repository identity + password,
// cross-repository Copy that assigns NEW ids and preserves tags like
// the real backend, probe C2/C3/C10 fault knobs) and a fixture that
// builds a complete fake capsule container — payload snapshot with a
// §16.2 manifest and accounting document, capsule destination seal in
// the seal.go wire form, and a physical restic-shaped repository tree
// packaged by the production writePackage. Everything is written with
// exact-byte writers, never heredocs.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// ---- the fake repository store ------------------------------------------

type fakeSnap struct {
	id    string
	files map[string][]byte
	dirs  map[string]bool
	tags  map[string]string
}

type fakeRepo struct {
	id    string
	pass  string // exact bytes a passfile must contain
	snaps map[string]*fakeSnap
}

type fakeCall struct {
	method string
	repo   string
}

// importFakeStore implements capsule.Store over in-memory snapshots
// scoped per repository directory, mirroring the behaviors import
// depends on: RepoID/List auth-check the passfile's EXACT bytes
// (StoreErrAuth on mismatch), Copy assigns fresh ids and preserves
// tags, and fault knobs model the real backend's silent-skip copy
// (probe C10), dump tampering and forget failures.
type importFakeStore struct {
	mu    sync.Mutex
	repos map[string]*fakeRepo
	next  int

	copyNoOp   bool
	copyErr    error
	forgetErr  error
	dumpTamper map[string]func([]byte) []byte
	// dumpTamperIn scopes a tamper to ONE repository's dumps. The local
	// import seal and the capsule's embedded seal share their tree path
	// BY DESIGN after the capture-op-id fix (.ebb-seal-<capture op
	// id>/receipt.json in both repositories), so a path-only key cannot
	// distinguish them; this map is consulted first.
	dumpTamperIn map[string]map[string]func([]byte) []byte

	calls      []fakeCall
	forgetIDs  [][]string
	copySrcIDs [][]string
}

func newImportFakeStore() *importFakeStore {
	return &importFakeStore{
		repos:      map[string]*fakeRepo{},
		dumpTamper: map[string]func([]byte) []byte{},
	}
}

func (s *importFakeStore) registerRepo(dir, password, repoID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.repos[filepath.Clean(dir)] = &fakeRepo{id: repoID, pass: password, snaps: map[string]*fakeSnap{}}
}

func (s *importFakeStore) log(method, repo string) {
	s.calls = append(s.calls, fakeCall{method: method, repo: filepath.Clean(repo)})
}

func (s *importFakeStore) newID() string {
	s.next++
	sum := sha256.Sum256(fmt.Appendf(nil, "fake-import-snap-%d", s.next))
	return hex.EncodeToString(sum[:])
}

// resolve authenticates one repoDir/passfile pair against the
// registered repositories (exact passfile bytes, like the real
// RESTIC_PASSWORD_FILE contract).
func (s *importFakeStore) resolve(repoDir, passfile string) (*fakeRepo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("resolve", repoDir)
	repo, ok := s.repos[filepath.Clean(repoDir)]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrRepo,
			Err: fmt.Errorf("fake: no repository at %s", repoDir)}
	}
	b, err := os.ReadFile(passfile)
	if err != nil {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage, Err: err}
	}
	if string(b) != repo.pass {
		return nil, &domain.StoreError{Class: domain.StoreErrAuth,
			Err: fmt.Errorf("fake: wrong password for %s", repoDir)}
	}
	return repo, nil
}

func (s *importFakeStore) Init(ctx context.Context, dir, passfile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("init", dir)
	b, err := os.ReadFile(passfile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	s.next++
	s.repos[filepath.Clean(dir)] = &fakeRepo{
		id: fmt.Sprintf("fake-init-repo-%d", s.next), pass: string(b), snaps: map[string]*fakeSnap{}}
	return nil
}

func (s *importFakeStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	repo, err := s.resolve(repoDir, passfile)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.log("repoid", repoDir)
	s.mu.Unlock()
	return repo.id, nil
}

func (s *importFakeStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	repo, err := s.resolve(repoDir, passfile)
	if err != nil {
		return domain.SnapshotRef{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("snapshot", repoDir)
	snap := &fakeSnap{id: s.newID(), files: map[string][]byte{}, dirs: map[string]bool{}, tags: tags}
	for _, rel := range relPaths {
		if err := s.walkInto(snap, baseDir, filepath.ToSlash(rel)); err != nil {
			return domain.SnapshotRef{}, err
		}
	}
	repo.snaps[snap.id] = snap
	return domain.SnapshotRef{
		BackendID: snap.id, ShortID: snap.id[:8], Time: "2026-09-19T00:00:00Z",
		Paths: relPaths, Tags: tags,
	}, nil
}

func (s *importFakeStore) walkInto(snap *fakeSnap, baseDir, rel string) error {
	abs := filepath.Join(baseDir, filepath.FromSlash(rel))
	fi, err := os.Lstat(abs)
	if err != nil {
		return err
	}
	// Parent-dir synthesis: the real backend's tree listing reports a
	// node for every ancestor of a captured file (lifecycle's coverage
	// gate expects them), even when the capture listed exact files only.
	addAncestors := func(p string) {
		for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
			snap.dirs[d] = true
		}
	}
	switch {
	case fi.Mode().IsRegular():
		b, err := os.ReadFile(abs)
		if err != nil {
			return err
		}
		snap.files["/"+rel] = b
		addAncestors("/" + rel)
	case fi.IsDir():
		snap.dirs["/"+rel] = true
		addAncestors("/" + rel)
		des, err := os.ReadDir(abs)
		if err != nil {
			return err
		}
		for _, de := range des {
			if err := s.walkInto(snap, baseDir, rel+"/"+de.Name()); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("fake import store: unsupported object %s (%s)", abs, fi.Mode())
	}
	return nil
}

func (s *importFakeStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	repo, err := s.resolve(repoDir, passfile)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("list", repoDir)
	ids := make([]string, 0, len(repo.snaps))
	for id := range repo.snaps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	refs := make([]domain.SnapshotRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, domain.SnapshotRef{
			BackendID: id, ShortID: id[:8], Time: "2026-09-19T00:00:00Z", Tags: repo.snaps[id].tags})
	}
	return refs, nil
}

func (s *importFakeStore) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	repo, err := s.resolve(repoDir, passfile)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("ls", repoDir)
	snap, ok := repo.snaps[snapID]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage,
			Err: fmt.Errorf("fake: snapshot %q not found", snapID)}
	}
	var out []domain.TreeEntry
	for p := range snap.dirs {
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindDir})
	}
	for p, b := range snap.files {
		out = append(out, domain.TreeEntry{Path: p, Kind: domain.KindFile, Size: int64(len(b))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func (s *importFakeStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	repo, err := s.resolve(repoDir, passfile)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("dump", repoDir)
	snap, ok := repo.snaps[snapID]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage,
			Err: fmt.Errorf("fake: snapshot %q not found", snapID)}
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	b, ok := snap.files[path]
	if !ok {
		return nil, &domain.StoreError{Class: domain.StoreErrUsage,
			Err: fmt.Errorf("fake: %q not found in snapshot %s", path, snapID)}
	}
	if f := s.dumpTamperIn[filepath.Clean(repoDir)][path]; f != nil {
		b = f(b)
	} else if f := s.dumpTamper[path]; f != nil {
		b = f(b)
	}
	return append([]byte(nil), b...), nil
}

func (s *importFakeStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	return fmt.Errorf("fake import store: Restore not implemented")
}

func (s *importFakeStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	repo, err := s.resolve(repoDir, passfile)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("forget", repoDir)
	if s.forgetErr != nil {
		return s.forgetErr
	}
	s.forgetIDs = append(s.forgetIDs, append([]string(nil), snapIDs...))
	for _, id := range snapIDs {
		delete(repo.snaps, id)
	}
	return nil
}

// Copy mirrors restic 0.19.1 cross-repository copy as the probes pinned
// it (D024): ids CHANGE, tags survive, and — with copyNoOp — nothing is
// copied while the call still exits nil (the probe C10 silent skip).
func (s *importFakeStore) Copy(ctx context.Context, srcRepoDir, srcPassfile, dstRepoDir, dstPassfile string, snapIDs []string) error {
	src, err := s.resolve(srcRepoDir, srcPassfile)
	if err != nil {
		return err
	}
	dst, err := s.resolve(dstRepoDir, dstPassfile)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.log("copy-src", srcRepoDir)
	s.log("copy-dst", dstRepoDir)
	if s.copyErr != nil {
		return s.copyErr
	}
	if s.copyNoOp {
		return nil
	}
	s.copySrcIDs = append(s.copySrcIDs, append([]string(nil), snapIDs...))
	for _, id := range snapIDs {
		snap, ok := src.snaps[id]
		if !ok {
			continue // nonexistent ids are skipped SILENTLY (probe C10)
		}
		clone := &fakeSnap{
			id:    s.newID(),
			files: map[string][]byte{},
			dirs:  map[string]bool{},
			tags:  map[string]string{},
		}
		for p, b := range snap.files {
			clone.files[p] = append([]byte(nil), b...)
		}
		for p := range snap.dirs {
			clone.dirs[p] = true
		}
		for k, v := range snap.tags {
			clone.tags[k] = v
		}
		dst.snaps[clone.id] = clone
	}
	return nil
}

// resetCalls drops the call log (fixture setup noise) so tests assert
// only what Import itself did.
func (s *importFakeStore) resetCalls() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = nil
}

// callsOn returns the method names invoked against one repository dir.
func (s *importFakeStore) callsOn(dir string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := filepath.Clean(dir)
	var out []string
	for _, c := range s.calls {
		if c.repo == want {
			out = append(out, c.method)
		}
	}
	return out
}

func (s *importFakeStore) snapIDs(repoDir string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	repo := s.repos[filepath.Clean(repoDir)]
	ids := make([]string, 0, len(repo.snaps))
	for id := range repo.snaps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (s *importFakeStore) snapTags(repoDir, id string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.repos[filepath.Clean(repoDir)].snaps[id].tags
}

func (s *importFakeStore) dumpFrom(repoDir, pass, id, path string) ([]byte, error) {
	return s.DumpFile(context.Background(), repoDir, pass, id, path)
}

// tamperDumpIn installs a byte tamper for ONE dump path in ONE
// repository only (see dumpTamperIn).
func (s *importFakeStore) tamperDumpIn(repoDir, path string, f func([]byte) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dumpTamperIn == nil {
		s.dumpTamperIn = map[string]map[string]func([]byte) []byte{}
	}
	key := filepath.Clean(repoDir)
	if s.dumpTamperIn[key] == nil {
		s.dumpTamperIn[key] = map[string]func([]byte) []byte{}
	}
	s.dumpTamperIn[key][path] = f
}

// ---- the fake capsule fixture -------------------------------------------

const (
	fxCapsulePass = "fx-capsule-recovery-secret"
	fxDestPass    = "fx-destination-vault-secret"
)

// capsuleSpec knobs for the fault/shape cases.
type capsuleSpec struct {
	trim            bool   // trim-kind payload (removal-manifest accounting doc)
	lieManifestDgst bool   // seal declares the digest of DIFFERENT bytes (tampered repo file)
	sealRepoID      string // override the seal's backend_repo_id (wrong-repo mint)
	noSealSnap      bool   // capsule repo without the seal snapshot
	twoPayloads     bool   // second payload snapshot in the capsule repo
	untaggedExtra   bool   // snapshot without an ebb-kind tag in the capsule repo
	wrongWsInSeal   bool   // seal replication block names a different workspace
	noAccountingDoc bool   // payload op dir missing its accounting document
}

// importFixture is one complete fake capsule plus its destination vault.
type importFixture struct {
	t *testing.T

	store          *importFakeStore
	capsulePath    string
	capsuleRepoDir string // the PHYSICAL tree packaged into the container
	extractedDir   string // the workDir/repo path Import will unlock (registered store key)
	impOpID        domain.OperationID
	dstRepoDir     string
	dstPassfile    string
	dstRepoID      string

	expOpID  domain.OperationID // the EXPORT operation that made the capsule
	opDir    string
	wsPrefix string
	snapID   domain.SnapshotID
	wsID     domain.WorkspaceID

	manifestBytes   []byte
	manifestDigest  string
	inventoryBytes  []byte
	inventoryDigest string
	accountingName  string // inventory.jsonl | removal-manifest.json

	payloadID string
	sealID    string
}

func digestOfTest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func buildImportFixture(t *testing.T, impOpID domain.OperationID, spec capsuleSpec) *importFixture {
	t.Helper()
	fx := &importFixture{
		t:              t,
		store:          newImportFakeStore(),
		impOpID:        impOpID,
		dstRepoID:      "fake-dst-repo-1",
		expOpID:        domain.OperationID(domain.NewID()),
		snapID:         domain.SnapshotID(domain.NewID()),
		wsID:           domain.WorkspaceID(domain.NewID()),
		wsPrefix:       "renderer",
		accountingName: "inventory.jsonl",
	}
	if spec.trim {
		fx.accountingName = "removal-manifest.json"
	}
	fx.opDir = ".ebb-op-" + string(fx.expOpID)

	base := t.TempDir()
	fx.capsuleRepoDir = filepath.Join(base, "capsule-repo")
	fx.dstRepoDir = filepath.Join(base, "vault", "repo")
	fx.extractedDir = filepath.Join(
		filepath.Dir(fx.dstRepoDir), ".ebb-import-"+string(impOpID), "repo")
	fx.capsulePath = filepath.Join(base, "project.ebb")
	fx.dstPassfile = filepath.Join(base, "dst.pass")

	// The capsule's physical repository: a restic-shaped regular-file
	// tree (what actually travels in the ZIP; the fake store serves the
	// SNAPSHOTS keyed by the directory Import will extract it to).
	for i := 0; i < 6; i++ {
		h := fmt.Sprintf("%064x", i)
		fxWriteFile(t, filepath.Join(fx.capsuleRepoDir, "data", h[:2], h), []byte(fmt.Sprintf("pack-%d-%s", i, strings.Repeat("p", 40))))
	}
	fxWriteFile(t, filepath.Join(fx.capsuleRepoDir, "config"), []byte("opaque-capsule-config"))
	fxWriteFile(t, filepath.Join(fx.capsuleRepoDir, "keys", "aabbccdd"), []byte("key-material"))

	fx.store.registerRepo(fx.extractedDir, fxCapsulePass, "fake-capsule-repo-1")
	if err := os.MkdirAll(fx.dstRepoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fxWriteFile(t, fx.dstPassfile, []byte(fxDestPass))
	fx.store.registerRepo(fx.dstRepoDir, fxDestPass, fx.dstRepoID)

	// A pre-existing unrelated snapshot in the destination vault (the
	// List diff must survive a non-empty before-set).
	seedBase := filepath.Join(base, "seed")
	fxWriteFile(t, filepath.Join(seedBase, "other", "keep.txt"), []byte("pre-existing vault content\n"))
	ctx := context.Background()
	if _, err := fx.store.Snapshot(ctx, fx.dstRepoDir, seedBase,
		[]string{"other"}, fx.dstPassfile, map[string]string{"note": "pre-existing"}); err != nil {
		t.Fatalf("seed destination snapshot: %v", err)
	}

	// ---- the payload snapshot -----------------------------------------
	stage := filepath.Join(base, "stage")
	wsFiles := map[string][]byte{
		"a.txt":     []byte("alpha content\n"),
		"sub/b.txt": []byte("beta content\n"),
	}
	for rel, content := range wsFiles {
		fxWriteFile(t, filepath.Join(stage, fx.wsPrefix, filepath.FromSlash(rel)), content)
	}

	// The accounting document: full inventory for park/snapshot
	// payloads; a removal-plan manifest for trim (its shape is not
	// parsed on the capsule path — only digest-gated).
	var entries []domain.Entry
	if spec.trim {
		fx.inventoryBytes = []byte(`{"schema_version":1,"operation_id":"` + string(fx.expOpID) + `","groups":[]}` + "\n")
	} else {
		var b strings.Builder
		for _, rel := range []string{"a.txt", "sub/b.txt"} {
			e := domain.Entry{
				Root: domain.RootMain, Path: rel, Kind: domain.KindFile,
				LogicalSize: int64(len(wsFiles[rel])), Digest: digestOfTest(wsFiles[rel]),
				Ownership: domain.OwnershipOwned, Sensitivity: domain.SensitivityOrdinary,
				Route: domain.RoutePreserve,
			}
			entries = append(entries, e)
			line, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(line)
			b.WriteByte('\n')
		}
		fx.inventoryBytes = []byte(b.String())
	}
	fx.inventoryDigest = digestOfTest(fx.inventoryBytes)

	fx.manifestBytes = fxBuildManifest(t, fx, spec, entries)
	fx.manifestDigest = digestOfTest(fx.manifestBytes)

	fxWriteFile(t, filepath.Join(stage, fx.opDir, "manifest.json"), fx.manifestBytes)
	if !spec.noAccountingDoc {
		fxWriteFile(t, filepath.Join(stage, fx.opDir, fx.accountingName), fx.inventoryBytes)
	}
	fxWriteFile(t, filepath.Join(stage, fx.opDir, "policy.toml"), []byte("# frozen policy fixture\n"))

	var err error
	fx.payloadID, err = fx.snapshotStage(ctx, stage, []string{fx.opDir, fx.wsPrefix},
		map[string]string{"ebb-op": string(fx.expOpID), "ebb-kind": "payload", "ws": string(fx.wsID)})
	if err != nil {
		t.Fatalf("payload snapshot: %v", err)
	}
	if spec.twoPayloads {
		if _, err := fx.snapshotStage(ctx, stage, []string{fx.opDir},
			map[string]string{"ebb-op": string(fx.expOpID), "ebb-kind": "payload", "ws": string(fx.wsID)}); err != nil {
			t.Fatalf("second payload snapshot: %v", err)
		}
	}
	if spec.untaggedExtra {
		if _, err := fx.snapshotStage(ctx, stage, []string{fx.wsPrefix}, map[string]string{}); err != nil {
			t.Fatalf("untagged snapshot: %v", err)
		}
	}

	// ---- the capsule's destination seal (seal.go wire form) -----------
	if !spec.noSealSnap {
		declaredManifest := fx.manifestDigest
		if spec.lieManifestDgst {
			declaredManifest = digestOfTest([]byte("tampered manifest bytes"))
		}
		sealWS := string(fx.wsID)
		if spec.wrongWsInSeal {
			sealWS = string(domain.WorkspaceID(domain.NewID()))
		}
		seal := buildDestinationSeal(
			string(fx.snapID), sealWS,
			"orig-vault-repo-id", "orig-payload-backend-id",
			"fake-capsule-repo-1", fx.payloadID,
			declaredManifest, fx.inventoryDigest,
			string(fx.expOpID), time.Now().UTC(),
			[]string{checkCoverage, checkPayloadReadback, checkIndependence}, "fixture",
		)
		if spec.sealRepoID != "" {
			seal.BackendRepoID = spec.sealRepoID
		}
		sealBytes, err := marshalSealDoc(seal)
		if err != nil {
			t.Fatal(err)
		}
		sealDir := ".ebb-seal-" + string(fx.expOpID)
		fxWriteFile(t, filepath.Join(stage, sealDir, "receipt.json"), sealBytes)
		fx.sealID, err = fx.snapshotStage(ctx, stage, []string{sealDir},
			map[string]string{"ebb-op": string(fx.expOpID), "ebb-kind": "seal", "ws": string(fx.wsID)})
		if err != nil {
			t.Fatalf("seal snapshot: %v", err)
		}
	}

	// ---- package the physical repository into the container -----------
	if _, err := writePackage(fx.capsulePath, fx.capsuleRepoDir,
		time.Now().UTC().Format(time.RFC3339Nano), string(fx.expOpID), string(fx.snapID), "ebb fixture"); err != nil {
		t.Fatalf("writePackage: %v", err)
	}
	return fx
}

func (fx *importFixture) snapshotStage(ctx context.Context, stage string, rels []string, tags map[string]string) (string, error) {
	ref, err := fx.store.Snapshot(ctx, fx.extractedDir, stage, rels, passfileOfBytes(fx.t, fxCapsulePass), tags)
	if err != nil {
		return "", err
	}
	return ref.BackendID, nil
}

func passfileOfBytes(t *testing.T, password string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake.pass")
	fxWriteFile(t, p, []byte(password))
	return p
}

func fxWriteFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---- the payload's §16.2 manifest ----------------------------------------

// fxManifest is the manifest field subset restore's strict reader
// enforces (schema version, parseable identities, contract vocabulary,
// the roots bijection, the accounting-document reference). Fields the
// reader merely tolerates are omitted; parsing rejects unknown fields,
// never absent ones.
type fxManifest struct {
	SchemaVersion    int         `json:"schema_version"`
	SnapshotID       string      `json:"snapshot_id"`
	WorkspaceID      string      `json:"workspace_id"`
	CreatedAt        string      `json:"created_at"`
	Producer         string      `json:"producer"`
	Contract         fxContract  `json:"contract"`
	Roots            []fxRoot    `json:"roots"`
	Inventory        fxInventory `json:"inventory"`
	Policy           fxPolicy    `json:"policy"`
	RequiredFeatures []string    `json:"required_features"`
}

type fxContract struct {
	Scope       string `json:"scope"`
	Consistency string `json:"consistency"`
}

type fxRoot struct {
	ID            string `json:"id"`
	Ownership     string `json:"ownership"`
	BackendPrefix string `json:"backend_prefix"`
}

type fxInventory struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
	Count  int64  `json:"count"`
	Bytes  int64  `json:"bytes"`
}

type fxPolicy struct {
	Frozen         string `json:"frozen"`
	FrozenDigest   string `json:"frozen_digest"`
	ResolvedDigest string `json:"resolved_digest"`
}

func fxBuildManifest(t *testing.T, fx *importFixture, spec capsuleSpec, entries []domain.Entry) []byte {
	t.Helper()
	frozen := "# frozen policy fixture\n"
	scope, consistency := "single-owned-root", "stopped-writers-asserted"
	if spec.trim {
		scope, consistency = "trim-removal-plan", "stopped-writers-asserted"
	}
	m := fxManifest{
		SchemaVersion: 1,
		SnapshotID:    string(fx.snapID),
		WorkspaceID:   string(fx.wsID),
		CreatedAt:     "2026-09-18T12:00:00Z",
		Producer:      "fixture",
		Contract:      fxContract{Scope: scope, Consistency: consistency},
		Roots: []fxRoot{
			{ID: "main", Ownership: "owned", BackendPrefix: fx.wsPrefix},
			{ID: "meta", Ownership: "owned", BackendPrefix: fx.opDir},
		},
		Inventory: fxInventory{
			Path: fx.accountingName, Digest: fx.inventoryDigest,
			Count: int64(len(entries)), Bytes: int64(len(fx.inventoryBytes)),
		},
		Policy: fxPolicy{
			Frozen: frozen, FrozenDigest: digestOfTest([]byte(frozen)), ResolvedDigest: "fixture",
		},
		RequiredFeatures: []string{},
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}
