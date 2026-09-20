package freezer

// freeze_test.go drives the Freeze-to-Vault pipeline end to end through
// REAL subprocesses: the real restic-store adapter talking to a fake
// restic binary (deterministic round-trip; see testdata/fakerestic) and
// a fake docker binary (canned save/inspect/load/rmi; testdata/fakedocker).
// The fake binaries are compiled once per test run by TestMain. A
// separate opt-in suite runs the same pipeline against a REAL restic
// repository (EBB_TEST_RESTIC_BIN override, else PATH lookup) for live
// conformance.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	resticstore "ebb/internal/storage/restic"
)

// ---- fake binary management ----------------------------------------------

var fakeBin = struct {
	once sync.Once
	dir  string // holds fakedocker(.exe) and fakerestic(.exe)
	err  error
}{}

// buildFakes compiles the two fake CLIs once for the whole package run.
func buildFakes(t *testing.T) (binDir string) {
	t.Helper()
	fakeBin.once.Do(func() {
		dir, err := os.MkdirTemp("", "ebb-freezer-fakebin-")
		if err != nil {
			fakeBin.err = err
			return
		}
		src := "ebb/internal/freezer/testdata"
		for _, name := range []string{"fakedocker", "fakerestic"} {
			out := filepath.Join(dir, name+exeSuffix())
			build := exec.Command("go", "build", "-o", out, src+"/"+name)
			if out, berr := build.CombinedOutput(); berr != nil {
				fakeBin.err = fmt.Errorf("building fake %s: %v: %s", name, berr, out)
				return
			}
		}
		fakeBin.dir = dir
	})
	if fakeBin.err != nil {
		t.Skipf("fake binaries unavailable (%v); freezer subprocess suite skipped", fakeBin.err)
	}
	return fakeBin.dir
}

func exeSuffix() string {
	if os.PathSeparator == '\\' {
		return ".exe"
	}
	return ""
}

// ---- harness ---------------------------------------------------------------

// fakeEnv is one disposable world: a control dir for the fake docker
// (FAKE_BIN_DIR), a fake-restic repository (control inside <repo>/fake-control),
// a passfile, a catalog with a registered vault, and a Freezer wired to
// the real restic-store adapter over the fake restic binary.
type fakeEnv struct {
	t            *testing.T
	ctlDir       string
	logPath      string
	repoDir      string
	resticCtlDir string
	cat          *catalog.Catalog
	freezer      *Freezer
	store        *resticstore.Store
	passfile     string
	vaultID      domain.VaultID
	imageID      string
	payload      []byte // the independent digest oracle's copy of the stream
}

const testVaultRowID = domain.VaultID("33333333333333333333333333333333")

func newFakeEnv(t *testing.T) *fakeEnv {
	t.Helper()
	binDir := buildFakes(t)
	base := t.TempDir()
	e := &fakeEnv{
		t:            t,
		ctlDir:       filepath.Join(base, "ctl"),
		repoDir:      filepath.Join(base, "repo"),
		passfile:     filepath.Join(base, "pw"),
		imageID:      "sha256:" + strings.Repeat("ab", 32),
		vaultID:      testVaultRowID,
		resticCtlDir: filepath.Join(base, "repo", "fake-control"),
	}
	for _, d := range []string{e.ctlDir, filepath.Join(base, "state")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.logPath = filepath.Join(e.ctlDir, "docker.log")
	if err := os.WriteFile(e.passfile, []byte("fake-repo-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Fake restic repository: init through the same binary the adapter
	// will drive.
	if out, err := exec.Command(filepath.Join(binDir, "fakerestic"+exeSuffix()),
		"--repo", e.repoDir, "init").CombinedOutput(); err != nil {
		t.Fatalf("fake restic init: %v: %s", err, out)
	}

	// Catalog with the registered vault row (FK discipline).
	cat, err := catalog.Open(filepath.Join(base, "state", "catalog.db"))
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	t.Cleanup(func() { cat.Close() })
	if err := cat.RegisterVault(catalog.Vault{
		ID: testVaultRowID, Path: e.repoDir, RepoID: "fake-repo",
		RegisteredAt: "2026-09-21T00:00:00Z",
	}); err != nil {
		t.Fatalf("register vault: %v", err)
	}
	e.cat = cat

	// The REAL adapter over the FAKE restic binary; the docker side
	// resolves through the EBB_TEST_DOCKER_BIN seam.
	t.Setenv(EnvDockerBin, filepath.Join(binDir, "fakedocker"+exeSuffix()))
	t.Setenv(envFakeBinDir, e.ctlDir)
	store := resticstore.New(filepath.Join(binDir, "fakerestic"+exeSuffix()))
	t.Cleanup(store.Close)
	e.store = store
	f, ferr := New("", store)
	if ferr != nil {
		t.Fatalf("freezer: %v", ferr)
	}
	e.freezer = f
	return e
}

// setPayload fixes the stream the fake docker will save (and records the
// oracle bytes the test digests independently of every other component).
func (e *fakeEnv) setPayload(size int64) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.ctlDir, "save-bytes"), []byte(fmt.Sprintf("%d", size)), 0o644); err != nil {
		e.t.Fatal(err)
	}
	payload := make([]byte, size)
	next := uint32(0x9E3779B9)
	for i := range payload {
		next = next*1664525 + 1013904223
		payload[i] = byte(next >> 23)
	}
	e.payload = payload
}

func (e *fakeEnv) ctl(name, content string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.ctlDir, name), []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *fakeEnv) setResticCtl(name, content string) {
	e.t.Helper()
	if err := os.MkdirAll(e.resticCtlDir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.resticCtlDir, name), []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

// dockerLog returns the fake docker's event log so far.
func (e *fakeEnv) dockerLog() string {
	e.t.Helper()
	b, err := os.ReadFile(e.logPath)
	if err != nil {
		return ""
	}
	return string(b)
}

// waitForLog polls the fake docker log until want appears (bounded).
func (e *fakeEnv) waitForLog(want string, timeout time.Duration) bool {
	e.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(e.dockerLog(), want) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func (e *fakeEnv) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

func (e *fakeEnv) oracleDigest() string {
	sum := sha256.Sum256(e.payload)
	return hex.EncodeToString(sum[:])
}

func (e *fakeEnv) freeze() (FreezeResult, error) {
	ctx, cancel := e.ctx()
	defer cancel()
	return e.freezer.Freeze(ctx, FreezeRequest{
		ImageID: e.imageID, RepoDir: e.repoDir, Passfile: e.passfile,
		VaultID: e.vaultID, Cat: e.cat,
	})
}

// ---- tests -----------------------------------------------------------------

func TestFreezeHappyPathVerifiedByteExact(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(512 * 1024)

	res, err := e.freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if !res.Verified {
		t.Fatalf("freeze not verified: %+v", res)
	}
	// Byte-exact against the independent oracle: what save emitted, what
	// was hashed in flight, what the catalog recorded, and what the
	// readback proved must all be the SAME digest.
	want := e.oracleDigest()
	if res.Entry.SHA256 != want {
		t.Fatalf("recorded digest %s want oracle %s", res.Entry.SHA256, want)
	}
	if res.Entry.Bytes != int64(len(e.payload)) {
		t.Fatalf("recorded bytes %d want %d", res.Entry.Bytes, len(e.payload))
	}
	if res.Entry.ImageID != e.imageID || res.Entry.VerifiedAt == "" || res.Entry.DaemonRemovedAt != "" {
		t.Fatalf("entry = %+v", res.Entry)
	}
	if res.Entry.Filename != FilenameFor(e.imageID) {
		t.Fatalf("filename = %q want %q", res.Entry.Filename, FilenameFor(e.imageID))
	}
	// The durable row is readable back and pinned.
	got, err := e.cat.GetDockerImage(res.Entry.ID)
	if err != nil || !got.Pinned || got.VerifiedAt == "" {
		t.Fatalf("row readback = %+v, %v", got, err)
	}
	// Subprocess discipline: save completed cleanly, nothing was removed.
	log := e.dockerLog()
	if !strings.Contains(log, "save-complete bytes=524288") {
		t.Fatalf("docker log lacks clean save completion:\n%s", log)
	}
	if strings.Contains(log, "rmi") {
		t.Fatalf("docker log shows an unrequested daemon removal:\n%s", log)
	}
	if !strings.Contains(log, "start image inspect "+e.imageID) {
		t.Fatalf("docker log lacks the inspect probe:\n%s", log)
	}
}

func TestFreezeTamperedReadbackRetainsUnverified(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(64 * 1024)
	e.setResticCtl("tamper", "1")

	_, err := e.freeze()
	if err == nil {
		t.Fatal("a tampered readback must fail the freeze")
	}
	var se *domain.StoreError
	if !errors.As(err, &se) || se.Class != domain.StoreErrIntegrity {
		t.Fatalf("tamper class = %v want StoreErrIntegrity (%v)", se, err)
	}
	var mm *ErrHashMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("error should carry the mismatch detail: %v", err)
	}
	// The entry is retained, unverified and pinned; NOTHING was removed
	// from the daemon.
	rows, _ := e.cat.FindDockerImages(e.imageID)
	if len(rows) != 1 {
		t.Fatalf("retained rows = %+v, want exactly the unverified one", rows)
	}
	if rows[0].VerifiedAt != "" || !rows[0].Pinned {
		t.Fatalf("retained row = %+v, want unverified+pinned", rows[0])
	}
	if strings.Contains(e.dockerLog(), "rmi") {
		t.Fatalf("docker log shows an unrequested daemon removal:\n%s", e.dockerLog())
	}
}

func TestFreezeDockerSaveDiesMidStream(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(256 * 1024)
	e.ctl("save-fail-after", "32768")

	_, err := e.freeze()
	if err == nil {
		t.Fatal("a save that dies mid-stream must fail the freeze")
	}
	var se *domain.StoreError
	if !errors.As(err, &se) {
		t.Fatalf("error should be a StoreError: %v", err)
	}
	if se.Class != domain.StoreErrSource {
		t.Fatalf("mid-stream save death class = %q want source (%v)", se.Class, err)
	}
	if !strings.Contains(err.Error(), "TRUNCATED") {
		t.Fatalf("error must name the truncation: %v", err)
	}
	// No durable row exists for a stream that never completed.
	rows, _ := e.cat.FindDockerImages(e.imageID)
	if len(rows) != 0 {
		t.Fatalf("rows recorded for a failed stream: %+v", rows)
	}
}

func TestFreezeResticBackupFailure(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(32 * 1024)
	e.setResticCtl("fail-backup", "1")

	_, err := e.freeze()
	if err == nil {
		t.Fatal("a failing restic backup must fail the freeze")
	}
	var se *domain.StoreError
	if !errors.As(err, &se) || se.Class != domain.StoreErrSource {
		t.Fatalf("backup failure class = %v (%v)", se, err)
	}
	if !strings.Contains(err.Error(), "INCOMPLETE snapshot") {
		t.Fatalf("error must name the stored-but-incomplete snapshot: %v", err)
	}
	rows, _ := e.cat.FindDockerImages(e.imageID)
	if len(rows) != 0 {
		t.Fatalf("no row may exist for a failed backup: %+v", rows)
	}
}

func TestProbeAndUnknownImage(t *testing.T) {
	e := newFakeEnv(t)
	ctx, cancel := e.ctx()
	defer cancel()

	if err := e.freezer.Probe(ctx); err != nil {
		t.Fatalf("probe with a healthy fake daemon: %v", err)
	}
	e.ctl("version-fail", "1")
	var unreach *ErrDockerUnreachable
	if err := e.freezer.Probe(ctx); !errors.As(err, &unreach) {
		t.Fatalf("probe with a dead daemon = %v, want ErrDockerUnreachable", err)
	}
	e.ctl("version-fail", "")

	e.ctl("inspect-missing", "1")
	_, err := e.freezer.Inspect(ctx, e.imageID)
	var unknown *ErrImageUnknown
	if !errors.As(err, &unknown) {
		t.Fatalf("inspect of an unknown image = %v, want ErrImageUnknown", err)
	}

	if err := ValidateImageID("bad image\n"); err == nil {
		t.Fatal("whitespace image id must be rejected")
	}
	if err := ValidateImageID("sha256:" + strings.Repeat("a", 64)); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
}

// TestFreezeCancellationMidStream pins the teardown contract: canceling
// mid-stream fails the freeze, kills the consumer, and lets the producer
// die of the closed pipe (bounded by the grace kill) — no orphan
// processes, no deadlock, and the producer's death is observable in the
// fake's lifecycle log.
func TestFreezeCancellationMidStream(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(8 << 20) // big enough to still be streaming
	e.ctl("slow-ms", "20")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := e.freezer.Freeze(ctx, FreezeRequest{
			ImageID: e.imageID, RepoDir: e.repoDir, Passfile: e.passfile,
			VaultID: e.vaultID, Cat: e.cat,
		})
		done <- err
	}()
	// Let the stream actually start, then cancel.
	time.Sleep(250 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled freeze must fail")
		}
		if !strings.Contains(err.Error(), "context canceled") &&
			!strings.Contains(err.Error(), "interrupted") {
			t.Fatalf("error should carry the cancellation: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Freeze did not return after cancellation (orphaned producer or leaked pipe)")
	}

	log := e.dockerLog()
	if !strings.Contains(log, "start save "+e.imageID) {
		t.Fatalf("the stream never started; log:\n%s", log)
	}
	if strings.Contains(log, "save-complete") {
		t.Fatalf("a cancelled stream must not report completion:\n%s", log)
	}
	// The producer must be gone: it observes the closed pipe and exits
	// by itself (the observable no-orphan evidence on both platforms).
	if !e.waitForLog("save-exit", 10*time.Second) {
		t.Fatalf("producer did not exit after the teardown closed the pipe (orphan?); log:\n%s", e.dockerLog())
	}
	rows, _ := e.cat.FindDockerImages(e.imageID)
	if len(rows) != 0 {
		t.Fatalf("no row may exist for a cancelled freeze: %+v", rows)
	}
}

func TestRestoreHappyPath(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(128 * 1024)
	res, err := e.freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}

	ctx, cancel := e.ctx()
	defer cancel()
	rr, err := e.freezer.Restore(ctx, res.Entry, e.repoDir, e.passfile)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rr.Bytes != int64(len(e.payload)) || rr.SHA256 != e.oracleDigest() {
		t.Fatalf("restore = %+v (want %d bytes, oracle digest)", rr, len(e.payload))
	}
	if rr.LoadOutput == "" {
		t.Fatalf("restore lost the docker load report: %+v", rr)
	}
	// The load consumer drank the whole verified stream.
	if !strings.Contains(e.dockerLog(), fmt.Sprintf("load bytes=%d digest=%s", len(e.payload), e.oracleDigest())) {
		t.Fatalf("docker log lacks the verified load record:\n%s", e.dockerLog())
	}
}

// TestRestoreHashMismatchAbortsBeforeLoad: with a tampered vault, the
// restore must abort in the verification pass — docker load is never
// even started (zero stdin consumed, no process spawned).
func TestRestoreHashMismatchAbortsBeforeLoad(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(128 * 1024)
	res, err := e.freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	e.setResticCtl("tamper", "1")

	ctx, cancel := e.ctx()
	defer cancel()
	_, rerr := e.freezer.Restore(ctx, res.Entry, e.repoDir, e.passfile)
	if rerr == nil {
		t.Fatal("a tampered vault must abort the restore")
	}
	var se *domain.StoreError
	if !errors.As(rerr, &se) || se.Class != domain.StoreErrIntegrity {
		t.Fatalf("abort class = %v want integrity (%v)", se, rerr)
	}
	if strings.Contains(e.dockerLog(), "load") {
		t.Fatalf("docker load received work despite the mismatch:\n%s", e.dockerLog())
	}
}

func TestRemovalConfirmationDiscipline(t *testing.T) {
	e := newFakeEnv(t)
	e.setPayload(32 * 1024)
	res, err := e.freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	ctx, cancel := e.ctx()
	defer cancel()

	// An UNVERIFIED entry never authorizes removal (defense in depth
	// beside the catalog's own refusal).
	unverified := res.Entry
	unverified.VerifiedAt = ""
	var uv *ErrUnverifiedFreeze
	if err := e.freezer.RemoveFromDaemon(ctx, unverified, e.cat); !errors.As(err, &uv) {
		t.Fatalf("unverified removal = %v, want ErrUnverifiedFreeze", err)
	}
	if strings.Contains(e.dockerLog(), "rmi") {
		t.Fatalf("an unverified freeze triggered docker rmi:\n%s", e.dockerLog())
	}

	// A verified entry removes exactly once and records the audit.
	if err := e.freezer.RemoveFromDaemon(ctx, res.Entry, e.cat); err != nil {
		t.Fatalf("verified removal: %v", err)
	}
	if !strings.Contains(e.dockerLog(), "rmi-done "+e.imageID) {
		t.Fatalf("docker log lacks the audited removal:\n%s", e.dockerLog())
	}
	got, _ := e.cat.GetDockerImage(res.Entry.ID)
	if got.DaemonRemovedAt == "" {
		t.Fatal("removal timestamp not recorded")
	}
	if err := e.freezer.RemoveFromDaemon(ctx, got, e.cat); err == nil {
		t.Fatal("double removal must be refused")
	}
}

// ---- real-restic opt-in conformance ---------------------------------------

// newRealResticEnv builds the fake-docker + REAL-restic combination.
func newRealResticEnv(t *testing.T) *fakeEnv {
	t.Helper()
	binDir := buildFakes(t)
	base := t.TempDir()
	e := &fakeEnv{
		t:            t,
		ctlDir:       filepath.Join(base, "ctl"),
		repoDir:      filepath.Join(base, "repo"),
		passfile:     filepath.Join(base, "pw"),
		imageID:      "sha256:" + strings.Repeat("cd", 32),
		vaultID:      testVaultRowID,
		resticCtlDir: filepath.Join(base, "repo-fake-ctl"),
	}
	if err := os.MkdirAll(e.ctlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(base, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.logPath = filepath.Join(e.ctlDir, "docker.log")
	if err := os.WriteFile(e.passfile, []byte("real-restic-freeze-password"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := os.Getenv("EBB_TEST_RESTIC_BIN")
	if bin == "" {
		bin = "restic"
	}
	path, lerr := exec.LookPath(bin)
	if lerr != nil {
		t.Skipf("restic binary %q not usable (%v); real-restic freezer suite skipped", bin, lerr)
	}
	store := resticstore.New(path)
	t.Cleanup(store.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := store.Init(ctx, e.repoDir, e.passfile); err != nil {
		t.Fatalf("init real repo: %v", err)
	}

	cat, err := catalog.Open(filepath.Join(base, "state", "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cat.Close() })
	if err := cat.RegisterVault(catalog.Vault{
		ID: testVaultRowID, Path: e.repoDir, RepoID: "real-repo",
		RegisteredAt: "2026-09-21T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	e.cat = cat

	t.Setenv(EnvDockerBin, filepath.Join(binDir, "fakedocker"+exeSuffix()))
	t.Setenv(envFakeBinDir, e.ctlDir)
	f, ferr := New("", store)
	if ferr != nil {
		t.Fatal(ferr)
	}
	e.freezer = f
	e.store = store
	return e
}

// TestFreezeRealResticRoundTrip runs the whole pipeline against a real
// restic repository: the digest the freezer recorded must equal the
// test's independent oracle (what the fake docker actually emitted), and
// the restore must feed the daemon byte-exactly.
func TestFreezeRealResticRoundTrip(t *testing.T) {
	e := newRealResticEnv(t)
	e.setPayload(768 * 1024)

	res, err := e.freeze()
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if !res.Verified || res.Entry.SHA256 != e.oracleDigest() || res.Entry.Bytes != int64(len(e.payload)) {
		t.Fatalf("result = %+v (digest %s want oracle %s)", res, res.Entry.SHA256, e.oracleDigest())
	}

	ctx, cancel := e.ctx()
	defer cancel()
	rr, rerr := e.freezer.Restore(ctx, res.Entry, e.repoDir, e.passfile)
	if rerr != nil {
		t.Fatalf("restore: %v", rerr)
	}
	if rr.Bytes != int64(len(e.payload)) || rr.SHA256 != e.oracleDigest() {
		t.Fatalf("restore = %+v", rr)
	}
	if !strings.Contains(e.dockerLog(), fmt.Sprintf("load bytes=%d", len(e.payload))) {
		t.Fatalf("load record missing:\n%s", e.dockerLog())
	}
}
