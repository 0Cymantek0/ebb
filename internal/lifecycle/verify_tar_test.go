package lifecycle

// Streaming whole-tree tar readback transport (verifyReadbackTar) —
// fault-injection tests with a scripted fake producer implementing the
// domain.TreeTarDumper seam, plus transport-equivalence assertions
// against the per-file loop over the SAME snapshot material. No restic
// binary needed; the real-backend equivalence (incl. timing) lives in
// e2e_tar_readback_test.go.

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// ---- scripted tar producer ----------------------------------------------

// tarOfTree renders dir's whole tree as restic's dump does: member names
// rooted at the snapshot root WITHOUT the leading slash, directory
// members WITH a trailing slash, exactly two trailing zero blocks.
func tarOfTree(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		hdr, herr := tar.FileInfoHeader(info, "")
		if herr != nil {
			return herr
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			if _, err := tw.Write(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("tar fixture: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar fixture close: %v", err)
	}
	return buf.Bytes()
}

// tarScriptStore is fakeStore plus the TreeTarDumper seam, so
// verifyReadback's transport switch takes the tar path. The archive it
// serves is rendered from the fake snapshot dir (rawTar overrides it for
// hand-built streams) with fault knobs for truncation and the
// producer-exit gate.
type tarScriptStore struct {
	*fakeStore
	t *testing.T

	mu        sync.Mutex
	dumpCalls int

	// deliver >= 0 truncates the served archive to its first deliver bytes.
	deliver int
	// closeErr is what the stream's Close reports (producer-exit gate).
	closeErr error
	// rawTar replaces the rendered archive when non-nil.
	rawTar []byte
}

func (f *tarScriptStore) dumpCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dumpCalls
}

func (f *tarScriptStore) DumpTreeTar(ctx context.Context, repoDir, passfile, snapID, treePath string) (io.ReadCloser, error) {
	f.mu.Lock()
	f.dumpCalls++
	f.mu.Unlock()
	if treePath != "/" {
		f.t.Errorf("DumpTreeTar treePath = %q, want the whole-tree spelling %q", treePath, "/")
	}
	raw := f.rawTar
	if raw == nil {
		raw = tarOfTree(f.t, filepath.Join(repoDir, "snap", snapID))
	}
	if f.deliver >= 0 && f.deliver < len(raw) {
		raw = raw[:f.deliver]
	}
	return &scriptedTarStream{Reader: bytes.NewReader(raw), closeErr: f.closeErr}, nil
}

// scriptedTarStream is a pre-rendered archive with a scripted Close
// (the producer-exit gate).
type scriptedTarStream struct {
	*bytes.Reader
	closeErr error
	closed   bool
}

func (s *scriptedTarStream) Close() error {
	s.closed = true
	return s.closeErr
}

// ---- fixture -------------------------------------------------------------

// buildTarFixture materializes a fake snapshot tree under
// repo/snap/<id>/ spanning BOTH capture prefixes, and returns the exact
// §11.4 readback set (path -> digest) derived from the bytes on disk.
func buildTarFixture(t *testing.T, repoDir, snapID string) []readbackFile {
	t.Helper()
	root := filepath.Join(repoDir, "snap", snapID)
	files := map[string]string{
		"ws/a.txt":                  "tar transport alpha\n",
		"ws/empty.txt":              "",
		"ws/sub/b.bin":              strings.Repeat("B", 8192),
		"ws/ünïcødé-文件-📄.txt":       "unicode content\n",
		".ebb-op-x/manifest.json":   `{"op":"x"}`,
		".ebb-op-x/inventory.jsonl": "entry\n",
	}
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "ws", "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out []readbackFile
	for rel, body := range files {
		out = append(out, readbackFile{
			SnapPath: "/" + rel,
			Digest:   digestBytes([]byte(body)),
		})
	}
	return out
}

func mustReadbackErr(t *testing.T, err error) *ErrVerification {
	t.Helper()
	if err == nil {
		t.Fatal("expected an ErrVerification, got nil")
	}
	var ev *ErrVerification
	if !errors.As(err, &ev) {
		t.Fatalf("error is not *ErrVerification: %v", err)
	}
	if ev.Check != "readback" {
		t.Fatalf("check = %q, want readback", ev.Check)
	}
	return ev
}

// ---- tests ----------------------------------------------------------------

// TestVerifyReadbackTransportEquivalenceFake: the tar transport and the
// per-file loop agree (pass) over the same snapshot material and set.
func TestVerifyReadbackTransportEquivalenceFake(t *testing.T) {
	repo := t.TempDir()
	files := buildTarFixture(t, repo, "aa")
	fs := newFakeStore()
	tarStore := &tarScriptStore{fakeStore: fs, t: t, deliver: -1}

	ctx := context.Background()
	if err := verifyReadback(ctx, tarStore, repo, "pw", "aa", files); err != nil {
		t.Fatalf("tar transport: %v", err)
	}
	if err := verifyReadbackPerFile(ctx, fs, repo, "pw", "aa", files); err != nil {
		t.Fatalf("per-file transport: %v", err)
	}
	if got := tarStore.dumpCount(); got != 1 {
		t.Errorf("tar transport ran %d dump subprocesses, want exactly 1 for the whole tree", got)
	}
}

// TestVerifyReadbackTarTruncatedStreamFailedProducer: the §11.4 double
// gate — a stream cut mid-archive from a producer that also failed
// (killed mid-stream, per the probe) must fail with BOTH the parser
// detail and the dirty-close detail.
func TestVerifyReadbackTarTruncatedStreamFailedProducer(t *testing.T) {
	repo := t.TempDir()
	files := buildTarFixture(t, repo, "aa")
	tarStore := &tarScriptStore{
		fakeStore: newFakeStore(), t: t,
		deliver: len(tarOfTree(t, filepath.Join(repo, "snap", "aa"))) / 2,
		closeErr: &domain.StoreError{Class: domain.StoreErrUnknown,
			Err: errors.New("fake producer: killed mid-stream, exit 1, empty stderr")},
	}
	err := verifyReadback(context.Background(), tarStore, repo, "pw", "aa", files)
	ev := mustReadbackErr(t, err)
	joined := strings.Join(ev.Details, "\n")
	if !strings.Contains(joined, "truncated or malformed archive") {
		t.Errorf("parser gate did not fire: %s", joined)
	}
	if !strings.Contains(joined, "closed dirty") {
		t.Errorf("producer-exit gate did not fire: %s", joined)
	}
	if !strings.Contains(joined, "missing from the tar dump") {
		t.Errorf("missing expected files not reported: %s", joined)
	}
}

// TestVerifyReadbackTarTruncatedStreamLyingExitZero: a producer that
// truncates the archive but exits clean is caught by the PARSER gate
// (unexpected EOF / missing members) — the case the adapter's Close
// alone is blind to (pinned by the restic-package fake tests).
func TestVerifyReadbackTarTruncatedStreamLyingExitZero(t *testing.T) {
	repo := t.TempDir()
	files := buildTarFixture(t, repo, "aa")
	tarStore := &tarScriptStore{
		fakeStore: newFakeStore(), t: t,
		deliver: len(tarOfTree(t, filepath.Join(repo, "snap", "aa"))) / 2,
	}
	ev := mustReadbackErr(t, verifyReadback(context.Background(), tarStore, repo, "pw", "aa", files))
	joined := strings.Join(ev.Details, "\n")
	if !strings.Contains(joined, "missing from the tar dump") {
		t.Errorf("missing expected files not reported: %s", joined)
	}
}

// TestVerifyReadbackTarDigestMismatchEquivalence: a tampered comparison
// (wrong expected digest for one file) fails BOTH transports with the
// same detail line for the same path.
func TestVerifyReadbackTarDigestMismatchEquivalence(t *testing.T) {
	repo := t.TempDir()
	files := buildTarFixture(t, repo, "aa")
	for i := range files {
		if files[i].SnapPath == "/ws/a.txt" {
			files[i].Digest = digestBytes([]byte("tampered inventory digest"))
		}
	}
	fs := newFakeStore()
	tarStore := &tarScriptStore{fakeStore: fs, t: t, deliver: -1}

	want := fmt.Sprintf("%s: readback digest", "/ws/a.txt")
	evTar := mustReadbackErr(t, verifyReadback(context.Background(), tarStore, repo, "pw", "aa", files))
	if !strings.Contains(strings.Join(evTar.Details, "; "), want) {
		t.Errorf("tar details lack the digest-mismatch line: %v", evTar.Details)
	}
	evFile := mustReadbackErr(t, verifyReadbackPerFile(context.Background(), fs, repo, "pw", "aa", files))
	if !strings.Contains(strings.Join(evFile.Details, "; "), want) {
		t.Errorf("per-file details lack the digest-mismatch line: %v", evFile.Details)
	}
}

// TestVerifyReadbackTarDuplicateMemberRejected: §11.4 rejects duplicate
// names in the streaming tar transport.
func TestVerifyReadbackTarDuplicateMemberRejected(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name, body string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write("ws/a.txt", "tar transport alpha\n")
	write("ws/a.txt", "tar transport alpha\n")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tarStore := &tarScriptStore{fakeStore: newFakeStore(), t: t, deliver: -1, rawTar: buf.Bytes()}
	files := []readbackFile{{SnapPath: "/ws/a.txt", Digest: digestBytes([]byte("tar transport alpha\n"))}}

	ev := mustReadbackErr(t, verifyReadback(context.Background(), tarStore, "r", "p", "s", files))
	if !strings.Contains(strings.Join(ev.Details, "; "), "duplicate tar member") {
		t.Errorf("duplicate member not rejected: %v", ev.Details)
	}
}

// TestVerifyReadbackTarNonzeroTailRejected: only zero padding may follow
// the end-of-archive marker (probe: exactly two zero blocks).
func TestVerifyReadbackTarNonzeroTailRejected(t *testing.T) {
	clean := tarOfTree(t, writeMiniTree(t))
	tarStore := &tarScriptStore{
		fakeStore: newFakeStore(), t: t, deliver: -1,
		rawTar: append(append([]byte{}, clean...), []byte("GARBAGE AFTER END")...),
	}
	files := []readbackFile{{SnapPath: "/ws/a.txt", Digest: digestBytes([]byte("x\n"))}}
	ev := mustReadbackErr(t, verifyReadback(context.Background(), tarStore, "r", "p", "s", files))
	if !strings.Contains(strings.Join(ev.Details, "; "), "after the end-of-archive marker") {
		t.Errorf("nonzero tail not rejected: %v", ev.Details)
	}
}

// TestVerifyReadbackTarExtraRegularMemberIgnored: a regular member
// outside the expected set is NOT readback's failure — the per-file
// transport cannot observe extras either, and extras are coverage's gate
// (I04). A stricter rule here would break transport equivalence.
func TestVerifyReadbackTarExtraRegularMemberIgnored(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name, body string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	write("ws/a.txt", "x\n")
	write("ws/not-in-the-readback-set.txt", "extra content the coverage check owns\n")
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	tarStore := &tarScriptStore{fakeStore: newFakeStore(), t: t, deliver: -1, rawTar: buf.Bytes()}
	files := []readbackFile{{SnapPath: "/ws/a.txt", Digest: digestBytes([]byte("x\n"))}}
	if err := verifyReadback(context.Background(), tarStore, "r", "p", "s", files); err != nil {
		t.Fatalf("extras are coverage's gate, not readback's: %v", err)
	}
}

// TestVerifyReadbackEmptySetRunsNoDump mirrors the per-file loop's
// zero-subprocess behavior for an empty readback set.
func TestVerifyReadbackEmptySetRunsNoDump(t *testing.T) {
	tarStore := &tarScriptStore{fakeStore: newFakeStore(), t: t, deliver: -1}
	if err := verifyReadback(context.Background(), tarStore, "r", "p", "s", nil); err != nil {
		t.Fatalf("empty readback set: %v", err)
	}
	if got := tarStore.dumpCount(); got != 0 {
		t.Errorf("empty set ran %d dumps, want 0", got)
	}
}

// TestVerifyReadbackFallsBackWithoutSeam: a store that does NOT
// implement TreeTarDumper keeps the per-file transport (and its exact
// failure text), so existing fakes behave identically.
func TestVerifyReadbackFallsBackWithoutSeam(t *testing.T) {
	repo := t.TempDir()
	files := buildTarFixture(t, repo, "aa")
	fs := newFakeStore()
	fs.corruptDump["/ws/a.txt"] = true

	// Sanity: the fake does not accidentally satisfy the seam.
	if _, ok := interface{}(fs).(domain.TreeTarDumper); ok {
		t.Fatal("fakeStore must not implement TreeTarDumper (fallback contract)")
	}
	// corruptDump alters the DUMPED BYTES, so the per-file loop reports a
	// digest mismatch for that path — the unchanged per-file semantics.
	ev := mustReadbackErr(t, verifyReadback(context.Background(), fs, repo, "pw", "aa", files))
	if !strings.Contains(strings.Join(ev.Details, "; "), "/ws/a.txt: readback digest") {
		t.Errorf("per-file fallback detail missing: %v", ev.Details)
	}
}

// TestVerifyReadbackTarCanceledContext: cancellation surfaces as the raw
// context error before any transport work, like the per-file loop.
func TestVerifyReadbackTarCanceledContext(t *testing.T) {
	tarStore := &tarScriptStore{fakeStore: newFakeStore(), t: t, deliver: -1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyReadback(ctx, tarStore, "r", "p", "s",
		[]readbackFile{{SnapPath: "/ws/a.txt", Digest: "0"}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
}

// writeMiniTree is a one-file fixture for the rawTar tests.
func writeMiniTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "ws"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ws", "a.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
