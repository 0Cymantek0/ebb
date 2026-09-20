package resticstore

// stdin_test.go covers the Freeze-to-Vault transport (D040 tier 3):
// client-side --stdin-filename validation (no subprocess), the
// streaming DumpBlob contract, and — when a real restic binary is
// available (EBB_TEST_RESTIC_BIN override, else PATH lookup) — live
// conformance pins for `backup --stdin` and the raw `dump` readback.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/domain"
)

// newStdinStore resolves the restic binary the way the higher-level
// suites do (EBB_TEST_RESTIC_BIN override first), so conformance runs can
// point at a pinned binary without touching PATH.
func newStdinStore(t *testing.T) *Store {
	t.Helper()
	bin := os.Getenv("EBB_TEST_RESTIC_BIN")
	if bin == "" {
		bin = "restic"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("restic binary %q not usable on this machine (%v); stdin conformance suite skipped", bin, err)
	}
	s := New(path)
	t.Cleanup(s.Close)
	return s
}

func TestValidateStdinFilename(t *testing.T) {
	for _, ok := range []string{"docker-image-abc123.tar", "image.tar", "a"} {
		if err := validateStdinFilename(ok); err != nil {
			t.Errorf("validateStdinFilename(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "a/b", `a\b`, ".", "..", "a\x00b"} {
		verr := validateStdinFilename(bad)
		if verr == nil {
			t.Errorf("validateStdinFilename(%q) accepted", bad)
		} else if c := errClass(t, verr); c != domain.StoreErrUsage {
			t.Errorf("validateStdinFilename(%q) class = %q want usage", bad, c)
		}
	}
}

// TestBackupStdinClientSideRejections proves the filename and nil-reader
// gates fire BEFORE any restic subprocess: the repo directory does not
// exist, so a StoreErrRepo answer would mean restic actually ran.
func TestBackupStdinClientSideRejections(t *testing.T) {
	s := newStdinStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	missingRepo := filepath.Join(t.TempDir(), "no-repo")
	cases := []struct {
		note     string
		filename string
		src      io.Reader
	}{
		{"empty filename", "", strings.NewReader("x")},
		{"path in filename", "sub/image.tar", strings.NewReader("x")},
		{"backslash in filename", `sub\image.tar`, strings.NewReader("x")},
		{"traversal filename", "..", strings.NewReader("x")},
		{"nil reader", "image.tar", nil},
	}
	for _, c := range cases {
		_, err := s.BackupStdin(ctx, missingRepo, "unused", c.filename, c.src, nil)
		if err == nil {
			t.Fatalf("%s: expected rejection", c.note)
		}
		if class := errClass(t, err); class != domain.StoreErrUsage {
			t.Fatalf("%s: class = %q want usage (client-side rejection before restic runs): %v", c.note, class, err)
		}
	}
}

// TestBackupStdinAndDumpBlobRoundTrip is the live conformance pin for the
// freeze transport: a deterministic multi-KiB stream goes in through
// --stdin, comes back out through a streaming raw dump, and the two agree
// byte-for-byte with an INDEPENDENT digest computed by the test (never
// the backend's own accounting). Also pins the tree path (/<filename>),
// tag round-trip, and the wrong-password class.
func TestBackupStdinAndDumpBlobRoundTrip(t *testing.T) {
	s := newStdinStore(t)
	repoDir, passfile := newRepo(t, s)

	// Deterministic, poorly-compressible payload (same generator style
	// as the fixture oracle: not trivially compressible, not random).
	payload := make([]byte, 256<<10)
	next := uint32(0x85EBCA6B)
	for i := range payload {
		next = next*1664525 + 1013904223
		payload[i] = byte(next >> 19)
	}
	wantDigest := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(wantDigest[:])

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	const filename = "docker-image-deadbeefcafe.tar"
	ref, err := s.BackupStdin(ctx, repoDir, passfile, filename, bytes.NewReader(payload),
		map[string]string{"op": "freeze", "image": "deadbeefcafe"})
	if err != nil {
		t.Fatalf("BackupStdin: %v", err)
	}
	if !isHexID(ref.BackendID, 64) || len(ref.ShortID) != 8 {
		t.Fatalf("ref = %+v", ref)
	}
	if ref.Tags["op"] != "freeze" || ref.Tags["ebb"] != "v1" || ref.Tags["image"] != "deadbeefcafe" {
		t.Fatalf("tags = %v", ref.Tags)
	}

	// Tree pin: exactly one file node at /<filename>.
	entries := lsOK(t, s, repoDir, passfile, ref.BackendID)
	if len(entries) != 1 || entries[0].Path != "/"+filename || entries[0].Kind != domain.KindFile {
		t.Fatalf("stdin snapshot tree = %+v, want the single file /%s", entries, filename)
	}
	if entries[0].Size != int64(len(payload)) {
		t.Fatalf("tree size = %d want %d", entries[0].Size, len(payload))
	}

	// Streaming readback through DumpBlob: digest and byte count must
	// match the independent oracle, and BOTH §11.4 gates must pass
	// (consume to EOF, then Close for the producer exit).
	stream, derr := s.DumpBlob(ctx, repoDir, passfile, ref.BackendID, filename)
	if derr != nil {
		t.Fatalf("DumpBlob: %v", derr)
	}
	h := sha256.New()
	n, cerr := io.Copy(h, stream)
	if cerr != nil {
		t.Fatalf("consume dump: %v", cerr)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close dump stream: %v", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantHex {
		t.Fatalf("readback digest %s want %s (content corrupted in transit)", got, wantHex)
	}
	if n != int64(len(payload)) {
		t.Fatalf("readback bytes = %d want %d", n, len(payload))
	}

	// Abandoned-stream gate: a dump closed mid-read must fail at Close.
	stream2, derr2 := s.DumpBlob(ctx, repoDir, passfile, ref.BackendID, filename)
	if derr2 != nil {
		t.Fatalf("DumpBlob (2): %v", derr2)
	}
	if _, err := stream2.Read(make([]byte, 64)); err != nil && err != io.EOF {
		t.Fatalf("partial read: %v", err)
	}
	if err := stream2.Close(); err == nil {
		t.Fatal("closing a partially-consumed dump must surface the §11.4 stream-completion failure")
	}

	// Bad snapshot id / bad path are usage errors before any mutation.
	if _, err := s.DumpBlob(ctx, repoDir, passfile, "zzzzzzzz", filename); err == nil {
		t.Fatal("nonexistent snapshot id must fail")
	} else if c := errClass(t, err); c != domain.StoreErrUsage {
		t.Fatalf("bad id class = %q want usage (%v)", c, err)
	}
	if _, err := s.DumpBlob(ctx, repoDir, passfile, ref.BackendID, "../escape"); err == nil {
		t.Fatal("traversal dump path must fail")
	}

	// Wrong password: auth class on the stdin path too.
	badPW := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(badPW, []byte("definitely-wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BackupStdin(ctx, repoDir, badPW, filename, bytes.NewReader(payload), nil); err == nil {
		t.Fatal("wrong password must fail")
	} else if c := errClass(t, err); c != domain.StoreErrAuth {
		t.Fatalf("wrong password class = %q want auth (%v)", c, err)
	}
}

// TestBackupStdinTruncatedSource pins the most dangerous stdin behavior:
// when the producer reader fails MID-STREAM (not EOF — an error), restic
// sees a clean early EOF and stores the truncated prefix; the adapter
// must fail the capture as a source error regardless.
func TestBackupStdinTruncatedSource(t *testing.T) {
	s := newStdinStore(t)
	repoDir, passfile := newRepo(t, s)

	full := bytes.Repeat([]byte{0xA5}, 64<<10)
	failAfter := int64(16 << 10)
	src := &failingReader{r: bytes.NewReader(full), failAfter: failAfter}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := s.BackupStdin(ctx, repoDir, passfile, "docker-image-truncated.tar", src, nil)
	if err == nil {
		t.Fatal("a source stream that fails mid-copy must fail the capture")
	}
	if c := errClass(t, err); c != domain.StoreErrSource {
		t.Fatalf("truncated source class = %q want source (%v)", c, err)
	}
	if !strings.Contains(err.Error(), "TRUNCATED") && !strings.Contains(err.Error(), "source stream failed") {
		t.Fatalf("error must name the truncation: %v", err)
	}
}

// failingReader returns an error (not EOF) after failAfter bytes.
type failingReader struct {
	r         *bytes.Reader
	failAfter int64
	read      int64
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.read >= f.failAfter {
		return 0, errors.New("fake docker save died mid-stream")
	}
	if int64(len(p)) > f.failAfter-f.read {
		p = p[:f.failAfter-f.read]
	}
	n, err := f.r.Read(p)
	f.read += int64(n)
	if err != nil && f.read < f.failAfter {
		return n, err
	}
	if f.read >= f.failAfter {
		return n, errors.New("fake docker save died mid-stream")
	}
	return n, err
}
