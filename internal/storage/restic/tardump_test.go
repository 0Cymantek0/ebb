package resticstore

// Streaming whole-tree tar dump transport (DumpTreeTar) — gate tests
// against a scripted FAKE producer binary, plus conformance against the
// real restic 0.19.1 binary (auto-skip when absent).
//
// The fake producer is a tiny Go helper built once in TestMain (the
// internal/actions precedent: never cmd.exe, which trips shell-detection
// warnings). The Store's child environment is constructed from scratch,
// so the helper cannot be steered by env — it scripts on the LAST argv
// element (the tree path), which the adapter normalizes to a leading-
// slash form before spawn.
//
// Probe behaviors these tests pin (lab/restic-probe/tar-dump):
//   - producer killed mid-stream: clean EOF to the reader, exit 1, EMPTY
//     stderr (the /trunc script) — parser gate AND exit gate required;
//   - a lying producer (truncated stream, exit 0 — /truncexit0) is NOT
//     the adapter's to catch at Close: the consumer's parser gate owns
//     it (held end-to-end by lifecycle's verifyReadbackTar tests);
//   - aborted consumer: producer fails writing ("The pipe has been
//     ended."), Close must report it (/block);
//   - plain-text Fatal stderr spellings classify to StoreErrUsage
//     (/fatal, /badid) exactly like DumpFile.

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"ebb/internal/domain"
)

// ---- fake producer helper ----------------------------------------------

var (
	helperOnce sync.Once
	helperExe  string
	helperErr  error
	helperDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if helperDir != "" {
		os.RemoveAll(helperDir) // test-only scratch; the package has no removal side effects
	}
	os.Exit(code)
}

// fakeProducerBin builds (once) the scripted tar-dump helper binary.
func fakeProducerBin(t *testing.T) string {
	t.Helper()
	helperOnce.Do(func() {
		var err error
		helperDir, err = os.MkdirTemp("", "ebb-tardump-helper-")
		if err != nil {
			helperErr = err
			return
		}
		src := filepath.Join(helperDir, "src")
		if err := os.MkdirAll(src, 0o755); err != nil {
			helperErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(helperSource), 0o644); err != nil {
			helperErr = err
			return
		}
		if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module ebb-tardump-test-helper\n\ngo 1.27\n"), 0o644); err != nil {
			helperErr = err
			return
		}
		exe := filepath.Join(helperDir, "helper")
		if runtime.GOOS == "windows" {
			exe += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", exe, ".")
		cmd.Dir = src
		if out, berr := cmd.CombinedOutput(); berr != nil {
			helperErr = fmt.Errorf("go build: %w\n%s", berr, out)
			return
		}
		helperExe = exe
	})
	if helperErr != nil {
		t.Skipf("cannot build the fake producer helper: %v", helperErr)
	}
	return helperExe
}

const helperSource = `package main

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// archive renders the fixture tree the way restic does: member names
// rooted at the snapshot tree root WITHOUT the leading slash, exactly two
// trailing zero blocks, nothing after them.
func archive() []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, body []byte) {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}
		if err := tw.WriteHeader(hdr); err != nil {
			panic(err)
		}
		if _, err := tw.Write(body); err != nil {
			panic(err)
		}
	}
	write("ws/alpha.txt", []byte("alpha-content\n"))
	big := make([]byte, 256*1024)
	for i := range big {
		big[i] = byte(i * 7)
	}
	write("ws/big.bin", big)
	write(".ebb-op-deadbeef/manifest.json", []byte(` + "`{}`" + `))
	write("ws/empty.txt", nil)
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func main() {
	// Fixture portability: the /truncexit0 script models the LYING
	// producer (broken-pipe write ignored, clean exit 0). On Windows a
	// write into a closed pipe is a plain error this helper already
	// ignores; on Linux the Go runtime KILLS fd-1/2 writers with SIGPIPE
	// before user code runs, which would turn the abandoned-consumer
	// scenario into a producer signal death and change which Close gate
	// fires. Ignoring SIGPIPE makes the fixture behave identically on
	// every platform (writes return EPIPE errors the helper ignores).
	// No-op on Windows.
	signal.Ignore(syscall.SIGPIPE)

	script := os.Args[len(os.Args)-1]
	full := archive()
	switch script {
	case "/ok":
		os.Stdout.Write(full)
		os.Exit(0)
	case "/trunc": // producer killed mid-stream: partial bytes, exit 1, EMPTY stderr
		os.Stdout.Write(full[:len(full)-1000])
		os.Exit(1)
	case "/truncexit0": // lying producer: partial bytes, clean exit
		os.Stdout.Write(full[:len(full)-1000])
		os.Exit(0)
	case "/fatal":
		fmt.Fprintln(os.Stderr, ` + "`Fatal: cannot dump file: path \"\\\\no-such-path\" not found in snapshot`" + `)
		os.Exit(1)
	case "/badid":
		fmt.Fprintln(os.Stderr, ` + "`Fatal: failed to find snapshot: no matching ID found for prefix \"badbadbad\"`" + `)
		os.Exit(1)
	case "/block": // fills the pipe and keeps writing; an aborted reader must fail us
		for {
			if _, err := os.Stdout.Write(full); err != nil {
				os.Exit(1)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	os.Exit(2)
}
`

// fakeProducerStore returns a Store whose binary is the scripted helper.
func fakeProducerStore(t *testing.T) *Store {
	t.Helper()
	s := New(fakeProducerBin(t))
	t.Cleanup(s.Close)
	return s
}

const fakeSnap = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// ---- gates against the scripted producer --------------------------------

func TestDumpTreeTarFakeHappyPath(t *testing.T) {
	s := fakeProducerStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := s.DumpTreeTar(ctx, t.TempDir(), "unused-passfile", fakeSnap, "/ok")
	if err != nil {
		t.Fatalf("DumpTreeTar: %v", err)
	}
	raw, rerr := io.ReadAll(stream)
	if rerr != nil {
		t.Fatalf("read stream: %v", rerr)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close on a clean stream must pass both gates: %v", err)
	}

	// Member form + content digests (probe-pinned: no leading slash).
	type member struct {
		name string
		body []byte
	}
	var got []member
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, nerr := tr.Next()
		if nerr == io.EOF {
			break
		}
		if nerr != nil {
			t.Fatalf("tar parse: %v", nerr)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		body, derr := io.ReadAll(tr)
		if derr != nil {
			t.Fatalf("member %s: %v", hdr.Name, derr)
		}
		got = append(got, member{hdr.Name, body})
	}
	byName := map[string][]byte{}
	for _, m := range got {
		byName[m.name] = m.body
	}
	if string(byName["ws/alpha.txt"]) != "alpha-content\n" {
		t.Errorf("ws/alpha.txt content = %q", byName["ws/alpha.txt"])
	}
	if len(byName["ws/big.bin"]) != 256*1024 {
		t.Errorf("ws/big.bin size = %d", len(byName["ws/big.bin"]))
	}
	if len(byName["ws/empty.txt"]) != 0 {
		t.Errorf("empty member carried %d bytes", len(byName["ws/empty.txt"]))
	}
	if _, ok := byName[".ebb-op-deadbeef/manifest.json"]; !ok {
		t.Errorf("op-dir prefix missing from the whole-tree dump; members = %d", len(got))
	}
	// The stream ended with the archive only: two zero blocks, no extras.
	if extra := len(raw) - (len(raw) / 512 * 512); extra != 0 {
		t.Errorf("stream is not a whole number of 512-byte blocks (%d rem)", extra)
	}
}

func TestDumpTreeTarFakeTruncatedNonZeroExit(t *testing.T) {
	s := fakeProducerStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := s.DumpTreeTar(ctx, t.TempDir(), "pw", fakeSnap, "/trunc")
	if err != nil {
		t.Fatalf("DumpTreeTar: %v", err)
	}
	raw, rerr := io.ReadAll(stream) // the reader sees a clean early EOF
	if rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if len(raw) == 0 || len(raw)%512 == 0 {
		t.Fatalf("expected partial blocks from the mid-stream kill, got %d bytes", len(raw))
	}
	cerr := stream.Close()
	if cerr == nil {
		t.Fatal("Close must fail: the producer exited non-zero (killed mid-stream)")
	}
	if got := errClass(t, cerr); got != domain.StoreErrUnknown {
		t.Errorf("class = %q, want unknown (killed producer carries no diagnostic)", got)
	}
	if !strings.Contains(cerr.Error(), "truncated") {
		t.Errorf("error must say the stream is truncated: %v", cerr)
	}
}

func TestDumpTreeTarFakeTruncatedCleanExitIsCloseClean(t *testing.T) {
	// A lying producer (partial stream, exit 0) passes the ADAPTER's
	// Close gates by design: detecting a short ARCHIVE is the parser's
	// gate, held end-to-end by lifecycle's verifyReadbackTar tests
	// (TestVerifyReadbackTarTruncatedStreamLyingExitZero).
	s := fakeProducerStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := s.DumpTreeTar(ctx, t.TempDir(), "pw", fakeSnap, "/truncexit0")
	if err != nil {
		t.Fatalf("DumpTreeTar: %v", err)
	}
	if _, rerr := io.ReadAll(stream); rerr != nil {
		t.Fatalf("read: %v", rerr)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("Close on a fully-consumed exit-0 stream: %v", err)
	}
}

func TestDumpTreeTarFakeUnconsumedStreamFailsClose(t *testing.T) {
	s := fakeProducerStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := s.DumpTreeTar(ctx, t.TempDir(), "pw", fakeSnap, "/truncexit0")
	if err != nil {
		t.Fatalf("DumpTreeTar: %v", err)
	}
	buf := make([]byte, 512)
	if _, rerr := stream.Read(buf); rerr != nil {
		t.Fatalf("first read: %v", rerr)
	}
	cerr := stream.Close()
	if cerr == nil {
		t.Fatal("Close must fail: the stream was abandoned before EOF (§11.4 full-consumption gate)")
	}
	if !strings.Contains(cerr.Error(), "consumed") {
		t.Errorf("error must name the consumption gate: %v", cerr)
	}
	if cerr2 := stream.Close(); cerr2 != cerr {
		t.Errorf("Close must be idempotent: %v vs %v", cerr2, cerr)
	}
}

func TestDumpTreeTarFakeAbortedConsumerFailsProducer(t *testing.T) {
	s := fakeProducerStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := s.DumpTreeTar(ctx, t.TempDir(), "pw", fakeSnap, "/block")
	if err != nil {
		t.Fatalf("DumpTreeTar: %v", err)
	}
	buf := make([]byte, 8192)
	if _, rerr := stream.Read(buf); rerr != nil {
		t.Fatalf("first read: %v", rerr)
	}
	// Abort without draining: the producer is mid-write into the pipe;
	// Close must not hang and must report the failed producer.
	done := make(chan error, 1)
	go func() { done <- stream.Close() }()
	select {
	case cerr := <-done:
		if cerr == nil {
			t.Fatal("Close must report the aborted producer (pipe-ended write, exit != 0)")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Close hung: closing the read end must unblock the producer")
	}
}

func TestDumpTreeTarFakeFatalClassification(t *testing.T) {
	s := fakeProducerStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, tc := range []struct {
		path string
		want domain.StoreErrorClass
		note string
	}{
		{"/fatal", domain.StoreErrUsage, "bad tree path (plain-text Fatal)"},
		{"/badid", domain.StoreErrUsage, "bad snapshot id (no matching ID found)"},
	} {
		stream, err := s.DumpTreeTar(ctx, t.TempDir(), "pw", fakeSnap, tc.path)
		if err != nil {
			t.Fatalf("%s: DumpTreeTar: %v", tc.note, err)
		}
		if _, rerr := io.ReadAll(stream); rerr != nil {
			t.Fatalf("%s: read: %v", tc.note, rerr)
		}
		cerr := stream.Close()
		if cerr == nil {
			t.Fatalf("%s: Close must fail", tc.note)
		}
		if got := errClass(t, cerr); got != tc.want {
			t.Errorf("%s: class %q want %q (%v)", tc.note, got, tc.want, cerr)
		}
	}
}

func TestDumpTreeTarClientSideValidation(t *testing.T) {
	// Usage errors surface BEFORE any subprocess: the binary below never
	// runs (a spawn failure would classify as unknown instead).
	s := New(filepath.Join(t.TempDir(), "no-such-restic-binary"))
	t.Cleanup(s.Close)
	ctx := context.Background()

	if _, err := s.DumpTreeTar(ctx, "repo", "pw", "short", "/"); err == nil ||
		errClass(t, err) != domain.StoreErrUsage {
		t.Errorf("bad snapshot id: err = %v", err)
	}
	if _, err := s.DumpTreeTar(ctx, "repo", "pw", fakeSnap, ""); err == nil ||
		errClass(t, err) != domain.StoreErrUsage {
		t.Errorf("empty path: err = %v", err)
	}
	if _, err := s.DumpTreeTar(ctx, "repo", "pw", fakeSnap, `ws\a.txt`); err == nil ||
		errClass(t, err) != domain.StoreErrUsage {
		t.Errorf("backslash path: err = %v", err)
	}
	if _, err := s.DumpTreeTar(ctx, "repo", "pw", fakeSnap, "/ws/../etc"); err == nil ||
		errClass(t, err) != domain.StoreErrUsage {
		t.Errorf("dotdot path: err = %v", err)
	}
}

// ---- conformance against the real restic binary --------------------------

// TestDumpTreeTarResticConformance pins the whole-tree dump against real
// restic 0.19.1: "/" streams every top-level prefix in ONE subprocess,
// members match the Ls listing, content digests match the source files,
// Close is clean, and repeated dumps are byte-identical.
func TestDumpTreeTarResticConformance(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	base := t.TempDir()
	ws := filepath.Join(base, "ws")
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(ws, "emptydir"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"ws/a.txt":          "conformance a\n",
		"ws/sub/b.txt":      "conformance b\n",
		"ws/ünïcødé-文件.txt": "unicode\n",
		"ws/zero.txt":       "",
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(rel)), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ref, err := s.Snapshot(ctx, repoDir, base, []string{"ws"}, passfile, nil)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	dump := func() []byte {
		stream, derr := s.DumpTreeTar(ctx, repoDir, passfile, ref.BackendID, "/")
		if derr != nil {
			t.Fatalf("DumpTreeTar: %v", derr)
		}
		raw, rerr := io.ReadAll(stream)
		if rerr != nil {
			t.Fatalf("read: %v", rerr)
		}
		if cerr := stream.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
		return raw
	}
	first := dump()

	// Members match the Ls listing exactly (names without the leading
	// slash, kinds, sizes) — the coverage side of the same tree.
	ls, err := s.Ls(ctx, repoDir, passfile, ref.BackendID)
	if err != nil {
		t.Fatalf("ls: %v", err)
	}
	lsByName := map[string]domain.TreeEntry{}
	for _, e := range ls {
		lsByName[strings.TrimPrefix(e.Path, "/")] = e
	}
	// Member names normalized exactly like the readback matcher: no
	// leading slash, and restic writes DIRECTORY members with a trailing
	// slash ("ws/") that Go's reader keeps (probe, raw-block verified).
	norm := func(name string) string { return strings.Trim(strings.TrimPrefix(name, "/"), "/") }
	hdrByName := map[string]*tar.Header{}
	var content = map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(first))
	for {
		hdr, nerr := tr.Next()
		if nerr == io.EOF {
			break
		}
		if nerr != nil {
			t.Fatalf("tar parse: %v", nerr)
		}
		hdrByName[norm(hdr.Name)] = hdr
		if hdr.Typeflag == tar.TypeReg {
			body, derr := io.ReadAll(tr)
			if derr != nil {
				t.Fatalf("member %s: %v", hdr.Name, derr)
			}
			content[norm(hdr.Name)] = body
		}
	}
	if len(hdrByName) != len(lsByName) {
		t.Fatalf("tar members = %d, ls entries = %d", len(hdrByName), len(lsByName))
	}
	for name, e := range lsByName {
		hdr, ok := hdrByName[name]
		if !ok {
			t.Errorf("ls entry %q missing from the tar dump", name)
			continue
		}
		switch e.Kind {
		case domain.KindFile:
			if hdr.Typeflag != tar.TypeReg {
				t.Errorf("%s: tar type %q for a file", name, string(hdr.Typeflag))
			}
			if hdr.Size != e.Size {
				t.Errorf("%s: tar size %d, ls size %d", name, hdr.Size, e.Size)
			}
			src := files[name]
			if sum := fmt.Sprintf("%x", sha256.Sum256(content[name])); sum != fmt.Sprintf("%x", sha256.Sum256([]byte(src))) {
				t.Errorf("%s: tar content digest differs from the source file", name)
			}
		case domain.KindDir:
			if hdr.Typeflag != tar.TypeDir {
				t.Errorf("%s: tar type %q for a dir", name, string(hdr.Typeflag))
			}
		}
	}
	// Determinism (probe): two dumps of the same snapshot are identical.
	if second := dump(); !bytes.Equal(first, second) {
		t.Error("two whole-tree dumps of the same snapshot differ")
	}
}
