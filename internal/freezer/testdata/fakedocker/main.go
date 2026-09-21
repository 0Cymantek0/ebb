// fakedocker is the fake docker CLI for the freezer tests (D040 tier 3).
// It is compiled on demand by freeze_test.go (`go build`) and driven by
// control files in $FAKE_BIN_DIR — a test-seam variable the freezer's
// docker environment forwards ONLY when the EBB_TEST_DOCKER_BIN seam is
// active (a real docker CLI ignores it either way). Every invocation
// appends events to $FAKE_BIN_DIR/docker.log so tests assert the exact
// subprocess discipline: what started, what a consumer actually drank,
// and how each producer exited.
//
// Control files (presence = on; numeric files carry a value):
//
//	version-fail      `docker version` exits 1 (daemon unreachable)
//	inspect-missing   `image inspect` exits 1 (unknown image)
//	inspect-id        overrides the inspect record's echoed Id verbatim
//	                  (hostile-daemon simulation; empty = canonical form)
//	size              inspect Size field (bytes; default 65536)
//	save-bytes        total deterministic payload for `save` (default 1 MiB)
//	slow-ms           per-chunk write delay in `save` (cancellation window)
//	save-fail-after   `save` exits 1 after N written bytes (mid-stream death)
//	load-fail         `load` consumes stdin then exits 1
//	rmi-fail          `rmi` exits 1: value "nosuch" answers with the
//	                  daemon's "No such image" text; any other value is an
//	                  unrelated failure
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Fixture portability: the `save` producer observes the freezer's
	// teardown as a broken pipe on stdout and must log its `save-exit`
	// evidence line before exiting 1. On Windows a write into a closed
	// pipe is a plain error the switch below already handles; on Linux
	// the Go runtime KILLS fd-1/2 writers with SIGPIPE before user code
	// runs, so the producer would die a signal death with no log line
	// and the test would see an orphan-lookalike instead. Ignoring
	// SIGPIPE makes the write return EPIPE on every platform, exactly as
	// the tardump fixture already does (Wave J). No-op on Windows.
	signal.Ignore(syscall.SIGPIPE)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "fakedocker: missing subcommand")
		os.Exit(2)
	}
	dir := os.Getenv("FAKE_BIN_DIR")
	logf := func(format string, a ...any) {
		if dir == "" {
			return
		}
		f, err := os.OpenFile(filepath.Join(dir, "docker.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return
		}
		fmt.Fprintf(f, format+"\n", a...)
		f.Close()
	}
	ctl := func(name string) (string, bool) {
		if dir == "" {
			return "", false
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(b)), true
	}
	ctlInt := func(name string, def int64) int64 {
		if s, ok := ctl(name); ok {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil && n >= 0 {
				return n
			}
		}
		return def
	}

	logf("start %s", strings.Join(os.Args[1:], " "))

	switch os.Args[1] {
	case "version":
		if _, bad := ctl("version-fail"); bad {
			fmt.Fprintln(os.Stderr, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")
			logf("exit version 1")
			os.Exit(1)
		}
		fmt.Println("Docker version 27.5.1-fake, build 0000000")
		logf("exit version 0")

	case "image":
		if len(os.Args) < 4 || os.Args[2] != "inspect" {
			fmt.Fprintln(os.Stderr, "fakedocker: expected `image inspect <id>`")
			logf("exit image 2")
			os.Exit(2)
		}
		id := os.Args[3]
		if _, miss := ctl("inspect-missing"); miss {
			fmt.Fprintf(os.Stderr, "Error response from daemon: No such image: %s\n", id)
			logf("exit inspect 1")
			os.Exit(1)
		}
		size := ctlInt("size", 65536)
		echo := id
		if v, ok := ctl("inspect-id"); ok && v != "" {
			// Hostile-daemon simulation: echo the raw value verbatim
			// (properly JSON-escaped so arbitrary hostile spellings still
			// parse — the point is testing the FREEZER's validation, not
			// JSON trivia).
			echo = v
		} else {
			full := strings.TrimPrefix(id, "sha256:")
			for len(full) < 64 {
				full += "0"
			}
			echo = "sha256:" + full
		}
		doc, merr := json.Marshal(struct {
			Id       string   `json:"Id"`
			Size     int64    `json:"Size"`
			RepoTags []string `json:"RepoTags"`
		}{Id: echo, Size: size, RepoTags: []string{id}})
		if merr != nil {
			fmt.Fprintln(os.Stderr, "fakedocker inspect:", merr)
			os.Exit(1)
		}
		fmt.Printf("[%s]\n", doc)
		logf("exit inspect 0")

	case "save":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "fakedocker: expected `save <id>`")
			os.Exit(2)
		}
		total := ctlInt("save-bytes", 1<<20)
		slow := ctlInt("slow-ms", 0)
		failAfter := ctlInt("save-fail-after", -1)
		payload := make([]byte, total)
		fillDeterministic(payload)
		var written int64
		const chunk = 4096
		for written < total {
			if failAfter >= 0 && written >= failAfter {
				fmt.Fprintf(os.Stderr, "fakedocker save: simulated failure after %d bytes\n", written)
				logf("save-fail after=%d", written)
				os.Exit(1)
			}
			end := written + chunk
			if end > total {
				end = total
			}
			if _, err := os.Stdout.Write(payload[written:end]); err != nil {
				// The consumer died: the broken pipe is exactly what the
				// freezer's teardown produces; record and exit nonzero.
				logf("save-exit err=%v bytes=%d", err, written)
				os.Exit(1)
			}
			written = end
			if slow > 0 {
				time.Sleep(time.Duration(slow) * time.Millisecond)
			}
		}
		logf("save-complete bytes=%d", written)

	case "load":
		h := sha256.New()
		n, err := io.Copy(h, os.Stdin)
		if err != nil {
			logf("load-exit err=%v bytes=%d", err, n)
			fmt.Fprintf(os.Stderr, "fakedocker load: stdin read failed: %v\n", err)
			os.Exit(1)
		}
		digest := hex.EncodeToString(h.Sum(nil))
		logf("load bytes=%d digest=%s", n, digest)
		if _, fail := ctl("load-fail"); fail {
			fmt.Fprintln(os.Stderr, "fakedocker load: simulated failure")
			os.Exit(1)
		}
		fmt.Printf("Loaded image: sha256:%s\n", digest)

	case "rmi":
		target := strings.Join(os.Args[2:], " ")
		if mode, ok := ctl("rmi-fail"); ok {
			if mode == "nosuch" {
				// The real daemon's already-gone response, verbatim shape.
				fmt.Fprintf(os.Stderr, "Error response from daemon: No such image: %s\n", target)
				logf("rmi-nosuch %s", target)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "fakedocker rmi: simulated unrelated failure")
			logf("rmi-fail-other %s", target)
			os.Exit(1)
		}
		fmt.Printf("Untagged: %s\n", target)
		logf("rmi-done %s", target)

	default:
		fmt.Fprintf(os.Stderr, "fakedocker: unknown subcommand %q\n", os.Args[1])
		logf("exit %s 2", os.Args[1])
		os.Exit(2)
	}
}

// fillDeterministic fills b with the LCG byte stream the tests reproduce
// independently to compute their own digest oracle.
func fillDeterministic(b []byte) {
	next := uint32(0x9E3779B9)
	for i := range b {
		next = next*1664525 + 1013904223
		b[i] = byte(next >> 23)
	}
}
