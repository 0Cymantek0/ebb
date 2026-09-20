// fakedocker is the fake docker CLI for the freezer tests (D040 tier 3).
// It is compiled on demand by freeze_test.go (`go build`) and driven by
// control files in $FAKE_BIN_DIR — the ONE test-seam variable the
// freezer's docker environment passes through (a real docker CLI ignores
// it). Every invocation appends events to $FAKE_BIN_DIR/docker.log so
// tests assert the exact subprocess discipline: what started, what a
// consumer actually drank, and how each producer exited.
//
// Control files (presence = on; numeric files carry a value):
//
//	version-fail      `docker version` exits 1 (daemon unreachable)
//	inspect-missing   `image inspect` exits 1 (unknown image)
//	size              inspect Size field (bytes; default 65536)
//	save-bytes        total deterministic payload for `save` (default 1 MiB)
//	slow-ms           per-chunk write delay in `save` (cancellation window)
//	save-fail-after   `save` exits 1 after N written bytes (mid-stream death)
//	load-fail         `load` consumes stdin then exits 1
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
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
		full := strings.TrimPrefix(id, "sha256:")
		for len(full) < 64 {
			full += "0"
		}
		fmt.Printf("[%s]\n", fmt.Sprintf(`{"Id":"sha256:%s","Size":%d,"RepoTags":["%s"]}`, full, size, id))
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
		fmt.Printf("Untagged: %s\n", strings.Join(os.Args[2:], " "))
		logf("rmi-done %s", strings.Join(os.Args[2:], " "))

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
