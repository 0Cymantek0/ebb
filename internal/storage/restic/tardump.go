package resticstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// Whole-tree tar dump transport (Foundation §11.4 "Readback", §14.3
// "avoid one subprocess per file"). Every behavior below is pinned by
// lab/restic-probe/tar-dump/FINDINGS.md (restic 0.19.1, live probe):
//
//   - `dump --archive tar <snapID> /` streams the WHOLE snapshot tree —
//     every top-level prefix (workspace AND op dir) — from ONE subprocess.
//     "/" is the whole-tree spelling; "./" is refused by restic.
//   - stdout is pure tar, stderr is empty on success, and two dumps of
//     the same snapshot are byte-identical.
//   - Member names are rooted at the snapshot tree root WITHOUT the
//     leading slash ("ws/file.txt"); regular members are type '0', dirs
//     '5' (empty dirs included, size 0), links '2' with the stored link
//     text; hardlinks are duplicated as two full regular members.
//   - The archive ends with exactly two all-zero 512-byte blocks and a
//     parser may stop one block early, so a consumer draining past the
//     end-of-archive marker must tolerate all-zero trailing bytes.
//   - A producer killed mid-stream leaves the reader a clean EOF with
//     exit code 1 and EMPTY stderr — the producer-exit gate and the
//     parser-completion gate are each independently load-bearing (§11.4
//     demands both). A reader that stops consuming fails the producer
//     ("write /dev/stdout: The pipe has been ended."), which Close must
//     report, never swallow.
//   - Failure spellings (all exit 1, plain text on stderr) reuse the
//     existing DumpFile classifications: "cannot dump file" and "not
//     found in snapshot" (bad path / link node), "no matching ID found"
//     (bad snapshot id, same string refineLsError matches).

// DumpTreeTar streams the tree at treePath as a tar archive WITHOUT
// buffering it (treePath uses the same normalization as DumpFile; "/"
// dumps the whole snapshot — one subprocess covers every prefix).
//
// The returned reader must be consumed to EOF and then Closed. Close is
// the producer-exit gate: it verifies restic exited 0 AND that the caller
// read through the stream's end; a stream abandoned mid-read or a failed
// producer surfaces as a typed StoreError there (a truncated archive
// additionally surfaces at read time through the tar parser's unexpected
// EOF — both gates are required, §11.4).
func (s *Store) DumpTreeTar(ctx context.Context, repoDir, passfile, snapID, treePath string) (io.ReadCloser, error) {
	dump, err := normalizeDumpPath(treePath)
	if err != nil {
		return nil, err
	}
	if !isSnapshotID(snapID) {
		return nil, storeErr(domain.StoreErrUsage, "resticstore: snapshot id %q is not 8-64 hex characters", snapID)
	}
	env, eerr := s.envFor(passfile)
	if eerr != nil {
		return nil, storeErr(domain.StoreErrUnknown, "resticstore: %v", eerr)
	}
	// The runner's scoped timeout does not fit a stream the caller still
	// owns: the timeout context rides the stream and its cancel is
	// released at Close. (A caller that loses the stream without closing
	// is still bounded — the deadline kills the child.)
	tctx := ctx
	var cancel context.CancelFunc
	if s.timeout > 0 {
		tctx, cancel = context.WithTimeout(ctx, s.timeout)
	}

	pr, pw, perr := os.Pipe()
	if perr != nil {
		if cancel != nil {
			cancel()
		}
		return nil, storeErr(domain.StoreErrUnknown, "resticstore: tar dump pipe: %v", perr)
	}
	cmd := exec.CommandContext(tctx, s.binary, "--repo", repoDir, "dump", "--archive", "tar", snapID, dump)
	cmd.Env = env
	cmd.Stdout = pw
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	// Kill the process the moment the context is done; WaitDelay makes
	// Wait return even if a grandchild holds the pipes open (the same
	// discipline as the buffered runner in run()).
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 10 * time.Second
	cmd.SysProcAttr = procAttr()

	if serr := cmd.Start(); serr != nil {
		pr.Close()
		pw.Close()
		if cancel != nil {
			cancel()
		}
		return nil, storeErr(domain.StoreErrUnknown, "resticstore: run %s: %w",
			argvLabel([]string{"dump", "--archive", "tar", snapID, dump}), serr)
	}
	// The child owns its inherited write end from here; the parent's copy
	// must go NOW, or the read end would never observe EOF (a parent-held
	// write end keeps the pipe open forever).
	pw.Close()

	return &tarDumpStream{
		pr: pr, cmd: cmd, cancel: cancel, stderr: stderr,
		label: fmt.Sprintf("dump --archive tar %s %s", snapID, dump),
	}, nil
}

// tarDumpStream is the streaming read side of one `dump --archive tar`
// subprocess. It is single-consumer by construction (one verification
// walk); Close is idempotent.
type tarDumpStream struct {
	pr     *os.File
	cmd    *exec.Cmd
	cancel context.CancelFunc
	stderr *bytes.Buffer
	label  string

	eofSeen   bool
	closeOnce sync.Once
	closeErr  error
}

// Read passes bytes through and records whether the consumer reached the
// producer's end of stream.
func (t *tarDumpStream) Read(p []byte) (int, error) {
	n, err := t.pr.Read(p)
	if err == io.EOF {
		t.eofSeen = true
	}
	return n, err
}

// Close releases the pipe and enforces the §11.4 producer gates.
func (t *tarDumpStream) Close() error {
	t.closeOnce.Do(func() { t.closeErr = t.close() })
	return t.closeErr
}

func (t *tarDumpStream) close() error {
	// Close the read end FIRST: it unblocks a producer still writing into
	// a full pipe (an aborted consumer must not deadlock Close) and fails
	// it with a pipe-ended write (probed), which Wait then reports.
	_ = t.pr.Close()
	werr := t.cmd.Wait()
	if t.cancel != nil {
		t.cancel()
	}

	if werr != nil {
		exit := -1
		var exitErr *exec.ExitError
		if errors.As(werr, &exitErr) && t.cmd.ProcessState != nil {
			if code := t.cmd.ProcessState.ExitCode(); code >= 0 {
				exit = code
			}
		}
		// A killed producer dies with a generic exit and EMPTY stderr
		// (probed) — the classification below then lands on "unknown",
		// which is honest: the stream is truncated, nothing better is
		// known.
		class := classForFailure(exit, t.stderr.Bytes())
		low := strings.ToLower(t.stderr.String())
		switch {
		case strings.Contains(low, "cannot dump file"),
			strings.Contains(low, "not found in snapshot"),
			strings.Contains(low, "no matching id found"),
			strings.Contains(low, "no snapshot matched"):
			class = domain.StoreErrUsage
		}
		return storeErr(class,
			"resticstore: %s failed (exit %d, wait error %v); the tar stream is truncated and must not be trusted\nstderr:\n%s",
			t.label, exit, werr, excerpt(t.stderr.Bytes(), stderrExcerptLimit))
	}
	if !t.eofSeen {
		return storeErr(domain.StoreErrUnknown,
			"resticstore: %s: stream closed before the producer's end of stream was consumed (Foundation §11.4 requires producer exit status AND parser completion)", t.label)
	}
	return nil
}
