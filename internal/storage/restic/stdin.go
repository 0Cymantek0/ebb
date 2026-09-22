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

// Stdin capture and single-blob readback (D040 tier 3, the Freeze-to-Vault
// cold-storage pipeline). Both directions are PURE STREAMS: the bytes move
// through pipes between the producer (`docker save`) and restic, and back
// out on restore (`restic dump | docker load`); nothing is staged on disk
// and nothing is buffered whole in memory (Foundation §14.1: a 20 GiB
// image must not need 20 GiB of headroom anywhere in Ebb).
//
//   - `backup --stdin --stdin-filename <name>` stores ONE regular file
//     named <name> at the snapshot tree root; the tree path of the blob is
//     therefore /<name>. The filename is validated client-side (a clean
//     single path segment) because restic accepts far looser spellings
//     than the freeze contract ever needs.
//   - A producer that dies mid-stream gives restic a clean early EOF:
//     restic stores the TRUNCATED prefix and exits 0. The subprocess
//     runner therefore treats a stdin COPY error as a capture failure even
//     when restic itself succeeded — the copied-bytes count and the error
//     are reported, and any summary snapshot id is named INCOMPLETE the
//     same way Snapshot names source-error snapshots (probe Q4a posture:
//     a stored id never authorizes anything).
//   - DumpBlob is the streaming counterpart of DumpFile for blobs that do
//     not fit memory: `dump <snapID> /<name>` with stdout wired to an
//     os.Pipe, under the same two independent §11.4 gates as DumpTreeTar
//     (producer exit status AND consumer EOF), plus snapshot-id and path
//     validation on every read.

// BackupStdin streams src into one restic snapshot as a single file named
// filename (the --stdin-filename). tags ride the same ebb:v1 + op-tag
// conventions as Snapshot. The caller's src is connected to the child's
// stdin directly when it is an *os.File (no intermediate copying
// goroutine); otherwise exec copies it.
//
// Failure contract (Foundation §11.2): a non-zero exit, any stderr
// {"message_type":"error"} record, a missing summary or a dry-run summary
// fails the capture EVEN THOUGH restic may have stored a snapshot; the
// returned error names its id as INCOMPLETE. A src that fails mid-stream
// (producer death) is reported as a source failure with the byte count
// that actually crossed the pipe.
func (s *Store) BackupStdin(ctx context.Context, repoDir, passfile, filename string, src io.Reader, tags map[string]string) (domain.SnapshotRef, error) {
	if err := validateStdinFilename(filename); err != nil {
		return domain.SnapshotRef{}, err
	}
	if src == nil {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUsage, "resticstore: BackupStdin requires a non-nil source reader")
	}
	tagArgs, tagMap, err := encodeTags(tags)
	if err != nil {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUsage, "resticstore: %v", err)
	}
	env, err := s.envFor(passfile)
	if err != nil {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUnknown, "resticstore: %v", err)
	}

	// The scoped timeout still applies: the whole stdin capture is one
	// subprocess, owned start to finish by this call (unlike DumpBlob,
	// whose stream outlives it).
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	argv := append([]string{"--repo", repoDir, "backup", "--json", "--host", backupHost}, tagArgs...)
	argv = append(argv, "--stdin", "--stdin-filename", filename)

	cmd := exec.CommandContext(ctx, s.binary, argv...)
	cmd.Env = env
	cmd.Stdin = src
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 10 * time.Second
	cmd.SysProcAttr = procAttr()

	runErr := cmd.Run()
	res := cmdResult{exit: -1, stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	var exitErr *exec.ExitError
	hasExitErr := errors.As(runErr, &exitErr)
	switch {
	case runErr == nil:
		res.exit = cmd.ProcessState.ExitCode()
	case hasExitErr:
		if code := cmd.ProcessState.ExitCode(); code >= 0 {
			res.exit = code
		}
	}

	// A src read failure surfaces as runErr WITHOUT an ExitError (the
	// copy goroutine aborted the command): restic observed a clean early
	// EOF and likely stored the truncated prefix. This is a source
	// failure no matter what restic's own exit says.
	copyFailed := runErr != nil && !hasExitErr && ctx.Err() == nil

	summary, _, perr := parseBackupSummary(res.stdout)
	sc := scanStderr(res.stderr)

	failed := res.exit != 0 || perr != nil || len(sc.errRecords) > 0 || copyFailed
	if !failed && summary != nil && summary.DryRun {
		failed = true // Ebb never passes --dry-run; a dry-run summary proves nothing
	}
	if failed {
		class := classForFailure(res.exit, res.stderr)
		switch {
		case copyFailed:
			class = domain.StoreErrSource
		case res.exit == 0 && len(sc.errRecords) > 0:
			class = domain.StoreErrSource
		}
		var b strings.Builder
		fmt.Fprintf(&b, "restic backup --stdin failed (exit %d)", res.exit)
		if copyFailed {
			fmt.Fprintf(&b, ": the source stream failed mid-copy (%v); restic observed an early EOF and any stored snapshot holds a TRUNCATED prefix", runErr)
		} else if perr != nil {
			fmt.Fprintf(&b, ": %v", perr)
		}
		if summary != nil && summary.SnapshotID != "" {
			fmt.Fprintf(&b, "; an INCOMPLETE snapshot %s was stored and must never be used as a capture", summary.SnapshotID)
		}
		for _, m := range sc.errRecords {
			fmt.Fprintf(&b, "\n  source error: %s", m)
		}
		if sc.exitMsg != "" {
			fmt.Fprintf(&b, "\n  exit_error: %s", sc.exitMsg)
		}
		if repoLocked(res.stderr) {
			fmt.Fprintf(&b, "\n  repository is locked by another process; Ebb never removes backend locks automatically")
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			fmt.Fprintf(&b, "\n  context: %v", ctxErr)
		}
		fmt.Fprintf(&b, "\nstderr:\n%s", excerpt(res.stderr, stderrExcerptLimit))
		return domain.SnapshotRef{}, storeErr(class, "%s", b.String())
	}

	if !isHexID(summary.SnapshotID, 64) {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUnknown,
			"resticstore: backup --stdin summary snapshot_id %q is not a full 64-hex id", summary.SnapshotID)
	}
	return domain.SnapshotRef{
		BackendID: summary.SnapshotID,
		ShortID:   summary.SnapshotID[:8],
		Time:      summary.BackupEnd,
		Paths:     []string{"/" + filename},
		Tags:      tagMap,
	}, nil
}

// DumpBlob streams one stored file's content out of the snapshot WITHOUT
// buffering it (the single-blob counterpart of DumpFile for GiB-scale
// images; path uses the same normalization, and "/" + filename is the
// tree path BackupStdin created).
//
// The returned reader must be consumed to EOF and then Closed. Close is
// the producer-exit gate: it verifies restic exited 0 AND that the caller
// read through the end of stream — the two independent §11.4 gates. A
// stream abandoned mid-read surfaces as a typed StoreError at Close,
// never as a silent partial success.
func (s *Store) DumpBlob(ctx context.Context, repoDir, passfile, snapID, filename string) (io.ReadCloser, error) {
	dump, err := normalizeDumpPath(filename)
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
	// owns: the deadline rides the stream and its cancel is released at
	// Close (same discipline as DumpTreeTar).
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
		return nil, storeErr(domain.StoreErrUnknown, "resticstore: blob dump pipe: %v", perr)
	}
	cmd := exec.CommandContext(tctx, s.binary, "--repo", repoDir, "dump", snapID, dump)
	cmd.Env = env
	cmd.Stdout = pw
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
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
			argvLabel([]string{"dump", snapID, dump}), serr)
	}
	// The child owns the inherited write end now; the parent's copy must
	// go immediately or the read end would never see EOF.
	pw.Close()

	return &blobDumpStream{
		pr: pr, cmd: cmd, tctx: tctx, cancel: cancel, stderr: stderr,
		label: fmt.Sprintf("dump %s %s", snapID, dump),
	}, nil
}

// blobDumpStream is the streaming read side of one raw `dump` subprocess
// (no --archive wrapper: stdout is the file's content bytes). It is
// single-consumer by construction; Close is idempotent.
type blobDumpStream struct {
	pr     *os.File
	cmd    *exec.Cmd
	tctx   context.Context
	cancel context.CancelFunc
	stderr *bytes.Buffer
	label  string

	eofSeen   bool
	closeOnce sync.Once
	closeErr  error
}

// Read passes bytes through and records whether the consumer reached the
// producer's end of stream.
func (b *blobDumpStream) Read(p []byte) (int, error) {
	n, err := b.pr.Read(p)
	if err == io.EOF {
		b.eofSeen = true
	}
	return n, err
}

// Close releases the pipe and enforces the §11.4 producer gates.
func (b *blobDumpStream) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.close() })
	return b.closeErr
}

func (b *blobDumpStream) close() error {
	// Close the read end FIRST: it unblocks a producer still writing into
	// a full pipe and fails it with a pipe-ended write, which Wait then
	// reports (the same teardown discipline as DumpTreeTar).
	_ = b.pr.Close()
	werr := b.cmd.Wait()
	if b.cancel != nil {
		b.cancel()
	}

	if werr != nil {
		exit := -1
		var exitErr *exec.ExitError
		if errors.As(werr, &exitErr) && b.cmd.ProcessState != nil {
			if code := b.cmd.ProcessState.ExitCode(); code >= 0 {
				exit = code
			}
		}
		class := classForFailure(exit, b.stderr.Bytes())
		low := strings.ToLower(b.stderr.String())
		switch {
		case strings.Contains(low, "cannot dump file"),
			strings.Contains(low, "not found in snapshot"),
			strings.Contains(low, "no matching id found"),
			strings.Contains(low, "no snapshot matched"):
			class = domain.StoreErrUsage
		}
		if b.tctx != nil && b.tctx.Err() != nil {
			return storeErr(class,
				"resticstore: %s failed (exit %d, wait error %v, context %v); the blob stream is interrupted\nstderr:\n%s",
				b.label, exit, werr, b.tctx.Err(), excerpt(b.stderr.Bytes(), stderrExcerptLimit))
		}
		return storeErr(class,
			"resticstore: %s failed (exit %d, wait error %v); the blob stream is truncated and must not be trusted\nstderr:\n%s",
			b.label, exit, werr, excerpt(b.stderr.Bytes(), stderrExcerptLimit))
	}
	if !b.eofSeen {
		return storeErr(domain.StoreErrUnknown,
			"resticstore: %s: stream closed before the producer's end of stream was consumed (Foundation §11.4 requires producer exit status AND stream completion)", b.label)
	}
	return nil
}

// validateStdinFilename enforces the --stdin-filename contract
// client-side: one clean path segment (no separators, no traversal, no
// NUL); the freeze pipeline names blobs like docker-image-<64hex>.tar and
// never needs anything looser.
func validateStdinFilename(name string) error {
	if name == "" {
		return storeErr(domain.StoreErrUsage, "resticstore: --stdin-filename must not be empty")
	}
	if strings.ContainsRune(name, 0) {
		return storeErr(domain.StoreErrUsage, "resticstore: --stdin-filename contains NUL")
	}
	if strings.ContainsAny(name, "/\\") {
		return storeErr(domain.StoreErrUsage, "resticstore: --stdin-filename %q must be a single path segment (no separators)", name)
	}
	if name == "." || name == ".." {
		return storeErr(domain.StoreErrUsage, "resticstore: --stdin-filename %q must be a real file name", name)
	}
	return nil
}
