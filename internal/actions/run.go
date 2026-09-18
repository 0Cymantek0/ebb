package actions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// captureLimit is the per-stream bounded capture: the ring keeps the
// first 64 KiB plus the last 64 KiB and counts what it dropped.
const captureLimit = 64 << 10

// waitDelay bounds how long Wait keeps draining output pipes after the
// process is killed (grandchildren holding the pipes cannot hang us).
const waitDelay = 5 * time.Second

// Stream identifies one child output stream.
type Stream int

const (
	StreamStdout Stream = iota + 1
	StreamStderr
)

// String names the stream for logs and excerpts.
func (s Stream) String() string {
	switch s {
	case StreamStdout:
		return "stdout"
	case StreamStderr:
		return "stderr"
	}
	return fmt.Sprintf("stream(%d)", int(s))
}

// OutputSink is a callback receiving raw chunks of child output as they
// are captured. Callbacks must return promptly and must not retain the
// chunk. A nil OutputSink is legal and discards everything beyond the
// bounded capture (the default). Use WriterSink to bridge an io.Writer.
type OutputSink func(stream Stream, chunk []byte)

// WriterSink returns an OutputSink forwarding both streams, merged, to w.
// The writer receives unbounded output; bounding is the caller's
// responsibility.
func WriterSink(w io.Writer) OutputSink {
	return func(_ Stream, chunk []byte) {
		_, _ = w.Write(chunk)
	}
}

// Result reports one completed (or killed) execution. A non-zero exit
// code is NOT an error: it is captured here with err == nil. Errors are
// reserved for refusals (approval, validation, missing inputs/outputs)
// and infrastructure failures.
type Result struct {
	// ExitCode is the child's exit code (-1 when it could not be
	// observed, e.g. after a kill).
	ExitCode int
	// Duration measures process start to wait completion.
	Duration time.Duration
	// OutputExcerpt is the bounded capture: the first and last 64 KiB of
	// each stream with a drop marker, labeled per stream.
	OutputExcerpt string
	// ToolUsed is the resolved, hashed executable that ran.
	ToolUsed ToolIdentity
	// ShellWarning is true when the action's argv[0] is a shell binary;
	// run logs must then also display ShellWarningMarker.
	ShellWarning bool
}

// Runner executes approved action definitions. The zero value is ready
// to use; it holds no state. The Runner has no delete API and never
// will: see the package documentation and TestNoDeletionAuthority.
type Runner struct{}

// New returns a ready Runner.
func New() *Runner { return &Runner{} }

// Run executes one definition under wsRoot after enforcing the full
// approval pipeline:
//
//  1. the definition is validated (an unvalidated Definition can never
//     reach exec — the same rules are re-enforced immediately before the
//     process starts);
//  2. argv[0] is resolved through PATH and the executable is hashed;
//  3. every declared input is digested (missing input: *ErrInputMissing,
//     no exec);
//  4. the approver must return an approval exactly matching the
//     resolution (*ErrApprovalRequired / *ErrApprovalStale otherwise,
//     no exec);
//  5. the literal argv runs with cmd.Dir = wsRoot/WorkingRoot, the OS
//     substrate environment plus ONLY the EnvAllow keys pulled from the
//     parent process env, /dev/null stdin, a context timeout and bounded
//     output capture forwarded to the optional sink;
//  6. every declared output must exist afterwards (*ErrOutputMissing).
//
// Timeout kills the DIRECT child only. exec.CommandContext kills the
// child process; on Windows grandchildren are not part of its job, so a
// action that spawns detached helpers may leave them running. This is a
// documented v1 limitation (Foundation §9.5: no sandbox is implied);
// cmd.WaitDelay at least guarantees Run returns. A future isolation
// provider is the stronger execution path, not a change here.
func (r *Runner) Run(ctx context.Context, def Definition, wsRoot string, appr Approver, capture OutputSink) (Result, error) {
	if appr == nil {
		return Result{}, fmt.Errorf("actions: nil approver: action %q cannot run unapproved", def.ID)
	}
	if err := def.Validate(); err != nil {
		return Result{}, err
	}
	if !filepath.IsAbs(wsRoot) {
		return Result{}, fmt.Errorf("actions: workspace root must be absolute, got %q", wsRoot)
	}
	wsRoot = filepath.Clean(wsRoot)

	// 1. Resolve the tool and pin its identity.
	tool, err := ResolveTool(def.Argv[0])
	if err != nil {
		return Result{}, err
	}

	// 2. Digest every declared input under the workspace root.
	inputDigests := make(map[string]string, len(def.Inputs))
	for _, rel := range def.Inputs {
		d, err := DigestFile(filepath.Join(wsRoot, filepath.FromSlash(rel)))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return Result{}, &ErrInputMissing{Path: rel, Err: err}
			}
			return Result{}, err
		}
		inputDigests[rel] = d
	}

	// 3. Require an exact local approval. Unapproved or stale: no exec.
	approval, err := appr.Matches(def, tool, inputDigests)
	if err != nil {
		return Result{}, err
	}
	if approval == nil {
		return Result{}, fmt.Errorf("actions: approver returned neither an approval nor an error for action %q", def.ID)
	}

	// 4. Re-validate immediately before execution (Foundation §9.5:
	// inputs and executables are revalidated immediately before use).
	// The approval above matched digests taken BEFORE this point, so a
	// concurrent writer could still swap an input file or the tool
	// binary in the window between hashing and Start. Re-digest inputs
	// and re-resolve/re-hash the tool NOW and refuse on any drift
	// (ACT-TOCTOU-1 / ACT-TOOLRACE-1). This narrows the race to the
	// final span between these reads and execve; a fully closed window
	// needs an OS-level exec-from-handle provider, which v1 does not
	// claim.
	if err := def.Validate(); err != nil {
		return Result{}, err
	}
	retool, err := ResolveTool(def.Argv[0])
	if err != nil {
		return Result{}, fmt.Errorf("actions: action %q: pre-exec tool revalidation: %w", def.ID, err)
	}
	if retool.ResolvedPath != tool.ResolvedPath || retool.SHA256 != tool.SHA256 {
		return Result{}, fmt.Errorf("actions: action %q: executable changed between approval and execution (%q -> %q): refusing", def.ID, tool.ResolvedPath, retool.ResolvedPath)
	}
	for _, rel := range def.Inputs {
		d, err := DigestFile(filepath.Join(wsRoot, filepath.FromSlash(rel)))
		if err != nil {
			return Result{}, fmt.Errorf("actions: action %q: pre-exec input revalidation of %q: %w", def.ID, rel, err)
		}
		if d != inputDigests[rel] {
			return Result{}, fmt.Errorf("actions: action %q: input %q changed between approval and execution: refusing", def.ID, rel)
		}
	}

	workDir := wsRoot
	if def.WorkingRoot != "" && def.WorkingRoot != "." {
		workDir = filepath.Join(wsRoot, filepath.FromSlash(def.WorkingRoot))
	}
	if _, err := os.Stat(workDir); err != nil {
		return Result{}, fmt.Errorf("actions: action %q: working dir %q: %w", def.ID, def.WorkingRoot, err)
	}

	env := childEnv(os.Environ(), def.EnvAllow)

	cctx, cancel := context.WithTimeout(ctx, def.Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, tool.ResolvedPath, def.Argv[1:]...)
	cmd.Dir = workDir
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return Result{}, fmt.Errorf("actions: open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()
	cmd.Stdin = devNull

	outCap := newCaptureStream(captureLimit)
	errCap := newCaptureStream(captureLimit)
	cmd.Stdout = &outputWriter{ring: outCap, sink: capture, stream: StreamStdout}
	cmd.Stderr = &outputWriter{ring: errCap, sink: capture, stream: StreamStderr}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("actions: action %q: start %q: %w", def.ID, tool.ResolvedPath, err)
	}
	waitErr := cmd.Wait()
	duration := time.Since(start)

	res := Result{
		ExitCode:      exitCode(waitErr),
		Duration:      duration,
		OutputExcerpt: formatExcerpt(outCap, errCap),
		ToolUsed:      tool,
		ShellWarning:  def.IsShell(),
	}

	// Cancellation by the caller outranks the action's own timeout.
	if ctx.Err() != nil {
		return res, fmt.Errorf("actions: action %q canceled by caller: %w", def.ID, ctx.Err())
	}
	if cctx.Err() == context.DeadlineExceeded {
		return res, &ErrTimeout{ActionID: def.ID, Timeout: def.Timeout}
	}
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			// The child ran and exited non-zero: a result, not an error.
			return res, nil
		}
		return res, fmt.Errorf("actions: action %q: wait: %w", def.ID, waitErr)
	}

	// 5. Every declared output must exist.
	var missing []string
	for _, rel := range def.Outputs {
		if _, err := os.Stat(filepath.Join(wsRoot, filepath.FromSlash(rel))); err != nil {
			missing = append(missing, rel)
		}
	}
	if len(missing) > 0 {
		return res, &ErrOutputMissing{Outputs: missing}
	}
	return res, nil
}

// exitCode extracts the child's exit code, 0 on clean exit and -1 when
// unobservable.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// substrateKeys lists the OS environment keys every action receives
// beyond its allowlist (Foundation §9.5 "allowed inherited environment
// keys"). Everything else from the parent environment is dropped by
// construction, following the D004 scrub precedent.
func substrateKeys() []string {
	if runtime.GOOS == "windows" {
		return []string{"PATH", "SYSTEMROOT", "COMSPEC", "TEMP", "TMP", "PATHEXT"}
	}
	return []string{"PATH", "TMPDIR", "LANG", "LC_ALL", "TZ"}
}

// envKeyMatches compares an env name against a wanted name using the
// platform's env-name matching rules (case-insensitive on Windows).
func envKeyMatches(name, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, want)
	}
	return name == want
}

// childEnv builds the child environment from scratch: the OS substrate
// plus the allowlisted keys, each pulled from the parent process
// environment (never from files). First spelling wins; keys absent from
// the parent are simply absent from the child.
func childEnv(parent []string, allow []string) []string {
	wanted := substrateKeys()
	wanted = append(wanted, allow...)
	out := make([]string, 0, len(wanted))
	for _, want := range wanted {
		for _, kv := range parent {
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				continue
			}
			if envKeyMatches(kv[:eq], want) {
				out = append(out, kv)
				break
			}
		}
	}
	return out
}

// captureStream is a bounded ring: the first limit bytes are kept whole,
// the last limit bytes are kept as a sliding tail, and everything pushed
// out of the middle is counted as dropped.
type captureStream struct {
	limit   int
	head    []byte
	tail    []byte
	dropped int64
}

func newCaptureStream(limit int) *captureStream {
	return &captureStream{limit: limit}
}

func (c *captureStream) Write(p []byte) (int, error) {
	n := len(p)
	if len(c.head) < c.limit {
		take := c.limit - len(c.head)
		if take > len(p) {
			take = len(p)
		}
		c.head = append(c.head, p[:take]...)
		p = p[take:]
	}
	if len(p) > 0 {
		c.tail = append(c.tail, p...)
		if len(c.tail) > c.limit {
			cut := len(c.tail) - c.limit
			c.dropped += int64(cut)
			c.tail = c.tail[cut:]
		}
	}
	return n, nil
}

// excerpt renders the bounded capture; the marker makes truncation
// visible instead of silent.
func (c *captureStream) excerpt() string {
	if c.dropped == 0 {
		return string(c.head) + string(c.tail)
	}
	return string(c.head) +
		fmt.Sprintf("\n[... %d bytes dropped; first and last %d KiB kept ...]\n", c.dropped, c.limit>>10) +
		string(c.tail)
}

// outputWriter pipes one child stream into the ring capture and the
// optional live sink.
type outputWriter struct {
	ring   *captureStream
	sink   OutputSink
	stream Stream
}

func (w *outputWriter) Write(p []byte) (int, error) {
	if w.sink != nil {
		w.sink(w.stream, p)
	}
	return w.ring.Write(p)
}

// formatExcerpt labels each non-empty stream capture.
func formatExcerpt(out, errOut *captureStream) string {
	var b strings.Builder
	if o := out.excerpt(); o != "" {
		b.WriteString("--- stdout ---\n")
		b.WriteString(o)
		if !strings.HasSuffix(o, "\n") {
			b.WriteByte('\n')
		}
	}
	if e := errOut.excerpt(); e != "" {
		b.WriteString("--- stderr ---\n")
		b.WriteString(e)
		if !strings.HasSuffix(e, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
