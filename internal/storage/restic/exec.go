package resticstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// stderrExcerptLimit bounds how much captured stderr is embedded in
// returned errors (the last bytes are kept: that is where the Fatal and
// exit_error records live). Fixture paths are not secrets and are kept
// verbatim.
const stderrExcerptLimit = 8 << 10

// exitClass maps probe-verified restic exit codes to StoreError
// classes (lab/restic-probe Q4): 3 source read error (snapshot still
// created!), 10 repository missing/inaccessible, 12 wrong password /
// no key, 2 usage. Everything else — including restic's generic 1 — is
// unknown.
var exitClass = map[int]domain.StoreErrorClass{
	3:  domain.StoreErrSource,
	10: domain.StoreErrRepo,
	12: domain.StoreErrAuth,
	2:  domain.StoreErrUsage,
}

// cmdResult is the captured outcome of one restic subprocess.
type cmdResult struct {
	exit   int // -1 when the process was killed without an exit status
	stdout []byte
	stderr []byte
}

// run executes one restic subprocess with the constructed environment,
// captured streams and a hard timeout. dir may be "" (inherit cwd).
// A non-nil error means the process did not run to completion (spawn
// failure, cancelation, timeout); callers convert it to a StoreError.
func (s *Store) run(ctx context.Context, dir string, env []string, argv ...string) (cmdResult, error) {
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, s.binary, argv...)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Kill the process the moment the context is done; WaitDelay makes
	// Wait return even if a grandchild holds the pipes open.
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 10 * time.Second
	cmd.SysProcAttr = procAttr()

	err := cmd.Run()
	res := cmdResult{exit: -1, stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	if err == nil {
		res.exit = cmd.ProcessState.ExitCode()
		return res, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := cmd.ProcessState.ExitCode(); code >= 0 {
			res.exit = code
		}
		// A recorded exit status is a normal restic failure; report it
		// through res.exit so callers classify it, not as a hard error.
		if ctx.Err() == nil {
			return res, nil
		}
	}
	return res, fmt.Errorf("resticstore: run %s: %w", argvLabel(argv), err)
}

// argvLabel renders a safe one-line label of the command (the password
// is never in argv by construction).
func argvLabel(argv []string) string {
	if len(argv) == 0 {
		return "<none>"
	}
	parts := append([]string{argv[0]}, argv[1:]...)
	for i, p := range parts {
		if strings.ContainsAny(p, " \t\n\x00") {
			parts[i] = fmt.Sprintf("%q", p)
		}
	}
	return strings.Join(parts, " ")
}

// stderrScan is the machine-readable content of a stderr stream.
// restic mixes plain-text warnings with NDJSON records (probe Q3), so
// unparsable lines are simply ignored here.
type stderrScan struct {
	errRecords []string // message_type=="error" records ("during archival"...)
	exitCode   int      // from the last exit_error record, 0 if none
	exitMsg    string
}

func scanStderr(stderr []byte) stderrScan {
	var sc stderrScan
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var rec struct {
			MessageType string `json:"message_type"`
			During      string `json:"during"`
			Item        string `json:"item"`
			Error       *struct {
				Message string `json:"message"`
			} `json:"error"`
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		switch rec.MessageType {
		case "error":
			msg := ""
			if rec.Error != nil {
				msg = rec.Error.Message
			} else if rec.Message != "" {
				msg = rec.Message
			}
			if msg == "" {
				msg = "(no message)"
			}
			sc.errRecords = append(sc.errRecords, msg)
		case "exit_error":
			sc.exitCode = rec.Code
			sc.exitMsg = rec.Message
		}
	}
	return sc
}

// classForFailure maps a subprocess outcome to a StoreErrorClass.
// The exit_error JSON code on stderr is preferred over the raw process
// exit code when present (it survives shell wrappers).
func classForFailure(exit int, stderr []byte) domain.StoreErrorClass {
	sc := scanStderr(stderr)
	if class, ok := exitClass[sc.exitCode]; ok {
		return class
	}
	if class, ok := exitClass[exit]; ok {
		return class
	}
	return domain.StoreErrUnknown
}

// repoLocked reports whether stderr shows a lock-held failure.
func repoLocked(stderr []byte) bool {
	low := strings.ToLower(string(stderr))
	return strings.Contains(low, "repository is already locked") ||
		strings.Contains(low, "unable to create lock")
}

// excerpt returns the last limit bytes of s with a truncation marker.
func excerpt(s []byte, limit int) string {
	if len(s) <= limit {
		return string(s)
	}
	return "…[truncated] " + string(s[len(s)-limit:])
}

// storeErr builds a typed error with the caller's message.
func storeErr(class domain.StoreErrorClass, format string, args ...any) *domain.StoreError {
	return &domain.StoreError{Class: class, Err: fmt.Errorf(format, args...)}
}
