package gitadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"time"
)

// Hardened subprocess runner (D004 rules 2-3). Every invocation carries
// the static safe prefix plus the per-repo neutralization overrides
// collected in pass 1, runs in the constructed environment, is bounded by
// a context timeout, and has stdout/stderr captured so nothing leaks to
// the user terminal.

const (
	// versionTimeout bounds `git --version` (no repository work).
	versionTimeout = 15 * time.Second
	// commandTimeout bounds each observation command. Repository sizes
	// vary; the caller's context remains the outer bound.
	commandTimeout = 60 * time.Second
)

// staticGitFlags is the safe global prefix validated by lab/git-probe
// (pass 1 of the recipe; pass 2 reuses "the same static -c prefix").
// Order is load-bearing for the allowlist check only in that -c values
// pair with their keys positionally.
var staticGitFlags = []string{
	"--no-pager",
	"-c", "core.fsmonitor=false", // only this stops the fsmonitor hook/daemon (V1/V4; --no-optional-locks does not)
	"-c", "core.untrackedCache=false",
	"-c", "gc.auto=0",
	"-c", "maintenance.auto=false",
	"-c", "diff.external=",
	"--no-optional-locks", // only this stops index refresh writes + post-index-change hooks (V3)
}

// allowedArgv enumerates the exact subcommand argv shapes the adapter may
// ever run (D004 rule 3). Matching is exact: any other argv — including
// reordered or partially-matched variants, non-builtins such as `git lfs`
// or alias-defined names, and filter-applying commands such as
// `ls-files -m` — is refused before a process is spawned.
// Aliases cannot shadow builtins (lab/git-probe O20) but can shadow
// non-builtin names (O21), which is why non-builtins are categorically
// absent here.
var allowedArgv = [][]string{
	{"--version"},
	{"config", "--list", "--show-origin", "--show-scope"}, // pass 1 inventory
	{"rev-parse", "--git-dir", "--git-common-dir", "--absolute-git-dir"},
	{"rev-parse", "--is-inside-work-tree", "--show-toplevel"},
	{"rev-parse", "HEAD"},
	{"symbolic-ref", "HEAD"},
	{"status", "--porcelain=v2", "--branch", "--ignore-submodules=all"},
	{"stash", "list", "--format=%H"},
	{"reflog", "show", "--format=%H", "HEAD"},
	{"reflog", "show", "--format=%H", "refs/stash"},
	{"remote", "-v"},
	{"worktree", "list", "--porcelain"},
	{"ls-files", "--stage"}, // never `ls-files -m` (fires clean filters; lab/git-probe)
}

// errNotAllowlisted reports an argv outside the D004 allowlist.
var errNotAllowlisted = errors.New("gitadapter: argv not in observation allowlist")

// allowlistCheck validates the subcommand part of an invocation. It is
// enforced inside run() so no code path can bypass it.
func allowlistCheck(args []string) error {
	for _, a := range allowedArgv {
		if slices.Equal(a, args) {
			return nil
		}
	}
	return errNotAllowlisted
}

// runner executes allowlisted git commands with the hardened environment
// and neutralization overrides.
type runner struct {
	env       []string // constructed child environment (env.go)
	overrides []string // flattened {"-c", "key=", ...} from pass 1
}

// run executes one hardened git invocation in dir. It returns stdout,
// stderr and the process exit code; err is non-nil only for
// infrastructure failures (spawn, timeout, cancellation) — git's own
// non-zero exits are reported via rc.
func (r *runner) run(ctx context.Context, dir string, timeout time.Duration, args ...string) (stdout, stderr string, rc int, err error) {
	if err := allowlistCheck(args); err != nil {
		return "", "", -1, fmt.Errorf("%w: %q", err, args)
	}
	argv := make([]string, 0, len(staticGitFlags)+len(r.overrides)+len(args))
	argv = append(argv, staticGitFlags...)
	argv = append(argv, r.overrides...)
	argv = append(argv, args...)

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "git", argv...)
	cmd.Dir = dir
	cmd.Env = r.env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", "", -1, fmt.Errorf("gitadapter: start git: %w", err)
	}
	werr := cmd.Wait()
	if cctx.Err() != nil {
		return outBuf.String(), errBuf.String(), -1, fmt.Errorf("gitadapter: git %q: %w", args, cctx.Err())
	}
	if werr != nil {
		var ee *exec.ExitError
		if errors.As(werr, &ee) {
			return outBuf.String(), errBuf.String(), ee.ExitCode(), nil
		}
		return outBuf.String(), errBuf.String(), -1, fmt.Errorf("gitadapter: wait git: %w", werr)
	}
	return outBuf.String(), errBuf.String(), 0, nil
}
