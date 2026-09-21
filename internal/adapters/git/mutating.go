package gitadapter

// Mutating git invocations under the D004/D005 hardening discipline.
//
// Every OBSERVATION verb is hardened inside runner.run (constructed
// environment, static safe prefix, two-pass per-key neutralization,
// exact argv allowlist). `ebb analyse --prune-worktrees` additionally
// drives one user-consented MUTATING verb — `git worktree remove` — and
// that invocation used to run with the fully inherited environment and
// no neutralization at all, letting a hostile repository execute its
// own configuration (core.fsmonitor was live-verified firing) during a
// removal the user consented to. MutatingSession gives the mutating
// path the same construction the observe/survey verbs get:
//
//   - the child environment is constructed (env.go), never inherited;
//   - the static safe prefix (runner.go) is extended with the two
//     execution knobs a removal can reach that observation never does
//     (core.hooksPath, core.attributesfile);
//   - pass 1 inventories the merged config and pass 2 empty-overrides
//     every execution-capable key it revealed, failing closed on
//     unneutralizable subsections (GIT-NEUT-2, the same rule as
//     Observe/SurveyRepo);
//   - the mutating argv shape itself is allowlisted: only
//     `[-C <dir>] worktree remove <path>` may ever be built, with the
//     path taken from ebb's own scan (an absolute path can never be
//     parsed as an option).
//
// The removal is ALWAYS user-consented upstream (analyse's --yes or a
// typed per-item confirmation); this helper only removes the
// repository's chance to execute code during it. It grants no new
// removal authority: the mutation is git's own administrative
// operation, not an ebb lifecycle removal.

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// mutatingGitFlags is the static safe prefix for mutating invocations:
// the observation prefix (runner.go staticGitFlags) plus the two
// execution knobs reachable from a removal that observation never hits.
var mutatingGitFlags = func() []string {
	f := make([]string, 0, len(staticGitFlags)+4)
	f = append(f, staticGitFlags...)
	f = append(f,
		"-c", "core.hooksPath=",
		"-c", "core.attributesfile=",
	)
	return f
}()

// errNotAllowedMutating reports a mutating argv outside the fixed shape.
var errNotAllowedMutating = errors.New("gitadapter: argv not in mutating allowlist")

// mutatingArgvCheck admits exactly the one mutating shape this helper
// exists for: an optional `-C <dir>` anchor followed by
// `worktree remove <path>`. The path comes from ebb's own scan (an
// absolute filesystem path) and is refused in option shape regardless.
func mutatingArgvCheck(argv []string) error {
	args := argv
	if len(args) > 1 && args[0] == "-C" {
		args = args[2:]
	}
	if len(args) == 3 && args[0] == "worktree" && args[1] == "remove" && !strings.HasPrefix(args[2], "-") {
		return nil
	}
	return errNotAllowedMutating
}

// MutatingSession holds the constructed environment and per-repo
// neutralization overrides for user-consented mutating git invocations.
// Not safe for concurrent use; sessions are per-item and short-lived.
type MutatingSession struct {
	box       *envBox
	dir       string   // anchor directory (cmd.Dir)
	overrides []string // flattened {"-c", "key=", ...} from pass 1
}

// NewMutatingSession prepares the hardened session for a mutation
// anchored at rootPath (the repository the mutating verb runs in — the
// `-C` directory). The pass-1 config inventory runs here, through the
// same hardened runner the observe verbs use, so the per-key
// neutralization is collected before the mutation ever spawns.
func NewMutatingSession(ctx context.Context, rootPath string) (*MutatingSession, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("gitadapter: mutating session root: %w", err)
	}
	box, err := newEnvBox(absRoot)
	if err != nil {
		return nil, err
	}
	m := &MutatingSession{box: box, dir: absRoot}
	r := &runner{env: box.env}
	cfgOut, _, cfgRc, err := r.run(ctx, absRoot, commandTimeout,
		"config", "--list", "--show-origin", "--show-scope")
	if err != nil {
		box.cleanup()
		return nil, fmt.Errorf("gitadapter: mutating session config inventory: %w", err)
	}
	if cfgRc == 0 {
		inv := parseConfigList(cfgOut)
		if len(inv.unneutralizable) > 0 {
			// Same fail-closed rule as Observe/SurveyRepo (GIT-NEUT-2):
			// never run even a consented mutation with a live execution
			// key no -c spelling can neutralize.
			box.cleanup()
			return nil, fmt.Errorf("gitadapter: refusing mutation: repository config contains execution keys that cannot be neutralized (subsection contains '='): %q", inv.unneutralizable[0])
		}
		m.overrides = inv.overrideArgs()
	}
	// cfgRc != 0 (no repository at the anchor): static neutralization
	// only; the mutation itself will fail honestly, exactly as before.
	return m, nil
}

// Command builds one hardened mutating invocation. The command is NOT
// started; the caller runs it (capturing output so nothing leaks to the
// user terminal) and must call Cleanup afterwards to release the
// private environment directory.
func (m *MutatingSession) Command(ctx context.Context, argv ...string) (*exec.Cmd, error) {
	if err := mutatingArgvCheck(argv); err != nil {
		return nil, fmt.Errorf("%w: %q", err, argv)
	}
	full := make([]string, 0, len(mutatingGitFlags)+len(m.overrides)+len(argv))
	full = append(full, mutatingGitFlags...)
	full = append(full, m.overrides...)
	full = append(full, argv...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Dir = m.dir
	cmd.Env = m.box.env
	return cmd, nil
}

// Cleanup releases the session's private environment directory
// (best-effort; it holds only an empty gitconfig).
func (m *MutatingSession) Cleanup() { m.box.cleanup() }
