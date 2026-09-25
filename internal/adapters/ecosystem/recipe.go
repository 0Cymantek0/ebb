package ecosystem

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/policy"
)

// ErrPipPreserveDefault is returned by Recipe for the pip adapter:
// Foundation §9.4 gives plain pip detection and a preservation default;
// a regeneration recipe is only possible as an explicitly approved
// custom action.
var ErrPipPreserveDefault = errors.New("ecosystem: pip recipes are v1 preserve-default; use a custom action")

// recipeTimeout bounds every generated install recipe. Large cold
// installs on slow networks are the norm, not the exception.
const recipeTimeout = 15 * time.Minute

// Recipe builds the recovery-action Definition for one detected group
// (Foundation §9.4):
//
//   - pnpm: pnpm install --frozen-lockfile (EnvAllow PNPM_HOME)
//   - npm:  npm ci (no extra env keys)
//   - uv:   uv sync --locked (EnvAllow UV_PYTHON)
//
// All recipes run at the workspace root with network allowed and a 15
// minute timeout. EnvAllow is the minimal LIST of extra keys the action
// may receive; values come from the parent process at run time.
//
// npm note (surfaced here because the adapter, not the actions package,
// chose the verb): `npm ci` executes package lifecycle scripts
// (prepare, postinstall, ...) with the user's privileges once the
// action is approved. Surfacing that risk at approval time is the
// approval flow's job (Foundation §9.4, §9.5), not the adapter's.
//
// A non-empty wsRoot enables early verification that every declared
// input exists under it (the actions runner re-digests inputs
// immediately before execution anyway). Pass "" to skip, e.g. when
// planning against a not-yet-restored tree.
//
// Adapters never emit deletion or cleanup subcommands (no
// `npm cache clean`, no `pnpm store prune`): an action may describe
// outputs, but source-removal authority belongs to the lifecycle
// coordinator alone (Foundation §9.5). TestNoDeletionVerbs is the
// tripwire.
func Recipe(g GroupSuggestion, wsRoot string) (actions.Definition, error) {
	if err := verifyInputs(wsRoot, g.Inputs); err != nil {
		return actions.Definition{}, err
	}
	switch g.Adapter {
	case AdapterPNPM:
		// Lock-enforcing install for the pinned pnpm version; a stale or
		// mutated lockfile fails instead of being silently updated.
		return build(g, []string{"pnpm", "install", "--frozen-lockfile"}, []string{"PNPM_HOME"})
	case AdapterNPM:
		// npm ci installs exactly the lockfile (never a loose install
		// that rewrites the dependency decision) and removes the existing
		// node_modules itself — that is npm's own documented behavior of
		// the approved verb, not a deletion subcommand we emit.
		return build(g, []string{"npm", "ci"}, nil)
	case AdapterUV:
		// --locked fails on a stale lockfile; --frozen skips the
		// freshness check and is only an explicitly chosen alternate.
		return build(g, []string{"uv", "sync", "--locked"}, []string{"UV_PYTHON"})
	case AdapterPip:
		return actions.Definition{}, ErrPipPreserveDefault
	default:
		return actions.Definition{}, fmt.Errorf("ecosystem: recipe: unknown adapter %q (want one of pnpm, npm, uv, pip)", g.Adapter)
	}
}

// build assembles and validates the Definition; the validation contract
// (path rules, input/output disjointness, env keys, timeout) is enforced
// by the actions package so it cannot drift from here. The working root
// is the suggestion's DECLARED logical root ("" or "." means the
// workspace root): a frozen recipe must execute inside the group's own
// directory exactly like a custom command does (wave-5 E04 — the
// hardcoded "." made every nested-root built-in recipe run at the
// workspace root and made restore synthesize the wrong working
// directory).
func build(g GroupSuggestion, argv, envAllow []string) (actions.Definition, error) {
	workingRoot := g.WorkingRoot
	if workingRoot == "" {
		workingRoot = "."
	}
	d := actions.Definition{
		ID:          g.GroupID,
		Argv:        argv,
		WorkingRoot: workingRoot,
		Inputs:      append([]string(nil), g.Inputs...),
		Outputs:     append([]string(nil), g.Outputs...),
		EnvAllow:    append([]string(nil), envAllow...),
		Network:     actions.NetworkAllowed,
		Timeout:     recipeTimeout,
	}
	if err := d.Validate(); err != nil {
		return actions.Definition{}, fmt.Errorf("ecosystem: recipe for %q: %w", g.GroupID, err)
	}
	return d, nil
}

// verifyInputs checks that every declared input exists under wsRoot,
// naming the first missing one. It is a no-op when wsRoot is empty.
func verifyInputs(wsRoot string, inputs []string) error {
	if wsRoot == "" {
		return nil
	}
	info, err := os.Stat(wsRoot)
	if err != nil {
		return fmt.Errorf("ecosystem: recipe: workspace root: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("ecosystem: recipe: workspace root is not a directory: %s", wsRoot)
	}
	for _, in := range inputs {
		if _, err := os.Stat(filepath.Join(wsRoot, filepath.FromSlash(in))); err != nil {
			return fmt.Errorf("ecosystem: recipe: declared input %q not found under the workspace root: %w", in, err)
		}
	}
	return nil
}

// Marries reports whether an existing [[regenerate]] group in pol
// already covers the suggestion: same adapter AND at least one output
// path overlapping (equal, or containing in either direction). Inspect
// uses it to avoid suggesting a group the user already wrote by hand.
// A suggestion with no outputs (e.g. pip without a conventional venv
// directory) cannot confirm coverage and reports false.
func Marries(g GroupSuggestion, pol policy.Policy) bool {
	for _, rg := range pol.Regenerate {
		if string(rg.Adapter) != g.Adapter {
			continue
		}
		for _, out := range rg.Outputs {
			for _, mine := range g.Outputs {
				if pathsOverlap(out, mine) {
					return true
				}
			}
		}
	}
	return false
}

// pathUnder reports whether path is inside dir (or equals dir). It
// mirrors the unexported helpers in policy and actions deliberately:
// the containment semantics must not drift between the three packages.
func pathUnder(dir, path string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// pathsOverlap reports whether two root-relative paths are equal or one
// contains the other.
func pathsOverlap(a, b string) bool {
	return pathUnder(a, b) || pathUnder(b, a)
}
