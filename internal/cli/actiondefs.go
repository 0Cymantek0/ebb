// actiondefs.go derives the exact action definitions captured into
// manifests (Foundation §16.2 "exact captured action definitions") from
// the workspace's resolved policy at capture time:
//
//   - adapter groups (pnpm/npm/uv) get the pinned ecosystem recipe
//     (ecosystem.Recipe), with the network declaration taken from the
//     policy group (the recipe constant is "allowed"; a group that
//     declares offline-artifacts keeps its stricter declaration);
//   - custom-command groups get their literal argv with a sensible
//     30-minute timeout, an empty env allowlist, and the group's
//     inputs/outputs/network;
//   - pip groups and custom groups without a command stay hint-only
//     (no definition — never executable from the manifest).
//
// The definitions are validated as a graph by lifecycle before the
// manifest is frozen; a cycle or invalid definition fails the capture.

package cli

import (
	"fmt"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/adapters/ecosystem"
	"github.com/0Cymantek0/ebb/internal/policy"
)

// customActionTimeout bounds a policy-declared custom command. Ecosystem
// recipes carry their own 15-minute constant (recipe.go); custom
// commands get a deliberately generous default — an install script may
// build from source.
const customActionTimeout = 30 * time.Minute

// deriveActionDefs derives one actions.Definition per policy regenerate
// group that has a runnable reconstruction. Groups without a runnable
// recipe (pip, custom without command) yield no definition: they are
// reported as hints at open time and never executed.
func deriveActionDefs(pol policy.Policy) ([]actions.Definition, error) {
	var defs []actions.Definition
	for _, g := range pol.Regenerate {
		def, ok, err := deriveGroupDef(g)
		if err != nil {
			return nil, fmt.Errorf("deriving action definition for group %q: %w", g.ID, err)
		}
		if ok {
			defs = append(defs, def)
		}
	}
	return defs, nil
}

// deriveGroupDef derives one group's definition; ok is false for groups
// that stay hint-only.
func deriveGroupDef(g policy.Regenerate) (def actions.Definition, ok bool, err error) {
	// The group's DECLARED logical root is the working directory for
	// every runnable form ("" normalizes to "." — the Parse-level
	// default, re-applied here for hand-built policies).
	root := g.Root
	if root == "" {
		root = "."
	}
	if len(g.Command) > 0 {
		// Custom command: literal argv (shell argv[0]s already carry the
		// standard shell-warning treatment inside the actions package).
		def = actions.Definition{
			ID:          g.ID,
			Argv:        append([]string(nil), g.Command...),
			WorkingRoot: root,
			Inputs:      append([]string(nil), g.Inputs...),
			Outputs:     append([]string(nil), g.Outputs...),
			EnvAllow:    nil,
			Network:     mapGroupNetwork(g.Network),
			Timeout:     customActionTimeout,
		}
		return def, true, def.Validate()
	}
	switch g.Adapter {
	case policy.AdapterPNPM, policy.AdapterNPM, policy.AdapterUV:
		// Pinned ecosystem recipe; wsRoot "" skips the input-existence
		// pre-check (the capture's own scan is the authority here, and
		// the runner re-digests inputs immediately before execution). The
		// group's DECLARED logical root rides along as the working root
		// (wave-5 E04: built-in recipes carry it exactly like custom
		// commands, so the frozen definition names one execution
		// directory for both trim and restore).
		def, err = ecosystem.Recipe(ecosystem.GroupSuggestion{
			GroupID:     g.ID,
			Adapter:     string(g.Adapter),
			Outputs:     append([]string(nil), g.Outputs...),
			Inputs:      append([]string(nil), g.Inputs...),
			WorkingRoot: root,
		}, "")
		if err != nil {
			return actions.Definition{}, false, err
		}
		// The recipe constant declares "allowed"; a policy group that
		// declares offline-artifacts keeps its stricter declaration so
		// the approval pins what the policy says.
		def.Network = mapGroupNetwork(g.Network)
		return def, true, def.Validate()
	default:
		// pip (preserve-default) and custom groups without a command:
		// hint-only.
		return actions.Definition{}, false, nil
	}
}

// mapGroupNetwork maps the policy network vocabulary onto the actions
// declaration vocabulary (identical strings today; the mapping keeps
// the two packages' constants from being coupled).
func mapGroupNetwork(n policy.GroupNetwork) actions.Network {
	switch n {
	case policy.GroupNetworkOfflineArtifacts:
		return actions.NetworkOfflineArtifacts
	default:
		return actions.NetworkAllowed
	}
}
