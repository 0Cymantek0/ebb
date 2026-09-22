package actions

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/policy"
)

// Network declares an action's network requirement and approval
// (Foundation §9.5). It is a declaration, NOT a sandbox: this package
// enforces no egress. An enforced no-egress requirement is a job for a
// future isolation provider, never a claim made here.
type Network string

// Accepted network declarations. The wire spellings match the
// [[regenerate]].network vocabulary of the policy package.
const (
	// NetworkNone declares that the action needs no network.
	NetworkNone Network = "none"
	// NetworkAllowed declares approved network use.
	NetworkAllowed Network = "allowed"
	// NetworkOfflineArtifacts declares that recovery can complete from
	// retained artifacts on a compatible host.
	NetworkOfflineArtifacts Network = "offline-artifacts"
)

// Valid reports whether n is one of the accepted declarations.
func (n Network) Valid() bool {
	switch n {
	case NetworkNone, NetworkAllowed, NetworkOfflineArtifacts:
		return true
	}
	return false
}

// Definition is one approvable recovery action (Foundation §9.5): a
// literal argument vector plus the contracts that pin it. IDs are stable
// and originate from the policy regenerate id; paths are root-relative
// with '/' separators, validated by policy.ValidateRelPath so the
// validation contract cannot drift from the policy package.
type Definition struct {
	// ID is the stable action identifier (from the policy regenerate id).
	ID string
	// Argv is the literal argument vector. There is NO shell: argv[0] is
	// resolved through PATH at approval time and again at run time.
	Argv []string
	// WorkingRoot is the root-relative working directory for execution;
	// "" means the workspace root.
	WorkingRoot string
	// Inputs are root-relative input paths (lockfiles, manifests...).
	Inputs []string
	// Outputs are root-relative output roots the action owns.
	Outputs []string
	// EnvAllow lists the exact extra env KEYS the action may receive
	// beyond the OS substrate (PATH, SYSTEMROOT, COMSPEC, TEMP, TMP,
	// PATHEXT on Windows). Values are pulled from the parent process
	// environment, never from files.
	EnvAllow []string
	// Network is the requirement/approval declaration (not a sandbox).
	Network Network
	// Timeout bounds execution; the direct child is killed on expiry.
	Timeout time.Duration
	// DependsOn lists action IDs; the dependency graph must be acyclic.
	DependsOn []string
}

// ToolIdentity pins the exact executable an approval covers: the name as
// written in argv[0], the PATH-resolved absolute path, and the SHA-256
// digest of the executable file.
type ToolIdentity struct {
	Name         string
	ResolvedPath string
	SHA256       string
}

// ShellWarningMarker is the mandatory stronger warning displayed on every
// surface (approval prompt text, run log) when an action's argv[0] is a
// shell binary. Foundation §7.1: an explicitly requested shell is treated
// as arbitrary trusted code, not a sandbox.
const ShellWarningMarker = "SHELL ACTION: explicitly requested shell = arbitrary trusted code, not a sandbox (Foundation \u00a77.1, \u00a79.5)"

// shellPrograms are the argv[0] names (after stripping a .exe suffix,
// case-insensitively) that mark an action as a shell action.
var shellPrograms = map[string]bool{
	"cmd":        true,
	"powershell": true,
	"pwsh":       true,
	"sh":         true,
	"bash":       true,
}

// IsShell reports whether argv[0] names a shell binary (cmd.exe,
// powershell, pwsh, sh, bash — by base name, so full paths such as
// C:\Windows\System32\cmd.exe are detected too). The value is derived
// from Argv, never stored, so it cannot drift.
func (d Definition) IsShell() bool {
	if len(d.Argv) == 0 || d.Argv[0] == "" {
		return false
	}
	return isShellProgram(d.Argv[0])
}

// ShellWarning returns the stronger warning marker for shell actions, or
// "" for non-shell actions. Approval prompts and run logs must display it
// verbatim whenever it is non-empty.
func (d Definition) ShellWarning() string {
	if !d.IsShell() {
		return ""
	}
	return ShellWarningMarker
}

// isShellProgram reports whether arg0 (a name, relative or absolute
// path) names a known shell binary.
func isShellProgram(arg0 string) bool {
	base := arg0
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if len(base) >= 4 && strings.EqualFold(base[len(base)-4:], ".exe") {
		base = base[:len(base)-4]
	}
	return shellPrograms[strings.ToLower(base)]
}

// Validate enforces the Definition contract: non-empty ID, Argv and
// Outputs; root-relative path rules for WorkingRoot, Inputs and Outputs;
// Inputs and Outputs disjoint (an action must not consume what it owns);
// a valid network declaration; a positive timeout; no self-dependency;
// and usable, duplicate-free, non-substrate env keys. The same rules are
// re-enforced by the Runner immediately before execution.
func (d Definition) Validate() error {
	if d.ID == "" {
		return fmt.Errorf("actions: definition: ID must not be empty")
	}
	if len(d.Argv) == 0 || d.Argv[0] == "" {
		return fmt.Errorf("actions: definition %q: Argv must be a non-empty literal argument vector (no shell)", d.ID)
	}
	if d.WorkingRoot != "" {
		if err := policy.ValidateRelPath(d.WorkingRoot, true); err != nil {
			return fmt.Errorf("actions: definition %q: working root: %w", d.ID, err)
		}
	}
	if len(d.Outputs) == 0 {
		return fmt.Errorf("actions: definition %q: at least one output root must be declared", d.ID)
	}
	if err := validatePathList(d.ID, "input", d.Inputs, false); err != nil {
		return err
	}
	if err := validatePathList(d.ID, "output", d.Outputs, false); err != nil {
		return err
	}
	for _, in := range d.Inputs {
		for _, out := range d.Outputs {
			if pathsOverlap(in, out) {
				return fmt.Errorf("actions: definition %q: input %q overlaps declared output %q (an action must not consume what it owns)",
					d.ID, in, out)
			}
		}
	}
	if !d.Network.Valid() {
		return fmt.Errorf("actions: definition %q: network must be one of %q, %q, %q, got %q",
			d.ID, NetworkNone, NetworkAllowed, NetworkOfflineArtifacts, string(d.Network))
	}
	if d.Timeout <= 0 {
		return fmt.Errorf("actions: definition %q: timeout must be positive, got %s", d.ID, d.Timeout)
	}
	for _, dep := range d.DependsOn {
		if dep == d.ID {
			return fmt.Errorf("actions: definition %q: depends on itself", d.ID)
		}
	}
	return validateEnvAllow(d)
}

// validatePathList checks one list of root-relative paths for the path
// contract and duplicates.
func validatePathList(defID, what string, paths []string, allowDot bool) error {
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if err := policy.ValidateRelPath(p, allowDot); err != nil {
			return fmt.Errorf("actions: definition %q: %s: %w", defID, what, err)
		}
		if seen[p] {
			return fmt.Errorf("actions: definition %q: duplicate %s path %q", defID, what, p)
		}
		seen[p] = true
	}
	return nil
}

// validateEnvAllow checks that every allowlisted key is a usable
// environment key: non-empty, no '=' or NUL, no duplicates (compared the
// way the platform compares env names), not one of the substrate keys
// that every action already receives, and not one of Ebb's own
// secret-bearing environment names (an action asking for the vault
// unlock secret is definitionally unapprovable — Foundation §13.1, Wave
// G review finding G1c: the refusal happens here, before any prompt or
// approval record can exist).
func validateEnvAllow(d Definition) error {
	for i, k := range d.EnvAllow {
		if k == "" {
			return fmt.Errorf("actions: definition %q: env allowlist entry must not be empty", d.ID)
		}
		if strings.ContainsAny(k, "=\x00") {
			return fmt.Errorf("actions: definition %q: env allowlist key %q must not contain '=' or NUL", d.ID, k)
		}
		for _, sub := range substrateKeys() {
			if envKeyMatches(k, sub) {
				return fmt.Errorf("actions: definition %q: env allowlist key %q is part of the OS substrate and cannot be re-allowed", d.ID, k)
			}
		}
		if EnvKeyDenylisted(k) {
			return &ErrEnvDenylisted{ActionID: d.ID, Key: k}
		}
		for j := 0; j < i; j++ {
			if envKeyMatches(d.EnvAllow[j], k) {
				return fmt.Errorf("actions: definition %q: duplicate env allowlist key %q", d.ID, k)
			}
		}
	}
	return nil
}

// ValidateGraph validates every definition and enforces that the
// DependsOn edges over the given set form a DAG: duplicate IDs and
// dependencies on actions outside the set are rejected, cycles are
// rejected by depth-first search with a deterministic error message, and
// two definitions whose declared Outputs overlap (same path or
// containment) are rejected — they would race for the same tree, and
// each would silently widen the other's F36 exclusion (the reader-side
// twin of policy's capture-time output-conflict rule; Wave G review
// finding G1).
func ValidateGraph(defs []Definition) error {
	byID := make(map[string]Definition, len(defs))
	for i := range defs {
		if err := defs[i].Validate(); err != nil {
			return err
		}
		if _, dup := byID[defs[i].ID]; dup {
			return fmt.Errorf("actions: duplicate action id %q in graph", defs[i].ID)
		}
		byID[defs[i].ID] = defs[i]
	}
	for i := range defs {
		for _, dep := range defs[i].DependsOn {
			if _, ok := byID[dep]; !ok {
				return fmt.Errorf("actions: action %q depends on unknown action %q", defs[i].ID, dep)
			}
		}
	}

	// Cross-definition output overlap: deterministic over the sorted id
	// pair sequence so the error never depends on input order.
	ids := slices.Sorted(maps.Keys(byID))
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			a, b := byID[ids[i]], byID[ids[j]]
			for _, oa := range a.Outputs {
				for _, ob := range b.Outputs {
					if pathsOverlap(oa, ob) {
						return fmt.Errorf(
							"actions: definitions %q and %q declare overlapping outputs (%q and %q); two actions racing for the same tree each silently widen the other's protected-content exclusion",
							a.ID, b.ID, oa, ob)
					}
				}
			}
		}
	}

	adj := make(map[string][]string, len(defs))
	for i := range defs {
		adj[defs[i].ID] = append([]string(nil), defs[i].DependsOn...)
		slices.Sort(adj[defs[i].ID])
	}

	const (
		white = 0 // unvisited
		gray  = 1 // on the current DFS stack
		black = 2 // finished
	)
	color := make(map[string]int, len(defs))
	var stack []string
	var visit func(id string) error
	visit = func(id string) error {
		color[id] = gray
		stack = append(stack, id)
		for _, dep := range adj[id] {
			switch color[dep] {
			case gray:
				cycle := append(append([]string(nil), stack...), dep)
				return fmt.Errorf("actions: dependency cycle detected: %s", strings.Join(cycle, " -> "))
			case white:
				if err := visit(dep); err != nil {
					return err
				}
			}
		}
		stack = stack[:len(stack)-1]
		color[id] = black
		return nil
	}
	for _, id := range slices.Sorted(maps.Keys(adj)) {
		if color[id] == white {
			if err := visit(id); err != nil {
				return err
			}
		}
	}
	return nil
}

// CanonicalEnvAllow returns the sorted copy of keys that approvals store
// for the env allowlist.
func CanonicalEnvAllow(keys []string) []string {
	out := append([]string(nil), keys...)
	slices.Sort(out)
	return out
}

// CanonicalOutputs returns the sorted copy of output roots that
// approvals store for the output ownership (Foundation §7.3).
func CanonicalOutputs(paths []string) []string {
	out := append([]string(nil), paths...)
	slices.Sort(out)
	return out
}

// envSetEqual reports whether two env key lists cover the same keys,
// compared with the platform's env-name matching rules.
func envSetEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, ka := range a {
		found := false
		for _, kb := range b {
			if envKeyMatches(ka, kb) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// pathUnder reports whether path is inside dir (or equals dir).
// This mirrors policy's unexported helper deliberately; the semantics
// (complete-segment containment) must not drift from the policy package.
func pathUnder(dir, path string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// pathsOverlap reports whether two root-relative paths are equal or one
// contains the other.
func pathsOverlap(a, b string) bool {
	return pathUnder(a, b) || pathUnder(b, a)
}
