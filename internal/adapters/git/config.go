package gitadapter

import "strings"

// Pass 1: the configuration inventory (D004 rule 2). `git config --list
// --show-origin --show-scope` never executes anything (config parsing has
// no execution primitive; include.path chains are file reads only —
// lab/git-probe O10), so it may run with the static prefix alone. Every
// execution-capable key it reveals is then empty-overridden in pass 2.

// maxConfigOutput bounds the pass-1 inventory read. Pathological include
// chains or huge configs are a documented residual risk (FINDINGS §3.2);
// exceeding the bound produces a warning rather than unbounded memory.
const maxConfigOutput = 4 << 20 // 4 MiB

// configInventory is the parsed result of pass 1.
type configInventory struct {
	// values maps lowercased key -> last value seen (git semantics:
	// later scopes override earlier ones). Used only for read-only
	// lookups (promisor, objectformat, filter.lfs presence).
	values map[string]string
	// overrideKeys are the exact-case keys needing empty `-c key=`
	// overrides in pass 2, deduplicated, in first-seen order.
	overrideKeys []string
}

// staticallyNeutralized keys already carry an empty/false override in
// staticGitFlags; collecting them again would only duplicate argv.
var staticallyNeutralized = map[string]bool{
	"core.fsmonitor": true,
	"diff.external":  true,
}

// executionKey reports whether a config key names an execution-capable
// setting, i.e. a value git may run as a program during observation:
// filter drivers, diff helpers, pagers/editors, plus core.fsmonitor in
// any value form (bool daemon or hook path; D004 rule 2). Section and
// variable matching is case-insensitive (git's own semantics); the
// subsection may appear in any case because an empty override written in
// any case neutralizes the same key (FINDINGS §2.2). Keys already
// overridden by staticGitFlags are still "execution keys" — they are
// deduplicated at collection time, not here.
func executionKey(key string) bool {
	low := strings.ToLower(key)
	switch {
	case low == "core.pager", low == "core.editor",
		low == "core.fsmonitor", low == "diff.external":
		return true
	case strings.HasPrefix(low, "filter."):
		return strings.HasSuffix(low, ".clean") ||
			strings.HasSuffix(low, ".smudge") ||
			strings.HasSuffix(low, ".process")
	case strings.HasPrefix(low, "diff."):
		return strings.HasSuffix(low, ".textconv") ||
			strings.HasSuffix(low, ".command")
	}
	return false
}

// parseConfigList parses `git config --list --show-origin --show-scope`
// output. Line format is `<scope>\t<origin>\t<key>=<value>`; lines without
// the expected shape are skipped rather than trusted.
func parseConfigList(out string) *configInventory {
	inv := &configInventory{values: map[string]string{}}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		scope, kv := "", line
		if len(parts) == 3 {
			scope, kv = parts[0], parts[2]
		}
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			continue
		}
		key, value := kv[:eq], kv[eq+1:]
		if scope == "command" {
			// Our own -c overrides from the static prefix; not repo content.
			continue
		}
		low := strings.ToLower(key)
		inv.values[low] = value
		if executionKey(low) && !staticallyNeutralized[low] && !seen[low] {
			seen[low] = true
			inv.overrideKeys = append(inv.overrideKeys, key)
		}
	}
	return inv
}

// overrideArgs flattens the collected keys into {"-c", "key=", ...}.
func (inv *configInventory) overrideArgs() []string {
	if len(inv.overrideKeys) == 0 {
		return nil
	}
	out := make([]string, 0, 2*len(inv.overrideKeys))
	for _, k := range inv.overrideKeys {
		out = append(out, "-c", k+"=")
	}
	return out
}

// hasPrefixKey reports whether any collected config key starts with the
// given lowercased prefix (subsection-insensitive presence test).
func (inv *configInventory) hasPrefixKey(prefix string) bool {
	for k := range inv.values {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// isPartialClone reports the promisor-remote markers of a partial clone:
// any remote configured promisor=true or carrying a partialclonefilter
// (lab/git-probe O15).
func (inv *configInventory) isPartialClone() bool {
	for k, v := range inv.values {
		low := strings.ToLower(v)
		if strings.HasPrefix(k, "remote.") && strings.HasSuffix(k, ".promisor") &&
			(low == "true" || low == "yes" || low == "on" || low == "1") {
			return true
		}
		if strings.HasPrefix(k, "remote.") && strings.HasSuffix(k, ".partialclonefilter") && v != "" {
			return true
		}
	}
	return false
}
