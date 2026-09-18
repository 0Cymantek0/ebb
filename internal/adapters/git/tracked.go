// TrackedFiles: the index view backing the `git:tracked` evidence token
// (Foundation §7.2 precedence class "required source and Git state",
// consumed by policy.Resolve as F53 cancellation). It uses the same
// D004-hardened environment and allowlisted argv shapes as Observe; the
// shared private machinery (envBox, runner, parseConfigList) is reused,
// never duplicated.

package gitadapter

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TrackedFiles returns the set of root-relative '/'-separated paths that
// Git tracks at rootPath, deduplicated. It reads `git ls-files --stage`
// (index entries only — never `-m`, which fires clean filters), so the
// set contains:
//
//   - every path present in the index at any stage (0 normal, 1-3 during
//     unmerged conflicts; dedup collapses the conflict stages to one path);
//   - gitlink entries (mode 160000): a submodule mount point exists at
//     that path, so it must NOT be ommissible — it is marked tracked.
//
// A root with no Git repository at-or-below it (discovery ceiling limited
// to rootPath's parent, exactly like Observe) yields an empty set and a
// nil error: that is an observation, not a failure. An error is returned
// only for infrastructure failures (unusable root, git not runnable,
// timeout, cancelled context, or ls-files failing inside a repo).
func TrackedFiles(ctx context.Context, rootPath string) (map[string]bool, error) {
	tracked := map[string]bool{}
	if ctx == nil {
		ctx = context.Background()
	}
	info, err := os.Stat(rootPath)
	if err != nil {
		return nil, fmt.Errorf("gitadapter: root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("gitadapter: root is not a directory: %s", rootPath)
	}
	absRoot, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, fmt.Errorf("gitadapter: root: %w", err)
	}

	// Construct a fresh observer environment the same way Observe does
	// (D004 rules 1-2): built-from-scratch child env, then pass 1's config
	// inventory, then empty overrides for every execution-capable key it
	// revealed before any repository command runs.
	box, err := newEnvBox(absRoot)
	if err != nil {
		return nil, err
	}
	defer box.cleanup()
	r := &runner{env: box.env}

	cfgOut, _, cfgRc, err := r.run(ctx, absRoot, commandTimeout,
		"config", "--list", "--show-origin", "--show-scope")
	if err != nil {
		return nil, fmt.Errorf("gitadapter: config inventory: %w", err)
	}
	if cfgRc == 0 {
		r.overrides = parseConfigList(cfgOut).overrideArgs()
	}
	// cfgRc != 0 degrades to static neutralization only, mirroring
	// Observe; the rev-parse triplet below decides repository-ness.

	// Repository check. With the ceiling at rootPath's parent this can
	// only find a repository whose top level IS rootPath, so the paths
	// ls-files prints are root-relative already (git uses '/' everywhere).
	_, _, rc, err := r.run(ctx, absRoot, commandTimeout,
		"rev-parse", "--git-dir", "--git-common-dir", "--absolute-git-dir")
	if err != nil {
		return nil, err
	}
	if rc != 0 {
		return tracked, nil // not a repository: nothing is tracked
	}

	out, _, rc, err := r.run(ctx, absRoot, commandTimeout, "ls-files", "--stage")
	if err != nil {
		return nil, err
	}
	if rc != 0 {
		return nil, fmt.Errorf("gitadapter: ls-files --stage exited %d", rc)
	}

	// Line format: "<mode> <object> <stage>\t<path>". The separator tab
	// is raw; a tab INSIDE a path only ever appears escaped inside a
	// quoted string, so the first raw tab is always the separator.
	for _, line := range strings.Split(out, "\n") {
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue // trailing empty line or malformed line
		}
		p := strings.TrimSuffix(line[tab+1:], "\r")
		if p == "" {
			continue
		}
		tracked[unquoteGitPath(p)] = true
	}
	return tracked, nil
}

// unquoteGitPath decodes git's C-style quoted path output. ls-files
// quotes any path containing '"', '\' or control bytes, and — with the
// default core.quotePath=true — any byte above 0x7f. Escapes are byte
// oriented (octal escapes carry raw byte values, not runes), so the
// decoded string preserves the exact on-disk name bytes.
func unquoteGitPath(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	body := s[1 : len(s)-1]
	var b []byte
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			b = append(b, c)
			continue
		}
		if i+1 >= len(body) {
			break
		}
		i++
		switch e := body[i]; e {
		case 'a':
			b = append(b, 7)
		case 'b':
			b = append(b, 8)
		case 't':
			b = append(b, 9)
		case 'n':
			b = append(b, 10)
		case 'v':
			b = append(b, 11)
		case 'f':
			b = append(b, 12)
		case 'r':
			b = append(b, 13)
		case '"', '\\':
			b = append(b, e)
		default:
			if e < '0' || e > '7' {
				b = append(b, e)
				continue
			}
			v := int(e - '0')
			for n := 0; n < 2 && i+1 < len(body) && body[i+1] >= '0' && body[i+1] <= '7'; n++ {
				i++
				v = v*8 + int(body[i]-'0')
			}
			b = append(b, byte(v))
		}
	}
	return string(b)
}
