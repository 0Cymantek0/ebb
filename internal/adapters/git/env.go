package gitadapter

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Environment construction (D004 rule 1). The child environment is built
// from scratch: a minimal OS substrate is copied from the inherited
// environment and everything else — including every GIT_* variable,
// XDG_CONFIG_HOME, USERPROFILE and hostile HOME values — is dropped by
// construction, then the hardened variables below are set explicitly.
//
// Lab evidence (lab/git-probe H1/H2): inherited GIT_DIR / GIT_INDEX_FILE
// silently retarget observation to another repository or index, so
// scrubbing must happen before any git invocation, including pass 1.

// osStateVars lists the inherited variables git.exe (or git on other
// platforms) minimally needs to start and that carry no Git semantics.
// This mirrors the validated probe environment exactly
// (lab/git-probe/probe.sh HARDEN_ENV).
func osStateVars() []string {
	if runtime.GOOS == "windows" {
		return []string{"PATH", "SYSTEMROOT", "COMSPEC", "WINDIR", "TMP", "TEMP", "PATHEXT"}
	}
	return []string{"PATH", "TMPDIR", "LANG", "LC_ALL", "TZ"}
}

// envKeyMatches compares an inherited variable name against an allowlist
// entry. Windows environment lookup is case-insensitive, so matching must
// be too; other platforms are exact.
func envKeyMatches(name, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, want)
	}
	return name == want
}

// childEnv builds the complete hardened child environment.
//
// inherited is the parent environment (os.Environ() at the call site);
// homeDir is an Ebb-owned empty directory; globalConfig is the path of an
// Ebb-owned empty file (on Windows the NUL device string is fragile when
// passed by a native Win32 Go process, so an empty real file is used);
// ceilingDir is the parent of the observed root, containing repository
// discovery (lab/git-probe O24).
func childEnv(inherited []string, homeDir, globalConfig, ceilingDir string) []string {
	out := make([]string, 0, len(osStateVars())+12)
	for _, want := range osStateVars() {
		for _, kv := range inherited {
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				continue
			}
			if envKeyMatches(kv[:eq], want) {
				out = append(out, kv)
				break // first spelling wins; duplicates are impossible upstream
			}
		}
	}
	out = append(out,
		"HOME="+homeDir,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+globalConfig,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_OPTIONAL_LOCKS=0",
		"GIT_NO_LAZY_FETCH=1",
		"GIT_ALLOW_PROTOCOL=none",
		"GIT_ATTR_NOSYSTEM=1", // real but undocumented in git(1); belt only
		"GIT_CEILING_DIRECTORIES="+ceilingDir,
		"GIT_PAGER=cat",
		"PAGER=cat", // belt under --no-pager
	)
	return out
}

// envBox owns the private temp directory backing the hardened
// environment: HOME and the empty GIT_CONFIG_GLOBAL file live here and
// both are removed when the observation finishes.
type envBox struct {
	dir string // private temp dir (HOME)
	cfg string // empty file passed as GIT_CONFIG_GLOBAL
	env []string
}

func newEnvBox(absRoot string) (*envBox, error) {
	dir, err := os.MkdirTemp("", "ebb-git-env-")
	if err != nil {
		return nil, fmt.Errorf("gitadapter: private env dir: %w", err)
	}
	cfg := filepath.Join(dir, "gitconfig")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("gitadapter: empty global config: %w", err)
	}
	return &envBox{
		dir: dir,
		cfg: cfg,
		env: childEnv(os.Environ(), dir, cfg, filepath.Dir(absRoot)),
	}, nil
}

func (b *envBox) cleanup() {
	// Best effort; the directory holds only an empty file.
	os.RemoveAll(b.dir)
}
