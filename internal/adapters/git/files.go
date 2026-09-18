package gitadapter

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// canonicalForm is declared per platform (canonical_windows.go /
// canonical_other.go): Windows normalizes 8.3 short-name spellings via
// GetLongPathNameW — which never resolves symlinks or junctions, so
// recorded link paths stay literal (D004 rule 5) — while other platforms
// return the path unchanged.

// Direct file reads (D004 rule 4). These repository facts are plain
// files; reading them directly avoids invoking git against
// attacker-controlled configuration entirely. Paths come from the
// resolved git dir / common dir that git itself reported (rule 5: no
// lexical tricks on links — the adapter never resolves or follows them).

func fileExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir()
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// firstExisting returns the first existing path, or "".
func firstExisting(paths ...string) string {
	for _, p := range paths {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// readHeadState reads <gitDir>/HEAD directly. It returns the symbolic
// branch ref (without the "ref: " prefix) when HEAD is symbolic, or the
// raw object id when HEAD is detached-shaped, else empty strings.
func readHeadState(gitDir string) (branch, hex string) {
	data, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return "", ""
	}
	s := strings.TrimSpace(string(data))
	if ref, ok := strings.CutPrefix(s, "ref: "); ok {
		return strings.TrimSpace(ref), ""
	}
	if len(s) == 40 || len(s) == 64 {
		if isHexString(s) {
			return "", s
		}
	}
	return "", ""
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}

// countFileLines counts non-empty lines of a small text file (reflogs).
func countFileLines(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return countNonEmptyLines(string(data))
}

// adminInside reports whether p is root itself or lies under root. It
// uses exactly the paths git reported (resolved git dir / common dir),
// never symlink-expanded: links recorded in those paths are a blocker
// reason, not something to chase lexically (Foundation §9.1-9.2).
// Windows path comparison is case-insensitive to match filesystem
// semantics; driver-letter forms are normalized by filepath.Clean.
func adminInside(root, p string) bool {
	if p == "" {
		return false
	}
	a, b := filepath.Clean(root), filepath.Clean(p)
	if runtime.GOOS == "windows" {
		a, b = strings.ToLower(a), strings.ToLower(b)
	}
	rel, err := filepath.Rel(a, b)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true // "." (the root itself) counts as inside
}
