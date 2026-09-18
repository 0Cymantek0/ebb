package policy

import (
	"fmt"
	"strings"
)

// ValidateRelPath enforces the root-relative path contract of Foundation
// §7.2: '/' separators only; NUL bytes, absolute roots, drive prefixes,
// '..' segments, empty segments and backslashes are rejected. When
// allowDot is true the single-segment path "." is accepted (used for the
// regenerate root default); '.' inside a longer path is always rejected.
func ValidateRelPath(p string, allowDot bool) error {
	if p == "" {
		return errBadPath(p, "empty path")
	}
	if strings.Contains(p, "\x00") {
		return errBadPath(p, "NUL byte")
	}
	if strings.Contains(p, "\\") {
		return errBadPath(p, "backslash; use '/' separators")
	}
	if strings.HasPrefix(p, "/") {
		return errBadPath(p, "absolute path")
	}
	segs := strings.Split(p, "/")
	for _, seg := range segs {
		switch {
		case seg == "":
			return errBadPath(p, "empty segment (double or trailing '/')")
		case seg == "..":
			return errBadPath(p, "'..' segment")
		case seg == ".":
			if !(allowDot && len(segs) == 1) {
				return errBadPath(p, "'.' segment")
			}
		}
		if len(seg) >= 2 && seg[1] == ':' {
			return errBadPath(p, "drive prefix")
		}
	}
	return nil
}

// ValidateGlob enforces the restricted glob grammar: the path rules of
// ValidateRelPath (no '.' allowance) plus: '**' is legal only as a
// complete segment; any other use of '**' inside a segment (e.g. 'a**b')
// and any regular-expression-like syntax ('[', ']', '{', '}') is
// rejected. Backslashes cannot appear, so there are no escapes.
func ValidateGlob(g string) error {
	if g == "" {
		return errBadPath(g, "empty pattern")
	}
	if strings.Contains(g, "\x00") {
		return errBadPath(g, "NUL byte")
	}
	if strings.Contains(g, "\\") {
		return errBadPath(g, "backslash; use '/' separators")
	}
	if strings.HasPrefix(g, "/") {
		return errBadPath(g, "absolute pattern")
	}
	for _, seg := range strings.Split(g, "/") {
		switch {
		case seg == "":
			return errBadPath(g, "empty segment (double or trailing '/')")
		case seg == "..":
			return errBadPath(g, "'..' segment")
		case seg == ".":
			return errBadPath(g, "'.' segment")
		}
		if len(seg) >= 2 && seg[1] == ':' {
			return errBadPath(g, "drive prefix")
		}
		if seg != "**" && strings.Contains(seg, "**") {
			return errBadPath(g, "'**' is only valid as a complete path segment")
		}
		if strings.ContainsAny(seg, "[]{}") {
			return errBadPath(g, "unsupported syntax; only '*', '?' and complete-segment '**' are allowed")
		}
	}
	return nil
}

func errBadPath(p, why string) error {
	return fmt.Errorf("invalid root-relative path %q: %s", p, why)
}

// isGlobMeta reports whether c is a glob metacharacter.
func isGlobMeta(c byte) bool { return c == '*' || c == '?' }

// segMatch matches one path segment against one pattern segment.
//
// '*' matches any run of characters within the segment and '?' exactly
// one character, but neither matches a literal metacharacter in the name
// (F52): the glob "a*b" does not match a file literally named "a*b".
// segMatchBudget bounds the total recursive work one segment match may
// perform. Without it the backtracking matcher explodes exponentially on
// hostile patterns like "*a*a*a*a*a*a*a*b" against long names
// (POL-GLOB-1); a blown budget is surfaced as a validation error, never
// a hang.
const segMatchBudget = 200_000

type budgetExceeded struct{}

func (budgetExceeded) Error() string { return "policy: glob match budget exceeded" }

func segMatchSafe(pattern, name string) (matched bool, err error) {
	var steps int
	ok, over := segMatchBounded(pattern, name, &steps)
	if over {
		return false, budgetExceeded{}
	}
	return ok, nil
}

func segMatchBounded(pattern, name string, steps *int) (bool, bool) {
	*steps++
	if *steps > segMatchBudget {
		return false, true
	}
	if pattern == "" {
		return name == "", false
	}
	switch pattern[0] {
	case '*':
		for i := 0; i <= len(name); i++ {
			if i > 0 && isGlobMeta(name[i-1]) {
				break // '*' never consumes a literal metacharacter
			}
			if ok, over := segMatchBounded(pattern[1:], name[i:], steps); ok || over {
				return ok, over
			}
		}
		return false, false
	case '?':
		if name == "" || isGlobMeta(name[0]) {
			return false, false
		}
		return segMatchBounded(pattern[1:], name[1:], steps)
	default:
		if name == "" || name[0] != pattern[0] {
			return false, false
		}
		return segMatchBounded(pattern[1:], name[1:], steps)
	}
}

// globMatch matches '/'-separated path segments against pattern
// segments. A complete-segment "**" matches zero or more path segments,
// so "a/**" matches "a" itself and everything below it. Matching is
// case-sensitive.
func globMatch(pattern, path []string) (bool, error) {
	if len(pattern) == 0 {
		return len(path) == 0, nil
	}
	if pattern[0] == "**" {
		for skip := 0; skip <= len(path); skip++ {
			ok, err := globMatch(pattern[1:], path[skip:])
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	if len(path) == 0 {
		return false, nil
	}
	ok, err := segMatchSafe(pattern[0], path[0])
	if err != nil || !ok {
		return false, err
	}
	return globMatch(pattern[1:], path[1:])
}

// matchGlobPath reports whether the glob pattern matches the
// root-relative path, and surfaces a blown match budget as an error
// (POL-GLOB-1: hostile patterns must fail fast, not hang).
func matchGlobPath(pattern, path string) (bool, error) {
	return globMatch(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

// pathUnder reports whether path is inside dir (or equals dir).
func pathUnder(dir, path string) bool {
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// pathsOverlap reports whether two root-relative paths are equal or one
// contains the other.
func pathsOverlap(a, b string) bool {
	return pathUnder(a, b) || pathUnder(b, a)
}
