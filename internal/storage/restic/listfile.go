package resticstore

import (
	"os"
	"strings"

	"ebb/internal/domain"
)

// ValidateRelPaths enforces the D003 capture-list contract client-side,
// before any restic subprocess is spawned.
//
// restic itself accepts far more than is safe: absolute backslash and
// forward-slash forms, and even mixed absolute+relative lists — which
// silently store the same file under two tree prefixes (probe Q1,
// surprise 3). Ebb therefore only accepts clean, forward-slash,
// baseDir-relative entries. A leading "./" is stripped (D003 writes the
// op dir as ./<opdirname>/...), everything else that could re-root or
// escape the base dir is a typed usage error.
func ValidateRelPaths(rel []string) ([]string, error) {
	if len(rel) == 0 {
		return nil, storeErr(domain.StoreErrUsage, "resticstore: empty capture list")
	}
	seen := make(map[string]bool, len(rel))
	out := make([]string, 0, len(rel))
	for i, raw := range rel {
		p := raw
		for strings.HasPrefix(p, "./") {
			p = p[2:]
		}
		if p == "" || p == "." {
			return nil, storeErr(domain.StoreErrUsage, "resticstore: capture entry %d (%q) is empty", i, raw)
		}
		if strings.ContainsRune(p, 0) {
			return nil, storeErr(domain.StoreErrUsage, "resticstore: capture entry %d contains NUL", i)
		}
		if len(p) >= 2 && p[1] == ':' {
			return nil, storeErr(domain.StoreErrUsage,
				"resticstore: capture entry %d (%q) is absolute (drive prefix); D003 requires baseDir-relative entries", i, raw)
		}
		if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") || strings.HasPrefix(p, "\\\\") {
			return nil, storeErr(domain.StoreErrUsage,
				"resticstore: capture entry %d (%q) is absolute or UNC/device-prefixed; D003 requires baseDir-relative entries", i, raw)
		}
		if strings.Contains(p, "\\") {
			return nil, storeErr(domain.StoreErrUsage,
				"resticstore: capture entry %d (%q) uses backslash separators; use forward slashes relative to baseDir", i, raw)
		}
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." {
				return nil, storeErr(domain.StoreErrUsage,
					"resticstore: capture entry %d (%q) escapes baseDir via '..'", i, raw)
			}
			if seg == "" || seg == "." {
				return nil, storeErr(domain.StoreErrUsage,
					"resticstore: capture entry %d (%q) has an empty or '.' segment", i, raw)
			}
		}
		if seen[p] {
			return nil, storeErr(domain.StoreErrUsage, "resticstore: capture entry %d (%q) is duplicated", i, raw)
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// writeListFile writes the NUL-delimited --files-from-raw list.
//
// The trailing NUL after the last entry is MANDATORY: without it restic
// rejects the whole backup with "trailing zero byte missing" (probe Q1).
// Newline is never a separator, so entry names may contain anything
// except NUL (enforced by ValidateRelPaths).
func writeListFile(dir string, rel []string) (string, error) {
	f, err := os.CreateTemp(dir, "ebb-files-raw-")
	if err != nil {
		return "", storeErr(domain.StoreErrUnknown, "resticstore: capture list temp file: %v", err)
	}
	var b strings.Builder
	for _, p := range rel {
		b.WriteString(p)
		b.WriteByte(0)
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", storeErr(domain.StoreErrUnknown, "resticstore: writing capture list: %v", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", storeErr(domain.StoreErrUnknown, "resticstore: closing capture list: %v", err)
	}
	return f.Name(), nil
}
