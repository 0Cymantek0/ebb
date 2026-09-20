// Workspace correlation (D040 §B "The Semantic Bridge"): cross-reference
// Docker daemon paths (compose working_dir labels) and image names
// against the live workspace roots the analyse worker scanned.
//
// Normalization rule (documented, single implementation):
//
//  1. Trim whitespace.
//  2. On Windows builds only, map WSL/git-bash drive spellings to drive
//     form: "/mnt/c/Users/x" and "/c/Users/x" both become "C:\Users\x".
//     (Docker Desktop compose running inside WSL records /mnt/<drive>
//     labels while the host tool sees C:\ paths.) On other platforms
//     those are real POSIX paths and are left untouched.
//  3. Normalize separators to the native form.
//  4. Canonicalize through internal/pathcanon (symlinks, junctions,
//     8.3-short and true-case spellings). Missing paths fall back to
//     their cleaned lexical spelling — documented pathcanon residual.
//  5. Comparison keys fold case on Windows only (NTFS is
//     case-insensitive; ext4 is not).
//
// Uncorrelated is a valid answer: honesty over coverage. An image with
// no correlation is never forced into a tier.
package dockeradapter

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"ebb/internal/pathcanon"
)

// Thresholds from the D040 tier table (see tiers.go for the full set).
const (
	// activeWorkspaceAge: a workspace touched within this window is
	// active and everything correlated to it is shielded.
	activeWorkspaceAge = 14 * 24 * time.Hour
	// activityScanEntries bounds the depth-1 activity scan.
	activityScanEntries = 512
)

var (
	// wslDriveRe matches "/mnt/<drive>/rest" (Docker Desktop WSL labels).
	wslDriveRe = regexp.MustCompile(`^/mnt/([a-zA-Z])(/(.*))?$`)
	// gitBashDriveRe matches "/<drive>/rest" (Git Bash / cygwin style).
	gitBashDriveRe = regexp.MustCompile(`^/([a-zA-Z])(/(.*))?$`)
)

// anonymousVolumeRe matches the 64-hex anonymous volume names.
var anonymousVolumeRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// isAnonymousVolumeName reports the compose-generated anonymous shape.
func isAnonymousVolumeName(name string) bool {
	return anonymousVolumeRe.MatchString(name)
}

// normalizeDockerPath applies rule steps 1-3 above.
func normalizeDockerPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if runtime.GOOS == "windows" {
		if m := wslDriveRe.FindStringSubmatch(p); m != nil {
			rest := ""
			if m[3] != "" {
				rest = strings.ReplaceAll("/"+m[3], "/", string(filepath.Separator))
			}
			return strings.ToUpper(m[1]) + ":" + string(filepath.Separator) + strings.TrimPrefix(rest, string(filepath.Separator))
		}
		if m := gitBashDriveRe.FindStringSubmatch(p); m != nil {
			rest := ""
			if m[3] != "" {
				rest = strings.ReplaceAll("/"+m[3], "/", string(filepath.Separator))
			}
			return strings.ToUpper(m[1]) + ":" + string(filepath.Separator) + strings.TrimPrefix(rest, string(filepath.Separator))
		}
		return strings.ReplaceAll(p, "/", string(filepath.Separator))
	}
	return filepath.Clean(strings.ReplaceAll(p, "\\", "/"))
}

// pathKey is the full comparison key for one path spelling (steps 1-5).
func pathKey(p string) string {
	normalized := normalizeDockerPath(p)
	if normalized == "" {
		return ""
	}
	key := pathcanon.CanonicalPath(normalized)
	if runtime.GOOS == "windows" {
		return strings.ToLower(key)
	}
	return key
}

// dirExistsDockerPath reports whether one Docker-side path (a compose
// working_dir label) exists as a directory on this filesystem, after
// normalization + canonicalization. Existence is the deleted/merged
// discriminator for tiers 2/6: a working_dir that no longer exists is a
// zombie by definition; one that exists but matches no scanned root is
// somebody's unscanned project and stays shielded.
func dirExistsDockerPath(p string) bool {
	normalized := normalizeDockerPath(p)
	if normalized == "" {
		return false
	}
	info, err := os.Stat(pathcanon.CanonicalPath(normalized))
	return err == nil && info.IsDir()
}

// correlateDockerPath resolves one Docker-side path against the scanned
// roots: (entry, matched, exists). exists is the filesystem fact;
// matched means it correlates to a scanned root (equal or below it).
func (ix *workspaceIndex) correlateDockerPath(p string) (entry wsEntry, matched, exists bool) {
	exists = dirExistsDockerPath(p)
	entry, matched = ix.matchPath(p)
	return entry, matched, exists
}

// wsEntry is one live workspace root the analyse worker scanned.
type wsEntry struct {
	Root    string // original spelling (for shields/details)
	Key     string // comparison key
	Base    string // lowercased final path segment (name correlation)
	Active  bool   // activity within activeWorkspaceAge
	LastUse time.Time
}

// workspaceIndex is the correlation target: the set of scanned roots.
type workspaceIndex struct {
	entries []wsEntry
}

// buildWorkspaceIndex canonicalizes every root and derives its activity
// signal. Unresolvable/empty roots are skipped (honesty: an unusable
// root cannot veto anything, and it cannot correlate either).
func buildWorkspaceIndex(roots []string, now time.Time) *workspaceIndex {
	ix := &workspaceIndex{}
	seen := map[string]bool{}
	for _, root := range roots {
		key := pathKey(root)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		canonical := normalizeDockerPath(root)
		if resolved := pathcanon.CanonicalPath(canonical); resolved != "" {
			canonical = resolved
		}
		lastUse, ok := workspaceActivity(canonical)
		if !ok {
			// Root not statable: keep it correlatable by key only, but
			// never treat it as active (unknown shields, not recommends).
			ix.entries = append(ix.entries, wsEntry{
				Root: root, Key: key,
				Base: lowerBase(canonical),
			})
			continue
		}
		ix.entries = append(ix.entries, wsEntry{
			Root:    root,
			Key:     key,
			Base:    lowerBase(canonical),
			LastUse: lastUse,
			Active:  now.Sub(lastUse) < activeWorkspaceAge,
		})
	}
	return ix
}

// workspaceActivity derives a dormancy signal from the filesystem: the
// newest mtime among the root and its depth-1 entries (bounded). A
// shallow proxy by construction — the analyse worker's git-level
// activity data is not in this package's frozen input; documented as
// such, and every unknown resolves to the shielded side.
func workspaceActivity(root string) (time.Time, bool) {
	fi, err := os.Stat(root)
	if err != nil {
		return time.Time{}, false
	}
	latest := fi.ModTime()
	entries, err := os.ReadDir(root)
	if err != nil {
		return latest, true
	}
	scanned := 0
	for _, de := range entries {
		if scanned++; scanned > activityScanEntries {
			break
		}
		if info, ierr := de.Info(); ierr == nil && info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest, true
}

// matchPath correlates one Docker-side path (compose working_dir) to a
// scanned root: equal keys or the root containing the path.
func (ix *workspaceIndex) matchPath(p string) (wsEntry, bool) {
	key := pathKey(p)
	if key == "" {
		return wsEntry{}, false
	}
	for _, e := range ix.entries {
		if e.Key == key || pathcanon.UnderPath(e.Key, key) {
			return e, true
		}
	}
	return wsEntry{}, false
}

// matchName correlates an image repository base name to a workspace:
// equal to the root's base, or a compose-style "<base>-<service>" /
// "<base>_<service>" derivation. Folded (docker repositories are
// lowercase; NTFS bases are not).
func (ix *workspaceIndex) matchName(repo string) (wsEntry, bool) {
	base := strings.ToLower(repoBase(repo))
	if base == "" {
		return wsEntry{}, false
	}
	for _, e := range ix.entries {
		if e.Base == "" {
			continue
		}
		if base == e.Base ||
			strings.HasPrefix(base, e.Base+"-") ||
			strings.HasPrefix(base, e.Base+"_") {
			return e, true
		}
	}
	return wsEntry{}, false
}

// repoBase strips registry host and namespace: "docker.io/library/node"
// -> "node", "ghcr.io/acme/api" -> "api", "myproj-web" -> "myproj-web".
func repoBase(repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return ""
	}
	segs := strings.Split(strings.ReplaceAll(repo, "\\", "/"), "/")
	return segs[len(segs)-1]
}

// repoFirstSegment returns the first path segment (host/namespace
// detection for upstream-registry shaping).
func repoFirstSegment(repo string) string {
	repo = strings.TrimSpace(repo)
	segs := strings.Split(strings.ReplaceAll(repo, "\\", "/"), "/")
	if len(segs) == 0 {
		return ""
	}
	return segs[0]
}

func lowerBase(p string) string {
	base := filepath.Base(strings.TrimRight(normalizeDockerPath(p), string(filepath.Separator)))
	return strings.ToLower(base)
}

// shortID renders docker's conventional 12-char display prefix.
func shortID(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		id = id[i+1:]
	}
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
