// Package resticstore implements domain.SnapshotStore on top of the
// restic 0.19.1 CLI subprocess, per Foundation §11, decision D003 and
// the verified behaviors in lab/restic-probe/FINDINGS.md.
//
// Contract highlights (all probe-verified, all load-bearing):
//
//   - The password never appears in argv; it is passed via the
//     RESTIC_PASSWORD_FILE environment variable. The child environment
//     is constructed from a minimal substrate (PATH, TEMP/TMP and the
//     Windows system variables) so hostile inherited RESTIC_* values
//     cannot retarget the adapter, and RESTIC_LOG_DIR is never set.
//   - Every subprocess gets a private RESTIC_CACHE_DIR under the OS temp
//     root so Ebb never touches the user's global restic cache.
//   - Capture uses cwd-relative entries with --files-from-raw (D003):
//     the subprocess runs with cwd = baseDir and the NUL-delimited list
//     ends with a mandatory trailing NUL byte. Mixed absolute/relative
//     or backslash-separated entries are rejected client-side because
//     restic silently accepts them and duplicates content under two
//     tree prefixes (probe surprise 3).
//   - A backup that exits non-zero OR emits any stderr
//     {"message_type":"error"} record is a failed capture even when a
//     snapshot id was produced: restic stores the incomplete snapshot
//     with no marker anywhere (probe Q4a). The returned error says so
//     explicitly; callers must never treat that id as a capture.
//   - Exit-code classes: 3 source, 10 repo, 12 auth, 2 usage, anything
//     else unknown (refined from the stderr exit_error JSON code when
//     present).
//   - The adapter never runs `restic unlock`; a lock-held failure is
//     surfaced with a precise note (Foundation §12.1).
//
// The adapter is stateless across calls: Init caches nothing and
// RepoID derives the repository identity from `cat config` each call
// (the on-disk config file is encrypted).
package resticstore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds every restic subprocess even when the caller's
// context has no deadline.
const DefaultTimeout = 15 * time.Minute

// hostTag constants: all Ebb-owned snapshots carry host "ebb" and the
// discovery tag ebb:v1 (Foundation §11.3: tags are hints, never
// authorization records).
const (
	backupHost = "ebb"
	baseTagKey = "ebb"
	baseTagVal = "v1"
)

// Store is a restic-CLI-backed domain.SnapshotStore. Create one with
// New and release its private cache directory with Close. All methods
// are safe for concurrent use; each subprocess is context-bounded.
type Store struct {
	binary  string
	timeout time.Duration

	cacheOnce sync.Once
	cacheDir  string
	cacheErr  error
}

// New returns a Store running the given restic binary ("" and bare
// names such as "restic" resolve through PATH, via exec.LookPath BEFORE
// any absolutization — a bare name must never silently select a restic
// binary sitting in the working directory). An absolute path is used as
// given (separator-normalized); an explicitly relative path ("./restic")
// names a cwd-relative file on purpose and is absolutized. A bare name
// PATH cannot resolve stays bare, so the first command fails with the
// honest not-found error instead of a cwd-hijacked copy.
func New(binary string) *Store {
	if binary == "" {
		binary = "restic"
	}
	switch {
	case filepath.IsAbs(binary):
		if abs, err := filepath.Abs(binary); err == nil {
			binary = abs
		}
	case strings.ContainsAny(binary, `/\`):
		// An explicitly relative path is deliberate cwd-relative naming,
		// not a bare name the caller expects PATH to answer.
		if abs, err := filepath.Abs(binary); err == nil {
			binary = abs
		}
	default:
		// Bare name: resolve through PATH, never filepath.Abs — Abs
		// here would turn "restic" into <cwd>\restic, the cwd-hijack
		// trap freezer.New's resolution deliberately avoids.
		if resolved, err := exec.LookPath(binary); err == nil {
			binary = resolved
		}
	}
	return &Store{binary: binary, timeout: DefaultTimeout}
}

// SetTimeout overrides the per-command timeout (testing).
func (s *Store) SetTimeout(d time.Duration) { s.timeout = d }

// Close removes the private cache directory. Call it when the store
// will no longer be used (defer in the product path, t.Cleanup in
// tests); leaked cache dirs contain only restic scratch data.
func (s *Store) Close() {
	if s.cacheDir != "" {
		os.RemoveAll(s.cacheDir)
	}
}

// cache lazily creates the per-store private cache directory.
func (s *Store) cache() (string, error) {
	s.cacheOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ebb-restic-cache-")
		if err != nil {
			s.cacheErr = fmt.Errorf("resticstore: private cache dir: %w", err)
			return
		}
		s.cacheDir = dir
	})
	return s.cacheDir, s.cacheErr
}

// osSubstrateVars lists the inherited variables the restic binary
// minimally needs and that carry no restic semantics. Everything else
// from the parent environment is dropped by construction, so no
// inherited RESTIC_* variable (repository location, password, log dir)
// can reach the child.
func osSubstrateVars() []string {
	if runtime.GOOS == "windows" {
		return []string{"PATH", "SYSTEMROOT", "COMSPEC", "WINDIR", "TEMP", "TMP", "PATHEXT"}
	}
	return []string{"PATH", "TMPDIR", "LANG", "LC_ALL", "TZ"}
}

// envKeyMatches compares an inherited variable name against an
// allowlist entry; Windows environment lookup is case-insensitive.
func envKeyMatches(name, want string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(name, want)
	}
	return name == want
}

// envFor builds the complete child environment for one command.
// RESTIC_LOG_DIR is intentionally absent (never set, never inherited).
func (s *Store) envFor(passfile string) ([]string, error) {
	cacheDir, err := s.cache()
	if err != nil {
		return nil, err
	}
	inherited := os.Environ()
	out := make([]string, 0, len(osSubstrateVars())+2)
	for _, want := range osSubstrateVars() {
		for _, kv := range inherited {
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				continue
			}
			if envKeyMatches(kv[:eq], want) {
				out = append(out, kv)
				break // first spelling wins
			}
		}
	}
	out = append(out,
		"RESTIC_PASSWORD_FILE="+passfile,
		"RESTIC_CACHE_DIR="+cacheDir,
	)
	return out, nil
}
