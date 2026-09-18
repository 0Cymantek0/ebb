package restore

// Staging cleanup and publication (Foundation §12.5 steps 6-9). The
// mutations permitted here are exactly the package's sanctioned set:
// shape-gated removal of .ebb-stage-<32hex> directories, removal of an
// EMPTY destination directory, and the publish rename of the staged
// workspace tree onto the absent destination.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"
)

// stageShape matches the only base names this package may ever remove:
// its own staging directories. Everything else is refused (mirroring
// lifecycle's shape-gated removeEbbOwned).
var stageShape = regexp.MustCompile(`^\.ebb-stage-[0-9a-f]{32}$`)

// removeStage removes an Ebb-owned staging directory after use (or
// after a failed verification). It refuses any path whose base name is
// not the .ebb-stage-<32hex> shape, so it can never be repurposed
// against user content. A missing directory is success (idempotent).
func removeStage(path string) error {
	if !stageShape.MatchString(filepath.Base(path)) {
		return fmt.Errorf("restore: refusing to remove %q: not an Ebb-owned staging directory", path)
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("restore: cleanup staging %s: %w", path, err)
	}
	return nil
}

// prepareDestination ensures the destination is absent immediately
// before the publish rename (§12.5 "after checking that the target is
// still absent" — F35). An existing EMPTY directory is removed (the
// only sanctioned destination mutation); anything else — including a
// directory that gained content since preflight — is an occupant.
func prepareDestination(dest string) error {
	fi, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("destination %s: %w", dest, err)
	}
	if !fi.IsDir() {
		return &ErrDestinationOccupied{Destination: dest, Occupant: "an existing non-directory file"}
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return fmt.Errorf("destination %s: %w", dest, err)
	}
	if len(entries) > 0 {
		return &ErrDestinationOccupied{Destination: dest, Occupant: fmt.Sprintf(
			"a directory that gained content since preflight (first entry %q)", entries[0].Name())}
	}
	// Still empty: remove it so the rename lands on an absent path.
	if err := os.Remove(dest); err != nil {
		if errors.Is(err, syscall.ENOTEMPTY) {
			// Raced with a writer between ReadDir and Remove.
			return &ErrDestinationOccupied{Destination: dest, Occupant: "a directory that gained content during publication"}
		}
		return fmt.Errorf("removing empty destination %s: %w", dest, err)
	}
	return nil
}

// rename retry bounds (Windows sharing violations during rename:
// concurrent readers without FILE_SHARE_DELETE hold the tree —
// Learnings precedent; bounded, never schedule-on-reboot).
const (
	renameAttempts = 5
	renameBackoff  = 100 * time.Millisecond
)

// renameWithRetry publishes the staged workspace tree by renaming it
// onto the (verified-absent) destination, retrying Windows sharing
// violations (errno 32) and access denials (errno 5) a bounded number
// of times with backoff. Any other failure returns immediately.
func renameWithRetry(from, to string) error {
	var lastErr error
	for attempt := 0; attempt < renameAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(renameBackoff)
		}
		err := os.Rename(from, to)
		if err == nil {
			return nil
		}
		if !isRetryableRenameError(err) {
			return err
		}
		lastErr = err
	}
	return fmt.Errorf("rename %s -> %s still blocked after %d attempts: %w",
		from, to, renameAttempts, lastErr)
}

// isRetryableRenameError matches Windows ERROR_SHARING_VIOLATION (32)
// and ERROR_ACCESS_DENIED (5). On non-Windows platforms errno 32 is
// EPIPE and 5 is EIO — deliberately not matched (lifecycle precedent).
func isRetryableRenameError(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == 32 || errno == 5)
}
