package platform

import (
	"fmt"
	"os"
)

// dirIdentityMismatchError reports that the object opened at path is
// provably NOT the object the caller classified (SCAN-RACE-1): the
// opened handle's native identity differs from the expected identity
// captured at classification time. It satisfies the structural
// IdentityMismatch contract documented on domain.VerifiedDirProbe.
type dirIdentityMismatchError struct {
	path     string
	expected string
	got      string
}

func (e *dirIdentityMismatchError) Error() string {
	return fmt.Sprintf("platform: open %q: directory replaced between classification and open (expected identity %q, opened handle has %q)",
		e.path, e.expected, e.got)
}

// IdentityMismatch distinguishes a detected substitution from an
// ordinary open failure (see domain.VerifiedDirProbe).
func (e *dirIdentityMismatchError) IdentityMismatch() bool { return true }

// identifiedDir is one open, identity-verified directory handle.
//
// Both native implementations enumerate through the SAME os.File they
// verified: on Windows Go's ReadDir drives
// GetFileInformationByHandleEx(File*DirectoryInfo) on the handle
// (never re-resolving the path); on Linux it is getdents64 on the fd.
// A directory handle cannot be re-pointed, so a name substituted after
// open cannot redirect the enumeration.
type identifiedDir struct {
	f        *os.File
	identity string
}

// Identity returns the native identity spelling captured from the
// handle at open time (same helper FileFacts.FileIdentity uses).
func (d *identifiedDir) Identity() string { return d.identity }

// ReadDir enumerates the directory through the verified handle.
func (d *identifiedDir) ReadDir() ([]os.DirEntry, error) { return d.f.ReadDir(-1) }

// Close releases the handle.
func (d *identifiedDir) Close() error { return d.f.Close() }

// requireDir verifies the opened handle really is a directory (and not,
// say, a regular file opened at a substituted name).
func requireDir(f *os.File, path string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("platform: stat of open directory %q: %w", path, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("platform: open %q: not a directory", path)
	}
	return nil
}
