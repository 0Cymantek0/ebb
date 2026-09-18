//go:build windows

package platform

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// CreateJunction creates a junction (or, when target names a volume
// GUID, a volume mount point) at path pointing at target — the same
// object class `cmd /c mklink /J` produces, requiring NO privilege
// (mount-point reparse points are set with FSCTL_SET_REPARSE_POINT,
// which is unprivileged; only symlink-tag reparse points need
// SeCreateSymbolicLinkPrivilege).
//
// target is the RETAINED INVENTORY LinkTarget spelling — the probe-side
// normalizeSubstituteName form: `C:\dir`, `\\server\share\dir`,
// `Volume{guid}\` or `\\?\Volume{guid}\`. It must be absolute (Windows
// junctions cannot carry relative targets) and is converted back into
// the `\??\`-prefixed substitute name the reparse buffer requires. The
// created junction round-trips exactly through os.Readlink and through
// the probe's classification (KindJunction / KindMountPoint with the
// same LinkTarget text).
func CreateJunction(path, target string) error {
	substitute, printName, err := junctionNames(target)
	if err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return fmt.Errorf("platform: create junction %s: %w", path, err)
	}
	buf, err := mountPointReparseBuffer(substitute, printName)
	if err != nil {
		return fmt.Errorf("platform: create junction %s: %w", path, err)
	}

	h, err := openReparseWriteHandle(path)
	if err != nil {
		_ = os.Remove(path) // roll back the plain directory we just made
		return fmt.Errorf("platform: create junction %s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	var returned uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT,
		&buf[0], uint32(len(buf)), nil, 0, &returned, nil); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("platform: create junction %s -> %s: FSCTL_SET_REPARSE_POINT: %w", path, target, err)
	}
	return nil
}

// CreateSymlink creates a true symbolic link at path pointing at target
// (relative or absolute text is preserved verbatim). On Windows this
// requires SeCreateSymbolicLinkPrivilege; a refusal is returned as the
// typed *LinkPrivilegeError so callers can name the capability instead
// of guessing at errno text.
func CreateSymlink(path, target string) error {
	if err := os.Symlink(target, path); err != nil {
		if asPrivilegeError(err) {
			return &LinkPrivilegeError{Path: path, Err: err}
		}
		return fmt.Errorf("platform: create symlink %s: %w", path, err)
	}
	return nil
}

// LinkPrivilegeError reports that the OS refused a link creation for
// lack of privilege: Windows SeCreateSymbolicLinkPrivilege (errno 1314
// ERROR_PRIVILEGE_NOT_HELD, or 740 ERROR_ELEVATION_REQUIRED on some
// configurations) for true symlinks. Junction creation never produces
// this error — that is the point of the junction path.
type LinkPrivilegeError struct {
	Path string
	Err  error
}

func (e *LinkPrivilegeError) Error() string {
	return fmt.Sprintf("platform: %s: creating this link requires SeCreateSymbolicLinkPrivilege (run elevated or enable Windows Developer Mode): %v",
		e.Path, e.Err)
}

func (e *LinkPrivilegeError) Unwrap() error { return e.Err }

// LinkPrivilegeBlocked is the structural marker the restore layer
// detects WITHOUT importing this package (same pattern as domain's
// IdentityMismatch contract).
func (e *LinkPrivilegeError) LinkPrivilegeBlocked() bool { return true }

// compile-time guarantee the typed error satisfies the structural
// contract restore detects.
var _ interface{ LinkPrivilegeBlocked() bool } = (*LinkPrivilegeError)(nil)

// asPrivilegeError reports whether err is an os.Symlink refusal caused
// by the missing symlink privilege.
func asPrivilegeError(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	const (
		errorPrivilegeNotHeld  = syscall.Errno(1314)
		errorElevationRequired = syscall.Errno(740)
	)
	return errno == errorPrivilegeNotHeld || errno == errorElevationRequired
}

// junctionNames maps a retained LinkTarget into the substitute and print
// names of a mount-point reparse buffer, mirroring what mklink /J writes
// (fsutil-verified on this tag: substitute `\??\<target>`, print
// `<target>`, `\\server\share` targets via the `\??\UNC\` spelling).
// The target text is used VERBATIM (no re-cleaning): it came from the
// capture-side substitute name of a real junction, so re-prefixing
// reproduces the original bytes exactly and os.Readlink round-trips the
// same spelling (Learnings, D008).
func junctionNames(target string) (substitute, printName string, err error) {
	if target == "" || strings.ContainsRune(target, 0) {
		return "", "", fmt.Errorf("platform: junction target %q is empty or carries NUL", target)
	}
	switch {
	case strings.HasPrefix(target, `\\?\Volume{`):
		// Go Readlink spelling of a volume mount point; the reparse
		// buffer uses the NT-namespace form.
		return `\??\` + strings.TrimPrefix(target, `\\?\`), target, nil
	case strings.HasPrefix(target, `Volume{`):
		return `\??\` + target, target, nil
	case strings.HasPrefix(target, `\\`):
		return `\??\UNC\` + strings.TrimPrefix(target, `\\`), target, nil
	}
	if !filepath.IsAbs(target) {
		return "", "", fmt.Errorf("platform: junction target %q must be absolute (Windows junctions cannot be relative)", target)
	}
	return `\??\` + target, target, nil
}

// mountPointReparseBuffer renders the FSCTL_SET_REPARSE_POINT input for
// a mount-point reparse point, byte-compatible with mklink /J output
// (fsutil-reparsepoint-query-verified on this machine):
//
//	[0:4]   ReparseTag = IO_REPARSE_TAG_MOUNT_POINT
//	[4:6]   ReparseDataLength = 12 + len(sub) + len(print) bytes
//	[6:8]   Reserved = 0
//	[8:10]  SubstituteNameOffset = 0        (relative to PathBuffer)
//	[10:12] SubstituteNameLength
//	[12:14] PrintNameOffset = SubstituteNameLength + 2 (NUL separator)
//	[14:16] PrintNameLength
//	[16:]   PathBuffer = substitute, NUL, print, NUL (UTF-16LE)
//
// The name lengths exclude their NUL separators; ReparseDataLength
// counts the four offset USHORTs (8) plus the full PathBuffer INCLUDING
// both NULs (so 12 + names) — exactly the arithmetic of a live mklink
// junction (sub 132 + print 124 + 12 = 268 = 0x10c).
func mountPointReparseBuffer(substitute, printName string) ([]byte, error) {
	sub, err := syscall.UTF16FromString(substitute) // trailing NUL included
	if err != nil {
		return nil, err
	}
	prn, err := syscall.UTF16FromString(printName)
	if err != nil {
		return nil, err
	}
	pathBuf := make([]uint16, 0, len(sub)+len(prn))
	pathBuf = append(pathBuf, sub...)
	pathBuf = append(pathBuf, prn...)

	subLen := uint16((len(sub) - 1) * 2) // exclude the NUL
	printLen := uint16((len(prn) - 1) * 2)
	dataLen := uint16(8 + len(pathBuf)*2) // offsets + PathBuffer with NULs

	buf := make([]byte, 16+len(pathBuf)*2)
	binary.LittleEndian.PutUint32(buf[0:4], ioReparseTagMountPoint)
	binary.LittleEndian.PutUint16(buf[4:6], dataLen)
	binary.LittleEndian.PutUint16(buf[6:8], 0) // Reserved
	binary.LittleEndian.PutUint16(buf[8:10], 0)
	binary.LittleEndian.PutUint16(buf[10:12], subLen)
	binary.LittleEndian.PutUint16(buf[12:14], subLen+2)
	binary.LittleEndian.PutUint16(buf[14:16], printLen)
	for i, u := range pathBuf {
		binary.LittleEndian.PutUint16(buf[16+i*2:], u)
	}
	return buf, nil
}

// openReparseWriteHandle opens an existing directory for reparse-point
// modification: write access, OPEN_REPARSE_POINT (the directory object
// itself, never a target) and BACKUP_SEMANTICS (required for
// directories; no backup privilege is needed for the flag).
func openReparseWriteHandle(path string) (windows.Handle, error) {
	p, err := extendLongPath(path)
	if err != nil {
		return 0, err
	}
	p16, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(p16, windows.GENERIC_WRITE, shareAll, nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, &os.PathError{Op: "CreateFile", Path: path, Err: err}
	}
	return h, nil
}
