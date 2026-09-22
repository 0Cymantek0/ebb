//go:build linux

package platform

import (
	"fmt"
	"os"
	"syscall"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// devInoIdentity is the single spelling of Linux native identity,
// "<dev-hex>:<ino-hex>". ProbeFile (FileFacts.FileIdentity) and
// OpenDirVerified both render through it so the classification-time
// and open-time spellings can never drift apart. RootIdentity carries
// the same two components in its struct fields.
func devInoIdentity(st syscall.Stat_t) string {
	return fmt.Sprintf("%x:%x", uint64(st.Dev), uint64(st.Ino))
}

// OpenDirVerified implements domain.VerifiedDirProbe — the SCAN-RACE-1
// fix for the inventory descent. os.Open FOLLOWS symlinks, which is
// exactly why the identity check must gate trust in the handle: when
// the path was substituted with a symlink after classification, the
// opened object is the TARGET, whose dev+ino differ from the classified
// directory's, so the mismatch is detected BEFORE any enumeration and
// no handle is returned.
func (linuxProbe) OpenDirVerified(path, expectedIdentity string) (domain.IdentifiedDir, error) {
	if expectedIdentity == "" {
		return nil, fmt.Errorf("platform: OpenDirVerified(%q): empty expected identity", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := requireDir(f, path); err != nil {
		f.Close()
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		f.Close()
		return nil, fmt.Errorf("platform: fstat of open directory %q: %w", path, err)
	}
	got := devInoIdentity(st)
	if got != expectedIdentity {
		f.Close()
		return nil, &dirIdentityMismatchError{path: path, expected: expectedIdentity, got: got}
	}
	return &identifiedDir{f: f, identity: got}, nil
}
