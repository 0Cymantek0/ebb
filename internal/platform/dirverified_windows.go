//go:build windows

package platform

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// OpenDirVerified implements domain.VerifiedDirProbe — the SCAN-RACE-1
// fix for the inventory descent. os.Open FOLLOWS junctions and
// symlinks, which is exactly why the identity check must gate trust in
// the handle: when the path was substituted with a link after
// classification, the opened object is the TARGET, whose native
// identity differs from the classified directory's, so the mismatch is
// detected BEFORE any enumeration and no handle is returned.
//
// The identity spelling is fileIdentity.fileIdentityString — the SAME
// helper behind FileFacts.FileIdentity (and the components of
// RootIdentity) — so the classification-time and open-time spellings
// can never drift apart.
func (windowsProbe) OpenDirVerified(path, expectedIdentity string) (domain.IdentifiedDir, error) {
	if expectedIdentity == "" {
		return nil, fmt.Errorf("platform: OpenDirVerified(%q): empty expected identity", path)
	}
	f, err := os.Open(path) // FILE_FLAG_BACKUP_SEMANTICS: directory opens work
	if err != nil {
		return nil, err
	}
	if err := requireDir(f, path); err != nil {
		f.Close()
		return nil, err
	}
	ident, err := identityFromHandle(windows.Handle(f.Fd()))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("platform: identity of open directory %q: %w", path, err)
	}
	got := ident.fileIdentityString()
	if got != expectedIdentity {
		f.Close()
		return nil, &dirIdentityMismatchError{path: path, expected: expectedIdentity, got: got}
	}
	return &identifiedDir{f: f, identity: got}, nil
}
