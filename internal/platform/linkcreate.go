package platform

// Native link RE-creation (Foundation §12.5, Wave F). Capture classifies
// and records link text through the probe side of this package; the
// restore ("open") path needs the inverse operation — materialize a link
// of a recorded inventory kind at a staged path with the retained
// literal target text. The backend cannot do this for reparse points on
// unprivileged Windows (restic needs SeCreateSymbolicLinkPrivilege for
// ANY reparse materialization), so restore recreates links itself
// through the CreateLink seam defined here:
//
//   - KindJunction / KindMountPoint → CreateJunction: a mount-point
//     reparse point via FSCTL_SET_REPARSE_POINT. This needs NO privilege
//     on Windows (it is what `mklink /J` does), which is the capability
//     that closes the unprivileged-open acceptance gap for junction
//     workspaces (pnpm-style node_modules).
//   - KindSymlink → CreateSymlink: a true symbolic link. On Windows this
//     genuinely requires SeCreateSymbolicLinkPrivilege (elevated process
//     or Developer Mode); the refusal is reported through the typed
//     LinkPrivilegeError so callers surface a precise blocker instead of
//     a raw errno. Linux/darwin symlinks are unprivileged.
//
// The error contract between this package and the restore layer is
// structural: a privilege refusal satisfies
// interface{ LinkPrivilegeBlocked() bool } — restore never imports
// platform (mirroring the IdentityMismatch() precedent in domain).

import (
	"fmt"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// CreateLink recreates one link of the given inventory kind at path with
// the retained literal target text. It is the wiring point the restore
// layer's Dependencies.CreateLink seam receives (the restore package
// cannot import platform; the CLI passes platform.CreateLink).
func CreateLink(kind domain.EntryKind, path, target string) error {
	switch kind {
	case domain.KindSymlink:
		return CreateSymlink(path, target)
	case domain.KindJunction, domain.KindMountPoint:
		return CreateJunction(path, target)
	default:
		return fmt.Errorf("platform: CreateLink: unsupported link kind %q", kind)
	}
}
