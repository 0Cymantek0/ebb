package restore

// Link staging and recreation (Foundation §12.5 step 6, Wave F). The
// backend cannot materialize reparse points on unprivileged Windows
// (restic needs SeCreateSymbolicLinkPrivilege for ANY link node), so
// the staging restore EXCLUDES every retained link node — plus the
// frozen op dir, whose documents are read back through DumpFile and
// never staged — and this layer then recreates each link natively from
// the retained inventory's LinkTarget:
//
//   - junctions/mount points (the pnpm/node_modules shape) are created
//     UNPRIVILEGED (mount-point reparse points need no token privilege);
//   - true symlinks are privilege-gated on Windows; a refusal fails the
//     open BEFORE publish with a precise typed error naming the blocked
//     entries and the two options (elevate / Developer Mode), because a
//     link that cannot be recreated means the staged tree differs from
//     the sealed inventory and the oracle would reject it anyway.
//
// The capability arrives through the Dependencies.CreateLink seam: this
// package must not import internal/platform (Module boundaries; the
// oracle/capture seams already cross packages only through domain
// contracts). The default seam is the stdlib os.Symlink with the
// Windows privilege refusal mapped to the typed contract; the platform
// implementation (junction-capable) is injected at wiring time — by
// tests here and in lifecycle, and by internal/cli in the integration
// wave that follows (orchestrator note: restore.New callers must pass
// CreateLink: platform.CreateLink).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// LinkCreator recreates one link of the given inventory kind (symlink /
// junction / mount-point) at path with the retained literal target
// text. Errors that are privilege refusals must satisfy
// interface{ LinkPrivilegeBlocked() bool } — the structural contract
// this package detects without importing internal/platform (mirroring
// domain's IdentityMismatch pattern).
type LinkCreator func(kind domain.EntryKind, path, target string) error

// privilegeBlockedLink is the structural privilege-refusal contract.
type privilegeBlockedLink interface {
	LinkPrivilegeBlocked() bool
}

// excludingRestorer is the optional store capability the link-safe
// staging path upgrades to: a restore that skips exactly the listed
// snapshot-relative paths. The restic adapter implements it
// (RestoreExcluding); stores that do not follow the legacy staging
// contract instead (full subtree restore, links included — the store
// itself owns link materialization there, so no native recreation
// runs and behavior is exactly the pre-Wave-F one).
type excludingRestorer interface {
	RestoreExcluding(ctx context.Context, repoDir, passfile, snapID, dest string, excludes []string) error
}

// stdlibCreateLink is the default LinkCreator: os.Symlink for every
// kind (the only stdlib link primitive). On Windows an unprivileged
// symlink refusal (errno 1314/740) is mapped to the typed privilege
// contract so even the unwired default reports the precise blocker
// instead of a raw errno.
func stdlibCreateLink(kind domain.EntryKind, path, target string) error {
	if err := os.Symlink(target, path); err != nil {
		if runtime.GOOS == "windows" && isLinkPrivilegeErrno(err) {
			return &stdlibPrivilegeError{path: path, err: err}
		}
		return err
	}
	return nil
}

type stdlibPrivilegeError struct {
	path string
	err  error
}

func (e *stdlibPrivilegeError) Error() string {
	return fmt.Sprintf("restore: %s: creating this link requires SeCreateSymbolicLinkPrivilege (run elevated or enable Windows Developer Mode): %v",
		e.path, e.err)
}

func (e *stdlibPrivilegeError) Unwrap() error { return e.err }

func (e *stdlibPrivilegeError) LinkPrivilegeBlocked() bool { return true }

func isLinkPrivilegeErrno(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == 1314 || errno == 740
}

// stagePayload materializes the payload snapshot into stage. When the
// store supports exclusion, every link node and the op dir are skipped
// (and the caller then recreates links natively); otherwise the legacy
// subtree restore runs unchanged. The bool reports whether links were
// excluded (i.e. native recreation is the caller's job).
func (o *Opener) stagePayload(ctx context.Context, vault VaultRef, snap catalog.Snapshot, docs payloadDocs, stage string) (linksExcluded bool, err error) {
	if ex, ok := o.store.(excludingRestorer); ok {
		excludes := docs.stageExcludes()
		if err := ex.RestoreExcluding(ctx, vault.RepoDir, vault.Passfile, snap.PayloadBackendID, stage, excludes); err != nil {
			return true, fmt.Errorf("restore: materialize payload into staging: %w", err)
		}
		return true, nil
	}
	if err := o.store.Restore(ctx, vault.RepoDir, vault.Passfile, snap.PayloadBackendID,
		"/"+docs.wsPrefix, stage); err != nil {
		return false, fmt.Errorf("restore: materialize payload into staging: %w", err)
	}
	return false, nil
}

// recreateLinks rebuilds every retained link inside the staged tree
// from the retained inventory's LinkTarget text. Parents are already
// present (the staging restore materialized every non-link entry;
// links are never descended, so a link's parent is always a real
// directory). A privilege refusal or any other failure fails the open
// before publish through the typed ErrLinksBlocked.
func (o *Opener) recreateLinks(staged string, links []domain.Entry) error {
	var blocked, failed []string
	for _, e := range links {
		p := filepath.Join(staged, filepath.FromSlash(e.Path))
		err := o.createLink(e.Kind, p, e.LinkTarget)
		if err == nil {
			continue
		}
		var pb privilegeBlockedLink
		if errors.As(err, &pb) && pb.LinkPrivilegeBlocked() {
			blocked = append(blocked, e.Path)
			continue
		}
		failed = append(failed, fmt.Sprintf("%s (%s): %v", e.Path, e.Kind, err))
	}
	if len(blocked) == 0 && len(failed) == 0 {
		return nil
	}
	return &ErrLinksBlocked{PrivilegeBlocked: blocked, Failures: failed}
}
