package restore

import (
	"fmt"
	"strings"

	"ebb/internal/domain"
)

// Typed errors of the restore ("open") coordinator, mirroring the style
// of internal/lifecycle/errors.go: every failure that decides whether
// anything is published is one of these (matched with errors.Is /
// errors.As), never a bare fmt.Errorf. Each carries a stable
// EBB_E_-prefixed code for the CLI's §17.5 exit-outcome mapping.

// Stable error codes (Foundation §5.5: blockers carry a stable code).
const (
	CodeNotOpenable       = "EBB_E_NOT_OPENABLE"
	CodeSealInvalid       = "EBB_E_SEAL_INVALID"
	CodeDestOccupied      = "EBB_E_DEST_OCCUPIED"
	CodeInsufficientSpace = "EBB_E_SPACE"
	CodeRestoreMismatch   = "EBB_E_RESTORE_MISMATCH"
	CodePublishBlocked    = "EBB_E_PUBLISH_BLOCKED"
	CodeInvalidOptions    = "EBB_E_INVALID_OPTIONS"
	CodeLinksBlocked      = "EBB_E_LINK_BLOCKED"
)

// ErrNotOpenable reports that the selected snapshot cannot be opened at
// all: wrong catalog kind (trim covers only a removal plan; seal is a
// metadata-only record), a missing payload/seal backend id (an unsealed
// payload is never publishable, Foundation §11.3), or an unknown
// snapshot. Nothing was staged and no operation was begun.
type ErrNotOpenable struct {
	SnapshotID domain.SnapshotID
	Kind       string // "" when the row itself was not found
	Reason     string
}

func (e *ErrNotOpenable) Error() string {
	if e.Kind == "" {
		return fmt.Sprintf("restore: snapshot %s is not openable: %s", e.SnapshotID, e.Reason)
	}
	return fmt.Sprintf("restore: snapshot %s (kind %s) is not openable: %s", e.SnapshotID, e.Kind, e.Reason)
}

func (e *ErrNotOpenable) Code() string { return CodeNotOpenable }

// ErrSealInvalid reports that the retained seal does not validate: the
// receipt is missing from the seal snapshot tree, cannot be parsed
// strictly, names a different payload/snapshot/workspace, or carries
// unsupported required features. The snapshot stays retained (pinned);
// nothing was staged.
type ErrSealInvalid struct {
	Details []string
}

func (e *ErrSealInvalid) Error() string {
	return "restore: seal invalid: " + strings.Join(e.Details, "; ")
}

func (e *ErrSealInvalid) Code() string { return CodeSealInvalid }

// ErrVerification reports a mismatch caught by verification. Check is
// "documents" (the payload's manifest/inventory bytes do not match the
// seal's digests, or fail strict parsing — I12) or "oracle" (the staged
// tree does not match the retained inventory — the E10 defense). On
// "oracle" the staging directory was already removed and nothing was
// published.
type ErrVerification struct {
	Check   string // "documents" | "oracle"
	Details []string
}

func (e *ErrVerification) Error() string {
	return fmt.Sprintf("restore: %s verification failed: %s", e.Check, strings.Join(e.Details, "; "))
}

func (e *ErrVerification) Code() string { return CodeRestoreMismatch }

// ErrDestinationOccupied reports that the requested destination exists
// and is non-empty (a non-directory, or a directory holding unrelated
// content, or files published by an earlier Ebb open operation).
// Nothing was mutated: the occupant is named, never overwritten
// (Foundation §12.5, F35).
type ErrDestinationOccupied struct {
	Destination string
	Occupant    string // human-readable description of what occupies it
}

func (e *ErrDestinationOccupied) Error() string {
	return fmt.Sprintf("restore: destination %s is occupied by %s; refusing to overwrite (Foundation §12.5)",
		e.Destination, e.Occupant)
}

func (e *ErrDestinationOccupied) Code() string { return CodeDestOccupied }

// ErrInsufficientSpace reports the peak-space preflight block: free
// bytes on the destination's volume are below the preserved file bytes
// the open must materialize. Blocked before any staging; both numbers
// are named (Foundation §12.5, §14.2).
type ErrInsufficientSpace struct {
	Destination string
	Free        int64
	Needed      int64
}

func (e *ErrInsufficientSpace) Error() string {
	return fmt.Sprintf("restore: insufficient space on %s: %d bytes free, %d bytes of preserved content to materialize",
		e.Destination, e.Free, e.Needed)
}

func (e *ErrInsufficientSpace) Code() string { return CodeInsufficientSpace }

// ErrPublishBlocked reports that publication found the destination no
// longer absent (a racing occupant appeared between preflight and the
// rename — F35) or the rename itself failed. The staged tree is KEPT
// and the operation remains RESTORING for recovery; the occupant was
// never touched.
type ErrPublishBlocked struct {
	Destination string
	Err         error
}

func (e *ErrPublishBlocked) Error() string {
	msg := fmt.Sprintf("restore: publish to %s blocked", e.Destination)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg + "; staged tree kept and operation left RESTORING for recovery"
}

func (e *ErrPublishBlocked) Unwrap() error { return e.Err }

func (e *ErrPublishBlocked) Code() string { return CodePublishBlocked }

// ErrInvalidOptions reports caller mistakes (empty or relative
// destination, missing vault references, missing destination parent)
// before any durable side effect (mirroring lifecycle.ErrInvalidOptions).
type ErrInvalidOptions struct {
	Detail string
}

func (e *ErrInvalidOptions) Error() string { return "restore: invalid options: " + e.Detail }

func (e *ErrInvalidOptions) Code() string { return CodeInvalidOptions }

// ErrLinksBlocked reports that one or more retained links could not be
// recreated natively after staging, so the staged tree would differ
// from the retained inventory — the open fails BEFORE publish (the
// oracle would reject the tree anyway), staging is removed and the
// operation is left at RESTORING. PrivilegeBlocked names the entries
// whose TRUE SYMLINK recreation the OS refused for lack of
// SeCreateSymbolicLinkPrivilege (unprivileged Windows; junctions — the
// common pnpm/node_modules shape — never land here, their creation is
// unprivileged). Failures carries other per-link errors verbatim.
type ErrLinksBlocked struct {
	PrivilegeBlocked []string
	Failures         []string
}

func (e *ErrLinksBlocked) Error() string {
	n := len(e.PrivilegeBlocked) + len(e.Failures)
	msg := fmt.Sprintf("restore: %d retained link(s) could not be recreated; the restored tree would differ from the sealed inventory, so nothing was published", n)
	if len(e.PrivilegeBlocked) > 0 {
		msg += fmt.Sprintf("; privilege-blocked symlink(s): %s — recreating true symlinks requires SeCreateSymbolicLinkPrivilege: run elevated or enable Windows Developer Mode, then retry the open",
			strings.Join(e.PrivilegeBlocked, ", "))
	}
	if len(e.Failures) > 0 {
		msg += "; link failure(s): " + strings.Join(e.Failures, "; ")
	}
	return msg
}

func (e *ErrLinksBlocked) Code() string { return CodeLinksBlocked }
