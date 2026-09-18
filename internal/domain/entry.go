package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Route is the selected recovery treatment for an entry or group
// (Foundation §6.2). "unknown" is deliberately absent: an unclassified
// entry resolves to RoutePreserve; uncertainty is an observation carried
// in Evidence, never a route.
type Route string

const (
	// RoutePreserve retains the bytes in the snapshot. Default route.
	RoutePreserve Route = "preserve"
	// RouteReconstruct omits the bytes; an approved action rebuilds them.
	RouteReconstruct Route = "reconstruct"
	// RouteRetainedArtifact omits live bytes; a retained immutable
	// artifact (e.g. an exported database dump) replaces them.
	RouteRetainedArtifact Route = "retained-artifact"
	// RouteExternal records the content as owned elsewhere; it is not
	// retained and not removed by parking this workspace.
	RouteExternal Route = "external"
	// RouteDiscard is explicit, user-recorded permission to lose the
	// bytes. It is never inferred from a filename or ignore rule.
	RouteDiscard Route = "discard"
)

// Ownership restricts mutation rights (Foundation §4.3).
type Ownership string

const (
	OwnershipOwned         Ownership = "owned"
	OwnershipShared        Ownership = "shared"
	OwnershipReferenceOnly Ownership = "reference-only"
)

// Sensitivity affects storage, logging and export; never routes.
type Sensitivity string

const (
	SensitivityOrdinary  Sensitivity = "ordinary"
	SensitivitySensitive Sensitivity = "sensitive"
)

// EntryKind is the losslessly represented filesystem object type
// (Foundation §8.2, §10.2). Reparse points are classified precisely;
// "other-reparse" is a blocker for destructive operations in v1.
type EntryKind string

const (
	KindFile        EntryKind = "file"
	KindDir         EntryKind = "dir"
	KindSymlink     EntryKind = "symlink"
	KindJunction    EntryKind = "junction"
	KindMountPoint  EntryKind = "mount-point"
	KindOtherReparse EntryKind = "other-reparse"
	KindFIFO        EntryKind = "fifo"
	KindSocket      EntryKind = "socket"
	KindDevice      EntryKind = "device"
)

// DestructiveSafe reports whether this kind can participate in v1
// destructive operations. Ephemeral objects (FIFO/socket/device) and
// unrecognized reparse points must block, not vanish.
func (k EntryKind) DestructiveSafe() bool {
	switch k {
	case KindFile, KindDir, KindSymlink:
		return true
	case KindJunction, KindMountPoint:
		// link itself is representable; descending is separately blocked
		// by the inventory scanner
		return true
	default:
		return false
	}
}

// Entry is one accounted filesystem object (Foundation §8.2).
// Fields are orthogonal by design: a generated file may be sensitive;
// an ignored asset may be shared (§6.2).
type Entry struct {
	Root   RootID    `json:"root"`
	Path   string    `json:"path"` // root-relative, '/', no '..' (validated)
	Kind   EntryKind `json:"kind"`

	// LogicalSize is the default-stream length for files; 0 for dirs/links.
	LogicalSize int64 `json:"logical_size"`
	// AllocatedSize is exclusive physical allocation where observable;
	// nil means unknown (report, never guess — §14.1).
	AllocatedSize *int64 `json:"allocated_size,omitempty"`
	// Digest is the SHA-256 of preserved content, required for preserved
	// files, empty otherwise. Absence never implies disposable (§16.3).
	Digest string `json:"digest,omitempty"`
	// LinkTarget is the literal link text for symlink/junction kinds.
	LinkTarget string `json:"link_target,omitempty"`
	// HardlinkGroup names the in-root hardlink group, "" when unshared.
	HardlinkGroup string `json:"hardlink_group,omitempty"`

	Ownership   Ownership   `json:"ownership"`
	Sensitivity Sensitivity `json:"sensitivity"`
	Route       Route       `json:"route"`
	// Evidence cites the classification source: policy id, adapter id,
	// or git observation that produced this entry's fields.
	Evidence []string `json:"evidence,omitempty"`
}

// ErrBadPath is returned for paths violating the root-relative contract.
var ErrBadPath = errors.New("domain: invalid root-relative path")

// Validate enforces the entry invariants that later stages rely on.
func (e Entry) Validate() error {
	if !e.Root.Valid() {
		return fmt.Errorf("entry %q: invalid root %q", e.Path, e.Root)
	}
	if e.Path == "" {
		// only the root itself may be empty; entries always have a path
		return fmt.Errorf("entry: empty path")
	}
	if strings.ContainsAny(e.Path, "\x00") {
		return ErrBadPath
	}
	if e.Path == ".." || strings.HasPrefix(e.Path, "../") ||
		strings.Contains(e.Path, "/../") || strings.HasSuffix(e.Path, "/..") {
		return ErrBadPath
	}
	// Windows namespace defenses (Foundation §13.4): drive prefixes and
	// backslashes are rejected so a hostile manifest cannot smuggle an
	// absolute spelling through a "relative" field.
	if len(e.Path) >= 2 && e.Path[1] == ':' {
		return ErrBadPath
	}
	if strings.Contains(e.Path, "\\") {
		return ErrBadPath
	}
	needsDigest := e.Kind == KindFile && e.Route == RoutePreserve
	if needsDigest && e.Digest == "" {
		return fmt.Errorf("entry %q: preserved file requires digest", e.Path)
	}
	if e.Route == "" {
		return fmt.Errorf("entry %q: route unresolved (unknown is not a route)", e.Path)
	}
	switch e.Ownership {
	case OwnershipOwned, OwnershipShared, OwnershipReferenceOnly:
	default:
		return fmt.Errorf("entry %q: invalid ownership %q", e.Path, e.Ownership)
	}
	return nil
}

// Timestamp convention for all durable records: UTC RFC 3339 with
// nanosecond precision, rendered via time.RFC3339Nano on stored UTC values.
func FormatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
