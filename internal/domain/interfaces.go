package domain

import (
	"context"
	"os"
)

// PlatformProbe is the capability seam the inventory scanner consumes.
// It is defined here (core) and implemented by internal/platform per OS,
// so tests can substitute deterministic fakes and fault injection
// (Foundation §16.7). Implementations must be read-only: no mutation of
// anything under the inspected path.
type PlatformProbe interface {
	// RootIdentity returns stable native identity for an existing root path.
	// A path that was replaced returns different identity; equal identity
	// implies the same object across renames (validated on Win NTFS and
	// ext4; see Learnings).
	RootIdentity(path string) (RootIdentity, error)

	// VolumeUsage reports quota-aware free/capacity for the volume
	// containing path.
	VolumeUsage(path string) (VolumeUsage, error)

	// ProbeFile returns file facts needed for one entry. It must not
	// follow symlinks/junctions and must not open file content (no
	// placeholder hydration, §8.1).
	ProbeFile(path string) (FileFacts, error)
}

// FileFacts carries the platform-neutral observations for one filesystem
// object, gathered without opening content.
type FileFacts struct {
	Kind          EntryKind
	LogicalSize   int64  // default-stream length for files
	AllocatedSize *int64 // exclusive allocation where observable
	LinkTarget    string // literal link text for symlink/junction

	// FileIdentity identifies the object for hardlink grouping and
	// rename-stable revalidation; empty when unavailable.
	FileIdentity string
	// LinkCount is the number of names sharing the content (1 = unshared).
	LinkCount int64

	// Streams lists named alternate data streams (Windows); the default
	// stream is never listed here.
	Streams []NamedStream

	// Sparse reports that the file carries sparse allocation.
	Sparse bool

	// Placeholder reports a provider cloud placeholder (Windows
	// FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS/RECALL_ON_OPEN). Content must
	// never be opened for such files (hydration, §8.1). When false but
	// the platform cannot observe allocation, scanners may still apply
	// their zero-allocation heuristic and mark suspicion.
	Placeholder bool

	// ReparseTag is the raw tag for reparse points, hex-encoded; used to
	// distinguish junction / mount point / other (§10.2).
	ReparseTag string
}

// NamedStream is one named data stream (Windows NTFS; §10.2).
type NamedStream struct {
	Name string `json:"name"` // without the file path, e.g. "cred"
	Size int64  `json:"size"`
}

// IdentifiedDir is an open directory enumerated through the SAME
// handle whose identity was verified at open time. A directory
// handle cannot be re-pointed, so entries enumerated through it
// cannot escape a race-substituted path (SCAN-RACE-1 fix).
type IdentifiedDir interface {
	// Identity returns the native identity of the opened directory
	// (same spelling as FileFacts.FileIdentity / RootIdentity).
	Identity() string
	// ReadDir enumerates the directory through the handle.
	ReadDir() ([]os.DirEntry, error)
	Close() error
}

// VerifiedDirProbe is implemented by native platform probes.
type VerifiedDirProbe interface {
	// OpenDirVerified opens path and verifies the OPENED HANDLE's
	// identity equals the identity previously observed for that path
	// (expectedIdentity, from the classification-time FileFacts).
	// A mismatch (path substituted between classification and open)
	// returns an error; it never returns a handle to a different object.
	//
	// Contract for mismatch errors: they must satisfy
	// interface{ IdentityMismatch() bool } returning true, so callers
	// can distinguish "the path was substituted" from ordinary open
	// failures without importing the platform package. All other
	// failures keep ordinary error semantics. expectedIdentity must be
	// non-empty; an empty expectation is an invalid-argument error.
	OpenDirVerified(path, expectedIdentity string) (IdentifiedDir, error)
}

// SnapshotStore is the storage backend seam (implemented by
// internal/storage/restic). Core owns selection and verification; the
// store owns chunking, encryption, integrity and GC (Foundation §11.1).
// All methods take literal, absolute-or-cwd-relative paths decided by the
// caller; the store never expands globs or recurses beyond what is listed.
type SnapshotStore interface {
	// Init creates a new empty repository at dir.
	Init(ctx context.Context, dir string, passfile string) error

	// RepoID returns the backend repository identity (restic: parsed
	// from `init` stdout or `cat config`; the on-disk config is
	// encrypted). Seals record it to bind to one specific repository.
	RepoID(ctx context.Context, repoDir, passfile string) (string, error)

	// Snapshot captures exactly the listed paths (NUL-safe, caller-built
	// per D003: cwd-relative from a base dir, sibling op dir included)
	// and returns the backend snapshot ID. Errors must distinguish
	// source-read failures from repo failures (StoreError).
	Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (SnapshotRef, error)

	// List returns snapshot summaries for the repo.
	List(ctx context.Context, repoDir, passfile string) ([]SnapshotRef, error)

	// Ls lists one snapshot's tree (names, kinds, sizes) for coverage
	// comparison against the inventory.
	Ls(ctx context.Context, repoDir, passfile string, snapID string) ([]TreeEntry, error)

	// DumpFile streams one file's bytes for independent digest readback.
	DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error)

	// Restore materializes a snapshot subtree to dest (already preflighted
	// by lifecycle).
	Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error

	// Forget removes explicit backend snapshot IDs (never auto policy).
	Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error
}

// SnapshotRef is an opaque backend snapshot identity plus the metadata
// the store guarantees to report truthfully.
type SnapshotRef struct {
	BackendID string            `json:"backend_id"` // opaque, not an Ebb ID
	ShortID   string            `json:"short_id"`
	Time      string            `json:"time"` // RFC3339
	Paths     []string          `json:"paths"`
	Tags      map[string]string `json:"tags,omitempty"`
}

// TreeEntry is one node in a backend snapshot listing.
type TreeEntry struct {
	Path       string    `json:"path"` // store-normalized, bijection via manifest
	Kind       EntryKind `json:"kind"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode,omitempty"`
	ModTime    string    `json:"mtime,omitempty"`
	LinkTarget string    `json:"link_target,omitempty"`
}

// StoreError separates failure classes so lifecycle can decide between
// "source unreadable → snapshot unusable for removal" and "repo problem
// → nothing was captured; source untouched" (restic: 3 vs 10/12).
type StoreError struct {
	Class StoreErrorClass
	Err   error
}

type StoreErrorClass string

const (
	StoreErrSource  StoreErrorClass = "source" // exit 3: incomplete snapshot created
	StoreErrRepo    StoreErrorClass = "repo"   // exit 10: repo missing/unavailable
	StoreErrAuth    StoreErrorClass = "auth"   // exit 12: wrong password/key
	StoreErrUsage   StoreErrorClass = "usage"  // bad invocation of the backend
	StoreErrUnknown StoreErrorClass = "unknown"
)

func (e *StoreError) Error() string { return string(e.Class) + ": " + e.Err.Error() }
func (e *StoreError) Unwrap() error { return e.Err }
