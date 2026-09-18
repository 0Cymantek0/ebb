// Package platform implements the native operating-system capability
// layer behind domain.PlatformProbe (the seam consumed by the inventory
// scanner) plus the WriterInspector diagnostics helper.
//
// Design rules inherited from Foundation §10.2/§10.3 and the platform
// probe findings (lab/platform-probe/FINDINGS.md):
//
//   - Read-only: probing never mutates anything under the inspected path.
//   - Never open file content. Placeholder (cloud-recall) attributes are
//     checked before any handle is opened so inspection can never hydrate
//     (Foundation §8.1, §10.2 "cloud placeholder").
//   - Never follow symlinks or junctions; reparse points are classified
//     by their raw tag, and unknown tags surface as KindOtherReparse
//     rather than disappearing.
//   - Everything runs unprivileged; no admin-gated tool (fsutil et al.)
//     is invoked.
//
// Windows gaps in golang.org/x/sys v0.48.0 (FindFirstStreamW,
// FindNextStreamW, GetCompressedFileSizeW, the Restart Manager) are
// bridged with in-tree LazyDLL bindings resolved once per process
// (lab/platform-probe verified the technique unprivileged).
package platform

import (
	"errors"

	"ebb/internal/domain"
)

// ErrUnsupported reports that the running platform (or its filesystem)
// does not offer the requested capability. Callers must treat it as a
// capability fact, not an I/O failure.
var ErrUnsupported = errors.New("platform: capability not supported on this platform")

// Writer is one process observed holding an open handle to an inspected
// path. It is diagnostics evidence ONLY — never proof that content
// changed and never an authorization input (Foundation §4.4): an open
// handle does not prove mutation, and a closed handle does not prove
// quiescence.
type Writer struct {
	// Name is the process image name as reported by the source
	// (e.g. "Code.exe", "postgres.exe").
	Name string `json:"name"`
	// PID is the process id at observation time; PIDs are recycled, so
	// pair with Name and observation time when persisting.
	PID uint32 `json:"pid"`
	// Kind classifies the writer: "editor", "process", "service",
	// "shell", or "console". Heuristic, for display triage only.
	Kind string `json:"kind"`
	// Source names the provenance route, e.g. "restart-manager".
	Source string `json:"source"`
}

// WriterInspector lists processes with open handles to the given paths.
// It exists to explain removal blockers (errno 32 in the quarantine
// step, Foundation §12.3 REMOVAL_BLOCKED), never to authorize anything.
type WriterInspector interface {
	// InspectWriters returns the distinct writers currently holding
	// open handles to any of paths. An empty slice with nil error means
	// the source was consulted and observed no writers; it does NOT
	// mean the files are safe to remove.
	InspectWriters(paths []string) ([]Writer, error)
}

// New returns the native domain.PlatformProbe for the running operating
// system. The returned probe is stateless and safe for concurrent use.
func New() domain.PlatformProbe {
	return newNativeProbe()
}

// NewWriterInspector returns the native WriterInspector. On platforms
// without a writer-listing capability it returns ErrUnsupported; callers
// should surface that as reduced diagnostics, never as a scan failure.
func NewWriterInspector() (WriterInspector, error) {
	return newNativeWriterInspector()
}
