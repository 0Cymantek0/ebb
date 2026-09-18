//go:build !windows

package platform

import "fmt"

// stubWriterInspector is the WriterInspector for platforms without an
// in-tree writer-listing capability. Its constructor reports
// ErrUnsupported up front; the method keeps the same contract for any
// value obtained elsewhere.
type stubWriterInspector struct{}

// newNativeWriterInspector reports ErrUnsupported off Windows (see
// platform.go NewWriterInspector). Linux v1 has no unprivileged
// writer-listing API worth binding (lsof/proc scanning is a separate
// decision); this is a declared capability gap, not an outage.
func newNativeWriterInspector() (WriterInspector, error) {
	return nil, fmt.Errorf("%w: writer inspection is only implemented on Windows (Restart Manager)", ErrUnsupported)
}

// InspectWriters always returns ErrUnsupported with a clear message.
func (stubWriterInspector) InspectWriters(_ []string) ([]Writer, error) {
	return nil, fmt.Errorf("%w: writer inspection is only implemented on Windows (Restart Manager)",
		ErrUnsupported)
}
