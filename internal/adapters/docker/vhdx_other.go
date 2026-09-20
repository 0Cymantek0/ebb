//go:build !windows

// Non-Windows platforms have no Docker Desktop VHDX to compact; tier 5
// is honestly absent (no fake parity, Foundation §Cross-Platform): the
// engine emits no tier 5 row, reports zero host slack, and adds no
// warning — the capability is out of scope here, not degraded.
package dockeradapter

// defaultAllocationProbe: no native capability on this platform.
func defaultAllocationProbe() AllocationProbe { return nil }

// hostSlackTier is the honest-zero path: nothing measured, nothing
// claimed.
func (e *Engine) hostSlackTier(logicalTotal int64, logicalKnown bool) (*DockerTier, int64, string, []string) {
	return nil, 0, "", nil
}
