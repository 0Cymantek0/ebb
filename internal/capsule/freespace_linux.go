//go:build linux

package capsule

import (
	"fmt"
	"syscall"
)

// freespace_linux.go — the default destination-volume free-space probe
// behind ImportParams.FreeSpace (Foundation §15.3 headroom check), in
// the per-OS file split that mirrors internal/platform's build-tagged
// layout. Stdlib only: capsule is platform-neutral core in the §16.7
// module diagram and must not grow adapter dependencies for one probe.

// capsuleFreeSpace reports quota-aware available bytes (f_bavail*f_bsize
// — the number headroom checks must use, exactly like
// domain.VolumeUsage.FreeToCaller) for the volume containing path.
func capsuleFreeSpace(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, fmt.Errorf("capsule: statfs(%s): %w", path, err)
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}
