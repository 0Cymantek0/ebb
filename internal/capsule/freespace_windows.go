//go:build windows

package capsule

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

// freespace_windows.go — the default destination-volume free-space probe
// behind ImportParams.FreeSpace (Foundation §15.3: "Version 1 may need
// temporary space approximately equal to the encrypted repository during
// capsule import... show that cost before extraction"). It re-declares
// the same GetDiskFreeSpaceExW call internal/platform's probe makes,
// through the STDLIB syscall LazyDLL bridge, so the capsule package —
// platform-neutral core in the §16.7 module diagram — keeps its
// dependency set exactly as documented (no internal/platform, no x/sys)
// while the per-OS file split mirrors platform_windows.go /
// platform_linux.go.
var (
	modKernel32          = syscall.NewLazyDLL("kernel32.dll")
	pGetDiskFreeSpaceExW = modKernel32.NewProc("GetDiskFreeSpaceExW")
)

// capsuleFreeSpace reports quota-aware available bytes
// (lpFreeBytesAvailableToCaller — the number headroom checks must use,
// exactly like domain.VolumeUsage.FreeToCaller) for the volume
// containing path.
func capsuleFreeSpace(path string) (int64, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return 0, fmt.Errorf("capsule: free space of %s: %w", path, err)
	}
	p16, err := syscall.UTF16PtrFromString(filepath.Clean(abs))
	if err != nil {
		return 0, fmt.Errorf("capsule: free space of %s: %w", abs, err)
	}
	var avail, total, free uint64
	r1, _, e1 := pGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p16)),
		uintptr(unsafe.Pointer(&avail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&free)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("capsule: GetDiskFreeSpaceExW(%s): %w", abs, e1)
	}
	return int64(avail), nil
}
