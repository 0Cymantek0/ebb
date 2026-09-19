//go:build !windows && !linux

package capsule

import (
	"fmt"
	"runtime"
)

// freespace_other.go — the honest-gap fallback for platforms without a
// native probe here (mirrors internal/platform's documented "streams
//+xattrs = ErrUnsupported" posture: report the gap, never guess a
// number). Windows and Linux carry build-tagged implementations; this
// file keeps every other GOOS compiling.

// capsuleFreeSpace refuses with an explicit unsupported error so the
// caller can inject ImportParams.FreeSpace instead.
func capsuleFreeSpace(path string) (int64, error) {
	return 0, fmt.Errorf("capsule: free-space probe for %s is not implemented on %s (pass ImportParams.FreeSpace)", path, runtime.GOOS)
}
