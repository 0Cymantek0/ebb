package gitadapter

import (
	"syscall"
	"unsafe"
)

// canonicalForm normalizes cosmetic Windows path spelling — 8.3 short
// names like C:\Users\SHUVAG~1 — to the long form, because different git
// commands report paths derived from different spellings of the same
// directory (the observer's cwd vs getcwd). It uses GetLongPathNameW,
// which only rewrites short-name components and never resolves symlinks
// or junctions: recorded link paths stay literal (D004 rule 5). On
// failure the path is returned unchanged; the case-insensitive
// comparison in adminInside absorbs residual case differences. In-tree
// LazyDLL binding per D002.amendment (no new deps).
func canonicalForm(path string) string {
	if path == "" {
		return path
	}
	p16, err := syscall.UTF16FromString(path)
	if err != nil || len(p16) == 0 {
		return path
	}
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetLongPathNameW")
	buf := make([]uint16, len(p16)+256)
	n, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&p16[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if n == 0 {
		return path
	}
	if int(n) >= len(buf) { // retry with the reported size
		buf = make([]uint16, n)
		n, _, _ = proc.Call(
			uintptr(unsafe.Pointer(&p16[0])),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
		)
		if n == 0 || int(n) >= len(buf) {
			return path
		}
	}
	return syscall.UTF16ToString(buf[:n])
}
