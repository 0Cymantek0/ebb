//go:build windows

package platform

import (
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// kernel32 functions NOT exported by golang.org/x/sys/windows v0.48.0
// (verified by the platform probe): named-stream enumeration and the
// path-based compressed-size fallback. Bound via LazyDLL; resolved
// exactly once per process under sync.Once, with load failures
// returned as errors, never panics.
var (
	modKernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pFindFirstStreamW       = modKernel32.NewProc("FindFirstStreamW")
	pFindNextStreamW        = modKernel32.NewProc("FindNextStreamW")
	pFindClose              = modKernel32.NewProc("FindClose")
	pGetCompressedFileSizeW = modKernel32.NewProc("GetCompressedFileSizeW")

	auxProcsOnce sync.Once
	auxProcsErr  error
)

// invalidHandle is INVALID_HANDLE_VALUE / INVALID_FILE_SIZE returned by
// the bound kernel32 calls on failure.
const invalidHandle = ^uintptr(0)

// resolveAuxProcs resolves the kernel32 bindings once; the error is
// sticky so every caller sees the same capability fact.
func resolveAuxProcs() error {
	auxProcsOnce.Do(func() {
		if err := pFindFirstStreamW.Find(); err != nil {
			auxProcsErr = fmt.Errorf("kernel32.FindFirstStreamW: %w", err)
			return
		}
		if err := pFindNextStreamW.Find(); err != nil {
			auxProcsErr = fmt.Errorf("kernel32.FindNextStreamW: %w", err)
			return
		}
		if err := pFindClose.Find(); err != nil {
			auxProcsErr = fmt.Errorf("kernel32.FindClose: %w", err)
			return
		}
		if err := pGetCompressedFileSizeW.Find(); err != nil {
			auxProcsErr = fmt.Errorf("kernel32.GetCompressedFileSizeW: %w", err)
		}
	})
	return auxProcsErr
}

// findStreamData mirrors WIN32_FIND_STREAM_DATA. The Win32 contract is
// WCHAR cStreamName[MAX_PATH+36] = 296 wchars: the kernel may write the
// full capacity regardless of the name's actual length, so the Go
// field must reserve all 296 (PLAT-STREAM-1: a [257] field let a
// 255-char stream name write 10 bytes past the field).
type findStreamData struct {
	size int64
	name [296]uint16
}

// listNamedStreams enumerates the named data streams of path via
// FindFirstStreamW/FindNextStreamW (metadata only — safe for
// placeholders-free probing and never opens content). The default
// stream `::$DATA` is skipped; names are stripped of the `:$DATA`
// suffix (e.g. `:cred:$DATA` -> "cred").
//
// Best-effort by contract: on filesystems without named streams (FAT
// family), on bind failure, or on any enumeration error it returns nil
// so a missing-streams capability degrades silently to "no named
// streams observed" — the same result a genuinely stream-less NTFS file
// produces. Foundation §10.2 requires streams to be RETAINED when they
// exist; absence of the enumeration capability on a volume that cannot
// have streams is not a fidelity loss.
func listNamedStreams(path string) []domain.NamedStream {
	if err := resolveAuxProcs(); err != nil {
		return nil
	}
	p, err := extendLongPath(path)
	if err != nil {
		return nil
	}
	p16, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return nil
	}
	var d findStreamData
	h, _, callErr := pFindFirstStreamW.Call(uintptr(unsafe.Pointer(p16)), 0,
		uintptr(unsafe.Pointer(&d)), 0)
	if h == invalidHandle {
		// ERROR_INVALID_PARAMETER / ERROR_NOT_SUPPORTED: volume has no
		// stream support; anything else is also non-fatal here.
		_ = callErr
		return nil
	}
	// FindFirstStreamW handles MUST be released with FindClose.
	// CloseHandle appears to succeed on them but does NOT release the
	// enumeration handle: the leaked handle then blocks renaming (and
	// deleting) the containing directory FOREVER — measured on Win11
	// 26200 (lifecycle wave: every park's quarantine rename failed after
	// the scan hashed files). FindClose is the documented deallocator.
	defer pFindClose.Call(h)

	var streams []domain.NamedStream
	for {
		if name, ok := streamNameOf(windows.UTF16ToString(d.name[:])); ok {
			streams = append(streams, domain.NamedStream{Name: name, Size: d.size})
		}
		r, _, _ := pFindNextStreamW.Call(h, uintptr(unsafe.Pointer(&d)), 0)
		if r == 0 {
			// ERROR_HANDLE_EOF (38) ends the walk; any other errno also
			// stops it, returning the streams observed so far.
			break
		}
	}
	return streams
}

// streamNameOf converts a raw stream name (`::$DATA`, `:cred:$DATA`)
// to (display name, true); the default stream reports ok=false.
func streamNameOf(raw string) (string, bool) {
	name := strings.TrimSuffix(raw, ":$DATA")
	name = strings.TrimPrefix(name, ":")
	if name == "" {
		return "", false // `::$DATA` — the default stream
	}
	return name, true
}

// compressedFileSizeByPath is the GetCompressedFileSizeW fallback for
// the on-disk allocation when the handle-based FileCompressionInfo
// route failed (e.g. sharing-restricted open). Returns (size, false)
// when the call fails.
func compressedFileSizeByPath(path string) (int64, bool) {
	if err := resolveAuxProcs(); err != nil {
		return 0, false
	}
	p, err := extendLongPath(path)
	if err != nil {
		return 0, false
	}
	p16, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, false
	}
	var high uint32
	r1, _, _ := pGetCompressedFileSizeW.Call(uintptr(unsafe.Pointer(p16)),
		uintptr(unsafe.Pointer(&high)))
	if r1 == invalidHandle { // INVALID_FILE_SIZE signals failure
		return 0, false
	}
	return int64(uint64(high)<<32 | uint64(uint32(r1))), true
}
