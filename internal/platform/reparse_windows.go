//go:build windows

package platform

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// Reparse tags Ebb classifies (Foundation §10.2). Only name-surrogate
// tags are interpreted; every other tag surfaces as KindOtherReparse
// with its hex recorded in FileFacts.ReparseTag.
const (
	ioReparseTagMountPoint uint32 = 0xA0000003 // junctions AND volume mount points
	ioReparseTagSymlink    uint32 = 0xA000000C // symbolic links
)

// maxReparseBufferSize is MAXIMUM_REPARSE_DATA_BUFFER_SIZE.
const maxReparseBufferSize = 16 * 1024

// reparseData is the decoded tail of a REPARSE_DATA_BUFFER for the
// name-surrogate tags (mount point / symlink): the raw substitute name
// (typically `\??\C:\...` or `\??\Volume{...}`) and print name.
type reparseData struct {
	tag            uint32
	substituteName string
	printName      string
}

// readReparsePoint opens path with FILE_FLAG_OPEN_REPARSE_POINT
// (never the target) and decodes FSCTL_GET_REPARSE_POINT. Both the API
// and the control code are exported by x/sys v0.48.0 and work
// unprivileged (probe Q1). The buffer is parsed with explicit
// little-endian reads instead of unsafe struct casts so alignment of
// the on-disk layout never matters.
func readReparsePoint(path string) (reparseData, error) {
	h, err := openMetadataHandle(path, true)
	if err != nil {
		return reparseData{}, err
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, maxReparseBufferSize)
	var returned uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_GET_REPARSE_POINT,
		nil, 0, &buf[0], uint32(len(buf)), &returned, nil); err != nil {
		return reparseData{}, fmt.Errorf("FSCTL_GET_REPARSE_POINT: %w", err)
	}
	if int(returned) < 8 || int(returned) > len(buf) {
		return reparseData{}, fmt.Errorf("reparse buffer: bad length %d", returned)
	}

	var out reparseData
	out.tag = binary.LittleEndian.Uint32(buf[0:4])
	if out.tag != ioReparseTagMountPoint && out.tag != ioReparseTagSymlink {
		// Non name-surrogate tag: nothing further to decode.
		return out, nil
	}

	// REPARSE_DATA_BUFFER union tail:
	//   mount point: 4 USHORT offsets at 8..16, PathBuffer at 16
	//   symlink:     4 USHORT offsets at 8..16, USHORT Flags at 16, PathBuffer at 18
	subOff := int(binary.LittleEndian.Uint16(buf[8:10]))
	subLen := int(binary.LittleEndian.Uint16(buf[10:12]))
	prOff := int(binary.LittleEndian.Uint16(buf[12:14]))
	prLen := int(binary.LittleEndian.Uint16(buf[14:16]))
	base := 16
	if out.tag == ioReparseTagSymlink {
		base = 18
	}
	// Bounds-check against the kernel-reported length, not the buffer
	// capacity, so a corrupt buffer cannot read stale bytes.
	read := func(off, length int) string {
		if length <= 0 || length%2 != 0 {
			return ""
		}
		start, end := base+off, base+off+length
		if start < 0 || end > int(returned) {
			return ""
		}
		return utf16BytesToString(buf[start:end])
	}
	out.substituteName = read(subOff, subLen)
	out.printName = read(prOff, prLen)
	return out, nil
}

// utf16BytesToString decodes a little-endian UTF-16 byte slice.
func utf16BytesToString(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return windows.UTF16ToString(u)
}

// normalizeSubstituteName converts a raw substitute name into a
// user-comparable path: `\??\C:\x` -> `C:\x`, `\??\UNC\s\y` ->
// `\\s\y`, `\??\Volume{...}` -> `Volume{...}`. Mirrors the rules Go's
// syscall.Readlink applies, kept local so junction/mount-point targets
// and symlink targets normalize identically.
func normalizeSubstituteName(s string) string {
	s = strings.TrimPrefix(s, `\??\`)
	if rest, ok := strings.CutPrefix(s, `UNC\`); ok {
		return `\\` + rest
	}
	return s
}
