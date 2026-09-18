//go:build windows

package platform

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"ebb/internal/domain"
)

// windowsProbe implements domain.PlatformProbe for Windows NTFS-family
// volumes using unprivileged handle-based APIs only
// (lab/platform-probe/FINDINGS.md, Foundation §10.2/§10.3).
type windowsProbe struct{}

// newNativeProbe returns the Windows probe (see platform.go New).
func newNativeProbe() domain.PlatformProbe { return windowsProbe{} }

// shareAll opens handles without blocking other readers or deleters;
// probing must never be the reason a quarantine rename fails.
const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// fileIDInfo mirrors the C FILE_ID_INFO layout for
// GetFileInformationByHandleEx(FileIdInfo). Both quirks found
// empirically by the platform probe are honored here: the API rejects
// a 20-byte buffer (errno 24 ERROR_BAD_LENGTH — hence the trailing pad
// making 24) and rejects 1-byte-aligned buffers (errno 998
// ERROR_NOACCESS — the leading uint32 guarantees struct alignment; a
// stack `var b [N]byte` is NOT acceptable).
type fileIDInfo struct {
	volumeSerialNumber uint32
	fileID             [16]byte
	pad                [4]byte
}

// fileCompressionInfo mirrors FILE_COMPRESSION_INFO for
// GetFileInformationByHandleEx(FileCompressionInfo). CompressedFileSize
// is the on-disk allocation and is sparse-correct (probe Q5: all
// allocated-size routes agreed on a sparse file).
type fileCompressionInfo struct {
	compressedFileSize   int64
	compressionFormat    uint16
	compressionUnitShift uint8
	chunkShift           uint8
	clusterShift         uint8
	reserved             [3]uint8
}

// fileIdentity is the raw native identity of one filesystem object,
// gathered from a single open handle.
type fileIdentity struct {
	volumeSerial uint32
	index64      uint64 // BY_HANDLE_FILE_INFORMATION FileIndex (64-bit)
	fileID128    string // FILE_ID_INFO 128-bit id, hex; "" when unavailable
	links        uint32 // nNumberOfLinks
}

// volumeID renders the identity's volume component: the NTFS volume
// serial number in 8 uppercase hex digits (no 0x prefix). Chosen over a
// `\\.\C:` spelling because the serial is stable across drive-letter
// reassignment and is the same key GetFileInformationByHandle pairs
// with the file index.
func (f fileIdentity) volumeID() string { return fmt.Sprintf("%08X", f.volumeSerial) }

// fileID renders the per-object component: the 128-bit FILE_ID_INFO
// hex when the OS provided it, else the 64-bit BY_HANDLE file index in
// 16 uppercase hex digits. The two shapes differ, but identity is only
// ever compared against identities produced by the same build on the
// same machine, where the shape is stable.
func (f fileIdentity) fileID() string {
	if f.fileID128 != "" {
		return f.fileID128
	}
	return fmt.Sprintf("%016X", f.index64)
}

// fileIdentityString is the compact form stored in FileFacts:
// "<volumeID>:<fileID>".
func (f fileIdentity) fileIdentityString() string {
	return f.volumeID() + ":" + f.fileID()
}

// IsCloudPlaceholder reports whether raw Win32 attributes mark an entry
// as recall-on-data-access (0x00400000, modern OneDrive dehydrated
// files), recall-on-open (0x00040000, older providers) or offline
// (0x1000). Callers must never open such entries: any read can hydrate
// (Foundation §8.1, §10.2; probe Q8 — the live modern bit is 0x400000,
// not the 0x1000 the original brief guessed). Lstat/ReadDir remain safe.
func IsCloudPlaceholder(attrs uint32) bool {
	const recallBits = windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS |
		windows.FILE_ATTRIBUTE_RECALL_ON_OPEN |
		windows.FILE_ATTRIBUTE_OFFLINE
	return attrs&recallBits != 0
}

// extendLongPath adds the \\?\ prefix to plain absolute paths that
// exceed the 260-char MAX_PATH limit so raw CreateFile calls accept
// them. Go's os package fixes long paths internally (probe Q10), but
// x/sys windows.CreateFile does not, so this mirrors the stdlib
// fixLongPath rules: already-prefixed paths pass through; UNC paths
// become \\?\UNC\...; relative paths are made absolute first.
func extendLongPath(p string) (string, error) {
	if strings.HasPrefix(p, `\\?\`) || strings.HasPrefix(p, `\\.\`) {
		return p, nil
	}
	if !filepath.IsAbs(p) {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", err
		}
		p = abs
	}
	if len(p) < 248 { // stdlib threshold; nothing to fix below it
		return p, nil
	}
	p = filepath.Clean(p)
	if strings.HasPrefix(p, `\\`) { // UNC share -> \\?\UNC\server\share\...
		return `\\?\UNC\` + strings.TrimPrefix(p, `\\`), nil
	}
	return `\\?\` + p, nil
}

// openMetadataHandle opens path without reading data: access is
// FILE_READ_ATTRIBUTES only, all sharing allowed. FILE_FLAG_BACKUP_SEMANTICS
// is required to open directories (no backup privilege is needed for
// that flag). reparse=true adds FILE_FLAG_OPEN_REPARSE_POINT so the
// handle refers to the named link object itself, never its target.
func openMetadataHandle(path string, reparse bool) (windows.Handle, error) {
	p, err := extendLongPath(path)
	if err != nil {
		return 0, err
	}
	p16, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if reparse {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, err := windows.CreateFile(p16, windows.FILE_READ_ATTRIBUTES, shareAll, nil,
		windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return 0, &os.PathError{Op: "CreateFile", Path: path, Err: err}
	}
	return h, nil
}

// identityFromHandle collects the native identity and link count from
// an open attribute handle. FileIdInfo is preferred (128-bit, survives
// NTFS index reuse pressure) with the BY_HANDLE (serial, index) pair as
// fallback; both routes were verified rename-stable and hardlink-equal
// by the platform probe (Q2).
func identityFromHandle(h windows.Handle) (fileIdentity, error) {
	var ident fileIdentity
	var bh windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &bh); err != nil {
		return ident, fmt.Errorf("GetFileInformationByHandle: %w", err)
	}
	ident.volumeSerial = bh.VolumeSerialNumber
	ident.index64 = uint64(bh.FileIndexHigh)<<32 | uint64(bh.FileIndexLow)
	ident.links = bh.NumberOfLinks

	var fid fileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, uint32(windows.FileIdInfo),
		(*byte)(unsafe.Pointer(&fid)), uint32(unsafe.Sizeof(fid))); err == nil {
		ident.fileID128 = hex.EncodeToString(fid.fileID[:])
	}
	return ident, nil
}

// identifyPath opens path (no-follow) and returns its identity.
func identifyPath(path string) (fileIdentity, error) {
	h, err := openMetadataHandle(path, true)
	if err != nil {
		return fileIdentity{}, err
	}
	defer windows.CloseHandle(h)
	return identityFromHandle(h)
}

// RootIdentity returns the rename-stable native identity of an existing
// root path. The handle is opened with OPEN_REPARSE_POINT so a root
// that is itself a junction/symlink is identified as that link object;
// replacing the path with a different object therefore yields a
// different identity (Foundation §12.1, I13).
func (windowsProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	ident, err := identifyPath(path)
	if err != nil {
		return domain.RootIdentity{}, err
	}
	return domain.RootIdentity{VolumeID: ident.volumeID(), FileID: ident.fileID()}, nil
}

// volumeRootOf returns the drive/UNC root of path's volume as required
// by Sep 2025 GetVolumeInformation, e.g. `C:\` or `\\server\share\`.
func volumeRootOf(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	vol := filepath.VolumeName(abs)
	if vol == "" {
		return `\`, nil
	}
	if strings.HasPrefix(vol, `\\`) { // UNC root keeps its trailing slash
		return vol + `\`, nil
	}
	return vol + `\`, nil
}

// volumeInformation reads volume metadata for a root path via
// path-based GetVolumeInformationW (serial number, label, filesystem
// name and capability flags).
func volumeInformation(root string) (label, fsName string, serial, flags uint32, err error) {
	p16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return "", "", 0, 0, err
	}
	var volName, fsBuf [261]uint16
	var maxComp uint32
	if err := windows.GetVolumeInformation(p16, &volName[0], uint32(len(volName)-1),
		&serial, &maxComp, &flags, &fsBuf[0], uint32(len(fsBuf)-1)); err != nil {
		return "", "", 0, 0, fmt.Errorf("GetVolumeInformation(%s): %w", root, err)
	}
	return windows.UTF16ToString(volName[:]), windows.UTF16ToString(fsBuf[:]), serial, flags, nil
}

// VolumeUsage reports quota-aware space for the volume containing path
// via GetDiskFreeSpaceEx. FreeToCaller is lpFreeBytesAvailableToCaller
// (quota-aware, what headroom checks must use); VolumeFree is the
// volume truth used for reclaim-delta reporting (probe Q6).
// VolumeID is the volume serial in the same "%08X" form RootIdentity
// uses. The volume label is readable via volumeInformation but has no
// field in domain.VolumeUsage (reported as contract friction).
func (windowsProbe) VolumeUsage(path string) (domain.VolumeUsage, error) {
	var u domain.VolumeUsage
	root, err := volumeRootOf(path)
	if err != nil {
		return u, err
	}
	p16, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return u, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p16, &avail, &total, &free); err != nil {
		return u, fmt.Errorf("GetDiskFreeSpaceEx(%s): %w", root, err)
	}
	u.FreeToCaller = int64(avail)
	u.VolumeFree = int64(free)
	u.Total = int64(total)
	if _, _, serial, _, verr := volumeInformation(root); verr == nil {
		u.VolumeID = fmt.Sprintf("%08X", serial)
	} else {
		// usage without a serial is still usable; label the volume by its root
		u.VolumeID = filepath.VolumeName(root)
	}
	return u, nil
}

// VolumeCaseSensitive reports whether the volume containing path is
// case-sensitive BY DEFAULT.
//
// HEURISTIC, documented per the platform brief: NTFS-family volumes
// are case-insensitive by default, so fs-name "NTFS"/"ReFS"/FAT-family
// maps to false. Per-DIRECTORY case-sensitivity flags (WSL-era,
// queryable unprivileged via `fsutil file queryCaseSensitiveInfo` per
// probe Q9) are NOT visible through any supported non-admin volume API
// in golang.org/x/sys v0.48.0; until a native per-dir query route is
// added, treat directories as case-insensitive and rely on on-disk
// enumeration (ReadDir) for name truth, never on echoed input case.
func VolumeCaseSensitive(path string) (bool, error) {
	root, err := volumeRootOf(path)
	if err != nil {
		return false, err
	}
	if _, _, _, _, err := volumeInformation(root); err != nil {
		return false, err
	}
	// Every filesystem Windows mounts by default (NTFS, ReFS, FAT,
	// exFAT, CDFS/UDF) is case-insensitive at the volume level.
	return false, nil
}

// fileAttributesOf extracts the raw Win32 attributes from an os.Lstat
// result (0 when the platform data is unavailable).
func fileAttributesOf(fi os.FileInfo) uint32 {
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes
	}
	return 0
}

// ProbeFile gathers FileFacts for one path without following links and
// without opening content. Order of operations is load-bearing:
//
//  1. os.Lstat (never os.Stat) provides kind, logical size and raw
//     attributes.
//  2. Placeholder check on attributes — before ANY handle is opened —
//     so cloud-recall entries can never be hydrated by probing. Such
//     entries come back with empty identity/streams and Kind=KindFile.
//  3. Reparse points are decoded via FSCTL_GET_REPARSE_POINT on an
//     OPEN_REPARSE_POINT handle (metadata-only, no hydration) to get
//     the exact tag; junction vs volume mount point is decided by the
//     substitute name. If that ioctl fails, Lstat's mode still yields
//     a conservative classification (symlink via ModeSymlink, anything
//     else KindOtherReparse which blocks destructive ops) with an
//     empty ReparseTag — degraded facts, never a wrong kind.
//  4. Regular files/dirs get identity + LinkCount from one BY_HANDLE /
//     FileIdInfo query, allocated size from FileCompressionInfo
//     (sparse-correct), sparse flag from attributes, and named-stream
//     enumeration. If the attribute-open itself fails (e.g. exclusive
//     sharing elsewhere), the Lstat facts are returned with empty
//     identity fields rather than failing the whole entry — the domain
//     documents FileIdentity as "empty when unavailable".
func (windowsProbe) ProbeFile(path string) (domain.FileFacts, error) {
	var facts domain.FileFacts
	fi, err := os.Lstat(path)
	if err != nil {
		return facts, err
	}
	attrs := fileAttributesOf(fi)

	switch {
	case fi.Mode()&os.ModeSymlink != 0 || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return probeReparsePoint(path, fi, attrs)
	case fi.IsDir():
		facts.Kind = domain.KindDir
	default:
		facts.Kind = domain.KindFile
		facts.LogicalSize = fi.Size()
	}
	facts.Sparse = attrs&windows.FILE_ATTRIBUTE_SPARSE_FILE != 0

	// Placeholder guard: no handle, no stream enumeration, no identity
	// query beyond Lstat (probe Q8: Lstat sizes of dehydrated files are
	// reliable; opening them is what hydrates).
	if IsCloudPlaceholder(attrs) {
		facts.Placeholder = true
		return facts, nil
	}

	ident, err := identifyPath(path)
	if err != nil {
		return facts, nil //nolint:nilerr // see method doc, step 4
	}
	facts.FileIdentity = ident.fileIdentityString()
	facts.LinkCount = int64(ident.links)

	if facts.Kind == domain.KindFile {
		if size, ok := allocatedSizeOf(path); ok {
			facts.AllocatedSize = &size
		}
	}
	facts.Streams = listNamedStreams(path) // nil on non-NTFS; see streams_windows.go
	return facts, nil
}

// probeReparsePoint classifies a reparse-point entry. Go >= 1.23
// reports junctions/mount points as ModeIrregular (probe Q1), so the
// Lstat mode alone is NOT sufficient; the raw tag decides.
func probeReparsePoint(path string, fi os.FileInfo, attrs uint32) (domain.FileFacts, error) {
	var facts domain.FileFacts
	rp, err := readReparsePoint(path)
	if err != nil {
		// Degraded but conservative: never claim a plain kind for an
		// undecodable reparse point (KindOtherReparse blocks destructive
		// operations via EntryKind.DestructiveSafe).
		if fi.Mode()&os.ModeSymlink != 0 {
			facts.Kind = domain.KindSymlink
			if target, lerr := os.Readlink(path); lerr == nil {
				facts.LinkTarget = target
			}
		} else {
			facts.Kind = domain.KindOtherReparse
		}
		return facts, nil //nolint:nilerr // classification degrades safely
	}
	facts.ReparseTag = fmt.Sprintf("0x%08X", rp.tag)
	switch rp.tag {
	case ioReparseTagSymlink:
		facts.Kind = domain.KindSymlink
		// os.Readlink handles the relative/absolute flag and \??\UNC\
		// normalization (Go stdlib syscall.Readlink); fall back to the
		// raw substitute name only if it somehow fails.
		if target, lerr := os.Readlink(path); lerr == nil {
			facts.LinkTarget = target
		} else {
			facts.LinkTarget = normalizeSubstituteName(rp.substituteName)
		}
	case ioReparseTagMountPoint:
		// Same tag covers junctions (filesystem-path target) and volume
		// mount points (Volume{GUID} target); distinguish by substitute
		// name (probe Q1).
		if strings.HasPrefix(rp.substituteName, `\??\Volume{`) {
			facts.Kind = domain.KindMountPoint
		} else {
			facts.Kind = domain.KindJunction
		}
		facts.LinkTarget = normalizeSubstituteName(rp.substituteName)
	default:
		// OneDrive cloud files, dedup, NFS, Projected FS...: record the
		// hex tag and let KindOtherReparse block destructive ops.
		facts.Kind = domain.KindOtherReparse
	}
	return facts, nil
}

// allocatedSizeOf returns the exclusive on-disk allocation of a file.
// Preferred route: handle-based FileCompressionInfo.CompressedFileSize
// (sparse-correct, probe Q5). Fallback: GetCompressedFileSizeW via the
// in-tree LazyDLL binding (not exported by x/sys v0.48.0).
func allocatedSizeOf(path string) (int64, bool) {
	h, err := openMetadataHandle(path, false)
	if err == nil {
		defer windows.CloseHandle(h)
		var ci fileCompressionInfo
		if err := windows.GetFileInformationByHandleEx(h, uint32(windows.FileCompressionInfo),
			(*byte)(unsafe.Pointer(&ci)), uint32(unsafe.Sizeof(ci))); err == nil {
			return ci.compressedFileSize, true
		}
	}
	return compressedFileSizeByPath(path)
}
