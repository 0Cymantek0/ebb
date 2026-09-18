//go:build linux

package platform

import (
	"fmt"
	"os"
	"syscall"

	"ebb/internal/domain"
)

// linuxProbe implements domain.PlatformProbe for Linux (ext4-family).
// Identity is dev+ino; allocated size comes from stat blocks; named
// streams and extended attributes are NOT enumerated in v1 — a
// documented capability gap (Foundation §10.1: a feature becomes
// supported only after a native round trip proves it; until then the
// gap must be reported, not guessed around).
type linuxProbe struct{}

// newNativeProbe returns the Linux probe (see platform.go New).
func newNativeProbe() domain.PlatformProbe { return linuxProbe{} }

// statOf Lstats path and returns its syscall.Stat_t.
func statOf(path string) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	fi, err := os.Lstat(path)
	if err != nil {
		return st, err
	}
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return *s, nil
	}
	return st, fmt.Errorf("platform: %s: no stat data (got %T)", path, fi.Sys())
}

// RootIdentity returns dev+ino for an existing root path. os.Lstat
// never follows symlinks, so a root that is a symlink is identified as
// the link object; dev+ino survives rename (ext4) per the domain
// contract's validation note.
func (linuxProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	st, err := statOf(path)
	if err != nil {
		return domain.RootIdentity{}, err
	}
	return domain.RootIdentity{
		VolumeID: fmt.Sprintf("%x", uint64(st.Dev)),
		FileID:   fmt.Sprintf("%x", uint64(st.Ino)),
	}, nil
}

// VolumeUsage reports statfs numbers: FreeToCaller is f_bavail*f_frsize
// (quota-aware, matching the domain contract), VolumeFree is
// f_bfree*f_bsize, Total is f_blocks*f_bsize. VolumeID is the device id
// in the same hex form RootIdentity uses.
func (linuxProbe) VolumeUsage(path string) (domain.VolumeUsage, error) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return domain.VolumeUsage{}, fmt.Errorf("statfs(%s): %w", path, err)
	}
	st, err := statOf(path)
	if err != nil {
		return domain.VolumeUsage{}, err
	}
	fsize := int64(fs.Bsize) // f_frsize == f_bsize on Linux
	return domain.VolumeUsage{
		FreeToCaller: int64(fs.Bavail) * fsize,
		VolumeFree:   int64(fs.Bfree) * fsize,
		Total:        int64(fs.Blocks) * fsize,
		VolumeID:     fmt.Sprintf("%x", uint64(st.Dev)),
	}, nil
}

// ProbeFile classifies one path without following symlinks. v1 Linux
// capability: kinds (file/dir/symlink/FIFO/socket/device), logical and
// allocated size (st_blocks*512), link count, and a block-based sparse
// heuristic. No named streams / xattrs (gap above).
func (linuxProbe) ProbeFile(path string) (domain.FileFacts, error) {
	var facts domain.FileFacts
	fi, err := os.Lstat(path)
	if err != nil {
		return facts, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return facts, fmt.Errorf("platform: %s: no stat data (got %T)", path, fi.Sys())
	}
	facts.LogicalSize = fi.Size()
	allocated := int64(st.Blocks) * 512
	facts.AllocatedSize = &allocated
	facts.LinkCount = int64(st.Nlink)
	facts.FileIdentity = devInoIdentity(*st)
	// Sparse heuristic: st_blocks never counts holes, so an allocation
	// below the logical size means the file carries holes (sparse).
	facts.Sparse = allocated >= 0 && uint64(allocated) < uint64(st.Size)

	mode := fi.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		facts.Kind = domain.KindSymlink
		facts.LogicalSize = 0
		facts.AllocatedSize = nil
		target, err := os.Readlink(path)
		if err != nil {
			return facts, err
		}
		facts.LinkTarget = target
	case fi.IsDir():
		facts.Kind = domain.KindDir
		facts.LogicalSize = 0
		facts.AllocatedSize = nil
	case mode&os.ModeNamedPipe != 0:
		facts.Kind = domain.KindFIFO
	case mode&os.ModeSocket != 0:
		facts.Kind = domain.KindSocket
	case mode&os.ModeDevice != 0:
		facts.Kind = domain.KindDevice
	default:
		facts.Kind = domain.KindFile
	}
	return facts, nil
}
