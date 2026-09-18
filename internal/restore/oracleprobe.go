package restore

// oracleProbe is the PlatformProbe the staged-tree verification scan
// runs through (§12.5 step 7). RootIdentity and VolumeUsage delegate to
// the injected platform probe (those calls close their native handles
// correctly); ProbeFile classifies with the Go standard library only.
//
// Two reasons, both load-bearing:
//
//  1. Oracle independence (E10, Foundation §18.1: "Snapshot/restore
//     comparison must use an independently generated expected
//     inventory, not the same potentially flawed encoder on both
//     sides"). The retained inventory was produced by the capture-side
//     native probe; verifying it through a different classification
//     route means a probe bug cannot hide the same file twice.
//
//  2. A same-process handle leak in the native probe's named-stream
//     enumeration (internal/platform/streams_windows.go closes the
//     FindFirstStreamW find handle with CloseHandle, which is invalid
//     for find handles — the handle stays open for the process
//     lifetime and pins every probed file against renaming an
//     ancestor directory). The publish rename of the staged tree would
//     fail with errno 5 for the rest of the process. The stdlib route
//     opens no handles at all. (Foundation F50 class; reported as a
//     cross-package friction — the platform package must switch to
//     FindClose.)
//
// Classification fidelity: regular files, directories and symlinks
// classify identically to the native probe (symlink link text comes
// from os.Readlink on both routes). Windows junctions surface as
// ModeIrregular and are labeled KindJunction; a volume mount point or
// an exotic reparse object would be mislabeled "junction" here and
// then FAIL the comparison against its sealed kind — a fail-closed
// false positive, never a false pass. Cloud placeholders cannot exist
// in a freshly materialized staging tree, so the allocation-based
// placeholder heuristic is not needed on this route.

import (
	"os"

	"ebb/internal/domain"
)

type oracleProbe struct {
	inner domain.PlatformProbe
}

func (p oracleProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	return p.inner.RootIdentity(path)
}

func (p oracleProbe) VolumeUsage(path string) (domain.VolumeUsage, error) {
	return p.inner.VolumeUsage(path)
}

func (p oracleProbe) ProbeFile(abs string) (domain.FileFacts, error) {
	fi, err := os.Lstat(abs)
	if err != nil {
		return domain.FileFacts{}, err
	}
	f := domain.FileFacts{}
	mode := fi.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		f.Kind = domain.KindSymlink
		f.LinkTarget = readlinkBestEffort(abs)
	case mode.IsDir():
		f.Kind = domain.KindDir
	case mode&os.ModeIrregular != 0:
		// Junction-class reparse directory: recorded, never descended.
		f.Kind = domain.KindJunction
		f.LinkTarget = readlinkBestEffort(abs)
	case mode&os.ModeNamedPipe != 0:
		f.Kind = domain.KindFIFO
	case mode&os.ModeSocket != 0:
		f.Kind = domain.KindSocket
	case mode&os.ModeDevice != 0:
		f.Kind = domain.KindDevice
	default:
		f.Kind = domain.KindFile
		f.LogicalSize = fi.Size()
	}
	return f, nil
}

func readlinkBestEffort(abs string) string {
	t, err := os.Readlink(abs)
	if err != nil {
		return ""
	}
	return t
}
