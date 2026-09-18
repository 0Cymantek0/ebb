//go:build windows

package inventory

import (
	"fmt"
	"os"
	"syscall"

	"ebb/internal/domain"
)

// Test-only Windows enrichment: (volume serial, file index) and link
// count from a stdlib syscall handle query, per lab/platform-probe Q2.
// The production platform probe uses access-0 handles so placeholders
// are never touched; this test probe only ever walks throwaway temp
// fixtures, where opening is harmless.
func init() {
	fsEnrich = enrichWindows
	fsRootIdentity = rootIdentityWindows
}

func byHandleInfo(abs string) (info *syscall.ByHandleFileInformation, ok bool) {
	f, err := os.Open(abs)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var bh syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(f.Fd()), &bh); err != nil {
		return nil, false
	}
	return &bh, true
}

func enrichWindows(abs string, f *domain.FileFacts) {
	info, ok := byHandleInfo(abs)
	if !ok {
		return
	}
	f.FileIdentity = fmt.Sprintf("%08x-%08x%08x",
		info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow)
	f.LinkCount = int64(info.NumberOfLinks)
}

func rootIdentityWindows(abs string) (domain.RootIdentity, error) {
	info, ok := byHandleInfo(abs)
	if !ok {
		// Fall back to a path-derived identity; tests only require that
		// the seam is exercised, not that it is cryptographically native.
		return domain.RootIdentity{VolumeID: "real-fs", FileID: abs}, nil
	}
	return domain.RootIdentity{
		VolumeID: fmt.Sprintf("%08x", info.VolumeSerialNumber),
		FileID:   fmt.Sprintf("%08x%08x", info.FileIndexHigh, info.FileIndexLow),
	}, nil
}
