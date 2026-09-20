//go:build windows

package cli

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// readDevModeUnlock reads the Windows Developer Mode switch
// (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock,
// value AllowDevelopmentWithoutDevLicense): 1 means unprivileged
// processes may create symbolic links. found is false when the value or
// key is absent (Developer Mode off); other read failures are errors.
func readDevModeUnlock() (value uint32, found bool, err error) {
	key, kerr := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock`, registry.QUERY_VALUE)
	if kerr != nil {
		if errors.Is(kerr, registry.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("doctor: open AppModelUnlock key: %w", kerr)
	}
	defer key.Close()
	v, _, gerr := key.GetIntegerValue("AllowDevelopmentWithoutDevLicense")
	if gerr != nil {
		if errors.Is(gerr, registry.ErrNotExist) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("doctor: read AllowDevelopmentWithoutDevLicense: %w", gerr)
	}
	return uint32(v), true, nil
}
