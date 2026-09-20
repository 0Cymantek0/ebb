//go:build !windows

package cli

import "errors"

// errDevModeUnsupported is the non-Windows answer of the Developer Mode
// registry seam (the probe itself reports n/a before reading).
var errDevModeUnsupported = errors.New("doctor: Windows Developer Mode registry probe is Windows-only")

func readDevModeUnlock() (value uint32, found bool, err error) {
	return 0, false, errDevModeUnsupported
}
