//go:build windows

package tui

import "golang.org/x/sys/windows"

// vtProbe reports whether the output console can process VT escape
// sequences. The probe is stateless: when the VT bit is off it is set
// and immediately reverted, so probing never leaks console-mode
// changes. A redirected output handle or a legacy conhost (SetConsoleMode
// rejecting ENABLE_VIRTUAL_TERMINAL_PROCESSING) reports false, which
// routes the menus to the numbered-list fallback.
//
// This mirrors internal/platform's native-capability discipline
// (resolve per call, sticky capability fact, never panic). No LazyDLL
// binding is needed here: unlike FindFirstStreamW et al.,
// GetConsoleMode/SetConsoleMode are already exported by
// golang.org/x/sys v0.48.0.
func vtProbe() bool {
	con, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return false
	}
	var mode uint32
	if err := windows.GetConsoleMode(con, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	if err := windows.SetConsoleMode(con, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false
	}
	windows.SetConsoleMode(con, mode) // revert; MakeRaw re-enables for the menu
	return true
}

// vtSetup enables VT processing on the output console for a menu's
// lifetime and returns the restore function, or nil when the console
// cannot do VT (legacy conhost, redirected output) — the caller must
// then render the plain numbered fallback. When the bit is already set
// by someone else the restore is a no-op, and sequential menus each
// enable/restore their own span, so stacking two menus never leaves
// the console in the wrong mode.
func vtSetup() func() {
	con, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
	if err != nil {
		return nil
	}
	var mode uint32
	if err := windows.GetConsoleMode(con, &mode); err != nil {
		return nil
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return func() {}
	}
	if err := windows.SetConsoleMode(con, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return nil
	}
	return func() { windows.SetConsoleMode(con, mode) }
}
