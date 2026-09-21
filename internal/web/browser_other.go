//go:build !windows && !linux

package web

// openBrowser is a no-op on platforms without a wired opener: the URL
// is already printed, and failing to open a browser is never fatal.
func openBrowser(url string) error { return nil }
