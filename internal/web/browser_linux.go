//go:build linux

package web

import "os/exec"

// openBrowser hands the URL to the freedesktop opener. Start (not Run):
// the opener returns immediately; the reaping Wait runs detached so the
// server never blocks on the desktop session.
func openBrowser(url string) error {
	cmd := exec.Command("xdg-open", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
