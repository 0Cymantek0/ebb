//go:build windows

package web

import "os/exec"

// openBrowser hands the URL to the Windows shell opener. Start (not
// Run): the opener returns immediately; the reaping Wait runs detached
// so the server never blocks on the desktop.
func openBrowser(url string) error {
	cmd := exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
