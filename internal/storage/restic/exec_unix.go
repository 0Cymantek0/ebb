//go:build !windows

package resticstore

import "syscall"

// procAttr starts restic in its own process group so a cancel-time kill
// takes down the whole group.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
