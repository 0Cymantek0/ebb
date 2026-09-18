//go:build windows

package resticstore

import "syscall"

// procAttr starts restic in its own process group so a cancel-time kill
// does not depend on (or propagate to) the parent console group.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}
