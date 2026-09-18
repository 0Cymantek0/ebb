//go:build !windows

package vault

import (
	"fmt"
	"runtime"
)

// v1 implements the OS credential store only on Windows (Credential
// Manager). Everywhere else every keyring call fails with a wrapped
// ErrUnsupported; the source chain then falls through to the prompt,
// and Enroll uses its guarded recovery-secret fallback. Secret-service
// integration (Linux) is deliberately deferred: a half-working DBus
// dependency would be worse than an explicit unsupported error.
func init() {
	unsupported := func(op string) error {
		return fmt.Errorf("vault: %s via OS keyring on %s: %w (secret-service integration comes later)", op, runtime.GOOS, ErrUnsupported)
	}
	keyringGet = func(string) (string, error) { return "", unsupported("read") }
	keyringSet = func(string, string) error { return unsupported("write") }
	keyringDelete = func(string) error { return unsupported("delete") }
	keyringExists = func(string) (bool, error) { return false, unsupported("exists") }
}
