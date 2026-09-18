//go:build !windows

package platform

import (
	"fmt"
	"os"
)

// CreateJunction: Linux/darwin have no junction object. A retained
// junction-kind entry can only originate from a Windows capture; the
// closest representable object is a symlink with the recorded target
// text (verbatim, so the oracle's os.Readlink comparison sees the same
// bytes). No privilege is needed.
func CreateJunction(path, target string) error {
	if target == "" {
		return fmt.Errorf("platform: junction target is empty")
	}
	if err := os.Symlink(target, path); err != nil {
		return fmt.Errorf("platform: create junction-as-symlink %s: %w", path, err)
	}
	return nil
}

// CreateSymlink on Linux/darwin is plain os.Symlink — unprivileged, no
// privilege-refusal class exists.
func CreateSymlink(path, target string) error {
	if err := os.Symlink(target, path); err != nil {
		return fmt.Errorf("platform: create symlink %s: %w", path, err)
	}
	return nil
}
