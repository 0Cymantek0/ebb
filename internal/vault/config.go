package vault

import (
	"fmt"
	"os"
	"path/filepath"
)

// File names inside the Ebb config directory. The directory itself is
// user-private (0700 semantics; on Windows the user-profile ACL of
// %AppData% provides this).
const (
	// RegistryFile is this package's vault registry.
	RegistryFile = "vaults.json"
	// LocatorFile is the exportable recovery locator (Foundation
	// §11.5/§16.5). It contains NO secret.
	LocatorFile = "locator.json"
	// CatalogFile is the SQLite catalog. It is OWNED BY
	// internal/catalog, not this package; the constant lives here only
	// to document the directory layout in one place. This package never
	// opens it.
	CatalogFile = "catalog.db"
)

// EnvStateDir is the environment override for the Ebb state directory.
// When set, it replaces the default user-config location for EVERYTHING
// the state dir holds (catalog.db, vaults.json, locator.json,
// approvals.json): automation, tests and cold-machine drills get a
// fully isolated install without touching the real per-user state. The
// value is absolutized once here so a relative setting cannot make the
// state location depend on the process working directory. It carries
// no secret. Empty/unset means the documented default path.
const EnvStateDir = "EBB_STATE_DIR"

// DefaultConfigDir returns the Ebb config directory:
// EBB_STATE_DIR when set, else os.UserConfigDir()/ebb (Windows:
// %AppData%\ebb, Linux: ~/.config/ebb... per XDG). It does not create
// the directory and does not require it to exist.
func DefaultConfigDir() (string, error) {
	if dir := os.Getenv(EnvStateDir); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("vault: %s %q: %w", EnvStateDir, dir, err)
		}
		return abs, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("vault: user config dir: %w", err)
	}
	return filepath.Join(base, "ebb"), nil
}

// EnsureConfigDir returns DefaultConfigDir, creating it (and parents)
// with 0700 if absent. On Windows the 0700 mode is advisory only —
// directory mode bits are not a Windows concept; the directory inherits
// the per-user ACL of %AppData%, which is the actual protection and is
// what Foundation §13.5 requires for the plaintext catalog/registry.
func EnsureConfigDir() (string, error) {
	dir, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("vault: create config dir %s: %w", dir, err)
	}
	return dir, nil
}
