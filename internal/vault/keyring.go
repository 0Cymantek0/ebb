package vault

import "errors"

// The OS credential store seam. Implementations are per-OS
// (keyring_windows.go; keyring_other.go returns ErrUnsupported) and are
// bound once to the function vars below. Tests may substitute them to
// stay hermetic; production never swaps them.
//
// Contract for all four:
//   - A missing entry is reported as an error wrapping ErrNotFound.
//   - An unavailable/unsupported store is reported as an error wrapping
//     ErrUnsupported.
//   - The secret crosses only these calls; it is never logged.
var (
	keyringGet    func(target string) (string, error)
	keyringSet    func(target, secret string) error
	keyringDelete func(target string) error
	keyringExists func(target string) (bool, error)
)

// keyringTarget is the credential-store target name for a vault:
// "ebb:vault:<vaultID>". Stable across sessions so rotation overwrites
// rather than accumulates entries.
func keyringTarget(vaultID string) string {
	return "ebb:vault:" + vaultID
}

// isMissingEntry reports whether a keyring error means "no such entry"
// (fall through to the next source) as opposed to a store failure
// (surface the error).
func isMissingEntry(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnsupported)
}

// KeyringRoundTrip self-tests the OS credential store: write, read back
// and delete a canary entry for vaultID, returning the round-trip
// result. It exists for diagnostics and for the test that proves this
// environment's credential store actually works; it never leaves the
// canary behind on success.
func KeyringRoundTrip(vaultID string) error {
	target := keyringTarget(vaultID)
	const canary = "ebb-keyring-selftest"
	if err := keyringSet(target, canary); err != nil {
		return err
	}
	got, err := keyringGet(target)
	if err != nil {
		keyringDelete(target)
		return err
	}
	if got != canary {
		keyringDelete(target)
		return errors.New("vault: credential store round trip mismatch")
	}
	return keyringDelete(target)
}
