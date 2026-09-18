package capsule

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// passphrase.go owns the capsule's NEW independent unlock secret
// (Foundation §13.1/§15.2): generated from crypto/rand, handed to the
// destination repository only through an ephemeral passfile, never
// stored by Ebb, never in argv/logs/envelopes, and displayed to the user
// exactly once by the CLI layer. The discipline mirrors
// vault.withPassfileBytes (private to that package and tied to its
// credential chain); the capsule password has no credential chain —
// Ebb holds it only for the duration of one export.

// GeneratePassphrase mints a fresh capsule passphrase: 32 bytes from
// crypto/rand, base64url-encoded (43 chars, shell-safe, no padding) —
// the same strength and shape as vault enrollment secrets. A broken
// crypto/rand cannot yield a trustworthy key: fail loudly instead.
func GeneratePassphrase() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("capsule: crypto/rand unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ephemeralPassfile writes the exact password bytes (no trailing
// newline) to a private temp file, runs fn with its path, and asserts
// the file is gone afterwards. Same contract as the vault adapter's
// passfile: 0600 create semantics (per-user %TEMP% ACL on Windows),
// fsync before use, exact-bytes content, removal asserted. No
// secure-erasure claim is made (SSD semantics).
func ephemeralPassfile(dir, password string, fn func(passfilePath string) error) error {
	if password == "" {
		return fmt.Errorf("capsule: refusing to write an empty passfile")
	}
	tmp, err := os.CreateTemp(dir, "ebb-capsule-pass-")
	if err != nil {
		return fmt.Errorf("capsule: create ephemeral passfile: %w", err)
	}
	path := tmp.Name()
	fail := func(e error) error {
		tmp.Close()
		_ = os.Remove(path)
		return e
	}
	if _, err := tmp.WriteString(password); err != nil {
		return fail(fmt.Errorf("capsule: write ephemeral passfile: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("capsule: sync ephemeral passfile: %w", err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("capsule: close ephemeral passfile: %w", err)
	}

	fnErr := fn(path)

	// Removal is asserted; a file that is already gone counts as removed
	// (the whole working dir is removed right after this regardless).
	if rerr := os.Remove(path); rerr != nil && !os.IsNotExist(rerr) && fnErr == nil {
		return fmt.Errorf("capsule: ephemeral passfile %s could not be removed (it contains the capsule password; delete it now): %w", path, rerr)
	}
	return fnErr
}
