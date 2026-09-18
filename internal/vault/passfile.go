package vault

import (
	"errors"
	"fmt"
	"os"
)

// PassfileCleanupError reports that WithPassfile's deferred removal of
// the ephemeral passfile failed. The file still exists on disk and
// CONTAINS THE VAULT PASSWORD; Path names it so the user (or tooling)
// can delete it. This error is both returned (when fn succeeded) and
// logged to stderr (always), because Foundation §13.1 permits the
// ephemeral passfile only under an exact-owned-and-removed contract —
// a silent leftover violates it.
type PassfileCleanupError struct {
	Path string
	Err  error
}

func (e *PassfileCleanupError) Error() string {
	return fmt.Sprintf("vault: ephemeral passfile %s could not be removed: %v (it contains the vault password; delete it now)", e.Path, e.Err)
}

func (e *PassfileCleanupError) Unwrap() error { return e.Err }

// WithPassfile obtains the vault password through the credential
// source chain (env > OS keyring > terminal prompt), hands fn the path
// of an ephemeral passfile containing it, and removes the file after
// fn returns. It is the ONLY way the password reaches the restic CLI:
// callers set RESTIC_PASSWORD_FILE=<passfilePath> (via the store
// adapter's env construction), keeping the secret out of argv.
//
// Semantics (Foundation §13.1, verbatim contract):
//   - the temp file is created in os.TempDir() with exclusive-create
//     0600 semantics. On POSIX that is the file mode; on Windows the
//     mode bits are advisory only — the actual protection is the
//     inherited per-user ACL of %TEMP% (a user-profile directory), the
//     same boundary restic itself relies on for its cache. No extra
//     SetFileAttributes is applied: the readonly attribute would fight
//     the guaranteed removal below.
//   - the file contains the EXACT password bytes — no trailing
//     newline, no quoting.
//   - the content is fsynced before fn runs.
//   - removal is asserted afterwards: if the file cannot be removed
//     the failure is logged to stderr and, when fn succeeded, returned
//     as *PassfileCleanupError. A file that is already gone (fn or the
//     store deleted it) counts as removed.
//   - when fn fails, fn's error is returned unchanged and the file is
//     still removed; a cleanup failure is logged but does not mask
//     fn's error.
//
// No secure-erasure claim is made (SSD semantics, §13.1); removal, not
// wiping, is the contract.
func WithPassfile(vaultID string, fn func(passfilePath string) error) error {
	if fn == nil {
		return errors.New("vault: WithPassfile: nil callback")
	}
	pw, _, err := Password(vaultID)
	if err != nil {
		return err
	}
	return withPassfileBytes(pw, fn)
}

// withPassfileBytes is WithPassfile with an already-obtained password
// (Enroll holds the freshly generated secret before any source holds
// it). Same contract and cleanup guarantees as WithPassfile.
func withPassfileBytes(password string, fn func(passfilePath string) error) error {
	if fn == nil {
		return errors.New("vault: passfile: nil callback")
	}
	if password == "" {
		return errors.New("vault: refusing to write an empty passfile")
	}
	tmp, err := os.CreateTemp("", "ebb-vault-pass-")
	if err != nil {
		return fmt.Errorf("vault: create ephemeral passfile: %w", err)
	}
	path := tmp.Name()
	if _, err := tmp.WriteString(password); err != nil {
		tmp.Close()
		removeAsserting(path)
		return fmt.Errorf("vault: write ephemeral passfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		removeAsserting(path)
		return fmt.Errorf("vault: sync ephemeral passfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		removeAsserting(path)
		return fmt.Errorf("vault: close ephemeral passfile: %w", err)
	}

	fnErr := fn(path)

	cleanupErr := removeAsserting(path)
	if cleanupErr != nil && fnErr == nil {
		return cleanupErr
	}
	return fnErr
}

// removeAsserting deletes path and reports (with a stderr warning) any
// failure. A missing file is success: the goal — no passfile left — is
// already met. This is the "never leave silently" half of the §13.1
// contract; the returned error carries the path for the caller.
func removeAsserting(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		warn := &PassfileCleanupError{Path: path, Err: err}
		fmt.Fprintln(os.Stderr, warn.Error())
		return warn
	}
	return nil
}
