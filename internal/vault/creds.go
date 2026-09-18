package vault

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/term"
)

// EnvPassword is the environment variable credential source. It is
// acceptable ONLY because an environment block is not argv and this
// tool never logs environment values (Foundation §13.1/§13.5); it
// exists for CI and tests. An empty value is treated as unset.
const EnvPassword = "EBB_VAULT_PASSWORD"

// Credential source names (the second return value of Password).
const (
	SourceEnv       = "env"        // EBB_VAULT_PASSWORD (CI/tests)
	SourceOSKeyring = "os-keyring" // OS credential store
	SourcePrompt    = "prompt"     // no-echo terminal prompt
)

// NoSourceError reports that no credential source could supply the
// vault password: env unset, no keyring entry (or keyring unsupported),
// and the prompt unavailable because stdin is not a terminal.
type NoSourceError struct {
	VaultID string
	Detail  string
}

func (e *NoSourceError) Error() string {
	d := e.Detail
	if d == "" {
		d = "stdin is not a terminal"
	}
	return fmt.Sprintf("vault: no password source for vault %s (env %s unset, no OS-keyring entry, %s)", e.VaultID, EnvPassword, d)
}

// Testing seams. The zero production wiring binds them to the real
// terminal; tests substitute deterministic fakes because a pty cannot
// be produced portably under `go test`. Each is consulted only on the
// prompt path.
var (
	// stdinIsTerminal reports whether fd 0 is a terminal.
	stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	// readPasswordRaw reads one no-echo password line from fd 0.
	readPasswordRaw = func(fd int) ([]byte, error) { return term.ReadPassword(fd) }
	// readLine reads one confirmation line from stdin (write path only).
	readLine = func() (string, error) {
		var buf [128]byte
		n, err := os.Stdin.Read(buf[:])
		if err != nil && n == 0 {
			return "", err
		}
		s := string(buf[:n])
		for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
			s = s[:len(s)-1]
		}
		return s, nil
	}
)

// Password returns the vault unlock password from the first available
// source, in fixed priority (Foundation §13.1):
//
//  1. env  — EBB_VAULT_PASSWORD (source "env")
//  2. keyring — OS credential store entry "ebb:vault:<vaultID>"
//     (source "os-keyring"); a missing entry or an unsupported
//     platform falls through, any other keyring failure is returned
//  3. prompt — no-echo terminal prompt (source "prompt"), only when
//     stdin is a terminal
//
// The password is never logged, never cached in package state, and
// never written anywhere except by WithPassfile (ephemeral) and
// StorePassword (credential store).
func Password(vaultID string) (password string, source string, err error) {
	if pw, ok := envPassword(); ok {
		return pw, SourceEnv, nil
	}
	secret, kerr := keyringGet(keyringTarget(vaultID))
	if kerr == nil {
		if secret != "" {
			return secret, SourceOSKeyring, nil
		}
		// An empty credential-store entry is treated as absent and the
		// chain continues; it is not a usable password.
	} else if !isMissingEntry(kerr) {
		return "", "", fmt.Errorf("vault: read credential store for vault %s: %w", vaultID, kerr)
	}
	if !stdinIsTerminal() {
		return "", "", &NoSourceError{VaultID: vaultID}
	}
	pw, perr := promptPassword(false)
	if perr != nil {
		return "", "", perr
	}
	return pw, SourcePrompt, nil
}

// PromptNewPassword interactively reads a NEW password twice (double
// entry, write path): the two entries must match. It requires a
// terminal; it is the manual counterpart of Enroll's generated secret.
func PromptNewPassword() (string, error) {
	if !stdinIsTerminal() {
		return "", &NoSourceError{VaultID: "", Detail: "stdin is not a terminal (new password)"}
	}
	return promptPassword(true)
}

// envPassword reads the env source; empty means unset.
func envPassword() (string, bool) {
	if pw := os.Getenv(EnvPassword); pw != "" {
		return pw, true
	}
	return "", false
}

// promptPassword reads one no-echo password from fd 0 with the prompt
// on stderr. With confirm=true (first set / write path) it asks twice
// and requires equality. The entered bytes are never echoed and never
// logged; only the fixed prompt text is written.
func promptPassword(confirm bool) (string, error) {
	pw1, err := promptOnce("vault password: ")
	if err != nil {
		return "", err
	}
	if !confirm {
		return pw1, nil
	}
	pw2, err := promptOnce("vault password (again): ")
	if err != nil {
		return "", err
	}
	if pw1 != pw2 {
		return "", errors.New("vault: password entries do not match")
	}
	return pw1, nil
}

// promptOnce writes the prompt to stderr and reads one no-echo line.
// ReadPassword leaves the cursor on the prompt line, so a bare newline
// is emitted to stderr afterwards; it carries no secret.
func promptOnce(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := readPasswordRaw(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("vault: read password from terminal: %w", err)
	}
	return string(b), nil
}

// StorePassword writes the vault password into the OS credential store
// (write path: enrollment, manual rotation). It never prints the
// password and never falls back to any file.
func StorePassword(vaultID, password string) error {
	if password == "" {
		return errors.New("vault: refusing to store an empty password")
	}
	if err := keyringSet(keyringTarget(vaultID), password); err != nil {
		return fmt.Errorf("vault: write credential store for vault %s: %w", vaultID, err)
	}
	return nil
}

// ForgetPassword deletes the vault's credential-store entry (wrapped
// ErrNotFound when absent). It does not touch the repository or the
// registry.
func ForgetPassword(vaultID string) error {
	if err := keyringDelete(keyringTarget(vaultID)); err != nil {
		return fmt.Errorf("vault: delete credential store for vault %s: %w", vaultID, err)
	}
	return nil
}
