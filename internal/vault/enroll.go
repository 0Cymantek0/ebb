package vault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"ebb/internal/domain"
)

// locatorVersion is the recovery locator schema version.
const locatorVersion = 1

// Locator is the user-exportable recovery locator (Foundation §11.5,
// §16.5): the minimum record needed to find a vault again after total
// catalog loss — which vault, where, when — and an explicit statement
// that it contains NO secret. The unlock secret stays in the OS
// credential store or the user's independently recorded recovery copy.
type Locator struct {
	SchemaVersion int    `json:"schema_version"`
	VaultID       string `json:"vault_id"`
	VaultName     string `json:"vault_name"`
	RepoDir       string `json:"repo_dir"`
	CreatedAt     string `json:"created_at"`
	Note          string `json:"note"`
}

// locatorNote is the fixed no-secret disclosure printed into every
// locator.
const locatorNote = "unlock secret lives in OS credential store (or your records); this file contains NO secret"

// UnlockRejectedError reports that Unlock verified the credential
// against the repository and the repository rejected it (wrong
// password / unauthorized). Infrastructural failures are returned as
// ordinary errors instead; only an authenticated rejection produces
// this type.
type UnlockRejectedError struct {
	VaultID string
	Err     error
}

func (e *UnlockRejectedError) Error() string {
	return fmt.Sprintf("vault: unlock rejected for vault %s (wrong password?): %v", e.VaultID, e.Err)
}

func (e *UnlockRejectedError) Unwrap() error { return e.Err }

// Enroll performs first-use enrollment of one vault (Foundation §11.5,
// §13.1, §16.5):
//
//  1. repoDir must be empty or absent (never implicitly adopts an
//     existing directory); it is created 0700.
//  2. A vault identity is minted (domain.NewID) and a strong random
//     password is generated (32 crypto/rand bytes, base64url).
//  3. The password is persisted to the OS credential store under
//     "ebb:vault:<vaultID>". When the store is unavailable (or fails),
//     the fallback is the ONE sanctioned secret print: the password is
//     written to out with an explicit warning, and enrollment proceeds
//     only after an interactive confirmation that the recovery secret
//     has been stored elsewhere. Without a terminal the fallback is
//     refused (ErrRecoveryUnconfirmed) — never a silent skip.
//  4. The restic repository is initialized through the injected
//     domain.SnapshotStore (caller wires resticstore.Store), with the
//     password reaching it only via an ephemeral passfile; the backend
//     RepoID is captured.
//  5. The vault is registered in <cfgDir>/vaults.json and the recovery
//     locator is written to <cfgDir>/locator.json; the locator path and
//     copy-it-outside advice are printed to out.
//
// When EBB_VAULT_PASSWORD is set, it is used as the enrollment
// password INSTEAD of a generated one and the credential store is
// deliberately NOT written (CI/tests must not mutate a real user's
// credential store; the env var is that environment's credential).
//
// Failure retention: if any step after repoDir creation fails, the
// created directory and any partial restic state are left in place
// (data is never deleted to tidy up an interrupted enrollment,
// §11.5); a retry on the same directory fails cleanly with
// ErrRepoDirNotEmpty.
func Enroll(ctx context.Context, cfgDir, name, repoDir string, store domain.SnapshotStore, out io.Writer) (Vault, error) {
	if store == nil {
		return Vault{}, errors.New("vault: enroll: nil SnapshotStore (caller must wire resticstore)")
	}
	if out == nil {
		return Vault{}, errors.New("vault: enroll: nil output writer")
	}
	if cfgDir == "" {
		return Vault{}, errors.New("vault: enroll: config dir required")
	}
	if name == "" {
		return Vault{}, errors.New("vault: enroll: vault name required")
	}
	if repoDir == "" {
		return Vault{}, errors.New("vault: enroll: repo dir required")
	}

	// Step 1: the target directory must be empty or absent.
	if entries, err := os.ReadDir(repoDir); err == nil {
		if len(entries) > 0 {
			return Vault{}, fmt.Errorf("%w: %s (%d entries)", ErrRepoDirNotEmpty, repoDir, len(entries))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Vault{}, fmt.Errorf("vault: inspect repo dir %s: %w", repoDir, err)
	}
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		return Vault{}, fmt.Errorf("vault: create config dir %s: %w", cfgDir, err)
	}
	absRepo, err := filepath.Abs(repoDir)
	if err != nil {
		return Vault{}, fmt.Errorf("vault: resolve repo dir %s: %w", repoDir, err)
	}
	if err := os.MkdirAll(absRepo, 0o700); err != nil {
		return Vault{}, fmt.Errorf("vault: create repo dir %s: %w", absRepo, err)
	}

	// Step 2+3: identity and password. The env source (CI/tests)
	// bypasses both generation and the credential store on purpose.
	vaultID := domain.NewID().String()
	pw, fromEnv := envPassword()
	if !fromEnv {
		pw = generatePassword()
		if err := keyringSet(keyringTarget(vaultID), pw); err != nil {
			if cerr := confirmRecoverySecret(out, pw, err); cerr != nil {
				return Vault{}, cerr
			}
		}
	}

	// Step 4: initialize the repository; the password travels only via
	// the ephemeral passfile.
	var repoID string
	if err := withPassfileBytes(pw, func(passfile string) error {
		if err := store.Init(ctx, absRepo, passfile); err != nil {
			return fmt.Errorf("vault: init repository at %s: %w", absRepo, err)
		}
		id, err := store.RepoID(ctx, absRepo, passfile)
		if err != nil {
			return fmt.Errorf("vault: read repository id at %s: %w", absRepo, err)
		}
		repoID = id
		return nil
	}); err != nil {
		return Vault{}, err
	}

	// Step 5a: register in the (secret-free) registry under the SAME
	// id the credential-store entry (if written) already targets.
	reg := New(filepath.Join(cfgDir, RegistryFile))
	v, err := reg.registerWithID(vaultID, name, absRepo, repoID)
	if err != nil {
		return Vault{}, fmt.Errorf("vault: repository initialized at %s (repo id %s) but registration failed: %w", absRepo, repoID, err)
	}

	// Step 5b: recovery locator. No secret, ever.
	loc := Locator{
		SchemaVersion: locatorVersion,
		VaultID:       v.ID,
		VaultName:     v.Name,
		RepoDir:       v.RepoDir,
		CreatedAt:     v.CreatedAt,
		Note:          locatorNote,
	}
	locPath := filepath.Join(cfgDir, LocatorFile)
	if err := writeLocator(locPath, loc); err != nil {
		return v, fmt.Errorf("vault: vault enrolled but recovery locator failed: %w", err)
	}

	// Step 5c: tell the user where the locator is and — per §11.5 —
	// that its only copy must NOT live inside the workspace being
	// parked.
	fmt.Fprintf(out, "recovery locator written: %s\n", locPath)
	fmt.Fprintln(out, "Copy this file OUTSIDE any workspace it protects; after catalog loss it is how the vault is found again.")
	if fromEnv {
		fmt.Fprintf(out, "note: password came from %s; the OS credential store was not written.\n", EnvPassword)
	}
	return v, nil
}

// Unlock verifies that the vault's credential actually opens the
// repository: it looks the vault up in <cfgDir>/vaults.json, obtains
// the password through the source chain (env > keyring > prompt) and
// asks the store to read the (encrypted) repository id through an
// ephemeral passfile.
//
// Returns (true, nil) when the credential works. A rejected credential
// — the repository answered "wrong password/unauthorized" — returns
// (false, *UnlockRejectedError). Any other failure (unknown vault,
// missing password source, store infrastructure error) returns
// (false, error).
func Unlock(ctx context.Context, cfgDir, idOrName string, store domain.SnapshotStore) (bool, error) {
	if store == nil {
		return false, errors.New("vault: unlock: nil SnapshotStore (caller must wire resticstore)")
	}
	reg := New(filepath.Join(cfgDir, RegistryFile))
	v, err := reg.Get(idOrName)
	if err != nil {
		return false, err
	}

	var verifyErr error
	if err := WithPassfile(v.ID, func(passfile string) error {
		// Swallow the store error into verifyErr so the passfile's
		// removal contract still runs on rejection; WithPassfile
		// returning a cleanup error must not be masked either.
		if _, err := store.RepoID(ctx, v.RepoDir, passfile); err != nil {
			verifyErr = err
		}
		return nil
	}); err != nil {
		return false, err
	}
	if verifyErr == nil {
		return true, nil
	}
	var se *domain.StoreError
	if errors.As(verifyErr, &se) && se.Class == domain.StoreErrAuth {
		return false, &UnlockRejectedError{VaultID: v.ID, Err: verifyErr}
	}
	return false, fmt.Errorf("vault: unlock check for vault %s: %w", v.ID, verifyErr)
}

// writeLocator durably writes the locator via the same atomic
// temp+rename discipline as the registry.
func writeLocator(path string, loc Locator) error {
	loc.SchemaVersion = locatorVersion
	b, err := json.MarshalIndent(loc, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: encode locator: %w", err)
	}
	if err := writeAtomic(path, b); err != nil {
		return fmt.Errorf("vault: save locator: %w", err)
	}
	return nil
}

// confirmRecoverySecret is the guarded one-time secret print used only
// when the OS credential store could not hold the enrollment password.
// It writes the marked secret to out, then requires an interactive
// "yes" confirmation. Without a terminal it refuses outright: printing
// a secret into a pipe (CI logs, redirected output) would leak it, and
// silently skipping the recovery step loses the vault.
func confirmRecoverySecret(out io.Writer, password string, cause error) error {
	if !stdinIsTerminal() {
		return fmt.Errorf("%w: OS credential store unavailable (%v) and stdin is not a terminal, so the recovery secret could neither be stored nor safely shown", ErrRecoveryUnconfirmed, cause)
	}
	fmt.Fprintf(out, "=== EBB RECOVERY SECRET (shown ONCE — not stored in the OS credential store: %v) ===\n", cause)
	fmt.Fprintln(out, password)
	fmt.Fprintln(out, "=== END RECOVERY SECRET ===")
	fmt.Fprint(out, "Store this secret now in your password manager or printed records.\nType yes to confirm you have stored it: ")
	line, err := readLine()
	if err != nil {
		return fmt.Errorf("%w: reading confirmation: %v", ErrRecoveryUnconfirmed, err)
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "yes", "y":
		return nil
	default:
		return fmt.Errorf("%w: answer %q was not confirmed", ErrRecoveryUnconfirmed, line)
	}
}

// generatePassword mints a fresh enrollment password: 32 bytes from
// crypto/rand, base64url-encoded (43 chars, shell-safe, no padding).
func generatePassword() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A broken crypto/rand cannot yield a trustworthy vault key;
		// fail loudly rather than enroll under a weak secret.
		panic(fmt.Sprintf("vault: crypto/rand unavailable: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
