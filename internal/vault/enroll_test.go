package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/domain"
	resticstore "ebb/internal/storage/restic"
)

// ---- fake-store enrollment (always runs) ----

func TestEnrollFakeStoreHappyPath(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "enroll-env-pw")
	cfgDir := filepath.Join(t.TempDir(), "cfg")
	repoDir := filepath.Join(t.TempDir(), "vault")
	store := &fakeStore{wantPassword: "enroll-env-pw", repoID: "repo-fake-1"}

	var out strings.Builder
	v, err := Enroll(context.Background(), cfgDir, "main", repoDir, store, &out)
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "main" || v.RepoID != "repo-fake-1" {
		t.Fatalf("vault record wrong: %+v", v)
	}
	if abs, _ := filepath.Abs(repoDir); v.RepoDir != abs {
		t.Fatalf("RepoDir must be absolute, got %q", v.RepoDir)
	}
	if len(store.inits) != 1 || store.repoIDCalls != 1 {
		t.Fatalf("store interactions wrong: inits=%v repoIDCalls=%d", store.inits, store.repoIDCalls)
	}
	// The password reached the store ONLY via the passfile, exact bytes.
	for _, c := range store.passfileContents {
		if c != "enroll-env-pw" {
			t.Fatalf("passfile content must be the exact password, got %q", c)
		}
	}
	// Registered in vaults.json.
	if got, err := New(filepath.Join(cfgDir, RegistryFile)).Get(v.ID); err != nil || got.Name != "main" {
		t.Fatalf("registry lookup after enroll: %+v %v", got, err)
	}
	// Locator: right fields, no secret.
	locBytes, err := os.ReadFile(filepath.Join(cfgDir, LocatorFile))
	if err != nil {
		t.Fatal(err)
	}
	var loc Locator
	if err := json.Unmarshal(locBytes, &loc); err != nil {
		t.Fatal(err)
	}
	if loc.SchemaVersion != 1 || loc.VaultID != v.ID || loc.VaultName != "main" || loc.RepoDir != v.RepoDir {
		t.Fatalf("locator wrong: %+v", loc)
	}
	if !strings.Contains(loc.Note, "NO secret") {
		t.Fatalf("locator note must disclose it carries no secret: %q", loc.Note)
	}
	assertNoSecret(t, string(locBytes), "enroll-env-pw", "locator")
	// Output names the locator and the copy-outside advice; env path is
	// disclosed and the credential store was NOT written (stub captured
	// nothing — verified by the env note plus stub below in other tests).
	s := out.String()
	if !strings.Contains(s, LocatorFile) || !strings.Contains(s, "OUTSIDE") {
		t.Fatalf("output must print the locator path and advice, got:\n%s", s)
	}
	if !strings.Contains(s, EnvPassword) {
		t.Fatalf("env-source enrollment must disclose that the keyring was not written:\n%s", s)
	}
	assertNoSecret(t, s, "enroll-env-pw", "enrollment output")
}

func TestEnrollRepoDirNotEmpty(t *testing.T) {
	t.Setenv(EnvPassword, "pw")
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, "user-file.txt"), []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Enroll(context.Background(), t.TempDir(), "main", repoDir, &fakeStore{}, &strings.Builder{})
	if !errors.Is(err, ErrRepoDirNotEmpty) {
		t.Fatalf("non-empty repo dir must be ErrRepoDirNotEmpty, got %v", err)
	}
	// The pre-existing file must be untouched (no adoption, no deletion).
	b, err := os.ReadFile(filepath.Join(repoDir, "user-file.txt"))
	if err != nil || string(b) != "data" {
		t.Fatalf("existing content must be preserved: %q %v", b, err)
	}
}

func TestEnrollSecondEnrollSameDirCleanError(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "pw")
	cfgDir := filepath.Join(t.TempDir(), "cfg")
	repoDir := filepath.Join(t.TempDir(), "vault")
	store := &fakeStore{wantPassword: "pw", repoID: "repo-1"}
	if _, err := Enroll(context.Background(), cfgDir, "main", repoDir, store, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	_, err := Enroll(context.Background(), cfgDir, "main2", repoDir, store, &strings.Builder{})
	if !errors.Is(err, ErrRepoDirNotEmpty) {
		t.Fatalf("second enroll on the same dir must fail cleanly, got %v", err)
	}
	// Registry still holds exactly the first vault.
	list, err := New(filepath.Join(cfgDir, RegistryFile)).List()
	if err != nil || len(list) != 1 || list[0].Name != "main" {
		t.Fatalf("registry after failed second enroll: %+v %v", list, err)
	}
}

func TestEnrollGeneratesAndStoresPassword(t *testing.T) {
	unsetEnvPassword(t)
	var setTarget, setSecret string
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(target, secret string) error { setTarget, setSecret = target, secret; return nil },
		func(string) error { return nil },
	)
	cfgDir := filepath.Join(t.TempDir(), "cfg")
	repoDir := filepath.Join(t.TempDir(), "vault")
	var out strings.Builder

	v, err := Enroll(context.Background(), cfgDir, "main", repoDir, &fakeStore{repoID: "r"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if setTarget != keyringTarget(v.ID) {
		t.Fatalf("keyring write must target ebb:vault:<id>, got %q", setTarget)
	}
	// 32 random bytes, base64url (43 chars, unpadded charset).
	if n := len(setSecret); n != 43 {
		t.Fatalf("generated password must be 43 chars base64url, got %d: %q", n, setSecret)
	}
	for _, c := range setSecret {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			t.Fatalf("generated password must be base64url, got %q", setSecret)
		}
	}
	// Keyring path must NOT print the secret.
	assertNoSecret(t, out.String(), setSecret, "enrollment output with keyring")
}

func TestEnrollFallbackConfirmed(t *testing.T) {
	unsetEnvPassword(t)
	var captured string
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(target, secret string) error {
			captured = secret
			return fmt.Errorf("store down: %w", ErrUnsupported)
		},
		func(string) error { return nil },
	)
	stubTerminal(t, true, "yes")
	cfgDir := filepath.Join(t.TempDir(), "cfg")
	repoDir := filepath.Join(t.TempDir(), "vault")
	var out strings.Builder

	v, err := Enroll(context.Background(), cfgDir, "main", repoDir, &fakeStore{repoID: "r"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "RECOVERY SECRET") || !strings.Contains(s, captured) {
		t.Fatalf("guarded fallback must print the marked secret exactly once:\n%s", s)
	}
	if strings.Count(s, captured) != 1 {
		t.Fatalf("secret must appear exactly once in output, got %d", strings.Count(s, captured))
	}
	if !strings.Contains(s, "yes") && !strings.Contains(s, "confirm") {
		t.Fatalf("output must show the confirmation request:\n%s", s)
	}
	if list, err := New(filepath.Join(cfgDir, RegistryFile)).List(); err != nil || len(list) != 1 || list[0].ID != v.ID {
		t.Fatalf("vault must be registered after confirmed fallback: %+v %v", list, err)
	}
}

func TestEnrollFallbackRefusedWithoutTerminal(t *testing.T) {
	unsetEnvPassword(t)
	var captured string
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(target, secret string) error {
			captured = secret
			return fmt.Errorf("store down: %w", ErrUnsupported)
		},
		func(string) error { return nil },
	)
	stubTerminal(t, false, "")
	cfgDir := filepath.Join(t.TempDir(), "cfg")
	var out strings.Builder

	_, err := Enroll(context.Background(), cfgDir, "main", filepath.Join(t.TempDir(), "vault"), &fakeStore{}, &out)
	if !errors.Is(err, ErrRecoveryUnconfirmed) {
		t.Fatalf("no tty + no keyring must refuse with ErrRecoveryUnconfirmed, got %v", err)
	}
	assertNoSecret(t, out.String(), captured, "refused fallback output")
	if list, err := New(filepath.Join(cfgDir, RegistryFile)).List(); err != nil || len(list) != 0 {
		t.Fatalf("nothing may be registered on refusal: %+v %v", list, err)
	}
}

func TestEnrollFallbackRefusedOnNoAnswer(t *testing.T) {
	unsetEnvPassword(t)
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return fmt.Errorf("down: %w", ErrUnsupported) },
		func(string) error { return nil },
	)
	stubTerminal(t, true, "no")
	var out strings.Builder
	_, err := Enroll(context.Background(), t.TempDir(), "main", filepath.Join(t.TempDir(), "vault"), &fakeStore{}, &out)
	if !errors.Is(err, ErrRecoveryUnconfirmed) {
		t.Fatalf("a non-yes answer must refuse, got %v", err)
	}
}

// ---- Unlock (fake store) ----

func TestUnlockFakeStore(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "right-pw")
	cfgDir := t.TempDir()
	reg := New(filepath.Join(cfgDir, RegistryFile))
	v, err := reg.Register("main", "/v/main", "repo-1")
	if err != nil {
		t.Fatal(err)
	}
	store := &fakeStore{wantPassword: "right-pw", repoID: "repo-1"}

	ok, err := Unlock(context.Background(), cfgDir, "main", store)
	if !ok || err != nil {
		t.Fatalf("right password must unlock: (%v, %v)", ok, err)
	}

	t.Setenv(EnvPassword, "wrong-pw")
	ok, err = Unlock(context.Background(), cfgDir, v.ID, store)
	if ok {
		t.Fatal("wrong password must not report unlocked")
	}
	var rej *UnlockRejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("wrong password must fail typed, got %T: %v", err, err)
	}
	if rej.VaultID != v.ID {
		t.Fatalf("rejection must name the vault, got %q", rej.VaultID)
	}

	// A non-auth store failure is an ordinary error, not a rejection.
	store2 := &authFailingStore{class: domain.StoreErrRepo}
	if _, err := Unlock(context.Background(), cfgDir, "main", store2); err == nil || errors.As(err, &rej) {
		t.Fatalf("repo-class failure must not be UnlockRejectedError, got %v", err)
	}

	// Unknown vault.
	if _, err := Unlock(context.Background(), cfgDir, "ghost", store); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown vault must be ErrNotFound, got %v", err)
	}
}

// authFailingStore always fails RepoID with a fixed error class.
type authFailingStore struct {
	class domain.StoreErrorClass
}

func (a *authFailingStore) Init(ctx context.Context, dir, passfile string) error { return nil }
func (a *authFailingStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	return "", &domain.StoreError{Class: a.class, Err: errors.New("boom")}
}
func (a *authFailingStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	return domain.SnapshotRef{}, nil
}
func (a *authFailingStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	return nil, nil
}
func (a *authFailingStore) Ls(ctx context.Context, repoDir, passfile string, snapID string) ([]domain.TreeEntry, error) {
	return nil, nil
}
func (a *authFailingStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	return nil, nil
}
func (a *authFailingStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	return nil
}
func (a *authFailingStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	return nil
}

// ---- real restic integration (skips when restic is absent) ----

func TestEnrollAndUnlockRealRestic(t *testing.T) {
	bin, err := exec.LookPath("restic")
	if err != nil {
		t.Skipf("restic not on PATH: %v", err)
	}
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	const pw = "real-restic-test-password-1"
	t.Setenv(EnvPassword, pw)

	cfgDir := filepath.Join(t.TempDir(), "cfg")
	repoDir := filepath.Join(t.TempDir(), "vault")
	store := resticstore.New(bin)
	t.Cleanup(store.Close)

	var out strings.Builder
	v, err := Enroll(context.Background(), cfgDir, "main", repoDir, store, &out)
	if err != nil {
		t.Fatal(err)
	}
	if v.RepoID == "" {
		t.Fatal("RepoID must be captured from the real repository")
	}
	// The repository must actually exist on disk.
	if _, err := os.Stat(filepath.Join(repoDir, "config")); err != nil {
		t.Fatalf("restic repository not created: %v", err)
	}
	// Locator written and secret-free.
	locBytes, err := os.ReadFile(filepath.Join(cfgDir, LocatorFile))
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, string(locBytes), pw, "locator")

	// Second enroll on the same directory: clean typed error.
	_, err = Enroll(context.Background(), cfgDir, "again", repoDir, store, &strings.Builder{})
	if !errors.Is(err, ErrRepoDirNotEmpty) {
		t.Fatalf("second enroll must fail cleanly, got %v", err)
	}

	// Unlock with the right password.
	ok, err := Unlock(context.Background(), cfgDir, v.ID, store)
	if !ok || err != nil {
		t.Fatalf("unlock with right password failed: (%v, %v)", ok, err)
	}

	// Unlock with the wrong password: typed rejection.
	t.Setenv(EnvPassword, "definitely-not-the-password")
	ok, err = Unlock(context.Background(), cfgDir, "main", store)
	if ok {
		t.Fatal("wrong password must not report unlocked")
	}
	var rej *UnlockRejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("wrong password must fail typed (real restic), got %T: %v", err, err)
	}
}
