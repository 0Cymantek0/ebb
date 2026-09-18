package vault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/domain"
)

// stubKeyring replaces the credential-store seam for one test and
// restores it afterwards, keeping every non-keyring test hermetic (the
// real Credential Manager is touched only by TestKeyringRoundTrip).
func stubKeyring(t *testing.T, get func(string) (string, error), set func(string, string) error, del func(string) error) {
	t.Helper()
	oldGet, oldSet, oldDel := keyringGet, keyringSet, keyringDelete
	keyringGet, keyringSet, keyringDelete = get, set, del
	t.Cleanup(func() { keyringGet, keyringSet, keyringDelete = oldGet, oldSet, oldDel })
}

// stubTerminal replaces the terminal seams: whether stdin is a tty and
// what readPassword returns per call. The default readLine
// confirmation answer can be given via confirm.
func stubTerminal(t *testing.T, isTTY bool, confirm string, reads ...string) {
	t.Helper()
	oldTTY, oldRead, oldLine := stdinIsTerminal, readPasswordRaw, readLine
	stdinIsTerminal = func() bool { return isTTY }
	remaining := append([]string(nil), reads...)
	readPasswordRaw = func(fd int) ([]byte, error) {
		if len(remaining) == 0 {
			return nil, errors.New("no scripted password entry left")
		}
		s := remaining[0]
		remaining = remaining[1:]
		return []byte(s), nil
	}
	readLine = func() (string, error) { return confirm, nil }
	t.Cleanup(func() { stdinIsTerminal, readPasswordRaw, readLine = oldTTY, oldRead, oldLine })
}

// unsetEnvPassword neutralizes the env source for one test (an empty
// value is defined to mean unset).
func unsetEnvPassword(t *testing.T) {
	t.Helper()
	t.Setenv(EnvPassword, "")
}

// fakeStore is a domain.SnapshotStore recording what it was asked to
// do. RepoID succeeds only when the passfile holds wantPassword; any
// other password yields an auth-class StoreError like restic's exit 12.
type fakeStore struct {
	wantPassword string
	repoID       string
	inits        []string
	repoIDCalls  int
	// contents of every passfile observed, for exact-bytes assertions
	passfileContents []string
}

func (f *fakeStore) Init(ctx context.Context, dir, passfile string) error {
	b, err := os.ReadFile(passfile)
	if err != nil {
		return err
	}
	f.inits = append(f.inits, dir)
	f.passfileContents = append(f.passfileContents, string(b))
	// Stand in for restic's on-disk footprint so a second enrollment on
	// the same directory observes a non-empty directory, like the real
	// thing.
	return os.WriteFile(filepath.Join(dir, "config"), []byte("fake repo"), 0o600)
}

func (f *fakeStore) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	f.repoIDCalls++
	b, err := os.ReadFile(passfile)
	if err != nil {
		return "", err
	}
	f.passfileContents = append(f.passfileContents, string(b))
	if f.wantPassword != "" && string(b) != f.wantPassword {
		return "", &domain.StoreError{
			Class: domain.StoreErrAuth,
			Err:   errors.New("fakeStore: wrong password"),
		}
	}
	return f.repoID, nil
}

func (f *fakeStore) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	return domain.SnapshotRef{}, errors.New("fakeStore: Snapshot not implemented")
}

func (f *fakeStore) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	return nil, errors.New("fakeStore: List not implemented")
}

func (f *fakeStore) Ls(ctx context.Context, repoDir, passfile string, snapID string) ([]domain.TreeEntry, error) {
	return nil, errors.New("fakeStore: Ls not implemented")
}

func (f *fakeStore) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	return nil, errors.New("fakeStore: DumpFile not implemented")
}

func (f *fakeStore) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	return errors.New("fakeStore: Restore not implemented")
}

func (f *fakeStore) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	return errors.New("fakeStore: Forget not implemented")
}

// assertNoSecret fails the test if needle (a secret) appears in got.
// Used to prove the no-secrets-in-output discipline.
func assertNoSecret(t *testing.T, got, needle, what string) {
	t.Helper()
	if needle != "" && strings.Contains(got, needle) {
		t.Fatalf("%s must not contain the secret %q", what, needle)
	}
}
