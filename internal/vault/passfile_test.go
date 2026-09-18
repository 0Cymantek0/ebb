package vault

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWithPassfileLifecycle(t *testing.T) {
	// Keep the keyring stubbed so this test never consults the real
	// credential store even if the env var disappears.
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "pw-123-exact")

	var observed string
	var stat os.FileInfo
	err := WithPassfile("vid", func(path string) error {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("passfile must exist during fn: %v", err)
		}
		observed = string(b)
		stat, err = os.Stat(path)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed != "pw-123-exact" {
		t.Fatalf("passfile must hold the EXACT password with no newline, got %q", observed)
	}
	if runtime.GOOS != "windows" {
		// 0600 is a POSIX mode; on Windows the %TEMP% user ACL governs.
		if perm := stat.Mode().Perm(); perm != 0o600 {
			t.Fatalf("passfile mode must be 0600, got %o", perm)
		}
	}
	// Directory-scan proof of removal (not just stat: the name is
	// random so a stat miss would prove it, but scanning is stricter).
	leftovers := 0
	entries, err2 := os.ReadDir(os.TempDir())
	if err2 == nil {
		for _, e := range entries {
			if len(e.Name()) > len("ebb-vault-pass-") && e.Name()[:len("ebb-vault-pass-")] == "ebb-vault-pass-" {
				leftovers++
			}
		}
	}
	if leftovers != 0 {
		t.Fatalf("%d ebb passfiles left in temp dir", leftovers)
	}
}

func TestWithPassfileFnErrorStillCleansUp(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "pw")
	sentinel := errors.New("fn failed")
	var seen string
	err := WithPassfile("vid", func(path string) error {
		seen = path
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("fn's error must be returned unchanged, got %v", err)
	}
	if _, serr := os.Stat(seen); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("passfile must be removed after fn error, stat: %v", serr)
	}
}

func TestWithPassfileNoSource(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	stubTerminal(t, false, "")
	if err := WithPassfile("vid", func(string) error { return nil }); err == nil {
		t.Fatal("no credential source must fail WithPassfile before any file is created")
	}
}

// TestWithPassfileCleanupFailureSurfaces proves the "never leave
// silently" half of the §13.1 contract. Injection: fn replaces the
// passfile with a non-empty directory, which no delete API accepts —
// a realistic "something is holding/blocking the name" failure that
// works identically on Windows and POSIX.
func TestWithPassfileCleanupFailureSurfaces(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "pw")
	var seen string
	err := WithPassfile("vid", func(path string) error {
		seen = path
		if rerr := os.Remove(path); rerr != nil {
			t.Fatalf("inject: remove passfile: %v", rerr)
		}
		if merr := os.Mkdir(path, 0o700); merr != nil {
			t.Fatalf("inject: mkdir over name: %v", merr)
		}
		if werr := os.WriteFile(filepath.Join(path, "blocker"), []byte("x"), 0o600); werr != nil {
			t.Fatalf("inject: blocker: %v", werr)
		}
		return nil
	})
	t.Cleanup(func() {
		if seen != "" {
			os.RemoveAll(filepath.Join(seen, "blocker"))
			os.Remove(seen)
		}
	})
	var pce *PassfileCleanupError
	if !errors.As(err, &pce) {
		t.Fatalf("removal failure must surface as *PassfileCleanupError, got %T: %v", err, err)
	}
	if pce.Path != seen {
		t.Fatalf("cleanup error must name the leftover path, got %q", pce.Path)
	}
	if _, serr := os.Stat(filepath.Join(seen, "blocker")); serr != nil {
		t.Fatalf("injected leftover must still exist for the cleanup: %v", serr)
	}
}
