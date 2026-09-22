package vault

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/term"
)

func TestKeyringTargetName(t *testing.T) {
	if got := keyringTarget("0123456789abcdef0123456789abcdef"); got != "ebb:vault:0123456789abcdef0123456789abcdef" {
		t.Fatalf("target name %q", got)
	}
}

func TestPasswordEnvWins(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "keyring-pw", nil },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "env-pw")
	pw, src, err := Password("vid")
	if err != nil || pw != "env-pw" || src != SourceEnv {
		t.Fatalf("env must win: got (%q, %q, %v)", pw, src, err)
	}
}

func TestPasswordEnvEmptyMeansUnset(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "keyring-pw", nil },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "")
	pw, src, err := Password("vid")
	if err != nil || pw != "keyring-pw" || src != SourceOSKeyring {
		t.Fatalf("empty env must fall through to keyring: got (%q, %q, %v)", pw, src, err)
	}
}

func TestPasswordKeyringMissingFallsToPrompt(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", errors.Join(ErrNotFound, errors.New("no entry")) },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	stubTerminal(t, true, "", "typed-pw")
	pw, src, err := Password("vid")
	if err != nil || pw != "typed-pw" || src != SourcePrompt {
		t.Fatalf("missing keyring entry must fall to prompt: got (%q, %q, %v)", pw, src, err)
	}
}

func TestPasswordKeyringUnsupportedFallsToPrompt(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrUnsupported },
		func(string, string) error { return ErrUnsupported },
		func(string) error { return ErrUnsupported },
	)
	unsetEnvPassword(t)
	stubTerminal(t, true, "", "typed-pw")
	pw, src, err := Password("vid")
	if err != nil || pw != "typed-pw" || src != SourcePrompt {
		t.Fatalf("unsupported keyring must fall to prompt: got (%q, %q, %v)", pw, src, err)
	}
}

// TestPasswordPromptSkippedWhenNotTTY covers the CI/test reality: with
// a pipe on stdin (go test), no source may fall back to reading a
// password interactively — the result is a typed NoSourceError, not a
// hang and not a guess.
func TestPasswordPromptSkippedWhenNotTTY(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	stubTerminal(t, false, "")
	pw, src, err := Password("vid")
	if err == nil {
		t.Fatalf("no source must error, got (%q, %q)", pw, src)
	}
	var nse *NoSourceError
	if !errors.As(err, &nse) {
		t.Fatalf("error must be *NoSourceError, got %T: %v", err, err)
	}
	if nse.VaultID != "vid" || !strings.Contains(nse.Error(), "stdin is not a terminal") {
		t.Fatalf("NoSourceError must name the vault and the reason: %+v", nse)
	}
}

// TestPasswordPromptSkippedOnRealNonTtyStdin exercises the REAL tty
// detection (no stub): under `go test` stdin is a pipe or /dev/null,
// never a terminal, so the prompt path must be skipped and the chain
// must end in NoSourceError instead of blocking on a read. If someone
// ever runs the test binary with a real terminal on fd 0, skip rather
// than hang.
func TestPasswordPromptSkippedOnRealNonTtyStdin(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a real terminal; pipe behavior cannot be observed")
	}
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	_, _, err := Password("vid")
	var nse *NoSourceError
	if !errors.As(err, &nse) {
		t.Fatalf("real piped stdin must yield *NoSourceError, got %T: %v", err, err)
	}
}

func TestPasswordKeyringFailureSurfaces(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", errors.New("keyring boom") },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	stubTerminal(t, true, "", "should-not-be-reached")
	_, _, err := Password("vid")
	if err == nil || !strings.Contains(err.Error(), "keyring boom") {
		t.Fatalf("a broken keyring must surface its error, got %v", err)
	}
}

// ---- PasswordNonInteractive (wave-4 K3: request handlers must never
// block on the terminal prompt rung) --------------------------------------

// TestPasswordNonInteractiveEnvWins: the env source resolves first,
// source "env", no error.
func TestPasswordNonInteractiveEnvWins(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "keyring-pw", nil },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "env-pw")
	pw, src, err := PasswordNonInteractive("vid")
	if err != nil || pw != "env-pw" || src != SourceEnv {
		t.Fatalf("env must win: got (%q, %q, %v)", pw, src, err)
	}
}

// TestPasswordNonInteractiveKeyring: with the env source unset, a
// present keyring entry resolves with source "os-keyring".
func TestPasswordNonInteractiveKeyring(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "keyring-pw", nil },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	pw, src, err := PasswordNonInteractive("vid")
	if err != nil || pw != "keyring-pw" || src != SourceOSKeyring {
		t.Fatalf("keyring entry must resolve: got (%q, %q, %v)", pw, src, err)
	}
}

// TestPasswordNonInteractiveNoSource: with neither source supplying a
// secret, the result is *NoSourceError naming the vault and explaining
// that the interactive prompt is unavailable for background reads —
// never a guess, never a block.
func TestPasswordNonInteractiveNoSource(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	stubTerminal(t, false, "")
	pw, src, err := PasswordNonInteractive("vid")
	if err == nil {
		t.Fatalf("no source must error, got (%q, %q)", pw, src)
	}
	var nse *NoSourceError
	if !errors.As(err, &nse) {
		t.Fatalf("error must be *NoSourceError, got %T: %v", err, err)
	}
	if nse.VaultID != "vid" {
		t.Fatalf("NoSourceError must name the vault, got %+v", nse)
	}
	if !strings.Contains(nse.Error(), "unavailable for background reads") {
		t.Fatalf("NoSourceError must explain the background-reads reason: %s", nse.Error())
	}
}

// TestPasswordNonInteractiveRefusesEvenOnTTY is the STRUCTURAL K3 pin:
// with stdin REPORTED as a terminal and a scripted read available, the
// non-interactive chain must still refuse with *NoSourceError rather
// than consume the prompt rung — the rung is absent from this chain,
// not merely skipped because stdin happened to be a pipe.
func TestPasswordNonInteractiveRefusesEvenOnTTY(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", errors.Join(ErrNotFound, errors.New("no entry")) },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	// A promptable terminal with a ready password line: reaching the
	// prompt rung would return ("typed-pw", SourcePrompt, nil).
	stubTerminal(t, true, "", "typed-pw")
	pw, src, err := PasswordNonInteractive("vid")
	var nse *NoSourceError
	if !errors.As(err, &nse) {
		t.Fatalf("must refuse even on a TTY, got (%q, %q, %T: %v)", pw, src, err, err)
	}
	if pw != "" || src != "" {
		t.Fatalf("a refusal must carry no partial credential: (%q, %q)", pw, src)
	}
}

// TestPasswordNonInteractiveKeyringUnsupportedIsNoSource: an
// unsupported keyring platform is a missing rung, not a failure — the
// chain ends in NoSourceError.
func TestPasswordNonInteractiveKeyringUnsupportedIsNoSource(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrUnsupported },
		func(string, string) error { return ErrUnsupported },
		func(string) error { return ErrUnsupported },
	)
	unsetEnvPassword(t)
	stubTerminal(t, true, "", "typed-pw")
	_, _, err := PasswordNonInteractive("vid")
	var nse *NoSourceError
	if !errors.As(err, &nse) {
		t.Fatalf("unsupported keyring must end in NoSourceError, got %T: %v", err, err)
	}
}

// TestPasswordNonInteractiveKeyringFailureSurfaces: a keyring hard
// failure (not a missing entry) propagates, exactly like Password.
func TestPasswordNonInteractiveKeyringFailureSurfaces(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", errors.New("keyring boom") },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	stubTerminal(t, true, "", "should-not-be-reached")
	_, _, err := PasswordNonInteractive("vid")
	if err == nil || !strings.Contains(err.Error(), "keyring boom") {
		t.Fatalf("a broken keyring must surface its error, got %v", err)
	}
	var nse *NoSourceError
	if errors.As(err, &nse) {
		t.Fatalf("a hard keyring failure is not a no-source refusal: %v", err)
	}
}

// TestWithPassfileNonInteractiveLifecycle: the passfile variant of the
// happy path — fn sees the exact env password bytes, and the file is
// removed afterwards (same §13.1 contract as WithPassfile).
func TestWithPassfileNonInteractiveLifecycle(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	t.Setenv(EnvPassword, "pw-123-exact")
	var observed, mine string
	err := WithPassfileNonInteractive("vid", func(path string) error {
		mine = path
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("passfile must exist during fn: %v", err)
		}
		observed = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if observed != "pw-123-exact" {
		t.Fatalf("passfile must hold the EXACT password, got %q", observed)
	}
	if _, serr := os.Stat(mine); !os.IsNotExist(serr) {
		t.Fatalf("passfile %s must be removed after fn, stat: %v", mine, serr)
	}
}

// TestWithPassfileNonInteractiveNoSource: with no non-interactive
// source, the *NoSourceError surfaces and fn never runs.
func TestWithPassfileNonInteractiveNoSource(t *testing.T) {
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(string, string) error { return nil },
		func(string) error { return nil },
	)
	unsetEnvPassword(t)
	stubTerminal(t, true, "", "typed-pw") // even a promptable TTY must not save it
	ran := false
	err := WithPassfileNonInteractive("vid", func(path string) error {
		ran = true
		return nil
	})
	var nse *NoSourceError
	if !errors.As(err, &nse) {
		t.Fatalf("must surface *NoSourceError, got %T: %v", err, err)
	}
	if ran {
		t.Fatal("fn must not run when no credential source is available")
	}
}

func TestPromptNewPasswordDoubleEntry(t *testing.T) {
	stubTerminal(t, true, "", "alpha", "alpha")
	got, err := PromptNewPassword()
	if err != nil || got != "alpha" {
		t.Fatalf("matching double entry must succeed: (%q, %v)", got, err)
	}
	stubTerminal(t, true, "", "alpha", "beta")
	if _, err := PromptNewPassword(); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched double entry must fail, got %v", err)
	}
}

func TestStoreAndForgetPassword(t *testing.T) {
	var setTarget, setSecret string
	var delTarget string
	stubKeyring(t,
		func(string) (string, error) { return "", ErrNotFound },
		func(target, secret string) error { setTarget, setSecret = target, secret; return nil },
		func(target string) error { delTarget = target; return nil },
	)
	if err := StorePassword("vid", "sekrit"); err != nil {
		t.Fatal(err)
	}
	if setTarget != "ebb:vault:vid" || setSecret != "sekrit" {
		t.Fatalf("StorePassword wrote (%q, %q)", setTarget, setSecret)
	}
	if err := StorePassword("vid", ""); err == nil {
		t.Fatal("empty password must be refused")
	}
	if err := ForgetPassword("vid"); err != nil {
		t.Fatal(err)
	}
	if delTarget != "ebb:vault:vid" {
		t.Fatalf("ForgetPassword deleted %q", delTarget)
	}
}
