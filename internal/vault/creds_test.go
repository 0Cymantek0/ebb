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
