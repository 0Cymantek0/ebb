package capsule

// passphrase_test.go — the capsule's independent unlock secret: strength
// and shape of generation, and the ephemeral-passfile lifecycle
// (created with exact bytes, removed after use, never empty).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePassphraseShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		pw, err := GeneratePassphrase()
		if err != nil {
			t.Fatalf("GeneratePassphrase: %v", err)
		}
		if len(pw) != 43 { // 32 bytes base64url, no padding
			t.Fatalf("length = %d, want 43", len(pw))
		}
		if strings.ContainsAny(pw, "+/= \t\n\r") {
			t.Fatalf("passphrase %q carries non-url-safe or whitespace bytes", pw)
		}
		if seen[pw] {
			t.Fatalf("passphrase repeated after %d draws", i)
		}
		seen[pw] = true
	}
}

func TestEphemeralPassfileLifecycle(t *testing.T) {
	dir := t.TempDir()
	var path string
	err := ephemeralPassfile(dir, "capsule-secret", func(p string) error {
		path = p
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if string(b) != "capsule-secret" {
			t.Errorf("passfile content %q (want exact bytes, no newline)", string(b))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ephemeralPassfile: %v", err)
	}
	if _, serr := os.Stat(path); !os.IsNotExist(serr) {
		t.Errorf("passfile %s survived (stat err = %v)", path, serr)
	}
	// A failing callback still removes the file and returns the error.
	sentinel := errString("boom")
	if err := ephemeralPassfile(dir, "x", func(p string) error { return sentinel }); err != sentinel {
		t.Errorf("fn error not propagated: %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestEphemeralPassfileRefusesEmpty(t *testing.T) {
	dir := t.TempDir()
	called := false
	if err := ephemeralPassfile(dir, "", func(string) error { called = true; return nil }); err == nil {
		t.Error("empty password accepted")
	}
	if called {
		t.Error("callback ran despite the refusal")
	}
	// The passfile lands inside the caller's directory (the export
	// working dir, so it is removed with it even on a hard crash).
	var got string
	if err := ephemeralPassfile(dir, "pw", func(p string) error { got = filepath.Dir(p); return nil }); err != nil {
		t.Fatal(err)
	}
	if got != dir {
		t.Errorf("passfile created in %s, want %s", got, dir)
	}
}
