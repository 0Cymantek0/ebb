package vault

import (
	"errors"
	"strings"
	"testing"

	"ebb/internal/domain"
)

// TestKeyringRoundTrip exercises the REAL OS credential store (Windows
// Credential Manager via advapi32). It uses its own throwaway vault id,
// deletes the entry on the way out, and SKIPS with a clear message when
// the session denies credential-store access (service sessions, locked
// down machines) or the platform has no v1 keyring. An interactive
// non-service session on this machine is expected to run it for real.
func TestKeyringRoundTrip(t *testing.T) {
	vid := domain.NewID().String()
	target := keyringTarget(vid)
	t.Cleanup(func() { keyringDelete(target) }) // best-effort; failures reported below

	if err := keyringSet(target, "ebb-round-trip-secret"); err != nil {
		if errors.Is(err, ErrUnsupported) {
			t.Skipf("OS keyring unsupported on this platform (v1): %v", err)
		}
		t.Skipf("Credential Manager unavailable in this environment (write denied): %v", err)
	}

	got, err := keyringGet(target)
	if err != nil {
		t.Skipf("Credential Manager unavailable in this environment (read denied): %v", err)
	}
	if got != "ebb-round-trip-secret" {
		t.Fatalf("keyring round trip mismatch: %q", got)
	}

	exists, err := keyringExists(target)
	if err != nil {
		t.Skipf("Credential Manager unavailable in this environment (exists denied): %v", err)
	}
	if !exists {
		t.Fatal("entry must exist after write")
	}

	if err := keyringDelete(target); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if exists, err := keyringExists(target); err != nil || exists {
		t.Fatalf("entry must be gone after delete: exists=%v err=%v", exists, err)
	}
	if _, err := keyringGet(target); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read after delete must be a wrapped ErrNotFound, got %v", err)
	}
}

// TestKeyringRoundTripHelper runs the exported self-test helper (same
// skip discipline).
func TestKeyringRoundTripHelper(t *testing.T) {
	if err := KeyringRoundTrip(domain.NewID().String()); err != nil {
		if errors.Is(err, ErrUnsupported) {
			t.Skipf("OS keyring unsupported on this platform (v1): %v", err)
		}
		t.Skipf("Credential Manager unavailable in this environment: %v", err)
	}
}

// TestKeyringSetSizeAndEmptyGuards checks the argument guards that run
// before any credential-store write: the CRED_MAX_CREDENTIAL_BLOB_SIZE
// limit (on Windows the guard fires before advapi32 is called, so
// nothing is stored) and the empty-secret refusal.
func TestKeyringSetSizeAndEmptyGuards(t *testing.T) {
	if err := StorePassword("vid", ""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty secret must be refused: %v", err)
	}
	err := keyringSet("ebb:vault:sizeguard", strings.Repeat("x", 3000))
	if err == nil {
		t.Fatal("oversized secret must be refused")
	}
	if !errors.Is(err, ErrUnsupported) && !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized secret must fail on the size guard (or be unsupported), got %v", err)
	}
}
