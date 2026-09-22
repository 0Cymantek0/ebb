//go:build !windows

package platform

// Minimal non-Windows link-creation coverage: both creators delegate to
// os.Symlink with verbatim target text (the oracle's os.Readlink
// comparison sees the same bytes back).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

func TestCreateLinksRoundTripOther(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "tgt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind domain.EntryKind
		name string
	}{
		{domain.KindSymlink, "sl"},
		{domain.KindJunction, "jl"},
	} {
		p := filepath.Join(dir, tc.name)
		if err := CreateLink(tc.kind, p, target); err != nil {
			t.Fatalf("CreateLink(%s): %v", tc.kind, err)
		}
		got, err := os.Readlink(p)
		if err != nil || got != target {
			t.Fatalf("%s text = %q (%v), want exactly %q", tc.kind, got, err, target)
		}
	}
	if err := CreateLink(domain.KindDir, filepath.Join(dir, "x"), target); err == nil {
		t.Fatal("non-link kinds must be refused")
	}
}
