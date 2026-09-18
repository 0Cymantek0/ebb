//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// TestProbeFileDoesNotBlockParentRename guards the FindClose fix in
// streams_windows.go: a FindFirstStreamW handle "closed" with
// CloseHandle is NOT actually released — the leaked enumeration handle
// then blocks renaming (and deleting) the probed file's parent
// directory FOREVER. The lifecycle wave caught this live: every park's
// §12.2 quarantine rename failed with Access Denied after the capture
// scan hashed files (measured on Win11 26200; reproducible 4/4 with
// CloseHandle, clean 4/4 with FindClose).
func TestProbeFileDoesNotBlockParentRename(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "a.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New().ProbeFile(file); err != nil {
		t.Fatal(err)
	}
	quar := filepath.Join(filepath.Dir(root), ".quarantine-probe-regression")
	if err := os.Rename(root, quar); err != nil {
		t.Fatalf("renaming the probed file's parent directory failed (leaked stream-enumeration handle?): %v", err)
	}
	if err := os.Rename(quar, root); err != nil {
		t.Fatal(err)
	}
}
