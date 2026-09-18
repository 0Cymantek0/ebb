package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// Cross-platform fixture builders. Every fixture lives under t.TempDir()
// and is disposable; tests never touch real user directories.

// writeFixtureFile creates dir/name with the given content and returns
// its path.
func writeFixtureFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("fixture: write %s: %v", p, err)
	}
	return p
}

// makeHardlinkPair creates a.txt + b.txt sharing one inode/file-id and
// returns both paths. os.Link is unprivileged on both NTFS (probe Q1)
// and ext4.
func makeHardlinkPair(t *testing.T, dir string) (a, b string) {
	t.Helper()
	a = writeFixtureFile(t, dir, "a.txt", "hardlink pair")
	b = filepath.Join(dir, "b.txt")
	if err := os.Link(a, b); err != nil {
		t.Skipf("fixture: os.Link unavailable on this filesystem: %v", err)
	}
	return a, b
}

// makeSymlink creates a symlink at dir/name pointing at target; it
// skips the test when creation needs a privilege the environment
// lacks (Windows without Developer Mode / admin, probe Q1).
func makeSymlink(t *testing.T, dir, name, target string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Symlink(target, p); err != nil {
		t.Skipf("fixture: os.Symlink requires privilege (Developer Mode/admin) not held here: %v", err)
	}
	return p
}

// makeDir creates and returns a subdirectory path.
func makeDir(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("fixture: mkdir %s: %v", p, err)
	}
	return p
}
