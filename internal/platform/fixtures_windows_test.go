//go:build windows

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// Windows-only fixture builders. Everything is created under
// t.TempDir() and torn down automatically; nothing outside the fixture
// tree is ever mutated.

// runCmd runs a command and returns its combined output and error.
func runCmd(t *testing.T, dir string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// makeJunction creates a junction via `cmd /c mklink /J` (no admin
// privilege needed, probe Q1) pointing at target.
func makeJunction(t *testing.T, dir, name, target string) string {
	t.Helper()
	out, err := runCmd(t, dir, "cmd", "/c", "mklink", "/J", name, target)
	if err != nil {
		t.Skipf("fixture: mklink /J unavailable: %v: %s", err, strings.TrimSpace(out))
	}
	return filepath.Join(dir, name)
}

// addNamedStream attaches a named data stream via cmd redirection
// (`echo secret>file.txt:s1`, probe Q4). Go can do this natively with
// os.WriteFile("file.txt:s1"), but the cmd route is the probed
// ground-truth creator.
func addNamedStream(t *testing.T, file, stream, content string) {
	t.Helper()
	dir, name := filepath.Split(file)
	// cmd's redirection is not quoted; build the exact token ourselves.
	out, err := runCmd(t, dir, "cmd", "/c", "echo "+content+">"+name+":"+stream)
	if err != nil {
		t.Skipf("fixture: stream creation via cmd failed: %v: %s", err, strings.TrimSpace(out))
	}
}

// makeSparseFile creates a file whose logical size is ~10 MiB but whose
// allocation stays small: FSCTL_SET_SPARSE (0x000900C4, unprivileged)
// then a single write at offset 10 MiB (probe Q5).
func makeSparseFile(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "sparse.bin")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("fixture: create sparse file: %v", err)
	}
	defer f.Close()

	h := windows.Handle(f.Fd())
	var returned uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_SPARSE,
		nil, 0, nil, 0, &returned, nil); err != nil {
		t.Skipf("fixture: FSCTL_SET_SPARSE failed on this volume/filesystem: %v", err)
	}
	const offset = int64(10) << 20
	if _, err := f.Seek(offset, 0); err != nil {
		t.Fatalf("fixture: seek: %v", err)
	}
	if _, err := f.Write([]byte{0xAB}); err != nil {
		t.Fatalf("fixture: write at 10 MiB: %v", err)
	}
	return p
}

// makeLongPath builds a >260-char nested directory tree under dir,
// creating each level through the \\?\ extended prefix (probe Q10:
// creation via \\?\, then plain-path access works through Go), and
// returns the PLAIN (un-prefixed) path of a file at the bottom.
func makeLongPath(t *testing.T, dir string) string {
	t.Helper()
	comp := strings.Repeat("d", 60)
	deep := dir // absolute, backslash-separated
	for len(deep) < 300 {
		deep = deep + `\` + comp
		if err := os.Mkdir(`\\?\`+deep, 0o755); err != nil {
			t.Fatalf("fixture: mkdir %s (len %d): %v", deep, len(deep), err)
		}
	}
	file := deep + `\deep.txt`
	if err := os.WriteFile(`\\?\`+file, []byte("deep"), 0o644); err != nil {
		t.Fatalf("fixture: write long file: %v", err)
	}
	return file
}

// findOneDrivePlaceholder scans the machine's OneDrive root(s) with
// metadata-only Lstat (never opens content, so nothing can hydrate;
// probe Q8) and returns the first dehydrated file path, or "" when no
// root or no placeholder exists.
func findOneDrivePlaceholder(t *testing.T) string {
	t.Helper()
	roots := map[string]bool{}
	for _, env := range []string{"OneDrive", "OneDriveCommercial", "OneDriveConsumer"} {
		if v := os.Getenv(env); v != "" {
			roots[v] = true
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		matches, _ := filepath.Glob(filepath.Join(home, "OneDrive*"))
		for _, m := range matches {
			if fi, err := os.Lstat(m); err == nil && fi.IsDir() {
				roots[m] = true
			}
		}
	}
	if len(roots) == 0 {
		return ""
	}
	const recallOnDataAccess = 0x00400000
	var scan func(dirPath string, depth, budget int) string
	scan = func(dirPath string, depth, budget int) string {
		if depth < 0 || budget <= 0 {
			return ""
		}
		des, err := os.ReadDir(dirPath)
		if err != nil {
			return ""
		}
		for _, de := range des {
			if budget <= 0 {
				return ""
			}
			budget--
			p := filepath.Join(dirPath, de.Name())
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok && d.FileAttributes&recallOnDataAccess != 0 {
				return p
			}
			if fi.IsDir() {
				if found := scan(p, depth-1, budget); found != "" {
					return found
				}
			}
		}
		return ""
	}
	for root := range roots {
		if p := scan(root, 2, 60); p != "" {
			return p
		}
	}
	return ""
}

// (fixture helpers only; no additional declarations needed here)
