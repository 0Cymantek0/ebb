//go:build windows

package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

// PLAT-STREAM-1: the Go mirror of WIN32_FIND_STREAM_DATA must reserve
// the full kernel write capacity (MAX_PATH+36 = 296 wchars); a 255-char
// stream name plus ":$DATA" and NUL is 262 wchars and previously wrote
// past a [257] field.
func TestFindStreamDataNameCapacity(t *testing.T) {
	if unsafe.Sizeof(findStreamData{}.name) < 296*2 {
		t.Fatalf("cStreamName capacity %d bytes < Win32 contract %d bytes",
			unsafe.Sizeof(findStreamData{}.name), 296*2)
	}
}

func TestLongStreamNameSurvivesEnumeration(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("s", 255)
	addNamedStream(t, file, long, "x")
	streams := listNamedStreams(file)
	found := false
	for _, s := range streams {
		if s.Name == long {
			found = true
		}
	}
	if !found {
		t.Fatalf("255-char stream name not enumerated intact: %+v", streams)
	}
}
