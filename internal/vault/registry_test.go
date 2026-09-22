package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

func TestDefaultConfigDir(t *testing.T) {
	dir, err := DefaultConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(filepath.ToSlash(dir), "/ebb") {
		t.Fatalf("config dir must end in /ebb, got %q", dir)
	}
}

func TestEnsureConfigDirCreates(t *testing.T) {
	base := t.TempDir()
	cfg := filepath.Join(base, "ebb")
	got, err := ensureDirAt(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != cfg {
		t.Fatalf("EnsureConfigDir-like creation returned %q, want %q", got, cfg)
	}
	st, err := os.Stat(cfg)
	if err != nil || !st.IsDir() {
		t.Fatalf("config dir not created: %v", err)
	}
}

// ensureDirAt mirrors EnsureConfigDir for an explicit path (the real
// function is anchored at the user config dir, which tests must not
// touch).
func ensureDirAt(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func TestRegistryRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), RegistryFile)
	reg := New(path)

	v1, err := reg.Register("main", `/v/edge/main`, "repo-1")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := reg.Register("archive", `/v/edge/archive`, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []Vault{v1, v2} {
		if _, err := domain.ParseID(v.ID); err != nil {
			t.Fatalf("vault id must be 32-hex domain id, got %q: %v", v.ID, err)
		}
		if _, err := time.Parse(time.RFC3339Nano, v.CreatedAt); err != nil {
			t.Fatalf("CreatedAt must be RFC3339Nano UTC, got %q: %v", v.CreatedAt, err)
		}
	}

	// A fresh instance over the same document must read everything back.
	fresh := New(path)
	got, err := fresh.Get(v1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if *got != v1 {
		t.Fatalf("round trip by id changed the record: %+v vs %+v", *got, v1)
	}
	byName, err := fresh.Get("archive")
	if err != nil {
		t.Fatal(err)
	}
	if *byName != v2 {
		t.Fatalf("round trip by name changed the record: %+v vs %+v", *byName, v2)
	}
	list, err := fresh.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %v, %v; want 2 vaults", list, err)
	}

	// The document must be schema-versioned JSON.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Version int     `json:"version"`
		Vaults  []Vault `json:"vaults"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("registry is not valid JSON: %v", err)
	}
	if raw.Version != 1 || len(raw.Vaults) != 2 {
		t.Fatalf("unexpected document shape: %+v", raw)
	}
}

func TestRegistryGetMiss(t *testing.T) {
	reg := New(filepath.Join(t.TempDir(), RegistryFile))
	if _, err := reg.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown vault must be ErrNotFound, got %v", err)
	}
}

func TestRegistryDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), RegistryFile)
	reg := New(path)
	if _, err := reg.Default(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty registry Default must be ErrNotFound, got %v", err)
	}
	first, err := reg.Register("first", "/v/first", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := reg.Default()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != first.ID {
		t.Fatalf("without a main, Default must be the first registered, got %s", got.ID)
	}
	second, err := reg.Register("main", "/v/main", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err = reg.Default()
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != second.ID {
		t.Fatalf("explicit default-name main must win, got %s", got.ID)
	}
}

func TestRegistryRegisterValidation(t *testing.T) {
	reg := New(filepath.Join(t.TempDir(), RegistryFile))
	if _, err := reg.Register("", "/v/x", ""); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if _, err := reg.Register("x", "", ""); err == nil {
		t.Fatal("empty repoDir must be rejected")
	}
	if _, err := reg.Register("dup", "/v/one", ""); err != nil {
		t.Fatal(err)
	}
	_, err := reg.Register("dup", "/v/two", "")
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate name must be rejected, got %v", err)
	}
}

func TestRegistryHostileDocumentRejected(t *testing.T) {
	cases := map[string]string{
		"future version": `{"version":2,"vaults":[]}`,
		"bad id":         `{"version":1,"vaults":[{"id":"zzz","name":"a","repo_dir":"/v/a","created_at":"2026-01-01T00:00:00Z"}]}`,
		"no name":        `{"version":1,"vaults":[{"id":"0123456789abcdef0123456789abcdef","repo_dir":"/v/a","created_at":"2026-01-01T00:00:00Z"}]}`,
		"no repo_dir":    `{"version":1,"vaults":[{"id":"0123456789abcdef0123456789abcdef","name":"a","created_at":"2026-01-01T00:00:00Z"}]}`,
		"torn json":      `{"version":1,"vaults":[`,
	}
	for name, doc := range cases {
		path := filepath.Join(t.TempDir(), RegistryFile)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := New(path).List(); err == nil {
			t.Fatalf("%s: hostile document must be rejected", name)
		}
	}
}

func TestVaultCatalogArgs(t *testing.T) {
	v := Vault{ID: "0123456789abcdef0123456789abcdef", Name: "main", RepoDir: "/v/main", RepoID: "repo-9", CreatedAt: "2026-01-01T00:00:00Z"}
	a := v.CatalogArgs()
	if string(a.ID) != v.ID || a.Path != v.RepoDir || a.RepoID != v.RepoID || a.Kind != "local" || a.RegisteredAt != v.CreatedAt {
		t.Fatalf("CatalogArgs mapping wrong: %+v", a)
	}
}

// TestRegistryConcurrentWritersNoLostUpdate hammers one Registry from
// two writer goroutines; the in-instance lock plus the atomic rename
// must preserve every registration (approvalstore test shape).
func TestRegistryConcurrentWritersNoLostUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), RegistryFile)
	reg := New(path)

	const perWriter = 25
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				if _, err := reg.Register(writerVaultName(w, i), "/v/x", ""); err != nil {
					t.Errorf("writer %d register %d: %v", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	list, err := reg.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2*perWriter {
		t.Fatalf("lost updates: %d vaults recorded, want %d", len(list), 2*perWriter)
	}
	seen := make(map[string]bool, len(list))
	for _, v := range list {
		if seen[v.Name] {
			t.Fatalf("duplicate vault name %s", v.Name)
		}
		seen[v.Name] = true
	}
}

// TestRegistryConcurrentReadsNeverSeeTornDocument runs a reader that
// re-parses the raw document while writers keep replacing it
// (approvalstore test shape).
func TestRegistryConcurrentReadsNeverSeeTornDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), RegistryFile)
	reg := New(path)
	if _, err := reg.Register("seed", "/v/seed", ""); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil && transientWindowsSharing(err) {
				// An external observer on Windows can momentarily fail
				// to open while a rename transaction is in flight; that
				// is a retry, not a torn document.
				continue
			}
			if err != nil {
				t.Errorf("read document: %v", err)
				return
			}
			var raw map[string]any
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Errorf("torn document observed: %v", err)
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := reg.Register(writerVaultName(w, i), "/v/x", ""); err != nil {
					t.Errorf("writer %d: %v", w, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	readers.Wait()
}

// TestAtomicSaveLeavesNoTempAndKeepsSiblings is the filesystem-authority
// guard: after mutations the directory holds the document plus whatever
// was there before, and no temp artifacts.
func TestAtomicSaveLeavesNoTempAndKeepsSiblings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, RegistryFile)
	decoy := filepath.Join(dir, "decoy.txt")
	if err := os.WriteFile(decoy, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := New(path)
	if _, err := reg.Register("main", "/v/main", "repo-1"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(entries))
	for _, e := range entries {
		names[e.Name()] = true
	}
	if len(entries) != 2 || !names[RegistryFile] || !names["decoy.txt"] {
		t.Fatalf("directory must contain exactly the document and the decoy, got %v", names)
	}
	got, err := os.ReadFile(decoy)
	if err != nil || string(got) != "do not touch" {
		t.Fatalf("decoy sibling was modified: %q, %v", got, err)
	}
}

func writerVaultName(w, i int) string {
	return fmt.Sprintf("vault-%c-%d", rune('a'+w), i)
}

// transientWindowsSharing mirrors the retryable errno set used by the
// package's own sharing tolerance.
func transientWindowsSharing(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == 32 || errno == 5)
}
