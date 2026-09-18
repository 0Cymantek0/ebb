package resticstore

// copy_test.go — live conformance for the cross-repository copy adapter
// (skips without a restic binary; the argv shape and error classes are
// pinned against lab/restic-probe/copy). The silent-skip gate is the
// load-bearing assertion: `restic copy` of an unknown snapshot id exits
// 0 with an `Ignoring …` stderr line (probe C10), so the adapter must
// convert it into a typed failure — the exporter's destination-side
// List check is the second, independent gate.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/domain"
)

func copyTestStore(t *testing.T) *Store {
	t.Helper()
	path, err := exec.LookPath("restic")
	if err != nil {
		t.Skipf("restic binary not on PATH: %v", err)
	}
	s := New(path)
	t.Cleanup(s.Close)
	return s
}

func TestCopyLiveIgnoringUnknownID(t *testing.T) {
	s := copyTestStore(t)
	base := t.TempDir()
	src, dst := filepath.Join(base, "src"), filepath.Join(base, "dst")
	p1, p2 := filepath.Join(base, "p1"), filepath.Join(base, "p2")
	ws := filepath.Join(base, "ws")
	os.MkdirAll(ws, 0o755)
	os.WriteFile(filepath.Join(ws, "f.txt"), []byte("copy fixture"), 0o600)
	os.WriteFile(p1, []byte("copy-pw-src"), 0o600)
	os.WriteFile(p2, []byte("copy-pw-dst"), 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := s.Init(ctx, src, p1); err != nil {
		t.Fatal(err)
	}
	ref, err := s.Snapshot(ctx, src, ws, []string{"f.txt"}, p1, map[string]string{"ebb-kind": "payload"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(ctx, dst, p2); err != nil {
		t.Fatal(err)
	}

	// The payload copies cleanly into the fresh destination (C1/C8).
	if err := s.Copy(ctx, src, p1, dst, p2, []string{ref.BackendID}); err != nil {
		t.Fatalf("copy of a real snapshot: %v", err)
	}
	refs, err := s.List(ctx, dst, p2)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].Tags["ebb-kind"] != "payload" {
		t.Fatalf("destination holds %+v after copy", refs)
	}

	// An unknown 64-hex id is silently skipped by restic (exit 0): the
	// adapter must fail it typed (source class — the snapshot is absent
	// from the source repository).
	err = s.Copy(ctx, src, p1, dst, p2, []string{strings.Repeat("de", 32)})
	if err == nil {
		t.Fatal("copy of an unknown id returned nil (the Ignoring gate failed)")
	}
	var se *domain.StoreError
	if !asStoreErrT(err, &se) {
		t.Fatalf("err = %v, want StoreError", err)
	}
	if !strings.Contains(err.Error(), "Ignoring") && !strings.Contains(err.Error(), "absent from the source") {
		t.Errorf("error does not name the skipped snapshot: %v", err)
	}

	// Client-side id validation: a "--"-prefixed id never reaches argv.
	err = s.Copy(ctx, src, p1, dst, p2, []string{"--flag-injection"})
	if err == nil || !isUsageT(err) {
		t.Fatalf("hostile id accepted: %v", err)
	}
}

func asStoreErrT(err error, target **domain.StoreError) bool {
	se, ok := err.(*domain.StoreError)
	if ok {
		*target = se
	}
	return ok
}

func isUsageT(err error) bool {
	se, ok := err.(*domain.StoreError)
	return ok && se.Class == domain.StoreErrUsage
}
