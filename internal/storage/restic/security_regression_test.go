package resticstore

import (
	"context"
	"strings"
	"testing"
)

// RESTIC-TAG-1: the empty tag key must be rejected (the error text
// always claimed it was).
func TestEncodeTagsRejectsEmptyKey(t *testing.T) {
	if _, _, err := encodeTags(map[string]string{"": "x"}); err == nil {
		t.Fatal("empty tag key accepted")
	}
}

// RESTIC-SNAP-1: Ls/DumpFile/Restore must gate snapshot ids exactly
// like Forget so a "--"-prefixed id can never become a restic flag.
// The gate fires before any subprocess, so no restic binary is needed.
func TestSnapshotIdGateOnAllReadPaths(t *testing.T) {
	s := New("restic")
	ctx := context.Background()
	bad := "--verify-data"
	if _, err := s.Ls(ctx, "repo", "pass", bad); err == nil ||
		!strings.Contains(err.Error(), "not 8-64 hex") {
		t.Fatalf("Ls: want id gate error, got %v", err)
	}
	if _, err := s.DumpFile(ctx, "repo", "pass", bad, "/x"); err == nil ||
		!strings.Contains(err.Error(), "not 8-64 hex") {
		t.Fatalf("DumpFile: want id gate error, got %v", err)
	}
	if err := s.Restore(ctx, "repo", "pass", bad, "", t.TempDir()); err == nil ||
		!strings.Contains(err.Error(), "not 8-64 hex") {
		t.Fatalf("Restore: want id gate error, got %v", err)
	}
}
