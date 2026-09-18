package resticstore

// Prune conformance tests against the real restic binary, pinning the
// behaviors recorded in lab/restic-probe/prune/FINDINGS.md: prune
// reclaims forgotten-only storage while the snapshot set stays
// IDENTICAL, --dry-run mutates nothing but still reports the estimate,
// a repo held by another restic process fails typed (exit 11 → repo
// class, never auto-unlock), and the auth/repo error classes match the
// pinned exit-code table.

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

// lcgBytes returns n deterministic high-entropy bytes (incompressible:
// restic's compression must not shrink the fixture into a size where
// reclaim deltas vanish).
func lcgBytes(n int, seed uint32) []byte {
	out := make([]byte, n)
	next := seed
	for i := range out {
		next = next*1664525 + 1013904223
		out[i] = byte(next >> 23)
	}
	return out
}

// prunableRepo builds a repository with two snapshots sharing one blob
// family and holding one unique family each, then forgets the first —
// exactly the state `ebb forget` leaves behind. Returns the repo, the
// passfile and the surviving snapshot id.
func prunableRepo(t *testing.T, s *Store) (repoDir, passfile, survivorID string) {
	t.Helper()
	repoDir, passfile = newRepo(t, s)
	parent := t.TempDir()
	ws := filepath.Join(parent, "ws")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "shared.bin"), lcgBytes(300_000, 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "unique-a.bin"), lcgBytes(300_000, 2), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	refA, err := s.Snapshot(ctx, repoDir, parent, []string{"ws/shared.bin", "ws/unique-a.bin"}, passfile, nil)
	if err != nil {
		t.Fatalf("snapshot A: %v", err)
	}
	if err := os.Remove(filepath.Join(ws, "unique-a.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "unique-b.bin"), lcgBytes(300_000, 3), 0o644); err != nil {
		t.Fatal(err)
	}
	refB, err := s.Snapshot(ctx, repoDir, parent, []string{"ws/shared.bin", "ws/unique-b.bin"}, passfile, nil)
	if err != nil {
		t.Fatalf("snapshot B: %v", err)
	}
	if err := s.Forget(ctx, repoDir, passfile, []string{refA.BackendID}); err != nil {
		t.Fatalf("forget A: %v", err)
	}
	return repoDir, passfile, refB.BackendID
}

// walkedSize sums regular-file sizes under dir (the test-side oracle
// for "the repository physically shrank").
func walkedSize(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			fi, ierr := d.Info()
			if ierr == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return total
}

func TestPruneReclaimsForgottenDataAndKeepsSnapshots(t *testing.T) {
	s := newStore(t)
	repoDir, passfile, survivor := prunableRepo(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	before, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("list before: %v", err)
	}
	sizeBefore := walkedSize(t, repoDir)

	stats, err := s.Prune(ctx, repoDir, passfile, domain.PruneOptions{})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if stats.DryRun {
		t.Error("stats must not claim dry-run for a real prune")
	}
	// The backend's own estimate must be reported (probe: the
	// "total prune" summary line) — with ~300 KiB of A-only blobs it is
	// comfortably above zero.
	if stats.ReclaimableBytes <= 0 {
		t.Errorf("ReclaimableBytes = %d, want > 0 (estimate not parsed)", stats.ReclaimableBytes)
	}

	after, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("list after: %v", err)
	}
	if len(after) != len(before) || after[0].BackendID != survivor {
		t.Fatalf("prune changed the snapshot set: before=%v after=%v", before, after)
	}
	sizeAfter := walkedSize(t, repoDir)
	if sizeAfter >= sizeBefore {
		t.Errorf("repository did not physically shrink: before=%d after=%d", sizeBefore, sizeAfter)
	}
	t.Logf("prune freed %d bytes (walk), backend estimate %d", sizeBefore-sizeAfter, stats.ReclaimableBytes)

	// A second prune on the now-clean repo is an honest no-op (exit 0,
	// zero estimate, still verified).
	stats2, err := s.Prune(ctx, repoDir, passfile, domain.PruneOptions{})
	if err != nil {
		t.Fatalf("clean re-prune: %v", err)
	}
	if stats2.ReclaimableBytes != 0 {
		t.Errorf("clean re-prune estimate = %d, want 0", stats2.ReclaimableBytes)
	}
}

func TestPruneDryRunMutatesNothing(t *testing.T) {
	s := newStore(t)
	repoDir, passfile, survivor := prunableRepo(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	before, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("list before: %v", err)
	}
	sizeBefore := walkedSize(t, repoDir)

	stats, err := s.Prune(ctx, repoDir, passfile, domain.PruneOptions{DryRun: true})
	if err != nil {
		t.Fatalf("Prune --dry-run: %v", err)
	}
	if !stats.DryRun {
		t.Error("stats must report DryRun")
	}
	if stats.ReclaimableBytes <= 0 {
		t.Errorf("ReclaimableBytes = %d, want > 0 (dry-run summary must parse)", stats.ReclaimableBytes)
	}
	// Probe-pinned: a dry run mutates nothing — byte-exact walk equality.
	if got := walkedSize(t, repoDir); got != sizeBefore {
		t.Errorf("dry-run changed the repository: before=%d after=%d", sizeBefore, got)
	}
	after, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		t.Fatalf("list after: %v", err)
	}
	if len(after) != len(before) || after[0].BackendID != survivor {
		t.Fatalf("dry-run changed the snapshot set: %v", after)
	}

	// The real prune still has the same estimate available afterwards
	// (nothing was consumed by the dry run).
	real, err := s.Prune(ctx, repoDir, passfile, domain.PruneOptions{})
	if err != nil {
		t.Fatalf("real prune after dry-run: %v", err)
	}
	if real.ReclaimableBytes <= 0 {
		t.Errorf("post-dry-run real prune estimate = %d, want > 0", real.ReclaimableBytes)
	}
}

// TestPruneEmptyRepoIsCleanNoop pins the empty-repo shape (probe P5):
// zero snapshots, exit 0, zero estimate — gc's no-op case rides on
// prune never failing just because nothing exists.
func TestPruneEmptyRepoIsCleanNoop(t *testing.T) {
	s := newStore(t)
	repoDir, passfile := newRepo(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	stats, err := s.Prune(ctx, repoDir, passfile, domain.PruneOptions{})
	if err != nil {
		t.Fatalf("prune on empty repo: %v", err)
	}
	if stats.ReclaimableBytes != 0 {
		t.Errorf("empty-repo estimate = %d, want 0", stats.ReclaimableBytes)
	}
}

// TestPruneLockedRepoTyped pins the lock behavior with a REAL second
// restic process holding the repository (backup --stdin with an open
// stdin pipe holds a shared lock; prune needs exclusive). The failure
// must be typed repo-class with the never-unlock note — never a silent
// skip, never an auto-unlock.
func TestPruneLockedRepoTyped(t *testing.T) {
	s := newStore(t)
	repoDir, passfile, _ := prunableRepo(t, s)

	cache := t.TempDir()
	holder := exec.Command(s.binary, "--repo", repoDir, "backup", "--stdin", "--host", "ebb")
	holder.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"SYSTEMROOT=" + os.Getenv("SYSTEMROOT"),
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
		"RESTIC_PASSWORD_FILE=" + passfile,
		"RESTIC_CACHE_DIR=" + cache,
	}
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := holder.Start(); err != nil {
		t.Fatalf("start lock holder: %v", err)
	}
	// Wait until restic has actually taken the lock.
	deadline := time.Now().Add(30 * time.Second)
	locked := false
	for time.Now().Before(deadline) {
		if ents, lerr := os.ReadDir(filepath.Join(repoDir, "locks")); lerr == nil && len(ents) > 0 {
			locked = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !locked {
		t.Fatal("lock holder never created a lock file")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err = s.Prune(ctx, repoDir, passfile, domain.PruneOptions{})
	if err == nil {
		t.Fatal("prune against a locked repository must fail")
	}
	if c := errClass(t, err); c != domain.StoreErrRepo {
		t.Fatalf("locked-repo class = %q want repo (%v)", c, err)
	}
	if want := "repository is locked by another process"; !strings.Contains(err.Error(), want) {
		t.Errorf("error lacks the lock note %q: %v", want, err)
	}

	// Release: closing stdin ends the holder backup.
	_ = stdin.Close()
	done := make(chan error, 1)
	go func() { done <- holder.Wait() }()
	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatal("lock holder did not exit after stdin close")
	}

	// With the holder gone, the same prune succeeds (no stale lock).
	if _, perr := s.Prune(ctx, repoDir, passfile, domain.PruneOptions{}); perr != nil {
		t.Fatalf("prune after lock release: %v", perr)
	}
}

func TestPruneErrorClasses(t *testing.T) {
	s := newStore(t)
	repoDir, passfile, _ := prunableRepo(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Wrong password: exit 12 → auth (probe P7a).
	badPW := filepath.Join(t.TempDir(), "bad")
	if err := os.WriteFile(badPW, []byte("definitely-wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prune(ctx, repoDir, badPW, domain.PruneOptions{DryRun: true}); err == nil {
		t.Fatal("wrong password must fail")
	} else if c := errClass(t, err); c != domain.StoreErrAuth {
		t.Fatalf("wrong password class = %q want auth (%v)", c, err)
	}

	// Missing repository: exit 10 → repo (probe P7b).
	if _, err := s.Prune(ctx, filepath.Join(t.TempDir(), "no-repo"), passfile, domain.PruneOptions{DryRun: true}); err == nil {
		t.Fatal("missing repo must fail")
	} else if c := errClass(t, err); c != domain.StoreErrRepo {
		t.Fatalf("missing repo class = %q want repo (%v)", c, err)
	}
}
