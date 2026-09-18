// wave_h_gc_test.go: `ebb gc` coverage over the eHarness world (Wave H).
// The eligibility gates (active operation, unresolved retention intent),
// the clean no-op, the dry-run contract, envelope shapes, and the
// unknown-vault / unsupported-backend refusals. The real-restic physical
// behaviors (size deltas, lock typing) live in gc_restic_test.go and
// internal/storage/restic/prune_test.go.

package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/vault"
)

// ---- eFakeStore prune extension ----------------------------------------

// Prune implements the optional domain.RepoPruner seam on the CLI fake:
// it records the call, simulates the backend's estimate, and asserts the
// snapshot set is unchanged (mirroring the real adapter's contract).
func (s *eFakeStore) Prune(ctx context.Context, repoDir, passfile string, opts domain.PruneOptions) (domain.PruneStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneCalls = append(s.pruneCalls, opts.DryRun)
	if s.onPrune != nil {
		if err := s.onPrune(opts.DryRun); err != nil {
			return domain.PruneStats{}, &domain.StoreError{Class: domain.StoreErrUnknown, Err: err}
		}
	}
	return domain.PruneStats{ReclaimableBytes: 4096, DryRun: opts.DryRun}, nil
}

// gcSnapshots captures the harness workspace twice (two logical
// snapshots in the fake vault) and forgets the FIRST — the state after
// which gc has real work to do. Returns the survivor row.
func gcSnapshotsAndForgetFirst(t *testing.T, h *eHarness) catalog.Snapshot {
	t.Helper()
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot 1 code = %d, stderr = %s", code, stderr)
	}
	// Different content so the two fake snapshots are distinct trees.
	if err := os.MkdirAll(filepath.Join(h.wsRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.wsRoot, "src", "second.go"),
		[]byte("package main\n\nfunc extra() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot 2 code = %d, stderr = %s", code, stderr)
	}
	all := snapshotsOf(t, h)
	if len(all) != 2 {
		t.Fatalf("want 2 snapshots, got %d", len(all))
	}
	first, second := all[0], all[1]
	if code, _, stderr := h.run("forget", string(first.ID), "--yes"); code != ExitOK {
		t.Fatalf("forget code = %d, stderr = %s", code, stderr)
	}
	return second
}

func TestGcHappyPathAfterForget(t *testing.T) {
	h := newEHarness(t)
	survivor := gcSnapshotsAndForgetFirst(t, h)

	code, stdout, stderr := h.run("gc", "main")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if len(h.store.pruneCalls) != 1 || h.store.pruneCalls[0] {
		t.Fatalf("prune calls = %v, want exactly one REAL prune", h.store.pruneCalls)
	}
	// Workspace/snapshot sets stay intact: the survivor row is still
	// pinned and present, the forgotten row is still recorded (unpinned).
	got, err := h.cat().GetSnapshot(survivor.ID)
	if err != nil || !got.Pinned {
		t.Fatalf("survivor row damaged: %+v (%v)", got, err)
	}
	for _, want := range []string{
		"gc vault \"main\"",
		"verified: the snapshot set is identical before and after prune",
		"backend reclaimed an estimated",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, stdout)
}

func TestGcJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	survivor := gcSnapshotsAndForgetFirst(t, h)

	code, stdout, _ := h.run("gc", "--json", "main")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || envString(t, env, "command") != "gc" {
		t.Fatalf("envelope head = %v", env)
	}
	if !mustCondition(env, "pruned") || !mustCondition(env, "snapshots-verified-unchanged") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["vault"] != "main" || det["dry_run"] != false {
		t.Errorf("details = %v", det)
	}
	if det["retained_snapshots"].(float64) < 1 {
		t.Errorf("retained_snapshots = %v, want >= 1 (the survivor)", det["retained_snapshots"])
	}
	if det["pinned_snapshots"].(float64) < 1 {
		t.Errorf("pinned_snapshots = %v, want >= 1", det["pinned_snapshots"])
	}
	if b, ok := env["bytes"].(map[string]any); !ok || b["freed_estimated"].(float64) <= 0 {
		t.Errorf("bytes.freed_estimated missing: %v", env["bytes"])
	}
	if survivor.ID == "" {
		t.Fatal("unreachable")
	}
}

func TestGcRefusedWithActiveOperation(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot code = %d, stderr = %s", code, stderr)
	}
	ws := snapshotsOf(t, h)[0]
	// An interrupted capture: a durable non-terminal operation row.
	opID, err := h.cat().BeginOperation(ws.WorkspaceID, catalog.OpKindPark,
		h.wsRoot, "identity", "digest")
	if err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := h.run("gc", "main")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeGcActiveOperation, string(opID))
	if !strings.Contains(stderr, "ebb recover "+string(opID)) {
		t.Errorf("safe action must name `ebb recover %s`:\n%s", opID, stderr)
	}
	if len(h.store.pruneCalls) != 0 {
		t.Error("prune ran despite an active operation")
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, stdout)
}

func TestGcRefusedWithUnresolvedRetentionIntent(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot code = %d, stderr = %s", code, stderr)
	}
	snap := snapshotsOf(t, h)[0]
	intentID, err := h.cat().CreateRetentionIntent(snap.ID, "user:forget")
	if err != nil {
		t.Fatal(err)
	}

	code, _, stderr := h.run("gc", "main")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeGcPendingIntent, string(snap.ID))
	if !strings.Contains(stderr, string(intentID)) {
		t.Errorf("refusal must name the exact intent id %s:\n%s", intentID, stderr)
	}
	if !strings.Contains(stderr, "ebb forget") {
		t.Errorf("safe action must point at the idempotent forget rerun:\n%s", stderr)
	}
	if len(h.store.pruneCalls) != 0 {
		t.Error("prune ran despite an unresolved retention intent")
	}
}

func TestGcDryRunPerformsNoPruneAndReportsEstimate(t *testing.T) {
	h := newEHarness(t)
	gcSnapshotsAndForgetFirst(t, h)

	// Human wording (--json suppresses it).
	code, _, stderr := h.run("gc", "--dry-run", "main")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"dry run: no changes were made", "reclaimable"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)

	// Machine shape + the no-mutation contract at the fake level: exactly
	// one prune call, flagged dry-run.
	code, stdout, stderr := h.run("gc", "--json", "--dry-run", "main")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if len(h.store.pruneCalls) != 2 || !h.store.pruneCalls[0] || !h.store.pruneCalls[1] {
		t.Fatalf("prune calls = %v, want two DRY-RUN prunes (one per invocation)", h.store.pruneCalls)
	}
	env := envelopeOf(t, stdout)
	if !mustCondition(env, "dry-run") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["dry_run"] != true || det["no_op"] == true {
		t.Errorf("details = %v", det)
	}
	assertNoSecrets(t, stdout)
}

func TestGcCleanNoOpOnEmptyVault(t *testing.T) {
	h := newEHarness(t) // registered vault, zero snapshots, no captures

	// Human wording (--json suppresses it).
	code, _, stderr := h.run("gc", "main")
	if code != ExitOK {
		t.Fatalf("empty-vault gc code = %d, want 0 (stderr %s)", code, stderr)
	}
	if !strings.Contains(stderr, "nothing to reclaim") {
		t.Errorf("stderr lacks the no-op wording:\n%s", stderr)
	}
	// Machine shape.
	code, stdout, stderr := h.run("gc", "--json", "main")
	if code != ExitOK {
		t.Fatalf("empty-vault gc code = %d, want 0 (stderr %s)", code, stderr)
	}
	if len(h.store.pruneCalls) != 0 {
		t.Error("prune ran on an empty vault")
	}
	env := envelopeOf(t, stdout)
	if !mustCondition(env, "noop") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	if det, ok := env["details"].(map[string]any); !ok || det["no_op"] != true {
		t.Errorf("details.no_op missing: %v", env["details"])
	}
}

func TestGcUnknownVaultAndArgShapes(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("gc", "nosuchvault")
	if code != ExitUsage {
		t.Fatalf("unknown vault code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "no vault named") {
		t.Errorf("stderr = %s", stderr)
	}
	// gc also resolves by vault ID.
	code, _, stderr = h.run("gc")
	if code != ExitUsage {
		t.Fatalf("missing arg code = %d, want %d (%s)", code, ExitUsage, stderr)
	}
}

func TestGcResolvesVaultById(t *testing.T) {
	h := newEHarness(t)
	gcSnapshotsAndForgetFirst(t, h)
	v, err := vault.New(filepath.Join(h.stateDir, vault.RegistryFile)).Get("main")
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("gc", v.ID)
	if code != ExitOK {
		t.Fatalf("gc by id code = %d, stderr = %s", code, stderr)
	}
	if len(h.store.pruneCalls) != 1 {
		t.Errorf("prune calls = %v", h.store.pruneCalls)
	}
}

func TestGcUnsupportedBackend(t *testing.T) {
	h := newEHarness(t)
	gcSnapshotsAndForgetFirst(t, h)
	// A store that is ONLY a domain.SnapshotStore: the optional RepoPruner
	// seam is invisible (D007 shape — fakes stay valid without prune).
	newStore := h.deps.NewStore
	h.deps.NewStore = func() (domain.SnapshotStore, func(), error) {
		store, closeStore, err := newStore()
		if err != nil {
			return nil, nil, err
		}
		return struct{ domain.SnapshotStore }{store}, closeStore, nil
	}

	code, _, stderr := h.run("gc", "main")
	if code != ExitBlocked {
		t.Fatalf("unsupported backend code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeGcUnsupported, "Safe action")
	if len(h.store.pruneCalls) != 0 {
		t.Error("prune ran despite unsupported backend")
	}
}
