// cmd_delete_test.go: `ebb delete` coverage over the eHarness world —
// the composed forget+prune flow against the fake vault, the guards
// (last-recovery-copy, active operation, confirmation), the --dry-run
// no-mutation contract, the prune-skip-with-warning paths for OTHER
// workspaces' state, and the idempotent rerun.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// deleteSecondWorkspace captures a SECOND workspace (own Ebbfile, own
// name) and returns its sealed snapshot row — the "other workspace"
// for prune-eligibility tests.
func deleteSecondWorkspaceSnapshot(t *testing.T, h *eHarness) catalog.Snapshot {
	t.Helper()
	root := filepath.Join(filepath.Dir(h.wsRoot), "cliws2")
	files := map[string]string{
		"Ebbfile.toml": `version = 1

[workspace]
name = "cliws2"

[policy]
network = "approved-actions"
unknown = "preserve"
`,
		"notes.md": "second workspace fixture\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if code, _, stderr := h.run("snapshot", root); code != ExitOK {
		t.Fatalf("second snapshot code = %d, stderr = %s", code, stderr)
	}
	return snapshotsOfName(t, h, "cliws2")[0]
}

// snapshotsOfName lists one workspace's snapshot rows by name.
func snapshotsOfName(t *testing.T, h *eHarness, name string) []catalog.Snapshot {
	t.Helper()
	wss, err := h.cat().ListWorkspaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range wss {
		if w.Name == name {
			snaps, err := h.cat().ListSnapshots(w.ID)
			if err != nil {
				t.Fatal(err)
			}
			return snaps
		}
	}
	t.Fatalf("no workspace named %q", name)
	return nil
}

func TestDeleteHappyPathBySnapshotID(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	code, stdout, stderr := h.run("delete", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// Both stages ran against the fake vault: pair forgotten, one REAL
	// prune call.
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Fatal("backend pair still present after delete")
	}
	if len(h.store.pruneCalls) != 1 || h.store.pruneCalls[0] {
		t.Fatalf("prune calls = %v, want exactly one REAL prune", h.store.pruneCalls)
	}
	got, err := h.cat().GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pinned {
		t.Error("snapshot still pinned after delete")
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("pending retention intents after delete: %v", pending)
	}
	for _, want := range []string{
		"unpinned, forgotten and verified gone",
		"prune",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, stdout)
}

func TestDeleteJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	code, stdout, _ := h.run("delete", "--json", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "command") != "delete" || envString(t, env, "outcome") != "ok" ||
		envString(t, env, "snapshot_id") != string(snap.ID) {
		t.Fatalf("envelope head = %v", env)
	}
	for _, want := range []string{"unpinned", "forgotten", "pruned"} {
		if !mustCondition(env, want) {
			t.Errorf("conditions lack %q: %v", want, env["conditions"])
		}
	}
	det := env["details"].(map[string]any)
	if det["target"] != string(snap.ID) || det["state_reached"] != "completed" || det["dry_run"] != false {
		t.Errorf("details head = %v", det)
	}
	snaps, _ := det["snapshots"].([]any)
	if len(snaps) != 1 {
		t.Fatalf("details.snapshots = %v", det["snapshots"])
	}
	s := snaps[0].(map[string]any)
	if s["snapshot_id"] != string(snap.ID) || s["state_reached"] != "completed" {
		t.Errorf("snapshot outcome = %v", s)
	}
	prune := det["prune"].(map[string]any)
	if prune["ran"] != true {
		t.Errorf("prune = %v", prune)
	}
	if b, ok := env["bytes"].(map[string]any); !ok || b["preserved"].(float64) <= 0 {
		t.Errorf("bytes.preserved missing: %v", env["bytes"])
	}
	assertNoSecrets(t, stdout)
}

func TestDeleteByWorkspaceNameDeletesAllSnapshots(t *testing.T) {
	h := newEHarness(t)
	// Two snapshots on the LIVE workspace "cliws".
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot 1: %d %s", code, stderr)
	}
	if err := os.MkdirAll(filepath.Join(h.wsRoot, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.wsRoot, "src", "second.go"),
		[]byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot 2: %d %s", code, stderr)
	}
	all := snapshotsOfName(t, h, "cliws")
	if len(all) != 2 {
		t.Fatalf("want 2 snapshots, got %d", len(all))
	}

	code, _, stderr := h.run("delete", "cliws", "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, snap := range all {
		if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
			t.Errorf("pair of %s still present", snap.ID)
		}
		if got, _ := h.cat().GetSnapshot(snap.ID); got.Pinned {
			t.Errorf("%s still pinned", snap.ID)
		}
	}
	if len(h.store.pruneCalls) != 1 {
		t.Errorf("prune calls = %v, want one prune after the batch", h.store.pruneCalls)
	}
	if !strings.Contains(stderr, "2 snapshot(s) unpinned, forgotten and verified gone") {
		t.Errorf("stderr must report the count:\n%s", stderr)
	}
}

func TestDeleteLastOfParkedGuardThenAcknowledged(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h) // PARKED workspace, ONE snapshot

	code, _, stderr := h.run("delete", string(snap.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeForgetLastOfParked, "--last-of-parked")
	if !backendPresent(h, snap.PayloadBackendID) {
		t.Error("protected snapshot's payload was deleted anyway")
	}
	if len(h.store.pruneCalls) != 0 {
		t.Error("prune ran despite the refused deletion")
	}

	// The explicit acknowledgement releases it; the emptied vault prunes
	// nothing (gc's clean empty-vault contract).
	code, _, stderr = h.run("delete", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("acknowledged delete code = %d, stderr = %s", code, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Error("backend pair still present after acknowledged delete")
	}
}

func TestDeleteConfirmationRules(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	// Headless without --yes: never silent.
	h.tty = false
	code, _, stderr := h.run("delete", string(snap.ID))
	if code != ExitBlocked {
		t.Fatalf("headless code = %d, want %d", code, ExitBlocked)
	}
	assertBlocker(t, stderr, CodeDeleteUnconfirmed, "--yes")
	if !backendPresent(h, snap.PayloadBackendID) {
		t.Error("unconfirmed delete removed the payload")
	}

	// Interactive mismatch: nothing happens, no durable state.
	h.tty = true
	h.lines = []string{"not-the-target"}
	code, _, stderr = h.run("delete", string(snap.ID))
	if code != ExitBlocked {
		t.Fatalf("mismatch code = %d, want %d", code, ExitBlocked)
	}
	assertBlocker(t, stderr, CodeDeleteUnconfirmed, "does not match")
	if !backendPresent(h, snap.PayloadBackendID) || !backendPresent(h, snap.SealBackendID) {
		t.Error("mismatched confirmation removed the pair")
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("declined confirmation left durable state: %v", pending)
	}
	if len(h.store.pruneCalls) != 0 {
		t.Error("prune ran despite the declined confirmation")
	}

	// Exact target match completes the whole flow.
	h.resetSignalContext()
	h.lines = []string{string(snap.ID)}
	code, _, stderr = h.run("delete", string(snap.ID))
	if code != ExitOK {
		t.Fatalf("matched code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "type the target") {
		t.Errorf("prompt must require the exact target:\n%s", stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) {
		t.Error("pair still present after confirmed delete")
	}
}

func TestDeleteDryRunIsNonMutating(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	code, stdout, stderr := h.run("delete", "--dry-run", "--json", string(snap.ID))
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// No mutation anywhere: pair present, row pinned, no intent, no
	// workspace-level change; exactly ONE prune call, flagged dry-run.
	if !backendPresent(h, snap.PayloadBackendID) || !backendPresent(h, snap.SealBackendID) {
		t.Fatal("dry run removed the backend pair")
	}
	if got, _ := h.cat().GetSnapshot(snap.ID); !got.Pinned {
		t.Error("dry run unpinned the snapshot")
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("dry run left durable state: %v", pending)
	}
	if len(h.store.pruneCalls) != 1 || !h.store.pruneCalls[0] {
		t.Fatalf("prune calls = %v, want exactly one DRY-RUN prune (the estimate)", h.store.pruneCalls)
	}
	env := envelopeOf(t, stdout)
	if !mustCondition(env, "dry-run") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["dry_run"] != true {
		t.Errorf("details.dry_run = %v", det["dry_run"])
	}
	snaps, _ := det["snapshots"].([]any)
	if len(snaps) != 1 || snaps[0].(map[string]any)["state_reached"] != "planned" {
		t.Errorf("dry-run snapshot rows must be planned: %v", det["snapshots"])
	}
	// Human wording (separate invocation, human mode).
	if code, _, stderr := h.run("delete", "--dry-run", string(snap.ID)); code != ExitOK {
		t.Fatalf("human dry-run code = %d, stderr = %s", code, stderr)
	} else if !strings.Contains(stderr, "dry run: no changes were made") {
		t.Errorf("human dry-run wording missing:\n%s", stderr)
	}
}

func TestDeletePruneSkippedWhenOtherWorkspaceHasPendingIntent(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h) // workspace "cliws"
	other := deleteSecondWorkspaceSnapshot(t, h)
	// An interrupted forget of the OTHER workspace: unresolved intent.
	if _, err := h.cat().CreateRetentionIntent(other.ID, "user:forget"); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := h.run("delete", "--json", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// The deletion itself completed.
	if backendPresent(h, snap.PayloadBackendID) {
		t.Fatal("target pair still present")
	}
	// The prune was SKIPPED and the warning names ebb gc.
	if len(h.store.pruneCalls) != 0 {
		t.Fatalf("prune ran despite another workspace's pending intent: %v", h.store.pruneCalls)
	}
	env := envelopeOf(t, stdout)
	if !mustCondition(env, "prune-skipped") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	prune := det["prune"].(map[string]any)
	if prune["ran"] != false || prune["skipped_reason"] == nil {
		t.Errorf("prune details = %v", prune)
	}
	if !strings.Contains(prune["skipped_reason"].(string), "retention intent") {
		t.Errorf("skip reason must name the pending intents: %v", prune["skipped_reason"])
	}
	warned := false
	for _, w := range env["warnings"].([]any) {
		if strings.Contains(w.(string), "ebb gc") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("warnings must name `ebb gc`: %v", env["warnings"])
	}
	if !strings.Contains(stderr, "prune skipped") && !strings.Contains(stdout, "prune skipped") {
		t.Errorf("human report must say the prune was skipped:\n%s", stderr)
	}
	// The OTHER workspace's intent is untouched.
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 1 || pending[0].SnapshotID != other.ID {
		t.Errorf("other workspace's pending intent damaged: %v", pending)
	}
}

func TestDeletePruneSkippedWhenOtherWorkspaceHasActiveOp(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)
	other := deleteSecondWorkspaceSnapshot(t, h)
	if _, err := h.cat().BeginOperation(other.WorkspaceID, catalog.OpKindPark,
		h.wsRoot, "identity", "digest"); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := h.run("delete", "--json", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	if len(h.store.pruneCalls) != 0 {
		t.Fatalf("prune ran despite an active operation: %v", h.store.pruneCalls)
	}
	env := envelopeOf(t, stdout)
	det := env["details"].(map[string]any)
	prune := det["prune"].(map[string]any)
	if !strings.Contains(prune["skipped_reason"].(string), "active operation") {
		t.Errorf("skip reason = %v", prune["skipped_reason"])
	}
}

func TestDeleteActiveOpOnTargetBlocks(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)
	opID, err := h.cat().BeginOperation(snap.WorkspaceID, catalog.OpKindOpen,
		h.wsRoot, "identity", "digest")
	if err != nil {
		t.Fatal(err)
	}

	code, _, stderr := h.run("delete", string(snap.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeDeleteActiveOperation, string(opID))
	if !strings.Contains(stderr, "ebb recover "+string(opID)) {
		t.Errorf("safe action must name `ebb recover %s`:\n%s", opID, stderr)
	}
	if !backendPresent(h, snap.PayloadBackendID) {
		t.Error("blocked delete removed the payload")
	}
	if len(h.store.pruneCalls) != 0 {
		t.Error("prune ran despite the block")
	}
}

func TestDeletePartialFailureThenIdempotentRerun(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	h.store.onForget = func(ids []string) error { return errBoom }
	code, stdout, stderr := h.run("delete", "--json", string(snap.ID), "--yes")
	if code != ExitInterrupted {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitInterrupted, stderr)
	}
	partEnv := envelopeOf(t, stdout)
	var partialMsg string
	if errs, ok := partEnv["errors"].([]any); ok && len(errs) > 0 {
		partialMsg, _ = errs[0].(string)
	}
	for _, want := range []string{"reached durable state", "rerun `ebb delete", "idempotent"} {
		if !strings.Contains(partialMsg, want) {
			t.Errorf("partial message lacks %q: %q", want, partialMsg)
		}
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 1 {
		t.Fatalf("partial state must hold the pending intent: %v", pending)
	}

	// Rerun resumes through the same durable flow and prunes.
	h.store.onForget = nil
	code, _, stderr = h.run("delete", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("rerun code = %d, stderr = %s", code, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) {
		t.Error("pair still present after rerun")
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("intent not completed on rerun: %v", pending)
	}
}

func TestDeleteIdempotentRerunAndCleanNoOp(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	if code, _, stderr := h.run("delete", string(snap.ID), "--yes"); code != ExitOK {
		t.Fatalf("first delete: %d %s", code, stderr)
	}
	// Rerun the SAME target: clean success (forget's idempotent flow
	// over the already-absent pair).
	code, _, stderr := h.run("delete", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("rerun code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "already absent") {
		t.Errorf("rerun must report the idempotent no-op pair:\n%s", stderr)
	}

	// A workspace with NO snapshots at all: clean nothing-to-delete.
	if err := h.cat().EnsureWorkspace(domain.WorkspaceID(domain.NewID()), "never-captured"); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := h.run("delete", "--json", "never-captured")
	if code != ExitOK {
		t.Fatalf("empty-workspace code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if !mustCondition(env, "noop") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["no_op"] != true {
		t.Errorf("details.no_op = %v", det["no_op"])
	}
	if snaps, _ := det["snapshots"].([]any); snaps == nil {
		t.Errorf("details.snapshots must be an empty array, not null: %v", det["snapshots"])
	}
	// Human mode carries the wording (--json suppresses it).
	if code, _, stderr := h.run("delete", "never-captured"); code != ExitOK {
		t.Fatalf("human noop code = %d, stderr = %s", code, stderr)
	} else if !strings.Contains(stderr, "nothing to delete") {
		t.Errorf("human wording missing:\n%s", stderr)
	}
}

func TestDeleteUnknownAndMalformedTargets(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("delete", "ghost-workspace", "--yes"); code != ExitUsage {
		t.Fatalf("unknown name code = %d, want %d (stderr %s)", code, ExitUsage, stderr)
	} else if !strings.Contains(stderr, CodeDeleteUnknownTarget) {
		t.Errorf("unknown name must carry the stable code:\n%s", stderr)
	}
	if code, _, _ := h.run("delete", "not-an-id", "--yes"); code != ExitUsage {
		t.Fatalf("malformed id code = %d, want %d", code, ExitUsage)
	}
	if code, _, stderr := h.run("delete", strings.Repeat("ab", 16), "--yes"); code != ExitUsage {
		t.Fatalf("unknown id code = %d, want %d (stderr %s)", code, ExitUsage, stderr)
	}
	if code, _, _ := h.run("delete", "--yes"); code != ExitUsage {
		t.Fatalf("missing target code = %d, want %d", code, ExitUsage)
	}
}

func TestDeleteRefusalsSealKindAndUnsealed(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot: %d %s", code, stderr)
	}
	ws := snapshotsOf(t, h)[0]

	sealOnly := catalog.Snapshot{
		ID: domain.SnapshotID(domain.NewID()), WorkspaceID: ws.WorkspaceID,
		Kind: catalog.SnapshotKindSeal,
	}
	if _, err := h.cat().RecordSnapshot(sealOnly); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("delete", string(sealOnly.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("seal-kind code = %d, stderr = %s", code, stderr)
	}
	assertBlocker(t, stderr, CodeForgetNotForgettable, "Safe action")

	unsealed := catalog.Snapshot{
		ID: domain.SnapshotID(domain.NewID()), WorkspaceID: ws.WorkspaceID,
		PayloadBackendID: "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
		Kind:             catalog.SnapshotKindSnapshot,
	}
	if _, err := h.cat().RecordSnapshot(unsealed); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = h.run("delete", string(unsealed.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("unsealed code = %d, stderr = %s", code, stderr)
	}
	assertBlocker(t, stderr, CodeForgetUnsealed, "§11.3")
}
