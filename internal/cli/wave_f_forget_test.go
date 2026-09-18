// wave_f_forget_test.go: `ebb forget` coverage over the eHarness world
// (Wave F). The durable flow (intent → unpin → verified backend forget →
// complete), the last-of-parked protection, the exact typed-id
// confirmation, idempotent rerun after a partial failure, and the
// refusal classes (seal kind, unsealed payload, unknown id).

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// errBoom is the injected backend failure for the partial-forget test.
var errBoom = errors.New("boom: injected backend failure")

// forgettableSnapshot captures the harness workspace (workspace stays
// LIVE, so the last-of-parked guard does not apply) and returns the
// sealed snapshot row.
func forgettableSnapshot(t *testing.T, h *eHarness) catalog.Snapshot {
	t.Helper()
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot code = %d, stderr = %s", code, stderr)
	}
	return latestSnapshotOf(t, h, catalog.SnapshotKindSnapshot)
}

// parkedOnlySnapshot parks the harness workspace: exactly ONE snapshot of
// a PARKED workspace (the last-of-parked protection case).
func parkedOnlySnapshot(t *testing.T, h *eHarness) catalog.Snapshot {
	t.Helper()
	if code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatalf("park code = %d, stderr = %s", code, stderr)
	}
	return latestSnapshotOf(t, h, catalog.SnapshotKindPark)
}

func latestSnapshotOf(t *testing.T, h *eHarness, kind string) catalog.Snapshot {
	t.Helper()
	for _, s := range snapshotsOf(t, h) {
		if s.Kind == kind {
			return s
		}
	}
	t.Fatalf("no %s snapshot found", kind)
	return catalog.Snapshot{}
}

// backendPresent reports whether the fake store still holds the id.
func backendPresent(h *eHarness, id string) bool {
	refs, err := h.store.List(context.Background(), "", "")
	if err != nil {
		return false
	}
	for _, r := range refs {
		if r.BackendID == id {
			return true
		}
	}
	return false
}

func TestForgetHappyPathForgetsPairAndCompletesIntent(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	code, stdout, stderr := h.run("forget", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// The backend pair is REALLY gone (List is the authority — forget of
	// a nonexistent id exits 0 silently, so the test verifies presence).
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Fatal("backend pair still present after forget")
	}
	// The catalog row is unpinned and the intent completed.
	got, err := h.cat().GetSnapshot(snap.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pinned {
		t.Error("snapshot still pinned after forget")
	}
	pending, err := h.cat().PendingRetentionIntents()
	if err != nil || len(pending) != 0 {
		t.Errorf("pending retention intents after completion: %v (%v)", pending, err)
	}
	for _, want := range []string{
		"forgotten snapshot",
		"backend pair forgotten and verified gone",
		"retention intent",
		"the recovery obligation has ended",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, stdout)
}

func TestForgetJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)
	code, stdout, stderr := h.run("forget", "--json", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || envString(t, env, "snapshot_id") != string(snap.ID) {
		t.Fatalf("envelope head = %v", env)
	}
	if !mustCondition(env, "obligation-released") || !mustCondition(env, "unpinned") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	det := env["details"].(map[string]any)
	if det["impact_known"] != true || det["state_reached"] != "completed" {
		t.Errorf("details = %v", det)
	}
	if b, ok := env["bytes"].(map[string]any); !ok || b["preserved"].(float64) <= 0 {
		t.Errorf("bytes.preserved missing: %v", env["bytes"])
	}
}

func TestForgetLastOfParkedProtectedThenAcknowledged(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h) // workspace parked with ONE snapshot

	code, _, stderr := h.run("forget", string(snap.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeForgetLastOfParked, "--last-of-parked")
	if !backendPresent(h, snap.PayloadBackendID) {
		t.Error("protected snapshot's payload was forgotten anyway")
	}

	// The explicit acknowledgement releases it.
	code, _, stderr = h.run("forget", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("acknowledged forget code = %d, stderr = %s", code, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Error("backend pair still present after acknowledged forget")
	}
}

func TestForgetTypedIDConfirmationMatchAndMismatch(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)
	h.tty = true

	// Mismatch: nothing is released.
	h.lines = []string{"deadbeef"}
	code, _, stderr := h.run("forget", string(snap.ID))
	if code != ExitBlocked {
		t.Fatalf("mismatch code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	assertBlocker(t, stderr, CodeForgetUnconfirmed, "does not match")
	if !backendPresent(h, snap.PayloadBackendID) || !backendPresent(h, snap.SealBackendID) {
		t.Error("mismatched confirmation released the pair")
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("mismatched confirmation left durable state: %v", pending)
	}

	// Exact match completes the flow.
	h.lines = []string{string(snap.ID)}
	code, _, stderr = h.run("forget", string(snap.ID))
	if code != ExitOK {
		t.Fatalf("matched code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "type the snapshot id") {
		t.Errorf("prompt must require the exact id:\n%s", stderr)
	}
}

func TestForgetNonInteractiveWithoutYesBlocked(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)
	h.tty = false
	code, _, stderr := h.run("forget", string(snap.ID))
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d", code, ExitBlocked)
	}
	assertBlocker(t, stderr, CodeForgetUnconfirmed, "--yes")
	if !backendPresent(h, snap.PayloadBackendID) || !backendPresent(h, snap.SealBackendID) {
		t.Error("unconfirmed forget released the pair")
	}
}

func TestForgetPartialFailureThenIdempotentRerun(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)

	// The backend forget fails after the durable catalog steps landed.
	h.store.onForget = func(ids []string) error {
		return errBoom
	}
	code, stdout, stderr := h.run("forget", "--json", string(snap.ID), "--yes")
	if code != ExitInterrupted {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitInterrupted, stderr)
	}
	// --json suppresses the human text; the partial-state message rides
	// the envelope's errors array.
	partEnv := envelopeOf(t, stdout)
	var partialMsg string
	if errs, ok := partEnv["errors"].([]any); ok && len(errs) > 0 {
		partialMsg, _ = errs[0].(string)
	}
	for _, want := range []string{
		"reached durable state",
		"unpinned",
		"rerun `ebb forget",
		"idempotent",
	} {
		if !strings.Contains(partialMsg, want) {
			t.Errorf("partial error message lacks %q: %q", want, partialMsg)
		}
	}
	partDet := partEnv["details"].(map[string]any)
	intentID, _ := partDet["intent_id"].(string)
	if intentID == "" || partDet["state_reached"] != "unpinned" {
		t.Fatalf("partial envelope details = %v", partDet)
	}
	// The intermediate state is exactly: intent pending, row unpinned,
	// pair still present.
	pending, err := h.cat().PendingRetentionIntents()
	if err != nil || len(pending) != 1 || pending[0].SnapshotID != snap.ID || string(pending[0].ID) != intentID {
		t.Fatalf("pending intents = %v (%v)", pending, err)
	}
	if got, _ := h.cat().GetSnapshot(snap.ID); got.Pinned {
		t.Error("snapshot should be unpinned in the partial state")
	}
	if !backendPresent(h, snap.PayloadBackendID) {
		t.Fatal("pair vanished despite the failed forget")
	}

	// Rerun resumes and completes; the PENDING intent is reused (the
	// completed report names the same intent id), not duplicated.
	h.store.onForget = nil
	code, stdout, stderr = h.run("forget", "--json", string(snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("rerun code = %d, stderr = %s", code, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Error("backend pair still present after rerun")
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("intent not completed on rerun: %v", pending)
	}
	rerunEnv := envelopeOf(t, stdout)
	if id, _ := rerunEnv["details"].(map[string]any)["intent_id"].(string); id != intentID {
		t.Errorf("rerun created a new intent %q instead of reusing %q", id, intentID)
	}
}

func TestForgetRefusals(t *testing.T) {
	h := newEHarness(t)
	// A snapshot-kind capture first, so the workspace exists with a
	// sealed snapshot plus room for synthetic rows.
	if code, _, stderr := h.run("snapshot", h.wsRoot); code != ExitOK {
		t.Fatalf("snapshot code = %d, stderr = %s", code, stderr)
	}
	ws := snapshotsOf(t, h)[0]

	// Unknown id: exit 2.
	code, _, stderr := h.run("forget", strings.Repeat("ab", 16), "--yes")
	if code != ExitUsage {
		t.Fatalf("unknown id code = %d, stderr = %s", code, stderr)
	}
	// Malformed id: exit 2.
	if code, _, _ := h.run("forget", "not-an-id", "--yes"); code != ExitUsage {
		t.Fatalf("malformed id code = %d, want %d", code, ExitUsage)
	}

	// Seal-kind row: refused with its own code.
	sealOnly := catalog.Snapshot{
		ID: domain.SnapshotID(domain.NewID()), WorkspaceID: ws.WorkspaceID,
		Kind: catalog.SnapshotKindSeal,
	}
	if _, err := h.cat().RecordSnapshot(sealOnly); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = h.run("forget", string(sealOnly.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("seal-kind code = %d, stderr = %s", code, stderr)
	}
	assertBlocker(t, stderr, CodeForgetNotForgettable, "Safe action")

	// Unsealed payload (no seal backend id): §11.3 review, not forget.
	unsealed := catalog.Snapshot{
		ID: domain.SnapshotID(domain.NewID()), WorkspaceID: ws.WorkspaceID,
		PayloadBackendID: "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111",
		Kind:             catalog.SnapshotKindSnapshot,
	}
	if _, err := h.cat().RecordSnapshot(unsealed); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = h.run("forget", string(unsealed.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("unsealed code = %d, stderr = %s", code, stderr)
	}
	assertBlocker(t, stderr, CodeForgetUnsealed, "§11.3")
}
