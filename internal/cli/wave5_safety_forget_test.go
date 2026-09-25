// wave5_safety_forget_test.go: the Wave 5 safety fix wave for `ebb
// forget`. Four regression families, all spec'd BEFORE the fix:
//
//   - E11 (the money test): the last-recovery-copy guard must count
//     SURVIVING custody — what the vault's CURRENT List still returns —
//     not catalog rows. A stale row (its backend copy already gone)
//     used to inflate len(all) and defeat the guard.
//   - The journaled forget operation (amended Wave 5 spec): every
//     durable boundary commits a FORGET_* phase; a crash leaves a row a
//     rerun of the SAME `ebb forget` adopts and resumes; the crash
//     states are constructed here through the same public catalog API
//     the command itself uses, then observed through a fresh handle
//     (reopen-state semantics).
//   - recover wiring: cancel stays valid while nothing destructive
//     happened (FORGET_PLANNED / FORGET_INTENT_RECORDED) and is REFUSED
//     once the row reached FORGET_UNPINNED — the false-invariant case
//     the amended spec forbids; plain recover reports and names the
//     rerun.
//   - Replica honesty: replica receipts are noted as unrevalidated and
//     never counted as surviving copies (they must not bypass the
//     guard either).

package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/lifecycle"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// staleHex returns a 64-hex backend id that the fake store does NOT hold
// (the shape of a catalog row whose backend copy is already gone).
func staleHex(prefix string) string { return strings.Repeat(prefix, 32) }

// seedSealedForgetRow inserts a sealed snapshot row for ws carrying the
// given backend pair, and — when register is true — puts that pair into
// the fake store so the backend List reports it as surviving.
func seedSealedForgetRow(t *testing.T, h *eHarness, ws domain.WorkspaceID, payload, seal string, register bool) catalog.Snapshot {
	t.Helper()
	if register {
		for _, id := range []string{payload, seal} {
			h.store.snaps[id] = &eFakeSnap{
				files: map[string][]byte{}, dirs: map[string]bool{}, links: map[string]string{},
			}
		}
	}
	row := catalog.Snapshot{
		ID:               domain.SnapshotID(domain.NewID()),
		WorkspaceID:      ws,
		PayloadBackendID: payload,
		SealBackendID:    seal,
		Kind:             catalog.SnapshotKindSnapshot,
	}
	if _, err := h.cat().RecordSnapshot(row); err != nil {
		t.Fatalf("seed sealed row: %v", err)
	}
	return row
}

// seedForgetCrashState reconstructs, through the same public catalog API
// the forget command uses, the durable state a crash at the named forget
// phase leaves behind (amended spec point 6): operation row with the
// target's backend refs, retention intent, unpin and backend removal in
// causal order, each phase committed by the same CAS transition the
// command performs. The test then reopens state (a fresh catalog handle
// per h.cat()/CLI run) and asserts the resume/refusal behavior.
func seedForgetCrashState(t *testing.T, h *eHarness, snap catalog.Snapshot, phase string) domain.OperationID {
	t.Helper()
	op, err := h.cat().BeginOperationIfNoActive(snap.WorkspaceID, catalog.OpKindForget, catalog.PhaseForgetPlanned)
	if err != nil {
		t.Fatalf("seed: begin forget op: %v", err)
	}
	if err := h.cat().SetForgetTarget(op.ID, string(snap.ID), snap.PayloadBackendID, snap.SealBackendID, string(snap.VaultID)); err != nil {
		t.Fatalf("seed: forget target: %v", err)
	}
	adv := func(from, to string) {
		t.Helper()
		if err := h.cat().AdvanceOperation(op.ID, from, to); err != nil {
			t.Fatalf("seed: advance %s -> %s: %v", from, to, err)
		}
	}
	if catalog.ForgetPhaseRank(phase) >= catalog.ForgetPhaseRank(catalog.PhaseForgetIntentRecorded) {
		if _, err := h.cat().CreateRetentionIntent(snap.ID, "user:forget"); err != nil {
			t.Fatalf("seed: retention intent: %v", err)
		}
		adv(catalog.PhaseForgetPlanned, catalog.PhaseForgetIntentRecorded)
	}
	if catalog.ForgetPhaseRank(phase) >= catalog.ForgetPhaseRank(catalog.PhaseForgetUnpinned) {
		if err := h.cat().Unpin(snap.ID, "user:forget:"+string(op.ID), true); err != nil {
			t.Fatalf("seed: unpin: %v", err)
		}
		adv(catalog.PhaseForgetIntentRecorded, catalog.PhaseForgetUnpinned)
	}
	if catalog.ForgetPhaseRank(phase) >= catalog.ForgetPhaseRank(catalog.PhaseForgetBackendForgotten) {
		if err := h.store.Forget(context.Background(), "", "",
			[]string{snap.PayloadBackendID, snap.SealBackendID}); err != nil {
			t.Fatalf("seed: backend forget: %v", err)
		}
		adv(catalog.PhaseForgetUnpinned, catalog.PhaseForgetBackendForgotten)
	}
	if got, gerr := h.cat().GetOperation(op.ID); gerr != nil || got.Phase != phase {
		t.Fatalf("seed: op phase = %s (%v), want %s", got.Phase, gerr, phase)
	}
	return op.ID
}

// assertForgetOpPhase reads the operation row through a FRESH catalog
// handle (the reopen-state check).
func assertForgetOpPhase(t *testing.T, h *eHarness, opID domain.OperationID, want string) {
	t.Helper()
	op, err := h.cat().GetOperation(opID)
	if err != nil {
		t.Fatalf("get operation %s: %v", opID, err)
	}
	if op.Phase != want {
		t.Fatalf("operation %s phase = %s, want %s", opID, op.Phase, want)
	}
}

// ---- E11: the last-recovery-copy guard counts surviving custody --------

func TestForgetLastCopyGuardCountsSurvivingCustody(t *testing.T) {
	t.Run("guard fires when only the target's pair survives", func(t *testing.T) {
		h := newEHarness(t)
		snap := parkedOnlySnapshot(t, h)
		// The stale twin: a sealed catalog row whose backend copy is
		// already gone (exactly the E11 shape). Old code counted two rows
		// and let the forget through; custody counting must refuse.
		seedSealedForgetRow(t, h, snap.WorkspaceID, staleHex("b1"), staleHex("c2"), false)

		code, _, stderr := h.run("forget", string(snap.ID), "--yes")
		if code != ExitBlocked {
			t.Fatalf("code = %d, want %d — the row-count guard let the last SURVIVING copy through (stderr %s)", code, ExitBlocked, stderr)
		}
		assertBlocker(t, stderr, CodeForgetLastOfParked, "--last-of-parked")
		if !backendPresent(h, snap.PayloadBackendID) || !backendPresent(h, snap.SealBackendID) {
			t.Error("the guarded pair was mutated despite the refusal")
		}
	})

	t.Run("guard passes when another snapshot's pair survives", func(t *testing.T) {
		h := newEHarness(t)
		snap := parkedOnlySnapshot(t, h)
		other := seedSealedForgetRow(t, h, snap.WorkspaceID, staleHex("d3"), staleHex("e4"), true)

		code, _, stderr := h.run("forget", string(snap.ID), "--yes")
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (stderr %s)", code, ExitOK, stderr)
		}
		if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
			t.Error("target pair still present after forget")
		}
		// The surviving twin's custody is untouched: forget removes only
		// the target's pair.
		if !backendPresent(h, other.PayloadBackendID) || !backendPresent(h, other.SealBackendID) {
			t.Error("the OTHER snapshot's pair was forgotten with the target")
		}
	})
}

// ---- the journaled forget operation: crash resume at every boundary ----

func TestForgetCrashResumeAfterIntentRecorded(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	opID := seedForgetCrashState(t, h, snap, catalog.PhaseForgetIntentRecorded)

	// The rerun adopts its own operation and resumes idempotently.
	code, _, stderr := h.run("forget", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("rerun code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Error("backend pair still present after resumed forget")
	}
	assertForgetOpPhase(t, h, opID, catalog.PhaseForgetDone)
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("pending intents after resume: %v", pending)
	}
}

func TestForgetCrashResumeAfterUnpin(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	opID := seedForgetCrashState(t, h, snap, catalog.PhaseForgetUnpinned)

	code, _, stderr := h.run("forget", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("rerun code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Error("backend pair still present after resumed forget")
	}
	assertForgetOpPhase(t, h, opID, catalog.PhaseForgetDone)
}

func TestForgetCrashResumeAfterBackendForgottenBeforeCompletion(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	opID := seedForgetCrashState(t, h, snap, catalog.PhaseForgetBackendForgotten)

	// The pending intent survived the crash (§16.6 visible state); the
	// rerun must complete it, not duplicate it.
	pending, err := h.cat().PendingRetentionIntents()
	if err != nil || len(pending) != 1 {
		t.Fatalf("seeded pending intents = %v (%v), want 1", pending, err)
	}
	code, stdout, stderr := h.run("forget", "--json", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("rerun code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	det := envelopeOf(t, stdout)["details"].(map[string]any)
	if det["intent_id"].(string) != string(pending[0].ID) {
		t.Errorf("rerun intent %v, want the seeded %s", det["intent_id"], pending[0].ID)
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("pending intents after resume: %v", pending)
	}
	assertForgetOpPhase(t, h, opID, catalog.PhaseForgetDone)
}

// TestForgetRerunAdoptsOnlyItsOwnTarget: an active forget operation for
// a DIFFERENT snapshot of the same workspace refuses the rerun — the
// atomic primitive's refusal — and the refused forget touches nothing.
func TestForgetRerunAdoptsOnlyItsOwnTarget(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	other := seedSealedForgetRow(t, h, snap.WorkspaceID, staleHex("f5"), staleHex("a6"), true)

	op, err := h.cat().BeginOperationIfNoActive(snap.WorkspaceID, catalog.OpKindForget, catalog.PhaseForgetPlanned)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.cat().SetBackendRefs(op.ID, other.PayloadBackendID, other.SealBackendID); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := h.run("forget", string(snap.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, string(op.ID)) || !strings.Contains(stderr, "ebb recover") {
		t.Errorf("refusal must name the active operation and the recover verb:\n%s", stderr)
	}
	// T4 honesty, stated verbatim at the refusal too: only FORGETS
	// serialize on the atomic primitive — the other verbs still use the
	// old caller-side check — so the wording must not overclaim.
	if !strings.Contains(stderr, "Concurrent ebb forgets are mutually exclusive at the catalog journal") {
		t.Errorf("refusal must state the narrowed concurrency scope verbatim:\n%s", stderr)
	}
	if !backendPresent(h, snap.PayloadBackendID) || !backendPresent(h, snap.SealBackendID) {
		t.Error("the refused forget mutated the backend")
	}
	assertForgetOpPhase(t, h, op.ID, catalog.PhaseForgetPlanned)
}

// TestForgetCrashResumeAfterPlannedRefsRecorded covers the EARLIEST
// adoptable boundary: a crash between the journaled begin and the first
// durable step leaves the row at FORGET_PLANNED with the target pair
// already recorded on it. The rerun of the SAME forget must adopt that
// row (kind forget + same recorded pair) and walk it to completion —
// every later boundary test starts from a phase this one precedes.
func TestForgetCrashResumeAfterPlannedRefsRecorded(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	opID := seedForgetCrashState(t, h, snap, catalog.PhaseForgetPlanned)

	code, _, stderr := h.run("forget", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("rerun code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Error("backend pair still present after resumed forget")
	}
	assertForgetOpPhase(t, h, opID, catalog.PhaseForgetDone)
}

// TestForgetCrashBeforeRefsRecordedRefusedThenCanceled covers the one
// crash shape that is NOT adoptable: the window between the begin and
// the SetBackendRefs write leaves a FORGET_PLANNED row with NO durable
// fingerprint, so the rerun cannot recognize it as its own — it refuses
// (the atomic primitive's mutual exclusion, exit 3), the row stays
// active, and the documented recovery closes it with `ebb recover
// --cancel` (valid: nothing destructive happened). Only then does a
// fresh forget proceed.
func TestForgetCrashBeforeRefsRecordedRefusedThenCanceled(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	op, err := h.cat().BeginOperationIfNoActive(snap.WorkspaceID, catalog.OpKindForget, catalog.PhaseForgetPlanned)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately NO SetBackendRefs: the unidentifiable row.

	code, _, stderr := h.run("forget", string(snap.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("rerun code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, string(op.ID)) || !strings.Contains(stderr, "ebb recover") {
		t.Errorf("refusal must name the active operation and the recover verb:\n%s", stderr)
	}
	assertForgetOpPhase(t, h, op.ID, catalog.PhaseForgetPlanned)

	code, _, stderr = h.run("recover", "--json", string(op.ID), "--cancel")
	if code != ExitOK {
		t.Fatalf("cancel code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	assertForgetOpPhase(t, h, op.ID, catalog.PhaseCanceled)
	if got, _ := h.cat().GetSnapshot(snap.ID); !got.Pinned {
		t.Error("cancel of the unidentifiable row must leave the snapshot pinned")
	}

	// The workspace accepts a fresh forget, which walks to completion.
	if code, _, stderr := h.run("forget", string(snap.ID), "--yes", "--last-of-parked"); code != ExitOK {
		t.Fatalf("fresh forget code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	if backendPresent(h, snap.PayloadBackendID) || backendPresent(h, snap.SealBackendID) {
		t.Error("backend pair still present after the fresh forget")
	}
}

// ---- recover wiring for the forget vocabulary ---------------------------

func TestRecoverCancelForgetBeforeUnpinAllowed(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	opID := seedForgetCrashState(t, h, snap, catalog.PhaseForgetIntentRecorded)

	// Nothing destructive happened: the row still has the snapshot
	// pinned and the backend pair intact, so cancel is a valid reading.
	code, stdout, stderr := h.run("recover", "--json", string(opID), "--cancel")
	if code != ExitOK {
		t.Fatalf("cancel code = %d, want %d (stderr %s / stdout %s)", code, ExitOK, stderr, stdout)
	}
	assertForgetOpPhase(t, h, opID, catalog.PhaseCanceled)
	if got, _ := h.cat().GetSnapshot(snap.ID); !got.Pinned {
		t.Error("cancel before unpin must leave the snapshot pinned")
	}
	// The pending intent stays pending (the forget did not complete) and
	// the workspace accepts a fresh forget that reuses it.
	pending, _ := h.cat().PendingRetentionIntents()
	if len(pending) != 1 {
		t.Fatalf("pending intents after cancel = %v, want the seeded one", pending)
	}
	if code, _, stderr := h.run("forget", string(snap.ID), "--yes", "--last-of-parked"); code != ExitOK {
		t.Fatalf("forget after cancel code = %d (stderr %s)", code, stderr)
	}
}

func TestRecoverCancelForgetAfterUnpinRefused(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	opID := seedForgetCrashState(t, h, snap, catalog.PhaseForgetUnpinned)

	// The obligation is already released locally: canceling would reason
	// from a false "nothing destructive happened" invariant. Refuse, and
	// name the rerun that resumes.
	code, _, stderr := h.run("recover", string(opID), "--cancel")
	if code != ExitInterrupted {
		t.Fatalf("cancel code = %d, want %d (stderr %s)", code, ExitInterrupted, stderr)
	}
	assertForgetOpPhase(t, h, opID, catalog.PhaseForgetUnpinned)
	if !strings.Contains(stderr, "ebb forget") {
		t.Errorf("refusal must name the resuming rerun:\n%s", stderr)
	}
	// The rerun still resumes and finishes the row.
	if code, _, stderr := h.run("forget", string(snap.ID), "--yes", "--last-of-parked"); code != ExitOK {
		t.Fatalf("resuming rerun code = %d (stderr %s)", code, stderr)
	}
	assertForgetOpPhase(t, h, opID, catalog.PhaseForgetDone)
}

func TestRecoverReportsForgetRowAndNamesRerun(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	opID := seedForgetCrashState(t, h, snap, catalog.PhaseForgetUnpinned)

	code, stdout, stderr := h.run("recover", "--json", string(opID))
	if code != ExitOK {
		t.Fatalf("recover code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	det := envelopeOf(t, stdout)["details"].(map[string]any)
	if det["kind"] != "forget" || det["phase_after"] != catalog.PhaseForgetUnpinned {
		t.Fatalf("details = %v", det)
	}
	if next, _ := det["next_action"].(string); !strings.Contains(next, "ebb forget") || !strings.Contains(next, string(snap.ID)) {
		t.Errorf("next_action must name the resuming rerun and the target snapshot: %q", next)
	}
}

// ---- replica honesty (T3) -----------------------------------------------

func TestForgetReplicaReceiptsNotedNotCounted(t *testing.T) {
	t.Run("a replica receipt never bypasses the guard", func(t *testing.T) {
		h := newEHarness(t)
		snap := parkedOnlySnapshot(t, h)
		if _, err := h.cat().RecordReplica(catalog.Replica{SnapshotID: snap.ID, Path: "out/capsule.ebb"}); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := h.run("forget", string(snap.ID), "--yes")
		if code != ExitBlocked {
			t.Fatalf("replica receipt bypassed the guard (code %d): %s", code, stderr)
		}
		assertBlocker(t, stderr, CodeForgetLastOfParked, "--last-of-parked")
		if !backendPresent(h, snap.PayloadBackendID) {
			t.Error("the guarded pair was mutated despite the refusal")
		}
	})

	t.Run("prompt and receipt note the receipts honestly", func(t *testing.T) {
		h := newEHarness(t)
		snap := parkedOnlySnapshot(t, h)
		if _, err := h.cat().RecordReplica(catalog.Replica{SnapshotID: snap.ID, Path: "out/capsule.ebb"}); err != nil {
			t.Fatal(err)
		}

		// Human run: the receipt carries the note (and the journaled
		// operation with its honest concurrency scope).
		code, _, stderr := h.run("forget", string(snap.ID), "--yes", "--last-of-parked")
		if code != ExitOK {
			t.Fatalf("acknowledged forget code = %d (stderr %s)", code, stderr)
		}
		for _, want := range []string{"replica", "not revalidated", "do NOT count as surviving copies"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("receipt lacks %q:\n%s", want, stderr)
			}
		}
		// T4: the receipt states the coordination scope exactly — catalog
		// level mutual exclusion, external vault mutation outside it.
		for _, want := range []string{"concurrent ebb forgets are mutually exclusive at the catalog", "changes made to the vault outside Ebb are not coordinated"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("receipt lacks the honest concurrency wording %q:\n%s", want, stderr)
			}
		}
	})
}

func TestForgetReplicaReceiptsJSONFields(t *testing.T) {
	h := newEHarness(t)
	snap := parkedOnlySnapshot(t, h)
	if _, err := h.cat().RecordReplica(catalog.Replica{SnapshotID: snap.ID, Path: "out/capsule.ebb"}); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := h.run("forget", "--json", string(snap.ID), "--yes", "--last-of-parked")
	if code != ExitOK {
		t.Fatalf("forget code = %d", code)
	}
	det := envelopeOf(t, stdout)["details"].(map[string]any)
	if n, _ := det["replica_receipts"].(float64); n != 1 {
		t.Errorf("details.replica_receipts = %v, want 1", det["replica_receipts"])
	}
	if note, _ := det["replica_note"].(string); !strings.Contains(note, "not revalidated") {
		t.Errorf("details.replica_note = %q", note)
	}
	if id, _ := det["operation_id"].(string); id == "" {
		t.Errorf("details.operation_id missing: %v", det)
	}
}

// TestForgetAdoptionBindsLogicalSnapshotID: two sealed catalog rows can
// reference the SAME backend pair (catalog reconstruction, imports,
// corruption repair). A rerun targeting logical snapshot B must never
// adopt an active forget operation belonging to logical snapshot A —
// backend ids are physical identity, not the logical recovery
// obligation (external review pre-merge fix, D060).
func TestForgetAdoptionBindsLogicalSnapshotID(t *testing.T) {
	h := newEHarness(t)
	a := parkedOnlySnapshot(t, h)
	// Same workspace, same physical pair, DIFFERENT logical row.
	bID := domain.SnapshotID(domain.NewID())
	if _, err := h.cat().RecordSnapshot(catalog.Snapshot{
		ID: bID, WorkspaceID: a.WorkspaceID,
		CreatedAt:        domain.FormatTime(time.Now().Add(time.Minute)),
		PayloadBackendID: a.PayloadBackendID, SealBackendID: a.SealBackendID,
		Kind: catalog.SnapshotKindPark, Pinned: true,
	}); err != nil {
		t.Fatal(err)
	}
	// A forget for A is active at INTENT_RECORDED with A's fingerprint.
	seedForgetCrashState(t, h, a, catalog.PhaseForgetIntentRecorded)

	code, _, stderr := h.run("forget", string(bID), "--yes", "--last-of-parked")
	if code == ExitOK {
		t.Fatal("forget of logical snapshot B adopted A's active operation — the fingerprint must bind the logical snapshot id, not only the physical pair")
	}
	if !strings.Contains(stderr, "another operation holds workspace") {
		t.Fatalf("refusal must name the active-operation conflict, stderr = %s", stderr)
	}
	// A's operation row is untouched by the refused B attempt.
	assertForgetOpPhase(t, h, mustActiveForgetOp(t, h, a.WorkspaceID), catalog.PhaseForgetIntentRecorded)
}

// mustActiveForgetOp returns the workspace's active FORGET operation id.
func mustActiveForgetOp(t *testing.T, h *eHarness, ws domain.WorkspaceID) domain.OperationID {
	t.Helper()
	ops, err := h.cat().ListOperations(ws)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range ops {
		if op.Kind == catalog.OpKindForget && op.Phase != catalog.PhaseForgetDone && op.Phase != catalog.PhaseCanceled {
			return op.ID
		}
	}
	t.Fatalf("no active forget operation for %s", ws)
	return ""
}

// ---- P0-1: physical deletion is REFERENCE-AWARE (vault-wide) ------------
//
// The new model explicitly permits two logical snapshot rows to share
// one payload/seal pair (catalog reconstruction, imports, corruption
// repair). A backend id may therefore be physically forgotten only when
// NO OTHER retained snapshot row of the vault still references it —
// across ALL workspaces, not just the target's. When a row shares an
// id, the forget releases the target's LOGICAL obligation (unpin,
// completed intent, DONE) but leaves the shared bytes in the vault and
// says so in the receipt.

// TestForgetSharedPairDoesNotDeleteOthersBytes: two pinned rows share
// the exact pair; forgetting A completes A's obligation while the
// shared P AND S remain in the backend and B stays verifiable.
func TestForgetSharedPairDoesNotDeleteOthersBytes(t *testing.T) {
	h := newEHarness(t)
	a := parkedOnlySnapshot(t, h)
	// B: a DIFFERENT logical row sharing A's exact pair (the shape
	// catalog reconstruction and imports create).
	b := seedSealedForgetRow(t, h, a.WorkspaceID, a.PayloadBackendID, a.SealBackendID, true)

	code, stdout, stderr := h.run("forget", "--json", string(a.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d — forgetting A must release A's logical obligation (stderr %s)", code, ExitOK, stderr)
	}
	// The SHARED backend pair must survive: B's recovery bytes are still
	// in the vault and still load.
	if !backendPresent(h, a.PayloadBackendID) || !backendPresent(h, a.SealBackendID) {
		t.Fatal("the shared backend pair was deleted although snapshot B still references it")
	}
	if _, lerr := h.store.Ls(context.Background(), "", "", a.PayloadBackendID); lerr != nil {
		t.Fatalf("shared payload no longer verifiable for B: %v", lerr)
	}
	// A's logical obligation IS released; B's is untouched.
	if got, err := h.cat().GetSnapshot(a.ID); err != nil || got.Pinned {
		t.Fatalf("snapshot A still pinned after its forget: %+v (%v)", got, err)
	}
	if got, err := h.cat().GetSnapshot(b.ID); err != nil || !got.Pinned {
		t.Fatalf("snapshot B row disturbed by A's forget: %+v (%v)", got, err)
	}
	// The receipt says the shared ids were kept, and the warnings say why.
	det := envelopeOf(t, stdout)["details"].(map[string]any)
	kept, _ := det["retained_shared_ids"].([]any)
	if len(kept) != 2 {
		t.Fatalf("details.retained_shared_ids = %v, want both shared ids", det["retained_shared_ids"])
	}
	env := envelopeOf(t, stdout)
	warnings, _ := env["warnings"].([]any)
	if len(warnings) == 0 {
		t.Fatalf("envelope warnings = %v, want the kept-shared-ids warning", env["warnings"])
	}
	joined := fmt.Sprint(warnings...)
	if !strings.Contains(joined, a.PayloadBackendID) || !strings.Contains(joined, "share") {
		t.Errorf("warnings must name the kept ids and the sharing reason: %v", warnings)
	}
}

// TestForgetPartiallySharedID: A→P1/S1, B→P1/S2. Forgetting A must
// delete the unshared S1 but keep the shared P1 — the reference check
// is per backend id, not per pair.
func TestForgetPartiallySharedID(t *testing.T) {
	h := newEHarness(t)
	a := parkedOnlySnapshot(t, h)
	seedSealedForgetRow(t, h, a.WorkspaceID, a.PayloadBackendID, staleHex("9a"), true)

	code, _, stderr := h.run("forget", string(a.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	if backendPresent(h, a.SealBackendID) {
		t.Error("A's own seal S1 is still present; unshared ids must be forgotten")
	}
	if !backendPresent(h, a.PayloadBackendID) {
		t.Fatal("shared payload P1 was deleted although another retained row still references it")
	}
}

// ---- P0-2: forget runs against the SNAPSHOT's bound vault ---------------
//
// Multi-vault is real (`ebb import --vault` binds Snapshot.VaultID to a
// non-default vault). A forget must resolve that binding and List/Forget
// THE BOUND vault; empty bindings (rows predating the column) keep the
// default-vault behavior, and an unresolvable binding FAILS CLOSED
// instead of silently running against the default repository.

// registerVaultAt enrolls a second registry vault plus its catalog vault
// row (the same digest derivation capture and import use) and returns
// the registry record and the row id a snapshot binds.
func registerVaultAt(t *testing.T, h *eHarness, name, repoDir string) (vault.Vault, domain.VaultID) {
	t.Helper()
	reg, err := vault.New(filepath.Join(h.stateDir, vault.RegistryFile)).Register(name, repoDir, "ecli-fake-repo")
	if err != nil {
		t.Fatalf("register %s: %v", name, err)
	}
	rowID := lifecycle.VaultIDFor("ecli-fake-repo", repoDir)
	if err := h.cat().RegisterVault(catalog.Vault{ID: rowID, Path: repoDir, RepoID: "ecli-fake-repo"}); err != nil {
		t.Fatalf("register %s catalog row: %v", name, err)
	}
	return reg, rowID
}

// seedSealedRowInVault registers the pair in the fake store and records
// the snapshot row bound to the given catalog vault row id.
func seedSealedRowInVault(t *testing.T, h *eHarness, ws domain.WorkspaceID, payload, seal string, vaultRowID domain.VaultID) catalog.Snapshot {
	t.Helper()
	for _, id := range []string{payload, seal} {
		h.store.snaps[id] = &eFakeSnap{
			files: map[string][]byte{}, dirs: map[string]bool{}, links: map[string]string{},
		}
	}
	row := catalog.Snapshot{
		ID:               domain.SnapshotID(domain.NewID()),
		WorkspaceID:      ws,
		PayloadBackendID: payload,
		SealBackendID:    seal,
		VaultID:          vaultRowID,
		Kind:             catalog.SnapshotKindSnapshot,
	}
	if _, err := h.cat().RecordSnapshot(row); err != nil {
		t.Fatalf("seed sealed row bound to %s: %v", vaultRowID, err)
	}
	return row
}

func TestForgetNonDefaultVaultTargetsItsVault(t *testing.T) {
	h := newEHarness(t)
	// A LIVE workspace with a real default-vault snapshot keeps the
	// last-of-parked guard out of play.
	snap := forgettableSnapshot(t, h)
	base := filepath.Dir(h.stateDir)
	v2, v2RowID := registerVaultAt(t, h, "vault2", filepath.Join(base, "vault2"))
	v2snap := seedSealedRowInVault(t, h, snap.WorkspaceID, staleHex("c1"), staleHex("c2"), v2RowID)

	code, stdout, stderr := h.run("forget", "--json", string(v2snap.ID), "--yes")
	if code != ExitOK {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitOK, stderr)
	}
	// The List/Forget calls ran against vault TWO — never the default.
	if len(h.store.forgetRepoDirs) != 1 || h.store.forgetRepoDirs[0] != v2.RepoDir {
		t.Fatalf("forget ran against %v, want exactly the bound vault %s", h.store.forgetRepoDirs, v2.RepoDir)
	}
	if len(h.store.listRepoDirs) == 0 {
		t.Fatal("no backend Lists recorded")
	}
	for _, dir := range h.store.listRepoDirs {
		if dir != v2.RepoDir {
			t.Fatalf("List ran against %q, want only the snapshot's bound vault %s", dir, v2.RepoDir)
		}
	}
	if backendPresent(h, v2snap.PayloadBackendID) || backendPresent(h, v2snap.SealBackendID) {
		t.Error("V2 pair still present after forget")
	}
	// The receipt names the vault the forget actually ran against.
	det := envelopeOf(t, stdout)["details"].(map[string]any)
	if id, _ := det["vault_id"].(string); id != v2.ID {
		t.Errorf("details.vault_id = %v, want the bound registry vault %s", det["vault_id"], v2.ID)
	}
}

func TestForgetCryptoVaultUnresolvableFailsClosed(t *testing.T) {
	h := newEHarness(t)
	snap := forgettableSnapshot(t, h)
	base := filepath.Dir(h.stateDir)
	ghostDir := filepath.Join(base, "ghost-vault")
	ghostRowID := lifecycle.VaultIDFor("ecli-fake-repo", ghostDir)
	// The CATALOG knows the vault row (the FK needs it), but NO
	// registered vault backs it: the binding cannot be resolved.
	if err := h.cat().RegisterVault(catalog.Vault{ID: ghostRowID, Path: ghostDir, RepoID: "ecli-fake-repo"}); err != nil {
		t.Fatal(err)
	}
	ghost := seedSealedRowInVault(t, h, snap.WorkspaceID, staleHex("e1"), staleHex("e2"), ghostRowID)

	code, _, stderr := h.run("forget", string(ghost.ID), "--yes")
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d — forget must FAIL CLOSED on an unresolvable vault, never fall back to the default (stderr %s)", code, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, ghostDir) && !strings.Contains(stderr, string(ghostRowID)) {
		t.Errorf("refusal must name the unresolvable vault:\n%s", stderr)
	}
	// Nothing ran against ANY vault, and the bytes are untouched.
	if len(h.store.forgetRepoDirs) != 0 {
		t.Fatalf("forget calls ran against %v; an unresolvable binding must not reach the backend", h.store.forgetRepoDirs)
	}
	if !backendPresent(h, ghost.PayloadBackendID) || !backendPresent(h, ghost.SealBackendID) {
		t.Fatal("the unresolvable vault's pair was forgotten through a fallback")
	}
	if got, err := h.cat().GetSnapshot(ghost.ID); err != nil || !got.Pinned {
		t.Fatalf("ghost snapshot row disturbed: %+v (%v)", got, err)
	}
	if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
		t.Errorf("retention intents recorded despite the fail-closed refusal: %v", pending)
	}
}
