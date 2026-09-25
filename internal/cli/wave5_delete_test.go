// wave5_delete_test.go: the Wave 5 safety round's `ebb delete` block.
// Two families, spec'd BEFORE the fix:
//
//   - Wrong-vault false success: delete ran every target against the
//     DEFAULT vault unconditionally, so a snapshot bound (import
//     --vault) to a non-default vault found "already absent" there —
//     unpinned, intent completed, exit 0 — while its bytes sat in its
//     own vault. The minimal fix refuses any target set that is not
//     ENTIRELY default-vault-bound, naming the topology and the
//     vault-safe per-snapshot path (`ebb forget <snapshot-id>`).
//   - Receipt truthfulness (reference-aware deletion): a default-vault
//     target sharing backend ids with a retained row keeps those ids —
//     the receipt must say KEPT and never claim "forgotten and verified
//     gone".

package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// TestDeleteNonDefaultVaultRefuses: a snapshot bound to a non-default
// vault is refused by `ebb delete` — by id and inside a mixed
// workspace-name target set — with zero Forget calls and an untouched
// catalog; the refusal names the vault topology and `ebb forget`.
func TestDeleteNonDefaultVaultRefuses(t *testing.T) {
	t.Run("a bound snapshot addressed by id refuses", func(t *testing.T) {
		h := newEHarness(t)
		snap := forgettableSnapshot(t, h) // keeps the workspace LIVE (guard quiet)
		base := filepath.Dir(h.stateDir)
		v2, v2Row := registerVaultAt(t, h, "vault2", filepath.Join(base, "vault2"))
		v2snap := seedSealedRowInVault(t, h, snap.WorkspaceID, staleHex("aa"), staleHex("bb"), v2Row)

		code, _, stderr := h.run("delete", string(v2snap.ID), "--yes")
		if code != ExitBlocked {
			t.Fatalf("code = %d, want %d — delete must not run a non-default-bound snapshot against the default vault (stderr %s)", code, ExitBlocked, stderr)
		}
		if !strings.Contains(stderr, CodeDeleteForeignVault) {
			t.Errorf("refusal must carry the stable code:\n%s", stderr)
		}
		for _, want := range []string{string(v2snap.ID), v2.RepoDir, "ebb forget"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("refusal must name %q (the topology and the vault-safe path):\n%s", want, stderr)
			}
		}
		// Nothing ran, nothing changed.
		if len(h.store.forgetRepoDirs) != 0 {
			t.Fatalf("Forget ran against %v; a refused delete must not reach the backend", h.store.forgetRepoDirs)
		}
		if len(h.store.pruneCalls) != 0 {
			t.Errorf("prune ran despite the refusal: %v", h.store.pruneCalls)
		}
		if !backendPresent(h, v2snap.PayloadBackendID) || !backendPresent(h, v2snap.SealBackendID) {
			t.Fatal("the V2-bound pair was deleted through the default vault")
		}
		if got, err := h.cat().GetSnapshot(v2snap.ID); err != nil || !got.Pinned {
			t.Fatalf("snapshot row disturbed: %+v (%v)", got, err)
		}
		if pending, _ := h.cat().PendingRetentionIntents(); len(pending) != 0 {
			t.Errorf("retention intents recorded despite the refusal: %v", pending)
		}
	})

	t.Run("a mixed workspace target set refuses whole", func(t *testing.T) {
		h := newEHarness(t)
		snap := forgettableSnapshot(t, h) // default-bound snapshot of "cliws"
		base := filepath.Dir(h.stateDir)
		_, v2Row := registerVaultAt(t, h, "vault2", filepath.Join(base, "vault2"))
		v2snap := seedSealedRowInVault(t, h, snap.WorkspaceID, staleHex("cc"), staleHex("dd"), v2Row)

		code, _, stderr := h.run("delete", "cliws", "--yes")
		if code != ExitBlocked {
			t.Fatalf("code = %d, want %d — a MIXED target set must refuse whole (stderr %s)", code, ExitBlocked, stderr)
		}
		if !strings.Contains(stderr, CodeDeleteForeignVault) || !strings.Contains(stderr, string(v2snap.ID)) {
			t.Errorf("refusal must name the foreign-bound snapshot:\n%s", stderr)
		}
		// The DEFAULT-bound snapshot of the same workspace was not swept
		// up either: the refusal covers the whole delete.
		if len(h.store.forgetRepoDirs) != 0 {
			t.Fatalf("Forget ran against %v; the whole delete must refuse", h.store.forgetRepoDirs)
		}
		if !backendPresent(h, snap.PayloadBackendID) || !backendPresent(h, snap.SealBackendID) {
			t.Error("the default-bound snapshot was deleted by the refused mixed delete")
		}
		if !backendPresent(h, v2snap.PayloadBackendID) {
			t.Error("the V2-bound snapshot was deleted by the refused mixed delete")
		}
	})
}

// TestDeleteSharedIDReceiptTruthful: a default-vault target whose
// backend pair is shared with another retained row keeps both ids
// (reference-aware deletion). The receipt must say KEPT and must NOT
// claim "forgotten and verified gone" — in the human report and in the
// JSON envelope alike.
func TestDeleteSharedIDReceiptTruthful(t *testing.T) {
	t.Run("human receipt names the kept ids", func(t *testing.T) {
		h := newEHarness(t)
		a := forgettableSnapshot(t, h)
		// B: a retained row (RecordSnapshot pins) sharing A's exact pair.
		b := seedSealedForgetRow(t, h, a.WorkspaceID, a.PayloadBackendID, a.SealBackendID, true)

		code, _, stderr := h.run("delete", string(a.ID), "--yes")
		if code != ExitOK {
			t.Fatalf("code = %d, want %d (stderr %s)", code, ExitOK, stderr)
		}
		// The shared pair survived: B's recovery bytes are intact.
		if !backendPresent(h, a.PayloadBackendID) || !backendPresent(h, a.SealBackendID) {
			t.Fatal("the shared pair was deleted although a retained row still shares it")
		}
		if got, err := h.cat().GetSnapshot(b.ID); err != nil || !got.Pinned {
			t.Fatalf("sharing row disturbed: %+v (%v)", got, err)
		}
		// A's obligation IS released.
		if got, err := h.cat().GetSnapshot(a.ID); err != nil || got.Pinned {
			t.Fatalf("target row still pinned: %+v (%v)", got, err)
		}
		// The receipt tells the truth: kept, never "verified gone".
		if strings.Contains(stderr, "forgotten and verified gone") {
			t.Errorf("receipt claims 'forgotten and verified gone' although shared ids were kept:\n%s", stderr)
		}
		for _, want := range []string{
			"was KEPT in the vault",
			a.PayloadBackendID + " was KEPT",
			a.SealBackendID + " was KEPT",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("receipt lacks %q:\n%s", want, stderr)
			}
		}
	})

	t.Run("json envelope carries the kept ids and warnings", func(t *testing.T) {
		h := newEHarness(t)
		a := forgettableSnapshot(t, h)
		seedSealedForgetRow(t, h, a.WorkspaceID, a.PayloadBackendID, a.SealBackendID, true)

		code, stdout, _ := h.run("delete", "--json", string(a.ID), "--yes")
		if code != ExitOK {
			t.Fatalf("code = %d, want %d", code, ExitOK)
		}
		env := envelopeOf(t, stdout)
		det := env["details"].(map[string]any)
		kept, _ := det["retained_shared_ids"].([]any)
		if len(kept) != 2 {
			t.Fatalf("details.retained_shared_ids = %v, want both shared ids", det["retained_shared_ids"])
		}
		warnings, _ := env["warnings"].([]any)
		joined := fmt.Sprint(warnings...)
		if !strings.Contains(joined, a.PayloadBackendID) || !strings.Contains(joined, "share") {
			t.Errorf("warnings must name the kept ids and the sharing reason: %v", warnings)
		}
	})
}
