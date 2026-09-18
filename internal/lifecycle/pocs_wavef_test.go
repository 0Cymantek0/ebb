//go:build security_poc

// Wave F adversarial security PoCs (lifecycle package, in-package so the
// unexported removal-authority seams are reachable). Opt-in via
// -tags security_poc so the default suite stays green by design (Wave C
// precedent, lab/security-review).
//
// F1  Tampered retained documents (P's manifest/inventory) steer
//
//	Recover/ResumeRemoval into deleting files OUTSIDE the quarantine:
//	parseInventoryLines and the trim-plan re-read never validate entry
//	paths (Foundation §13.4 requires rejecting traversal), and the
//	catalog row's seal-time Manifest/Inventory digests are never
//	cross-checked on the resume path.
//
// F2  Retained trim-plan Outputs feed removeEmptyAncestors unvalidated:
//
//	a tampered plan climbs outside the live root and deletes empty
//	directories there.
//
// F3  removeEmptyAncestors violates the no-follow discipline: os.ReadDir
//
//	follows a junction substituted for an ancestor, and the junction
//	link (user content, not a sealed member) is removed.
//
// F5  Crash window between the quarantine rename and the QUARANTINED CAS
//
//	commit leaves an unreconcilable SEALED operation: Recover reports
//	"source changed", never looks for its own quarantine, and the
//	workspace is locked (ErrOpInProgress) until manual catalog surgery.
//
// F6  preflight's vault/root overlap check is lexical: a root spelled
//
//	through a junction alias that points INSIDE the vault repository
//	passes (I06 "cannot overlap through aliases unnoticed" gap).
//
// F7  Recover (no --resume-removal) auto-resumes a REMOVING walk without
//
//	any writer-condition reconfirmation (§12.4 QUARANTINED row requires
//	"reconfirm identities and writer condition" — only identity is).
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/inventory"
)

// ---- F1 -----------------------------------------------------------------

// TestPoC parseInventoryLines accepts traversal entries: the strict JSON
// reader rejects unknown FIELDS but never runs domain.Entry.Validate, so
// "../precious-victim.txt" parses into an Entry that later reaches the
// removal permit.
func TestPoCRetainedInventoryTraversalParses(t *testing.T) {
	line, err := json.Marshal(inventoryRecord{Entry: domain.Entry{
		Root: domain.RootMain, Path: "../precious-victim.txt",
		Kind: domain.KindFile, LogicalSize: 30,
		Digest:      strings.Repeat("a", 64),
		Ownership:   domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary,
		Route:       domain.RoutePreserve,
	}})
	if err != nil {
		t.Fatal(err)
	}
	entries, perr := parseInventoryLines(append(line, '\n'))
	if perr != nil {
		t.Fatalf("parseInventoryLines rejected the hostile line: %v", perr)
	}
	if len(entries) != 1 || entries[0].Path != "../precious-victim.txt" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if verr := entries[0].Validate(); verr == nil {
		t.Log("note: Validate() accepts this shape too (no '..' at position 0? recheck domain)")
	} else {
		t.Logf("domain.Entry.Validate WOULD reject it (%v) — but parseInventoryLines never calls it", verr)
	}
	t.Errorf("F1 CONFIRMED: lifecycle's retained-inventory reader accepts a traversal entry (../precious-victim.txt) without validation; restore's parseInventory rejects the same line")
}

// TestPoCTamperedPayloadDeletesOutsideQuarantine — end-to-end F1: park is
// interrupted mid-removal (phase REMOVING); the vault's retained payload
// documents are then tampered to be internally self-consistent (exactly
// what an attacker with vault write access + the vault password can
// produce); `Recover` on a fresh coordinator resumes the removal walk and
// DELETES a file outside the quarantine — with a matching per-entry digest,
// because the attacker hashed the victim.
func TestPoCTamperedPayloadDeletesOutsideQuarantine(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	// Interrupt the park mid-removal: cancel the context during the
	// second per-entry probe INSIDE the quarantine (the walk removes
	// entry 1, then observes the cancel at entry 2's loop head).
	ctx, cancel := context.WithCancel(context.Background())
	quarProbes := 0
	h.probe.onProbeFile = func(path string) {
		if !strings.Contains(filepath.ToSlash(path), "/"+quarantinePrefix) {
			return // capture-time probes use the live root path
		}
		quarProbes++
		if quarProbes == 2 {
			cancel()
		}
	}
	if _, err := h.coord().Park(ctx, h.vault, root, parkOpts(ws)); err == nil {
		t.Fatal("expected the interrupted park to fail")
	}
	cancel()
	opID := h.opIDOf(t, ws)
	if phase := h.phaseOf(t, opID); phase != catalog.PhaseRemoving {
		t.Fatalf("phase after interruption = %s, want REMOVING", phase)
	}

	// The victim: a user file OUTSIDE the workspace, sibling of the root.
	victim := filepath.Join(h.base, "work", "precious-victim.txt")
	victimData := []byte("user data outside any Ebb removal authority\n")
	if err := os.WriteFile(victim, victimData, 0o644); err != nil {
		t.Fatal(err)
	}
	victimDigest, err := digestFile(victim)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper P's retained documents in the vault (fake store = on-disk
	// snapshot trees under <repo>/snap/<id>/...): append the hostile
	// entry to inventory.jsonl and patch the manifest's inventory digest
	// + count so loadPayloadEvidence's self-consistency checks pass.
	c := h.coord()
	op, err := c.cat.GetOperation(opID)
	if err != nil {
		t.Fatal(err)
	}
	snapInv := filepath.Join(h.vault.RepoDir, "snap", op.PayloadSnap, opDirName(opID), inventoryName)
	invBytes, err := os.ReadFile(snapInv)
	if err != nil {
		t.Fatal(err)
	}
	hostile, err := json.Marshal(inventoryRecord{Entry: domain.Entry{
		Root: domain.RootMain, Path: "../precious-victim.txt",
		Kind: domain.KindFile, LogicalSize: int64(len(victimData)),
		Digest:      victimDigest,
		Ownership:   domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary,
		Route:       domain.RoutePreserve,
		Evidence:    []string{"inventory.scan"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	invBytes = append(invBytes, append(hostile, '\n')...)
	if err := os.WriteFile(snapInv, invBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	// Count the original records for the manifest patch.
	origEntries, perr := parseInventoryLines(invBytes)
	if perr != nil {
		t.Fatal(perr)
	}
	patchManifestDigest(t,
		filepath.Join(h.vault.RepoDir, "snap", op.PayloadSnap, opDirName(opID), manifestName),
		digestBytes(invBytes), int64(len(origEntries)))

	// Fresh coordinator (new-process simulation) runs plain Recover —
	// NO --resume-removal, no writer re-assertion (also F7 evidence).
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("Recover failed: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseAfter != catalog.PhaseDone {
		t.Fatalf("phase after recover = %s, want DONE", rep.PhaseAfter)
	}
	if _, serr := os.Lstat(victim); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("F1 CONFIRMED: victim %s still exists — walk did not delete it (unexpected)", victim)
	}
	t.Errorf("F1 CONFIRMED: Recover completed the removal walk and DELETED %s (outside the quarantine); phase DONE; every check in loadPayloadEvidence passed on the tampered, self-consistent documents", victim)
}

func patchManifestDigest(t *testing.T, manifestPath, newInvDigest string, count int64) {
	t.Helper()
	mb, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(mb, &doc); err != nil {
		t.Fatal(err)
	}
	inv, _ := doc["inventory"].(map[string]any)
	if inv == nil {
		t.Fatal("manifest has no inventory object")
	}
	inv["digest"] = newInvDigest
	inv["count"] = count
	nb, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(nb, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// ---- F2 -----------------------------------------------------------------

// TestPoCTrimOutputsClimbOutsideRoot: permit.removeEmptyAncestors with a
// retained-plan Outputs entry containing ".." (possible only via a
// tampered/corrupt removal manifest — the policy layer validates fresh
// trims, resumeTrimRemoval does not re-validate) removes empty
// directories OUTSIDE the live root.
func TestPoCTrimOutputsClimbOutsideRoot(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")

	// A minimal permit: one real member (so the allowed set is non-empty).
	res := inventory.Scan(context.Background(), h.probe.PlatformProbe, root, inventory.Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	allowed := map[string]domain.Entry{}
	for _, e := range res.Entries {
		if e.Kind == domain.KindFile {
			allowed[e.Path] = e
			break
		}
	}
	ident, err := h.probe.PlatformProbe.RootIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := newRemovalPermit(domain.OperationID(domain.NewID()), domain.SnapshotID(domain.NewID()), root, ident, allowed)
	if err != nil {
		t.Fatal(err)
	}

	// Empty directories OUTSIDE the root (siblings of the workspace).
	outA := filepath.Join(h.base, "work", "outside-empty", "deep")
	if err := os.MkdirAll(outA, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := permit.removeEmptyAncestors([]string{"../outside-empty/deep/output"}, nil); err != nil {
		t.Fatalf("removeEmptyAncestors: %v", err)
	}
	if _, serr := os.Lstat(outA); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("outside dir %s still exists (unexpected)", outA)
	}
	if _, serr := os.Lstat(filepath.Join(h.base, "work", "outside-empty")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("outside dir parent still exists (unexpected)")
	}
	t.Errorf("F2 CONFIRMED: unvalidated trim Outputs removed empty directories outside the live root (%s)", outA)
}

// ---- F3 (Windows: junction) ----------------------------------------------

// TestPoCAncestorWalkFollowsJunction: an ancestor directory replaced by a
// junction is READ THROUGH (os.ReadDir follows the link outside the root)
// and then the junction link itself — user content that is not a sealed
// group member — is removed. §12.2 step 8 requires no-follow operations.
func TestPoCAncestorWalkFollowsJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction fixture is windows-only")
	}
	h := newHarness(t)
	root := h.workspace("ws")

	res := inventory.Scan(context.Background(), h.probe.PlatformProbe, root, inventory.Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	allowed := map[string]domain.Entry{}
	for _, e := range res.Entries {
		if e.Kind == domain.KindFile {
			allowed[e.Path] = e
			break
		}
	}
	ident, err := h.probe.PlatformProbe.RootIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	permit, err := newRemovalPermit(domain.OperationID(domain.NewID()), domain.SnapshotID(domain.NewID()), root, ident, allowed)
	if err != nil {
		t.Fatal(err)
	}

	// g/ is a retained directory (no members under it) holding one file.
	if err := os.MkdirAll(filepath.Join(root, "g"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "g", "user.txt"), []byte("user's own file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Replace g/ with a junction to an EMPTY outside directory (the
	// substitution the permit's kind checks exist to catch — but
	// removeEmptyAncestors performs no kind check).
	if err := os.Remove(filepath.Join(root, "g", "user.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "g")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(h.base, "outside-target")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "g"), outside).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}

	if err := permit.removeEmptyAncestors([]string{"g/x"}, nil); err != nil {
		t.Fatalf("removeEmptyAncestors: %v", err)
	}
	if _, serr := os.Lstat(filepath.Join(root, "g")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatalf("junction at root/g still exists (unexpected — no deletion happened)")
	}
	if _, serr := os.Lstat(outside); serr != nil {
		t.Fatalf("outside target damaged: %v", serr)
	}
	t.Errorf("F3 CONFIRMED: removeEmptyAncestors followed the substituted junction outside the root for its emptiness decision and removed the junction link (non-member user content) without any kind/no-follow check")
}

// ---- F5 -----------------------------------------------------------------

// TestPoCSealedQuarantineCrashWindow: durable state SEALED + quarantine
// present + root absent (crash between the quarantine rename and the
// QUARANTINED CAS commit — reproduced by driving capture() and performing
// only the rename). Recover reports "source changed", leaves the operation
// SEALED, never considers its own quarantine sibling, and the workspace
// stays locked against every future park.
func TestPoCSealedQuarantineCrashWindow(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	c := h.coord()
	st, err := c.capture(context.Background(), h.vault, root, parkOpts(ws), catalog.OpKindPark, catalog.SnapshotKindPark)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	defer st.journal.close()
	if h.phaseOf(t, st.opID) != catalog.PhaseSealed {
		t.Fatalf("phase = %s, want SEALED", h.phaseOf(t, st.opID))
	}
	// The crash point: the rename happened, nothing after it did.
	quar := quarantinePath(st.parent, st.opID)
	if err := renameToQuarantine(root, quar); err != nil {
		t.Fatal(err)
	}

	rep, rerr := h.coord().Recover(context.Background(), h.vault, st.opID)
	if rerr != nil {
		t.Fatalf("Recover errored: %v", rerr)
	}
	if rep.PhaseAfter != catalog.PhaseSealed {
		t.Fatalf("phase after recover = %s, want SEALED (report-only)", rep.PhaseAfter)
	}
	foundQuarantine := false
	for _, a := range rep.Actions {
		if strings.Contains(a, "quarantine") {
			foundQuarantine = true
		}
	}
	if foundQuarantine {
		t.Fatalf("unexpected: recover noticed the quarantine")
	}
	if !strings.Contains(strings.Join(rep.Remaining, " "), "source") {
		t.Logf("remaining: %v", rep.Remaining)
	}

	// Even after the user manually restores the original name, the SEALED
	// operation permanently blocks the workspace (F37 single-op lock).
	if err := os.Rename(quar, root); err != nil {
		t.Fatal(err)
	}
	if _, perr := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws)); perr == nil {
		t.Fatal("re-park unexpectedly succeeded")
	} else {
		var inProgress *ErrOpInProgress
		if !errors.As(perr, &inProgress) {
			t.Fatalf("re-park failed with %v, want ErrOpInProgress", perr)
		}
	}
	t.Errorf("F5 CONFIRMED: SEALED+quarantine crash window is unreconcilable — Recover never inspects the quarantine sibling and the workspace is locked by the dead operation until manual catalog surgery")
}

// ---- F6 (Windows: junction) ----------------------------------------------

// TestPoCPreflightJunctionAliasMissesVaultOverlap: a workspace root that
// lives INSIDE the vault repository is blocked when spelled directly, but
// passes preflight when spelled through a junction alias — the lexical
// comparison never resolves the alias (I06).
func TestPoCPreflightJunctionAliasMissesVaultOverlap(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction fixture is windows-only")
	}
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(vaultDir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	ref := VaultRef{RepoDir: vaultDir, Passfile: filepath.Join(base, "pass")}

	// Root-inside-vault: preflight checks only the OTHER direction
	// (vault inside root), so even the DIRECT spelling passes.
	if err := preflight(ws, ref); err != nil {
		t.Fatalf("direct spelling of a root inside the vault was blocked: %v (unexpected — the gap is narrower than thought)", err)
	}
	t.Logf("direct spelling %s INSIDE the vault repository passed preflight (only vault-inside-root is checked)", ws)

	// Alias spelling: junction base/link -> base/vault, root via the link.
	link := filepath.Join(base, "link")
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, vaultDir).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}
	if err := preflight(filepath.Join(link, "ws"), ref); err != nil {
		t.Fatalf("alias spelling was blocked: %v (unexpected — gap closed?)", err)
	}
	t.Errorf("F6 CONFIRMED: preflight accepted a workspace root that lives INSIDE the vault repository, in both the direct spelling and a junction-alias spelling — the overlap check covers only vault-inside-root and is lexical (I06: aliases go unnoticed)")
}

// ---- helpers -------------------------------------------------------------

var _ = fmt.Sprintf // keep fmt available for PoC extensions
