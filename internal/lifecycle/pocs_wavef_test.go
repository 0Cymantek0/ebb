//go:build security_poc

// Wave F adversarial security PoCs (lifecycle package, in-package so the
// unexported removal-authority seams are reachable). Opt-in via
// -tags security_poc so the default suite stays green by design (Wave C
// precedent, lab/security-review).
//
// F1  FIXED (Wave F secfix, regression form): retained-document re-reads
//
//	now validate every entry (Entry.Validate) AND cross-check the
//	catalog's seal-time manifest/inventory digests; the removal permit
//	re-validates entry paths as the last gate. The PoCs below assert
//	the tampered-payload attacks are REFUSED with the victim intact.
//
// F2  FIXED (regression form): removeEmptyAncestors path-validates every
//
//	plan-supplied output before climbing.
//
// F3  FIXED (regression form): the ancestor climb classifies via Lstat
//
//	first and never follows or removes a link.
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

// TestPoCRetainedInventoryTraversalParses (FIXED, regression form): the
// retained-inventory reader must reject a traversal entry with a typed
// journal-mismatch error — never parse it into an Entry that could reach
// a removal permit.
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
	_, perr := parseInventoryLines(append(line, '\n'))
	if perr == nil {
		t.Fatalf("F1 REGRESSION: parseInventoryLines accepted a traversal entry (../precious-victim.txt) — validation lost")
	}
	var jm *ErrJournalMismatch
	if !errors.As(perr, &jm) {
		t.Fatalf("rejection is not a typed ErrJournalMismatch: %v", perr)
	}
	if !strings.Contains(perr.Error(), "precious-victim.txt") {
		t.Fatalf("rejection does not name the offending path: %v", perr)
	}
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
	// Count the original records for the manifest patch (counting only —
	// the validating reader correctly refuses the tampered line).
	origCount := 0
	for _, line := range strings.Split(string(invBytes), "\n") {
		if line != "" {
			origCount++
		}
	}
	patchManifestDigest(t,
		filepath.Join(h.vault.RepoDir, "snap", op.PayloadSnap, opDirName(opID), manifestName),
		digestBytes(invBytes), int64(origCount))

	// Fresh coordinator (new-process simulation) runs plain Recover —
	// the tampered, internally self-consistent documents must now be
	// REFUSED: the catalog's seal-time digests disagree with the
	// tampered inventory (and the traversal entry itself fails
	// validation first). Nothing outside the quarantine is touched.
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr == nil {
		t.Fatalf("F1 REGRESSION: Recover accepted tampered documents (phase after=%s)", rep.PhaseAfter)
	}
	var jm *ErrJournalMismatch
	if !errors.As(rerr, &jm) {
		t.Fatalf("Recover refusal is not a typed ErrJournalMismatch: %v", rerr)
	}
	if phase := h.phaseOf(t, opID); phase == catalog.PhaseDone {
		t.Fatalf("F1 REGRESSION: operation reached DONE on tampered evidence")
	}
	if _, serr := os.Lstat(victim); serr != nil {
		t.Fatalf("F1 REGRESSION: victim %s was deleted: %v", victim, serr)
	}
	if _, serr := os.Lstat(quarantinePath(filepath.Dir(root), opID)); serr != nil {
		t.Fatalf("quarantine content disturbed by the refused recovery: %v", serr)
	}
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

// TestPoCTrimOutputsClimbOutsideRoot (FIXED, regression form): a
// retained-plan Outputs entry containing ".." must be REFUSED by
// removeEmptyAncestors's path validation before any climb; nothing
// outside the live root is touched.
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
	if err := permit.removeEmptyAncestors([]string{"../outside-empty/deep/output"}, nil); err == nil {
		t.Fatalf("F2 REGRESSION: removeEmptyAncestors accepted a traversal output")
	}
	if _, serr := os.Lstat(outA); serr != nil {
		t.Fatalf("F2 REGRESSION: outside dir %s was removed: %v", outA, serr)
	}
	if _, serr := os.Lstat(filepath.Join(h.base, "work", "outside-empty")); serr != nil {
		t.Fatalf("F2 REGRESSION: outside dir parent was removed: %v", serr)
	}
}

// ---- F3 (Windows: junction) ----------------------------------------------

// TestPoCAncestorWalkFollowsJunction (FIXED, regression form): an
// ancestor directory replaced by a junction must STOP the climb — the
// link is user content, never read through and never removed (§12.2
// step 8 no-follow).
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

	// g/ is a retained directory (no members under it), replaced by a
	// junction to an EMPTY outside directory.
	if err := os.MkdirAll(filepath.Join(root, "g"), 0o700); err != nil {
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
		t.Fatalf("removeEmptyAncestors errored on a legitimate output: %v", err)
	}
	if _, serr := os.Lstat(filepath.Join(root, "g")); serr != nil {
		t.Fatalf("F3 REGRESSION: the junction at root/g was removed: %v", serr)
	}
	if _, serr := os.Lstat(outside); serr != nil {
		t.Fatalf("F3 REGRESSION: outside target damaged: %v", serr)
	}
}

// ---- F5 -----------------------------------------------------------------

// TestPoCSealedQuarantineCrashWindow (FIXED, regression form): durable
// state SEALED + quarantine present + root absent (crash between the
// quarantine rename and the QUARANTINED CAS commit — reproduced by
// driving capture() and performing only the rename). Recover must probe
// its own quarantine sibling, verify its identity, commit SEALED ->
// QUARANTINED and reconcile the walk to completion — the workspace is
// never left locked by a dead operation.
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
	if rep.PhaseAfter != catalog.PhaseDone {
		t.Fatalf("F5 REGRESSION: phase after recover = %s, want DONE (the crash window must reconcile; report %+v)", rep.PhaseAfter, rep)
	}
	foundQuarantine := false
	for _, a := range rep.Actions {
		if strings.Contains(a, quarantinePrefix) {
			foundQuarantine = true
		}
	}
	if !foundQuarantine {
		t.Fatalf("F5 REGRESSION: recover never mentions the quarantine sibling:\n%v", rep.Actions)
	}
	mustLstatErrNotExist(t, quar)
	mustLstatErrNotExist(t, root)
	if got := h.phaseOf(t, st.opID); got != catalog.PhaseDone {
		t.Fatalf("F5 REGRESSION: op phase = %s, want DONE", got)
	}
	// The workspace is unlocked: the dead operation no longer blocks it.
	if n := activeCount(t, h.coord(), ws); n != 0 {
		t.Fatalf("F5 REGRESSION: workspace still carries %d active operation(s) after reconciliation", n)
	}
}

// ---- F6 (Windows: junction) ----------------------------------------------

// TestPoCPreflightJunctionAliasMissesVaultOverlap (FIXED, regression
// form): a workspace root that lives INSIDE the vault repository must be
// refused in BOTH the direct spelling and a junction-alias spelling —
// preflight canonicalizes both sides and checks both directions (I06).
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

	// Root-inside-vault, direct spelling: refused.
	if err := preflight(ws, ref); err == nil {
		t.Fatalf("F6 REGRESSION: the direct spelling of a root inside the vault passed preflight")
	} else {
		var blocked *ErrDestructiveBlocked
		if !errors.As(err, &blocked) {
			t.Fatalf("refusal is not ErrDestructiveBlocked: %v", err)
		}
	}

	// Alias spelling: junction base/link -> base/vault, root via the
	// link: refused (canonicalPath resolves the junction).
	link := filepath.Join(base, "link")
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, vaultDir).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}
	if err := preflight(filepath.Join(link, "ws"), ref); err == nil {
		t.Fatalf("F6 REGRESSION: the junction-alias spelling of a root inside the vault passed preflight (I06: aliases must not go unnoticed)")
	}
}

// ---- helpers -------------------------------------------------------------

var _ = fmt.Sprintf // keep fmt available for PoC extensions
