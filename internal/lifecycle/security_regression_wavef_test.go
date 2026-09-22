package lifecycle

// Regression tests for the Wave F security review fixes (F1/F2/F3,
// lab/security-review/wave-F/FINDINGS.md). These run in the DEFAULT
// suite so the hardened behavior is continuously protected; the
// security_poc-tagged twins demonstrate the original attacks.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/inventory"
)

// TestRetainedInventoryRejectsTraversalEntries (F1a): the retained
// inventory reader must reject a traversal entry with a typed
// ErrJournalMismatch naming the path.
func TestRetainedInventoryRejectsTraversalEntries(t *testing.T) {
	// Hostile forms Entry.Validate rejects. A LEADING SLASH is not in
	// the list: filepath.Join anchors it under basePath (no escape),
	// and the domain contract deliberately tolerates it.
	hostile := []string{"../victim.txt", `C:\drive.txt`, `back\slash.txt`, "a/../../b", "trailing/..", "nul\x00byte"}
	for _, p := range hostile {
		line, err := json.Marshal(inventoryRecord{Entry: domain.Entry{
			Root: domain.RootMain, Path: p, Kind: domain.KindFile,
			Digest: strings.Repeat("a", 64), Ownership: domain.OwnershipOwned,
			Sensitivity: domain.SensitivityOrdinary, Route: domain.RoutePreserve,
		}})
		if err != nil {
			t.Fatal(err)
		}
		_, perr := parseInventoryLines(append(line, '\n'))
		if perr == nil {
			t.Errorf("path %q: parseInventoryLines accepted a hostile entry", p)
			continue
		}
		var jm *ErrJournalMismatch
		if !errors.As(perr, &jm) {
			t.Errorf("path %q: rejection is not ErrJournalMismatch: %v", p, perr)
		}
	}
	// A legitimate line still parses.
	ok, err := json.Marshal(inventoryRecord{Entry: domain.Entry{
		Root: domain.RootMain, Path: "src/main.go", Kind: domain.KindFile,
		LogicalSize: 3, Digest: strings.Repeat("b", 64), Ownership: domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary, Route: domain.RoutePreserve,
	}})
	if err != nil {
		t.Fatal(err)
	}
	entries, perr := parseInventoryLines(append(ok, '\n'))
	if perr != nil || len(entries) != 1 || entries[0].Path != "src/main.go" {
		t.Fatalf("legitimate line rejected: entries=%v err=%v", entries, perr)
	}
}

// TestRecoverRefusesTamperedPayloadDocuments (F1, end to end): a park
// interrupted at REMOVING, whose vault payload documents are tampered to
// be internally self-consistent (matching digest of the victim!), must
// be REFUSED by a fresh coordinator; the victim outside the quarantine
// survives and the operation never reaches DONE.
func TestRecoverRefusesTamperedPayloadDocuments(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	ctx, cancel := context.WithCancel(context.Background())
	quarProbes := 0
	h.probe.onProbeFile = func(path string) {
		if !strings.Contains(filepath.ToSlash(path), "/"+quarantinePrefix) {
			return
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

	victim := filepath.Join(h.base, "work", "precious-victim.txt")
	victimData := []byte("user data outside any Ebb removal authority\n")
	if err := os.WriteFile(victim, victimData, 0o644); err != nil {
		t.Fatal(err)
	}
	victimDigest, err := digestFile(victim)
	if err != nil {
		t.Fatal(err)
	}

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
		Digest: victimDigest, Ownership: domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary, Route: domain.RoutePreserve,
		Evidence: []string{"inventory.scan"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	invBytes = append(invBytes, append(hostile, '\n')...)
	if err := os.WriteFile(snapInv, invBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	origCount, perr := parseInventoryLinesForCount(invBytes)
	if perr != nil {
		t.Fatal(perr)
	}
	patchManifestDigestForTest(t,
		filepath.Join(h.vault.RepoDir, "snap", op.PayloadSnap, opDirName(opID), manifestName),
		digestBytes(invBytes), int64(origCount))

	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr == nil {
		t.Fatalf("Recover accepted tampered documents (phase after=%s, actions=%v)", rep.PhaseAfter, rep.Actions)
	}
	var jm *ErrJournalMismatch
	if !errors.As(rerr, &jm) {
		t.Fatalf("refusal is not ErrJournalMismatch: %v", rerr)
	}
	if phase := h.phaseOf(t, opID); phase == catalog.PhaseDone {
		t.Fatal("operation reached DONE on tampered evidence")
	}
	if _, serr := os.Lstat(victim); serr != nil {
		t.Fatalf("victim outside the quarantine was deleted: %v", serr)
	}
}

// parseInventoryLinesForCount counts records without the validation
// gate (the attacker's own bookkeeping during tampering).
func parseInventoryLinesForCount(b []byte) (int, error) {
	n := 0
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		n++
	}
	return n, nil
}

// patchManifestDigestForTest rewrites the manifest's inventory digest
// and count so a tampered inventory is INTERNALLY self-consistent —
// exactly the attacker's forgery (the catalog row keeps the truth).
func patchManifestDigestForTest(t *testing.T, manifestPath, newInvDigest string, count int64) {
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

// TestRemovalPermitRejectsInvalidEntryPaths (F1c): the permit — the
// last gate before os.Remove — must refuse entries whose paths fail
// validation, regardless of how its caller constructed them.
func TestRemovalPermitRejectsInvalidEntryPaths(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ident, err := h.probe.PlatformProbe.RootIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"../escape.txt", `win\path`, "a/../../b", "C:x"} {
		allowed := map[string]domain.Entry{
			"ok.txt": {Root: domain.RootMain, Path: "ok.txt", Kind: domain.KindFile,
				Digest: strings.Repeat("c", 64), Route: domain.RoutePreserve},
			p: {Root: domain.RootMain, Path: p, Kind: domain.KindFile,
				Digest: strings.Repeat("d", 64), Route: domain.RoutePreserve},
		}
		if _, perr := newRemovalPermit(domain.OperationID(domain.NewID()), domain.SnapshotID(domain.NewID()), root, ident, allowed); perr == nil {
			t.Errorf("permit accepted hostile entry path %q", p)
		}
	}
}

// TestRemoveEmptyAncestorsRejectsTraversalOutputs (F2): plan-supplied
// outputs with traversal never climb outside the live root.
func TestRemoveEmptyAncestorsRejectsTraversalOutputs(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	res := inventory.Scan(context.Background(), h.probe.PlatformProbe, root, inventory.Options{Hash: true})
	if res.Err != nil {
		t.Fatal(res.Err)
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
	outside := filepath.Join(h.base, "work", "outside-empty", "deep")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := permit.removeEmptyAncestors([]string{"../outside-empty/deep/output"}, nil); err == nil {
		t.Fatal("removeEmptyAncestors accepted a traversal output")
	}
	if _, serr := os.Lstat(outside); serr != nil {
		t.Fatalf("outside directory removed: %v", serr)
	}
}

// TestRemoveEmptyAncestorsStopsAtLink (F3): a junction substituted for
// an ancestor stops the climb; the link is never removed (no-follow).
func TestRemoveEmptyAncestorsStopsAtLink(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction fixture is windows-only")
	}
	h := newHarness(t)
	root := h.workspace("ws")
	res := inventory.Scan(context.Background(), h.probe.PlatformProbe, root, inventory.Options{Hash: true})
	if res.Err != nil {
		t.Fatal(res.Err)
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
	linkPath := filepath.Join(root, "g")
	outside := filepath.Join(h.base, "outside-target")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", linkPath, outside).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}
	if err := permit.removeEmptyAncestors([]string{"g/x"}, nil); err != nil {
		t.Fatalf("legitimate output errored: %v", err)
	}
	if _, serr := os.Lstat(linkPath); serr != nil {
		t.Fatalf("the junction itself was removed: %v", serr)
	}
	if _, serr := os.Lstat(outside); serr != nil {
		t.Fatalf("outside target damaged: %v", serr)
	}
}

// TestCrossCheckSealDigests (F1b): the catalog snapshot row's seal-time
// digests are the tamper-independent witness — mismatch refuses, a
// missing row refuses at sealed phases, and pre-seal phases fall back
// to P-internal consistency.
func TestCrossCheckSealDigests(t *testing.T) {
	h := newHarness(t)
	op := catalog.Operation{
		ID: domain.OperationID(domain.NewID()), WorkspaceID: newWSID(),
		Phase: catalog.PhaseRemoving, PayloadSnap: "snapaaaabbbbccccdddd",
	}
	// No row + sealed phase => refuse.
	if err := h.coord().crossCheckSealDigests(op, "m", "i"); err == nil {
		t.Fatal("sealed-phase op with no snapshot row was accepted")
	}
	// One row with different digests => refuse.
	ws := op.WorkspaceID
	cat := h.coord().cat
	if err := cat.UpsertWorkspace(catalog.Workspace{ID: ws, Name: "ws", Status: catalog.WorkspaceLive}); err != nil {
		t.Fatal(err)
	}
	if _, err := cat.RecordSnapshot(catalog.Snapshot{
		ID: domain.SnapshotID(domain.NewID()), WorkspaceID: ws,
		PayloadBackendID: op.PayloadSnap,
		ManifestDigest:   "sealed-manifest-digest", InventoryDigest: "sealed-inventory-digest",
		Kind: catalog.SnapshotKindPark,
	}); err != nil {
		t.Fatal(err)
	}
	err := h.coord().crossCheckSealDigests(op, "tampered-manifest", "sealed-inventory-digest")
	if err == nil {
		t.Fatal("digest mismatch was accepted")
	}
	var jm *ErrJournalMismatch
	if !errors.As(err, &jm) {
		t.Fatalf("not a typed mismatch: %v", err)
	}
	if !strings.Contains(err.Error(), "tampering") {
		t.Fatalf("error does not name the suspicion: %v", err)
	}
	// Matching digests => pass.
	if err := h.coord().crossCheckSealDigests(op, "sealed-manifest-digest", "sealed-inventory-digest"); err != nil {
		t.Fatalf("matching digests refused: %v", err)
	}
	// Pre-seal phase with no row => P-internal fallback allowed.
	op2 := catalog.Operation{
		ID: domain.OperationID(domain.NewID()), WorkspaceID: newWSID(),
		Phase: catalog.PhasePayloadCommitted, PayloadSnap: "snapeeeeffffgggghhhh",
	}
	if err := h.coord().crossCheckSealDigests(op2, "m", "i"); err != nil {
		t.Fatalf("pre-seal fallback refused: %v", err)
	}
}
