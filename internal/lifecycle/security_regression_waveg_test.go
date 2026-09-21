package lifecycle

// Regression tests for the Wave G security fixes (F5/F6/F7 of the Wave F
// review, lab/security-review/wave-F/FINDINGS.md). Default suite: the
// hardened behavior is continuously protected; the security_poc-tagged
// twins demonstrate the original attacks.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/pathcanon"
)

// ---- F6: bidirectional canonical preflight overlap (I06) ------------------

// TestPreflightBlocksRootInsideVaultDirect: a workspace root that lives
// INSIDE the vault repository is refused in the direct spelling (the old
// check covered only the opposite direction).
func TestPreflightBlocksRootInsideVaultDirect(t *testing.T) {
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	ws := filepath.Join(vaultDir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	ref := VaultRef{RepoDir: vaultDir, Passfile: filepath.Join(base, "pass")}
	err := preflight(ws, ref)
	if err == nil {
		t.Fatal("root inside the vault repository passed preflight")
	}
	var blocked *ErrDestructiveBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("refusal is not ErrDestructiveBlocked: %v", err)
	}
	if !strings.Contains(err.Error(), "inside the vault repository") {
		t.Fatalf("blocker does not name the direction: %v", err)
	}
}

// TestPreflightBlocksJunctionAlias: the same overlap spelled through a
// junction alias is refused — canonicalPath resolves junctions (Go's
// EvalSymlinks alone does not: junctions are ModeIrregular).
func TestPreflightBlocksJunctionAlias(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction fixture is windows-only")
	}
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	ws := filepath.Join(vaultDir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	ref := VaultRef{RepoDir: vaultDir, Passfile: filepath.Join(base, "pass")}
	link := filepath.Join(base, "link")
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, vaultDir).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}
	if err := preflight(filepath.Join(link, "ws"), ref); err == nil {
		t.Fatal("junction-alias spelling of a root inside the vault passed preflight (I06)")
	}
	// Chained aliases collapse too.
	link2 := filepath.Join(base, "link2")
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link2, link).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}
	if err := preflight(filepath.Join(link2, "ws"), ref); err == nil {
		t.Fatal("chained junction-alias spelling passed preflight (I06)")
	}
}

// TestPreflightBlocksSymlinkAlias: the same overlap spelled through a
// plain symlink is refused on platforms where unprivileged symlink
// creation works (linux; Windows with Developer Mode).
func TestPreflightBlocksSymlinkAlias(t *testing.T) {
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	ws := filepath.Join(vaultDir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(vaultDir, link); err != nil {
		t.Skipf("symlink fixture unavailable (%v); junction twin covers Windows", err)
	}
	ref := VaultRef{RepoDir: vaultDir, Passfile: filepath.Join(base, "pass")}
	if err := preflight(filepath.Join(link, "ws"), ref); err == nil {
		t.Fatal("symlink-alias spelling of a root inside the vault passed preflight (I06)")
	}
}

// TestPreflightBlocksVaultInsideRootCanonically: the pre-existing
// direction (vault inside root) keeps refusing, including alias
// spellings of the REPO side.
func TestPreflightBlocksVaultInsideRootCanonically(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	ref := VaultRef{RepoDir: repo, Passfile: filepath.Join(base, "pass")}
	if err := preflight(root, ref); err == nil {
		t.Fatal("vault inside the captured root passed preflight")
	}
	if !strings.Contains(preflightErr(t, root, ref), "destroy its own backend") {
		t.Fatalf("blocker wording changed: %v", preflightErr(t, root, ref))
	}
	// Alias spelling of the repo: junction link -> base/ws, repo spelled
	// through it (canonicalizes INSIDE the root).
	if runtime.GOOS == "windows" {
		link := filepath.Join(base, "link")
		if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, root).CombinedOutput(); jerr != nil {
			t.Fatalf("mklink /J: %v\n%s", jerr, out)
		}
		aliased := VaultRef{RepoDir: filepath.Join(link, "repo"), Passfile: filepath.Join(base, "pass")}
		if err := preflight(root, aliased); err == nil {
			t.Fatal("alias-spelled vault inside the captured root passed preflight (I06)")
		}
	}
}

// TestPreflightBlocksPassfileInsideRootViaAlias: the passfile check also
// canonicalizes — a passfile spelled through an alias that resolves
// inside the root is caught.
func TestPreflightBlocksPassfileInsideRootViaAlias(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	vaultDir := filepath.Join(base, "vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if runtime.GOOS == "windows" {
		if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, root).CombinedOutput(); jerr != nil {
			t.Fatalf("mklink /J: %v\n%s", jerr, out)
		}
	} else if serr := os.Symlink(root, link); serr != nil {
		t.Skipf("alias fixture unavailable (%v)", serr)
	}
	// Passfile lives at <link>/pass; <link> resolves to the root, so the
	// passfile IS inside the captured root through the alias.
	ref := VaultRef{RepoDir: vaultDir, Passfile: filepath.Join(link, "pass")}
	if err := preflight(root, ref); err == nil {
		t.Fatal("alias-spelled passfile inside the captured root passed preflight")
	}
	if !strings.Contains(preflightErr(t, root, ref), "unlock secret") {
		t.Fatalf("blocker wording changed: %v", preflightErr(t, root, ref))
	}
}

// TestPreflightCleanLayoutStillPasses: disjoint root/vault/passfile
// pass, including a vault repo that does not exist yet (first run — the
// canonicalizer falls back to the lexical spelling without refusing).
func TestPreflightCleanLayoutStillPasses(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "ws")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	ref := VaultRef{RepoDir: filepath.Join(base, "vault"), Passfile: filepath.Join(base, "pass")}
	if err := preflight(root, ref); err != nil {
		t.Fatalf("clean layout refused: %v", err)
	}
	if err := preflight(filepath.Join(base, "other"), ref); err != nil {
		t.Fatalf("nonexistent sibling root refused: %v", err)
	}
}

// TestCanonicalPathCollapsesAliases: pathcanon.CanonicalPath (the shared
// canonicalizer behind preflight) resolves junctions
// (and chains of them) to the final target path.
func TestCanonicalPathCollapsesAliases(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junction fixture is windows-only")
	}
	base := t.TempDir()
	vaultDir := filepath.Join(base, "vault")
	ws := filepath.Join(vaultDir, "ws")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link, vaultDir).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}
	link2 := filepath.Join(base, "link2")
	if out, jerr := exec.Command("cmd", "/c", "mklink", "/J", link2, link).CombinedOutput(); jerr != nil {
		t.Fatalf("mklink /J: %v\n%s", jerr, out)
	}
	want := pathcanon.CanonicalPath(ws)
	if got := pathcanon.CanonicalPath(filepath.Join(link, "ws")); got != want {
		t.Errorf("canonical(junction alias) = %q, want %q", got, want)
	}
	if got := pathcanon.CanonicalPath(filepath.Join(link2, "ws")); got != want {
		t.Errorf("canonical(chained junction alias) = %q, want %q", got, want)
	}
	if got := pathcanon.CanonicalPath(filepath.Join(base, "missing", "tail")); got != filepath.Join(pathcanon.CanonicalPath(base), "missing", "tail") {
		t.Errorf("missing path fell back to %q", got)
	}
}

func preflightErr(t *testing.T, root string, ref VaultRef) string {
	t.Helper()
	err := preflight(root, ref)
	if err == nil {
		t.Fatal("expected a blocker")
	}
	return err.Error()
}

// ---- F5: SEALED+quarantine crash window -----------------------------------

// TestRecoverSealedQuarantineCrashWindowReconciles: the crash state
// (phase SEALED, root renamed to the quarantine sibling, nothing else
// committed) is reconciled by a FRESH coordinator's Recover — the
// sibling's identity is verified, SEALED→QUARANTINED committed, and the
// existing QUARANTINED reconciliation completes the park.
func TestRecoverSealedQuarantineCrashWindowReconciles(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	c := h.coord()
	st, err := c.capture(context.Background(), h.vault, root, parkOpts(ws), catalog.OpKindPark, catalog.SnapshotKindPark)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	defer st.journal.close()
	if got := h.phaseOf(t, st.opID); got != catalog.PhaseSealed {
		t.Fatalf("phase = %s, want SEALED", got)
	}
	// The crash point: the quarantine rename happened, nothing after.
	quar := quarantinePath(st.parent, st.opID)
	if err := renameToQuarantine(st.opID, root, quar); err != nil {
		t.Fatal(err)
	}

	rep, rerr := h.coord().Recover(context.Background(), h.vault, st.opID)
	if rerr != nil {
		t.Fatalf("recover of the crash window: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseBefore != catalog.PhaseSealed || rep.PhaseAfter != catalog.PhaseDone {
		t.Fatalf("phases %s -> %s, want SEALED -> DONE", rep.PhaseBefore, rep.PhaseAfter)
	}
	joined := strings.Join(rep.Actions, "\n")
	if !strings.Contains(joined, quarantinePrefix) {
		t.Errorf("report never mentions the quarantine sibling:\n%s", joined)
	}
	mustLstatErrNotExist(t, quar)
	mustLstatErrNotExist(t, root)
	if got := h.phaseOf(t, st.opID); got != catalog.PhaseDone {
		t.Errorf("op phase after recover = %s, want DONE", got)
	}
	if w, err := h.coord().cat.GetWorkspace(ws); err != nil || w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace after recovery = %+v (%v), want parked", w, err)
	}
}

// TestRecoverSealedWrongIdentitySiblingReportedNotAdopted: a quarantine
// sibling whose native identity does NOT match the operation's recorded
// root identity is reported and never adopted (the rename intent is not
// proof of content — I13).
func TestRecoverSealedWrongIdentitySiblingReportedNotAdopted(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	c := h.coord()
	st, err := c.capture(context.Background(), h.vault, root, parkOpts(ws), catalog.OpKindPark, catalog.SnapshotKindPark)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	defer st.journal.close()

	// Substitute a DIFFERENT directory as the quarantine sibling: the
	// root is absent (the crash), but the tree sitting at the sibling
	// path is not the sealed root.
	quar := quarantinePath(st.parent, st.opID)
	if err := renameToQuarantine(st.opID, root, quar); err != nil {
		t.Fatal(err)
	}
	holding := filepath.Join(h.base, "the-real-root-holding")
	if err := os.Rename(quar, holding); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(h.base, "foreign-tree")
	if err := os.MkdirAll(filepath.Join(foreign, "junk"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "junk", "data.txt"), []byte("not the sealed root\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(foreign, quar); err != nil {
		t.Fatal(err)
	}
	if _, serr := os.Lstat(root); serr == nil {
		t.Fatal("setup error: the live root should be absent in this crash state")
	}

	rep, rerr := h.coord().Recover(context.Background(), h.vault, st.opID)
	if rerr == nil {
		t.Fatalf("wrong-identity sibling was adopted (phase after=%s, actions=%v)", rep.PhaseAfter, rep.Actions)
	}
	var jm *ErrJournalMismatch
	if !errors.As(rerr, &jm) {
		t.Fatalf("refusal is not ErrJournalMismatch: %v", rerr)
	}
	if !strings.Contains(rerr.Error(), "identity") {
		t.Fatalf("refusal does not name the identity mismatch: %v", rerr)
	}
	if got := h.phaseOf(t, st.opID); got != catalog.PhaseSealed {
		t.Errorf("phase after refused adoption = %s, want SEALED (untouched)", got)
	}
	mustExist(t, filepath.Join(quar, "junk", "data.txt")) // foreign tree untouched
	mustExist(t, filepath.Join(holding, "notes.md"))      // the real root data untouched
}

// TestCancelSealedUnblocksWorkspace: an explicit cancel of a SEALED
// operation (root intact and present) unblocks the workspace — the next
// park succeeds — while the retained P/S pair stays pinned (I07).
func TestCancelSealedUnblocksWorkspace(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	// Drive the sequence to exactly SEALED (capture leaves the operation
	// sealed with the live root intact — the pre-quarantine crash state).
	c := h.coord()
	st, err := c.capture(context.Background(), h.vault, root, parkOpts(ws), catalog.OpKindPark, catalog.SnapshotKindPark)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	defer st.journal.close()
	opID := st.opID
	if got := h.phaseOf(t, opID); got != catalog.PhaseSealed {
		t.Fatalf("phase = %s, want SEALED", got)
	}

	// While SEALED, a fresh park is blocked (F37 single-op lock)...
	if _, perr := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws)); perr == nil {
		t.Fatal("park during an active SEALED operation unexpectedly succeeded")
	} else {
		var inProgress *ErrOpInProgress
		if !errors.As(perr, &inProgress) {
			t.Fatalf("park blocked with %v, want ErrOpInProgress", perr)
		}
	}
	// ...and plain Recover stays report-only (TestRecoverSealedReportsOnly).
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("recover on SEALED: %v", rerr)
	}
	if rep.PhaseAfter != catalog.PhaseSealed {
		t.Fatalf("plain recover changed the SEALED phase: %s", rep.PhaseAfter)
	}

	// The explicit cancel unblocks the workspace.
	crep, cerr := h.coord().CancelOperation(context.Background(), h.vault, opID)
	if cerr != nil {
		t.Fatalf("cancel: %v (report %+v)", cerr, crep)
	}
	if crep.PhaseAfter != catalog.PhaseCanceled {
		t.Fatalf("phase after cancel = %s, want CANCELED", crep.PhaseAfter)
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseCanceled {
		t.Errorf("journal phase after cancel = %s, want CANCELED", got)
	}
	// I07: the sealed pair stays pinned; only forget releases it.
	snaps, err := h.coord().cat.ListSnapshots(ws)
	if err != nil || len(snaps) != 1 {
		t.Fatalf("snapshots after cancel: %+v (%v)", snaps, err)
	}
	if !snaps[0].Pinned || snaps[0].SealBackendID == "" {
		t.Fatalf("sealed pair must stay pinned after cancel: %+v", snaps[0])
	}
	// The workspace is unblocked: a subsequent park succeeds.
	if _, perr := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws)); perr != nil {
		t.Fatalf("park after cancel still blocked: %v", perr)
	}
	if got := h.phaseOf(t, h.opIDOf(t, ws)); got != catalog.PhaseDone {
		t.Errorf("fresh park phase = %s, want DONE", got)
	}
	mustLstatErrNotExist(t, root)
}

// TestCancelRefusesMidRemovalPhases: cancel never abandons a quarantine
// mid-removal — those phases require reconciliation.
func TestCancelRefusesMidRemovalPhases(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	ctx, cancel := context.WithCancel(context.Background())
	removed := 0
	h.probe.onProbeFile = func(path string) {
		if strings.Contains(filepath.ToSlash(path), quarantinePrefix) {
			removed++
			if removed == 2 {
				cancel()
			}
		}
	}
	if _, err := h.coord().Park(ctx, h.vault, root, parkOpts(ws)); err == nil {
		t.Fatal("expected the interrupted park to fail")
	}
	cancel()
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseRemoving {
		t.Fatalf("phase after interruption = %s, want REMOVING", got)
	}
	_, cerr := h.coord().CancelOperation(context.Background(), h.vault, opID)
	if cerr == nil {
		t.Fatal("cancel accepted a mid-removal operation")
	}
	var jm *ErrJournalMismatch
	if !errors.As(cerr, &jm) {
		t.Fatalf("refusal is not ErrJournalMismatch: %v", cerr)
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseRemoving {
		t.Errorf("phase changed by the refused cancel: %s", got)
	}
}

// ---- F7: writer-condition discipline on resume ----------------------------

// TestRecoverRemovalBlockedIsReportOnly: plain Recover on a
// REMOVAL_BLOCKED park reports the blocker and removes NOTHING; the
// explicit verb (ResumeRemoval) performs the destructive resume.
func TestRecoverRemovalBlockedIsReportOnly(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	// Block the walk with a digest change, cross-platform (no handles
	// needed): once the walk is inside the quarantine (reverse canonical
	// order: vendor/dist/gen.js is walked first), tamper
	// vendor/LICENSE.txt at its own probe — the probe precedes the
	// per-entry re-digest in the same iteration, so the walk blocks on
	// it and everything from pnpm-lock.yaml on stays retained.
	quarProbes := 0
	h.probe.onProbeFile = func(path string) {
		slash := filepath.ToSlash(path)
		if !strings.Contains(slash, quarantinePrefix) {
			return
		}
		quarProbes++
		if quarProbes >= 2 && strings.HasSuffix(slash, "vendor/LICENSE.txt") {
			_ = os.WriteFile(path, []byte("tampered mid-walk\n"), 0o644)
		}
	}
	if _, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws)); err == nil {
		t.Fatal("expected the blocked park to fail")
	}
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseRemovalBlocked {
		t.Fatalf("phase after block = %s, want REMOVAL_BLOCKED", got)
	}
	h.probe.onProbeFile = nil // disarm: the walk must not be re-tampered on resume
	quar := quarantinePath(filepath.Dir(root), opID)
	mustExist(t, quar)

	// Plain Recover: report-only. The blocker is named, the phase does
	// not move, and nothing else is removed.
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("report-only recover errored: %v", rerr)
	}
	if rep.PhaseAfter != catalog.PhaseRemovalBlocked {
		t.Fatalf("plain recover changed the phase: %s", rep.PhaseAfter)
	}
	if !strings.Contains(rep.NextAction, "resume-removal") {
		t.Errorf("next action must name the explicit verb: %q", rep.NextAction)
	}
	if got := h.phaseOf(t, opID); got != catalog.PhaseRemovalBlocked {
		t.Errorf("journal phase changed by report-only recover: %s", got)
	}
	mustExist(t, filepath.Join(quar, "package.json")) // nothing further removed
	mustExist(t, filepath.Join(quar, "notes.md"))
	mustExist(t, filepath.Join(quar, "node_modules", "a.js"))

	// The user resolves the blocker (restore the tampered content) and
	// uses the EXPLICIT verb: the resume completes with evidence
	// verification.
	if err := os.WriteFile(filepath.Join(quar, "vendor", "LICENSE.txt"), []byte(fixtureLicense), 0o644); err != nil {
		t.Fatal(err)
	}
	rrep, rerr2 := h.coord().ResumeRemoval(context.Background(), h.vault, opID)
	if rerr2 != nil {
		t.Fatalf("ResumeRemoval after resolving the blocker: %v (report %+v)", rerr2, rrep)
	}
	if rrep.PhaseAfter != catalog.PhaseDone {
		t.Fatalf("phase after explicit resume = %s, want DONE", rrep.PhaseAfter)
	}
	mustLstatErrNotExist(t, quar)
	mustLstatErrNotExist(t, root)
}

// TestResumeRecordsWriterAssertionSource: every destructive resume —
// the explicit verb AND the auto-resumed idempotent completions —
// durably names its writer-assertion source as resume:<phase> on the
// operation row (§12.4 QUARANTINED row: "reconfirm identities and
// writer condition").
func TestResumeRecordsWriterAssertionSource(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	ctx, cancel := context.WithCancel(context.Background())
	removed := 0
	h.probe.onProbeFile = func(path string) {
		if strings.Contains(filepath.ToSlash(path), quarantinePrefix) {
			removed++
			if removed == 2 {
				cancel()
			}
		}
	}
	if _, err := h.coord().Park(ctx, h.vault, root, parkOpts(ws)); err == nil {
		t.Fatal("expected the interrupted park to fail")
	}
	cancel()
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseRemoving {
		t.Fatalf("phase after interruption = %s, want REMOVING", got)
	}

	// Plain Recover auto-resumes the interrupted REMOVING walk to
	// completion (idempotent) — and records resume:REMOVING.
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("recover: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseAfter != catalog.PhaseDone {
		t.Fatalf("phase after recover = %s, want DONE", rep.PhaseAfter)
	}
	op, err := h.coord().cat.GetOperation(opID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(op.LastError, "resume:"+catalog.PhaseRemoving) {
		t.Fatalf("operation row lacks the durable resume note (last_error = %q)", op.LastError)
	}
}

// TestCancelSealedRefusedWhenQuarantineSiblingExists (G4 regression,
// Wave G review): in the §12.2 step-7 crash window (phase SEALED, root
// renamed to the quarantine sibling, nothing committed), the explicit
// cancel must REFUSE — existence-only probe, sibling untouched, phase
// unchanged — because canceling would strand the tree at an opaque path
// with no durable pointer while deleting the scratch that names it.
// `ebb recover <op>` is the reconciliation path.
func TestCancelSealedRefusedWhenQuarantineSiblingExists(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")
	ws := newWSID()

	c := h.coord()
	st, err := c.capture(context.Background(), h.vault, root, parkOpts(ws), catalog.OpKindPark, catalog.SnapshotKindPark)
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	defer st.journal.close()
	if got := h.phaseOf(t, st.opID); got != catalog.PhaseSealed {
		t.Fatalf("phase = %s, want SEALED", got)
	}
	// The crash point: the quarantine rename happened, nothing after.
	quar := quarantinePath(st.parent, st.opID)
	if err := renameToQuarantine(st.opID, root, quar); err != nil {
		t.Fatal(err)
	}

	_, cerr := h.coord().CancelOperation(context.Background(), h.vault, st.opID)
	if cerr == nil {
		t.Fatal("cancel accepted an operation whose quarantine sibling exists")
	}
	var refused *ErrCancelRefused
	if !errors.As(cerr, &refused) {
		t.Fatalf("refusal is not ErrCancelRefused: %v", cerr)
	}
	if refused.Quarantine != quar {
		t.Fatalf("refusal names quarantine %q, want %q", refused.Quarantine, quar)
	}
	if got := h.phaseOf(t, st.opID); got != catalog.PhaseSealed {
		t.Fatalf("phase changed by the refused cancel: %s", got)
	}
	if _, serr := os.Lstat(quar); serr != nil {
		t.Fatalf("the refusal must never touch the sibling: %v", serr)
	}
}
