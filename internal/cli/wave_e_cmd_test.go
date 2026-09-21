// wave_e_cmd_test.go: per-command coverage over the eHarness world —
// happy paths, blocked paths, §17.2 JSON envelope shape, §5.5 human
// blocker wording, secrets discipline, and the signal-cancel → 130 →
// journal-preserved → recover-resume flow.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
)

// ---- init ---------------------------------------------------------------

func TestInitEnrollsVaultInteractively(t *testing.T) {
	h := newEHarness(t)
	// Remove the pre-registered vault: init must enroll from scratch.
	if err := os.Remove(filepath.Join(h.stateDir, "vaults.json")); err != nil {
		t.Fatal(err)
	}
	h.tty = true
	repoDir := filepath.Join(t.TempDir(), "fresh-vault")
	h.lines = []string{repoDir}
	// The detection root is a plain markers-only dir; init must not
	// write an Ebbfile into it.
	markers := t.TempDir()
	if err := os.WriteFile(filepath.Join(markers, "package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markers, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := h.run("init", markers)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Fatalf("human mode wrote to stdout: %q", stdout)
	}
	for _, want := range []string{"vault enrolled: main", "vault repository directory", "suggestions only"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if !strings.Contains(stderr, "pnpm") {
		t.Errorf("stderr lacks the pnpm suggestion:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Join(markers, "Ebbfile.toml")); err == nil {
		t.Error("init wrote an Ebbfile (detection must never write policy)")
	}
	// The enrolled vault is now the registry default: a second init
	// verifies unlock instead of enrolling again.
	code, _, stderr = h.run("init", markers)
	if code != ExitOK {
		t.Fatalf("second init code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "unlock verified") {
		t.Errorf("second init must verify the existing vault:\n%s", stderr)
	}
}

func TestInitSecondRunVerifiesUnlock(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("init", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "unlock verified") {
		t.Errorf("stderr lacks unlock verification:\n%s", stderr)
	}
}

func TestInitNoVaultNonInteractive(t *testing.T) {
	h := newEHarness(t)
	if err := os.Remove(filepath.Join(h.stateDir, "vaults.json")); err != nil {
		t.Fatal(err)
	}
	h.tty = false
	code, _, stderr := h.run("init", h.wsRoot)
	if code != ExitVault {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitVault, stderr)
	}
	assertBlocker(t, stderr, CodeNoVault, "ebb init")
}

// ---- snapshot -------------------------------------------------------------

func TestSnapshotEndToEnd(t *testing.T) {
	h := newEHarness(t)

	code, _, stderr := h.run("snapshot", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"sealed for workspace \"cliws\"", "entries preserved:", "nothing was removed"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	// The source is untouched.
	if _, err := os.Stat(filepath.Join(h.wsRoot, "notes.md")); err != nil {
		t.Fatalf("source mutated: %v", err)
	}
	assertNoSecrets(t, stderr)

	// The workspace row is live with its retained snapshot (catalog
	// read; `ebb status` is the stats dashboard since Wave 3).
	w := h.workspaceRowOf("cliws")
	if w.Status != catalog.WorkspaceLive {
		t.Errorf("workspace status = %s, want live", w.Status)
	}
	snaps := h.snapshotsOf(w.ID)
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %+v, want exactly one", snaps)
	}
	if snaps[0].Kind != catalog.SnapshotKindSnapshot || !snaps[0].Pinned {
		t.Errorf("snapshot row = %+v", snaps[0])
	}
}

func TestSnapshotJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("snapshot", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	// The "scanning ..." progress line is sanctioned on the human stream
	// even in --json mode (§14.4); nothing else may land there.
	for _, line := range strings.Split(strings.TrimSpace(stderr), "\n") {
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "scanning ") {
			t.Fatalf("json mode wrote non-progress human output to stderr: %q", stderr)
		}
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "command") != "snapshot" || envString(t, env, "outcome") != "ok" {
		t.Fatalf("envelope head = %v", env)
	}
	snapID := envString(t, env, "snapshot_id")
	if _, err := domain.ParseID(snapID); err != nil {
		t.Fatalf("snapshot_id %q: %v", snapID, err)
	}
	if envString(t, env, "workspace_id") == "" {
		t.Error("workspace_id missing")
	}
	if b, ok := env["bytes"].(map[string]any); !ok || b["preserved"].(float64) <= 0 {
		t.Errorf("bytes.preserved missing or zero: %v", env["bytes"])
	}
	if env["warnings"] == nil || env["errors"] == nil {
		t.Error("warnings/errors must serialize as arrays")
	}
	assertNoSecrets(t, stdout)
}

func TestSnapshotNoVaultBlocked(t *testing.T) {
	h := newEHarness(t)
	if err := os.Remove(filepath.Join(h.stateDir, "vaults.json")); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("snapshot", h.wsRoot)
	if code != ExitVault {
		t.Fatalf("code = %d, want %d", code, ExitVault)
	}
	assertBlocker(t, stderr, CodeNoVault, "ebb init")
}

func TestSnapshotMissingPath(t *testing.T) {
	h := newEHarness(t)
	missing := filepath.Join(t.TempDir(), "absent")
	if code, _, _ := h.run("snapshot", missing); code != ExitBlocked {
		t.Fatalf("code = %d, want %d", code, ExitBlocked)
	}
}

// ---- park -----------------------------------------------------------------

func TestParkEndToEndFlagAssertion(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(h.wsRoot); !os.IsNotExist(err) {
		t.Fatalf("workspace root still exists: %v", err)
	}
	for _, want := range []string{"parked workspace \"cliws\"", "space returned", "writer assertion recorded: flag:--assert-writers-stopped", "ebb open cliws"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)

	// The workspace row is parked (catalog read; status is the stats
	// dashboard since Wave 3).
	if w := h.workspaceRowOf("cliws"); w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace status = %s, want parked", w.Status)
	}
}

func TestParkJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	code, stdout, stderr := h.run("park", "--json", "--assert-writers-stopped", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "ok" || envString(t, env, "phase") != "DONE" {
		t.Fatalf("envelope = %v", env)
	}
	if !mustCondition(env, "writer-assertion:flag:--assert-writers-stopped") {
		t.Errorf("conditions lack the writer assertion: %v", env["conditions"])
	}
	if !mustCondition(env, "workspace-parked") {
		t.Errorf("conditions lack workspace-parked: %v", env["conditions"])
	}
	if _, err := domain.ParseID(envString(t, env, "snapshot_id")); err != nil {
		t.Fatalf("snapshot_id: %v", err)
	}
	assertNoSecrets(t, stdout)
}

func TestParkInteractiveConfirmAndDecline(t *testing.T) {
	h := newEHarness(t)
	h.tty = true
	h.lines = []string{"no"}
	code, _, stderr := h.run("park", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("declined code = %d, want %d", code, ExitBlocked)
	}
	assertBlocker(t, stderr, CodeWritersUnasserted, "NOT removed")
	if _, err := os.Stat(h.wsRoot); err != nil {
		t.Fatalf("declined park removed the root: %v", err)
	}
	if !strings.Contains(stderr, "assert all writers are stopped") {
		t.Errorf("prompt text missing:\n%s", stderr)
	}

	h.lines = []string{"yes"}
	code, _, stderr = h.run("park", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("confirmed code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "writer assertion recorded: interactive-confirm") {
		t.Errorf("interactive assertion not recorded:\n%s", stderr)
	}
}

func TestParkNonInteractiveNoAssertion(t *testing.T) {
	h := newEHarness(t)
	h.tty = false
	// --yes must NOT supply the writer assertion (§17.2).
	code, _, stderr := h.run("park", "--yes", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d", code, ExitBlocked)
	}
	assertBlocker(t, stderr, CodeWritersUnasserted, "--assert-writers-stopped")
	if !strings.Contains(stderr, "--yes never supplies it") {
		t.Errorf("wording must state --yes does not supply the assertion:\n%s", stderr)
	}
	if _, err := os.Stat(h.wsRoot); err != nil {
		t.Fatal("park removed the root without an assertion")
	}
}

// ---- trim -----------------------------------------------------------------

func TestTrimHappyPath(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("trim", "--groups", "deps", "--yes", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); !os.IsNotExist(err) {
		t.Fatalf("node_modules still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "notes.md")); err != nil {
		t.Fatalf("retained file removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.wsRoot, "package.json")); err != nil {
		t.Fatalf("recipe input removed: %v", err)
	}
	for _, want := range []string{
		"removed group deps",
		"recreate with: pnpm install --frozen-lockfile",
		"workspace root stays live",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)

	// The trim snapshot is retained (catalog read; status is the stats
	// dashboard since Wave 3).
	w := h.workspaceRowOf("cliws")
	found := false
	for _, sn := range h.snapshotsOf(w.ID) {
		if sn.Kind == catalog.SnapshotKindTrim {
			found = true
		}
	}
	if !found {
		t.Errorf("no trim snapshot retained")
	}
}

func TestTrimUnknownGroupUsage(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("trim", "--groups", "nope", "--yes", h.wsRoot)
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if !strings.Contains(stderr, "nope") || !strings.Contains(stderr, "deps") {
		t.Errorf("usage error must name the unknown group and the declared ones:\n%s", stderr)
	}
}

func TestTrimMissingGroupsFlag(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("trim", h.wsRoot); code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
}

func TestTrimNonInteractiveWithoutYes(t *testing.T) {
	h := newEHarness(t)
	h.tty = false
	code, _, stderr := h.run("trim", "--groups", "deps", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d", code, ExitBlocked)
	}
	assertBlocker(t, stderr, CodeWritersUnasserted, "--yes")
	if _, err := os.Stat(filepath.Join(h.wsRoot, "node_modules")); err != nil {
		t.Fatal("trim removed the group without an approval")
	}
}

func TestTrimInteractiveConfirm(t *testing.T) {
	h := newEHarness(t)
	h.tty = true
	h.lines = []string{"yes"}
	code, _, stderr := h.run("trim", "--groups", "deps", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "Remove these groups?") || !strings.Contains(stderr, "outputs: node_modules") {
		t.Errorf("confirmation must list the group's outputs:\n%s", stderr)
	}
}

// ---- open -----------------------------------------------------------------

func TestOpenAfterParkByName(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatalf("park code = %d, stderr = %s", code, stderr)
	}
	dest := filepath.Join(t.TempDir(), "restored")

	code, stdout, stderr := h.run("open", "cliws", "--to", dest, "--files-only")
	if code != ExitOK {
		t.Fatalf("open code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{"files-ready", "entries restored", "rebuild hint", "pnpm"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	// Preserved content is really back.
	b, err := os.ReadFile(filepath.Join(dest, "notes.md"))
	if err != nil || !strings.Contains(string(b), "private notes") {
		t.Fatalf("notes.md not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "node_modules")); !os.IsNotExist(err) {
		t.Errorf("reconstruct output was restored (files-only restores preserved content): %v", err)
	}
	assertNoSecrets(t, stderr)
	assertNoSecrets(t, stdout)

	// The workspace is live again at the new root (catalog read).
	if w := h.workspaceRowOf("cliws"); w.Status != catalog.WorkspaceLive || w.RootPath != dest {
		t.Errorf("workspace row after open = %+v", w)
	}
}

func TestOpenJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatal("park failed")
	}
	dest := filepath.Join(t.TempDir(), "restored-json")
	code, stdout, stderr := h.run("open", "--json", "cliws", "--to", dest, "--files-only")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "phase") != "DONE" {
		t.Errorf("phase = %v", env["phase"])
	}
	if !mustCondition(env, "files-ready") || !mustCondition(env, "snapshot-pinned") {
		t.Errorf("conditions = %v", env["conditions"])
	}
	if _, err := domain.ParseID(envString(t, env, "operation_id")); err != nil {
		t.Errorf("operation_id: %v", err)
	}
	det := env["details"].(map[string]any)
	if det["destination"] != dest {
		t.Errorf("destination = %v", det["destination"])
	}
	if det["bytes_restored"].(float64) <= 0 {
		t.Errorf("bytes_restored = %v", det["bytes_restored"])
	}
}

func TestOpenBySnapshotID(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatal("park failed")
	}
	// Find the snapshot id from the catalog (status keeps only a view).
	var snapID string
	for _, s := range snapshotsOf(t, h) {
		if s.Kind == catalog.SnapshotKindPark {
			snapID = string(s.ID)
		}
	}
	if snapID == "" {
		t.Fatal("no park snapshot found")
	}
	dest := filepath.Join(t.TempDir(), "by-id")
	code, _, stderr := h.run("open", snapID, "--to", dest, "--files-only")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dest, "src", "main.go")); err != nil {
		t.Fatalf("src tree not restored: %v", err)
	}
}

func TestOpenOccupiedDestinationBlocked(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatal("park failed")
	}
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "occupant.txt"), []byte("someone lives here"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := h.run("open", "cliws", "--to", dest)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d", code, ExitBlocked)
	}
	assertBlocker(t, stderr, "EBB_E_DEST_OCCUPIED", "refusing to overwrite")
	if b, _ := os.ReadFile(filepath.Join(dest, "occupant.txt")); string(b) != "someone lives here" {
		t.Error("occupant was modified")
	}
}

func TestOpenTrimSnapshotRefused(t *testing.T) {
	h := newEHarness(t)
	if code, _, stderr := h.run("trim", "--groups", "deps", "--yes", h.wsRoot); code != ExitOK {
		t.Fatalf("trim code = %d, stderr = %s", code, stderr)
	}
	var trimID string
	for _, s := range snapshotsOf(t, h) {
		if s.Kind == catalog.SnapshotKindTrim {
			trimID = string(s.ID)
		}
	}
	if trimID == "" {
		t.Fatal("no trim snapshot found")
	}
	dest := filepath.Join(t.TempDir(), "no-trim-open")
	code, _, stderr := h.run("open", trimID, "--to", dest)
	if code != ExitBlocked {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, "removal plan") || !strings.Contains(stderr, "EBB_E_NOT_OPENABLE") {
		t.Errorf("stderr must name the trim-kind refusal:\n%s", stderr)
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Error("trim open must not create anything")
	}
}

func TestOpenUnknownTarget(t *testing.T) {
	h := newEHarness(t)
	code, _, stderr := h.run("open", "no-such-workspace")
	if code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	assertBlocker(t, stderr, CodeOpenUnknownTarget, "ebb status")
}

func TestOpenParkedWithoutToFallsBackToOriginalRoot(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("park", "--assert-writers-stopped", h.wsRoot); code != ExitOK {
		t.Fatal("park failed")
	}
	// D032: no --to → the park operation's journaled source root is the
	// default destination ("original location"); the workspace row itself
	// is unbound after park (§16.5).
	code, _, stderr := h.run("open", "cliws", "--files-only")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if b, err := os.ReadFile(filepath.Join(h.wsRoot, "notes.md")); err != nil || !strings.Contains(string(b), "private notes") {
		t.Fatalf("notes.md not restored at the original root: %v", err)
	}
}

// The fallback needs durable evidence: no park operation root recorded →
// no destination guess (pinned at the helper contract level).
func TestOpenOriginalRootFallbackNeedsEvidence(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cat, err := catalog.Open(filepath.Join(state, "catalog.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer cat.Close()
	ws := domain.NewID()
	if err := cat.EnsureWorkspace(domain.WorkspaceID(ws), "evidencews"); err != nil {
		t.Fatal(err)
	}
	if got := originalRootOf(cat, domain.WorkspaceID(ws)); got != "" {
		t.Fatalf("empty journal returned %q", got)
	}
	opID, err := cat.BeginOperation(domain.WorkspaceID(ws), catalog.OpKindPark,
		filepath.Join(t.TempDir(), "orig-root"), "", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = opID
	if got := originalRootOf(cat, domain.WorkspaceID(ws)); got == "" {
		t.Fatal("park op source root not recovered")
	}
}

// ---- recover + signal cancel ----------------------------------------------

func TestSignalCancelPreservesJournalAndRecoverResumes(t *testing.T) {
	h := newEHarness(t)
	// Cancel the signal context the first time the removal walk probes
	// an entry inside the quarantine (only the park tail probes there).
	var once bool
	h.probe.onProbeFile = func(path string) {
		if !once && strings.Contains(filepath.ToSlash(path), ".ebb-quarantine-") {
			once = true
			h.cancelSig()
		}
	}

	code, stdout, stderr := h.run("park", "--json", "--assert-writers-stopped", h.wsRoot)
	if code != ExitCancelled {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitCancelled, stderr)
	}
	env := envelopeOf(t, stdout)
	if envString(t, env, "outcome") != "cancelled" {
		t.Fatalf("outcome = %v", env["outcome"])
	}
	// The next invocation runs under a fresh context (new process).
	h.resetSignalContext()
	// The journal keeps the last durable phase: REMOVING.
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces: %v (%v)", wss, err)
	}
	active, err := cat.ActiveOperations(wss[0].ID)
	if err != nil || len(active) != 1 {
		t.Fatalf("active operations: %v (%v)", active, err)
	}
	op := active[0]
	if op.Phase != catalog.PhaseRemoving {
		t.Fatalf("journal phase = %s, want %s", op.Phase, catalog.PhaseRemoving)
	}

	// Recover on a REMOVING park reconciles from durable evidence and
	// completes the authorized walk to DONE (the resume is part of the
	// §12.4 REMOVING row; each entry is re-digested).
	code, _, stderr = h.run("recover", string(op.ID))
	if code != ExitOK {
		t.Fatalf("recover code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, string(op.ID)) {
		t.Errorf("recover report lacks the operation id:\n%s", stderr)
	}
	if !strings.Contains(stderr, catalog.PhaseRemoving+" -> "+catalog.PhaseDone) {
		t.Errorf("recover must report REMOVING -> DONE:\n%s", stderr)
	}
	if _, err := os.Stat(filepath.Dir(h.wsRoot)); err != nil {
		t.Fatal(err)
	}
	// Quarantine and root are both gone after the reconciled walk.
	parent := filepath.Dir(h.wsRoot)
	des, _ := os.ReadDir(parent)
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".ebb-quarantine-") {
			t.Errorf("quarantine %s survived", de.Name())
		}
	}
	// Workspace is parked now (catalog read).
	if w := h.workspaceRowOf("cliws"); w.Status != catalog.WorkspaceParked {
		t.Errorf("status after resume = %s, want parked", w.Status)
	}

	// Resuming a finished operation is a journal mismatch (exit 5).
	code, _, stderr = h.run("recover", string(op.ID), "--resume-removal")
	if code != ExitInterrupted {
		t.Fatalf("code = %d, want %d (stderr %s)", code, ExitInterrupted, stderr)
	}
}

func TestRecoverUnknownOperation(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("recover", strings.Repeat("f", 32)); code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	if code, _, _ := h.run("recover", "not-an-id"); code != ExitUsage {
		t.Fatalf("malformed id code = %d", code)
	}
}

// ---- status ----------------------------------------------------------------

func TestStatusAliasBasics(t *testing.T) {
	h := newEHarness(t)
	// `ebb status` is the stats alias since Wave 3: an empty catalog is
	// a valid report (the dashboard with unknowns), and a positional
	// argument is a usage error (stats takes none; the old workspace
	// filter is superseded).
	code, _, stderr := h.run("status")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, "Ebb Developer Space Economy") {
		t.Errorf("status did not render the stats dashboard:\n%s", stderr)
	}
	if code, _, _ := h.run("status", "ghost"); code != ExitUsage {
		t.Fatalf("positional argument code = %d, want %d", code, ExitUsage)
	}
}

// ---- helpers ---------------------------------------------------------------

// assertBlocker checks §5.5: a stable EBB_E_ code and a safe action.
func assertBlocker(t *testing.T, stderr, code, actionPart string) {
	t.Helper()
	if !strings.Contains(stderr, code) {
		t.Errorf("stderr lacks stable code %s:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "Safe action:") || !strings.Contains(stderr, actionPart) {
		t.Errorf("stderr lacks the safe action %q:\n%s", actionPart, stderr)
	}
}

// assertNoSecrets verifies the env password never appears in output.
func assertNoSecrets(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "ecli-test-secret") || strings.Contains(out, "SECRET_TOKEN") {
		t.Errorf("output leaked a secret:\n%s", out)
	}
}

// snapshotsOf reads the workspace's snapshot rows directly.
func snapshotsOf(t *testing.T, h *eHarness) []catalog.Snapshot {
	t.Helper()
	cat := h.cat()
	wss, err := cat.ListWorkspaces()
	if err != nil || len(wss) != 1 {
		t.Fatalf("workspaces: %v (%v)", wss, err)
	}
	snaps, err := cat.ListSnapshots(wss[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return snaps
}
