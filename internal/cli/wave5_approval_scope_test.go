// wave5_approval_scope_test.go pins the wave-5 review's P1 authorization
// defects on the restore/open approval resolver wiring:
//
//   - P1-A: --legacy-approve authorizes ONLY pendings marked Legacy (a
//     trim manifest without frozen action definitions). It must never
//     stand in for a missing regular approval of a NEW-format trim —
//     headless such a run is blocked with the approval-required error
//     and the approval store stays empty.
//   - P1-B: --json is machine mode for the approval resolver too (the
//     same rule the branch/drift prompter already follows): even on a
//     terminal, a missing or stale approval is a structured blocked
//     result with ZERO terminal reads — never a hidden prompt.
//
// The explicit --legacy-approve consent still authorizes genuinely
// legacy pendings headless (that IS explicit machine consent), behind
// the honest legacy-recovery-attempt banner.

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/restore"
)

// countingReadLine installs a stdin seam that counts every read attempt
// and never returns input: a machine-mode run must perform ZERO reads.
func countingReadLine(h *eHarness) *int {
	reads := 0
	h.deps.ReadLine = func() (string, error) {
		reads++
		return "", fmt.Errorf("no input may be read by a machine-mode run")
	}
	return &reads
}

// dropTrimApprovals deletes the state dir's approval document, so the
// frozen trim recipe's exact approval is MISSING at restore time (the
// trim recorded one; the pendings the resolver sees are non-legacy).
func dropTrimApprovals(t *testing.T, h *eHarness) {
	t.Helper()
	if err := os.Remove(filepath.Join(h.stateDir, approvalsFile)); err != nil {
		t.Fatalf("removing the approval store: %v", err)
	}
}

// tamperTrimApprovalToolSHA rewrites the recorded approval's tool digest
// to a different hash: the same action, DRIFTED tool identity (stale).
func tamperTrimApprovalToolSHA(t *testing.T, h *eHarness) {
	t.Helper()
	path := filepath.Join(h.stateDir, approvalsFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the approval store: %v", err)
	}
	var doc struct {
		Version   int                `json:"version"`
		Approvals []actions.Approval `json:"approvals"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing the approval store: %v", err)
	}
	if doc.Version != 1 {
		t.Fatalf("approval document version = %d, want 1", doc.Version)
	}
	if len(doc.Approvals) == 0 {
		t.Fatal("no recorded approval to tamper with")
	}
	for i := range doc.Approvals {
		doc.Approvals[i].Tool.SHA256 = strings.Repeat("cd", 32)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// legacyPendingWithIdentity completes the shared legacyPending fixture
// with the resolved tool identity and input digests the driver always
// supplies (the resolver records exactly what it was shown).
func legacyPendingWithIdentity() restore.PendingApproval {
	p := legacyPending()
	p.Tool = actions.ToolIdentity{
		Name:         "pnpm",
		ResolvedPath: filepath.Join("fake", "bin", "pnpm"),
		SHA256:       strings.Repeat("ab", 32),
	}
	p.InputDigests = map[string]string{
		"package.json":   strings.Repeat("11", 32),
		"pnpm-lock.yaml": strings.Repeat("22", 32),
	}
	return p
}

// TestLegacyApproveDoesNotAuthorizeNonLegacyPending (P1-A): a
// NEW-format trim whose stored approval is missing, replayed headless
// with --legacy-approve, must stay BLOCKED with the approval-required
// error and an EMPTY approval store. The flag's scope is the legacy
// disclosure — it is not a generic --yes for restore.
func TestLegacyApproveDoesNotAuthorizeNonLegacyPending(t *testing.T) {
	h, runner := newRestoreHarness(t)
	trimCliws(t, h) // a current trim: frozen definitions, approval recorded
	dropTrimApprovals(t, h)
	reads := countingReadLine(h)
	h.tty = false

	code, _, stderr := h.run("restore", "--legacy-approve", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("restore --legacy-approve on a new-format trim code = %d, want blocked (3); stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, CodeApprovalRequired) {
		t.Errorf("stderr must carry the approval-required code:\n%s", stderr)
	}
	if reads := *reads; reads != 0 {
		t.Errorf("headless run read stdin %d time(s); a block must need no input", reads)
	}
	if runner.count() != 0 {
		t.Errorf("nothing may run without a real approval; runner calls = %d", runner.count())
	}
	// The store stays empty: no approval may be recorded by the
	// out-of-scope flag.
	store := approvalstore.New(filepath.Join(h.stateDir, approvalsFile))
	list, lerr := store.List()
	if lerr != nil || len(list) != 0 {
		t.Errorf("--legacy-approve recorded approvals for a non-legacy pending: %+v (%v)", list, lerr)
	}
}

// TestLegacyApproveStillAuthorizesLegacyPending (P1-A's other edge):
// the flag keeps its advertised power — a genuinely LEGACY pending,
// consented headless with --legacy-approve, is authorized (the approval
// is recorded as the flag's explicit consent, behind the honest legacy
// banner) with zero terminal reads.
func TestLegacyApproveStillAuthorizesLegacyPending(t *testing.T) {
	dir := t.TempDir()
	store := approvalstore.New(filepath.Join(dir, approvalsFile))
	errb := &strings.Builder{}
	deps := Deps{
		StdinIsTerminal: func() bool { return false },
		ReadLine: func() (string, error) {
			return "", fmt.Errorf("headless consent must not read stdin")
		},
	}
	base := openApprovalResolver(deps, Streams{Err: errb}, false, false, store,
		"rerun with --yes to record the approval, or run in a terminal to review the actions first")
	resolver := restoreLegacyApprovalResolver(deps, Streams{Err: errb}, true, false, store, base)

	if err := resolver(context.Background(), []restore.PendingApproval{legacyPendingWithIdentity()}); err != nil {
		t.Fatalf("consented headless legacy replay must resolve: %v", err)
	}
	if msg := errb.String(); !strings.Contains(msg, "legacy recovery attempt") {
		t.Errorf("the honest legacy banner must precede the consent:\n%s", msg)
	}
	list, lerr := store.List()
	if lerr != nil || len(list) != 1 {
		t.Fatalf("the legacy approval must be recorded: %+v (%v)", list, lerr)
	}
	if list[0].ActionID != "deps" {
		t.Errorf("recorded action = %q, want deps", list[0].ActionID)
	}
	if list[0].ApprovedBy != "flag:--legacy-approve" {
		t.Errorf("approved_by = %q, want the flag's own consent label", list[0].ApprovedBy)
	}
}

// TestRestoreJSONOnTTYMissingApprovalNeverPrompts (P1-B): `--json` on a
// terminal with a MISSING approval is machine mode — a structured
// blocked result carrying the typed code, never an approval prompt and
// never a terminal read.
func TestRestoreJSONOnTTYMissingApprovalNeverPrompts(t *testing.T) {
	h, runner := newRestoreHarness(t)
	trimCliws(t, h)
	dropTrimApprovals(t, h)
	reads := countingReadLine(h)
	h.tty = true

	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("restore --json with a missing approval code = %d, want blocked (3); stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	errs := strings.Join(stringList(env["errors"]), " ")
	if !strings.Contains(errs, CodeApprovalRequired) {
		t.Fatalf("the structured error must carry %s: %v (stderr %s)", CodeApprovalRequired, errs, stderr)
	}
	if strings.Contains(stderr, "Approve these actions?") {
		t.Errorf("--json must not print an approval prompt:\n%s", stderr)
	}
	if reads := *reads; reads != 0 {
		t.Errorf("machine mode read stdin %d time(s); zero reads are required", reads)
	}
	if runner.count() != 0 {
		t.Errorf("nothing may run without a resolved approval; runner calls = %d", runner.count())
	}
}

// TestRestoreJSONOnTTYStaleApprovalNeverPrompts (P1-B, drift variant):
// a STALE approval under --json on a terminal is the structured
// approval-drift block — the same machine-mode contract as headless.
func TestRestoreJSONOnTTYStaleApprovalNeverPrompts(t *testing.T) {
	h, runner := newRestoreHarness(t)
	trimCliws(t, h)
	tamperTrimApprovalToolSHA(t, h)
	reads := countingReadLine(h)
	h.tty = true

	code, stdout, stderr := h.run("restore", "--json", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("restore --json with a stale approval code = %d, want blocked (3); stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	errs := strings.Join(stringList(env["errors"]), " ")
	if !strings.Contains(errs, CodeApprovalDrift) {
		t.Fatalf("the structured error must carry %s: %v (stderr %s)", CodeApprovalDrift, errs, stderr)
	}
	if strings.Contains(stderr, "Approve these actions?") {
		t.Errorf("--json must not print an approval prompt:\n%s", stderr)
	}
	if reads := *reads; reads != 0 {
		t.Errorf("machine mode read stdin %d time(s); zero reads are required", reads)
	}
	if runner.count() != 0 {
		t.Errorf("nothing may run across unresolved drift; runner calls = %d", runner.count())
	}
}

// TestOpenJSONOnTTYMissingApprovalNeverPrompts (P1-B on `ebb open`):
// open shares the restore defect — its grouped approval resolver decided
// interactivity from the terminal alone, so `open --json` on a terminal
// dropped a scripted consumer into the hidden confirm. Machine mode must
// refuse with the typed approval-required error and zero reads.
func TestOpenJSONOnTTYMissingApprovalNeverPrompts(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	reads := countingReadLine(h)
	h.tty = true

	code, stdout, stderr := h.run("open", "cliws", "--to", gDest(t), "--json")
	if code != ExitRebuildFailed {
		t.Fatalf("open --json with a missing approval code = %d, want rebuild-blocked (6); stderr = %s", code, stderr)
	}
	// The structured result: the JSON envelope on stdout carries the
	// blocked rebuild phase. (Open's rebuild-failure reporting routes
	// the typed approval text to the human stream only — pre-existing.)
	env := envelopeOf(t, stdout)
	if got := envString(t, env, "phase"); got != catalog.PhaseRebuildFailed {
		t.Errorf("envelope phase = %q, want %s (stderr %s)", got, catalog.PhaseRebuildFailed, stderr)
	}
	if strings.Contains(stderr, "Approve these actions?") {
		t.Errorf("--json must not print an approval prompt:\n%s", stderr)
	}
	if reads := *reads; reads != 0 {
		t.Errorf("machine mode read stdin %d time(s); zero reads are required", reads)
	}
	if runner.count() != 0 {
		t.Errorf("nothing may run without a resolved approval; runner calls = %d", runner.count())
	}
}

// TestRestoreHeadlessMissingApprovalNamesRealAction (the small-B
// regression): restore has NO --yes flag, but its headless
// missing-approval guidance (inherited verbatim from open's grouped
// resolver) said "rerun with --yes" — a flag that does not exist on
// `ebb restore`. The message must name a REAL remediation (approve
// interactively in a terminal) and must never mention --yes.
func TestRestoreHeadlessMissingApprovalNamesRealAction(t *testing.T) {
	h, runner := newRestoreHarness(t)
	trimCliws(t, h)
	dropTrimApprovals(t, h)
	h.tty = false

	code, _, stderr := h.run("restore", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("restore headless with a missing approval code = %d, want blocked (3); stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, CodeApprovalRequired) {
		t.Errorf("stderr must carry the approval-required code:\n%s", stderr)
	}
	if strings.Contains(stderr, "--yes") {
		t.Errorf("restore's guidance recommends --yes, a flag `ebb restore` does not have:\n%s", stderr)
	}
	if !strings.Contains(stderr, "terminal") {
		t.Errorf("guidance must name the real remediation (interactive approval in a terminal):\n%s", stderr)
	}
	if runner.count() != 0 {
		t.Errorf("nothing may run without a resolved approval; runner calls = %d", runner.count())
	}
}

// TestOpenHeadlessMissingApprovalStillNamesItsYesFlag (small-B's other
// half): `ebb open` HAS --yes, and its headless missing-approval
// guidance must keep recommending it — parameterizing the guidance must
// not lose open's honest wording.
func TestOpenHeadlessMissingApprovalStillNamesItsYesFlag(t *testing.T) {
	h := newGHarness(t)
	parkG(t, h)
	runner := &gRunner{}
	withRunner(h, runner)
	h.tty = false

	code, _, stderr := h.run("open", "cliws", "--to", gDest(t))
	if code != ExitRebuildFailed {
		t.Fatalf("open headless with a missing approval code = %d, want rebuild-blocked (6); stderr = %s", code, stderr)
	}
	if !strings.Contains(stderr, CodeApprovalRequired) {
		t.Errorf("stderr must carry the approval-required code:\n%s", stderr)
	}
	if !strings.Contains(stderr, "rerun with --yes") {
		t.Errorf("open's guidance must keep recommending its real --yes flag:\n%s", stderr)
	}
	if runner.count() != 0 {
		t.Errorf("nothing may run without a resolved approval; runner calls = %d", runner.count())
	}
}
