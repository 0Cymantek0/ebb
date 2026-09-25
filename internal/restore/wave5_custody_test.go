package restore

// wave5_custody_test.go pins the wave-5 restore-side custody contract:
//
//   - T2 (D2): a restore replays the FROZEN action definition verbatim —
//     argv, working root, network, env allowlist and timeout reach the
//     runner exactly as the trim sealed them (E05/E07 die here).
//   - T3 (D4): the REAL approval decides. An exact match (tool + digests
//     recorded at trim time) replays silently; a drifted tool binary
//     refuses; nothing fabricates an approval at restore time.
//   - T4 (D5): a legacy manifest (no frozen definitions) refuses normal
//     replay with a full disclosure, proceeds only behind fresh
//     explicit approval, and is labeled a "legacy recovery attempt".
//   - T6 (D7): a frozen working root that resolves through a
//     junction/symlink OUTSIDE the workspace refuses the restore before
//     any effect.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/pathcanon"
)

// frozenFixtureDef is the definition a wave-5 trim freezes for the
// standard fixture group (here with a NON-root working directory to
// prove verbatim replay).
func frozenFixtureDef(workingRoot string) *actionDefinitionDoc {
	return &actionDefinitionDoc{
		ID:          lrGroupName,
		Argv:        []string{"pnpm", "install", "--frozen-lockfile"},
		WorkingRoot: workingRoot,
		Inputs:      []string{"package.json", "pnpm-lock.yaml"},
		Outputs:     []string{"node_modules"},
		EnvAllow:    []string{"PNPM_HOME"},
		Network:     "allowed",
		TimeoutNS:   int64(15 * time.Minute),
	}
}

// TestRestoreReplaysFrozenDefinition: the runner receives the frozen
// argv, working root, network, env allowlist and timeout VERBATIM —
// never a synthesized WorkingRoot "." or hardcoded NetworkAllowed.
func TestRestoreReplaysFrozenDefinition(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenDef:   frozenFixtureDef("sub"),
		recordedGit: recGit, liveGit: liveGit,
	})
	// The declared working root exists (a real trim root would).
	if err := os.MkdirAll(filepath.Join(f.wsRoot, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &lrRunner{}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err != nil {
		t.Fatalf("frozen replay: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("phase = %s, want RESTORE_DONE", res.Phase)
	}
	defs := runner.definitions()
	if len(defs) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(defs))
	}
	def := defs[0]
	if def.ID != lrGroupName {
		t.Errorf("id = %q, want the frozen %q", def.ID, lrGroupName)
	}
	if strings.Join(def.Argv, " ") != "pnpm install --frozen-lockfile" {
		t.Errorf("argv = %v, want the frozen recipe verbatim", def.Argv)
	}
	if def.WorkingRoot != "sub" {
		t.Errorf("working root = %q, want the frozen %q (never a synthesized \".\")", def.WorkingRoot, "sub")
	}
	if def.Network != actions.NetworkAllowed {
		t.Errorf("network = %q, want the FROZEN declaration (never a hardcoded allowed)", def.Network)
	}
	if strings.Join(def.EnvAllow, ",") != "PNPM_HOME" {
		t.Errorf("env allow = %v, want [PNPM_HOME]", def.EnvAllow)
	}
	if def.Timeout != 15*time.Minute {
		t.Errorf("timeout = %s, want the frozen 15m", def.Timeout)
	}
	if strings.Join(def.Outputs, ",") != "node_modules" {
		t.Errorf("outputs = %v, want [node_modules]", def.Outputs)
	}
}

// TestRestoreApprovalExactMatchRunsSilently: the approval recorded at
// trim time matches the CURRENT tool and input digests exactly — the
// replay runs and the approval resolver is NEVER invoked (D033's
// no-re-prompt property, now on real trust).
func TestRestoreApprovalExactMatchRunsSilently(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenDef:   frozenFixtureDef("."),
		recordedGit: recGit, liveGit: liveGit,
	})
	// Fail loud if anything prompts: an exact match must not re-approve.
	f.resolver = func(ctx context.Context, pending []PendingApproval) error {
		t.Errorf("approval resolver invoked for an exact match: %+v", pending)
		return errors.New("no prompt expected")
	}
	runner := &lrRunner{}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err != nil {
		t.Fatalf("exact-match replay must run silently: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone || len(runner.definitions()) != 1 {
		t.Fatalf("res.Phase = %s, runner calls = %d", res.Phase, len(runner.definitions()))
	}
}

// TestRestoreApprovalDriftRefuses: rewriting the pinned tool binary
// (different SHA-256) makes the recorded approval stale — the restore
// refuses with the re-approval guidance and NOTHING runs. A second
// restore with the approval store emptied proves no approval is ever
// fabricated at restore time (the tautology is gone).
func TestRestoreApprovalDriftRefuses(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenDef:   frozenFixtureDef("."),
		recordedGit: recGit, liveGit: liveGit,
	})
	// Non-interactive: no resolver, no prompt.
	f.resolver = nil
	runner := &lrRunner{}

	// Tool drift: same path, different bytes (different SHA-256).
	writeFile(t, f.toolPath, []byte("@echo off\r\nrem REBUILT tool\r\n"))
	_, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err == nil {
		t.Fatalf("a drifted tool binary must refuse the replay")
	}
	if calls := len(runner.definitions()); calls != 0 {
		t.Fatalf("runner invocations = %d, want 0 (refused before any recipe)", calls)
	}
	var req *ErrRestoreApprovalRequired
	if !errors.As(err, &req) {
		t.Fatalf("expected *ErrRestoreApprovalRequired, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "re-approve") {
		t.Fatalf("blocked error must explain how to re-approve: %v", err)
	}

	// No fabrication: with the approval store emptied entirely, the same
	// replay refuses again — the old driver synthesized an exact
	// approval out of thin air, this one must not.
	empty := buildTrimFixture(t, trimFixtureSpec{
		frozenDef:      frozenFixtureDef("."),
		noTrimApproval: true,
		recordedGit:    recGit, liveGit: liveGit,
	})
	empty.resolver = nil
	_, err = empty.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), empty.vault, empty.wsRoot, LiveRestoreOptions{})
	if !errors.As(err, &req) {
		t.Fatalf("a missing approval must refuse (nothing may fabricate one), got %T: %v", err, err)
	}
}

// TestLegacyTrimManifestRequiresFreshApproval: a manifest without the
// frozen definition refuses normal replay with the disclosure (command,
// root, inputs, outputs; historical approval identity unavailable) and
// opens no operation; behind fresh explicit consent it executes through
// the legacy synthesis path labeled a "legacy recovery attempt" — which
// never claims to be the previously-approved action.
func TestLegacyTrimManifestRequiresFreshApproval(t *testing.T) {
	recGit, liveGit := noDriftGit()

	// (a) Normal replay refused, zero effects.
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	f.resolver = nil // non-interactive, no --legacy-approve
	runner := &lrRunner{}
	_, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err == nil {
		t.Fatalf("a legacy manifest must refuse normal replay (D5)")
	}
	var legacy *ErrLegacyTrimManifest
	if !errors.As(err, &legacy) {
		t.Fatalf("expected *ErrLegacyTrimManifest, got %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range []string{
		"pnpm install --frozen-lockfile", // the command
		"package.json", "pnpm-lock.yaml", // the inputs
		"node_modules", // the outputs
		"historical approval identity is unavailable",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("disclosure lacks %q:\n%s", want, msg)
		}
	}
	if calls := len(runner.definitions()); calls != 0 {
		t.Fatalf("runner invocations = %d, want 0", calls)
	}
	ops, lerr := f.cat.ListOperations(f.wsID)
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, op := range ops {
		if op.Kind == catalog.OpKindRestore {
			t.Fatalf("legacy refusal must not open a restore operation row: %+v", op)
		}
	}

	// (b) Fresh explicit consent (--legacy-approve) → legacy recovery
	// attempt runs through the old synthesis path, labeled honestly.
	f2 := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	runner2 := &lrRunner{}
	res, err := f2.newLiveRestorer(runner2).LiveRestore(context.Background(), f2.vault, f2.wsRoot,
		LiveRestoreOptions{LegacyApprove: true})
	if err != nil {
		t.Fatalf("consented legacy replay must run: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone || len(runner2.definitions()) != 1 {
		t.Fatalf("res.Phase = %s, runner calls = %d", res.Phase, len(runner2.definitions()))
	}
	if len(res.Groups) != 1 || !res.Groups[0].Legacy {
		t.Fatalf("legacy group not labeled: %+v", res.Groups)
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, "legacy recovery attempt") {
		t.Fatalf("the legacy label warning is missing: %v", res.Warnings)
	}
	if !strings.Contains(joined, "freshly approved NOW") ||
		!strings.Contains(joined, "are not the previously-approved actions") {
		t.Fatalf("the warning must state the recipes are freshly approved NOW and NOT the previously-approved actions: %v", res.Warnings)
	}
}

// TestWorkingRootJunctionEscapeRefused: a frozen working root that
// resolves through a junction/symlink pointing OUTSIDE the workspace
// refuses the whole restore before any recipe runs (D7).
func TestWorkingRootJunctionEscapeRefused(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenDef:   frozenFixtureDef("sub"),
		recordedGit: recGit, liveGit: liveGit,
	})
	outside := filepath.Join(f.parent, "outside-target")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	// sub -> outside (symlink where permitted, unprivileged Windows
	// junction otherwise — the same creator discipline existing tests use).
	linkPath := filepath.Join(f.wsRoot, "sub")
	if serr := os.Symlink(outside, linkPath); serr != nil {
		out, jerr := exec.Command("cmd", "/c", "mklink", "/J", linkPath, outside).CombinedOutput()
		if jerr != nil {
			t.Skipf("cannot create the escape link fixture (symlink %v; junction %v: %s)", serr, jerr, out)
		}
	}

	runner := &lrRunner{}
	_, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err == nil {
		t.Fatalf("a working root escaping the workspace must refuse the restore (D7)")
	}
	var esc *ErrWorkingRootEscape
	if !errors.As(err, &esc) {
		t.Fatalf("expected *ErrWorkingRootEscape, got %T: %v", err, err)
	}
	// Compare canonical spellings: pathcanon resolves the 8.3-short
	// temp spellings, so the raw fixture spelling may differ.
	if !strings.Contains(err.Error(), "outside") || !strings.Contains(err.Error(), pathcanon.CanonicalPath(outside)) {
		t.Fatalf("refusal must name the resolved outside path: %v", err)
	}
	if calls := len(runner.definitions()); calls != 0 {
		t.Fatalf("runner invocations = %d, want 0 (refused before any recipe)", calls)
	}
}
