package lifecycle

// wave5_reclaim_test.go pins the E05 single-source fix for trim's
// recreate commands: when a group carries a FROZEN action definition
// (the exact contract the user approved and restore replays), the trim
// result's ReclaimCommands — the text the receipt tells the user to run
// — must BE that definition's argv. Lifecycle's separate adapter-switch
// derivation (reclaimCommand) had drifted from the approved recipe (uv:
// --frozen vs the approved --locked), so the user was approved for one
// command and instructed to run another. The switch derivation stays
// only for genuinely legacy groups without a frozen definition
// (hint-only paths, D5).

import (
	"context"
	"testing"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/policy"
)

// trimWavebox runs one trim of the uv wavebox group over a fresh
// harness, with or without the frozen action definition.
func trimWavebox(t *testing.T, withDef bool) (TrimResult, trimPlanDoc) {
	t.Helper()
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("wavebox-ws")
	writeWaveboxFixture(t, root)

	pol, err := policy.Parse([]byte(waveboxPolicyTOML))
	if err != nil {
		t.Fatal(err)
	}
	opts := CaptureOptions{
		WorkspaceName: "wavebox-fixture", WorkspaceID: ws,
		Policy: pol, DoTrim: []string{"pydeps"},
		ApprovalReady: func(groupID string) error { return nil },
	}
	if withDef {
		opts.ActionDefs = []actions.Definition{waveboxActionDef()}
	}
	res, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	if err != nil {
		t.Fatalf("trim: %v", err)
	}

	// The persisted receipt twin: the sealed removal manifest.
	snaps, _ := h.coord().cat.ListSnapshots(ws)
	if len(snaps) != 1 || snaps[0].Kind != catalog.SnapshotKindTrim {
		t.Fatalf("trim snapshot row wrong: %+v", snaps)
	}
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	raw, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile,
		snaps[0].PayloadBackendID, prefix+"/"+removalManifestName)
	if err != nil {
		t.Fatalf("dump removal manifest: %v", err)
	}
	var plan trimPlanDoc
	if err := decodeStrictJSON(raw, &plan); err != nil {
		t.Fatalf("removal manifest: %v", err)
	}
	return res, plan
}

// TestTrimReceiptMatchesFrozenDefinition: trimming the uv group with its
// frozen definition reports the DEFINITION argv (`uv sync --locked` —
// what the approval covered) in TrimResult.ReclaimCommands, and the
// manifest's ReclaimCommand equals its frozen Definition argv exactly —
// one source of truth, no drifted adapter-switch copy.
func TestTrimReceiptMatchesFrozenDefinition(t *testing.T) {
	want := waveboxActionDef().Argv
	res, plan := trimWavebox(t, true)

	if len(res.ReclaimCommands) != 1 {
		t.Fatalf("reclaim commands = %v, want exactly one", res.ReclaimCommands)
	}
	if !equalStrings(res.ReclaimCommands[0], want) {
		t.Errorf("receipt reclaim command = %v, want the FROZEN definition argv %v (the user was approved for `uv sync --locked`, not instructed to run the drifted --frozen)",
			res.ReclaimCommands[0], want)
	}
	if len(plan.Groups) != 1 {
		t.Fatalf("plan groups = %d, want 1", len(plan.Groups))
	}
	g := plan.Groups[0]
	if g.Definition == nil {
		t.Fatalf("frozen plan carries NO definition for group %s", g.GroupID)
	}
	if !equalStrings(g.ReclaimCommand, g.Definition.Argv) {
		t.Errorf("manifest reclaim = %v, want its own frozen definition argv %v",
			g.ReclaimCommand, g.Definition.Argv)
	}
	if !equalStrings(g.Definition.Argv, want) {
		t.Errorf("frozen definition argv = %v, want %v", g.Definition.Argv, want)
	}
}

// TestTrimReceiptLegacyGroupStillDerives: WITHOUT a frozen definition
// (the hint-only/legacy plan shape — no ActionDefs), the trim keeps the
// adapter-switch derivation (`uv sync --frozen` here), the manifest
// records no definition object (the labeled legacy shape, D5), and the
// derived command stays consistent between result and manifest.
func TestTrimReceiptLegacyGroupStillDerives(t *testing.T) {
	legacy := []string{"uv", "sync", "--frozen"}
	res, plan := trimWavebox(t, false)

	if len(res.ReclaimCommands) != 1 {
		t.Fatalf("reclaim commands = %v, want exactly one", res.ReclaimCommands)
	}
	if !equalStrings(res.ReclaimCommands[0], legacy) {
		t.Errorf("legacy receipt reclaim = %v, want the derived %v (legacy groups keep the switch derivation)",
			res.ReclaimCommands[0], legacy)
	}
	if len(plan.Groups) != 1 {
		t.Fatalf("plan groups = %d, want 1", len(plan.Groups))
	}
	g := plan.Groups[0]
	if g.Definition != nil {
		t.Errorf("a legacy plan must carry no definition object (the D5 legacy label), got %+v", g.Definition)
	}
	if !equalStrings(g.ReclaimCommand, legacy) {
		t.Errorf("legacy manifest reclaim = %v, want %v", g.ReclaimCommand, legacy)
	}
}
