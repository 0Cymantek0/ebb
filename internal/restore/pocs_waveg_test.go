//go:build security_poc

package restore

// Wave G adversarial security PoCs (restore package, in-package so the
// unexported document/rebuild seams are reachable; Wave C/F precedent —
// opt-in via -tags security_poc so the default suite stays green).
//
// G1  Approval identity does not pin WorkingRoot or Outputs (Foundation
//
//	§7.3 explicitly authorizes "working root" and "output ownership"):
//	a definition mutated between two captures of the same action id —
//	arriving through the project's own Ebbfile, no vault or catalog
//	tampering needed — matches a previously recorded approval exactly,
//	never re-prompts, and its drifted Outputs widen the F36 gate's
//	exclusion set: the approved action can damage preserved content
//	under the new output root and the rebuild still completes DONE.
//
// G1b Unit-level proof of the same hole: ApprovalMatches returns nil
//
//	for a WorkingRoot-drifted definition.
//
// G2  A forged "succeeded" action_runs row (attacker with catalog write,
//
//	the D017 witness boundary) makes --resume skip the action and
//	complete DONE with the group never rebuilt — and the F36 gate
//	cannot catch it, because it never checks output presence.
//
// G3  Open has no vault-overlap preflight (I06 is enforced for captures
//
//	only): a destination inside the vault repository — staging,
//	published tree and all — is accepted without a word.
//
// A PoC test that FAILS prints "G* CONFIRMED" — the failure IS the
// reproduced vulnerability. A PoC that passes means the guard held.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ebb/internal/actions"
	"ebb/internal/actions/approvalstore"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/platform"
)

// mintVariantCapture re-freezes the fixture's capture documents with a
// mutated manifest (a legitimate second capture of the same unchanged
// workspace: same inventory bytes, same argv/inputs) and returns the new
// snapshot id. This is exactly what a new park after an Ebbfile edit
// produces — no tampering, every digest chain intact.
func mintVariantCapture(t *testing.T, f *fixture, mutate func(m *manifestDoc)) domain.SnapshotID {
	t.Helper()
	ctx := context.Background()

	var m manifestDoc
	if err := json.Unmarshal(f.manifestBytes, &m); err != nil {
		t.Fatalf("unmarshal fixture manifest: %v", err)
	}
	mutate(&m)
	op2 := domain.NewID()
	opDir2 := opPrefix + string(op2)
	snapID2 := domain.SnapshotID(domain.NewID())
	m.SnapshotID = string(snapID2) // the new capture's logical snapshot id
	for i := range m.Roots {       // re-point the meta root at the new op dir
		if m.Roots[i].ID == "meta" {
			m.Roots[i].BackendPrefix = opDir2
		}
	}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	mb = append(mb, '\n')
	manifestDigest := digestBytes(mb)

	dir2 := filepath.Join(f.parent, opDir2)
	if err := os.MkdirAll(dir2, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, manifestName), mb, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, inventoryName), f.inventoryBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "policy.toml"), []byte("# frozen policy v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payload, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent, []string{opDir2, f.wsPrefix},
		f.vault.Passfile, map[string]string{"ebb-kind": "payload"})
	if err != nil {
		t.Fatalf("variant payload snapshot: %v", err)
	}

	receipt := receiptDoc{
		SchemaVersion:    schemaVersionCurrent,
		SnapshotID:       string(snapID2),
		WorkspaceID:      string(f.wsID),
		BackendRepoID:    "fake-repo-id",
		PayloadBackendID: payload.BackendID,
		ManifestDigest:   manifestDigest,
		InventoryDigest:  f.inventoryDigest,
		RequiredFeatures: []string{},
		Verification: receiptVerification{
			Checks:       []string{"coverage-complete", "payload-readback-complete"},
			Scope:        "single-owned-root",
			Time:         domain.FormatTime(time.Now()),
			ToolVersions: map[string]string{"ebb": "fixture", "backend": "fakeStore"},
		},
		OperationID: string(op2),
		Retention:   "pinned",
	}
	rb, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rb = append(rb, '\n')
	sealDir2 := sealPrefix + string(op2)
	sealDir := filepath.Join(f.parent, sealDir2)
	if err := os.MkdirAll(sealDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sealDir, receiptName), rb, 0o600); err != nil {
		t.Fatal(err)
	}
	seal, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent, []string{sealDir2},
		f.vault.Passfile, map[string]string{"ebb-kind": "seal"})
	if err != nil {
		t.Fatalf("variant seal snapshot: %v", err)
	}

	if _, err := f.cat.RecordSnapshot(catalog.Snapshot{
		ID: snapID2, WorkspaceID: f.wsID,
		PayloadBackendID: payload.BackendID, SealBackendID: seal.BackendID,
		ManifestDigest: manifestDigest, InventoryDigest: f.inventoryDigest,
		Kind: catalog.SnapshotKindPark,
	}); err != nil {
		t.Fatalf("variant snapshot row: %v", err)
	}
	return snapID2
}

// TestPoCApprovalDriftOutputsBlindsF36Gate: capture 1 records an
// approval for argv `go version` with outputs ["node_modules"]; capture
// 2 (Ebbfile edit) widens outputs to ["node_modules", "sub"]. The
// approval matches without a prompt, the action trashes the preserved
// sub/b.txt, and the open completes DONE.
func TestPoCApprovalDriftOutputsBlindsF36Gate(t *testing.T) {
	f := buildFixture(t, fixtureSpec{recipeGroup: true, defArgv: []string{"go", "version"}})
	ctx := context.Background()
	store := approvalstore.New(filepath.Join(f.parent, "approvals.json"))

	// Capture 1's open: the resolver plays the user approving after the
	// grouped prompt (the prompt showed outputs: node_modules).
	o1, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner: &fakeRunner{}, Approver: store,
		Approve: func(ctx context.Context, pending []PendingApproval) error {
			for _, p := range pending {
				if _, aerr := store.Approve(p.Def, p.Tool, p.InputDigests, "interactive-confirm"); aerr != nil {
					return aerr
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dest1 := filepath.Join(f.parent, "opened-v1")
	res1, oerr := o1.Open(ctx, f.vault, f.snapID, Options{Destination: dest1})
	if oerr != nil || res1.Phase != catalog.PhaseDone {
		t.Fatalf("first open failed (fixture problem, not the PoC): %v (phase %s)", oerr, res1.Phase)
	}

	// Capture 2: the Ebbfile edit — same action id, same argv, same
	// inputs/env/network; outputs widened to cover the preserved "sub"
	// tree (policy-valid: ValidateRelPath accepts "sub").
	snap2 := mintVariantCapture(t, f, func(m *manifestDoc) {
		m.Actions[0].Definition.Outputs = []string{"node_modules", "sub"}
	})

	dest2 := filepath.Join(f.parent, "opened-v2")
	prompted := false
	malicious := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		for _, out := range def.Outputs {
			if err := os.MkdirAll(filepath.Join(dest2, filepath.FromSlash(out)), 0o755); err != nil {
				return actions.Result{ExitCode: -1}, err
			}
		}
		// The approved action damages preserved content now covered by
		// the drifted output set.
		if err := os.WriteFile(filepath.Join(dest2, "sub", "b.txt"), []byte("PWNED\n"), 0o644); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
		return actions.Result{ExitCode: 0}, nil
	}}
	o2, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner: malicious, Approver: store,
		Approve: func(ctx context.Context, pending []PendingApproval) error {
			prompted = true
			// The SAFE behavior re-prompts here (approval drift); decline
			// so a fixed build fails the open instead of running.
			return errors.New("re-approval requested (safe behavior); declined by the PoC")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res2, oerr := o2.Open(ctx, f.vault, snap2, Options{Destination: dest2})
	if oerr == nil && res2.Phase == catalog.PhaseDone && !prompted {
		b, _ := os.ReadFile(filepath.Join(dest2, "sub", "b.txt"))
		if string(b) == "PWNED\n" {
			t.Fatalf("G1 CONFIRMED: the drifted definition (outputs widened to cover the preserved "+
				"tree \"sub\") matched capture 1's recorded approval with NO re-prompt, ran, damaged the "+
				"preserved file sub/b.txt (%q), and the F36 gate never flagged it because every drifted "+
				"output root is excluded from protected verification — the rebuild completed DONE", b)
		}
	}
	// Fixed build: approval drift must re-prompt (prompted==true, open fails).
}

// TestPoCApprovalMatchesIgnoresWorkingRoot: unit-level — the pure
// comparison behind every Approver returns "exact match" for a
// definition whose WorkingRoot changed after the approval was recorded.
func TestPoCApprovalMatchesIgnoresWorkingRoot(t *testing.T) {
	approved := actions.Definition{
		ID: "build", Argv: []string{"go", "version"}, WorkingRoot: ".",
		Inputs: nil, Outputs: []string{"build"}, Network: actions.NetworkNone, Timeout: time.Minute,
	}
	drifted := approved
	drifted.WorkingRoot = "attacker-shipped-dir"
	tool := actions.ToolIdentity{Name: "go", ResolvedPath: `C:\go\bin\go.exe`, SHA256: "cafebabe"}
	appr := &actions.Approval{
		ActionID: "build", ArgvDigest: actions.ArgvDigest(approved.Argv), Tool: tool,
		InputDigests: map[string]string{}, EnvAllow: nil, Network: actions.NetworkNone,
	}
	if stale := actions.ApprovalMatches(appr, drifted, tool, map[string]string{}); stale == nil {
		t.Fatalf("G1b CONFIRMED: ApprovalMatches accepted a WorkingRoot drift (%q -> %q); "+
			"Foundation §7.3 pins the working root as approval-authorized state", approved.WorkingRoot, drifted.WorkingRoot)
	}
}

// TestPoCPoisonedActionRunJournalSkipsRebuild: a "succeeded" row forged
// into action_runs (catalog-write attacker — the D017 witness boundary)
// makes --resume skip the failed action and complete DONE with the
// group never rebuilt; the F36 gate cannot notice because it verifies
// only protected (non-output) entries, never output presence.
func TestPoCPoisonedActionRunJournalSkipsRebuild(t *testing.T) {
	f := buildFixture(t, fixtureSpec{recipeGroup: true, defArgv: []string{"go", "version"}})
	ctx := context.Background()
	store := approvalstore.New(filepath.Join(f.parent, "approvals.json"))
	dest := filepath.Join(f.parent, "opened")
	failing := &fakeRunner{fn: func(def actions.Definition) (actions.Result, error) {
		// Fails without creating any output.
		return actions.Result{ExitCode: 1}, nil
	}}
	resolver := func(ctx context.Context, pending []PendingApproval) error {
		for _, p := range pending {
			if _, aerr := store.Approve(p.Def, p.Tool, p.InputDigests, "interactive-confirm"); aerr != nil {
				return aerr
			}
		}
		return nil
	}
	o, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner: failing, Approver: store, Approve: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, oerr := o.Open(ctx, f.vault, f.snapID, Options{Destination: dest})
	if oerr == nil || res.Phase != catalog.PhaseRebuildFailed {
		t.Fatalf("first open should land at REBUILD_FAILED (fixture problem): %v (phase %s)", oerr, res.Phase)
	}
	opID := res.OperationID

	// The attacker (with catalog write) forges a successful run.
	runID, rerr := f.cat.StartActionRun(opID, "node-dependencies")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if ferr := f.cat.FinishActionRun(runID, catalog.ActionRunSucceeded, 0, "forged by catalog-write attacker"); ferr != nil {
		t.Fatal(ferr)
	}

	o2, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner: failing, Approver: store, Approve: func(ctx context.Context, p []PendingApproval) error {
			return errors.New("no approval should be needed for a skipped action")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	res2, rerr := o2.ResumeRebuild(ctx, f.vault, opID)
	if rerr == nil && res2.Phase == catalog.PhaseDone {
		if _, serr := os.Lstat(filepath.Join(dest, "node_modules")); os.IsNotExist(serr) {
			skipped := false
			for _, a := range res2.Actions {
				if a.ID == "node-dependencies" && a.Skipped {
					skipped = true
				}
			}
			if skipped {
				t.Fatalf("G2 CONFIRMED: a forged succeeded action_runs row made --resume skip the action; " +
					"the rebuild completed DONE/ready with node_modules never built and no check (F36 or " +
					"otherwise) verifying output presence for skipped actions")
			}
		}
	}
}

// TestPoCOpenPublishesInsideVaultRepository: I06 ("root/vault/operation
// paths cannot overlap through aliases unnoticed") is enforced on the
// capture side only — an open whose destination lies INSIDE the vault
// repository (staging sibling included) is accepted silently.
func TestPoCOpenPublishesInsideVaultRepository(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	if err := os.MkdirAll(f.vault.RepoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(f.vault.RepoDir, "restored-ws")
	o, err := New(Dependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, oerr := o.Open(context.Background(), f.vault, f.snapID, Options{Destination: dest, FilesOnly: true})
	if oerr == nil {
		if _, serr := os.Lstat(filepath.Join(dest, "a.txt")); serr == nil {
			// Any staging leftovers inside the repo?
			stageLeft := ""
			des, _ := os.ReadDir(f.vault.RepoDir)
			for _, de := range des {
				if len(de.Name()) > len(stagePrefix) && de.Name()[:len(stagePrefix)] == stagePrefix {
					stageLeft = de.Name()
				}
			}
			t.Fatalf("G3 CONFIRMED: open accepted a destination INSIDE the vault repository %s "+
				"(published a.txt there; phase %s; staging leftovers in repo: %q) — the capture-side I06 "+
				"overlap preflight has no open-side twin, so restore and vault state interleave unnoticed",
				f.vault.RepoDir, res.Phase, stageLeft)
		}
	}
}
