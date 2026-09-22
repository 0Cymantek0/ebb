package restore

// liverestore.go is the D033 driver: `ebb restore` re-executes a sealed
// trim's recorded recipes IN-PLACE on the live workspace. It is the
// direct functional inverse of `ebb reclaim`/`ebb trim` for active
// projects:
//
//   - select the workspace's latest completed trim and read its sealed
//     documents from the payload (digest-witnessed, strict-parsed);
//   - the Git pre-flight gate fails closed on in-flight merge/rebase
//     state and never auto-decides a branch mismatch;
//   - the outputs-present gate refuses a redundant restore unless a
//     FAILED/RUNNING restore op makes the rerun a resume;
//   - recipe-input drift is reconciled by an explicit strategy
//     (merge / current / baseline); Ebb unions TOP-LEVEL declared
//     manifests only and NEVER edits lockfiles or synthesizes
//     dependency graphs — resolution is 100% native tool (D033 golden
//     rule);
//   - recipes run through the actions runner (action_runs journaled)
//     under a NEW restore operation (RESTORE_PLANNED → RESTORE_RUNNING
//     → RESTORE_DONE), with NO interactive tool re-approval — the
//     recipe was displayed and approved at trim time and is sealed in
//     the manifest;
//   - carve-out overlay patches (D034) are re-applied after the recipes
//     so custom edits land on top of downloaded files;
//   - the post-flight protected-file integrity gate compares a full
//     pre/post walk of everything outside the groups' outputs, minus
//     the files the chosen strategy intentionally wrote.
//
// The driver owns NO prompting: interactive choice lives in the CLI
// through the Prompter seam (restore must not import internal/cli), and
// Git observation arrives through the ObserveGit seam (restore must not
// import internal/adapters).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// Strategy names a drift-reconciliation strategy (D033 §5). The zero
// value means "no strategy chosen yet" (no drift, or a choice is
// required).
type Strategy string

const (
	StrategyMerge    Strategy = "merge"    // union manifests, live wins, native tool resolves
	StrategyCurrent  Strategy = "current"  // run the live files unchanged
	StrategyBaseline Strategy = "baseline" // write the frozen inputs back, frozen recipe
)

// Valid reports whether s is one of the accepted strategy spellings.
func (s Strategy) Valid() bool {
	switch s {
	case StrategyMerge, StrategyCurrent, StrategyBaseline:
		return true
	}
	return false
}

// String renders the strategy ("" for none).
func (s Strategy) String() string { return string(s) }

// DriftEntry is one recipe input's divergence from the frozen trim
// baseline. State is "differs" (both sides exist, digests differ),
// "missing" (frozen copy exists, the live file is gone) or "new" (the
// input was absent at trim time and exists now).
type DriftEntry struct {
	Group    string `json:"group"`
	Path     string `json:"path"`
	State    string `json:"state"`
	Recorded string `json:"recorded,omitempty"`
	Live     string `json:"live,omitempty"`
}

func (d DriftEntry) Describe() string {
	switch d.State {
	case "missing":
		return fmt.Sprintf("recorded %s, live file absent", shortDigest(d.Recorded))
	case "new":
		return fmt.Sprintf("absent at trim time, live file now %s", shortDigest(d.Live))
	default:
		return fmt.Sprintf("recorded %s, live %s", shortDigest(d.Recorded), shortDigest(d.Live))
	}
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12] + "…"
	}
	if d == "" {
		return "(none)"
	}
	return d
}

// BranchMismatch is the Git-context divergence the branch gate reports
// to the interactive seam (D033 rule 1).
type BranchMismatch struct {
	Root             string
	RecordedBranch   string
	RecordedCommit   string
	RecordedDetached bool
	LiveBranch       string
	LiveCommit       string
	LiveDetached     bool
}

// BranchChoice is one resolution of a branch mismatch.
type BranchChoice int

const (
	// BranchSwitchBack: switch back to the recorded branch first (the
	// driver returns ErrBranchSwitchAdvice naming the exact command).
	BranchSwitchBack BranchChoice = iota + 1
	// BranchRebuildCurrent: rebuild for the current branch using the
	// live manifests.
	BranchRebuildCurrent
	// BranchCancel: cancel the restore.
	BranchCancel
)

// Prompter is the CLI-supplied interactive seam. Both methods are
// invoked only when a decision is genuinely the user's; the driver
// NEVER auto-decides. ChooseStrategy returning ("", nil) means the user
// cancelled; returning any other error fails the restore as declined.
type Prompter interface {
	ChooseBranch(ctx context.Context, m BranchMismatch) (BranchChoice, error)
	ChooseStrategy(ctx context.Context, drift []DriftEntry) (Strategy, error)
}

// LiveDependencies wires the live-restore driver. Store, Cat and Probe
// are required; New refuses nil seams so a half-constructed driver can
// never reach execution (mirroring New/Dependencies in restore.go).
type LiveDependencies struct {
	Store domain.SnapshotStore
	Cat   *catalog.Catalog
	Probe domain.PlatformProbe
	// CreateLink recreates overlay links (links.go seam). Optional;
	// defaults to the stdlib creator with the typed privilege contract.
	CreateLink LinkCreator
	// Runner executes the recipes (satisfied by *actions.Runner; tests
	// substitute a fake). Required for every non-dry-run restore.
	Runner ActionRunner
	// ObserveGit produces the live Git observation for the pre-flight
	// gate. Required whenever the trim recorded a Git context.
	ObserveGit func(ctx context.Context, root string) (domain.GitObservation, error)
	// Prompt is the interactive decision seam; nil = non-interactive
	// (branch mismatches and unreconciled drift then refuse).
	Prompt Prompter
	Clock  func() time.Time // optional; defaults to time.Now
}

// LiveRestorer executes `ebb restore` sequences. Safe for sequential
// use by the serialized CLI (D11).
type LiveRestorer struct {
	store      domain.SnapshotStore
	cat        *catalog.Catalog
	probe      domain.PlatformProbe
	createLink LinkCreator
	runner     ActionRunner
	observeGit func(ctx context.Context, root string) (domain.GitObservation, error)
	prompt     Prompter
	now        func() time.Time
}

// NewLiveRestorer validates the seams and returns a ready driver.
func NewLiveRestorer(d LiveDependencies) (*LiveRestorer, error) {
	if d.Store == nil {
		return nil, fmt.Errorf("restore: live dependencies: Store is required")
	}
	if d.Cat == nil {
		return nil, fmt.Errorf("restore: live dependencies: Cat is required")
	}
	if d.Probe == nil {
		return nil, fmt.Errorf("restore: live dependencies: Probe is required")
	}
	if d.CreateLink == nil {
		d.CreateLink = stdlibCreateLink
	}
	if d.Clock == nil {
		d.Clock = time.Now
	}
	return &LiveRestorer{
		store: d.Store, cat: d.Cat, probe: d.Probe, createLink: d.CreateLink,
		runner: d.Runner, observeGit: d.ObserveGit, prompt: d.Prompt, now: d.Clock,
	}, nil
}

// LiveRestoreOptions parameterizes one restore.
type LiveRestoreOptions struct {
	// Strategy pre-decides drift reconciliation (the --strategy flag).
	// Required non-interactively whenever drift exists.
	Strategy Strategy
	// DryRun reports the selected trim, groups, commands, drift table
	// and overlay list with zero effects (no operation row, no writes,
	// no prompts).
	DryRun bool
}

// RestoredGroup is one group's outcome in the result.
type RestoredGroup struct {
	GroupID  string
	Command  []string
	Drift    []DriftEntry
	Overlays []string
}

// LiveRestoreResult reports a completed (or previewed) restore.
type LiveRestoreResult struct {
	WorkspaceID     domain.WorkspaceID
	TrimOperationID domain.OperationID
	SnapshotID      domain.SnapshotID
	OperationID     domain.OperationID
	Root            string
	Strategy        Strategy
	DryRun          bool
	Drift           []DriftEntry
	Groups          []RestoredGroup
	Actions         []ActionReport
	OverlaysApplied []string
	Warnings        []string
	// Phase is the operation's terminal phase ("" on a dry run).
	Phase string
}

// liveRestoreTimeout bounds one recipe execution.
const liveRestoreTimeout = 15 * time.Minute

// LiveRestore runs the D033 sequence for the workspace at root.
func (o *LiveRestorer) LiveRestore(ctx context.Context, vault VaultRef, root string, opts LiveRestoreOptions) (LiveRestoreResult, error) {
	if ctx == nil {
		return LiveRestoreResult{}, fmt.Errorf("restore: nil context")
	}
	if opts.Strategy != "" && !opts.Strategy.Valid() {
		return LiveRestoreResult{}, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"strategy %q is not one of merge, current, baseline", opts.Strategy)}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return LiveRestoreResult{}, &ErrInvalidOptions{Detail: fmt.Sprintf("resolving path %q: %v", root, err)}
	}
	if fi, serr := os.Stat(absRoot); serr != nil || !fi.IsDir() {
		return LiveRestoreResult{}, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"restore target %s is not an existing directory: %v", absRoot, serr)}
	}
	if vault.RepoDir == "" || vault.Passfile == "" {
		return LiveRestoreResult{}, &ErrInvalidOptions{Detail: "vault RepoDir and Passfile are required"}
	}

	// ---- select the latest completed trim ------------------------------
	ws, trimOp, snap, serr := o.selectTrimRecord(absRoot)
	if serr != nil {
		return LiveRestoreResult{}, serr
	}
	if !opts.DryRun && o.runner == nil {
		return LiveRestoreResult{}, &ErrInvalidOptions{Detail: "the actions runner seam is not wired; recipes cannot execute"}
	}
	res := LiveRestoreResult{
		WorkspaceID: ws.ID, TrimOperationID: trimOp.ID, SnapshotID: snap.ID,
		Root: absRoot, Strategy: opts.Strategy, DryRun: opts.DryRun,
	}

	// ---- read the sealed trim documents --------------------------------
	docs, derr := readTrimDocs(ctx, o.store, vault, snap.PayloadBackendID, string(trimOp.ID),
		snap.ManifestDigest, snap.InventoryDigest)
	if derr != nil {
		return res, derr
	}

	// ---- Git pre-flight gate (D033 rules 1-2) --------------------------
	if err := o.gitGate(ctx, absRoot, docs.manifest.GitObservations, opts.DryRun, &res); err != nil {
		return res, err
	}

	// ---- outputs-present gate -------------------------------------------
	ops, lerr := o.cat.ListOperations(ws.ID)
	if lerr != nil {
		return res, fmt.Errorf("restore: list operations of %s: %w", ws.ID, lerr)
	}
	if outputsAllPresent(absRoot, docs.plan.Groups) && !hasResumableRestoreOp(ops) {
		return res, &ErrAlreadyRestored{Root: absRoot, TrimOp: string(trimOp.ID)}
	}

	// ---- supersede dead restore rows (BEFORE any later refusal) ---------
	// Close stale RUNNING/FAILED restore rows of THIS workspace to CANCELED
	// here — ahead of the refusals below that return WITHOUT opening an
	// operation (headless drift without --strategy returning
	// ErrStrategyRequired in particular). The rerun may not proceed, but
	// it must still un-wedge the dead row: a restore owns no removal
	// authority, so closing it is always safe, while leaving it open
	// blocks every later destructive operation (trim/reclaim/park) until
	// someone runs the cancel verb (Wave 1 restore review F3). A dry run
	// stays zero-effects and leaves superseding to a real rerun.
	if !opts.DryRun {
		for _, prev := range ops {
			if prev.Kind != catalog.OpKindRestore {
				continue
			}
			switch prev.Phase {
			case catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed:
				_ = o.cat.FailOperation(prev.ID, prev.Phase,
					"superseded by a restore rerun (D033: a failed restore is resumable by rerunning; `ebb recover <op> --cancel` closes it when no rerun can proceed)")
				_ = o.cat.AdvanceOperation(prev.ID, prev.Phase, catalog.PhaseCanceled)
			}
		}
	}

	// ---- drift detection -------------------------------------------------
	drift := detectDrift(absRoot, docs.plan.Groups)
	res.Drift = drift
	res.Groups = previewGroups(docs.plan.Groups, drift, opts.Strategy)

	if len(drift) == 0 && opts.Strategy != "" {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"no drift detected; strategy %s unused (all recipes run from the frozen baseline)", opts.Strategy))
	}

	// ---- strategy resolution ---------------------------------------------
	strategy := Strategy("")
	if len(drift) > 0 {
		switch {
		case opts.Strategy != "":
			strategy = opts.Strategy
		case opts.DryRun:
			res.Warnings = append(res.Warnings,
				"drift detected: a real run needs --strategy merge|current|baseline (or an interactive choice in a terminal)")
		case o.prompt == nil:
			return res, &ErrStrategyRequired{Root: absRoot, Drift: drift}
		default:
			choice, perr := o.prompt.ChooseStrategy(ctx, drift)
			if perr != nil {
				var declined *ErrRestoreDeclined
				if errors.As(perr, &declined) {
					return res, perr
				}
				return res, &ErrRestoreDeclined{Root: absRoot, Detail: perr.Error()}
			}
			if choice == "" {
				return res, &ErrRestoreDeclined{Root: absRoot, Detail: "the reconciliation menu was cancelled"}
			}
			strategy = choice
		}
	}
	res.Strategy = strategy
	res.Groups = previewGroups(docs.plan.Groups, drift, strategy)

	// ---- dry run: report and stop ---------------------------------------
	if opts.DryRun {
		return res, nil
	}

	// ---- durable restore operation --------------------------------------
	ident, ierr := o.probe.RootIdentity(absRoot)
	if ierr != nil {
		return res, fmt.Errorf("restore: root identity of %s: %w", absRoot, ierr)
	}
	opID, berr := o.cat.BeginOperation(ws.ID, catalog.OpKindRestore, absRoot, ident.String(),
		liveRestoreIntentDigest(string(trimOp.ID), strategy, absRoot))
	if berr != nil {
		return res, fmt.Errorf("restore: begin operation: %w", berr)
	}
	res.OperationID = opID
	fail := func(action, reason string, cause error) (LiveRestoreResult, error) {
		msg := reason
		if cause != nil {
			msg += ": " + cause.Error()
		}
		_ = o.cat.FailOperation(opID, catalog.PhaseRestoreRunning, msg)
		_ = o.cat.AdvanceOperation(opID, catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed)
		return res, &ErrLiveRestoreFailed{
			OperationID: opID, TrimOp: trimOp.ID, FailedAction: action, Reason: reason, Err: cause}
	}
	// (Dead restore rows were already superseded by the early loop above.)
	if err := o.cat.SetBackendRefs(opID, snap.PayloadBackendID, snap.SealBackendID); err != nil {
		return res, fmt.Errorf("restore: record backend refs: %w", err)
	}
	if err := o.cat.AdvanceOperation(opID, catalog.PhasePlanned, catalog.PhaseRestorePlanning); err != nil {
		return res, fmt.Errorf("restore: advance %s: PLANNED -> RESTORE_PLANNED: %w", opID, err)
	}
	if err := o.cat.AdvanceOperation(opID, catalog.PhaseRestorePlanning, catalog.PhaseRestoreRunning); err != nil {
		return res, fmt.Errorf("restore: advance %s: RESTORE_PLANNED -> RESTORE_RUNNING: %w", opID, err)
	}

	var outputRoots []string
	for _, g := range docs.plan.Groups {
		outputRoots = append(outputRoots, g.Outputs...)
	}

	// ---- protected-set baseline walk (before any execution) --------------
	before, werr := walkProtected(absRoot, outputRoots)
	if werr != nil {
		return fail("", "walking the live root for the protected-set baseline", werr)
	}

	// ---- strategy application (backups + manifest writes) ----------------
	exempt, aerr := o.applyStrategy(ctx, vault, docs, snap.PayloadBackendID, absRoot, drift, strategy, &res.Warnings)
	if aerr != nil {
		return fail("", "applying the reconciliation strategy", aerr)
	}

	// ---- execution: frozen recipes through the actions runner ------------
	appr := sealedManifestApprover{now: o.now}
	for i := range docs.plan.Groups {
		g := docs.plan.Groups[i]
		if cerr := ctx.Err(); cerr != nil {
			return fail("", "cancelled", cerr)
		}
		def, dwerr := groupDefinition(absRoot, trimOp.ID, g, drift, strategy, &res.Warnings)
		if dwerr != nil {
			return fail("", "building the action definition for group "+g.GroupID, dwerr)
		}
		rep, rerr := o.runRecipe(ctx, opID, def, absRoot, appr)
		res.Actions = append(res.Actions, rep)
		if rerr != nil {
			if errors.Is(rerr, context.Canceled) || errors.Is(rerr, context.DeadlineExceeded) {
				return res, &ErrLiveRestoreFailed{OperationID: opID, TrimOp: trimOp.ID,
					FailedAction: def.ID, Reason: "cancelled", Err: rerr}
			}
			return fail(def.ID, "recipe failed", rerr)
		}
	}

	// ---- overlay reapplication (D034) -------------------------------------
	applied, oerr := o.applyOverlays(ctx, vault, docs, snap.PayloadBackendID, absRoot)
	res.OverlaysApplied = applied
	if oerr != nil {
		return fail("", "re-applying carved-out overlay patches", oerr)
	}

	// ---- post-flight protected-file integrity gate ------------------------
	after, werr2 := walkProtected(absRoot, outputRoots)
	if werr2 != nil {
		return fail("", "re-walking the live root for the protected-file gate", werr2)
	}
	// F1 (Wave 1 restore review): a group executed via its recreate_live
	// variant under merge/current runs a plain `pnpm install` / `npm
	// install` / `uv sync`, which legitimately REWRITES recipe-input paths
	// at the workspace root — most notably the lockfile, which regenerates
	// whenever the unioned/current manifests differ from what it recorded,
	// even when the lockfile itself never drifted. Exempt ALL of those
	// groups' recorded input paths from the after-pass comparison and
	// REPORT each input whose digest actually changed as a warning instead
	// of a failure. Baseline (frozen commands: --frozen-lockfile, npm ci,
	// --locked) adds NO exemptions: those commands must not touch their
	// inputs, and the gate stays strict there.
	for _, p := range sortedBoolKeys(liveVariantInputs(docs.plan.Groups, drift, strategy)) {
		if exempt[p] {
			continue // the strategy itself wrote it (already reported)
		}
		exempt[p] = true
		b, bok := before[p]
		a, aok := after[p]
		if bok && aok && b.kind == "file" && a.kind == "file" && a.digest != b.digest {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"input %s rewritten by the native resolver (expected under merge/current)", p))
		}
	}
	if changes := compareProtected(before, after, exempt); len(changes) > 0 {
		return fail("", "protected-file integrity gate", &ErrProtectedChanged{Changes: changes})
	}

	if err := o.cat.AdvanceOperation(opID, catalog.PhaseRestoreRunning, catalog.PhaseRestoreDone); err != nil {
		return res, fmt.Errorf("restore: advance %s: RESTORE_RUNNING -> RESTORE_DONE: %w", opID, err)
	}
	res.Phase = catalog.PhaseRestoreDone
	return res, nil
}

// ---- selection ---------------------------------------------------------------

// selectTrimRecord resolves the workspace, its newest completed trim
// operation and that trim's snapshot row for root. Match order: a
// workspace whose recorded RootPath equals the root, else a workspace
// with a completed trim whose SourceRoot equals the root; among
// candidates the newest TRIM_DONE row wins (ListOperations orders
// ascending by recency).
func (o *LiveRestorer) selectTrimRecord(root string) (catalog.Workspace, catalog.Operation, catalog.Snapshot, error) {
	workspaces, err := o.cat.ListWorkspaces()
	if err != nil {
		return catalog.Workspace{}, catalog.Operation{}, catalog.Snapshot{},
			fmt.Errorf("restore: list workspaces: %w", err)
	}
	sameRoot := func(p string) bool { return filepath.Clean(p) == filepath.Clean(root) }

	var candidates []catalog.Workspace
	for _, w := range workspaces {
		if w.RootPath != "" && sameRoot(w.RootPath) {
			candidates = append(candidates, w)
		}
	}
	if len(candidates) == 0 {
		// Fallback: a completed trim's recorded source root still binds a
		// workspace to this path even when the workspace row moved on.
		all, aerr := o.cat.ListOperations("")
		if aerr != nil {
			return catalog.Workspace{}, catalog.Operation{}, catalog.Snapshot{},
				fmt.Errorf("restore: list operations: %w", aerr)
		}
		byID := map[domain.WorkspaceID]bool{}
		for _, op := range all {
			if op.Kind == catalog.OpKindTrim && op.Phase == catalog.PhaseTrimDone && op.SourceRoot != "" && sameRoot(op.SourceRoot) {
				byID[op.WorkspaceID] = true
			}
		}
		for _, w := range workspaces {
			if byID[w.ID] {
				candidates = append(candidates, w)
			}
		}
	}

	var bestOp *catalog.Operation
	var bestWS catalog.Workspace
	for _, w := range candidates {
		ops, lerr := o.cat.ListOperations(w.ID)
		if lerr != nil {
			return catalog.Workspace{}, catalog.Operation{}, catalog.Snapshot{},
				fmt.Errorf("restore: list operations of %s: %w", w.ID, lerr)
		}
		for i := range ops {
			op := ops[i]
			if op.Kind == catalog.OpKindTrim && op.Phase == catalog.PhaseTrimDone {
				if bestOp == nil || op.UpdatedAt > bestOp.UpdatedAt {
					opCopy := op
					bestOp = &opCopy
					bestWS = w
				}
			}
		}
	}
	if bestOp == nil {
		return catalog.Workspace{}, catalog.Operation{}, catalog.Snapshot{},
			&ErrNothingToRestore{Root: root}
	}
	if bestOp.PayloadSnap == "" {
		return catalog.Workspace{}, catalog.Operation{}, catalog.Snapshot{},
			&ErrVerification{Check: "trim-documents", Details: []string{fmt.Sprintf(
				"trim operation %s records no payload backend id; its sealed plan cannot be located", bestOp.ID)}}
	}
	snaps, serr := o.cat.ListSnapshots(bestWS.ID)
	if serr != nil {
		return catalog.Workspace{}, catalog.Operation{}, catalog.Snapshot{},
			fmt.Errorf("restore: list snapshots of %s: %w", bestWS.ID, serr)
	}
	for i := range snaps {
		if snaps[i].PayloadBackendID == bestOp.PayloadSnap {
			return bestWS, *bestOp, snaps[i], nil
		}
	}
	return catalog.Workspace{}, catalog.Operation{}, catalog.Snapshot{},
		&ErrVerification{Check: "trim-documents", Details: []string{fmt.Sprintf(
			"no snapshot row records the payload %s of trim operation %s", bestOp.PayloadSnap, bestOp.ID)}}
}

// ---- Git pre-flight gate ------------------------------------------------------

// gitGate enforces D033 rules 1-2 against a fresh live observation.
// The in-flight conflict gate fails closed ALWAYS (even interactive).
// The branch gate refuses non-interactively and hands the decision to
// the Prompter seam otherwise; dry runs never prompt and report the
// mismatch as a warning instead.
func (o *LiveRestorer) gitGate(ctx context.Context, root string, recorded domain.GitObservation, dryRun bool, res *LiveRestoreResult) error {
	if !recorded.IsRepo {
		return nil // nothing was recorded to diverge from
	}
	if o.observeGit == nil {
		return &ErrInvalidOptions{Detail: "the trim recorded a Git context but no Git observer is wired; the branch gate cannot run (fail closed)"}
	}
	live, err := o.observeGit(ctx, root)
	if err != nil {
		return &ErrGitConflict{Root: root, Details: []string{fmt.Sprintf("live Git observation failed: %v", err)}}
	}

	// Rule 2: in-flight conflict gate — fail closed, no exceptions.
	if details := conflictDetails(live); len(details) > 0 {
		return &ErrGitConflict{Root: root, Details: details}
	}

	// Rule 1: branch/commit parity.
	mismatch := branchDivergence(recorded, live)
	if mismatch == nil {
		return nil
	}
	if dryRun {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"branch mismatch on a dry run (nothing ran): trim recorded %s, live is %s; a real run asks switch-back / rebuild-current / cancel",
			mismatch.RecordedLabel(), mismatch.LiveLabel()))
		return nil
	}
	if o.prompt == nil {
		return &ErrBranchMismatch{Root: root, Recorded: mismatch.RecordedLabel(), Live: mismatch.LiveLabel(), Detached: mismatch.RecordedDetached}
	}
	choice, perr := o.prompt.ChooseBranch(ctx, *mismatch)
	if perr != nil {
		var declined *ErrRestoreDeclined
		if errors.As(perr, &declined) {
			return perr
		}
		return &ErrRestoreDeclined{Root: root, Detail: perr.Error()}
	}
	switch choice {
	case BranchSwitchBack:
		branch := mismatch.RecordedBranch
		if branch == "" {
			branch = mismatch.RecordedCommit // recorded detached: return to the commit
		}
		return &ErrBranchSwitchAdvice{Root: root, Recorded: mismatch.RecordedLabel(),
			SwitchArgv: []string{"git", "switch", branch}}
	case BranchRebuildCurrent:
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"rebuilding for the current Git context %s (the trim was recorded on %s)", mismatch.LiveLabel(), mismatch.RecordedLabel()))
		return nil
	default:
		return &ErrRestoreDeclined{Root: root, Detail: "the branch-mismatch menu was cancelled"}
	}
}

// conflictDetails lists the in-flight markers of a live observation.
func conflictDetails(obs domain.GitObservation) []string {
	var details []string
	if obs.UnmergedEntries > 0 {
		details = append(details, fmt.Sprintf("%d unmerged index entries", obs.UnmergedEntries))
	}
	if obs.MergeInProgress {
		details = append(details, "MERGE_HEAD present (merge in progress)")
	}
	if obs.RebaseInProgress {
		details = append(details, "rebase-merge/rebase-apply present (rebase in progress)")
	}
	if obs.CherryPickInProgress {
		details = append(details, "CHERRY_PICK_HEAD present (cherry-pick in progress)")
	}
	if obs.RevertInProgress {
		details = append(details, "REVERT_HEAD present (revert in progress)")
	}
	return details
}

// branchDivergence compares the recorded and live Git contexts. nil
// means parity: same branch (by name), or same commit when the trim was
// recorded detached. A repo that lost or gained its Git administration
// relative to the recording is a divergence too (never auto-decided).
func branchDivergence(recorded, live domain.GitObservation) *BranchMismatch {
	if !live.IsRepo {
		m := &BranchMismatch{
			RecordedBranch: recorded.HeadBranch, RecordedCommit: recorded.HeadCommit,
			RecordedDetached: recorded.Detached,
			LiveBranch:       "(no repository)", LiveCommit: "", LiveDetached: false,
		}
		return m
	}
	if recorded.Detached {
		if live.Detached && live.HeadCommit == recorded.HeadCommit {
			return nil
		}
		return &BranchMismatch{
			RecordedBranch: recorded.HeadBranch, RecordedCommit: recorded.HeadCommit,
			RecordedDetached: true,
			LiveBranch:       live.HeadBranch, LiveCommit: live.HeadCommit, LiveDetached: live.Detached,
		}
	}
	if !live.Detached && live.HeadBranch == recorded.HeadBranch {
		return nil
	}
	return &BranchMismatch{
		RecordedBranch: recorded.HeadBranch, RecordedCommit: recorded.HeadCommit,
		RecordedDetached: recorded.Detached,
		LiveBranch:       live.HeadBranch, LiveCommit: live.HeadCommit, LiveDetached: live.Detached,
	}
}

func (m BranchMismatch) RecordedLabel() string {
	if m.RecordedDetached {
		return "detached HEAD at " + shortCommit(m.RecordedCommit)
	}
	return "branch " + m.RecordedBranch
}

func (m BranchMismatch) LiveLabel() string {
	if m.LiveDetached {
		return "detached HEAD at " + shortCommit(m.LiveCommit)
	}
	if m.LiveBranch == "" && m.LiveCommit == "" {
		return "(no repository)"
	}
	return "branch " + m.LiveBranch
}

func shortCommit(c string) string {
	if len(c) > 10 {
		return c[:10] + "…"
	}
	return c
}

// ---- outputs-present gate ------------------------------------------------------

// outputsAllPresent reports whether every group's every output exists
// and is non-empty (a directory with at least one child, or a non-empty
// file).
func outputsAllPresent(root string, groups []removalGroupReader) bool {
	for _, g := range groups {
		for _, out := range g.Outputs {
			if !outputPresent(root, out) {
				return false
			}
		}
	}
	return true
}

func outputPresent(root, out string) bool {
	p := filepath.Join(root, filepath.FromSlash(out))
	fi, err := os.Stat(p)
	if err != nil {
		return false
	}
	if fi.IsDir() {
		des, derr := os.ReadDir(p)
		return derr == nil && len(des) > 0
	}
	return fi.Size() > 0
}

// hasResumableRestoreOp reports whether a prior restore operation sits
// in RESTORE_RUNNING (a crash leftover) or RESTORE_FAILED — the states
// that make rerunning `ebb restore` a resume rather than a redundant
// install (package managers tolerate existing partial directories).
func hasResumableRestoreOp(ops []catalog.Operation) bool {
	for _, op := range ops {
		if op.Kind != catalog.OpKindRestore {
			continue
		}
		switch op.Phase {
		case catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed:
			return true
		}
	}
	return false
}

// ---- drift ---------------------------------------------------------------------

// detectDrift compares every group's recorded recipe inputs against the
// live files. Inputs recorded missing at trim time that exist now are
// "new"; frozen inputs whose live digest differs are "differs"; frozen
// inputs whose live file is gone are "missing".
func detectDrift(root string, groups []removalGroupReader) []DriftEntry {
	var drift []DriftEntry
	for _, g := range groups {
		for _, in := range g.RecipeInputs {
			live, err := actions.DigestFile(filepath.Join(root, filepath.FromSlash(in.Path)))
			switch {
			case in.Missing && errors.Is(err, fs.ErrNotExist):
				continue // absent then, absent now
			case in.Missing:
				drift = append(drift, DriftEntry{Group: g.GroupID, Path: in.Path, State: "new", Live: live})
			case errors.Is(err, fs.ErrNotExist):
				drift = append(drift, DriftEntry{Group: g.GroupID, Path: in.Path, State: "missing", Recorded: in.Digest})
			case err != nil:
				// Unreadable live file: surface it as a drift difference,
				// never silently skip the input.
				drift = append(drift, DriftEntry{Group: g.GroupID, Path: in.Path, State: "differs",
					Recorded: in.Digest, Live: "unreadable: " + err.Error()})
			case live != in.Digest:
				drift = append(drift, DriftEntry{Group: g.GroupID, Path: in.Path, State: "differs",
					Recorded: in.Digest, Live: live})
			}
		}
	}
	return drift
}

// groupDrifted reports whether any drift entry belongs to the group.
func groupDrifted(drift []DriftEntry, groupID string) bool {
	for _, d := range drift {
		if d.Group == groupID {
			return true
		}
	}
	return false
}

// groupCommand selects the argv a strategy would run for one group:
// merge/current execute the non-lockfile recreate_live variant for
// DRIFTED groups (falling back to the frozen recipe — with an honest
// warning — when the group recorded none); no-drift and baseline run
// the frozen lockfile-pinned reclaim_command.
func groupCommand(g removalGroupReader, strategy Strategy, drifted bool, warnings *[]string) []string {
	switch strategy {
	case StrategyMerge, StrategyCurrent:
		if !drifted {
			return g.ReclaimCommand
		}
		if len(g.RecreateLive) > 0 {
			return g.RecreateLive
		}
		*warnings = append(*warnings, fmt.Sprintf(
			"group %s drifted but records no recreate_live recipe; running the frozen lockfile-pinned command %q — it may refuse under drift (baseline is the deterministic alternative)",
			g.GroupID, strings.Join(g.ReclaimCommand, " ")))
		return g.ReclaimCommand
	default:
		return g.ReclaimCommand
	}
}

// liveVariantInputs returns the recipe-input paths of every group whose
// command under the chosen strategy is the recreate_live variant — the
// same predicate groupCommand uses to select that argv (merge/current on
// a drifted group that records one). The native resolver behind those
// commands may legitimately rewrite ANY of the group's inputs (a unioned
// package.json forces lockfile regeneration even when the lockfile never
// drifted), so the post-flight protected-file gate exempts them all and
// the caller reports the actual rewrites as warnings. The frozen
// (baseline / no-drift) commands add no exemptions: lockfile-pinned
// installs must not touch their inputs, and the gate stays strict there.
func liveVariantInputs(groups []removalGroupReader, drift []DriftEntry, strategy Strategy) map[string]bool {
	out := map[string]bool{}
	if strategy != StrategyMerge && strategy != StrategyCurrent {
		return out
	}
	for _, g := range groups {
		if !groupDrifted(drift, g.GroupID) || len(g.RecreateLive) == 0 {
			continue
		}
		for _, in := range g.RecipeInputs {
			out[in.Path] = true
		}
	}
	return out
}

// previewGroups assembles the per-group report view (command selection
// plus the group's own drift slice and overlay list).
func previewGroups(groups []removalGroupReader, drift []DriftEntry, strategy Strategy) []RestoredGroup {
	var out []RestoredGroup
	for _, g := range groups {
		rg := RestoredGroup{GroupID: g.GroupID, Command: groupCommand(g, strategy, groupDrifted(drift, g.GroupID), &[]string{})}
		for _, d := range drift {
			if d.Group == g.GroupID {
				rg.Drift = append(rg.Drift, d)
			}
		}
		rg.Overlays = overlaysOf(g)
		out = append(out, rg)
	}
	return out
}

func overlaysOf(g removalGroupReader) []string {
	var out []string
	for _, p := range g.OverlayPatches {
		out = append(out, p.Path)
	}
	return out
}

// ---- strategy application --------------------------------------------------------

// applyStrategy backs up and rewrites drifted inputs per the chosen
// strategy and returns the exemption set (paths the driver itself
// wrote) for the post-flight protected-file gate.
//
//	merge    — union top-level declared manifests (live wins, every
//	           decision a warning); malformed or out-of-scope files
//	           keep the live bytes and the native tool resolves;
//	current  — back the live files up, change nothing;
//	baseline — back the live files up and write the FROZEN input bytes
//	           back (digest-verified from the payload).
//
// Every manifest-derived write path (the input itself AND its
// `.bak-drift-<stamp>` sibling — the backup name is derived from the
// input path by appending a suffix of dots, dashes, alphanumerics and a
// timestamp, so a base that passes the strict gate keeps the sibling
// portable too) must first pass validPortableLivePath, the SAME strict
// gate the overlay writer uses: the weaker read-time contract lets a
// colon at position >1 through (an NTFS alternate-data-stream write
// channel onto a protected file) and accepts `.` segments. An input that
// fails is refused honestly — the strategy is unavailable for it, the
// live file is kept and a warning explains the fallback.
//
// Ebb NEVER edits lockfiles: only package.json / Cargo.toml /
// pyproject.toml participate in unions, and resolution stays 100%
// native tool (D033 golden rule).
func (o *LiveRestorer) applyStrategy(ctx context.Context, vault VaultRef, docs trimDocs, payloadID, root string, drift []DriftEntry, strategy Strategy, warnings *[]string) (map[string]bool, error) {
	exempt := map[string]bool{}
	if strategy == "" || len(drift) == 0 {
		return exempt, nil
	}
	stamp := o.now().Format("20060102-150405")
	for _, d := range drift {
		if err := validPortableLivePath(d.Path); err != nil {
			*warnings = append(*warnings, fmt.Sprintf(
				"%s unavailable for %s (%v); keeping the live file — the native tool resolves", strategy, d.Path, err))
			continue
		}
		livePath := filepath.Join(root, filepath.FromSlash(d.Path))
		switch strategy {
		case StrategyCurrent:
			// Keep the live file; only the safety backup runs.
			if d.State == "differs" || d.State == "new" {
				if err := backupLiveFile(livePath, stamp); err != nil {
					return exempt, err
				}
				*warnings = append(*warnings, fmt.Sprintf("current: backed up %s to %s.bak-drift-%s", d.Path, d.Path, stamp))
			}
		case StrategyBaseline:
			g, in, ok := findInput(docs.plan.Groups, d.Group, d.Path)
			_ = g
			if !ok || in.Missing {
				*warnings = append(*warnings, fmt.Sprintf(
					"baseline: no frozen copy exists for %s (absent at trim time); keeping the live file", d.Path))
				continue
			}
			frozen, err := o.frozenInput(ctx, vault, payloadID, docs.opDir, in)
			if err != nil {
				return exempt, err
			}
			if d.State != "missing" {
				if err := backupLiveFile(livePath, stamp); err != nil {
					return exempt, err
				}
			}
			if err := writeFileProtected(livePath, frozen); err != nil {
				return exempt, err
			}
			exempt[d.Path] = true
			*warnings = append(*warnings, fmt.Sprintf("baseline: restored the frozen %s (live copy at %s.bak-drift-%s)", d.Path, d.Path, stamp))
		case StrategyMerge:
			g, in, ok := findInput(docs.plan.Groups, d.Group, d.Path)
			_ = g
			switch d.State {
			case "new":
				continue // recorded nothing; live file is the truth
			case "missing":
				if !ok {
					continue
				}
				frozen, err := o.frozenInput(ctx, vault, payloadID, docs.opDir, in)
				if err != nil {
					return exempt, err
				}
				if err := writeFileProtected(livePath, frozen); err != nil {
					return exempt, err
				}
				exempt[d.Path] = true
				*warnings = append(*warnings, fmt.Sprintf(
					"merge: live %s absent; recreated from the frozen baseline", d.Path))
				continue
			}
			frozen, err := o.frozenInput(ctx, vault, payloadID, docs.opDir, in)
			if err != nil {
				return exempt, err
			}
			live, rerr := os.ReadFile(livePath)
			if rerr != nil {
				return exempt, fmt.Errorf("restore: reading drifted input %s: %w", d.Path, rerr)
			}
			merged, notes, ok := unionManifest(d.Path, live, frozen)
			if !ok {
				*warnings = append(*warnings, fmt.Sprintf(
					"merge unavailable for %s (%s); keeping the live file — the native tool resolves", d.Path, strings.Join(notes, "; ")))
				continue
			}
			if err := backupLiveFile(livePath, stamp); err != nil {
				return exempt, err
			}
			if err := writeFileProtected(livePath, merged); err != nil {
				return exempt, err
			}
			exempt[d.Path] = true
			*warnings = append(*warnings, notes...)
			*warnings = append(*warnings, fmt.Sprintf("merge: wrote unioned %s (live copy at %s.bak-drift-%s)", d.Path, d.Path, stamp))
		}
	}
	return exempt, nil
}

// findInput locates one group's recipe-input record by path.
func findInput(groups []removalGroupReader, groupID, path string) (removalGroupReader, recipeInputReader, bool) {
	for _, g := range groups {
		if g.GroupID != groupID {
			continue
		}
		for _, in := range g.RecipeInputs {
			if in.Path == path {
				return g, in, true
			}
		}
	}
	return removalGroupReader{}, recipeInputReader{}, false
}

// frozenInput dumps one input's frozen copy from the payload and
// verifies its digest against the manifest record (I12: bytes read
// through the backend, compared against the sealed claim).
func (o *LiveRestorer) frozenInput(ctx context.Context, vault VaultRef, payloadID, opDir string, in recipeInputReader) ([]byte, error) {
	raw, err := o.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, payloadID, "/"+opDir+"/"+in.Copy)
	if err != nil {
		return nil, fmt.Errorf("restore: frozen input %s: %w", in.Path, err)
	}
	if got := digestBytes(raw); got != in.Digest {
		return nil, &ErrVerification{Check: "trim-documents", Details: []string{fmt.Sprintf(
			"frozen input %s: digest %s, manifest records %s — vault tampering suspected (D017)", in.Path, got, in.Digest)}}
	}
	return raw, nil
}

// backupLiveFile copies the live file to <path>.bak-drift-<stamp>. A
// missing live file is a no-op (the caller decides what that means).
func backupLiveFile(path, stamp string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("restore: backup read %s: %w", path, err)
	}
	return writeFileProtected(path+".bak-drift-"+stamp, b)
}

// writeFileProtected writes bytes under an existing parent with private
// permissions (0600), creating the parent when absent.
func writeFileProtected(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("restore: mkdir for %s: %w", path, err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("restore: write %s: %w", path, err)
	}
	return nil
}

// ---- manifest union (D033 "safe manifest union") ---------------------------------

// unionManifest merges one drifted input's live and frozen bytes at the
// top-level declaration layer. ok=false means the format is out of
// scope or the live file is malformed — the caller keeps the live file
// and lets the native tool resolve (never an error: a merge failure is
// a reported fallback, not a failed restore).
func unionManifest(path string, live, frozen []byte) (out []byte, notes []string, ok bool) {
	switch filepath.Base(filepath.FromSlash(path)) {
	case "package.json":
		return unionJSONManifest(live, frozen)
	case "Cargo.toml":
		return unionCargoTOML(live, frozen)
	case "pyproject.toml":
		return unionPyprojectTOML(live, frozen)
	default:
		return nil, []string{fmt.Sprintf("%s is not a unionable manifest format (package.json, Cargo.toml, pyproject.toml)", path)}, false
	}
}

// jsonDepSections are package.json's declared-dependency object maps.
var jsonDepSections = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// unionJSONManifest unions the declared-dependency sections of two
// package.json documents: recorded-only keys are added, direct key
// conflicts keep the LIVE version and are reported. All other
// top-level fields pass through from the live document byte-exactly
// (raw JSON values). Malformed input on either side refuses the union.
func unionJSONManifest(live, recorded []byte) ([]byte, []string, bool) {
	var liveTop, recTop map[string]json.RawMessage
	if err := json.Unmarshal(live, &liveTop); err != nil {
		return nil, []string{"live package.json is not a JSON object: " + err.Error()}, false
	}
	if err := json.Unmarshal(recorded, &recTop); err != nil {
		return nil, []string{"frozen package.json is not a JSON object: " + err.Error()}, false
	}
	if liveTop == nil || recTop == nil {
		return nil, []string{"package.json top level must be a JSON object"}, false
	}
	var notes []string
	for _, section := range jsonDepSections {
		recRaw, present := recTop[section]
		if !present {
			continue
		}
		var recSec map[string]json.RawMessage
		if err := json.Unmarshal(recRaw, &recSec); err != nil {
			return nil, []string{fmt.Sprintf("frozen package.json %s is not an object: %v", section, err)}, false
		}
		// F4 (Wave 1 restore review): JSON null leaves the target map nil
		// (Unmarshal of null is a no-op) — a later assignment into a nil
		// map panics. Normalize both sides to empty maps.
		if recSec == nil {
			recSec = map[string]json.RawMessage{}
		}
		liveSec := map[string]json.RawMessage{}
		if liveRaw, ok := liveTop[section]; ok {
			if err := json.Unmarshal(liveRaw, &liveSec); err != nil {
				return nil, []string{fmt.Sprintf("live package.json %s is not an object: %v", section, err)}, false
			}
			if liveSec == nil {
				liveSec = map[string]json.RawMessage{}
			}
		}
		added := 0
		for _, key := range sortedRawKeys(recSec) {
			if _, exists := liveSec[key]; exists {
				notes = append(notes, fmt.Sprintf(
					"package.json %s %q: keeping live %s (recorded %s)",
					section, key, trimJSONString(liveSec[key]), trimJSONString(recSec[key])))
				continue
			}
			liveSec[key] = recSec[key]
			added++
		}
		merged, merr := json.Marshal(liveSec)
		if merr != nil {
			return nil, []string{fmt.Sprintf("package.json %s merge: %v", section, merr)}, false
		}
		liveTop[section] = merged
		if added > 0 {
			notes = append(notes, fmt.Sprintf("package.json %s: union added %d recorded package(s)", section, added))
		}
	}
	out, err := json.MarshalIndent(liveTop, "", "  ")
	if err != nil {
		return nil, []string{"package.json union re-marshal: " + err.Error()}, false
	}
	return append(out, '\n'), notes, true
}

func sortedRawKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// trimJSONString renders a raw JSON value for a warning line (strings
// unquoted; anything else verbatim).
func trimJSONString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// ---- minimal TOML union -----------------------------------------------------------

// tomlFile is a line-oriented TOML document: a preamble plus named
// [header] sections, every line preserved verbatim. The union only ever
// appends whole recorded lines inside matched sections; anything it
// cannot parse refuses the union (the caller falls back to the live
// file). This is a merger for declared-dependency tables, NOT a TOML
// implementation: nested tables are addressed by their literal header
// text.
type tomlFile struct {
	sections []*tomlSection
}

type tomlSection struct {
	header string // "" for the preamble
	lines  []string
}

func parseTOMLFile(b []byte) (*tomlFile, error) {
	doc := &tomlFile{}
	cur := &tomlSection{header: ""}
	doc.sections = append(doc.sections, cur)
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	for _, line := range strings.Split(text, "\n") {
		if header, ok := tomlHeaderOf(line); ok {
			cur = &tomlSection{header: header}
			doc.sections = append(doc.sections, cur)
			continue
		}
		cur.lines = append(cur.lines, line)
	}
	return doc, nil
}

// tomlHeaderOf recognizes a table header line ([a.b] / [[a]]; comments
// after it are not part of the header).
func tomlHeaderOf(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") {
		return "", false
	}
	// Find the closing bracket of the (possibly array-of-table) header.
	end := strings.LastIndex(t, "]")
	if end < 1 {
		return "", false
	}
	inner := t[1:end]
	if strings.ContainsAny(inner, "[]=\"#") {
		return "", false // malformed or a value line like `key = [1]`
	}
	if rest := strings.TrimSpace(t[end+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
		return "", false
	}
	return inner, true
}

// render emits the document back to bytes.
func (t *tomlFile) render() []byte {
	var b strings.Builder
	for i, sec := range t.sections {
		if i > 0 {
			b.WriteString("[" + sec.header + "]\n")
		}
		for _, line := range sec.lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
}

// section returns the section with exactly this header, or nil.
func (t *tomlFile) section(header string) *tomlSection {
	for _, sec := range t.sections {
		if sec.header == header {
			return sec
		}
	}
	return nil
}

// ensureSection appends a new empty section with this header.
func (t *tomlFile) ensureSection(header string) *tomlSection {
	sec := &tomlSection{header: header}
	t.sections = append(t.sections, sec)
	return sec
}

// entry is one key's block inside a section: the key text and the raw
// lines carrying it (multi-line arrays keep their continuation lines).
type tomlEntry struct {
	key   string
	lines []string
}

// parseEntries splits a section's lines into key entries and other
// lines (comments/blanks), preserving order. Multi-line values are
// consumed by bracket balance.
func parseEntries(sec *tomlSection) (entries []tomlEntry, rest []string) {
	if sec == nil {
		return nil, nil
	}
	lines := sec.lines
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			rest = append(rest, line)
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			rest = append(rest, line)
			continue
		}
		key := strings.TrimSpace(line[:eq])
		block := []string{line}
		value := strings.TrimSpace(line[eq+1:])
		if strings.HasPrefix(value, "[") && !bracketsBalanced(value) {
			for i+1 < len(lines) && !bracketsBalanced(joinValues(block)) {
				i++
				block = append(block, lines[i])
			}
		}
		entries = append(entries, tomlEntry{key: key, lines: block})
	}
	return entries, rest
}

// joinValues concatenates a block's value text for balance checks: the
// value half of the key line plus every continuation line verbatim.
func joinValues(block []string) string {
	var b strings.Builder
	for i, l := range block {
		if i == 0 {
			if eq := strings.Index(l, "="); eq >= 0 {
				b.WriteString(strings.TrimSpace(l[eq+1:]))
			}
		} else {
			b.WriteString(l)
		}
		b.WriteByte(' ')
	}
	return b.String()
}

// bracketsBalanced reports whether s's square brackets nest to zero
// (string literals are respected crudely: a quoted ']' does not count
// after its quote — adequate for dependency arrays).
func bracketsBalanced(s string) bool {
	depth := 0
	inQuote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote != 0:
			if c == inQuote {
				inQuote = 0
			}
		case c == '"' || c == '\'':
			inQuote = c
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == '#' && depth == 0:
			return depth == 0
		}
	}
	return depth == 0
}

// unionTOMLTable unions one dependency TABLE (Cargo's [dependencies]
// family, pyproject's [tool.uv.sources]): recorded-only keys append
// their whole recorded lines; live wins on conflicts (reported). The
// recorded section must itself parse; a missing recorded section is a
// no-op.
func unionTOMLTable(live, recorded *tomlFile, header, label string, notes *[]string) {
	recSec := recorded.section(header)
	if recSec == nil {
		return
	}
	recEntries, _ := parseEntries(recSec)
	if len(recEntries) == 0 {
		return
	}
	liveSec := live.section(header)
	if liveSec == nil {
		liveSec = live.ensureSection(header)
	}
	liveEntries, _ := parseEntries(liveSec)
	liveKeys := map[string]bool{}
	for _, e := range liveEntries {
		liveKeys[e.key] = true
	}
	added := 0
	for _, e := range recEntries {
		if liveKeys[e.key] {
			*notes = append(*notes, fmt.Sprintf("%s %s: keeping live declaration (recorded also declares it)", label, e.key))
			continue
		}
		liveSec.lines = append(liveSec.lines, e.lines...)
		liveKeys[e.key] = true
		added++
	}
	if added > 0 {
		*notes = append(*notes, fmt.Sprintf("%s: union added %d recorded declaration(s)", label, added))
	}
}

// unionTOMLArrayKey unions one ARRAY-valued key inside a table
// (pyproject's [project] dependencies, [tool.uv] dev-dependencies):
// live items keep their order; recorded-only items append. Scalar
// (string) items only; anything else refuses the whole union.
func unionTOMLArrayKey(live, recorded *tomlFile, header, key, label string, notes *[]string) bool {
	recSec := recorded.section(header)
	if recSec == nil {
		return true
	}
	recEntries, _ := parseEntries(recSec)
	var recEntry *tomlEntry
	for i := range recEntries {
		if recEntries[i].key == key {
			recEntry = &recEntries[i]
			break
		}
	}
	if recEntry == nil {
		return true
	}
	recItems, ok := arrayItems(joinValues(recEntry.lines))
	if !ok {
		*notes = append(*notes, fmt.Sprintf("%s: recorded value is not a flat array of strings; merge unavailable", label))
		return false
	}
	liveSec := live.section(header)
	if liveSec == nil {
		liveSec = live.ensureSection(header)
	}
	liveEntries, liveRest := parseEntries(liveSec)
	for i := range liveEntries {
		if liveEntries[i].key != key {
			continue
		}
		liveItems, ok2 := arrayItems(joinValues(liveEntries[i].lines))
		if !ok2 {
			*notes = append(*notes, fmt.Sprintf("%s: live value is not a flat array of strings; merge unavailable", label))
			return false
		}
		seen := map[string]bool{}
		for _, it := range liveItems {
			seen[it] = true
		}
		added := 0
		for _, it := range recItems {
			if seen[it] {
				continue
			}
			liveItems = append(liveItems, it)
			seen[it] = true
			added++
		}
		if added > 0 {
			// F2 (Wave 1 restore review): re-rendering the section can only
			// emit key-block lines — every rest line the live parse produced
			// (a comment, a blank line, or the continuation body of a
			// multi-line basic string like `description = """`) would be
			// silently DELETED, and a vanished string body yields invalid
			// TOML. Refuse the rewrite (and with it the whole union: the
			// caller keeps the live file byte-for-byte and the native tool
			// resolves — the documented honest fallback) unless the section
			// is purely key-block lines.
			if len(liveRest) > 0 {
				*notes = append(*notes, fmt.Sprintf(
					"%s: the live [%s] section carries comment, blank or multi-line-string lines the line-oriented union cannot preserve; merge unavailable",
					label, header))
				return false
			}
			rendered := make([]string, 0, len(liveItems))
			for _, it := range liveItems {
				rendered = append(rendered, "\t"+quoteTOMLString(it)+",")
			}
			liveEntries[i].lines = append([]string{key + " = ["}, rendered...)
			liveEntries[i].lines = append(liveEntries[i].lines, "]")
			liveSec.lines = rebuildSectionLines(liveEntries)
			*notes = append(*notes, fmt.Sprintf("%s: union added %d recorded item(s)", label, added))
		}
		return true
	}
	// Live has no such key: append the recorded block verbatim.
	liveSec.lines = append(liveSec.lines, recEntry.lines...)
	*notes = append(*notes, fmt.Sprintf("%s: adopted the recorded declaration", label))
	return true
}

// rebuildSectionLines re-renders ONLY the parsed key-block lines — every
// rest line of the section (comments, blanks, continuation bodies of
// multi-line basic strings) is dropped by construction. It is therefore
// called exclusively on sections whose parse produced NO rest lines: the
// F2 gate in unionTOMLArrayKey declines the whole union for any section
// that is not purely key-block lines, keeping the live file byte-for-byte
// instead of deleting content it cannot represent.
func rebuildSectionLines(entries []tomlEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.lines...)
	}
	return out
}

// arrayItems parses a flat TOML array of basic strings
// ("[\"a\", \"b\"]"), reporting the unquoted items.
func arrayItems(value string) ([]string, bool) {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(v, "[") {
		return nil, false
	}
	// Strip any trailing comment after the closing bracket.
	if idx := indexUnquoted(v, '#'); idx >= 0 {
		v = v[:idx]
	}
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	if strings.TrimSpace(v) == "" {
		return nil, true // empty array: no items, still an array
	}
	var items []string
	for _, part := range splitTopLevel(v) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.HasPrefix(part, "\"") || !strings.HasSuffix(part, "\"") {
			return nil, false
		}
		unquoted, err := unquoteTOMLBasic(part)
		if err != nil {
			return nil, false
		}
		items = append(items, unquoted)
	}
	return items, true
}

// splitTopLevel splits on commas outside quotes and brackets.
func splitTopLevel(s string) []string {
	var parts []string
	depth := 0
	inQuote := false
	last := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == '\\' {
				i++
			} else if c == '"' {
				inQuote = false
			}
			continue
		}
		switch c {
		case '"':
			inQuote = true
		case '[':
			depth++
		case ']':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[last:i])
				last = i + 1
			}
		}
	}
	parts = append(parts, s[last:])
	return parts
}

// indexUnquoted finds c outside quotes (-1 when absent).
func indexUnquoted(s string, c byte) int {
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote {
			if ch == '\\' {
				i++
			} else if ch == '"' {
				inQuote = false
			}
			continue
		}
		if ch == '"' {
			inQuote = true
			continue
		}
		if ch == c {
			return i
		}
	}
	return -1
}

func quoteTOMLString(s string) string {
	return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(s) + "\""
}

func unquoteTOMLBasic(s string) (string, error) {
	var out strings.Builder
	body := s[1 : len(s)-1]
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		i++
		if i >= len(body) {
			return "", fmt.Errorf("dangling escape")
		}
		switch body[i] {
		case 'n':
			out.WriteByte('\n')
		case 't':
			out.WriteByte('\t')
		case 'r':
			out.WriteByte('\r')
		case '"':
			out.WriteByte('"')
		case '\\':
			out.WriteByte('\\')
		default:
			return "", fmt.Errorf("unsupported escape \\%c", body[i])
		}
	}
	return out.String(), nil
}

// unionCargoTOML unions Cargo.toml's [dependencies], [dev-dependencies]
// and [build-dependencies] tables (live wins on direct conflicts).
func unionCargoTOML(live, frozen []byte) ([]byte, []string, bool) {
	liveDoc, _ := parseTOMLFile(live)
	recDoc, err := parseTOMLFile(frozen)
	if err != nil {
		return nil, []string{"frozen Cargo.toml unparseable: " + err.Error()}, false
	}
	var notes []string
	for _, table := range []string{"dependencies", "dev-dependencies", "build-dependencies"} {
		unionTOMLTable(liveDoc, recDoc, table, "Cargo.toml "+table, &notes)
	}
	return liveDoc.render(), notes, true
}

// unionPyprojectTOML unions pyproject.toml's [project].dependencies
// array, [tool.uv].dev-dependencies array and [tool.uv.sources] table
// where representable.
func unionPyprojectTOML(live, frozen []byte) ([]byte, []string, bool) {
	liveDoc, _ := parseTOMLFile(live)
	recDoc, err := parseTOMLFile(frozen)
	if err != nil {
		return nil, []string{"frozen pyproject.toml unparseable: " + err.Error()}, false
	}
	var notes []string
	if !unionTOMLArrayKey(liveDoc, recDoc, "project", "dependencies", "pyproject [project].dependencies", &notes) {
		return nil, notes, false
	}
	if !unionTOMLArrayKey(liveDoc, recDoc, "tool.uv", "dev-dependencies", "pyproject [tool.uv].dev-dependencies", &notes) {
		return nil, notes, false
	}
	unionTOMLTable(liveDoc, recDoc, "tool.uv.sources", "pyproject [tool.uv.sources]", &notes)
	return liveDoc.render(), notes, true
}

// ---- execution --------------------------------------------------------------------

// sealedManifestApprover is the D033 no-re-approval contract: the recipe
// was displayed and approved at trim time and is sealed in the removal
// manifest, so the runner's mandatory approval check is satisfied by an
// approval synthesized from the definition it was handed (an exact match
// by construction — it pins exactly what is about to run, including the
// resolved tool identity and live input digests).
type sealedManifestApprover struct{ now func() time.Time }

func (a sealedManifestApprover) Matches(def actions.Definition, tool actions.ToolIdentity, inputDigests map[string]string) (*actions.Approval, error) {
	return &actions.Approval{
		ID:           domain.ID(domain.NewID()),
		ActionID:     def.ID,
		ArgvDigest:   actions.ArgvDigest(def.Argv),
		Tool:         tool,
		WorkingRoot:  def.WorkingRoot,
		Outputs:      actions.CanonicalOutputs(def.Outputs),
		InputDigests: inputDigests,
		EnvAllow:     actions.CanonicalEnvAllow(def.EnvAllow),
		Network:      def.Network,
		ApprovedBy:   "trim-manifest-seal",
		ApprovedAt:   domain.FormatTime(a.now()),
	}, nil
}

// groupDefinition builds one group's actions.Definition. The argv is
// the manifest-frozen argv EXACTLY (never reconstructed from policy);
// inputs are the group's recipe inputs, minus inputs recorded missing
// at trim time that are still absent (reported, never guessed), and
// minus inputs whose paths fail the STRICT portable gate (F5: a
// manifest-derived path Ebb cannot safely touch is fenced out of the
// runner's contract entirely — reported, never guessed).
func groupDefinition(root string, trimOpID domain.OperationID, g removalGroupReader, drift []DriftEntry, strategy Strategy, warnings *[]string) (actions.Definition, error) {
	var inputs []string
	for _, in := range g.RecipeInputs {
		if perr := validPortableLivePath(in.Path); perr != nil {
			*warnings = append(*warnings, fmt.Sprintf(
				"group %s input %s is not a portable live path (%v); excluded from the action's input contract",
				g.GroupID, in.Path, perr))
			continue
		}
		if !in.Missing {
			inputs = append(inputs, in.Path)
			continue
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(in.Path))); err == nil {
			inputs = append(inputs, in.Path)
			*warnings = append(*warnings, fmt.Sprintf(
				"group %s input %s was absent at trim time and exists now; included in the action's input contract", g.GroupID, in.Path))
			continue
		}
		*warnings = append(*warnings, fmt.Sprintf(
			"group %s input %s was absent at trim time and is still absent; excluded from the action's input contract", g.GroupID, in.Path))
	}
	def := actions.Definition{
		ID:          fmt.Sprintf("restore-%s-%s", trimOpID, g.GroupID),
		Argv:        append([]string(nil), groupCommand(g, strategy, groupDrifted(drift, g.GroupID), warnings)...),
		WorkingRoot: ".",
		Inputs:      inputs,
		Outputs:     append([]string(nil), g.Outputs...),
		Network:     actions.NetworkAllowed,
		EnvAllow:    envAllowForAdapter(g.Adapter),
		Timeout:     liveRestoreTimeout,
	}
	if err := def.Validate(); err != nil {
		return actions.Definition{}, err
	}
	return def, nil
}

// envAllowForAdapter derives the env allowlist from the frozen adapter
// name (D033): pnpm needs PNPM_HOME and uv needs UV_PYTHON; npm, pip
// and custom recipes inherit nothing extra.
func envAllowForAdapter(adapter string) []string {
	switch adapter {
	case "pnpm":
		return []string{"PNPM_HOME"}
	case "uv":
		return []string{"UV_PYTHON"}
	default:
		return nil
	}
}

// runRecipe executes one group's definition with per-attempt journaling
// (action_runs) and the sealed-approval contract. A non-zero exit,
// runner refusal or cancellation lands the operation at RESTORE_FAILED.
func (o *LiveRestorer) runRecipe(ctx context.Context, opID domain.OperationID, def actions.Definition, root string, appr actions.Approver) (ActionReport, error) {
	runID, err := o.cat.StartActionRun(opID, def.ID)
	if err != nil {
		return ActionReport{}, fmt.Errorf("restore: journaling the action run: %w", err)
	}
	res, rerr := o.runner.Run(ctx, def, root, appr, nil)
	switch {
	case rerr != nil && errors.Is(rerr, context.Canceled):
		_ = o.cat.FinishActionRun(runID, catalog.ActionRunCancelled, res.ExitCode, res.OutputExcerpt)
		return ActionReport{ID: def.ID, Status: ActionCancelled, ExitCode: res.ExitCode}, rerr
	case rerr != nil:
		_ = o.cat.FinishActionRun(runID, catalog.ActionRunFailed, res.ExitCode, res.OutputExcerpt)
		return ActionReport{ID: def.ID, Status: ActionFailed, ExitCode: res.ExitCode}, rerr
	case res.ExitCode != 0:
		_ = o.cat.FinishActionRun(runID, catalog.ActionRunFailed, res.ExitCode, res.OutputExcerpt)
		return ActionReport{ID: def.ID, Status: ActionFailed, ExitCode: res.ExitCode},
			fmt.Errorf("restore: recipe %s exited %d", strings.Join(def.Argv, " "), res.ExitCode)
	}
	if err := o.cat.FinishActionRun(runID, catalog.ActionRunSucceeded, res.ExitCode, res.OutputExcerpt); err != nil {
		return ActionReport{ID: def.ID, Status: ActionSucceeded}, fmt.Errorf("restore: journaling the action result: %w", err)
	}
	return ActionReport{ID: def.ID, Status: ActionSucceeded, ExitCode: 0}, nil
}

// ---- overlay reapplication (D034) --------------------------------------------------

// applyOverlays re-applies one trim's carved-out overlay patches after
// the recipes recreated the outputs: bytes come from the payload's
// op-dir copies, live paths re-pass the strict portable gate AND the
// under-an-output confinement, written digests are verified against the
// sealed record, and links are recreated through the CreateLink seam
// with the junction fallback (the unprivileged Windows shape).
func (o *LiveRestorer) applyOverlays(ctx context.Context, vault VaultRef, docs trimDocs, payloadID, root string) ([]string, error) {
	var applied []string
	for _, g := range docs.plan.Groups {
		for _, p := range g.OverlayPatches {
			if err := validPortableLivePath(p.Path); err != nil {
				return applied, fmt.Errorf("restore: overlay patch %s: %v", p.Path, err)
			}
			if !underAnyRelPrefix(g.Outputs, p.Path) {
				return applied, fmt.Errorf(
					"restore: overlay patch %s does not lie under group %s's outputs %v — a carve-out outside the group is not an overlay (D034)", p.Path, g.GroupID, g.Outputs)
			}
			raw, err := o.store.DumpFile(ctx, vault.RepoDir, vault.Passfile, payloadID, "/"+docs.opDir+"/"+p.Copy)
			if err != nil {
				return applied, fmt.Errorf("restore: overlay copy %s: %w", p.Copy, err)
			}
			target := filepath.Join(root, filepath.FromSlash(p.Path))
			if p.Kind == overlayKindLink {
				// Post-amendment witnesses bind the sidecar's target-text
				// bytes cryptographically (F7): a payload-only rewrite of
				// the link target is refused here, exactly like a tampered
				// file overlay. Pre-amendment records ("" digest) are
				// unwitnessed and proceed.
				if p.Digest != "" {
					if got := digestBytes(raw); got != p.Digest {
						return applied, fmt.Errorf(
							"restore: overlay link %s: sidecar digest %s, manifest records %s — vault tampering suspected (D017)", p.Path, got, p.Digest)
					}
				}
				if err := o.recreateOverlayLink(target, string(raw)); err != nil {
					return applied, fmt.Errorf("restore: overlay link %s: %w", p.Path, err)
				}
				applied = append(applied, p.Path)
				continue
			}
			if got := digestBytes(raw); got != p.Digest {
				return applied, fmt.Errorf(
					"restore: overlay %s: payload copy digest %s, manifest records %s — vault tampering suspected (D017)", p.Path, got, p.Digest)
			}
			if err := writeFileProtected(target, raw); err != nil {
				return applied, err
			}
			// F9: restore the captured permission bits (exec shims stay
			// executable on POSIX); 0/absent keeps the safe 0600 default.
			if p.Mode != 0 {
				if cerr := os.Chmod(target, fs.FileMode(p.Mode)&fs.ModePerm); cerr != nil {
					return applied, fmt.Errorf("restore: overlay %s: applying recorded mode %#o: %w", p.Path, p.Mode, cerr)
				}
			}
			got, derr := actions.DigestFile(target)
			if derr != nil || got != p.Digest {
				return applied, fmt.Errorf("restore: overlay %s: written digest verification failed (want %s)", p.Path, p.Digest)
			}
			applied = append(applied, p.Path)
		}
	}
	return applied, nil
}

// recreateOverlayLink recreates one carved-out link at path with the
// frozen target text, verifying the recreated text byte-for-byte. A
// true-symlink privilege refusal falls back to a junction ONLY when the
// junction semantics are equivalent (an absolute target of an existing
// directory); a relative or file target surfaces the typed privilege
// failure instead of silently recreating different semantics.
func (o *LiveRestorer) recreateOverlayLink(path, target string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing the downloaded node: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	err := o.createLink(domain.KindSymlink, path, target)
	if err != nil {
		var pb privilegeBlockedLink
		if errors.As(err, &pb) && pb.LinkPrivilegeBlocked() &&
			filepath.IsAbs(target) && dirExists(target) {
			if jerr := o.createLink(domain.KindJunction, path, target); jerr == nil {
				err = nil
			} else {
				err = jerr
			}
		}
		if err != nil {
			return err
		}
	}
	got, rerr := os.Readlink(path)
	if rerr != nil || got != target {
		return fmt.Errorf("recreated link text %q, frozen target %q (readlink: %v)", got, target, rerr)
	}
	return nil
}

// dirExists reports whether path is an existing directory.
func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// ---- protected-file integrity gate ---------------------------------------------------

// protFact is one protected node's observed fact.
type protFact struct {
	kind   string // "file" | "link" | "dir" | "other"
	digest string
	link   string
}

// walkProtected hashes every FILE and records every LINK under root,
// except anything under the declared output roots (the recipes own
// those trees). Links are never followed; reparse points surface via
// Lstat's mode bits.
func walkProtected(root string, outputs []string) (map[string]protFact, error) {
	out := map[string]protFact{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		relSlash := filepath.ToSlash(rel)
		if underAnyRelPrefix(outputs, relSlash) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		fi, ferr := d.Info()
		if ferr != nil {
			return ferr
		}
		switch {
		case fi.Mode().IsRegular():
			dg, derr := actions.DigestFile(p)
			if derr != nil {
				return derr
			}
			out[relSlash] = protFact{kind: "file", digest: dg}
		case d.IsDir():
			if p != root {
				out[relSlash] = protFact{kind: "dir"}
			}
		case fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0:
			txt, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			out[relSlash] = protFact{kind: "link", link: txt}
		default:
			out[relSlash] = protFact{kind: "other"}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("restore: protected walk of %s: %w", root, err)
	}
	return out, nil
}

// underAnyRelPrefix reports whether a root-relative slash path equals
// or lies below one of the prefixes (mirror of lifecycle's helper).
func underAnyRelPrefix(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// compareProtected compares the before/after protected walks over the
// BEFORE set (new files — backups, merged side outputs — are not part
// of the comparison; the set is the pre-restore truth), exempting the
// paths the chosen strategy intentionally wrote.
func compareProtected(before, after map[string]protFact, exempt map[string]bool) []string {
	var changes []string
	for _, p := range sortedKeys(before) {
		if exempt[p] {
			continue
		}
		b, a := before[p], after[p]
		switch {
		case a.kind == "" && a.digest == "" && a.link == "":
			changes = append(changes, fmt.Sprintf("%s: %s removed or replaced after the restore started", p, b.kind))
		case a.kind != b.kind:
			changes = append(changes, fmt.Sprintf("%s: kind changed from %s to %s", p, b.kind, a.kind))
		case b.kind == "file" && a.digest != b.digest:
			changes = append(changes, fmt.Sprintf("%s: content digest %s, before the restore %s", p, a.digest, b.digest))
		case b.kind == "link" && a.link != b.link:
			changes = append(changes, fmt.Sprintf("%s: link text %q, before the restore %q", p, a.link, b.link))
		}
	}
	return changes
}

func sortedKeys(m map[string]protFact) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedBoolKeys sorts a set's members for deterministic reporting.
func sortedBoolKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// liveRestoreIntentDigest freezes what one restore intends: the trim it
// replays, the resolved strategy and the root (Foundation §12.1).
func liveRestoreIntentDigest(trimOpID string, strategy Strategy, root string) string {
	h := sha256.New()
	h.Write([]byte("ebb:restore:v1\x00"))
	h.Write([]byte(trimOpID))
	h.Write([]byte{0})
	h.Write([]byte(strategy))
	h.Write([]byte{0})
	h.Write([]byte(root))
	return hex.EncodeToString(h.Sum(nil))
}
