// cmd_delete.go implements `ebb delete <workspace-name | snapshot-id>`
// (ADR D035): ONE destructive action that unpins AND physically prunes
// vault storage, replacing the two-step `ebb forget` + `ebb gc` dance
// while retaining every protection those commands carry.
//
// Target resolution (forget's exact semantics, extended to names): a
// 32-hex id addresses ONE snapshot; anything else is a workspace NAME
// addressing ALL its snapshots.
//
// Stage 1 — the forget stage — is forget's durable, idempotent ordering
// VERBATIM (D015), reused through the same runForget: retention intent
// (reusing a pending one) → unpin (reason carries the intent id) →
// backend forget of only the ids still present, VERIFIED by List after
// → intent completed. Guards, likewise forget's: seal-kind rows and
// unsealed payloads are refused (§11.3 review, not deletion); the LAST
// snapshot of a PARKED/UNBOUND workspace (no local root — the vault
// copy may be the only Ebb-known recovery copy) requires the explicit
// --last-of-parked acknowledgement (the flag keeps forget's Wave F
// name); and deletion is DESTRUCTIVE and reaches physical storage, so
// it always carries an explicit confirmation — interactive (typing the
// exact target after seeing the count and bytes) or headless via
// --yes. Never silent; --dry-run needs no confirmation.
//
// On top of forget's guards, one more: an ACTIVE operation on the
// workspace being deleted blocks the whole command (an in-flight
// capture/open/trim on the target must not race its snapshots being
// removed) — the target-scoped sibling of gc's global gate (F38).
//
// Stage 2 — the prune stage — runs gc's D022-gated prune immediately
// for the vault, but as a SKIP-WITH-WARNING, never a refusal: after
// this deletion consumed its own intents, OTHER workspaces' pending
// retention intents or active operations (or an unsupported backend)
// make the prune ineligible — the deletion is still logically
// complete, and the warning names `ebb gc` as the honest completion
// path.
//
// Vault selection mirrors forget exactly (the registry's default
// vault; forget has no --vault override, so delete adds none either).
//
// Exit contract: 0 deleted (or clean nothing-to-delete no-op); 2
// unknown target / malformed argument; 3 refused (seal kind, unsealed
// payload, last-recovery-copy without ack, active operation on the
// target, declined or mismatched confirmation); 4 prune-side integrity
// verification failure; 5 partial durable state needing a rerun (every
// step is idempotent); 7 vault unavailable; 130 cancelled.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/restore"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// Stable CLI blocker codes for the delete surface (§5.5). The
// forget-stage guards reuse forget's own codes verbatim.
const (
	CodeDeleteUnknownTarget   = "EBB_E_DELETE_UNKNOWN_TARGET"
	CodeDeleteUnconfirmed     = "EBB_E_DELETE_UNCONFIRM"
	CodeDeleteActiveOperation = "EBB_E_DELETE_ACTIVE_OPERATION"
	CodeDeleteForeignVault    = "EBB_E_DELETE_FOREIGN_VAULT"
)

// deleteSnapshotDetails is one snapshot's outcome inside the --json
// payload. StateReached mirrors forget's states ("completed" on
// success; the partial states match forget's flow); "planned" marks a
// --dry-run row (nothing was done).
type deleteSnapshotDetails struct {
	SnapshotID        string `json:"snapshot_id"`
	Kind              string `json:"kind"`
	CreatedAt         string `json:"created_at"`
	IntentID          string `json:"intent_id,omitempty"`
	PairAlreadyAbsent bool   `json:"pair_already_absent,omitempty"`
	StateReached      string `json:"state_reached"`
	// RetainedSharedIDs: backend ids of THIS snapshot that were KEPT in
	// the vault because other retained snapshot rows still share them
	// (reference-aware deletion; forget's P0-1 honesty, per target).
	RetainedSharedIDs []string `json:"retained_shared_ids,omitempty"`
}

// deletePruneDetails is the prune stage's outcome: ran, or skipped
// with the reason; the counters mirror gc's accounting.
type deletePruneDetails struct {
	Ran                 bool   `json:"ran"`
	SkippedReason       string `json:"skipped_reason,omitempty"`
	ReclaimableEstimate int64  `json:"reclaimable_estimate_bytes,omitempty"`
	RepoBytesBefore     int64  `json:"repo_bytes_before,omitempty"`
	RepoBytesAfter      int64  `json:"repo_bytes_after,omitempty"`
	RepoBytesKnown      bool   `json:"repo_bytes_known,omitempty"`
	FreedObserved       int64  `json:"freed_observed,omitempty"`
}

// deleteDetails is the --json payload of a delete (success or partial).
type deleteDetails struct {
	Target      string `json:"target"`
	Workspace   string `json:"workspace"`
	WorkspaceID string `json:"workspace_id"`
	DryRun      bool   `json:"dry_run"`

	// NoOp + NoOpReason: a clean nothing-to-delete result (exit 0).
	NoOp       bool   `json:"no_op,omitempty"`
	NoOpReason string `json:"no_op_reason,omitempty"`

	// ImpactKnown reports whether the retained-evidence readback
	// succeeded; PreservedBytes is the TOTAL released retained material
	// and is meaningful only then.
	ImpactKnown    bool  `json:"impact_known"`
	PreservedBytes int64 `json:"preserved_bytes,omitempty"`

	Snapshots []deleteSnapshotDetails `json:"snapshots"`
	Prune     deletePruneDetails      `json:"prune"`

	// RetainedSharedIDs aggregates, across the run's snapshots, every
	// backend id KEPT in the vault because other retained snapshot rows
	// still share it (reference-aware deletion). Non-empty means the
	// deletion released the targets' obligations WITHOUT physically
	// removing every id — the receipts say so.
	RetainedSharedIDs []string `json:"retained_shared_ids,omitempty"`

	// StateReached names the last durable forget step completed across
	// the run ("" until a mutation lands; "completed" on success).
	StateReached string `json:"state_reached,omitempty"`
}

func cmdDelete(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	yes := fs.Bool("yes", false, "accept the typed-target confirmation (the deletion summary is shown first)")
	dryRun := fs.Bool("dry-run", false,
		"show what would be deleted and the backend's reclaim estimate without mutating anything (no confirmation needed)")
	lastOfParked := fs.Bool("last-of-parked", false,
		"acknowledge deleting snapshots of a workspace with no local root (parked or UNBOUND — it becomes unrecoverable by Ebb)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb delete: takes exactly one target (workspace name or 32-hex snapshot id; see `ebb status`)")
		return ExitUsage
	}
	target := fs.Arg(0)

	env := newEnvelope("delete", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	ws, snaps, rerr := resolveDeleteTarget(sess, target)
	if rerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(rerr), rerr.Error())
	}

	details := deleteDetails{
		Target: target, Workspace: ws.Name, WorkspaceID: string(ws.ID), DryRun: *dryRun,
		Snapshots: []deleteSnapshotDetails{},
	}
	if len(snaps) == 0 {
		// Clean nothing-to-delete (idempotent rerun after success, or a
		// workspace whose snapshots were all forgotten already).
		details.NoOp = true
		details.NoOpReason = "the target has no snapshots to delete"
		env.Outcome = "ok"
		env.WorkspaceID = string(ws.ID)
		env.Conditions = []string{"noop"}
		env.Details = details
		emit(env, *jsonOut, streams, renderDeleteHuman(details, ws, ""))
		return ExitOK
	}

	// ---- refusals before any prompt (exit 3) ----------------------------
	for _, snap := range snaps {
		switch {
		case snap.Kind == catalog.SnapshotKindSeal:
			return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
				CodeForgetNotForgettable, "delete "+target,
				fmt.Sprintf("snapshot %s is a seal-only record carrying no payload to forget; it is catalog metadata, not a recovery obligation", snap.ID),
				"Safe action: nothing to release; if the row is stale, inspect it with `ebb status`"))
		case snap.PayloadBackendID == "" || snap.SealBackendID == "":
			return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
				CodeForgetUnsealed, "delete "+target,
				fmt.Sprintf("snapshot %s is UNSEALED (payload/seal backend id missing); an unverified or incomplete capture needs §11.3 review, not deletion", snap.ID),
				"Safe action: inspect with `ebb status` / `ebb recover <operation-id>`; an unsealed payload may still contain useful captured work"))
		}
	}
	// The last-recovery-copy guard (forget's D015 rule): a workspace
	// with NO LOCAL ROOT — PARKED or UNBOUND — whose snapshots this
	// deletion would ALL remove, is unrecoverable-by-Ebb afterwards and
	// needs the explicit --last-of-parked acknowledgement.
	if (ws.Status == catalog.WorkspaceParked || ws.Status == catalog.WorkspaceUnbound) && !*lastOfParked {
		return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
			CodeForgetLastOfParked, "delete "+target,
			fmt.Sprintf("this would remove ALL %d snapshot(s) of %s workspace %q (no local root exists); afterwards the workspace is unrecoverable by Ebb",
				len(snaps), ws.Status, ws.Name),
			"Safe action: reopen it first (`ebb open "+ws.Name+" --to <dir>`), or rerun with --last-of-parked to acknowledge losing the last recovery copy"))
	}
	// The target-scoped active-operation guard (F38 sibling of gc's
	// global gate): an in-flight operation on the workspace being
	// deleted must reconcile first.
	active, aerr := sess.cat.ActiveOperations(ws.ID)
	if aerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(aerr),
			fmt.Sprintf("delete %s: listing active operations: %v", target, aerr))
	}
	if len(active) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%s [delete %s]: %d operation(s) are still active on workspace %q and must not race its deletion:",
			CodeDeleteActiveOperation, target, len(active), ws.Name)
		for _, op := range active {
			fmt.Fprintf(&b, "\n  %s kind %s phase %s — reconcile with `ebb recover %s`",
				op.ID, op.Kind, op.Phase, op.ID)
		}
		fmt.Fprintf(&b, ". Safe action: reconcile each active operation (or let it finish), then rerun `ebb delete %s`", target)
		return emitFailure(env, *jsonOut, streams, ExitBlocked, b.String())
	}

	details.Snapshots = make([]deleteSnapshotDetails, len(snaps))
	for i, snap := range snaps {
		details.Snapshots[i] = deleteSnapshotDetails{
			SnapshotID: string(snap.ID), Kind: snap.Kind, CreatedAt: snap.CreatedAt,
			StateReached: "planned",
		}
	}
	v, verr := sess.defaultVault()
	if verr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(verr), verr.Error())
	}

	// P0 (wrong-vault false success): every target below would run
	// against THIS default vault. A snapshot bound (import --vault) to a
	// non-default vault would be "already absent" here — unpinned, its
	// retention intent completed, exit 0 — while its bytes sit untouched
	// in their own vault. Refuse any target set that is not ENTIRELY
	// default-vault-bound (all-default proceeds; mixed refuses whole)
	// and name the vault-safe per-snapshot path instead. (The minimal
	// wave-5 fix; a vault-aware delete state machine is a later wave.)
	foreign, ferr := foreignVaultTargets(sess, v, snaps)
	if ferr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(ferr),
			fmt.Sprintf("delete %s: resolving the targets' bound vaults: %v", target, ferr))
	}
	if len(foreign) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%s [delete %s]: %d of %d target snapshot(s) live in a NON-DEFAULT vault, so a delete against the default vault %q would find nothing to forget and still report success while their bytes stay in their own vault:",
			CodeDeleteForeignVault, target, len(foreign), len(snaps), v.Name)
		for _, f := range foreign {
			fmt.Fprintf(&b, "\n  snapshot %s", f)
		}
		fmt.Fprintf(&b, ". Safe action: forget each snapshot against its own bound vault — `ebb forget <snapshot-id>` (forget resolves the SNAPSHOT'S bound vault and verifies the repository identity); a vault-aware delete may arrive in a later wave")
		return emitFailure(env, *jsonOut, streams, ExitBlocked, b.String())
	}

	var pruneErr error
	forgotAny := false // this run actually removed at least one backend pair
	cErr := sess.withVaultPassfileOf(ctx, v, func(repoDir, passfile string) error {
		vaultRef := restore.VaultRef{RepoDir: repoDir, Passfile: passfile}
		// Informational readback per snapshot (forget's contract: a
		// failed readback NEVER blocks, but it is said).
		var total int64
		for _, snap := range snaps {
			ev, eerr := restore.LoadRetainedEvidence(ctx, sess.store, vaultRef, snap.ID, snap)
			if eerr != nil {
				env.Warnings = append(env.Warnings, fmt.Sprintf(
					"retained evidence for %s could not be read back (%s); proceeding on catalog facts only",
					snap.ID, codedMessage(eerr)))
				continue
			}
			details.ImpactKnown = true
			total += ev.PreservedBytes
		}
		details.PreservedBytes = total

		if !*dryRun {
			// ---- confirmation: typed exact target, or --yes ------------
			if !*yes {
				if deps.StdinIsTerminal == nil || !deps.StdinIsTerminal() {
					return blockedError(fmt.Errorf("%s [delete %s]: stdin is not a terminal and --yes was not given, so the deletion cannot be confirmed. Safe action: rerun with --yes after checking `ebb status`, or preview first with --dry-run",
						CodeDeleteUnconfirmed, target))
				}
				fmt.Fprint(streams.Err, deletePrompt(details, ws, *lastOfParked))
				line, rerr := deps.ReadLine()
				if rerr != nil {
					return blockedError(fmt.Errorf("%s [delete %s]: reading the confirmation failed: %v. Safe action: rerun the command",
						CodeDeleteUnconfirmed, target, rerr))
				}
				if strings.TrimSpace(line) != target {
					return blockedError(fmt.Errorf("%s [delete %s]: the typed confirmation %q does not match the target; nothing was deleted. Safe action: retype the exact target, or rerun with --yes after checking `ebb status`",
						CodeDeleteUnconfirmed, target, line))
				}
			}

			// ---- forget stage: forget's durable flow, verbatim ---------
			for i, snap := range snaps {
				fd := forgetDetails{Workspace: ws.Name, WorkspaceID: string(ws.ID), SnapshotID: string(snap.ID)}
				if ferr := runForget(ctx, sess, repoDir, passfile, snap, &fd); ferr != nil {
					if fd.StateReached == "" {
						// Failed before any durable step landed (e.g. the
						// intent insert itself): an ordinary error, not a
						// partial state.
						details.Snapshots[i].StateReached = "failed"
					} else {
						details.Snapshots[i].StateReached = fd.StateReached
						details.Snapshots[i].IntentID = fd.IntentID
						details.StateReached = "forget:" + fd.StateReached
					}
					return fmt.Errorf("forgetting snapshot %s: %w", snap.ID, ferr)
				}
				details.Snapshots[i].IntentID = fd.IntentID
				details.Snapshots[i].PairAlreadyAbsent = fd.PairAlreadyAbsent
				details.Snapshots[i].StateReached = fd.StateReached
				details.Snapshots[i].RetainedSharedIDs = fd.RetainedSharedIDs
				details.RetainedSharedIDs = append(details.RetainedSharedIDs, fd.RetainedSharedIDs...)
				if !fd.PairAlreadyAbsent {
					forgotAny = true
				}
			}
			details.StateReached = "completed"
		}

		// ---- prune stage (gc's gated prune; skip-with-warning) --------
		pruneErr = runDeletePrune(ctx, sess, v, repoDir, passfile, &env, &details, *dryRun, forgotAny)
		return nil
	})
	if cErr != nil {
		code := classifyExitCode(cErr)
		if details.StateReached != "" {
			// Durable state changed: whatever the underlying class, this
			// is a partial delete needing an idempotent rerun — unless
			// the vault itself is unavailable (7 keeps its meaning).
			if code != ExitVault {
				code = ExitInterrupted
			}
			env.Details = details
			return emitFailure(env, *jsonOut, streams, code, fmt.Sprintf(
				"delete %s reached durable state %q (%s); rerun `ebb delete %s` — every step is idempotent. Safe action: resolve the cause (%s)",
				target, details.StateReached, describeDeleteState(details.StateReached), target, codedWithSafeAction(cErr)))
		}
		return emitFailure(env, *jsonOut, streams, code,
			fmt.Sprintf("delete %s: %s", target, codedWithSafeAction(cErr)))
	}
	if pruneErr != nil {
		// Every forget completed: the deletion IS logically complete; the
		// prune failure keeps its own class (gc's contract: 4 integrity,
		// 7 vault) with the honest completion path named. The state line
		// stays truthful when reference-aware deletion kept shared ids.
		stateLine := "the snapshots are forgotten and verified gone"
		if len(details.RetainedSharedIDs) > 0 {
			stateLine = "the snapshots are unpinned and their obligations released (shared backend ids kept; see the report)"
		}
		env.Details = details
		return emitFailure(env, *jsonOut, streams, classifyExitCode(pruneErr), fmt.Sprintf(
			"delete %s: %s, but the prune stage failed: %s. Safe action: the deletion is logically complete; run `ebb gc %s` to reclaim the storage (it re-checks every gate and is idempotent)",
			target, stateLine, codedWithSafeAction(pruneErr), v.Name))
	}

	// Reference-aware honesty (P0-1): name every id that was deliberately
	// KEPT in the vault — the machine payload and the human receipt must
	// never read as a full physical deletion when a retained row still
	// shares ids with the forgotten targets.
	for _, id := range details.RetainedSharedIDs {
		env.Warnings = append(env.Warnings, fmt.Sprintf(
			"backend snapshot %s was kept in the vault: other retained snapshot row(s) still share it (reference-aware delete; their recovery bytes are intact)", id))
	}

	env.Outcome = "ok"
	env.WorkspaceID = string(ws.ID)
	if id, perr := domain.ParseID(target); perr == nil {
		env.SnapshotID = string(id)
	}
	switch {
	case details.NoOp:
		env.Conditions = []string{"noop"}
	case *dryRun:
		env.Conditions = []string{"dry-run"}
	default:
		env.Conditions = []string{"unpinned", "forgotten"}
		if len(details.RetainedSharedIDs) > 0 {
			env.Conditions = append(env.Conditions, "shared-ids-kept")
		}
		if details.Prune.Ran {
			env.Conditions = append(env.Conditions, "pruned", "snapshots-verified-unchanged")
		} else {
			env.Conditions = append(env.Conditions, "prune-skipped")
		}
	}
	if details.PreservedBytes > 0 || details.Prune.FreedObserved > 0 || details.Prune.ReclaimableEstimate > 0 {
		env.Bytes = &BytesSummary{
			Preserved:      details.PreservedBytes,
			FreedObserved:  details.Prune.FreedObserved,
			FreedEstimated: details.Prune.ReclaimableEstimate,
		}
	}
	env.Details = details
	emit(env, *jsonOut, streams, renderDeleteHuman(details, ws, v.Name))
	return ExitOK
}

// resolveDeleteTarget maps the CLI argument onto one workspace and the
// snapshots to delete. A 32-hex argument addresses the snapshot
// directly (forget's resolution); anything else is a workspace NAME
// (exact match; when several rows share the name the parked one wins —
// open's rule), addressing ALL its snapshots.
func resolveDeleteTarget(sess *session, target string) (catalog.Workspace, []catalog.Snapshot, error) {
	if id, perr := domain.ParseID(target); perr == nil {
		snap, gerr := sess.cat.GetSnapshot(domain.SnapshotID(id))
		if gerr != nil {
			return catalog.Workspace{}, nil, usageError(fmt.Errorf("%s: no snapshot %s in the catalog. Safe action: check `ebb status` for snapshot ids",
				CodeDeleteUnknownTarget, target))
		}
		ws, werr := sess.cat.GetWorkspace(snap.WorkspaceID)
		if werr != nil {
			return catalog.Workspace{}, nil, usageError(fmt.Errorf("delete %s: snapshot has no workspace row: %v", target, werr))
		}
		return ws, []catalog.Snapshot{snap}, nil
	}
	workspaces, lerr := sess.cat.ListWorkspaces()
	if lerr != nil {
		return catalog.Workspace{}, nil, blockedError(fmt.Errorf("delete %s: listing workspaces: %v", target, lerr))
	}
	var candidates []catalog.Workspace
	for _, w := range workspaces {
		if w.Name == target {
			candidates = append(candidates, w)
		}
	}
	if len(candidates) == 0 {
		return catalog.Workspace{}, nil, usageError(fmt.Errorf(
			"%s: no workspace named %q is recorded (and the argument is not a 32-hex snapshot id). Safe action: check `ebb status` for workspace names and snapshot ids",
			CodeDeleteUnknownTarget, target))
	}
	ws := candidates[0]
	for _, c := range candidates {
		if c.Status == catalog.WorkspaceParked {
			ws = c
			break
		}
	}
	snaps, serr := sess.cat.ListSnapshots(ws.ID)
	if serr != nil {
		return catalog.Workspace{}, nil, blockedError(fmt.Errorf("delete %s: listing the workspace's snapshots: %v", target, serr))
	}
	return ws, snaps, nil
}

// foreignVaultTargets names the target snapshots whose vault binding
// does not resolve to the default vault: bound to a non-default vault
// row, or bound to a row that no longer exists (delete cannot prove
// such a snapshot default-bound, so it refuses rather than guess).
// Empty bindings are legacy default-vault rows and stay delete-eligible
// (forget runs them against the default with the full identity
// verification).
func foreignVaultTargets(sess *session, def *vault.Vault, snaps []catalog.Snapshot) ([]string, error) {
	var foreign []string
	for _, s := range snaps {
		if s.VaultID == "" {
			continue
		}
		row, err := sess.cat.GetVault(s.VaultID)
		if err != nil {
			if errors.Is(err, catalog.ErrNotFound) {
				foreign = append(foreign, fmt.Sprintf("%s is bound to vault %s, which has no catalog vault row", s.ID, s.VaultID))
				continue
			}
			return nil, err
		}
		if filepath.Clean(row.Path) != filepath.Clean(def.RepoDir) {
			foreign = append(foreign, fmt.Sprintf("%s is bound to vault %s at %s", s.ID, row.ID, row.Path))
		}
	}
	return foreign, nil
}

// runDeletePrune runs gc's D022-gated prune for the vault, as a
// skip-with-warning stage: after this deletion consumed its own
// retention intents, other workspaces' unresolved intents or active
// operations (or an unsupported backend) make the prune ineligible —
// the deletion is still logically complete, and the warning names
// `ebb gc` as the completion path. The prune itself (and its
// before/after snapshot-set verification, inside the adapter) mirrors
// gc exactly; with dryRun the estimate is gathered and nothing is
// reclaimed.
//
// One deliberate divergence from gc's gate (c): gc skips the prune
// when the vault lists zero snapshots (an already-empty repo has
// nothing interesting to reclaim). Delete only sees that state when
// THIS run just emptied the vault (forgotAny) — in which case every
// blob is now unreferenced and the prune MUST run, or the command's
// physical-space promise would be silently unkept. An empty vault on a
// rerun (forgotAny=false, pairs already absent) keeps gc's clean skip.
func runDeletePrune(ctx context.Context, sess *session, v *vault.Vault, repoDir, passfile string, env *Envelope, details *deleteDetails, dryRun, forgotAny bool) error {
	skip := func(reason string) {
		details.Prune.Ran = false
		details.Prune.SkippedReason = reason
		env.Warnings = append(env.Warnings, fmt.Sprintf(
			"prune skipped (%s): the deletion itself is complete. Safe action: run `ebb gc %s` when ready — it re-checks every gate and reclaims the storage",
			reason, v.Name))
	}
	// gate (b): no retention intent may be unresolved (this deletion's
	// own intents are consumed by the completed forget stage above).
	pending, perr := sess.cat.PendingRetentionIntents()
	if perr != nil {
		return perr
	}
	if len(pending) > 0 {
		skip(fmt.Sprintf("%d unresolved retention intent(s) from other deletions/forgets (first: snapshot %s)",
			len(pending), pending[0].SnapshotID))
		return nil
	}
	// gate (a): no operation may be active on ANY workspace (F38 — the
	// same global scope gc uses, because an in-flight capture has no
	// snapshot row yet).
	active, aerr := sess.cat.ActiveOperations("")
	if aerr != nil {
		return aerr
	}
	if len(active) > 0 {
		skip(fmt.Sprintf("%d active operation(s) must not race a prune (first: %s)",
			len(active), active[0].ID))
		return nil
	}
	pruner, ok := sess.store.(domain.RepoPruner)
	if !ok {
		skip("the configured backend does not support prune")
		return nil
	}
	refs, lerr := sess.store.List(ctx, repoDir, passfile)
	if lerr != nil {
		return lerr
	}
	if len(refs) == 0 && !forgotAny {
		// gc's clean no-op shape (nothing was removed this run; the
		// vault was already empty — an idempotent rerun or an externally
		// drained repo).
		details.Prune.Ran = false
		details.Prune.SkippedReason = "vault has no snapshots; nothing is unreferenced"
		return nil
	}
	details.Prune.RepoBytesBefore, details.Prune.RepoBytesKnown = repoDirSize(repoDir)
	stats, perr2 := pruner.Prune(ctx, repoDir, passfile, domain.PruneOptions{DryRun: dryRun})
	if perr2 != nil {
		return perr2
	}
	details.Prune.Ran = true
	details.Prune.ReclaimableEstimate = stats.ReclaimableBytes
	if dryRun {
		return nil
	}
	after, known := repoDirSize(repoDir)
	details.Prune.RepoBytesAfter, details.Prune.RepoBytesKnown = after, known
	if known {
		details.Prune.FreedObserved = details.Prune.RepoBytesBefore - after
	}
	return nil
}

// describeDeleteState renders the partial-failure state for the rerun
// message; the suffix is forget's own vocabulary (the forget stage IS
// forget's flow), scoped to the snapshots processed so far.
func describeDeleteState(state string) string {
	return describeForgetState(strings.TrimPrefix(state, "forget:")) + " (across the snapshots processed so far)"
}

// deletePrompt renders the confirmation: the target, the count and
// bytes going away, and the exact-target requirement.
func deletePrompt(d deleteDetails, ws catalog.Workspace, lastOfParked bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "delete %s of workspace %q [%s]\n", d.Target, ws.Name, ws.Status)
	fmt.Fprintf(&b, "  %d snapshot(s) will be permanently removed from the vault\n", len(d.Snapshots))
	if d.ImpactKnown {
		fmt.Fprintf(&b, "  retained material going away: %s\n", HumanBytes(d.PreservedBytes))
	} else {
		fmt.Fprintf(&b, "  size impact unknown (retained evidence unreadable; see warnings)\n")
	}
	if ws.Status == catalog.WorkspaceParked || ws.Status == catalog.WorkspaceUnbound {
		fmt.Fprintf(&b, "  THE WORKSPACE HAS NO LOCAL ROOT: after this delete, Ebb cannot recover it%s\n",
			lastOfParkedAckSuffix(lastOfParked))
	}
	fmt.Fprintf(&b, "  unreferenced vault storage will be pruned immediately\n")
	fmt.Fprintf(&b, "type the target %q to delete permanently: ", d.Target)
	return b.String()
}

// renderDeleteHuman renders the completion report.
func renderDeleteHuman(d deleteDetails, ws catalog.Workspace, vaultName string) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("delete %s of workspace %q [%s]\n", d.Target, ws.Name, ws.Status)
	if d.NoOp {
		line("  nothing to delete: %s\n", d.NoOpReason)
		return b.String()
	}
	if d.DryRun {
		line("  dry run: no changes were made; %d snapshot(s) would be forgotten and pruned:\n", len(d.Snapshots))
	} else if len(d.RetainedSharedIDs) > 0 {
		// Reference-aware honesty (P0-1): shared ids were KEPT, so the
		// batch was NOT "forgotten and verified gone" — say what happened.
		line("  %d snapshot(s) unpinned and their retention obligations released:\n", len(d.Snapshots))
	} else {
		line("  %d snapshot(s) unpinned, forgotten and verified gone:\n", len(d.Snapshots))
	}
	for _, s := range d.Snapshots {
		if s.PairAlreadyAbsent {
			line("    %s kind %s created %s (pair already absent — idempotent rerun)\n", s.SnapshotID, s.Kind, s.CreatedAt)
		} else {
			line("    %s kind %s created %s\n", s.SnapshotID, s.Kind, s.CreatedAt)
		}
	}
	for _, id := range d.RetainedSharedIDs {
		line("  backend snapshot %s was KEPT in the vault: other retained snapshot(s) still share it; their recovery bytes are intact\n", id)
	}
	if d.ImpactKnown && d.PreservedBytes > 0 {
		line("  released retained material: %s\n", HumanBytes(d.PreservedBytes))
	}
	if !d.DryRun && d.Prune.Ran {
		if d.Prune.RepoBytesKnown && d.Prune.RepoBytesAfter != 0 {
			line("  prune: repository size %s before, %s after", HumanBytes(d.Prune.RepoBytesBefore), HumanBytes(d.Prune.RepoBytesAfter))
			if d.Prune.FreedObserved > 0 {
				line(" (freed %s)", HumanBytes(d.Prune.FreedObserved))
			} else if d.Prune.FreedObserved < 0 {
				line(" (grew %s — repack overhead; nothing was lost)", HumanBytes(-d.Prune.FreedObserved))
			}
			line("\n")
		}
		if d.Prune.ReclaimableEstimate > 0 {
			line("  prune reclaimed an estimated %s\n", HumanBytes(d.Prune.ReclaimableEstimate))
		}
		line("  verified: the snapshot set is identical before and after prune\n")
	} else if d.DryRun && d.Prune.ReclaimableEstimate > 0 {
		line("  backend estimates %s reclaimable (its own dry-run summary covers ALL unreferenced data in the vault, not only this deletion)\n",
			HumanBytes(d.Prune.ReclaimableEstimate))
	} else if d.Prune.SkippedReason != "" {
		line("  prune skipped: %s\n", d.Prune.SkippedReason)
		if vaultName != "" {
			line("  run `ebb gc %s` to reclaim the storage when ready\n", vaultName)
		}
	}
	return b.String()
}
