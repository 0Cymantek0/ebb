// cmdForget implements `ebb forget <snapshot-id>` (Foundation §11.6,
// §16.6, §17.1): the deliberate, explicitly confirmed end of one
// snapshot's recovery obligation (I07: parked recovery snapshots stay
// pinned until exactly this release). The durable-state ordering is
// designed for idempotent reruns after a partial failure — and since the
// Wave 5 safety wave it is JOURNALED in a dedicated operation
// vocabulary, each phase commit naming durable evidence that already
// exists (the retention_intents row stays the authoritative evidence of
// the release obligation, §16.6; the operation row records orchestration
// only):
//
//	(0) journaled operation begun (or adopted) ATOMICALLY: the
//	    no-active-operation check and the INSERT are one SQLite
//	    transaction (catalog.BeginOperationIfNoActive; the catalog's
//	    connections take BEGIN IMMEDIATE). Concurrent EBB forgets are
//	    thereby mutually exclusive at the catalog level — one active
//	    operation per workspace. External mutation of the vault (restic
//	    run by hand, another tool) was never inside Ebb's coordination
//	    contract and remains outside it.
//	(0b) surviving-custody check: ONE backend List at forget time
//	    decides what still exists (E11: catalog rows are not custody);
//	    the last-recovery-copy guard counts only pairs the list returns.
//	    The List runs against the SNAPSHOT'S BOUND VAULT (snapshots
//	    .vault_id — import --vault binds rows to non-default vaults);
//	    empty bindings keep the default vault, and an unresolvable
//	    binding FAILS CLOSED (never a silent fallback to another
//	    repository).
//	(1) retention intent recorded → FORGET_INTENT_RECORDED;
//	(2) snapshot unpinned → FORGET_UNPINNED (post-destruction from here:
//	    recover's cancel no longer applies — a rerun resumes);
//	(3) backend pair forgotten — REFERENCE-AWARE: two logical rows may
//	    share one pair, so each id STILL PRESENT is physically forgotten
//	    only when no other retained snapshot row of the vault (all
//	    workspaces) references it; a shared id stays and the receipt says
//	    so (restic forget of a nonexistent id exits 0 silently, so
//	    presence is decided by List, and removal is VERIFIED by List
//	    after) → FORGET_BACKEND_FORGOTTEN;
//	(4) intent completed → FORGET_DONE (terminal).
//
// A crash leaves the row at its last committed phase; a rerun of the
// SAME `ebb forget <id>` recognizes its own row (kind forget + the same
// payload/seal pair recorded on it) and RESUMES idempotently — the
// pending intent is reused, unpinnning an unpinned row is a documented
// no-op, absent backend ids skip the forget call. Any failure after (2)
// deliberately leaves the row ACTIVE: canceling there would reason from
// a false "nothing destructive happened" invariant, so `ebb recover
// <op> --cancel` refuses past FORGET_UNPINNED and the rerun is the
// completion path. Failures before it close the row CANCELED.
//
// Protections: seal-kind rows and unsealed payloads are refused (§11.3
// review, not forget); the LAST SURVIVING snapshot pair of a workspace
// with NO LOCAL ROOT — PARKED or UNBOUND (rebuilt/imported), the two
// statuses whose vault copy may be the only Ebb-known recovery copy —
// requires the explicit --last-of-parked acknowledgement (the flag keeps
// its Wave F name for compatibility; it acknowledges forgetting the last
// recovery copy of a workspace with no local root). Replica receipts are
// informational only: they are never revalidated by forget and never
// count as surviving copies. The interactive confirmation requires
// typing the exact snapshot id; --yes accepts it for decided
// invocations.
//
// Exit contract: 0 forgotten; 2 unknown id / malformed argument; 3
// refused (seal kind, unsealed payload, last-surviving-recovery-copy of
// a no-local-root workspace without ack, declined or mismatched
// confirmation, an unrelated active operation); 5 partial durable state
// needing a rerun; 7 vault unavailable.

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

// forgetDetails is the --json payload of a forget (success or partial).
type forgetDetails struct {
	Workspace   string `json:"workspace"`
	WorkspaceID string `json:"workspace_id"`
	SnapshotID  string `json:"snapshot_id"`
	Kind        string `json:"kind"`
	CreatedAt   string `json:"created_at"`
	// OperationID is the journaled forget operation (FORGET_* phases):
	// concurrent EBB forgets serialize on it at the catalog level.
	OperationID string `json:"operation_id"`
	// ImpactKnown reports whether the retained-evidence readback
	// succeeded; the counters below are meaningful only then.
	ImpactKnown      bool  `json:"impact_known"`
	PreservedBytes   int64 `json:"preserved_bytes,omitempty"`
	PreservedEntries int64 `json:"preserved_entries,omitempty"`
	EntryCount       int64 `json:"inventory_count,omitempty"`
	// NotNewest: later snapshots of the workspace exist; restic dedup
	// means forgetting this snapshot may free little (said honestly).
	NotNewest         bool      `json:"not_newest"`
	LaterSnapshots    []string  `json:"later_snapshots,omitempty"`
	BackendIDs        [2]string `json:"backend_ids"`
	IntentID          string    `json:"intent_id"`
	PairAlreadyAbsent bool      `json:"pair_already_absent,omitempty"`
	// VaultName / VaultID name the vault the forget actually ran
	// against: the snapshot's bound vault (snapshots.vault_id), or the
	// registry's default for unbound rows (empty VaultID).
	VaultName string `json:"vault,omitempty"`
	VaultID   string `json:"vault_id,omitempty"`
	// RetainedSharedIDs: backend ids the target references that were
	// KEPT in the vault because other retained snapshot rows still share
	// them (reference-aware deletion: the owners' custody wins over the
	// target's physical deletion). Their presence is the honest result,
	// not a partial failure.
	RetainedSharedIDs []string `json:"retained_shared_ids,omitempty"`
	// ReplicaReceipts / ReplicaNote (T3 honesty): replica rows exist for
	// this workspace's snapshots. They were NOT revalidated by this
	// forget and do NOT count as surviving copies — informational only,
	// never a guard bypass.
	ReplicaReceipts int    `json:"replica_receipts,omitempty"`
	ReplicaNote     string `json:"replica_note,omitempty"`
	// StateReached names the last durable step completed ("completed" on
	// success; the partial states match the flow comment above).
	StateReached string `json:"state_reached"`
}

func cmdForget(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("forget", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	yes := fs.Bool("yes", false, "accept the typed-id confirmation (the obligation being ended is shown first)")
	lastOfParked := fs.Bool("last-of-parked", false,
		"acknowledge forgetting the ONLY surviving recovery copy of a workspace with no local root (parked or UNBOUND — it becomes unrecoverable by Ebb)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb forget: takes exactly one snapshot id (32 hex chars; see `ebb status`)")
		return ExitUsage
	}
	idArg := fs.Arg(0)
	if _, perr := domain.ParseID(idArg); perr != nil {
		fmt.Fprintf(streams.Err, "ebb forget: %v (got %q)\n", perr, idArg)
		return ExitUsage
	}
	snapID := domain.SnapshotID(idArg)

	env := newEnvelope("forget", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	snap, gerr := sess.cat.GetSnapshot(snapID)
	if gerr != nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage, fmt.Sprintf(
			"forget %s: no such snapshot in the catalog. Safe action: check `ebb status` for snapshot ids", idArg))
	}
	ws, werr := sess.cat.GetWorkspace(snap.WorkspaceID)
	if werr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(werr),
			fmt.Sprintf("forget %s: snapshot has no workspace row: %v", idArg, werr))
	}

	// ---- refusals before any prompt (exit 3) ----------------------------
	switch {
	case snap.Kind == catalog.SnapshotKindSeal:
		return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
			CodeForgetNotForgettable, "forget "+idArg,
			"a seal-only record carries no payload to forget; it is catalog metadata, not a recovery obligation",
			"Safe action: nothing to release; if the row is stale, inspect it with `ebb status`"))
	case snap.PayloadBackendID == "" || snap.SealBackendID == "":
		return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
			CodeForgetUnsealed, "forget "+idArg,
			fmt.Sprintf("the payload is UNSEALED (payload/seal backend id missing); an unverified or incomplete capture needs §11.3 review, not forget"),
			"Safe action: inspect with `ebb status` / `ebb recover <operation-id>`; an unsealed payload may still contain useful captured work"))
	}
	all, lerr := sess.cat.ListSnapshots(ws.ID)
	if lerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(lerr),
			fmt.Sprintf("forget %s: listing the workspace's snapshots: %v", idArg, lerr))
	}

	// ---- vault routing: the SNAPSHOT's bound vault (P0-2) ---------------
	// Multi-vault is real (`ebb import --vault` binds snapshots to
	// non-default vaults), so List/Forget must run against the vault the
	// pair actually lives in — resolved BEFORE the operation journal
	// opens, and NEVER falling back: an unresolvable binding is a blocked
	// refusal naming the vault, because a forget against a different
	// repository would find nothing and still release the obligation.
	v, verr := forgetVaultFor(sess, snap)
	if verr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(verr), verr.Error())
	}

	// ---- what it is: workspace, created, kind, size impact, dedup note --
	details := forgetDetails{
		Workspace: ws.Name, WorkspaceID: string(ws.ID),
		SnapshotID: idArg, Kind: snap.Kind, CreatedAt: snap.CreatedAt,
		BackendIDs: [2]string{snap.PayloadBackendID, snap.SealBackendID},
		VaultName:  v.Name, VaultID: v.ID,
	}
	for _, s := range all {
		if s.CreatedAt > snap.CreatedAt && s.ID != snap.ID {
			details.NotNewest = true
			details.LaterSnapshots = append(details.LaterSnapshots, string(s.ID))
		}
	}
	// Replica honesty (T3): receipts on this workspace's snapshots are
	// reported as what they are — un-revalidated history, not custody.
	reps, rerr := sess.cat.ListReplicas("")
	if rerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(rerr),
			fmt.Sprintf("forget %s: listing replica receipts: %v", idArg, rerr))
	}
	wsSnaps := make(map[domain.SnapshotID]bool, len(all))
	for _, s := range all {
		wsSnaps[s.ID] = true
	}
	for _, r := range reps {
		if wsSnaps[r.SnapshotID] {
			details.ReplicaReceipts++
		}
	}
	if details.ReplicaReceipts > 0 {
		details.ReplicaNote = fmt.Sprintf("this workspace has %d replica receipt(s), but they were not revalidated and do NOT count as surviving copies",
			details.ReplicaReceipts)
	}

	// ---- (0) begin (or adopt) the journaled operation -------------------
	op, berr := beginOrAdoptForget(sess.cat, ws.ID, snap)
	if berr != nil {
		var active *catalog.ActiveOperationError
		if errors.As(berr, &active) {
			// An operation this forget cannot adopt holds the workspace:
			// the atomic primitive's mutual exclusion doing its job.
			return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
				"forget %s: another operation holds workspace %q: %s (kind %s, phase %s). Concurrent ebb forgets are mutually exclusive at the catalog journal, and a forget resumes only its own interrupted row. Safe action: inspect with `ebb status`, then `ebb recover %s` — a forget row still before its unpin can be closed with --cancel; after the unpin, rerun `ebb forget` for that row's target",
				idArg, ws.Name, active.Operation.ID, active.Operation.Kind, active.Operation.Phase, active.Operation.ID))
		}
		return emitFailure(env, *jsonOut, streams, classifyExitCode(berr),
			fmt.Sprintf("forget %s: %s", idArg, codedWithSafeAction(berr)))
	}
	details.OperationID = string(op.ID)

	// opPhase mirrors the row's committed phase; reach moves it FORWARD
	// only (a resumed row may already sit at or past a re-walked
	// boundary — the idempotent flow must never regress it).
	opPhase := op.Phase
	reach := func(want string) error {
		if catalog.ForgetPhaseRank(opPhase) >= catalog.ForgetPhaseRank(want) {
			return nil
		}
		if aerr := sess.cat.AdvanceOperation(op.ID, opPhase, want); aerr != nil {
			return fmt.Errorf("forget: journal phase %s -> %s: %w", opPhase, want, aerr)
		}
		opPhase = want
		return nil
	}
	opOpen := true
	// closeOpCanceled ends the row while nothing destructive happened
	// (refusals, declines, pre-unpin failures): CANCELED is an honest
	// reading there.
	closeOpCanceled := func(reason string) {
		if !opOpen {
			return
		}
		opOpen = false
		_ = sess.cat.FailOperation(op.ID, opPhase, reason) // observation; the advance is the authority
		if aerr := sess.cat.AdvanceOperation(op.ID, opPhase, catalog.PhaseCanceled); aerr != nil {
			env.Warnings = append(env.Warnings, fmt.Sprintf(
				"closing the forget operation %s failed (%v); the row stays active — `ebb recover %s --cancel` closes it", op.ID, aerr, op.ID))
		}
	}
	// failOp closes the row according to how far the walk got: a
	// post-unpin row stays ACTIVE at its phase (the rerun adopts and
	// completes it; cancel is refused there by design), a pre-unpin row
	// closes CANCELED.
	failOp := func(failErr error) {
		if !opOpen {
			return
		}
		if catalog.ForgetPhaseRank(opPhase) >= catalog.ForgetPhaseRank(catalog.PhaseForgetUnpinned) {
			opOpen = false
			_ = sess.cat.FailOperation(op.ID, opPhase, failErr.Error())
			return
		}
		closeOpCanceled(failErr.Error())
	}

	// Record the target's LOGICAL identity (snapshot id + bound vault)
	// and backend pair on the row: this is the durable fingerprint by
	// which a later rerun recognizes its own operation. The snapshot id
	// is load-bearing: backend ids identify physical objects, and two
	// logical snapshot rows can share one pair (catalog reconstruction,
	// imports, corruption repair) — adoption must never cross logical
	// targets. The vault id is equally load-bearing (schemaV6): a
	// resumed forget must complete against the SAME repository the row
	// began against, even if the default vault changed in between.
	// A crash between the begin and this write leaves an unidentifiable
	// FORGET_PLANNED row (empty refs) that a rerun refuses — closing it
	// with `ebb recover <op> --cancel` is valid there (nothing
	// destructive happened yet).
	if serr := sess.cat.SetForgetTarget(op.ID, string(snap.ID), snap.PayloadBackendID, snap.SealBackendID, string(snap.VaultID)); serr != nil {
		failOp(serr)
		return emitFailure(env, *jsonOut, streams, classifyExitCode(serr),
			fmt.Sprintf("forget %s: recording the target pair on operation %s: %s", idArg, op.ID, codedWithSafeAction(serr)))
	}

	// ---- the vault-bound half -------------------------------------------
	cErr := sess.withVaultPassfileOf(ctx, v, func(repoDir, passfile string) error {
		// Reference-aware deletion preview (P0-1): which of the target's
		// backend ids other retained snapshot rows still share. The
		// prompt and the durable flow must both tell the truth about
		// what will actually be deleted — a shared id is KEPT.
		sharedRefs, sherr := otherRetainedBackendRefs(sess.cat, snap)
		if sherr != nil {
			return fmt.Errorf("forget: enumerate the vault's retained references: %w", sherr)
		}

		// (0b) Surviving custody — ONE List at forget time (E11): the
		// guard below counts only pairs this list still returns.
		surviving, serr := domain.SurvivingBackendIDs(ctx, sess.store, repoDir, passfile)
		if serr != nil {
			return fmt.Errorf("forget: list the vault for the surviving-custody check: %w", serr)
		}
		lastSurviving := noOtherSurvivingCopy(all, snap, surviving)

		// The last-recovery-copy guard covers every status with NO LOCAL
		// ROOT (Wave J review J8): PARKED and UNBOUND (rebuilt/imported)
		// — for either, the vault copy may be the only Ebb-known
		// recovery copy besides a capsule file, and a workspace with no
		// surviving snapshots is unrecoverable-by-Ebb. The flag keeps
		// its Wave F name (--last-of-parked) for compatibility.
		if (ws.Status == catalog.WorkspaceParked || ws.Status == catalog.WorkspaceUnbound) && lastSurviving && !*lastOfParked {
			return blockedError(fmt.Errorf("%s", blockerMessage(
				CodeForgetLastOfParked, "forget "+idArg,
				fmt.Sprintf("no OTHER SURVIVING recovery copy of snapshot %s exists in the vault: workspace %q is %s with no local root, and no other snapshot row's payload/seal pair is still present in the backend; forgetting it makes the workspace unrecoverable by Ebb", idArg, ws.Name, ws.Status),
				"Safe action: reopen it first (`ebb open "+ws.Name+" --to <dir>`), or rerun with --last-of-parked to acknowledge losing the last recovery copy")))
		}

		// Informational readback: logical preserved bytes when cheaply
		// available; catalog facts (entry counts unavailable) otherwise.
		// A failed readback NEVER blocks forget — the user is explicitly
		// ending an obligation, not asking for proof — but it is said.
		ev, eerr := restore.LoadRetainedEvidence(ctx, sess.store, restore.VaultRef{RepoDir: repoDir, Passfile: passfile}, snapID, snap)
		if eerr != nil {
			env.Warnings = append(env.Warnings, fmt.Sprintf(
				"retained evidence could not be read back (%s); proceeding on catalog facts only", codedMessage(eerr)))
		} else {
			details.ImpactKnown = true
			details.PreservedBytes = ev.PreservedBytes
			details.PreservedEntries = ev.PreservedEntries
			details.EntryCount = ev.Manifest.InventoryCount
		}

		// ---- confirmation: typed exact id, or --yes ---------------------
		if !*yes {
			if deps.StdinIsTerminal == nil || !deps.StdinIsTerminal() {
				return blockedError(fmt.Errorf("%s [forget %s]: stdin is not a terminal and --yes was not given, so the release cannot be confirmed. Safe action: rerun with --yes after checking `ebb status`",
					CodeForgetUnconfirmed, idArg))
			}
			fmt.Fprint(streams.Err, forgetPrompt(details, ws, *lastOfParked, lastSurviving, sharedRefs))
			line, rerr := deps.ReadLine()
			if rerr != nil {
				return blockedError(fmt.Errorf("%s [forget %s]: reading the confirmation failed: %v. Safe action: rerun the command",
					CodeForgetUnconfirmed, idArg, rerr))
			}
			if strings.TrimSpace(line) != idArg {
				return blockedError(fmt.Errorf("%s [forget %s]: the typed confirmation %q does not match the snapshot id; nothing was released. Safe action: retype the exact snapshot id, or rerun with --yes after checking `ebb status`",
					CodeForgetUnconfirmed, idArg, line))
			}
		}

		return runForgetJournaled(ctx, sess, repoDir, passfile, snap, &details, reach, sharedRefs)
	})
	// Reference-aware honesty (P0-1): name every id that was deliberately
	// KEPT in the vault — on the success receipt and on a partial state
	// alike, the user must see that the pair was not fully removed.
	for _, id := range details.RetainedSharedIDs {
		env.Warnings = append(env.Warnings, fmt.Sprintf(
			"backend snapshot %s was kept in the vault: other retained snapshot row(s) still share it (reference-aware forget; their recovery bytes are intact)", id))
	}
	if cErr != nil {
		failOp(cErr)
		code := classifyExitCode(cErr)
		if details.StateReached != "" {
			// Durable state changed: whatever the underlying class, this
			// is a partial forget needing an idempotent rerun — unless
			// the vault itself is unavailable (7 keeps its meaning). A
			// post-unpin partial leaves the operation row ACTIVE at its
			// phase on purpose: the rerun below adopts and completes it.
			if code != ExitVault {
				code = ExitInterrupted
			}
			env.Details = details // the machine payload names the reached state
			return emitFailure(env, *jsonOut, streams, code, fmt.Sprintf(
				"forget %s reached durable state %q (%s); rerun `ebb forget %s` — every step is idempotent and the journaled operation resumes. Safe action: resolve the cause (%s)",
				idArg, details.StateReached, describeForgetState(details.StateReached), idArg, codedWithSafeAction(cErr)))
		}
		return emitFailure(env, *jsonOut, streams, code,
			fmt.Sprintf("forget %s: %s", idArg, codedWithSafeAction(cErr)))
	}

	env.Outcome = "ok"
	env.WorkspaceID = string(ws.ID)
	env.SnapshotID = idArg
	env.OperationID = string(op.ID)
	env.Conditions = []string{"obligation-released", "unpinned"}
	if details.PreservedBytes > 0 {
		env.Bytes = &BytesSummary{Preserved: details.PreservedBytes}
	}
	env.Details = details
	emit(env, *jsonOut, streams, renderForgetHuman(details, ws))
	return ExitOK
}

// beginOrAdoptForget opens the journaled forget operation: atomically
// when no operation is active, or by ADOPTING the active row when it is
// this forget's own interrupted run — kind forget AND the same recorded
// fingerprint (the durable identity a crash leaves behind): the logical
// snapshot id, the BOUND VAULT (schemaV6: a resumed forget must complete
// against the same repository it began against), and the target pair.
// Anything else is refused: the *ActiveOperationError travels to the
// caller.
func beginOrAdoptForget(cat *catalog.Catalog, ws domain.WorkspaceID, snap catalog.Snapshot) (catalog.Operation, error) {
	op, err := cat.BeginOperationIfNoActive(ws, catalog.OpKindForget, catalog.PhaseForgetPlanned)
	if err == nil {
		return op, nil
	}
	var active *catalog.ActiveOperationError
	if !errors.As(err, &active) {
		return catalog.Operation{}, err
	}
	holder := active.Operation
	if holder.Kind != catalog.OpKindForget ||
		holder.SnapID != string(snap.ID) ||
		holder.VaultID != string(snap.VaultID) ||
		holder.PayloadSnap != snap.PayloadBackendID ||
		holder.SealSnap != snap.SealBackendID {
		return catalog.Operation{}, active
	}
	return holder, nil
}

// forgetVaultFor resolves the vault a forget must run against: the
// SNAPSHOT's bound vault (snapshots.vault_id — the catalog vault-row id
// capture and import both derive with lifecycle.VaultIDFor), matched to
// the registered vault by its physical repo directory. An empty binding
// (rows predating vault binding; the default-vault capture path) means
// the registry's default vault — forget's historical behavior, kept for
// compatibility. A bound vault that has no catalog row or no registry
// entry is a FAIL-CLOSED refusal naming the vault (P0-2): running the
// forget against some other repository would find nothing to forget and
// still complete the release intent while the material sits untouched.
func forgetVaultFor(sess *session, snap catalog.Snapshot) (*vault.Vault, error) {
	if snap.VaultID == "" {
		return sess.defaultVault()
	}
	row, err := sess.cat.GetVault(snap.VaultID)
	if err != nil {
		if errors.Is(err, catalog.ErrNotFound) {
			return nil, blockedError(fmt.Errorf(
				"%s: snapshot %s is bound to vault %s, which has no catalog vault row; forget refuses rather than running against a different vault. Safe action: inspect the vault rows with `ebb doctor` and re-register the vault at its recorded path",
				CodeNoVault, snap.ID, snap.VaultID))
		}
		return nil, blockedError(fmt.Errorf(
			"forget: reading the snapshot's bound vault row %s: %v", snap.VaultID, err))
	}
	list, err := sess.registry().List()
	if err != nil {
		return nil, blockedError(fmt.Errorf(
			"forget: resolving the snapshot's bound vault %s: %v", snap.VaultID, err))
	}
	for i := range list {
		if filepath.Clean(list[i].RepoDir) == filepath.Clean(row.Path) {
			return &list[i], nil
		}
	}
	return nil, blockedError(fmt.Errorf(
		"%s: snapshot %s is bound to vault %s at %s, which is not a registered vault; forget refuses rather than running against a different vault. Safe action: re-register that vault (`ebb init`), or inspect `ebb doctor` to compare the registry with the catalog",
		CodeNoVault, snap.ID, row.ID, row.Path))
}

// otherRetainedBackendRefs maps each backend id that OTHER retained
// snapshot rows still reference to the logical snapshot ids referencing
// it (P0-1: physical deletion is reference-aware). Two logical rows may
// share one payload/seal pair, so a target id may only be physically
// forgotten when NO other retained row of the vault still needs it. A
// row is retained when it is pinned or still obligated by a pending
// retention intent; the target's own row never counts. The enumeration
// spans ALL workspaces — custody is vault-wide, not workspace-scoped.
// Rows bound to a different catalog vault row that reference the same
// backend id are counted conservatively: physically that requires
// catalog corruption, and keeping bytes is always the safe reading.
func otherRetainedBackendRefs(cat *catalog.Catalog, target catalog.Snapshot) (map[string][]domain.SnapshotID, error) {
	pending, err := cat.PendingRetentionIntents()
	if err != nil {
		return nil, fmt.Errorf("pending retention intents: %w", err)
	}
	obligated := make(map[domain.SnapshotID]bool, len(pending))
	for _, ri := range pending {
		obligated[ri.SnapshotID] = true
	}
	workspaces, err := cat.ListWorkspaces()
	if err != nil {
		return nil, fmt.Errorf("list workspaces: %w", err)
	}
	refs := map[string][]domain.SnapshotID{}
	for _, ws := range workspaces {
		snaps, err := cat.ListSnapshots(ws.ID)
		if err != nil {
			return nil, fmt.Errorf("list snapshots of %s: %w", ws.ID, err)
		}
		for _, s := range snaps {
			if s.ID == target.ID || (!s.Pinned && !obligated[s.ID]) {
				continue
			}
			for _, id := range [2]string{s.PayloadBackendID, s.SealBackendID} {
				if id != "" {
					refs[id] = append(refs[id], s.ID)
				}
			}
		}
	}
	return refs, nil
}

// noOtherSurvivingCopy is the custody counting of the last-recovery-copy
// guard (E11): per the CURRENT backend list, no OTHER snapshot row of
// the workspace still has BOTH its backend ids present. Catalog rows are
// not custody — a stale row whose pair the vault no longer lists must
// not defeat the guard.
func noOtherSurvivingCopy(all []catalog.Snapshot, target catalog.Snapshot, surviving map[string]bool) bool {
	for _, s := range all {
		if s.ID == target.ID {
			continue
		}
		if s.PayloadBackendID != "" && s.SealBackendID != "" &&
			surviving[s.PayloadBackendID] && surviving[s.SealBackendID] {
			return false
		}
	}
	return true
}

// runForget is the NO-JOURNAL form of forget's durable flow, reused
// verbatim by `ebb delete` (delete keeps its own active-operation gate
// and begins no forget row in this wave — later waves migrate it to the
// journaled primitive; its per-snapshot flow therefore commits no
// phases). The forget command itself uses runForgetJournaled.
func runForget(ctx context.Context, sess *session, repoDir, passfile string, snap catalog.Snapshot, details *forgetDetails) error {
	refs, err := otherRetainedBackendRefs(sess.cat, snap)
	if err != nil {
		return fmt.Errorf("forget: enumerate the vault's retained references: %w", err)
	}
	return runForgetJournaled(ctx, sess, repoDir, passfile, snap, details, func(string) error { return nil }, refs)
}

// runForgetJournaled performs the durable flow (intent → unpin →
// verified backend forget → complete), committing the matching FORGET_*
// phase through reach after each durable act and updating
// details.StateReached as each step lands. It runs inside the bound
// vault's passfile closure (repoDir/passfile of the SNAPSHOT's vault).
// reach is the forward-only phase committer owned by cmdForget.
// sharedRefs carries the vault-wide retained references (P0-1); when
// nil it is computed here.
func runForgetJournaled(ctx context.Context, sess *session, repoDir, passfile string, snap catalog.Snapshot, details *forgetDetails, reach func(string) error, sharedRefs map[string][]domain.SnapshotID) error {
	// (1) Retention intent — reuse a pending one for this snapshot (an
	// interrupted forget stays visible, §16.6). The intent row — not the
	// operation row — is the authoritative evidence of the release
	// obligation.
	var intentID domain.ID
	if pending, perr := sess.cat.PendingRetentionIntents(); perr != nil {
		return fmt.Errorf("forget: pending retention intents: %w", perr)
	} else {
		for _, ri := range pending {
			if ri.SnapshotID == snap.ID {
				intentID = ri.ID
				break
			}
		}
	}
	if intentID == "" {
		id, cerr := sess.cat.CreateRetentionIntent(snap.ID, "user:forget")
		if cerr != nil {
			return fmt.Errorf("forget: record retention intent: %w", cerr)
		}
		intentID = id
	}
	details.IntentID = string(intentID)
	details.StateReached = "intent-recorded"
	if err := reach(catalog.PhaseForgetIntentRecorded); err != nil {
		return err
	}

	// (2) Unpin with the intent id in the reason. force: the explicit,
	// confirmed forget IS the deliberate release I07 names; the
	// parked-last-copy case was gated above (--last-of-parked). From
	// this commit on the operation is post-destruction: the rerun (not
	// recover --cancel) is its completion path.
	if uerr := sess.cat.Unpin(snap.ID, "user:forget:"+string(intentID), true); uerr != nil {
		return fmt.Errorf("forget: unpin snapshot: %w", uerr)
	}
	details.StateReached = "unpinned"
	if err := reach(catalog.PhaseForgetUnpinned); err != nil {
		return err
	}

	// (3) Backend forget of the ids STILL PRESENT (restic forget of a
	// nonexistent id exits 0 silently — Learnings — so presence is
	// decided by List before, and removal is VERIFIED by List after).
	// Physical deletion is REFERENCE-AWARE (P0-1): a backend id is
	// forgotten only when no other retained snapshot row of the vault
	// still references it; a shared id is KEPT and named on the receipt.
	if sharedRefs == nil {
		refs, rerr := otherRetainedBackendRefs(sess.cat, snap)
		if rerr != nil {
			return fmt.Errorf("forget: enumerate the vault's retained references: %w", rerr)
		}
		sharedRefs = refs
	}
	ids := [2]string{snap.PayloadBackendID, snap.SealBackendID}
	present := []string{}
	kept := []string{}
	before, berr := sess.store.List(ctx, repoDir, passfile)
	if berr != nil {
		return fmt.Errorf("forget: list vault before forget: %w", berr)
	}
	have := map[string]bool{}
	for _, r := range before {
		have[r.BackendID] = true
	}
	for _, id := range ids {
		if !have[id] {
			continue
		}
		if sharers := sharedRefs[id]; len(sharers) > 0 {
			kept = append(kept, id)
			continue
		}
		present = append(present, id)
	}
	switch {
	case len(present) == 0 && len(kept) == 0:
		// Idempotent rerun (or external removal): nothing to forget.
		details.PairAlreadyAbsent = true
	case len(present) > 0:
		if ferr := sess.store.Forget(ctx, repoDir, passfile, present); ferr != nil {
			return fmt.Errorf("forget: backend forget of %s: %w", strings.Join(present, ", "), ferr)
		}
	}
	if len(kept) > 0 {
		details.RetainedSharedIDs = kept
	}
	// VERIFY: the ids we INTENDED to delete are really gone (never trust
	// forget's exit status alone). A kept shared id intentionally stays.
	after, aerr := sess.store.List(ctx, repoDir, passfile)
	if aerr != nil {
		return fmt.Errorf("forget: post-forget verification list failed (the pair may or may not be gone): %w", aerr)
	}
	gone := map[string]bool{}
	for _, r := range after {
		gone[r.BackendID] = true
	}
	for _, id := range present {
		if gone[id] {
			return fmt.Errorf("forget: backend snapshot %s is still present after forget; the backend refused or skipped it", id)
		}
	}
	details.StateReached = "backend-forgotten"
	if err := reach(catalog.PhaseForgetBackendForgotten); err != nil {
		return err
	}

	// (4) Complete the intent (idempotent) and close the operation.
	if cerr := sess.cat.CompleteRetentionIntent(intentID); cerr != nil {
		return fmt.Errorf("forget: complete retention intent %s: %w", intentID, cerr)
	}
	details.StateReached = "completed"
	return reach(catalog.PhaseForgetDone)
}

// forgetPrompt renders the confirmation: what the obligation is, what
// ending it means, and the exact-id requirement. sharedRefs (P0-1)
// names the backend ids other retained rows still share, so the prompt
// tells the truth per id: a shared id will be KEPT, not removed.
func forgetPrompt(d forgetDetails, ws catalog.Workspace, lastOfParked, lastSurviving bool, sharedRefs map[string][]domain.SnapshotID) string {
	var b strings.Builder
	fate := func(label, id string) {
		if sharers := sharedRefs[id]; len(sharers) > 0 {
			fmt.Fprintf(&b, "  backend snapshot %s=%s will be KEPT in the vault: still shared by retained snapshot(s) %s\n",
				label, id, joinSnapshotIDs(sharers))
			return
		}
		fmt.Fprintf(&b, "  backend snapshot %s=%s will be removed from the vault permanently\n", label, id)
	}
	fmt.Fprintf(&b, "forget %s of workspace %q [%s]\n", d.SnapshotID, ws.Name, ws.Status)
	fmt.Fprintf(&b, "  kind %s, created %s\n", d.Kind, d.CreatedAt)
	if d.ImpactKnown {
		fmt.Fprintf(&b, "  retained material: %s across %d preserved entries (inventory: %d entries)\n",
			HumanBytes(d.PreservedBytes), d.PreservedEntries, d.EntryCount)
	}
	if d.ReplicaNote != "" {
		fmt.Fprintf(&b, "  note: %s\n", d.ReplicaNote)
	}
	if lastSurviving {
		fmt.Fprintf(&b, "  NO OTHER SURVIVING RECOVERY COPY: no other snapshot of this workspace is still\n")
		fmt.Fprintf(&b, "  present in the vault; after this forget, Ebb cannot recover it%s\n", lastOfParkedAckSuffix(lastOfParked))
	} else if d.NotNewest {
		fmt.Fprintf(&b, "  note: later snapshots exist (%d); restic dedup shares chunks between them,\n", len(d.LaterSnapshots))
		fmt.Fprintf(&b, "  so forgetting this one may free little space\n")
	}
	fate("P", d.BackendIDs[0])
	fate("S", d.BackendIDs[1])
	fmt.Fprintf(&b, "type the snapshot id %s to end this recovery obligation: ", d.SnapshotID)
	return b.String()
}

// joinSnapshotIDs renders a logical-snapshot-id list for the prompt and
// receipt lines.
func joinSnapshotIDs(ids []domain.SnapshotID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, ", ")
}

func lastOfParkedAckSuffix(acked bool) string {
	if acked {
		return " (--last-of-parked acknowledged)"
	}
	return ""
}

// describeForgetState renders one durable state for the partial-failure
// message.
func describeForgetState(state string) string {
	switch state {
	case "intent-recorded":
		return "the retention intent is recorded and the snapshot is still pinned"
	case "unpinned":
		return "the snapshot is unpinned and the backend pair is still present"
	case "backend-forgotten":
		return "the backend pair is forgotten and verified gone; only the intent completion is outstanding"
	default:
		return state
	}
}

// renderForgetHuman renders the completion report.
func renderForgetHuman(d forgetDetails, ws catalog.Workspace) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("forgotten snapshot %s of workspace %q [%s]\n", d.SnapshotID, ws.Name, ws.Status)
	line("  kind %s, created %s\n", d.Kind, d.CreatedAt)
	if d.VaultName != "" {
		if d.VaultID != "" {
			line("  vault %q (%s)\n", d.VaultName, d.VaultID)
		} else {
			line("  vault %q\n", d.VaultName)
		}
	}
	if d.ImpactKnown {
		line("  released retained material: %s across %d preserved entries\n", HumanBytes(d.PreservedBytes), d.PreservedEntries)
	} else {
		line("  size impact unknown (retained evidence unreadable; see warnings)\n")
	}
	if d.NotNewest {
		line("  note: later snapshots of %q share deduped chunks; little space may actually free\n", ws.Name)
	}
	if d.ReplicaNote != "" {
		line("  note: %s\n", d.ReplicaNote)
	}
	if d.PairAlreadyAbsent && len(d.RetainedSharedIDs) == 0 {
		line("  backend pair was already absent (idempotent rerun); verified gone\n")
	} else if len(d.RetainedSharedIDs) == 0 {
		line("  backend pair forgotten and verified gone: P=%s S=%s\n", d.BackendIDs[0], d.BackendIDs[1])
	} else {
		line("  backend ids forgotten and verified gone: %s\n", forgottenBackendLine(d.BackendIDs, d.RetainedSharedIDs))
	}
	for _, id := range d.RetainedSharedIDs {
		line("  backend snapshot %s was KEPT in the vault: other retained snapshot(s) still share it; their recovery bytes are intact\n", id)
	}
	line("  retention intent %s completed; the recovery obligation has ended\n", d.IntentID)
	// T4, stated exactly: what the journaled operation does and does not
	// coordinate.
	line("  journaled as operation %s: concurrent ebb forgets are mutually exclusive at the catalog\n", d.OperationID)
	line("  journal; changes made to the vault outside Ebb are not coordinated\n")
	return b.String()
}

// forgottenBackendLine names which of the target's pair were forgotten:
// both, one (the other was kept for a sharing row), or neither.
func forgottenBackendLine(ids [2]string, kept []string) string {
	keptSet := map[string]bool{}
	for _, id := range kept {
		keptSet[id] = true
	}
	var forgotten []string
	for _, id := range ids {
		if !keptSet[id] {
			forgotten = append(forgotten, id)
		}
	}
	if len(forgotten) == 0 {
		return "(none — both ids are shared and were kept)"
	}
	return "P=" + strings.Join(forgotten, " S=")
}
