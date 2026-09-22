// cmdForget implements `ebb forget <snapshot-id>` (Foundation §11.6,
// §16.6, §17.1): the deliberate, explicitly confirmed end of one
// snapshot's recovery obligation (I07: parked recovery snapshots stay
// pinned until exactly this release). The durable-state ordering is
// designed for idempotent reruns after a partial failure:
//
//	(1) retention intent recorded (reusing an existing PENDING intent
//	    for the same snapshot — an interrupted forget stays visible);
//	(2) snapshot unpinned (reason carries the intent id);
//	(3) backend pair forgotten (only the ids still present; restic
//	    forget of a nonexistent id exits 0 silently, so presence is
//	    decided by List, and removal is VERIFIED by List after);
//	(4) intent completed.
//
// Any failure after (1) is exit 5 with the exact durable state reached;
// rerunning the same command resumes (unpin of an unpinned row is a
// documented no-op, absent backend ids skip the forget call).
//
// Protections: seal-kind rows and unsealed payloads are refused (§11.3
// review, not forget); the LAST snapshot of a workspace with NO LOCAL
// ROOT — PARKED or UNBOUND (rebuilt/imported), the two statuses whose
// vault copy may be the only Ebb-known recovery copy — requires the
// explicit --last-of-parked acknowledgement (the flag keeps its Wave F
// name for compatibility; it acknowledges forgetting the last recovery
// copy of a workspace with no local root). The interactive confirmation
// requires typing the exact snapshot id; --yes accepts it for decided
// invocations.
//
// Exit contract: 0 forgotten; 2 unknown id / malformed argument; 3
// refused (seal kind, unsealed payload, last-recovery-copy of a
// no-local-root workspace without ack, declined or mismatched
// confirmation); 5 partial durable state needing a rerun; 7 vault
// unavailable.

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/restore"
)

// forgetDetails is the --json payload of a forget (success or partial).
type forgetDetails struct {
	Workspace   string `json:"workspace"`
	WorkspaceID string `json:"workspace_id"`
	SnapshotID  string `json:"snapshot_id"`
	Kind        string `json:"kind"`
	CreatedAt   string `json:"created_at"`
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
		"acknowledge forgetting the ONLY snapshot of a workspace with no local root (parked or UNBOUND — it becomes unrecoverable by Ebb)")
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
	// The last-recovery-copy guard covers every status with NO LOCAL
	// ROOT (Wave J review J8): PARKED and UNBOUND (rebuilt/imported) —
	// for either, the vault copy may be the only Ebb-known recovery copy
	// besides a capsule file, and a workspace with zero snapshots is
	// unrecoverable-by-Ebb. The flag keeps its Wave F name
	// (--last-of-parked) for compatibility.
	if (ws.Status == catalog.WorkspaceParked || ws.Status == catalog.WorkspaceUnbound) && len(all) == 1 && !*lastOfParked {
		return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
			CodeForgetLastOfParked, "forget "+idArg,
			fmt.Sprintf("this is the ONLY snapshot of %s workspace %q (no local root exists); forgetting it makes the workspace unrecoverable by Ebb", ws.Status, ws.Name),
			"Safe action: reopen it first (`ebb open "+ws.Name+" --to <dir>`), or rerun with --last-of-parked to acknowledge losing the last recovery copy"))
	}

	// ---- what it is: workspace, created, kind, size impact, dedup note --
	details := forgetDetails{
		Workspace: ws.Name, WorkspaceID: string(ws.ID),
		SnapshotID: idArg, Kind: snap.Kind, CreatedAt: snap.CreatedAt,
		BackendIDs: [2]string{snap.PayloadBackendID, snap.SealBackendID},
	}
	for _, s := range all {
		if s.CreatedAt > snap.CreatedAt && s.ID != snap.ID {
			details.NotNewest = true
			details.LaterSnapshots = append(details.LaterSnapshots, string(s.ID))
		}
	}

	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		vault := restore.VaultRef{RepoDir: repoDir, Passfile: passfile}
		// Informational readback: logical preserved bytes when cheaply
		// available; catalog facts (entry counts unavailable) otherwise.
		// A failed readback NEVER blocks forget — the user is explicitly
		// ending an obligation, not asking for proof — but it is said.
		ev, eerr := restore.LoadRetainedEvidence(ctx, sess.store, vault, snapID, snap)
		if eerr != nil {
			env.Warnings = append(env.Warnings, fmt.Sprintf(
				"retained evidence could not be read back (%s); proceeding on catalog facts only", codedMessage(eerr)))
		} else {
			details.ImpactKnown = true
			details.PreservedBytes = ev.PreservedBytes
			details.PreservedEntries = ev.PreservedEntries
			details.EntryCount = ev.Manifest.InventoryCount
		}

		// ---- confirmation: typed exact id, or --yes --------------------
		if !*yes {
			if deps.StdinIsTerminal == nil || !deps.StdinIsTerminal() {
				return blockedError(fmt.Errorf("%s [forget %s]: stdin is not a terminal and --yes was not given, so the release cannot be confirmed. Safe action: rerun with --yes after checking `ebb status`",
					CodeForgetUnconfirmed, idArg))
			}
			fmt.Fprint(streams.Err, forgetPrompt(details, ws, *lastOfParked, len(all) == 1))
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

		return runForget(ctx, sess, repoDir, passfile, snap, &details)
	})
	if cErr != nil {
		code := classifyExitCode(cErr)
		if details.StateReached != "" {
			// Durable state changed: whatever the underlying class, this
			// is a partial forget needing an idempotent rerun — unless
			// the vault itself is unavailable (7 keeps its meaning).
			if code != ExitVault {
				code = ExitInterrupted
			}
			env.Details = details // the machine payload names the reached state
			return emitFailure(env, *jsonOut, streams, code, fmt.Sprintf(
				"forget %s reached durable state %q (%s); rerun `ebb forget %s` — every step is idempotent. Safe action: resolve the cause (%s)",
				idArg, details.StateReached, describeForgetState(details.StateReached), idArg, codedWithSafeAction(cErr)))
		}
		return emitFailure(env, *jsonOut, streams, code,
			fmt.Sprintf("forget %s: %s", idArg, codedWithSafeAction(cErr)))
	}

	env.Outcome = "ok"
	env.WorkspaceID = string(ws.ID)
	env.SnapshotID = idArg
	env.Conditions = []string{"obligation-released", "unpinned"}
	if details.PreservedBytes > 0 {
		env.Bytes = &BytesSummary{Preserved: details.PreservedBytes}
	}
	env.Details = details
	emit(env, *jsonOut, streams, renderForgetHuman(details, ws))
	return ExitOK
}

// runForget performs the durable flow (intent → unpin → verified backend
// forget → complete), updating details.StateReached as each step lands.
// It runs inside the withVaultPassfile closure (repoDir/passfile bound).
func runForget(ctx context.Context, sess *session, repoDir, passfile string, snap catalog.Snapshot, details *forgetDetails) error {
	// (1) Retention intent — reuse a pending one for this snapshot (an
	// interrupted forget stays visible, §16.6).
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

	// (2) Unpin with the intent id in the reason. force: the explicit,
	// confirmed forget IS the deliberate release I07 names; the
	// parked-last-copy case was gated above (--last-of-parked).
	if uerr := sess.cat.Unpin(snap.ID, "user:forget:"+string(intentID), true); uerr != nil {
		return fmt.Errorf("forget: unpin snapshot: %w", uerr)
	}
	details.StateReached = "unpinned"

	// (3) Backend forget of the ids STILL PRESENT (restic forget of a
	// nonexistent id exits 0 silently — Learnings — so presence is
	// decided by List before, and removal is VERIFIED by List after).
	ids := [2]string{snap.PayloadBackendID, snap.SealBackendID}
	present := []string{}
	before, berr := sess.store.List(ctx, repoDir, passfile)
	if berr != nil {
		return fmt.Errorf("forget: list vault before forget: %w", berr)
	}
	have := map[string]bool{}
	for _, r := range before {
		have[r.BackendID] = true
	}
	for _, id := range ids {
		if have[id] {
			present = append(present, id)
		}
	}
	if len(present) == 0 {
		// Idempotent rerun (or external removal): nothing to forget.
		details.PairAlreadyAbsent = true
	} else if ferr := sess.store.Forget(ctx, repoDir, passfile, present); ferr != nil {
		return fmt.Errorf("forget: backend forget of %s: %w", strings.Join(present, ", "), ferr)
	}
	// VERIFY: the backend ids are really gone (never trust forget's exit
	// status alone).
	after, aerr := sess.store.List(ctx, repoDir, passfile)
	if aerr != nil {
		return fmt.Errorf("forget: post-forget verification list failed (the pair may or may not be gone): %w", aerr)
	}
	gone := map[string]bool{}
	for _, r := range after {
		gone[r.BackendID] = true
	}
	for _, id := range ids {
		if gone[id] {
			return fmt.Errorf("forget: backend snapshot %s is still present after forget; the backend refused or skipped it", id)
		}
	}
	details.StateReached = "backend-forgotten"

	// (4) Complete the intent (idempotent).
	if cerr := sess.cat.CompleteRetentionIntent(intentID); cerr != nil {
		return fmt.Errorf("forget: complete retention intent %s: %w", intentID, cerr)
	}
	details.StateReached = "completed"
	return nil
}

// forgetPrompt renders the confirmation: what the obligation is, what
// ending it means, and the exact-id requirement.
func forgetPrompt(d forgetDetails, ws catalog.Workspace, lastOfParked, onlySnapshot bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "forget %s of workspace %q [%s]\n", d.SnapshotID, ws.Name, ws.Status)
	fmt.Fprintf(&b, "  kind %s, created %s\n", d.Kind, d.CreatedAt)
	if d.ImpactKnown {
		fmt.Fprintf(&b, "  retained material: %s across %d preserved entries (inventory: %d entries)\n",
			HumanBytes(d.PreservedBytes), d.PreservedEntries, d.EntryCount)
	}
	if onlySnapshot {
		fmt.Fprintf(&b, "  THIS IS ITS ONLY RECOVERY COPY: the workspace has no other snapshot; after this\n")
		fmt.Fprintf(&b, "  forget, Ebb cannot recover it%s\n", lastOfParkedAckSuffix(lastOfParked))
	} else if d.NotNewest {
		fmt.Fprintf(&b, "  note: later snapshots exist (%d); restic dedup shares chunks between them,\n", len(d.LaterSnapshots))
		fmt.Fprintf(&b, "  so forgetting this one may free little space\n")
	}
	fmt.Fprintf(&b, "  the retained pair P=%s S=%s will be removed from the vault permanently\n", d.BackendIDs[0], d.BackendIDs[1])
	fmt.Fprintf(&b, "type the snapshot id %s to end this recovery obligation: ", d.SnapshotID)
	return b.String()
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
	if d.ImpactKnown {
		line("  released retained material: %s across %d preserved entries\n", HumanBytes(d.PreservedBytes), d.PreservedEntries)
	} else {
		line("  size impact unknown (retained evidence unreadable; see warnings)\n")
	}
	if d.NotNewest {
		line("  note: later snapshots of %q share deduped chunks; little space may actually free\n", ws.Name)
	}
	if d.PairAlreadyAbsent {
		line("  backend pair was already absent (idempotent rerun); verified gone\n")
	} else {
		line("  backend pair forgotten and verified gone: P=%s S=%s\n", d.BackendIDs[0], d.BackendIDs[1])
	}
	line("  retention intent %s completed; the recovery obligation has ended\n", d.IntentID)
	return b.String()
}
