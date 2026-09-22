// cmd_gc.go implements `ebb gc <vault>` (Foundation §11.6, §17.1): ask
// the backend to reclaim ONLY storage that is no longer referenced by
// any retained snapshot — after Ebb has verified its own retention state
// is fully resolved. This closes the physical-space loop: `ebb forget`
// removes snapshots logically, but the vault's blobs are only released
// by the backend's prune.
//
// gc has NO deletion authority of its own: it never forgets snapshots,
// never touches pins, never removes local files (beyond the backend's
// own repository maintenance), and never runs `restic unlock`. The only
// mutations it can cause happen inside the repository, governed by the
// backend's exclusive lock.
//
// Eligibility gate (Ebb-side, catalog-only, BEFORE any backend call):
//
//	(a) no operation may be active on ANY workspace — v1 Ebb has one
//	    vault and every capture/open/trim writes to it, so this is at
//	    least as strict as "bound to this vault" (F38: prune must not
//	    race a capture; an in-flight capture has no snapshot row yet, so
//	    a vault-bound query could not see it);
//	(b) no retention intent may be unresolved — an interrupted forget
//	    (§16.6) is reconciled first, by name, with its exact op id;
//	(c) a vault with no snapshots at all is a clean no-op, exit 0
//	    (nothing to reclaim is a valid result).
//
// Safety assertion (backend-side, inside the adapter): the snapshot id
// set is listed before and after the prune and MUST be identical — the
// gc-side equivalent of forget's List verification (D015). Any
// difference or verification failure is a hard typed failure (exit 4)
// reporting both sets.
//
// Locking honesty (Foundation §12.1): restic takes an exclusive lock
// for prune itself. Ebb's serialization is the catalog eligibility gate
// above; a concurrently-running EXTERNAL restic process makes prune fail
// (exit 11, surfaced typed as vault-unavailable with a never-unlock
// note). No cross-process Ebb locking exists beyond the catalog check —
// that is the v1 contract.
//
// Exit contract: 0 reclaimed or clean no-op; 2 unknown vault / bad
// arguments; 3 eligibility refusal (active operation or unresolved
// retention intent, each named with its safe action); 4 snapshot-set
// verification failure (or prune's own integrity class); 7 vault locked
// / unavailable / wrong password; 130 cancelled.

package cli

import (
	"flag"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/lifecycle"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// gcDetails is the --json payload of a gc run.
type gcDetails struct {
	Vault   string `json:"vault"`
	VaultID string `json:"vault_id,omitempty"` // registry id (not the catalog row id)
	RepoDir string `json:"repo_dir"`
	DryRun  bool   `json:"dry_run"`

	// NoOp + NoOpReason: a clean nothing-to-reclaim result (exit 0).
	NoOp       bool   `json:"no_op,omitempty"`
	NoOpReason string `json:"no_op_reason,omitempty"`

	// Snapshot accounting: backend refs (Ebb's P and S are separate
	// backend snapshots) and the catalog rows still bound to this vault
	// whose pair is present — the "retained logical snapshots".
	BackendSnapshots  int `json:"backend_snapshots"`
	RetainedSnapshots int `json:"retained_snapshots,omitempty"`
	PinnedSnapshots   int `json:"pinned_snapshots,omitempty"`

	// Space accounting. ReclaimableEstimate is the backend's own dry-run
	// summary ("total prune"); FreedObserved is the walked repository
	// file-size delta of a real prune (never asserted equal to the
	// estimate: the walk also sees index-rebuild effects).
	RepoBytesBefore     int64 `json:"repo_bytes_before,omitempty"`
	RepoBytesAfter      int64 `json:"repo_bytes_after,omitempty"`
	RepoBytesKnown      bool  `json:"repo_bytes_known,omitempty"`
	ReclaimableEstimate int64 `json:"reclaimable_estimate_bytes,omitempty"`
	FreedObserved       int64 `json:"freed_observed,omitempty"`
}

// gcWalkEntryLimit bounds the repository-size walk (a huge external
// repository must not turn `ebb gc` into an unbounded scan; beyond the
// bound the sizes are simply reported as unknown with a warning).
const gcWalkEntryLimit = 1 << 20

func cmdGc(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	dryRun := fs.Bool("dry-run", false,
		"run the eligibility gate and the backend's prune estimate without reclaiming anything (no mutation)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb gc: takes exactly one vault (name or id; see `ebb doctor` for registered vaults)")
		return ExitUsage
	}
	vaultArg := fs.Arg(0)

	env := newEnvelope("gc", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	v, verr := sess.resolveVault(vaultArg)
	if verr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(verr), verr.Error())
	}

	// ---- eligibility gate: catalog-only, before any backend call ------
	active, aerr := sess.cat.ActiveOperations("")
	if aerr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(aerr),
			fmt.Sprintf("gc %s: listing active operations: %v", vaultArg, aerr))
	}
	if len(active) > 0 {
		return emitFailure(env, *jsonOut, streams, ExitBlocked, gcActiveOpMessage(vaultArg, active))
	}
	pending, perr := sess.cat.PendingRetentionIntents()
	if perr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(perr),
			fmt.Sprintf("gc %s: listing pending retention intents: %v", vaultArg, perr))
	}
	if len(pending) > 0 {
		return emitFailure(env, *jsonOut, streams, ExitBlocked, gcPendingIntentMessage(vaultArg, pending))
	}

	details := gcDetails{Vault: v.Name, VaultID: v.ID, RepoDir: v.RepoDir, DryRun: *dryRun}
	cErr := sess.withVaultPassfileOf(ctx, v, func(repoDir, passfile string) error {
		pruner, ok := sess.store.(domain.RepoPruner)
		if !ok {
			return blockedError(fmt.Errorf("%s [gc %s]: the configured backend does not support prune; nothing was reclaimed. Safe action: run `ebb doctor` to check the backend capability",
				CodeGcUnsupported, vaultArg))
		}

		// (c) empty vault: nothing to reclaim is a VALID result (exit 0).
		refs, lerr := sess.store.List(ctx, repoDir, passfile)
		if lerr != nil {
			return lerr
		}
		details.BackendSnapshots = len(refs)
		if len(refs) == 0 {
			details.NoOp = true
			details.NoOpReason = "vault has no snapshots; nothing is unreferenced"
			return nil
		}

		// Catalog-side accounting: which logical rows still live here.
		// The vault-row id derivation is lifecycle's single authority.
		if repoID, rerr := sess.store.RepoID(ctx, repoDir, passfile); rerr == nil {
			gcCountCatalogRows(sess, lifecycle.VaultIDFor(repoID, repoDir), refs, &details)
		} else {
			env.Warnings = append(env.Warnings, fmt.Sprintf(
				"catalog attribution unavailable (repo identity unread: %s); retained-snapshot counts are backend-only", codedMessage(rerr)))
		}

		details.RepoBytesBefore, details.RepoBytesKnown = repoDirSize(repoDir)

		stats, perr := pruner.Prune(ctx, repoDir, passfile, domain.PruneOptions{DryRun: *dryRun})
		if perr != nil {
			return perr
		}
		details.ReclaimableEstimate = stats.ReclaimableBytes

		if *dryRun {
			// No mutation happened (probe-pinned): no after-walk, no
			// freed delta. The adapter already asserted the snapshot set
			// is unchanged.
			return nil
		}
		after, known := repoDirSize(repoDir)
		details.RepoBytesAfter, details.RepoBytesKnown = after, known
		if known {
			details.FreedObserved = details.RepoBytesBefore - after
		}
		return nil
	})
	if cErr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("gc %s: %s", vaultArg, codedWithSafeAction(cErr)))
	}

	env.Outcome = "ok"
	env.Details = details
	switch {
	case details.NoOp:
		env.Conditions = []string{"noop"}
	case *dryRun:
		env.Conditions = []string{"dry-run", "snapshots-verified-unchanged"}
	default:
		env.Conditions = []string{"pruned", "snapshots-verified-unchanged"}
	}
	if details.FreedObserved > 0 || details.ReclaimableEstimate > 0 {
		env.Bytes = &BytesSummary{
			FreedObserved:  details.FreedObserved,
			FreedEstimated: details.ReclaimableEstimate,
		}
	}
	emit(env, *jsonOut, streams, renderGcHuman(details))
	return ExitOK
}

// gcCountCatalogRows fills the retained/pinned snapshot counters: rows
// still bound to this vault whose payload OR seal backend id is present
// in the listed backend refs (a forgotten row keeps its ids but the pair
// is gone — that row is no longer a retained logical snapshot).
func gcCountCatalogRows(sess *session, vaultID domain.VaultID, refs []domain.SnapshotRef, details *gcDetails) {
	present := make(map[string]bool, len(refs))
	for _, r := range refs {
		present[r.BackendID] = true
	}
	workspaces, err := sess.cat.WorkspacesForVault(vaultID)
	if err != nil {
		return // attribution is informational, never a gate
	}
	for _, ws := range workspaces {
		rows, err := sess.cat.ListSnapshots(ws)
		if err != nil {
			continue
		}
		for _, row := range rows {
			if present[row.PayloadBackendID] || present[row.SealBackendID] {
				details.RetainedSnapshots++
				if row.Pinned {
					details.PinnedSnapshots++
				}
			}
		}
	}
}

// gcActiveOpMessage renders the (a) refusal: every blocking operation
// named with its durable phase and a reconciliation command that
// ACTUALLY WORKS for the blocked op's kind (Wave J review J1: the
// capsule transports' phases are closed by --cancel, and plain recover
// there is report-only — the advice must never name a dead end).
func gcActiveOpMessage(vaultArg string, active []catalog.Operation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [gc %s]: %d operation(s) are still active and maintenance must not race them (F38):",
		CodeGcActiveOperation, vaultArg, len(active))
	for _, op := range active {
		switch op.Kind {
		case catalog.OpKindExport, catalog.OpKindImport:
			fmt.Fprintf(&b, "\n  %s kind %s phase %s — close it with `ebb recover %s --cancel` (safe: the capsule transport owns no removal authority)",
				op.ID, op.Kind, op.Phase, op.ID)
		default:
			fmt.Fprintf(&b, "\n  %s kind %s phase %s — reconcile with `ebb recover %s`",
				op.ID, op.Kind, op.Phase, op.ID)
		}
	}
	fmt.Fprintf(&b, ". Safe action: reconcile each active operation (or let it finish), then rerun `ebb gc %s`", vaultArg)
	return b.String()
}

// gcPendingIntentMessage renders the (b) refusal: the unresolved forget
// is named by snapshot and intent id; the idempotent rerun completes it.
func gcPendingIntentMessage(vaultArg string, pending []catalog.RetentionIntent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s [gc %s]: %d retention intent(s) are unresolved — an interrupted forget must be reconciled before prune (the forgotten pair may still hold the only copy of its bytes):",
		CodeGcPendingIntent, vaultArg, len(pending))
	for _, ri := range pending {
		fmt.Fprintf(&b, "\n  snapshot %s (intent %s, requested by %s)",
			ri.SnapshotID, ri.ID, requestedByOrUser(ri))
	}
	fmt.Fprintf(&b, ". Safe action: rerun `ebb forget <snapshot-id> --yes` (every step is idempotent) to complete it, then rerun `ebb gc %s`", vaultArg)
	return b.String()
}

func requestedByOrUser(ri catalog.RetentionIntent) string {
	if ri.RequestedBy != "" {
		return ri.RequestedBy
	}
	return "user"
}

// repoDirSize walks the repository directory summing regular-file sizes
// (logical bytes; pack files are not sparse in practice). Bounded by
// gcWalkEntryLimit entries; ok=false when the bound or a walk failure
// makes the sum untrustworthy.
func repoDirSize(dir string) (int64, bool) {
	var total int64
	entries := 0
	ok := true
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable subtree: the sum stays a lower bound — mark it
			// untrustworthy rather than lying with a precise number.
			ok = false
			return nil
		}
		entries++
		if entries > gcWalkEntryLimit {
			ok = false
			return fs.SkipAll
		}
		if d.Type().IsRegular() {
			if fi, ierr := d.Info(); ierr == nil {
				total += fi.Size()
			}
		}
		return nil
	})
	if err != nil {
		return 0, false
	}
	return total, ok
}

// renderGcHuman renders the completion report.
func renderGcHuman(d gcDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("gc vault %q (%s)\n", d.Vault, d.RepoDir)
	if d.NoOp {
		line("  nothing to reclaim: %s\n", d.NoOpReason)
		line("  no prune was run; the vault is unchanged\n")
		return b.String()
	}
	line("  snapshots: %d backend refs", d.BackendSnapshots)
	if d.RetainedSnapshots > 0 {
		line(", %d retained logical (%d pinned)", d.RetainedSnapshots, d.PinnedSnapshots)
	}
	line("\n")
	if d.DryRun {
		line("  dry run: no changes were made\n")
		if d.ReclaimableEstimate > 0 {
			line("  backend estimates %s reclaimable (its own dry-run summary; rerun without --dry-run to reclaim)\n",
				HumanBytes(d.ReclaimableEstimate))
		} else {
			line("  backend reports nothing reclaimable\n")
		}
	} else {
		if d.RepoBytesKnown && d.RepoBytesAfter != 0 {
			line("  repository size: %s before, %s after", HumanBytes(d.RepoBytesBefore), HumanBytes(d.RepoBytesAfter))
			if d.FreedObserved > 0 {
				line(" (freed %s)", HumanBytes(d.FreedObserved))
			} else if d.FreedObserved < 0 {
				line(" (grew %s — repack overhead; nothing was lost)", HumanBytes(-d.FreedObserved))
			} else {
				line(" (no measurable change)")
			}
			line("\n")
		} else {
			line("  repository size: %s (after-walk unavailable)\n", HumanBytes(d.RepoBytesBefore))
		}
		if d.ReclaimableEstimate > 0 {
			line("  backend reclaimed an estimated %s\n", HumanBytes(d.ReclaimableEstimate))
		}
	}
	line("  verified: the snapshot set is identical before and after prune (prune never removes snapshots)\n")
	return b.String()
}

// gcVaultNamesHint lists registered vault names for error wording (the
// unknown-vault path points at doctor; this keeps gc self-contained).
func gcVaultNamesHint(reg *vault.Registry) string {
	list, err := reg.List()
	if err != nil || len(list) == 0 {
		return "no vaults are registered"
	}
	names := make([]string, 0, len(list))
	for _, v := range list {
		names = append(names, v.Name)
	}
	sort.Strings(names)
	return "registered vaults: " + strings.Join(names, ", ")
}
