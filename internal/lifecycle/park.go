package lifecycle

// The park destructive tail (Foundation §12.2 steps 6-9). Nothing here
// runs unless capture() already committed SEALED with a read-back seal.
// Step numbers in comments map to §12.2:
//
//	step 6  revalidate the live source against the sealed inventory
//	step 7  rename the owned root to a unique quarantine sibling
//	step 8  remove only authorized entries from the quarantine root
//	step 9  commit PARKED and report the measured volume change

import (
	"context"
	"errors"
	"fmt"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/inventory"
)

// Park executes the full parking sequence: §12.2 steps 1-5 (capture),
// then the destructive tail 6-9. On any tail failure the retained P/S
// pair stays pinned and whatever remains of the source stays on disk.
func (c *Coordinator) Park(ctx context.Context, vault VaultRef, root string, opts CaptureOptions) (ParkResult, error) {
	st, err := c.capture(ctx, vault, root, opts, catalog.OpKindPark, catalog.SnapshotKindPark)
	if st != nil {
		defer st.journal.close() // no sequence end may leave the file held open
	}
	if err != nil {
		return ParkResult{}, err
	}
	return c.parkTail(ctx, st)
}

// parkTail runs steps 6-9 against an SEALED capture state.
func (c *Coordinator) parkTail(ctx context.Context, st *captureState) (ParkResult, error) {
	// ---- §12.2 step 6: revalidate the live source -------------------
	if err := c.revalidateSource(ctx, st.rootAbs, st.rootIdent, st.entries, st.journal); err != nil {
		// §12.2: a changed source "invalidates removal; keep P/S and
		// start a new capture when the user resolves" the change. The
		// operation fails in SEALED; the snapshot stays pinned; the
		// root is intact.
		c.failOperation(st.opID, catalog.PhaseSealed, err.Error())
		st.journal.step("revalidation-failed", err.Error())
		return ParkResult{}, err
	}
	st.journal.step("source-revalidated", st.rootAbs)

	// ---- §12.2 step 7: quarantine rename ----------------------------
	quar := quarantinePath(st.parent, st.opID)
	if err := renameToQuarantine(st.opID, st.rootAbs, quar); err != nil {
		c.failOperation(st.opID, catalog.PhaseSealed, err.Error())
		return ParkResult{}, err
	}
	// F32 protection: the renamed directory must still carry the sealed
	// identity — a replaced directory is never mistaken for the
	// original (identity, not names: I13).
	ident, err := c.probe.RootIdentity(quar)
	if err != nil {
		return c.revertQuarantine(st, quar, fmt.Errorf("lifecycle: identity probe of quarantine failed: %w", err))
	}
	if ident != st.rootIdent {
		return c.revertQuarantine(st, quar, &ErrJournalMismatch{
			Detail: fmt.Sprintf("quarantine %s identity %s does not match the sealed identity %s", quar, ident, st.rootIdent)})
	}
	if err := c.advance(st.opID, catalog.PhaseSealed, catalog.PhaseQuarantined, st.journal); err != nil {
		return ParkResult{}, err
	}

	// ---- §12.2 step 8: authorized removal from the quarantine -------
	return c.removeQuarantinedRoot(ctx, st, quar)
}

// revertQuarantine restores the original name when the post-rename
// identity check failed (never tested in practice; the identity is
// rename-stable — platform probe — but the check stays because the cost
// of being wrong is unbounded).
func (c *Coordinator) revertQuarantine(st *captureState, quar string, cause error) (ParkResult, error) {
	if rerr := renameBackFromQuarantine(quar, st.rootAbs); rerr != nil {
		cause = fmt.Errorf("%v (additionally restoring the original name failed: %v — data retained at %s)", cause, rerr, quar)
	}
	c.failOperation(st.opID, catalog.PhaseSealed, cause.Error())
	return ParkResult{}, cause
}

// removeQuarantinedRoot runs the removal walk (step 8) and the finish
// (step 9). Shared by parkTail and Recover/ResumeRemoval (the permit
// machinery is identical; resume skips entries a prior authorized walk
// removed).
func (c *Coordinator) removeQuarantinedRoot(ctx context.Context, st *captureState, quar string) (ParkResult, error) {
	// Never begin destructive work under a canceled context (§12.2: the
	// stopped-writers window must be the coordinator's own choice).
	if err := ctx.Err(); err != nil {
		err = fmt.Errorf("lifecycle: removal not started: %w", err)
		c.failOperation(st.opID, catalog.PhaseQuarantined, err.Error())
		return ParkResult{}, err
	}
	allowed := make(map[string]domain.Entry, len(st.entries))
	for _, e := range st.entries {
		allowed[e.Path] = e
	}
	permit, err := newRemovalPermit(st.opID, st.snapID, quar, st.rootIdent, allowed)
	if err != nil {
		c.failOperation(st.opID, catalog.PhaseQuarantined, err.Error())
		return ParkResult{}, err
	}
	if err := c.advance(st.opID, catalog.PhaseQuarantined, catalog.PhaseRemoving, st.journal); err != nil {
		return ParkResult{}, err
	}
	return c.finishParkRemoval(ctx, st, permit)
}

// finishParkRemoval runs the authorized walk from REMOVING through the
// park completion. Shared by the park tail and resume (Recover/
// ResumeRemoval), which enter with the journal already at REMOVING.
func (c *Coordinator) finishParkRemoval(ctx context.Context, st *captureState, permit *removalPermit) (ParkResult, error) {
	stats, err := permit.execute(ctx, c.probe, st.journal, func(removed int, last string) {
		// Removal progress is journaled per entry by the permit; this
		// callback marks the 256-entry cadence for observers.
		st.journal.step("removal-progress", fmt.Sprintf("%d removed; last %s", removed, last))
	})
	if err != nil {
		return c.parkRemovalFailed(st, err)
	}

	// ---- §12.2 step 9: quarantine root gone; commit PARKED ----------
	if err := permit.removeRoot(st.journal); err != nil {
		return c.parkRemovalFailed(st, err)
	}
	if err := c.advance(st.opID, catalog.PhaseRemoving, catalog.PhaseParked, st.journal); err != nil {
		return ParkResult{}, err
	}

	// Workspace is now parked: unbound from any live root (§16.5).
	if err := c.cat.UpsertWorkspace(catalog.Workspace{
		ID: st.wsID, Name: st.opts.WorkspaceName, Status: catalog.WorkspaceParked,
	}); err != nil {
		return ParkResult{}, fmt.Errorf("lifecycle: mark workspace parked: %w", err)
	}
	// PARKED is not in the catalog's terminal set, and ActiveOperations
	// therefore still reports a parked-complete operation as active —
	// which would block the workspace forever. The completed park's
	// final step is the PARKED→DONE transition (workspace status, not
	// the operation row, carries "this root is gone").
	if err := c.advance(st.opID, catalog.PhaseParked, catalog.PhaseDone, st.journal); err != nil {
		return ParkResult{}, err
	}

	observed := int64(0)
	if st.beforeVolume != "" {
		if after, uerr := c.probe.VolumeUsage(st.parent); uerr == nil && after.VolumeID == st.beforeVolume {
			observed = after.FreeToCaller - st.beforeFree
		}
	}
	st.journal.step("parked", fmt.Sprintf("removed=%d skipped-gone=%d freed~%d", stats.Removed, stats.SkippedGone, observed))
	c.cleanupScratch(st)

	return ParkResult{Snapshot: st.result(), VolumeDeltaObserved: observed, VolumeDeltaEstimated: st.expectedLogicalBytes()}, nil
}

// parkRemovalFailed records a stopped removal walk. A context cancellation
// is an interruption, not a block: the journal keeps the last durable
// phase REMOVING (§17.5 exit 130). Any other failure transitions to
// REMOVAL_BLOCKED with the exact blocker recorded; whatever remains stays
// and P/S stay pinned.
func (c *Coordinator) parkRemovalFailed(st *captureState, err error) (ParkResult, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		c.failOperation(st.opID, catalog.PhaseRemoving, err.Error())
		st.journal.step("removal-interrupted", err.Error())
		return ParkResult{}, err
	}
	if berr := c.cat.AdvanceOperation(st.opID, catalog.PhaseRemoving, catalog.PhaseRemovalBlocked); berr == nil {
		st.journal.step("phase:"+catalog.PhaseRemovalBlocked, err.Error())
	}
	c.failOperation(st.opID, catalog.PhaseRemovalBlocked, err.Error())
	return ParkResult{}, err
}

// revalidateSource compares a fresh scan (with hashing) of the live
// source against the sealed inventory EXACTLY: entry set, kinds, file
// digests, link texts (§12.2 step 6). Any difference — new, missing,
// changed, unreadable — invalidates removal.
func (c *Coordinator) revalidateSource(ctx context.Context, rootAbs string, ident domain.RootIdentity, sealed []domain.Entry, j *opJournal) error {
	// Root identity first: a replaced directory at the same pathname is
	// a different directory (I13/F32).
	now, err := c.probe.RootIdentity(rootAbs)
	if err != nil {
		return &ErrSourceChanged{Diff: []string{fmt.Sprintf("root %s identity unreadable: %v", rootAbs, err)}}
	}
	if now != ident {
		return &ErrSourceChanged{Diff: []string{
			fmt.Sprintf("root %s identity %s differs from sealed identity %s (directory replaced?)", rootAbs, now, ident)}}
	}
	res := inventory.Scan(ctx, c.probe, rootAbs, inventory.Options{Hash: true})
	if res.Err != nil {
		return &ErrSourceChanged{Diff: []string{fmt.Sprintf("rescan incomplete: %v", res.Err)}}
	}
	diff := compareScanToSealed(res.Entries, sealed)
	if len(diff) > 0 {
		return &ErrSourceChanged{Diff: diff}
	}
	return nil
}

// compareScanToSealed diffs a fresh entry stream against the sealed one.
// Both are canonical-ordered; the comparison covers every entry exactly
// once. The sealed ROUTES are not re-derived: removal was authorized
// against the sealed policy (re-resolving with a possibly different
// current policy could silently change what is removed).
func compareScanToSealed(fresh, sealed []domain.Entry) []string {
	var diff []string
	sealedByPath := make(map[string]domain.Entry, len(sealed))
	for _, e := range sealed {
		sealedByPath[e.Path] = e
	}
	freshByPath := make(map[string]domain.Entry, len(fresh))
	for _, e := range fresh {
		freshByPath[e.Path] = e
	}
	for _, e := range sealed {
		got, ok := freshByPath[e.Path]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s: sealed entry missing from live source", e.Path))
			continue
		}
		if got.Kind != e.Kind {
			diff = append(diff, fmt.Sprintf("%s: live kind %q, sealed %q (reparse substitution?)", e.Path, got.Kind, e.Kind))
			continue
		}
		switch e.Kind {
		case domain.KindFile:
			if got.Digest != e.Digest {
				diff = append(diff, fmt.Sprintf("%s: content changed since seal", e.Path))
			}
		case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
			if got.LinkTarget != e.LinkTarget {
				diff = append(diff, fmt.Sprintf("%s: link text changed since seal", e.Path))
			}
		}
	}
	for _, e := range fresh {
		if _, ok := sealedByPath[e.Path]; !ok {
			diff = append(diff, fmt.Sprintf("%s: new entry appeared since seal", e.Path))
		}
	}
	return diff
}
