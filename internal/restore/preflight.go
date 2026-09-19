package restore

// Destination preflight (Foundation §12.5 step 4) and interrupted-staging
// recovery (§12.4 RESTORING row). Everything here runs BEFORE this
// operation's own journal row exists, so any refusal leaves no durable
// trace and no filesystem change.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/pathcanon"
)

// preflight validates the requested destination, its separation from
// the vault (I06, the open-side twin of lifecycle's capture preflight),
// and the destination volume's peak space. Accepted destination states:
//
//   - absent (the normal case; publish renames onto the absent path);
//   - an existing EMPTY directory (removed at publish time, only if
//     still empty then — rename-over-dir always fails on Windows, so
//     the empty dir must go first).
//
// Refused: a non-directory, a non-empty directory (typed error naming
// the occupant — including files previously published by an Ebb open
// operation, which must be reconciled, not overwritten), a missing
// parent (restore never creates directory structure outside its own
// staging), any overlap with the vault repository or passfile in either
// direction and through alias spellings, and insufficient free space vs
// the preserved file bytes.
func (o *Opener) preflight(ctx context.Context, wsID domain.WorkspaceID, vault VaultRef, destOpt string, docs payloadDocs) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if destOpt == "" {
		return "", &ErrInvalidOptions{Detail: "destination path is required"}
	}
	dest := filepath.Clean(destOpt)
	if !filepath.IsAbs(dest) {
		return "", &ErrInvalidOptions{Detail: fmt.Sprintf("destination %q must be an absolute path", destOpt)}
	}
	if err := checkVaultOverlap(dest, vault); err != nil {
		return "", err
	}
	parent := filepath.Dir(dest)
	if fi, err := os.Stat(parent); err != nil {
		return "", &ErrInvalidOptions{Detail: fmt.Sprintf("destination parent %s: %v (restore never creates parent directories)", parent, err)}
	} else if !fi.IsDir() {
		return "", &ErrInvalidOptions{Detail: fmt.Sprintf("destination parent %s is not a directory", parent)}
	}

	switch fi, err := os.Lstat(dest); {
	case errors.Is(err, fs.ErrNotExist):
		// Absent: the publish target. Good.
	case err != nil:
		return "", fmt.Errorf("restore: destination %s: %w", dest, err)
	case !fi.IsDir():
		return "", &ErrDestinationOccupied{Destination: dest, Occupant: "an existing non-directory file"}
	default:
		entries, err := os.ReadDir(dest)
		if err != nil {
			return "", fmt.Errorf("restore: destination %s: %w", dest, err)
		}
		if len(entries) > 0 {
			// Is this Ebb's own prior publish? An open operation bound to
			// this destination at a publish-or-later phase (FILES_READY,
			// REBUILDING, REBUILD_FAILED, READY or DONE) put these files
			// here; they may include user work since. Overwriting them
			// needs authority this package does not have — name the
			// operation and refuse.
			if opID, phase, ok := o.publishedOpenAt(wsID, dest); ok {
				return "", &ErrDestinationOccupied{Destination: dest, Occupant: fmt.Sprintf(
					"files published by Ebb open operation %s (phase %s); never overwritten — resume or cancel that operation, or choose another --to destination", opID, phase)}
			}
			first := "unknown"
			if len(entries) > 0 {
				first = entries[0].Name()
			}
			return "", &ErrDestinationOccupied{Destination: dest, Occupant: fmt.Sprintf(
				"a non-empty directory (first entry %q)", first)}
		}
		// Empty directory: acceptable; removed at publish time.
	}

	// Peak-space check (§12.5 "calculating peak space"): the staged tree
	// and the published tree coexist on this volume until the source of
	// the rename moves within it, so preserved bytes must fit in free
	// space. Fail closed when usage cannot be observed.
	usage, err := o.probe.VolumeUsage(dest)
	if err != nil {
		usage, err = o.probe.VolumeUsage(parent) // dest may not exist yet; same volume
	}
	if err != nil {
		return "", fmt.Errorf("restore: volume usage of %s: %w", dest, err)
	}
	if usage.FreeToCaller < docs.preservedBytes {
		return "", &ErrInsufficientSpace{Destination: dest, Free: usage.FreeToCaller, Needed: docs.preservedBytes}
	}
	return dest, nil
}

// checkVaultOverlap enforces the open-side half of I06 ("Root/vault/
// operation paths cannot overlap through aliases unnoticed" — Wave G
// review finding G3): the destination — and with it the
// .ebb-stage-<opID> staging sibling, which shares the destination's
// parent and therefore lies inside the vault exactly when the
// destination does — must lie OUTSIDE the vault repository, must not
// CONTAIN the vault repository (publishing over the backend's tree),
// and must not contain the vault passfile. Comparisons run on
// canonicalized paths through the same junction-aware canonicalizer
// lifecycle's capture preflight uses (internal/pathcanon; symlink,
// junction and 8.3/case alias spellings collapse), so restore and
// capture can never disagree about what overlaps. The canonicalizer's
// documented residual (subst drives and not-yet-existing paths stay
// lexical) applies here exactly as it does on the capture side.
func checkVaultOverlap(dest string, vault VaultRef) error {
	destCanon := pathcanon.CanonicalPath(dest)
	repoCanon := pathcanon.CanonicalPath(vault.RepoDir)
	if destCanon == repoCanon {
		return &ErrVaultOverlap{Destination: dest, VaultPath: vault.RepoDir, Detail: "the destination IS the vault repository"}
	}
	if pathcanon.UnderPath(repoCanon, destCanon) {
		return &ErrVaultOverlap{Destination: dest, VaultPath: vault.RepoDir,
			Detail: "the destination lies inside the repository, so the staging sibling, the published tree and the live backend state would interleave unnoticed"}
	}
	if pathcanon.UnderPath(destCanon, repoCanon) {
		return &ErrVaultOverlap{Destination: dest, VaultPath: vault.RepoDir,
			Detail: "the destination would contain the repository, so publishing would swallow the live backend"}
	}
	if pathcanon.UnderPath(destCanon, pathcanon.CanonicalPath(vault.Passfile)) {
		return &ErrVaultOverlap{Destination: dest, VaultPath: vault.Passfile,
			Detail: "the destination would contain the passfile holding the vault unlock secret"}
	}
	return nil
}

// publishedOpenAt reports the id and phase of the open operation that
// already published its files at dest (dest as its root of record, at a
// publish-or-later phase). An ACTIVE operation (resumable) wins over a
// completed one: it is the reconciliation target the message names.
func (o *Opener) publishedOpenAt(wsID domain.WorkspaceID, dest string) (domain.OperationID, string, bool) {
	ops, err := o.cat.ListOperations(wsID)
	if err != nil {
		return "", "", false // preflight treats a journal failure as "not Ebb's"
	}
	published := func(phase string) bool {
		switch phase {
		case catalog.PhaseFilesReady, catalog.PhaseRebuilding, catalog.PhaseRebuildFailed,
			catalog.PhaseReady, catalog.PhaseDone:
			return true
		}
		return false
	}
	var doneMatch *catalog.Operation
	for i := range ops {
		op := ops[i]
		if op.Kind != catalog.OpKindOpen || op.SourceRoot != dest || !published(op.Phase) {
			continue
		}
		if resumePhases[op.Phase] {
			return op.ID, op.Phase, true // active: the reconciliation target
		}
		o := op
		doneMatch = &o
	}
	if doneMatch != nil {
		return doneMatch.ID, doneMatch.Phase, true
	}
	return "", "", false
}

// recoverInterruptedOpen reconciles ACTIVE open operations of this
// workspace bound to the same destination (§12.4 RESTORING row:
// "Resume verified owned staging or leave it for explicit cleanup";
// v1's serialized CLI chooses: recognize, clean, cancel, redo fresh —
// never overwrite anything unrecognized). The stale operation's staging
// directory is removed only when its base name carries that operation's
// own id (shape-gated, I13).
func (o *Opener) recoverInterruptedOpen(ctx context.Context, wsID domain.WorkspaceID, dest string) ([]string, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	active, err := o.cat.ActiveOperations(wsID)
	if err != nil {
		return nil, fmt.Errorf("restore: active operations: %w", err)
	}
	var warnings []string
	for _, op := range active {
		if op.Kind != catalog.OpKindOpen || op.SourceRoot != dest {
			continue
		}
		stage := stagingRoot(dest, op.ID)
		if fi, err := os.Lstat(stage); err == nil {
			if base := filepath.Base(stage); base == stagePrefix+string(op.ID) && fi.IsDir() {
				if rerr := removeStage(stage); rerr != nil {
					return warnings, fmt.Errorf("restore: recover interrupted open %s: %w", op.ID, rerr)
				}
				warnings = append(warnings, fmt.Sprintf(
					"removed stale staging %s of interrupted open operation %s (phase %s)", stage, op.ID, op.Phase))
			} else {
				// Unrecognized shape at the staging path: never touch it.
				warnings = append(warnings, fmt.Sprintf(
					"staging path %s of operation %s is not this operation's own staging shape; left untouched", stage, op.ID))
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return warnings, fmt.Errorf("restore: recover interrupted open %s: staging %s: %w", op.ID, stage, err)
		}
		if aerr := o.cat.AdvanceOperation(op.ID, op.Phase, catalog.PhaseCanceled); aerr != nil {
			return warnings, fmt.Errorf("restore: cancel stale open operation %s (%s): %w", op.ID, op.Phase, aerr)
		}
		warnings = append(warnings, fmt.Sprintf(
			"canceled stale open operation %s (was %s) targeting %s", op.ID, op.Phase, dest))
	}
	return warnings, nil
}
