// cmdImport implements `ebb import <capsule-file>` (Foundation §15.3,
// §17.1): register a capsule's retained payload snapshot in a selected
// destination vault WITHOUT publishing a working directory — the
// mirror of `ebb export`. The transport is internal/capsule (deep
// module: capsule.Import); this file owns vault resolution, capsule
// passphrase sourcing, the duplicate-gate policy (the CLI's catalog
// knowledge), the operation journal, and the snapshot/replica
// registration.
//
// Passphrase sourcing (§13.1/§15.3: never argv, never logged, never in
// the JSON envelope): the EBB_CAPSULE_PASSWORD environment variable
// wins; else ONE prompt through the ReadLine seam when stdin is a
// terminal (v1 has no hidden-input facility, so the typed line is
// visible — accepted v1 behavior; the prompt says so implicitly by
// being a plain line read); else a §5.5 blocked refusal naming the env
// var and the terminal option. An empty passphrase refuses (capsule
// itself re-validates).
//
// Journal honesty (§12): import has NO workspace row yet when the
// command starts — the logical ids live inside the encrypted capsule —
// and catalog.BeginOperation requires an existing workspace row (FK).
// The workspace row is therefore ensured LAZILY: capsule verification
// (container check, headroom, extraction, unlock, seal cross-checks,
// digest re-derivation) is read-only against durable state and needs no
// row; at the IDENTIFIED boundary — after verification, before the
// duplicate gate and any vault mutation — the transport reports the
// capsule's verified logical identity and the CLI ADOPTS it (§16.1
// identity continuity: the capsule's logical workspace id becomes the
// LOCAL workspace id, so multiple snapshots of one producer workspace
// group under ONE row and `ebb open <name>` selects the latest). The
// journal itself opens at the COPYING boundary — the first
// destination-vault mutation. One consequence, accepted deliberately:
// the capsule-side transport operation id (naming the transport's
// working dir) and the journal operation id are minted separately and
// differ; every receipt reader checks the id embedded in its own seal
// directory (I13), and the journal never names the receipt. The LOCAL
// seal the transport writes records the CAPTURE's operation id (see
// internal/capsule writeImportSeal), so the imported pair loads exactly
// like a native capture.
//
// Import NEVER implies forget, and never imports trust: the snapshot
// registers pinned (I07) and imported action approvals stay empty even
// when the source manifest claims they were approved elsewhere
// (§13.3, §15.3).
//
// Exit contract: 0 registered (or already known — the idempotent
// rerun); 2 bad arguments (unknown vault, missing/invalid capsule
// file, unwired store seam); 3 blocked before mutation (no passphrase
// source, same logical id claiming different content, destination
// headroom, trim-kind capsule); 4 a verification check failed or the
// copy could not be proven (the destination is rolled back and
// List-verified by the transport); 7 wrong capsule passphrase or
// destination vault unavailable; 130 cancelled.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"ebb/internal/capsule"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/vault"
	"ebb/internal/version"
)

// EnvCapsulePassword is the environment source for the capsule's
// recovery secret (the passphrase shown once at export time). It
// mirrors vault.EnvPassword's role: automation supplies the secret
// without argv exposure. The value never reaches logs or the JSON
// envelope.
const EnvCapsulePassword = "EBB_CAPSULE_PASSWORD"

// Import blockers the CLI layer itself raises (Wave I; §5.5 codes).
const (
	// CodeImportPassphrase: no capsule passphrase source is available.
	CodeImportPassphrase = "EBB_E_CAPSULE_PASSPHRASE"
	// CodeImportIDConflict: the capsule's logical snapshot id is
	// already registered with a DIFFERENT manifest digest.
	CodeImportIDConflict = "EBB_E_IMPORT_ID_CONFLICT"
)

// importDetails is the --json payload of an import (success, dry-run
// or already-known). The capsule passphrase is NEVER a field.
type importDetails struct {
	CapsulePath string `json:"capsule_path"`
	Vault       string `json:"vault"`
	VaultID     string `json:"vault_id,omitempty"` // registry id (not the catalog row id)
	RepoDir     string `json:"repo_dir,omitempty"`
	DryRun      bool   `json:"dry_run"`

	// Public/declared facts (present in dry-run too).
	ContainerVersion  int      `json:"container_version,omitempty"`
	BackendFamily     string   `json:"backend_family,omitempty"`
	Producer          string   `json:"producer,omitempty"`
	MinReaderFeatures []string `json:"min_reader_features,omitempty"`
	RepoBytes         int64    `json:"repo_bytes,omitempty"`
	RepoEntries       int64    `json:"repo_entries,omitempty"`
	CapsuleBytes      int64    `json:"capsule_bytes,omitempty"`

	// Dry-run headroom estimate against the destination volume.
	FreeBytes     int64 `json:"free_bytes,omitempty"`
	HeadroomKnown bool  `json:"headroom_known,omitempty"`

	// Verified facts (from the capsule's own bytes).
	Workspace   string `json:"workspace,omitempty"`    // manifest main-root prefix (D003)
	WorkspaceID string `json:"workspace_id,omitempty"` // the ADOPTED capsule logical workspace id
	SnapshotID  string `json:"snapshot_id,omitempty"`  // LOGICAL snapshot id from the capsule
	Kind        string `json:"kind,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`

	AlreadyKnown     bool   `json:"already_known,omitempty"`
	ManifestDigest   string `json:"manifest_digest,omitempty"`
	InventoryDigest  string `json:"inventory_digest,omitempty"`
	PreservedBytes   int64  `json:"preserved_bytes,omitempty"`
	PreservedEntries int64  `json:"preserved_entries,omitempty"`

	// Destination identities (empty on dry-run and already-known — the
	// vault was not touched).
	VaultRowID           string   `json:"vault_row_id,omitempty"` // catalog vault-row id the snapshot binds
	DestinationPayloadID string   `json:"destination_payload_id,omitempty"`
	DestinationSealID    string   `json:"destination_seal_id,omitempty"`
	OperationID          string   `json:"operation_id,omitempty"`
	Checks               []string `json:"checks,omitempty"`
}

func cmdImport(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	vaultArg := fs.String("vault", "", "destination vault (name or id; default: the registry's default vault)")
	dryRun := fs.Bool("dry-run", false,
		"verify the container and print the public-metadata plan (declared totals, headroom) without extracting, unlocking or registering anything")
	if err := fs.Parse(reorderFlags(args, "vault")); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb import: takes exactly one capsule file (produced by `ebb export`)")
		return ExitUsage
	}
	capsulePath := fs.Arg(0)
	// The file argument is validated up front: a missing or non-regular
	// file is an argument mistake (exit 2), decided before any
	// passphrase sourcing or vault unlock.
	if fi, err := os.Stat(capsulePath); err != nil {
		fmt.Fprintf(streams.Err, "ebb import: capsule %s: %v\n", capsulePath, err)
		return ExitUsage
	} else if !fi.Mode().IsRegular() {
		fmt.Fprintf(streams.Err, "ebb import: capsule %s is not a regular file\n", capsulePath)
		return ExitUsage
	}

	env := newEnvelope("import", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	var v *vault.Vault
	if *vaultArg != "" {
		v, err = sess.resolveVault(*vaultArg)
	} else {
		v, err = sess.defaultVault()
	}
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}

	details := importDetails{
		CapsulePath: capsulePath, Vault: v.Name, VaultID: v.ID,
		RepoDir: v.RepoDir, DryRun: *dryRun,
	}

	if *dryRun {
		// §15.3 "show that cost before extraction", public half only:
		// structural container verification, declared totals, headroom
		// estimate. No vault unlock, no extraction, no registration —
		// the destination vault contributes only its volume.
		info, ierr := capsule.ReadPublicInfo(capsulePath)
		if ierr != nil {
			return emitFailure(env, *jsonOut, streams, classifyExitCode(ierr),
				fmt.Sprintf("import %s: %s", capsulePath, codedWithSafeAction(ierr)))
		}
		details.fillPublic(info)
		details.FreeBytes, details.HeadroomKnown = importHeadroom(deps, v.RepoDir)
		env.Outcome = "ok"
		env.Conditions = []string{"dry-run", "container-verified", "unlock-happens-at-import"}
		if details.HeadroomKnown && details.FreeBytes < 2*details.RepoBytes {
			env.Warnings = append(env.Warnings, fmt.Sprintf(
				"destination volume holds %s free, but v1 budgets approximately %s for this import (extraction plus the copy; the capsule declares %s of repository) — the real import will refuse unless space is freed or another vault is chosen",
				HumanBytes(details.FreeBytes), HumanBytes(2*details.RepoBytes), HumanBytes(details.RepoBytes)))
		}
		env.Details = details
		emit(env, *jsonOut, streams, renderImportHuman(details))
		return ExitOK
	}

	cErr := sess.withVaultPassfileOf(ctx, v, func(repoDir, passfile string) error {
		capStore, ok := sess.store.(capsule.Store)
		if !ok {
			return usageError(fmt.Errorf("import: the snapshot store does not support cross-repository copy %w", ErrNotIntegrated))
		}
		passphrase, perr := capsulePassphrase(deps, streams)
		if perr != nil {
			return perr
		}
		destRepoID, rerr := sess.store.RepoID(ctx, repoDir, passfile)
		if rerr != nil {
			return fmt.Errorf("import: destination vault identity: %w", rerr)
		}
		return runImport(ctx, sess, capStore, repoDir, passfile, destRepoID, capsulePath, passphrase, streams, &details)
	})
	if cErr != nil {
		code := classifyExitCode(cErr)
		env.Details = details
		if details.OperationID != "" {
			env.OperationID = details.OperationID
			env.SnapshotID = details.SnapshotID
			env.WorkspaceID = details.WorkspaceID
		}
		return emitFailure(env, *jsonOut, streams, code,
			fmt.Sprintf("import %s: %s", capsulePath, codedWithSafeAction(cErr)))
	}

	env.Outcome = "ok"
	env.Details = details
	env.SnapshotID = details.SnapshotID
	env.WorkspaceID = details.WorkspaceID
	if details.AlreadyKnown {
		env.Conditions = []string{"already-known", "nothing-to-do"}
		emit(env, *jsonOut, streams, renderImportHuman(details))
		return ExitOK
	}
	env.OperationID = details.OperationID
	env.Conditions = []string{"registered", "pinned-by-creation", "import-never-implies-forget"}
	env.Warnings = append(env.Warnings,
		"imported actions are UNTRUSTED: rebuild approvals start empty (§13.3)")
	if details.PreservedBytes > 0 {
		env.Bytes = &BytesSummary{Preserved: details.PreservedBytes}
	}
	emit(env, *jsonOut, streams, renderImportHuman(details))
	return ExitOK
}

// runImport performs the real import inside the vault closure: the
// identity adoption (capsule's Identified hook → EnsureWorkspace under
// the CAPSULE's logical workspace id), the duplicate-gate policy
// (capsule's Known callback), the lazy journal (the copying-boundary
// Phase hook), the transport itself, and on success the catalog
// registration — vault row, pinned snapshot row under the ADOPTED
// workspace, replica receipt, DONE.
func runImport(ctx context.Context, sess *session, capStore capsule.Store,
	repoDir, passfile, destRepoID, capsulePath, passphrase string,
	streams Streams, details *importDetails) error {

	// The ADOPTED workspace identity: set by the Identified hook below
	// (the capsule's own logical workspace id, verified from its bytes).
	var wsAdopted domain.WorkspaceID
	// The capsule-side transport operation id names the transport's
	// working dir only; the journal operation id is minted by
	// catalog.BeginOperation at the copying boundary, and the local seal
	// records the CAPTURE's op id (see the file comment).
	capsuleOpID := domain.OperationID(domain.NewID())

	var (
		opID  domain.OperationID
		phase = catalog.PhasePlanned // the journal's ACTUAL phase; failClose CASes from here (J1b class)
	)
	// beginJournal opens the operation and walks onto the import
	// vocabulary. It runs at the copying boundary — after capsule
	// verification and identity adoption, before the first
	// destination-vault mutation. On a partial failure the caller's
	// failClose closes whatever was opened (opID is set the moment
	// BeginOperation succeeds), with `phase` tracking the last committed
	// transition so the CAS always matches.
	beginJournal := func() error {
		id, err := sess.cat.BeginOperation(wsAdopted, catalog.OpKindImport, capsulePath, "", "")
		if err != nil {
			return fmt.Errorf("import: begin operation: %w", err)
		}
		opID = id
		details.OperationID = string(opID)
		phase = catalog.PhasePlanned
		steps := [][2]string{
			{catalog.PhasePlanned, catalog.PhaseImportPlanned},
			{catalog.PhaseImportPlanned, catalog.PhaseImportCopying},
		}
		for _, s := range steps {
			if err := sess.cat.AdvanceOperation(opID, s[0], s[1]); err != nil {
				return fmt.Errorf("import: journal: %w", err)
			}
			phase = s[1]
		}
		return nil
	}
	// failClose mirrors export's discipline: record the failure on the
	// journal without a transition, then one CAS advance to CANCELED.
	// A failure before the journal opened (pre-verification) has
	// nothing to close.
	failClose := func(failErr error) error {
		if opID == "" {
			return failErr
		}
		_ = sess.cat.FailOperation(opID, phase, failErr.Error())
		if aerr := sess.cat.AdvanceOperation(opID, phase, catalog.PhaseCanceled); aerr != nil {
			return fmt.Errorf("%w (additionally closing the import operation: %v)", failErr, aerr)
		}
		return failErr
	}

	res, ierr := capsule.Import(ctx, capsule.ImportParams{
		Store:        capStore,
		CapsulePath:  capsulePath,
		Passphrase:   passphrase,
		DestRepoDir:  repoDir,
		DestPassfile: passfile,
		DestRepoID:   destRepoID,
		OperationID:  capsuleOpID,
		EbbVersion:   version.Version,
		Progress:     streams.Err,
		FreeSpace:    nil, // production default (build-tagged stdlib probe)
		// Identity adoption (§16.1): the capsule's logical workspace id
		// becomes the LOCAL workspace id. EnsureWorkspace is the
		// never-modify insert — an existing row (LIVE or UNBOUND) is
		// never clobbered and its name never changed — so adopting is
		// safe to run before any gate. Note the AlreadyKnown path: Known
		// returning true implies the snapshot ROW exists (the gate reads
		// GetSnapshot), whose workspace_id references an existing
		// workspace row (FK ON) — and that row carries this same adopted
		// id whenever the prior registration was itself an import of
		// this capsule, so EnsureWorkspace was a no-op; the one exotic
		// shape (a snapshot hand-registered under a DIFFERENT workspace
		// with the same manifest digest) leaves at most one extra
		// UNBOUND label row behind, never a clobbered one.
		Identified: func(id capsule.ImportIdentity) error {
			wsAdopted = domain.WorkspaceID(id.WorkspaceID)
			details.WorkspaceID = id.WorkspaceID
			if err := sess.cat.EnsureWorkspace(wsAdopted, id.WorkspaceName); err != nil {
				return fmt.Errorf("import: adopt workspace %s: %w", id.WorkspaceID, err)
			}
			return nil
		},
		// The duplicate gate is CLI-owned policy — the catalog is
		// knowledge internal/capsule deliberately does not have:
		// not-found proceeds; same id + same re-derived manifest digest
		// is the idempotent rerun (AlreadyKnown, no vault mutation);
		// same id + different digest refuses.
		Known: func(snapshotID, manifestDigest string) (bool, error) {
			snap, gerr := sess.cat.GetSnapshot(domain.SnapshotID(snapshotID))
			if gerr != nil {
				if errors.Is(gerr, catalog.ErrNotFound) {
					return false, nil
				}
				return false, fmt.Errorf("import: reading the catalog for snapshot %s: %w", snapshotID, gerr)
			}
			if snap.ManifestDigest == manifestDigest {
				return true, nil
			}
			return false, blockedError(fmt.Errorf(
				"%s [import %s]: snapshot %s is already registered with manifest digest %s, but this capsule carries %s — the same logical id claims different content. Safe action: inspect the capsule (`ebb inspect %s`) and the registered snapshot (`ebb status`); refusing to overwrite",
				CodeImportIDConflict, capsulePath, snapshotID, snap.ManifestDigest, manifestDigest, capsulePath))
		},
		Phase: func(step string) error {
			switch step {
			case capsule.PhaseExtracting:
				// Pre-verification work (container check, headroom,
				// extraction, unlock, evidence re-derivation): read-only
				// against durable state — the journal opens at the
				// copying boundary below (see the file comment).
				return nil
			case capsule.PhaseCopying:
				return beginJournal()
			case capsule.PhaseVerifying:
				if opID == "" {
					return errors.New("import: journal: verifying step without an open operation")
				}
				if err := sess.cat.AdvanceOperation(opID, catalog.PhaseImportCopying, catalog.PhaseImportVerifying); err != nil {
					return fmt.Errorf("import: journal: %w", err)
				}
				phase = catalog.PhaseImportVerifying
			}
			return nil
		},
	})
	if ierr != nil {
		return failClose(fmt.Errorf("import %s: %w", capsulePath, ierr))
	}
	details.fillResult(res)

	if res.AlreadyKnown {
		// The gate recognized the logical snapshot with the same
		// manifest digest: the destination vault was not touched and the
		// journal never opened (Known fires after Identified — the
		// EnsureWorkspace above was a no-op in this shape; see its
		// comment) — exit 0.
		return nil
	}

	// Registration order (FKs): ensure the catalog's vault row (the same
	// derivation capture uses), then the pinned snapshot row under the
	// ADOPTED workspace (ImportDiscoveredSnapshot re-runs the same
	// never-modify workspace insert EnsureWorkspace used — a no-op
	// now), the replica receipt, and DONE.
	//
	// Durable record for crash reconciliation (Wave J review J1): the
	// destination backend ids are the only handle on what this import
	// created in the vault; recording them on the op row lets
	// `ebb recover <op> --cancel` NAME leaked snapshots instead of
	// reporting them as unnameable. Best effort — a failed record must
	// not fail the import.
	if res.DestinationPayload != "" || res.DestinationSeal != "" {
		_ = sess.cat.SetBackendRefs(opID, res.DestinationPayload, res.DestinationSeal)
	}
	//
	// Rollback discipline (Wave J review J3): while the registration can
	// still fail BEFORE the snapshot row exists, a failure rolls back
	// the just-copied payload+seal pair through the transport's own
	// List-verified forget (capsule.RollbackImport — the same deletion
	// mechanism, never a second one), so a rerun starts clean instead of
	// orphaning unregistered backend snapshots. Once the row EXISTS it
	// references exactly these backend ids, so a later bookkeeping
	// failure (replica receipt / DONE close) must NOT roll the pair
	// back — the snapshot IS registered, and the idempotent rerun hits
	// the Known duplicate gate (already-known) rather than copying a
	// second time.
	rollbackPair := func(cause error) error {
		var created []string
		if res.DestinationPayload != "" {
			created = append(created, res.DestinationPayload)
		}
		if res.DestinationSeal != "" {
			created = append(created, res.DestinationSeal)
		}
		if len(created) == 0 {
			return cause
		}
		if rerr := capsule.RollbackImport(ctx, capStore, repoDir, passfile, created); rerr != nil {
			return fmt.Errorf(
				"%w — ROLLBACK FAILED: backend snapshot(s) %s may remain in the destination vault (%v); inspect and remove them explicitly before rerunning",
				cause, strings.Join(created, ", "), rerr)
		}
		return fmt.Errorf(
			"%w (the copied pair %s was rolled back in the destination vault and List-verified gone; a rerun copies fresh)",
			cause, strings.Join(created, ", "))
	}
	vaultRowID := lifecycle.VaultIDFor(destRepoID, repoDir)
	details.VaultRowID = string(vaultRowID)
	if err := sess.cat.RegisterVault(catalog.Vault{
		ID: vaultRowID, Path: repoDir, RepoID: destRepoID,
	}); err != nil {
		return failClose(rollbackPair(fmt.Errorf("import: register vault row: %w", err)))
	}
	if err := sess.cat.ImportDiscoveredSnapshot(res.WorkspaceID, res.WorkspaceName, catalog.Snapshot{
		ID:               res.LogicalSnapshotID,
		WorkspaceID:      res.WorkspaceID,
		CreatedAt:        res.CreatedAt,
		PayloadBackendID: res.DestinationPayload,
		SealBackendID:    res.DestinationSeal,
		VaultID:          vaultRowID,
		ManifestDigest:   res.ManifestDigest,
		InventoryDigest:  res.InventoryDigest,
		Kind:             res.Kind,
		Pinned:           true, // recorded pinned by construction (I07)
	}); err != nil {
		// A divergent row means another registration already claims this
		// logical id with different content: our copied pair is redundant
		// for it and is rolled back; the refusal names the divergence.
		return failClose(rollbackPair(fmt.Errorf("import: register snapshot %s: %w", res.LogicalSnapshotID, err)))
	}
	// From here the row exists and references the copied pair: keep it.
	if _, rerr := sess.cat.RecordReplica(catalog.Replica{
		SnapshotID: res.LogicalSnapshotID,
		VerifiedAt: domain.FormatTime(time.Now().UTC()),
		Scope:      "capsule-import:" + strings.Join(res.Checks, "+") + "+local-seal-readback",
		Path:       capsulePath,
	}); rerr != nil {
		return failClose(fmt.Errorf(
			"import: record replica: %w (the snapshot %s IS registered and its pair retained — a rerun reports already-known and copies nothing)", rerr, res.LogicalSnapshotID))
	}
	if aerr := sess.cat.AdvanceOperation(opID, catalog.PhaseImportVerifying, catalog.PhaseDone); aerr != nil {
		return failClose(fmt.Errorf(
			"import: close operation DONE: %w (the snapshot %s IS registered and its pair retained; if the operation stays active, close it with `ebb recover %s --cancel`)", aerr, res.LogicalSnapshotID, opID))
	}
	return nil
}

// capsulePassphrase sources the capsule's recovery secret (§13.1):
// the environment wins; else one prompt through the ReadLine seam
// when stdin is a terminal (v1 has no hidden-input facility — the
// line echoes while typed; accepted v1 behavior); else a §5.5 refusal
// naming both options. The value is returned to the caller only.
func capsulePassphrase(deps Deps, streams Streams) (string, error) {
	if pw := os.Getenv(EnvCapsulePassword); pw != "" {
		return pw, nil
	}
	if deps.StdinIsTerminal != nil && deps.StdinIsTerminal() && deps.ReadLine != nil {
		fmt.Fprint(streams.Err, "capsule passphrase: ")
		line, err := deps.ReadLine()
		if err != nil {
			return "", blockedError(fmt.Errorf(
				"%s: the capsule passphrase could not be read: %v. Safe action: set %s and rerun `ebb import`",
				CodeImportPassphrase, err, EnvCapsulePassword))
		}
		pw := strings.TrimSpace(line)
		if pw == "" {
			return "", blockedError(fmt.Errorf(
				"%s: an empty passphrase cannot unlock a capsule. Safe action: supply the passphrase shown at export time (set %s, or run in a terminal and enter it)",
				CodeImportPassphrase, EnvCapsulePassword))
		}
		return pw, nil
	}
	return "", blockedError(fmt.Errorf(
		"%s: importing a capsule requires its recovery passphrase, and no source is available (stdin is not a terminal and %s is unset). Safe action: set %s to the passphrase shown at export time, or run `ebb import` in a terminal to be prompted once",
		CodeImportPassphrase, EnvCapsulePassword, EnvCapsulePassword))
}

// importHeadroom estimates free bytes on the destination volume for
// the dry-run plan (the real import re-measures inside its preflight).
// known=false when no probe seam is wired or the probe fails — the
// plan then reports the headroom as unknown instead of guessing.
func importHeadroom(deps Deps, repoDir string) (free int64, known bool) {
	if deps.NewProbe == nil {
		return 0, false
	}
	vu, err := deps.NewProbe().VolumeUsage(repoDir)
	if err != nil || vu.FreeToCaller < 0 {
		return 0, false
	}
	return vu.FreeToCaller, true
}

// fillPublic copies the capsule's public metadata into the details.
func (d *importDetails) fillPublic(info capsule.PublicInfo) {
	d.ContainerVersion = info.ContainerVersion
	d.BackendFamily = info.BackendFamily
	d.Producer = info.Producer
	d.MinReaderFeatures = info.MinReaderFeatures
	d.RepoBytes = info.RepoBytes
	d.RepoEntries = info.RepoEntries
	d.CapsuleBytes = info.CapsuleBytes
}

// fillResult copies the transport's verified facts into the details.
// The passphrase never appears — capsule.ImportResult does not carry
// it and never will.
func (d *importDetails) fillResult(res capsule.ImportResult) {
	d.SnapshotID = string(res.LogicalSnapshotID)
	d.Workspace = res.WorkspaceName
	d.WorkspaceID = string(res.WorkspaceID) // the ADOPTED capsule id (equal to the Identified report)
	d.Kind = res.Kind
	d.CreatedAt = res.CreatedAt
	d.AlreadyKnown = res.AlreadyKnown
	d.ManifestDigest = res.ManifestDigest
	d.InventoryDigest = res.InventoryDigest
	d.PreservedBytes = res.PreservedBytes
	d.PreservedEntries = res.PreservedEntries
	if res.RepoBytes > 0 {
		d.RepoBytes = res.RepoBytes
	}
	if res.DestinationPayload != "" {
		d.DestinationPayloadID = res.DestinationPayload
	}
	if res.DestinationSeal != "" {
		d.DestinationSealID = res.DestinationSeal
	}
	if len(res.Checks) > 0 {
		d.Checks = res.Checks
	}
}

// renderImportHuman renders the import report (dry-run, already-known
// or full success). The §13.3 trust warning is part of every
// successful registration report.
func renderImportHuman(d importDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	if d.DryRun {
		line("import dry-run for capsule %s into vault %q (%s)\n", d.CapsulePath, d.Vault, d.RepoDir)
		line("  container verified structurally: version %d, backend %s, producer %s\n",
			d.ContainerVersion, d.BackendFamily, d.Producer)
		line("  declared repository: %s across %d entries; capsule file %s\n",
			HumanBytes(d.RepoBytes), d.RepoEntries, HumanBytes(d.CapsuleBytes))
		if d.HeadroomKnown {
			line("  headroom: %s free on the destination volume (v1 budgets ~%s: the extraction plus the copy into the vault)\n",
				HumanBytes(d.FreeBytes), HumanBytes(2*d.RepoBytes))
		} else {
			line("  headroom: unknown (the destination volume could not be probed)\n")
		}
		line("  unlock happens at import (%s or a terminal prompt); nothing was extracted, unlocked or registered\n",
			EnvCapsulePassword)
		return b.String()
	}
	if d.AlreadyKnown {
		line("import %s: snapshot %s is already registered with manifest digest %s; nothing to do\n",
			d.CapsulePath, d.SnapshotID, d.ManifestDigest)
		line("  the destination vault was not touched; no new rows were written\n")
		return b.String()
	}
	line("imported snapshot %s of workspace %q into vault %q\n", d.SnapshotID, d.Workspace, d.Vault)
	line("  capsule: %s (declared repository %s across %d entries)\n",
		d.CapsulePath, HumanBytes(d.RepoBytes), d.RepoEntries)
	line("  workspace %q [%s] created %s — registered UNBOUND (no working directory was published)\n",
		d.Workspace, d.Kind, d.CreatedAt)
	line("  preserved: %s across %d entries\n", HumanBytes(d.PreservedBytes), d.PreservedEntries)
	line("  destination payload %s\n    local seal %s (new destination seal, F43)\n",
		d.DestinationPayloadID, d.DestinationSealID)
	line("  digests: manifest %s / inventory %s\n", d.ManifestDigest, d.InventoryDigest)
	line("  checks: %s\n", strings.Join(d.Checks, ", "))
	line("  stays pinned; import never implies forget\n")
	line("  imported actions are UNTRUSTED: rebuild approvals start empty (§13.3)\n")
	return b.String()
}
