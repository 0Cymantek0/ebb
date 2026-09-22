// cmdExport implements `ebb export <snapshot-id> --output <file>`
// (Foundation §15.2, §17.1): produce an independent encrypted capsule —
// a fresh restic repository holding ONLY the selected payload snapshot
// and a NEW destination seal — packaged as a ZIP64 container of stored
// entries, fully verified before a no-clobber publication. Export NEVER
// implies forget: the source snapshot stays pinned by its original
// reasons; the export's own pin (reason `export:<opID>`) is released on
// completion. Import (`ebb import`) is the counterpart command.
//
// Wiring: vault resolution + catalog duties (pin, operation journal,
// replicas receipt) live here; the transport itself is internal/capsule
// (deep module: capsule.Export).
//
// Passphrase display contract: the generated capsule passphrase is the
// user's recovery secret. It prints ONCE, to the terminal (stderr),
// clearly marked — IMMEDIATELY after the publish rename durably places
// the capsule it unlocks and BEFORE any fallible bookkeeping (Wave J
// review J2: a post-publication bookkeeping failure is a warning on a
// success, never the failure that silences the secret) — including
// under --json, whose machine output instead names the output file and
// says the passphrase was displayed there. It never enters argv, logs
// or the JSON envelope.
//
// Exit contract: 0 capsule published; 2 malformed id / bad arguments /
// unwired seam; 3 refused (trim/seal kind, unsealed payload, occupied
// output path, stale partial); 4 a verification check failed (nothing
// published); 7 vault unavailable; 130 cancelled.

package cli

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/capsule"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/restore"
	"github.com/0Cymantek0/ebb/internal/version"
)

// exportDetails is the --json payload of an export (success or dry-run).
// Passphrase is a GUIDANCE STRING ONLY — the secret itself never
// serializes (printed once to the terminal by the human channel).
type exportDetails struct {
	Workspace   string `json:"workspace"`
	SnapshotID  string `json:"snapshot_id"`
	Kind        string `json:"kind"`
	CreatedAt   string `json:"created_at"`
	OutputPath  string `json:"output_path,omitempty"`
	DryRun      bool   `json:"dry_run"`
	OperationID string `json:"operation_id,omitempty"`
	// Size facts: the capsule's final size is only known after the copy
	// (backend re-encryption), so a dry-run reports the source payload's
	// logical bytes and says so.
	PayloadLogicalBytes int64 `json:"payload_logical_bytes,omitempty"`
	PreservedEntries    int64 `json:"preserved_entries,omitempty"`
	CapsuleBytes        int64 `json:"capsule_bytes,omitempty"`
	// Destination identities (F43: the destination seal refers to these).
	DestinationRepoID    string   `json:"destination_repo_id,omitempty"`
	DestinationPayloadID string   `json:"destination_payload_id,omitempty"`
	DestinationSealID    string   `json:"destination_seal_id,omitempty"`
	Checks               []string `json:"checks,omitempty"`
	Passphrase           string   `json:"passphrase,omitempty"` // guidance text, never the secret
	// Warnings carry post-publication bookkeeping failures (J2): the
	// capsule exists and its passphrase was displayed; the warnings name
	// what durable bookkeeping (replica row, pin release, DONE close)
	// did not land and how to reconcile it.
	Warnings []string `json:"warnings,omitempty"`
}

func cmdExport(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	output := fs.String("output", "", "capsule output file (required; never overwritten)")
	dryRun := fs.Bool("dry-run", false, "check eligibility and print the plan without creating anything")
	if err := fs.Parse(reorderFlags(args, "output")); err != nil {
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb export: takes exactly one snapshot id (32 hex chars; see `ebb status`)")
		return ExitUsage
	}
	idArg := fs.Arg(0)
	if *output == "" {
		fmt.Fprintln(streams.Err, "ebb export: --output <file> is required")
		return ExitUsage
	}
	if _, perr := domain.ParseID(idArg); perr != nil {
		fmt.Fprintf(streams.Err, "ebb export: %v (got %q)\n", perr, idArg)
		return ExitUsage
	}
	snapID := domain.SnapshotID(idArg)

	env := newEnvelope("export", "error")
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
			"export %s: no such snapshot in the catalog. Safe action: check `ebb status` for snapshot ids", idArg))
	}
	ws, werr := sess.cat.GetWorkspace(snap.WorkspaceID)
	if werr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(werr),
			fmt.Sprintf("export %s: snapshot has no workspace row: %v", idArg, werr))
	}
	// Scope gate (mirrors verify/D011): v1 exports full workspace
	// payloads. A trim's seal covers only a removal plan; a seal-only
	// row has no payload; an unsealed payload was never verified.
	switch {
	case snap.Kind == catalog.SnapshotKindTrim:
		return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
			CodeExportNotExportable, "export "+idArg,
			"a trim snapshot's authoritative material is its sealed removal plan, not a recoverable workspace payload",
			"Safe action: export a park- or snapshot-kind snapshot (see `ebb status`)"))
	case snap.Kind == catalog.SnapshotKindSeal:
		return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
			CodeExportNotExportable, "export "+idArg,
			"a seal-only record has no payload to export",
			"Safe action: nothing to capsule; see `ebb status`"))
	case snap.PayloadBackendID == "" || snap.SealBackendID == "":
		return emitFailure(env, *jsonOut, streams, ExitBlocked, blockerMessage(
			CodeExportNotExportable, "export "+idArg,
			"the payload is UNSEALED (payload/seal backend id missing); an unverified capture cannot be exported",
			"Safe action: inspect with `ebb status` / `ebb recover <operation-id>` (§11.3)"))
	}

	details := exportDetails{
		Workspace: ws.Name, SnapshotID: idArg, Kind: snap.Kind,
		CreatedAt: snap.CreatedAt, OutputPath: *output, DryRun: *dryRun,
	}

	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		ev, eerr := restore.LoadRetainedEvidence(ctx, sess.store,
			restore.VaultRef{RepoDir: repoDir, Passfile: passfile}, snapID, snap)
		if eerr != nil {
			return fmt.Errorf("export %s: retained evidence: %w", idArg, eerr)
		}
		details.PayloadLogicalBytes = ev.PreservedBytes
		details.PreservedEntries = ev.PreservedEntries

		if *dryRun {
			return nil // eligibility checks passed; nothing is created
		}
		return runExport(ctx, sess, repoDir, passfile, snap, ev, *output, streams, &details)
	})
	if cErr != nil {
		code := classifyExitCode(cErr)
		env.Details = details
		env.Warnings = append(env.Warnings, details.Warnings...)
		if details.OperationID != "" {
			env.OperationID = details.OperationID
			env.SnapshotID = idArg
			env.WorkspaceID = string(ws.ID)
		}
		return emitFailure(env, *jsonOut, streams, code,
			fmt.Sprintf("export %s: %s", idArg, codedWithSafeAction(cErr)))
	}

	env.Outcome = "ok"
	env.SnapshotID = idArg
	env.WorkspaceID = string(ws.ID)
	env.Details = details
	env.Warnings = append(env.Warnings, details.Warnings...)
	if *dryRun {
		env.Conditions = []string{"dry-run"}
	} else {
		env.OperationID = details.OperationID
		env.Conditions = []string{
			"independent-encryption-domain",
			"source-stays-pinned",
			"verified-before-publication",
		}
		if details.PayloadLogicalBytes > 0 {
			env.Bytes = &BytesSummary{Preserved: details.PayloadLogicalBytes}
		}
	}
	emit(env, *jsonOut, streams, renderExportHuman(details, ws, *dryRun))
	return ExitOK
}

// runExport performs the real export: journal + duration pin, the
// capsule transport, the replicas receipt, and the pin release. It runs
// inside the withVaultPassfile closure.
func runExport(ctx context.Context, sess *session, repoDir, passfile string,
	snap catalog.Snapshot, ev restore.Evidence, outputPath string,
	streams Streams, details *exportDetails) error {

	capStore, ok := sess.store.(capsule.Store)
	if !ok {
		return usageError(fmt.Errorf("export: the snapshot store does not support cross-repository copy %w", ErrNotIntegrated))
	}
	// Source repository identity (recorded in the destination seal's
	// §16.4 source block).
	srcRepoID, err := sess.store.RepoID(ctx, repoDir, passfile)
	if err != nil {
		return fmt.Errorf("export: source vault identity: %w", err)
	}

	// Re-read the row for the honest pre-export pin state (the duration
	// pin must not change the snapshot's long-term pinned state).
	fresh, err := sess.cat.GetSnapshot(snap.ID)
	if err != nil {
		return fmt.Errorf("export: re-read snapshot: %w", err)
	}
	wasPinned := fresh.Pinned

	opID, err := sess.cat.BeginOperation(snap.WorkspaceID, catalog.OpKindExport, "", "", "")
	if err != nil {
		return fmt.Errorf("export: begin operation: %w", err)
	}
	details.OperationID = string(opID)

	// Journal discipline (Wave J review J1/J1b): from the moment
	// BeginOperation lands, EVERY failure — including the early ones
	// between the begin and the first phase advance — routes through
	// failClose, so neither a stuck-active operation nor a stale export
	// pin can result. `phase` always names the journal's ACTUAL phase so
	// failClose's CAS matches.
	phase := catalog.PhasePlanned
	failClose := func(failErr error) error {
		_ = sess.cat.FailOperation(opID, phase, failErr.Error())
		if aerr := sess.cat.AdvanceOperation(opID, phase, catalog.PhaseCanceled); aerr != nil {
			return fmt.Errorf("%w (additionally closing the export operation: %v)", failErr, aerr)
		}
		return failErr
	}
	// releasePin closes the duration pin. It returns an error instead of
	// swallowing one: after publication the caller reports the failure as
	// a warning (J2), and before publication failClose's error already
	// names the primary failure — the pin state is then visible via
	// `ebb recover <op> --cancel`, which releases the pin audit-only.
	releasePin := func() error {
		if wasPinned {
			// Audit-only release: the snapshot stays pinned by its
			// original reasons (creation); the export adds no permanent
			// obligation.
			if rerr := sess.cat.RecordPinRelease(snap.ID, "export:"+string(opID)); rerr != nil {
				return fmt.Errorf("export: release export pin (audit-only): %w", rerr)
			}
			return nil
		}
		// It was unpinned before the export: restore that state.
		if uerr := sess.cat.Unpin(snap.ID, "export:"+string(opID), true); uerr != nil {
			return fmt.Errorf("export: release export pin (restore unpinned): %w", uerr)
		}
		return nil
	}

	if err := sess.cat.Pin(snap.ID, "export:"+string(opID)); err != nil {
		return failClose(fmt.Errorf("export: take export pin: %w", err))
	}
	// BeginOperation journals at the generic PLANNED phase; move onto
	// the export vocabulary before the capsule starts. The pin is
	// already taken here, so a failed advance must also release it.
	if err := sess.cat.AdvanceOperation(opID, catalog.PhasePlanned, catalog.PhaseExportPlanned); err != nil {
		if perr := releasePin(); perr != nil {
			details.Warnings = append(details.Warnings, perr.Error())
		}
		return failClose(fmt.Errorf("export: journal: %w", err))
	}
	phase = catalog.PhaseExportPlanned

	res, xerr := capsule.Export(ctx, capsule.Params{
		Store:          capStore,
		Snapshot:       snap,
		Evidence:       ev,
		SourceRepoDir:  repoDir,
		SourcePassfile: passfile,
		SourceRepoID:   srcRepoID,
		OutputPath:     outputPath,
		OperationID:    opID,
		EbbVersion:     version.Version,
		Progress:       streams.Err,
		Phase: func(step string) error {
			switch step {
			case capsule.PhaseCopying:
				if err := sess.cat.AdvanceOperation(opID, catalog.PhaseExportPlanned, catalog.PhaseExportCopying); err != nil {
					return fmt.Errorf("export: journal: %w", err)
				}
				phase = catalog.PhaseExportCopying
			case capsule.PhaseVerifying:
				if err := sess.cat.AdvanceOperation(opID, catalog.PhaseExportCopying, catalog.PhaseExportVerifying); err != nil {
					return fmt.Errorf("export: journal: %w", err)
				}
				phase = catalog.PhaseExportVerifying
			case capsule.PhasePackaging:
				// Packaging is the second half of EXPORT_VERIFYING; no
				// separate catalog phase exists for it.
			}
			return nil
		},
	})
	if xerr != nil {
		// Nothing was published (capsule.Export removed its own partial
		// on failure): a hard failure is honest. The pin release and the
		// op close are part of the close-out; their own failures become
		// warnings so the primary error is never masked.
		if perr := releasePin(); perr != nil {
			details.Warnings = append(details.Warnings, perr.Error())
		}
		return failClose(fmt.Errorf("export %s: %w", snap.ID, xerr))
	}

	// The capsule is PUBLISHED (the no-clobber rename inside
	// capsule.Export has completed; no .partial remains). Print the
	// one-time passphrase IMMEDIATELY — before any fallible bookkeeping
	// — so no later failure can destroy the crypto/rand secret that
	// unlocks the artifact that now exists (Wave J review J2). Terminal
	// (stderr) only, marked; never argv, logs or the JSON envelope.
	details.CapsuleBytes = res.CapsuleBytes
	details.DestinationRepoID = res.DestinationRepoID
	details.DestinationPayloadID = res.DestinationPayload
	details.DestinationSealID = res.DestinationSeal
	details.Checks = res.Checks
	details.Passphrase = "displayed on terminal only; not recorded in machine output"
	fmt.Fprintf(streams.Err, "\nCAPSULE PASSPHRASE — shown ONCE, never stored by Ebb:\n  %s\n", res.Passphrase)
	fmt.Fprintln(streams.Err, "Store it in a password manager now; without it the capsule cannot be opened.")

	// Post-publication bookkeeping (replica receipt, pin release, DONE
	// close) degrades to WARNINGS on a SUCCESS outcome (J2): the
	// capsule exists and its passphrase was displayed, so a catalog
	// hiccup must neither fail the export nor silence what already
	// succeeded. Every warning discloses that the complete capsule sits
	// at the final path.
	warn := func(format string, a ...any) {
		w := fmt.Sprintf(format, a...)
		details.Warnings = append(details.Warnings, w)
		fmt.Fprintf(streams.Err, "warning: %s\n", w)
	}
	if _, rerr := sess.cat.RecordReplica(catalog.Replica{
		SnapshotID: snap.ID,
		VerifiedAt: domain.FormatTime(time.Now().UTC()),
		Scope:      "capsule-export:" + strings.Join(res.Checks, "+") + "+container-verified",
		Path:       res.OutputPath,
	}); rerr != nil {
		warn("recording the capsule replica receipt failed (%v); the COMPLETE capsule is published at %s and opens with the passphrase shown above — only the replicas bookkeeping row is missing", rerr, res.OutputPath)
	}
	if perr := releasePin(); perr != nil {
		warn("%v; the COMPLETE capsule is published at %s — the export pin may still be taken (visible in `ebb status`; `ebb recover %s --cancel` releases it audit-only)", perr, res.OutputPath, opID)
	}
	if aerr := sess.cat.AdvanceOperation(opID, catalog.PhaseExportVerifying, catalog.PhaseDone); aerr != nil {
		warn("closing the export operation DONE failed (%v); the COMPLETE capsule is published at %s — the operation may still be active and block the workspace until closed with `ebb recover %s --cancel` (safe: the export owns no removal authority)", aerr, res.OutputPath, opID)
	}
	return nil
}

// renderExportHuman renders the export report (without the passphrase
// block, which prints separately so it also appears in --json mode).
func renderExportHuman(d exportDetails, ws catalog.Workspace, dryRun bool) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	if dryRun {
		line("export dry-run for snapshot %s of workspace %q [%s]\n", d.SnapshotID, ws.Name, ws.Status)
		line("  kind %s, created %s\n", d.Kind, d.CreatedAt)
		line("  eligibility: sealed payload present, evidence readable — exportable\n")
		line("  capsule output: %s (never overwritten; a stale %s.partial must be removed explicitly)\n",
			d.OutputPath, d.OutputPath)
		line("  source payload: %s across %d preserved entries\n", HumanBytes(d.PayloadLogicalBytes), d.PreservedEntries)
		line("  capsule size: unknown before the copy (the backend re-encrypts; roughly the encrypted size of the payload)\n")
		line("  nothing was created\n")
		return b.String()
	}
	line("exported snapshot %s of workspace %q [%s] to %s\n", d.SnapshotID, ws.Name, ws.Status, d.OutputPath)
	line("  capsule: %s (source payload: %s across %d preserved entries)\n",
		HumanBytes(d.CapsuleBytes), HumanBytes(d.PayloadLogicalBytes), d.PreservedEntries)
	line("  destination repository %s\n    payload %s\n    seal %s (new destination seal, F43)\n",
		d.DestinationRepoID, d.DestinationPayloadID, d.DestinationSealID)
	line("  checks: %s\n", strings.Join(d.Checks, ", "))
	line("  source snapshot stays pinned (export never implies forget)\n")
	return b.String()
}
