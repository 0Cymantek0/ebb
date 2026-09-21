// cmd_freeze implements `ebb freeze` (D040 tier 3, product plan §11.7C):
// the Freeze-to-Vault cold-storage pipeline for docker images —
// `docker save <image>` streamed directly into `restic backup --stdin`
// with in-flight SHA-256 hashing, a durable catalog row, and an
// independent readback proof before anything is reported as captured.
// `--restore` is the 1-command inverse (`restic dump | docker load`)
// with the digest verified BEFORE a single byte reaches the daemon.
//
// Destructive discipline: the daemon-side `docker rmi` runs ONLY behind
// a SECOND, separate confirmation (--remove plus --yes-removal or the
// explicit prompt) and only after a VERIFIED freeze; --yes (the freeze
// confirmation) never supplies it. --dry-run probes and reports sizes
// with zero effects.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/freezer"
	"ebb/internal/lifecycle"
	resticstore "ebb/internal/storage/restic"
	"ebb/internal/version"
)

// Freeze-flow blocker codes (§5.5 shape; local to this command family).
const (
	CodeFreezeUnconfirmed  = "EBB_E_FREEZE_UNCONFIRM"
	CodeRemovalUnconfirmed = "EBB_E_REMOVAL_UNCONFIRM"
	CodeFreezeUnknownEntry = "EBB_E_FREEZE_UNKNOWN_ENTRY"
)

// freezeDetails is the --json payload of the freeze command.
type freezeDetails struct {
	Mode         string `json:"mode"` // freeze | restore | dry-run
	ImageID      string `json:"image_id"`
	EntryID      string `json:"entry_id,omitempty"`
	Filename     string `json:"filename,omitempty"`
	SnapshotID   string `json:"snapshot_id,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Bytes        int64  `json:"bytes,omitempty"`
	SizeEstimate int64  `json:"size_estimate,omitempty"`
	Verified     bool   `json:"verified"`
	Vault        string `json:"vault,omitempty"`
	LoadOutput   string `json:"load_output,omitempty"`
	Removed      bool   `json:"daemon_image_removed,omitempty"`
	RemovedAt    string `json:"daemon_removed_at,omitempty"`
}

func cmdFreeze(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("freeze", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	dryRun := fs.Bool("dry-run", false, "show the size estimate and plan without effects")
	yes := fs.Bool("yes", false, "accept the freeze confirmation without a prompt (NEVER answers the removal confirmation)")
	restore := fs.String("restore", "", "restore a frozen image into the docker daemon (entry id or image id)")
	remove := fs.Bool("remove", false, "after a VERIFIED freeze, offer removing the image from the daemon (separate confirmation)")
	yesRemoval := fs.Bool("yes-removal", false, "accept the separate daemon-removal confirmation without a prompt (requires --remove)")
	if err := fs.Parse(reorderFlags(args, "restore")); err != nil {
		return ExitUsage
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb freeze: takes at most one image id")
		return ExitUsage
	}
	if *restore != "" && fs.NArg() != 0 {
		fmt.Fprintln(streams.Err, "ebb freeze: --restore takes the entry/image id itself, not a positional argument")
		return ExitUsage
	}
	if *restore == "" && fs.NArg() != 1 {
		fmt.Fprintln(streams.Err, "ebb freeze: exactly one image id is required (or --restore <entry-or-image-id>)")
		return ExitUsage
	}
	if *yesRemoval && !*remove {
		fmt.Fprintln(streams.Err, "ebb freeze: --yes-removal only applies together with --remove")
		return ExitUsage
	}
	if *dryRun && (*remove || *restore != "") {
		fmt.Fprintln(streams.Err, "ebb freeze: --dry-run takes no other action flags")
		return ExitUsage
	}

	env := newEnvelope("freeze", "ok")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()
	ctx, stop := commandContext(deps)
	defer stop()

	// The vault store for the freeze transport: the session store is the
	// domain.SnapshotStore (frozen interface), so the freeze path builds
	// its own adapter instance over the same binary, honoring the
	// EBB_TEST_RESTIC_BIN seam exactly like the restic conformance suites.
	store, serr := newFreezeVaultStore()
	if serr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(serr), serr.Error())
	}
	defer store.Close()
	fz, ferr := freezer.New("", store)
	if ferr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(ferr), ferr.Error())
	}

	// Connectivity gate FIRST — an unreachable daemon is a cheap honest
	// block before any prompt or vault unlock.
	if perr := fz.Probe(ctx); perr != nil {
		return emitFailure(env, *jsonOut, streams, ExitBlocked,
			fmt.Sprintf("ebb freeze: %v. Safe action: start the docker daemon (or install the docker CLI) and rerun", perr))
	}

	if *restore != "" {
		return freezeRestore(env, *jsonOut, streams, deps, sess, fz, *restore)
	}
	return freezeRun(env, *jsonOut, streams, deps, sess, fz, freezeFlags{
		imageID: fs.Arg(0), dryRun: *dryRun, yes: *yes, remove: *remove, yesRemoval: *yesRemoval,
	})
}

type freezeFlags struct {
	imageID    string
	dryRun     bool
	yes        bool
	remove     bool
	yesRemoval bool
}

// newFreezeVaultStore resolves the restic binary for the freeze
// transport (EBB_TEST_RESTIC_BIN override first; production: PATH).
func newFreezeVaultStore() (*resticstore.Store, error) {
	bin := os.Getenv("EBB_TEST_RESTIC_BIN")
	if bin == "" {
		bin = "restic"
	}
	path, lerr := exec.LookPath(bin)
	if lerr != nil {
		return nil, vaultError(fmt.Errorf("restic binary not found on PATH (freeze transport prerequisite; `ebb doctor` reports tool details)"))
	}
	return resticstore.New(path), nil
}

// freezeRun is the freeze (or dry-run) path.
func freezeRun(env Envelope, jsonOut bool, streams Streams, deps Deps, sess *session, fz *freezer.Freezer, fl freezeFlags) int {
	if verr := freezer.ValidateImageID(fl.imageID); verr != nil {
		return emitFailure(env, jsonOut, streams, ExitUsage, fmt.Sprintf("ebb freeze: %v (got %q)", verr, fl.imageID))
	}
	ctx, stop := commandContext(deps)
	defer stop()

	info, ierr := fz.Inspect(ctx, fl.imageID)
	if ierr != nil {
		var unknown *freezer.ErrImageUnknown
		if errors.As(ierr, &unknown) {
			return emitFailure(env, jsonOut, streams, ExitUsage,
				fmt.Sprintf("ebb freeze: docker does not know image %q. Safe action: check `docker images` for the exact id or tag", fl.imageID))
		}
		return emitFailure(env, jsonOut, streams, classifyExitCode(ierr), ierr.Error())
	}

	vault, verr := sess.defaultVault()
	if verr != nil {
		return emitFailure(env, jsonOut, streams, classifyExitCode(verr), verr.Error())
	}

	if fl.dryRun {
		env.Details = freezeDetails{Mode: "dry-run", ImageID: info.ID,
			SizeEstimate: info.Size, Verified: false, Vault: vault.Name}
		emit(env, jsonOut, streams, renderFreezeHuman(env.Details.(freezeDetails), nil))
		return ExitOK
	}

	// Freeze confirmation (the vault write itself). --yes is the
	// headless acceptance; a terminal gets the prompt naming the image,
	// the size and the target vault; anything else fails closed.
	if !fl.yes {
		if deps.StdinIsTerminal == nil || !deps.StdinIsTerminal() {
			return emitFailure(env, jsonOut, streams, ExitBlocked, blockerMessage(CodeFreezeUnconfirmed, info.ID,
				fmt.Sprintf("freezing image %s (%s) into vault %q needs a confirmation and none is available (stdin is not a terminal and --yes was not given)", info.ID, HumanBytes(info.Size), vault.Name),
				"rerun with --yes to freeze headlessly, or run in a terminal and confirm interactively"))
		}
		prompt := fmt.Sprintf("freeze docker image %s (%s estimate) into vault %q — the image STAYS in the daemon until a separate removal? type 'yes': ",
			info.ID, HumanBytes(info.Size), vault.Name)
		if !confirmYes(deps, streams.Err, prompt) {
			return emitFailure(env, jsonOut, streams, ExitBlocked, blockerMessage(CodeFreezeUnconfirmed, info.ID,
				"the interactive freeze confirmation was declined; nothing was streamed or recorded",
				"rerun `ebb freeze` when you have decided"))
		}
	}

	var res freezer.FreezeResult
	fErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		// Bind the durable row to a registered vault row (the same
		// derivation the lifecycle capture path uses).
		repoID, rerr := sess.store.RepoID(ctx, repoDir, passfile)
		if rerr != nil {
			return rerr
		}
		vaultID := lifecycle.VaultIDFor(repoID, repoDir)
		if rerr := sess.cat.RegisterVault(catalog.Vault{ID: vaultID, Path: repoDir, RepoID: repoID}); rerr != nil {
			return rerr
		}
		var zerr error
		res, zerr = fz.Freeze(ctx, freezer.FreezeRequest{
			ImageID: info.ID, RepoDir: repoDir, Passfile: passfile,
			VaultID: vaultID, Cat: sess.cat,
		})
		return zerr
	})
	if fErr != nil {
		// When a durable row was recorded before the failure, the
		// envelope still reports it: an unverified retained entry is
		// exactly what the user must see (exit-4 outcome).
		if res.Entry.ID != "" {
			env.Details = freezeDetails{Mode: "freeze", ImageID: res.Info.ID, EntryID: string(res.Entry.ID),
				Filename: res.Entry.Filename, SnapshotID: res.Entry.SnapshotID,
				SHA256: res.Entry.SHA256, Bytes: res.Entry.Bytes, Verified: false,
				Vault: vault.Name, SizeEstimate: res.Info.Size}
			env.Bytes = &BytesSummary{Preserved: res.Entry.Bytes}
		}
		return emitFailure(env, jsonOut, streams, classifyExitCode(fErr),
			fmt.Sprintf("ebb freeze %s: %s", info.ID, codedWithSafeAction(fErr)))
	}

	details := freezeDetails{Mode: "freeze", ImageID: res.Info.ID, EntryID: string(res.Entry.ID),
		Filename: res.Entry.Filename, SnapshotID: res.Entry.SnapshotID,
		SHA256: res.Entry.SHA256, Bytes: res.Entry.Bytes,
		Verified: res.Verified, Vault: vault.Name, SizeEstimate: res.Info.Size}

	// Daemon-side removal: a SEPARATE confirmation after a VERIFIED
	// freeze, never supplied by --yes, never in --dry-run.
	if fl.remove {
		if !res.Verified {
			env.Warnings = append(env.Warnings,
				fmt.Sprintf("freeze of %s is UNVERIFIED; the daemon image was NOT removed and --remove was ignored", info.ID))
		} else {
			ok, rerr := removalConfirmed(deps, streams, fl, res)
			if rerr != nil {
				env.Warnings = append(env.Warnings, rerr.Error())
			} else if ok {
				ctx2, stop2 := commandContext(deps)
				defer stop2()
				if merr := fz.RemoveFromDaemon(ctx2, res.Entry, sess.cat); merr != nil {
					env.Warnings = append(env.Warnings, merr.Error())
				} else {
					entry, _ := sess.cat.GetDockerImage(res.Entry.ID)
					details.Removed, details.RemovedAt = true, entry.DaemonRemovedAt
				}
			}
		}
	}

	env.Details = details
	env.Bytes = &BytesSummary{Preserved: res.Entry.Bytes}
	if !res.Verified {
		// The freeze failed its readback proof: the entry is retained
		// unverified and pinned; nothing was removed. This is the
		// capture-verify outcome (exit 4), not an ok.
		env.Outcome = outcomeForExit(ExitCaptureVerify)
		env.Errors = []string{fmt.Sprintf(
			"ebb freeze %s: the vault readback did not match the recorded digest; the entry (%s) is retained UNVERIFIED and pinned, nothing was removed from the daemon. Safe action: keep the image, inspect the vault with `ebb doctor`, and rerun the freeze",
			info.ID, res.Entry.ID)}
		emit(env, jsonOut, streams, renderFreezeHuman(details, env.Errors))
		return ExitCaptureVerify
	}
	emit(env, jsonOut, streams, renderFreezeHuman(details, nil))
	return ExitOK
}

// removalConfirmed resolves the separate daemon-removal confirmation.
// The declined/error case returns a warning line, never a silent skip.
func removalConfirmed(deps Deps, streams Streams, fl freezeFlags, res freezer.FreezeResult) (bool, error) {
	if fl.yesRemoval {
		return true, nil
	}
	if deps.StdinIsTerminal == nil || !deps.StdinIsTerminal() {
		return false, fmt.Errorf(
			"%s [%s]: removing the image from the docker daemon needs its own confirmation and none is available (stdin is not a terminal and --yes-removal was not given); the verified freeze stands, the image was NOT removed. Safe action: rerun with --remove --yes-removal, or run in a terminal",
			CodeRemovalUnconfirmed, res.Info.ID)
	}
	prompt := fmt.Sprintf("REMOVE docker image %s from the daemon? The verified vault copy (%s, %s) stays for `ebb freeze --restore %s`. type 'yes': ",
		res.Info.ID, res.Entry.ID, HumanBytes(res.Entry.Bytes), res.Entry.ID)
	if !confirmYes(deps, streams.Err, prompt) {
		return false, fmt.Errorf(
			"%s [%s]: the interactive removal confirmation was declined; the verified freeze stands, the image was NOT removed",
			CodeRemovalUnconfirmed, res.Info.ID)
	}
	return true, nil
}

// freezeRestore is the --restore path: locate the entry, verify the
// vault copy against the recorded digest, and only then stream it into
// `docker load` (the freezer enforces the verify-before-load order).
func freezeRestore(env Envelope, jsonOut bool, streams Streams, deps Deps, sess *session, fz *freezer.Freezer, idArg string) int {
	entry, warn, gerr := resolveFreezeEntry(sess, idArg)
	if gerr != nil {
		return emitFailure(env, jsonOut, streams, ExitUsage, gerr.Error())
	}
	if warn != "" {
		env.Warnings = append(env.Warnings, warn)
	}

	vault, verr := sess.defaultVault()
	if verr != nil {
		return emitFailure(env, jsonOut, streams, classifyExitCode(verr), verr.Error())
	}

	ctx, stop := commandContext(deps)
	defer stop()
	var res freezer.RestoreResult
	rErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var zerr error
		res, zerr = fz.Restore(ctx, entry, repoDir, passfile)
		return zerr
	})
	if rErr != nil {
		return emitFailure(env, jsonOut, streams, classifyExitCode(rErr),
			fmt.Sprintf("ebb freeze --restore %s: %s", idArg, codedWithSafeAction(rErr)))
	}

	env.Details = freezeDetails{Mode: "restore", ImageID: entry.ImageID, EntryID: string(entry.ID),
		Filename: entry.Filename, SnapshotID: entry.SnapshotID,
		SHA256: res.SHA256, Bytes: res.Bytes, Verified: entry.VerifiedAt != "",
		Vault: vault.Name, LoadOutput: res.LoadOutput}
	env.Bytes = &BytesSummary{Restored: res.Bytes}
	emit(env, jsonOut, streams, renderFreezeHuman(env.Details.(freezeDetails), nil))
	return ExitOK
}

// resolveFreezeEntry locates the freeze entry by entry id (32 hex) or by
// docker image id (newest VERIFIED row preferred; an unverified match is
// reported through the warning, never silently trusted).
func resolveFreezeEntry(sess *session, idArg string) (entry catalog.DockerImage, warning string, err error) {
	if id, perr := domain.ParseID(idArg); perr == nil {
		e, gerr := sess.cat.GetDockerImage(id)
		if gerr != nil {
			return catalog.DockerImage{}, "", fmt.Errorf(
				"ebb freeze --restore: no frozen-image entry %s in the catalog. Safe action: pass the docker image id to resolve by image, or re-freeze the image with `ebb freeze <image-id>`; `ebb doctor` reports the catalog's frozen-image row count (no list command exists yet)", idArg)
		}
		return e, unverifiedWarning(e), nil
	}
	rows, ferr := sess.cat.FindDockerImages(idArg)
	if ferr != nil {
		return catalog.DockerImage{}, "", ferr
	}
	if len(rows) == 0 {
		return catalog.DockerImage{}, "", fmt.Errorf(
			"%s: no frozen image %q in the catalog. Safe action: freeze it first with `ebb freeze %s`, or check the id with `docker images`",
			CodeFreezeUnknownEntry, idArg, idArg)
	}
	// Newest verified wins; else the newest row with a warning.
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].VerifiedAt != "" {
			return rows[i], "", nil
		}
	}
	newest := rows[len(rows)-1]
	return newest, unverifiedWarning(newest), nil
}

func unverifiedWarning(e catalog.DockerImage) string {
	if e.VerifiedAt != "" {
		return ""
	}
	return fmt.Sprintf("freeze entry %s (%s) is UNVERIFIED (its readback proof never completed); the restore still verifies every byte against the recorded digest before docker load", e.ID, e.ImageID)
}

// renderFreezeHuman renders the freeze/restore report.
func renderFreezeHuman(d freezeDetails, errs []string) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	switch d.Mode {
	case "dry-run":
		line("freeze (dry-run) of %s:\n", d.ImageID)
		line("  estimated stream size: %s (docker's own accounting)\n", HumanBytes(d.SizeEstimate))
		line("  target vault: %s\n", d.Vault)
		line("  effects: none (no stream, no catalog row, nothing removed)\n")
	case "restore":
		line("restored %s into the docker daemon:\n", d.ImageID)
		line("  entry %s (snapshot %s)\n", d.EntryID, d.ShortSnapshot())
		line("  verified digest %s over %s\n", d.SHA256, HumanBytes(d.Bytes))
		line("  docker load: %s\n", d.LoadOutput)
	default:
		line("froze %s into vault %s:\n", d.ImageID, d.Vault)
		line("  entry %s (snapshot %s, file %s)\n", d.EntryID, d.ShortSnapshot(), d.Filename)
		line("  digest %s over %s (estimate was %s)\n", d.SHA256, HumanBytes(d.Bytes), HumanBytes(d.SizeEstimate))
		if d.Verified {
			line("  readback verified: the vault's bytes match the recorded digest byte-for-byte\n")
		}
		if d.Removed {
			line("  daemon image REMOVED at %s (audited; restore with `ebb freeze --restore %s`)\n", d.RemovedAt, d.EntryID)
		} else {
			line("  the image STAYS in the docker daemon (removal is a separate confirmed step)\n")
		}
	}
	for _, e := range errs {
		line("  %s\n", e)
	}
	line("  tools: ebb %s, restic target %s\n", version.Version, ResticTarget)
	return b.String()
}

// ShortSnapshot renders an 8-char snapshot prefix for humans.
func (d freezeDetails) ShortSnapshot() string {
	if len(d.SnapshotID) > 8 {
		return d.SnapshotID[:8]
	}
	return d.SnapshotID
}
