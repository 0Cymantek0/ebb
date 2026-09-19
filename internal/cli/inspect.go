// cmdInspect implements `ebb inspect [path-or-capsule]` (Foundation
// §5.3, §8.1, §15.3): for a workspace root, the real metadata-first
// pipeline through Deps — identity, volume, Git topology,
// tracked-files evidence, no-digest scan, policy resolution and a plan
// preview — assembled into an InspectReport. When the positional names
// an existing REGULAR FILE (a workspace root is a directory), the
// command switches to capsule mode (cmdInspectCapsule): bounded public
// metadata and, when EBB_CAPSULE_PASSWORD is set, full capsule-side
// verification — never a registration.
//
// Exit contract: 0 for a completed inspection (blockers are data, not
// failures; capsule mode: public and/or verified facts); 2 for
// usage/schema errors and a file that is not a usable capsule; 3 when
// the path is missing (and for infrastructure failures that prevent
// completion: unidentifiable root or incomplete scan); 7 when capsule
// verification was requested (env set) and the passphrase did not
// unlock the capsule.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"ebb/internal/capsule"
	"ebb/internal/domain"
	"ebb/internal/planner"
)

func cmdInspect(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb inspect: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
		// Capsule mode (§15.3: "ebb inspect project.ebb reads bounded
		// public metadata"): an existing regular file is a capsule
		// argument, not a workspace root.
		if fi, serr := os.Stat(root); serr == nil && fi.Mode().IsRegular() {
			return cmdInspectCapsule(root, streams, deps, *jsonOut)
		}
	}

	env := newEnvelope("inspect", "error")
	disc, err := runDiscovery(context.Background(), deps, root, streams.Err)
	if err != nil {
		var ce *cliError
		if errors.As(err, &ce) {
			env.Errors = []string{fmt.Sprintf("inspect %s: %v", root, err)}
			emit(env, *jsonOut, streams, "")
			return ce.code
		}
		env.Errors = []string{fmt.Sprintf("inspect %s: %v", root, err)}
		emit(env, *jsonOut, streams, "")
		return ExitBlocked
	}

	// Planner preview without a target: what a reclaim COULD do with
	// this state. Preview grants no removal authority (Foundation §17.1).
	plan, err := planner.PlanReclaim(planner.Input{
		Summary:  disc.Summary,
		Resolved: disc.Resolved,
		Volume:   disc.Volume,
	})
	if err != nil {
		env.Errors = []string{fmt.Sprintf("inspect %s: %v", root, err)}
		emit(env, *jsonOut, streams, "")
		return ExitUsage
	}

	report := buildInspectReport(disc, plan)
	env.Outcome = "ok"
	env.Details = report
	env.Warnings = append(env.Warnings, report.Warnings...)
	env.Warnings = append(env.Warnings, plan.Warnings...)
	for _, iss := range disc.Resolved.Issues {
		env.Warnings = append(env.Warnings, fmt.Sprintf("%s %s: %s", iss.Code, iss.Path, iss.Note))
	}

	emit(env, *jsonOut, streams, renderInspectHuman(report))
	return ExitOK
}

// ---- capsule mode (Foundation §15.3, §17.1 "path-or-capsule") --------

// capsuleInspectReport is the --json payload of a capsule inspection.
// The public half is always present; the verified half only when the
// capsule passphrase was available (EnvCapsulePassword) and the full
// verification ran.
type capsuleInspectReport struct {
	CapsulePath       string   `json:"capsule_path"`
	ContainerVersion  int      `json:"container_version"`
	BackendFamily     string   `json:"backend_family"`
	Producer          string   `json:"producer"`
	MinReaderFeatures []string `json:"min_reader_features"`
	RepoEntries       int64    `json:"repo_entries"`
	RepoBytes         int64    `json:"repo_bytes"`
	CapsuleBytes      int64    `json:"capsule_bytes"`

	// Verified half (empty when the passphrase was not supplied).
	Verified          bool     `json:"verified"`
	Workspace         string   `json:"workspace,omitempty"`            // manifest main-root prefix (D003)
	WorkspaceID       string   `json:"capsule_workspace_id,omitempty"` // the PRODUCER machine's id (reported, never adopted)
	SnapshotID        string   `json:"snapshot_id,omitempty"`
	Kind              string   `json:"kind,omitempty"`
	CreatedAt         string   `json:"created_at,omitempty"`
	ManifestDigest    string   `json:"manifest_digest,omitempty"`
	InventoryDigest   string   `json:"inventory_digest,omitempty"`
	PreservedBytes    int64    `json:"preserved_bytes,omitempty"`
	PreservedEntries  int64    `json:"preserved_entries,omitempty"`
	VerificationScope []string `json:"verification,omitempty"`
}

// cmdInspectCapsule is `ebb inspect <capsule-file>`: bounded public
// metadata — container version, backend family, producer, declared
// repository totals, capsule size, minimum reader features — with NO
// unlock. When EBB_CAPSULE_PASSWORD is set, the capsule is ADDITIONALLY
// verified end to end by driving capsule.Import with a Known gate that
// returns (true, nil) UNCONDITIONALLY: the transport then performs
// every capsule-side verification step (container, headroom,
// extraction, unlock, classification, seal cross-checks, digest
// re-derivation) and returns AlreadyKnown BEFORE any
// destination-vault mutation — so full verification runs and NOTHING
// registers. The staging destination is a private temp directory (the
// transport needs a volume for its extraction); the
// required-but-pre-gate-unused DestRepoID/DestPassfile strings are
// never read on this path (see ImportParams.Known's contract in
// internal/capsule/import.go).
//
// inspect NEVER prompts for the capsule passphrase (a missing env var
// simply stays public-only with a hint), NEVER registers, and NEVER
// mutates a vault.
//
// Exit contract: 0 public facts (and, with the env set, verified
// facts); 2 the file is not a usable capsule; 3 verification blocked
// before unlock (e.g. headroom in the staging directory); 7 the
// passphrase did not unlock the capsule (env was set).
func cmdInspectCapsule(path string, streams Streams, deps Deps, jsonOut bool) int {
	env := newEnvelope("inspect", "error")
	info, err := capsule.ReadPublicInfo(path)
	if err != nil {
		return emitFailure(env, jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("inspect %s: %s", path, codedWithSafeAction(err)))
	}
	rep := capsuleInspectReport{
		CapsulePath:       path,
		ContainerVersion:  info.ContainerVersion,
		BackendFamily:     info.BackendFamily,
		Producer:          info.Producer,
		MinReaderFeatures: info.MinReaderFeatures,
		RepoEntries:       info.RepoEntries,
		RepoBytes:         info.RepoBytes,
		CapsuleBytes:      info.CapsuleBytes,
	}

	if pw := os.Getenv(EnvCapsulePassword); pw != "" {
		// The store seam only — the catalog is opened by the session but
		// never written on this path.
		sess, serr := openSession(deps)
		if serr != nil {
			return emitFailure(env, jsonOut, streams, classifyExitCode(serr), serr.Error())
		}
		defer sess.close()
		capStore, ok := sess.store.(capsule.Store)
		if !ok {
			return emitFailure(env, jsonOut, streams, ExitUsage, fmt.Sprintf(
				"inspect %s: the snapshot store does not support capsule verification %v", path, ErrNotIntegrated))
		}
		stage, derr := os.MkdirTemp("", "ebb-inspect-")
		if derr != nil {
			return emitFailure(env, jsonOut, streams, ExitBlocked,
				fmt.Sprintf("inspect %s: staging directory for capsule verification: %v", path, derr))
		}
		defer os.RemoveAll(stage)
		ctx, stop := commandContext(deps)
		defer stop()

		// The §15.3 inspect trick (see the function comment): Known →
		// (true, nil) makes the transport run its FULL verification and
		// stop at the gate — nothing is copied, sealed or registered.
		res, ierr := capsule.Import(ctx, capsule.ImportParams{
			Store:       capStore,
			CapsulePath: path,
			Passphrase:  pw,
			// Pre-gate-unused obligations of the params contract; the
			// temp staging dir is the only filesystem footprint.
			DestRepoDir:  stage,
			DestPassfile: "inspect-not-used",
			DestRepoID:   "inspect-not-used",
			OperationID:  domain.OperationID(domain.NewID()),
			EbbVersion:   Version,
			Known:        func(string, string) (bool, error) { return true, nil },
		})
		if ierr != nil {
			return emitFailure(env, jsonOut, streams, classifyExitCode(ierr),
				fmt.Sprintf("inspect %s: capsule verification: %s", path, codedWithSafeAction(ierr)))
		}
		if !res.AlreadyKnown {
			// Cannot happen with the unconditional gate; guard the
			// invariant honestly rather than assume it.
			return emitFailure(env, jsonOut, streams, ExitCaptureVerify,
				fmt.Sprintf("inspect %s: capsule verification registered something (invariant broken); inspect the vault", path))
		}
		rep.Verified = true
		rep.Workspace = res.WorkspaceName
		rep.WorkspaceID = string(res.WorkspaceID)
		rep.SnapshotID = string(res.LogicalSnapshotID)
		rep.Kind = res.Kind
		rep.CreatedAt = res.CreatedAt
		rep.ManifestDigest = res.ManifestDigest
		rep.InventoryDigest = res.InventoryDigest
		rep.PreservedBytes = res.PreservedBytes
		rep.PreservedEntries = res.PreservedEntries
		rep.VerificationScope = res.Checks
	}

	env.Outcome = "ok"
	env.Details = rep
	if rep.Verified {
		env.Conditions = []string{"capsule-public-metadata", "capsule-verified", "nothing-registered"}
	} else {
		env.Conditions = []string{"capsule-public-metadata"}
	}
	emit(env, jsonOut, streams, renderCapsuleInspectHuman(rep))
	return ExitOK
}

// renderCapsuleInspectHuman renders the capsule inspection report.
func renderCapsuleInspectHuman(r capsuleInspectReport) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("inspect capsule %s\n", r.CapsulePath)
	line("  container version %d, backend %s, producer %s\n",
		r.ContainerVersion, r.BackendFamily, r.Producer)
	line("  reader features: %s\n", strings.Join(r.MinReaderFeatures, ", "))
	line("  declared repository: %s across %d entries; capsule file %s\n",
		HumanBytes(r.RepoBytes), r.RepoEntries, HumanBytes(r.CapsuleBytes))
	if r.Verified {
		line("  verified (unlock + digest re-derivation from the capsule's own bytes):\n")
		line("    snapshot %s of workspace %q [%s], created %s\n",
			r.SnapshotID, r.Workspace, r.Kind, r.CreatedAt)
		line("    preserved %s across %d entries; digests manifest %s / inventory %s\n",
			HumanBytes(r.PreservedBytes), r.PreservedEntries, r.ManifestDigest, r.InventoryDigest)
		line("    checks: %s\n", strings.Join(r.VerificationScope, ", "))
		line("  nothing was registered (registration is `ebb import`'s job)\n")
	} else {
		line("  public metadata only — full verification (unlock + digest re-derivation) runs at `ebb import`;\n")
		line("  set %s to verify here without registering anything\n", EnvCapsulePassword)
	}
	return b.String()
}
