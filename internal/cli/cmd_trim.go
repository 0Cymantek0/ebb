// cmdTrim implements `ebb trim [path] --groups a,b` (Foundation §17.3):
// remove explicitly approved generated groups from a LIVE workspace,
// leaving retained project files in place. The v1 approval is the
// interactive grouped confirmation (or --yes for an already-decided
// invocation): it lists each group's outputs and the recreate command
// derived from the policy (the policy file is the recorded replaceable
// declaration). Wave 5 (D3) closes the loop that comment used to call
// "future work": the recorded decision is persisted as a REAL approval
// in the state dir's approvalstore — the same local trust `ebb open`
// and `ebb restore` verify against — pinning the exact frozen action
// definition, the resolved tool identity and the live input digests.
// The recorded decision also remains the lifecycle ApprovalReady
// callback.
//
// §17.3 requires the same stopped-writer discipline park uses ("an
// active process using that group requires the same stopped-writer
// discipline"), so trim carries the §17.2 flag as a passthrough:
// --assert-writers-stopped records "flag:--assert-writers-stopped" as
// the trim manifest's consistency source when supplied; without it the
// manifest honestly records best-effort-live. --yes NEVER supplies the
// assertion (it acknowledges the group approval only).
//
// Exit contract: 0 trimmed; 2 usage (missing --groups, groups not
// declared by the policy, bad Ebbfile); 3 blocked (group not applicable
// for removal, scan blockers inside outputs, declined confirmation, a
// declined or unauthorized carve-out (D034)); 4
// plan verification failure; 5 removal blocked mid-walk (TRIM_SEALING;
// reconcile with `ebb recover <op>`); 7 vault; 130 cancelled.

package cli

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/lifecycle"
	"github.com/0Cymantek0/ebb/internal/policy"
)

// trimDetails is the --json payload of a completed trim.
type trimDetails struct {
	Workspace        string     `json:"workspace"`
	Root             string     `json:"root"`
	SnapshotID       string     `json:"snapshot_id"`
	Groups           []string   `json:"groups"`
	EntriesRemoved   int        `json:"entries_removed"`
	ReclaimCommands  [][]string `json:"reclaim_commands"`
	EntriesPreserved int64      `json:"entries_preserved"`
	EntriesOmitted   int64      `json:"entries_omitted"`
	// CarvedEntries counts D034 overlay-patch entries per group
	// (aligned with Groups; omitted shapes report zero).
	CarvedEntries []int `json:"carved_entries,omitempty"`
}

func cmdTrim(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("trim", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	groupsFlag := fs.String("groups", "", "comma-separated regenerate group ids to remove (declared by the Ebbfile; required)")
	yes := fs.Bool("yes", false, "accept the removal confirmation without a prompt (NEVER supplies the writer assertion)")
	carveOutFlag := fs.Bool("carve-out", false,
		"authorize granular carve-out (D034): capture preserved/tracked entries inside the trimmed groups as vault overlay patches, then remove them with the bulk (headless runs need this together with --yes; interactive runs confirm separately)")
	assertStopped := fs.Bool("assert-writers-stopped", false,
		"assert all writers of the trimmed groups are stopped (Foundation §17.3 via §17.2; recorded in the trim manifest's consistency source)")
	if err := fs.Parse(reorderFlags(args, "groups")); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb trim: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}

	env := newEnvelope("trim", "error")
	if strings.TrimSpace(*groupsFlag) == "" {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			"--groups is required: the regenerate group ids to remove, e.g. --groups node-dependencies")
	}
	var groups []string
	for _, g := range strings.Split(*groupsFlag, ",") {
		g = strings.TrimSpace(g)
		if g != "" {
			groups = append(groups, g)
		}
	}

	sess, disc, probe, opts, ctx, stop, err := openCaptureCommand(deps, streams, root)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("trim %s: %v", root, err))
	}
	defer stop()
	defer sess.close()

	// ---- the policy must declare every requested group ----------------
	var unknown []string
	declared := map[string]policy.Regenerate{}
	for _, g := range disc.Policy.Regenerate {
		declared[g.ID] = g
	}
	for _, id := range groups {
		if _, ok := declared[id]; !ok {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		return emitFailure(env, *jsonOut, streams, ExitUsage, fmt.Sprintf(
			"--groups names %s, which the policy does not declare; declared regenerate groups: %s (declare them in Ebbfile.toml before trimming)",
			strings.Join(unknown, ", "), declaredGroupList(disc.Policy)))
	}

	// ---- the v1 approval: the grouped confirmation --------------------
	approved := map[string]bool{}
	if *yes {
		for _, id := range groups {
			approved[id] = true
		}
	} else if deps.StdinIsTerminal != nil && deps.StdinIsTerminal() {
		fmt.Fprint(streams.Err, trimApprovalText(disc.Root, groups, declared))
		if !confirmYes(deps, streams.Err, "") {
			return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
				"%s [trim]: the removal confirmation was declined; nothing was removed. Safe action: review the listed outputs and rerun `ebb trim --groups %s`, or run with --yes after verifying the policy",
				CodeWritersUnasserted, strings.Join(groups, ",")))
		}
		for _, id := range groups {
			approved[id] = true
		}
	} else {
		return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
			"%s [trim]: stdin is not a terminal and --yes was not given, so the removal approval cannot be recorded. Safe action: rerun with --yes after verifying the policy declares exactly these groups: %s",
			CodeWritersUnasserted, strings.Join(groups, ", ")))
	}

	opts.DoTrim = groups
	// F53 evidence parity (D034): hand lifecycle the git-index
	// observation this command already annotated, so its authoritative
	// plan sees the same cancellers the offers below were derived from.
	opts.GitTrackedPaths = gitTrackedPathsOf(disc.Entries)
	// ---- D034 carve-out consent (no silent carve, ever) ----------------
	// A carve means files that were preserved now get removed after
	// capture; that material change needs its own explicit yes. Consent
	// is pinned to the exact candidate paths on display (F8): the same
	// list feeds opts.CarveOutPaths, so a canceller that only shows up
	// in lifecycle's later scan refuses the trim instead of being
	// removed unseen.
	if *carveOutFlag {
		opts.CarveOut = true
		// Headless pre-authorization: pin the set to the CLI's
		// classification of the discovery scan — the displayed-
		// equivalent candidate list the interactive confirmation would
		// have rendered.
		opts.CarveOutPaths = carveOfferPaths(eligibleCarveOffers(disc.Resolved, groups))
	} else if offers := eligibleCarveOffers(disc.Resolved, groups); len(offers) > 0 {
		ids := carveOfferIDs(offers)
		if deps.StdinIsTerminal != nil && deps.StdinIsTerminal() {
			fmt.Fprint(streams.Err, carveApprovalText(disc.Root, offers))
			if !confirmYes(deps, streams.Err, "") {
				return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
					"%s [trim]: the carve-out confirmation for group(s) %s was declined; nothing was removed. Safe action: rerun `ebb trim --groups %s` and answer the carve confirmation, or add --carve-out to pre-authorize it",
					CodeApprovalDeclined, strings.Join(ids, ","), strings.Join(groups, ",")))
			}
			opts.CarveOut = true
			opts.CarveOutPaths = carveOfferPaths(offers)
		} else {
			return emitFailure(env, *jsonOut, streams, ExitBlocked, fmt.Sprintf(
				"%s [trim]: group(s) %s are cancelled by preserved entries inside their outputs; a carve-out (capture to vault, then remove) needs explicit authorization that stdin cannot give. Safe action: rerun with --yes --carve-out after reviewing the entries, or run in a terminal and confirm the carve prompt",
				CodeApprovalRequired, strings.Join(ids, ",")))
		}
	}
	// §17.2/§17.3 writer-assertion passthrough: recorded truthfully in
	// the trim manifest's consistency source when the explicit flag is
	// supplied; never sourced from --yes (group approval is not a writer
	// assertion), and omitted (best-effort-live) otherwise.
	if *assertStopped {
		opts.WriterAssertion = assertionFlagSource
	}
	// ApprovalReady is the recorded decision: the confirmed group set.
	// A group outside it is refused (defense in depth — lifecycle also
	// validates the policy and the resolved applicability).
	opts.ApprovalReady = func(groupID string) error {
		if approved[groupID] {
			return nil
		}
		return fmt.Errorf("group %s was not part of the confirmed removal set", groupID)
	}

	// ---- wave-5 (D3): record the REAL approval behind the consent ------
	// The typed confirmation above is the consent act; here it is
	// persisted as local trust in the SAME approvalstore `ebb open` and
	// `ebb restore` consult: the exact frozen definition of the group
	// (what will run at restore), the resolved tool identity and the
	// live input digests are pinned. Nothing approval-related is frozen
	// into the manifest — approvals are local, non-transferable trust
	// (Foundation §7.3). Resolving the tool here also fails the trim
	// honestly when the recorded recipe could never run on this host.
	approvedBy := "flag:--yes"
	if !*yes {
		approvedBy = "trim:interactive-confirm"
	}
	if err := recordTrimApprovals(sess, disc, groups, approvedBy); err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("trim %s: %s", disc.Root, codedWithSafeAction(err)))
	}

	coord, err := sess.newLifecycle(probe)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err),
			fmt.Sprintf("trim %s: %v", disc.Root, err))
	}

	var res lifecycle.TrimResult
	cErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		var rErr error
		res, rErr = coord.Trim(ctx, lifecycleVaultRef(repoDir, passfile), disc.Root, opts)
		return rErr
	})
	if cErr != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(cErr),
			fmt.Sprintf("trim %s: %s", disc.Root, codedWithSafeAction(cErr)))
	}

	details := trimDetails{
		Workspace: opts.WorkspaceName, Root: disc.Root,
		SnapshotID: string(res.Snapshot.SnapshotID),
		Groups:     res.Groups, EntriesRemoved: res.EntriesRemoved,
		ReclaimCommands:  res.ReclaimCommands,
		EntriesPreserved: res.Snapshot.EntriesPreserved,
		EntriesOmitted:   res.Snapshot.EntriesOmitted,
		CarvedEntries:    res.CarvedEntries,
	}
	env.Outcome = "ok"
	env.Phase = catalog.PhaseTrimDone
	env.WorkspaceID = string(sess.resolveWorkspaceID(opts.WorkspaceName, disc.Root))
	env.SnapshotID = details.SnapshotID
	env.Conditions = []string{"trim-approval:" + strings.Join(groups, ",")}
	if opts.CarveOut {
		env.Conditions = append(env.Conditions, "carve-out-consent")
	}
	if opts.WriterAssertion != "" {
		env.Conditions = append(env.Conditions, "writer-assertion:"+opts.WriterAssertion)
	}
	env.Bytes = &BytesSummary{Preserved: res.Snapshot.PreservedBytes}
	env.Details = details
	env.Warnings = append(env.Warnings, res.Snapshot.Warnings...)
	emit(env, *jsonOut, streams, renderTrimHuman(details))
	return ExitOK
}

// recordTrimApprovals persists one REAL approval per confirmed group
// (wave-5 D3): the group's exact frozen action definition (the same
// deriveGroupDef source the manifest freezes), the PATH-resolved and
// SHA-256-hashed tool identity, and the digests of the declared inputs
// that exist right now. `ebb restore` later compares its CURRENT
// resolution against exactly this record (D4): an exact match replays
// silently; any drift re-approves. Groups without a runnable recipe
// (pip, custom without command) record nothing — their restore is the
// labeled legacy path (D5). A tool that cannot be resolved fails the
// trim fail-closed: restore could never honestly re-approve it.
func recordTrimApprovals(sess *session, disc discovery, groups []string, approvedBy string) error {
	store := approvalstore.New(sess.approvalsPath())
	for _, id := range groups {
		var regen policy.Regenerate
		ok := false
		for _, r := range disc.Policy.Regenerate {
			if r.ID == id {
				regen, ok = r, true
				break
			}
		}
		if !ok {
			continue // lifecycle validates the group set independently
		}
		def, runnable, err := deriveGroupDef(regen)
		if err != nil {
			return err
		}
		if !runnable {
			continue // hint-only group: no executable contract to approve
		}
		tool, terr := actions.ResolveTool(def.Argv[0])
		if terr != nil {
			return blockedError(fmt.Errorf(
				"%s: trim group %s records recipe %q, whose tool cannot be resolved on this host, so no honest approval can be recorded: %v. Safe action: install the recipe's toolchain (restore needs it to re-create the group), then rerun `ebb trim`",
				CodeApprovalRequired, id, strings.Join(def.Argv, " "), terr))
		}
		digests := make(map[string]string, len(def.Inputs))
		for _, rel := range def.Inputs {
			p := filepath.Join(disc.Root, filepath.FromSlash(rel))
			d, derr := actions.DigestFile(p)
			if derr != nil {
				// An input absent right now is simply not covered by the
				// approval (the manifest records it missing too); an
				// UNREADABLE input fails the trim fail-closed.
				if _, serr := os.Stat(p); serr != nil && !errors.Is(serr, fs.ErrNotExist) {
					return blockedError(fmt.Errorf(
						"%s: trim group %s input %s cannot be read for the approval record: %v",
						CodeApprovalRequired, id, rel, serr))
				}
				continue
			}
			digests[rel] = d
		}
		if _, aerr := store.Approve(def, tool, digests, approvedBy); aerr != nil {
			return blockedError(fmt.Errorf("recording the %s approval for trim group %s: %w", approvedBy, id, aerr))
		}
	}
	return nil
}

// trimApprovalText builds the grouped-removal confirmation shared by
// `ebb trim` and `ebb reclaim`'s trim stages (§17.3/§17.4: each group's
// outputs and the policy-derived recreate command, then the typed
// confirmation).
func trimApprovalText(root string, groups []string, declared map[string]policy.Regenerate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The following generated groups will be REMOVED from %s\n", root)
	fmt.Fprintf(&b, "(a removal plan is captured and sealed first; recreate commands are recorded):\n")
	for _, id := range groups {
		g := declared[id]
		cmdLine := strings.Join(reclaimCommandForDisplay(g), " ")
		if cmdLine == "" {
			cmdLine = "(no recreate command declared for adapter " + string(g.Adapter) + ")"
		}
		fmt.Fprintf(&b, "  - %s [%s] outputs: %s\n", id, g.Adapter, strings.Join(g.Outputs, ", "))
		fmt.Fprintf(&b, "      recreate: %s\n", cmdLine)
	}
	fmt.Fprint(&b, "Remove these groups? type 'yes': ")
	return b.String()
}

// declaredGroupList renders the policy's regenerate group ids ("" when
// none).
func declaredGroupList(p policy.Policy) string {
	if len(p.Regenerate) == 0 {
		return "(none — the Ebbfile declares no regenerate groups)"
	}
	ids := make([]string, 0, len(p.Regenerate))
	for _, g := range p.Regenerate {
		ids = append(ids, g.ID)
	}
	return strings.Join(ids, ", ")
}

// ---- D034 carve-out approval surface (shared by trim and reclaim) -----

// carveOffer is one cancelled group's carve-out proposal for the
// approval surface: the carve-able canceller entries plus the honest
// blocker when the group cannot be carved at all.
type carveOffer struct {
	Group      string
	Candidates []lifecycle.CarveCandidate
	Refusals   []string
	// Eligible: the group is cancelled and a carve would be accepted
	// (carve-able entries within budgets — possibly zero of them when
	// the only cancellers are directories).
	Eligible bool
	// Blocker names the refusal/budget reason when not eligible.
	Blocker string
}

// carveOfferFor derives one group's offer from the resolved policy.
// ok is false when the group is not cancelled (no carve question).
func carveOfferFor(res policy.Resolved, groupID string) (carveOffer, bool) {
	found := false
	for _, d := range res.Groups {
		if d.ID == groupID {
			found = true
			if d.Applicable || !d.Cancelled {
				return carveOffer{}, false
			}
		}
	}
	if !found {
		return carveOffer{}, false
	}
	cands, refusals := lifecycle.CarveOutCandidates(res, groupID)
	o := carveOffer{Group: groupID, Candidates: cands, Refusals: refusals}
	var total int64
	for _, c := range cands {
		total += c.Bytes
	}
	switch {
	case len(refusals) > 0:
		o.Blocker = "carve-out refused: " + strings.Join(refusals, "; ")
	case len(cands) > lifecycle.CarveOutMaxEntries:
		o.Blocker = fmt.Sprintf("carve-out exceeds the entry budget (%d > %d)", len(cands), lifecycle.CarveOutMaxEntries)
	case total > lifecycle.CarveOutMaxBytes:
		o.Blocker = fmt.Sprintf("carve-out exceeds the byte budget (%s > %s)", HumanBytes(total), HumanBytes(lifecycle.CarveOutMaxBytes))
	default:
		o.Eligible = true
	}
	return o, true
}

// eligibleCarveOffers returns the consent-worthy offers for the given
// requested groups (cancelled AND carve-able). Budget/refusal blockers
// are left to lifecycle's authoritative text.
func eligibleCarveOffers(res policy.Resolved, groups []string) []carveOffer {
	var out []carveOffer
	for _, id := range groups {
		if o, ok := carveOfferFor(res, id); ok && o.Eligible {
			out = append(out, o)
		}
	}
	return out
}

// eligibleCarveGroupIDs lists the resolved groups a carve-out offer
// exists for (cancelled AND carve-able), regardless of what the caller
// requested — reclaim uses this to add carve stages the planner's
// whole-group semantics cannot propose.
func eligibleCarveGroupIDs(res policy.Resolved) []string {
	var ids []string
	for _, d := range res.Groups {
		if o, ok := carveOfferFor(res, d.ID); ok && o.Eligible {
			ids = append(ids, o.Group)
		}
	}
	return ids
}

func carveOfferIDs(offers []carveOffer) []string {
	ids := make([]string, 0, len(offers))
	for _, o := range offers {
		ids = append(ids, o.Group)
	}
	return ids
}

// carveOfferPaths renders the approved carve-path set (F8) from the
// offers the consent surface displayed — or, headless, from the same
// classification of the discovery scan the confirmation would have
// displayed. Lifecycle carves ONLY these root-relative slash paths;
// anything else its own later scan classifies as a canceller refuses
// the group as consent drift.
func carveOfferPaths(offers []carveOffer) []string {
	var out []string
	for _, o := range offers {
		for _, c := range o.Candidates {
			out = append(out, c.Path)
		}
	}
	return out
}

// gitTrackedPathsOf extracts the git:tracked paths from the discovery
// entries (the CLI annotated exactly these tokens before resolving);
// lifecycle re-applies them to its own scan so both sides classify the
// same F53 cancellers.
func gitTrackedPathsOf(entries []domain.Entry) []string {
	var out []string
	for _, e := range entries {
		for _, ev := range e.Evidence {
			if ev == "git:tracked" {
				out = append(out, e.Path)
				break
			}
		}
	}
	return out
}

// carveApprovalText renders the typed carve-out confirmation: every
// carved path with its size and the honest "captured to vault, then
// removed" treatment (a carve removes files that were preserved — the
// material change being confirmed).
func carveApprovalText(root string, offers []carveOffer) string {
	var b strings.Builder
	var totalN int
	var totalBytes int64
	for _, o := range offers {
		totalN += len(o.Candidates)
		for _, c := range o.Candidates {
			totalBytes += c.Bytes
		}
	}
	fmt.Fprintf(&b, "Carve-out (D034): the group(s) below are cancelled by preserved entries inside their outputs.\n")
	fmt.Fprintf(&b, "Each listed entry is captured to the vault as an overlay patch, then REMOVED with the group's bulk:\n")
	for _, o := range offers {
		fmt.Fprintf(&b, "  group %s (%d file(s)/link(s)):\n", o.Group, len(o.Candidates))
		for _, c := range o.Candidates {
			fmt.Fprintf(&b, "    - %s (%s) [captured to vault, then removed]\n", c.Path, HumanBytes(c.Bytes))
		}
		if len(o.Candidates) == 0 {
			fmt.Fprintf(&b, "    (no file content to carve; only the cancelling directories, which the recreate recipe rebuilds)\n")
		}
	}
	fmt.Fprintf(&b, "carve out %d file(s) (%s) from group(s) %s under %s and remove them after capture? type 'yes': ",
		totalN, HumanBytes(totalBytes), strings.Join(carveOfferIDs(offers), ","), root)
	return b.String()
}

// renderTrimHuman renders the trim completion report (§17.3: groups
// removed + commands required to recreate them; D034 carve reporting).
func renderTrimHuman(d trimDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("trimmed workspace %q\n", d.Workspace)
	for i, g := range d.Groups {
		cmdLine := "(no recreate command recorded)"
		if i < len(d.ReclaimCommands) && len(d.ReclaimCommands[i]) > 0 {
			cmdLine = strings.Join(d.ReclaimCommands[i], " ")
		}
		line("  removed group %s; recreate with: %s\n", g, cmdLine)
		if i < len(d.CarvedEntries) && d.CarvedEntries[i] > 0 {
			line("    carved %d preserved file(s)/link(s) to the vault overlay (D034); restore reapplies them after the recreate recipe\n", d.CarvedEntries[i])
		}
	}
	line("  entries removed: %d\n", d.EntriesRemoved)
	line("  removal plan retained: snapshot %s (pinned)\n", d.SnapshotID)
	line("  workspace root stays live: %s\n", d.Root)
	return b.String()
}
