// cmdTrim implements `ebb trim [path] --groups a,b` (Foundation §17.3):
// remove explicitly approved generated groups from a LIVE workspace,
// leaving retained project files in place. The v1 approval is the
// interactive grouped confirmation (or --yes for an already-decided
// invocation): it lists each group's outputs and the recreate command
// derived from the policy (the policy file is the recorded replaceable
// declaration; approvalstore coupling is future work for rebuild
// actions). The recorded decision becomes the lifecycle
// ApprovalReady callback.
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
// for removal, scan blockers inside outputs, declined confirmation); 4
// plan verification failure; 5 removal blocked mid-walk (TRIM_SEALING;
// reconcile with `ebb recover <op>`); 7 vault; 130 cancelled.

package cli

import (
	"flag"
	"fmt"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/lifecycle"
	"ebb/internal/policy"
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
}

func cmdTrim(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("trim", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	groupsFlag := fs.String("groups", "", "comma-separated regenerate group ids to remove (declared by the Ebbfile; required)")
	yes := fs.Bool("yes", false, "accept the removal confirmation without a prompt (NEVER supplies the writer assertion)")
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
	}
	env.Outcome = "ok"
	env.Phase = catalog.PhaseTrimDone
	env.WorkspaceID = string(sess.resolveWorkspaceID(opts.WorkspaceName, disc.Root))
	env.SnapshotID = details.SnapshotID
	env.Conditions = []string{"trim-approval:" + strings.Join(groups, ",")}
	if opts.WriterAssertion != "" {
		env.Conditions = append(env.Conditions, "writer-assertion:"+opts.WriterAssertion)
	}
	env.Bytes = &BytesSummary{Preserved: res.Snapshot.PreservedBytes}
	env.Details = details
	env.Warnings = append(env.Warnings, res.Snapshot.Warnings...)
	emit(env, *jsonOut, streams, renderTrimHuman(details))
	return ExitOK
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

// renderTrimHuman renders the trim completion report (§17.3: groups
// removed + commands required to recreate them).
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
	}
	line("  entries removed: %d\n", d.EntriesRemoved)
	line("  removal plan retained: snapshot %s (pinned)\n", d.SnapshotID)
	line("  workspace root stays live: %s\n", d.Root)
	return b.String()
}
