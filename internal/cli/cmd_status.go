// cmd_status.go implements `ebb status` (Foundation §17.1, superseded
// Wave 3): status is now an ALIAS for `ebb stats` — the Developer Space
// Economy dashboard replaced the old catalog view as the at-a-glance
// surface. The delegate is total: same flags, same output, same exit
// codes as `ebb stats` (the invocation is still RECORDED under its own
// "status" verb by the dispatch wrapper, so the dashboard's top-verbs
// list keeps showing what the user actually typed).
//
// The old dry output (workspaces/snapshots/operations listing) was a
// catalog view; `ebb doctor` and `ebb recover` carry the operational
// inspection duties, and the machine surface for workspace rows is the
// catalog itself.

package cli

// cmdStatus delegates to the stats command (alias).
func cmdStatus(args []string, streams Streams, deps Deps) int {
	return cmdStats(args, streams, deps)
}
