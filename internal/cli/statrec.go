// statrec.go is the Wave 3 stats-event recording layer: ONE
// catalog.StatEvent appended per dispatched CLI verb at command
// completion, success or failure. The event is telemetry, never a
// safety input; a failure to record it must never fail the user's
// command (a warning on the human stream, silence in --json mode).
//
// Mechanics: Main wraps every verb dispatch in recordDispatch. The
// recorder learns the command's §17.2 envelope through emit() — the
// single point every command's terminal result already flows through —
// via a package-level sink that nested in-process invocations (analyse
// batch children run cmdReclaim in-process) swap and restore, so each
// dispatch observes exactly its own envelope. Bytes are taken from the
// envelope's own accounting (the numbers the command already reported),
// per-verb:
//
//	trim              bytes_out = Preserved   (the removal-plan snapshot
//	                                          captures exactly the removed
//	                                          groups' logical bytes)
//	reclaim/park/gc   bytes_out = FreedObserved, else FreedEstimated
//	delete            bytes_out = FreedObserved, else FreedEstimated,
//	                                          else Preserved (released
//	                                          retained material)
//	freeze            bytes_out = Preserved (the frozen image),
//	                  bytes_in  = Restored (the --restore path)
//	open/restore      bytes_in  = Restored
//	every other verb  command-only (no bytes)
//
// Dry runs (outcome/conditions marking dry-run) record no bytes: a
// preview reclaimed nothing.

package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"ebb/internal/catalog"
)

// envelopeSink receives the envelope of each emit() call made by the
// dispatch currently being recorded. The CLI is single-threaded per
// invocation; nested in-process commands swap the sink for their own
// recorder and restore the previous one on exit.
var envelopeSink func(Envelope)

// recordDispatch runs one dispatched verb under the stats recorder.
func recordDispatch(deps Deps, streams Streams, command string, args []string, fn func() int) int {
	return recordDispatchDetail(deps, streams, command, args, nil, fn)
}

// recordDispatchDetail is recordDispatch with extra detail keys minted
// by the caller (analyse's nested reclaim executions mark {"stale":true}
// so Compute can credit ZombieBytesExorcised).
func recordDispatchDetail(deps Deps, streams Streams, command string, args []string, extra map[string]any, fn func() int) int {
	rec := dispatchRecorder{
		deps:      deps,
		streams:   streams,
		command:   command,
		workspace: workspaceLabel(firstPositional(command, args)),
		jsonOut:   hasJSONFlag(args),
		extra:     extra,
	}
	prev := envelopeSink
	envelopeSink = rec.observe
	defer func() { envelopeSink = prev }()
	code := fn()
	rec.finish(code)
	return code
}

// dispatchRecorder accumulates one invocation's stats event.
type dispatchRecorder struct {
	deps      Deps
	streams   Streams
	command   string
	workspace string
	jsonOut   bool
	extra     map[string]any
	env       *Envelope
}

// observe captures the last envelope the wrapped command emitted.
func (r *dispatchRecorder) observe(env Envelope) {
	cp := env
	r.env = &cp
}

// finish appends the stats event. A nil RecordStatEvent seam records
// nothing (unit-test dependency sets); a recording error warns on the
// human stream only.
func (r *dispatchRecorder) finish(code int) {
	if r.deps.RecordStatEvent == nil {
		return
	}
	detail := make(map[string]any, len(r.extra)+1)
	for k, v := range r.extra {
		detail[k] = v
	}
	// ExitOK is success; ExitShortfall is an honest no-gain/shortfall
	// completion (the same standard analyse's own batch ledger uses) —
	// everything else records a failed invocation. Success records no
	// outcome key (the default).
	if code != ExitOK && code != ExitShortfall {
		detail["outcome"] = "failed"
	}
	e := catalog.StatEvent{
		Command:   r.command,
		Workspace: r.workspace,
		Detail:    marshalStatDetail(detail),
	}
	if r.env != nil && !dryRunEnvelope(*r.env) {
		e.BytesIn, e.BytesOut = statEventBytes(r.command, r.env.Bytes)
	}
	if err := r.deps.RecordStatEvent(e); err != nil && !r.jsonOut {
		fmt.Fprintf(r.streams.Err, "ebb: warning: stats event not recorded: %v\n", err)
	}
}

// statEventBytes maps one command's §17.2 byte summary onto the stats
// event's in/out flows (see the file comment's table). A nil summary
// records no bytes.
func statEventBytes(command string, b *BytesSummary) (in, out int64) {
	if b == nil {
		return 0, 0
	}
	freed := func() int64 {
		if b.FreedObserved > 0 {
			return b.FreedObserved
		}
		if b.FreedEstimated > 0 {
			return b.FreedEstimated
		}
		return 0
	}
	switch command {
	case "open", "restore":
		return b.Restored, 0
	case "freeze":
		return b.Restored, b.Preserved
	case "park", "reclaim", "gc":
		return 0, freed()
	case "trim":
		return 0, b.Preserved
	case "delete":
		if n := freed(); n > 0 {
			return 0, n
		}
		return 0, b.Preserved // released retained material
	}
	return 0, 0
}

// dryRunEnvelope reports whether the envelope marks a preview (no
// effects happened; bytes, if present, are estimates for a plan).
func dryRunEnvelope(env Envelope) bool {
	if env.Outcome == "dry-run" {
		return true
	}
	for _, c := range env.Conditions {
		if strings.Contains(c, "dry-run") {
			return true
		}
	}
	return false
}

// verbValueFlags lists each verb's value-taking flags (the same sets
// the commands hand reorderFlags) so the recorder's positional-label
// heuristic can tell a flag's VALUE from a positional argument.
var verbValueFlags = map[string][]string{
	"plan":    {"from-inventory", "target"},
	"trim":    {"groups"},
	"reclaim": {"target"},
	"open":    {"to"},
	"restore": {"strategy"},
	"export":  {"output"},
	"import":  {"vault"},
	"stats":   {"out"},
	"status":  {"out"},
}

// firstPositional returns the verb's first positional token (heuristic
// workspace label source: for path-taking verbs it is the root, whose
// base name is the workspace label; for open/delete it is the user's
// name-or-id reference). Flags and their VALUES are skipped using the
// verb's own value-flag table, mirroring the command's reorderFlags
// logic.
func firstPositional(verb string, args []string) string {
	takesValue := func(tok string) bool {
		if strings.IndexByte(tok, '=') >= 0 {
			return false // --flag=value is self-contained
		}
		for _, vf := range verbValueFlags[verb] {
			if tok == "--"+vf || tok == "-"+vf {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			if takesValue(a) {
				i++
			}
			continue
		}
		return a
	}
	return ""
}

// hasJSONFlag reports whether the invocation asked for machine output
// (recording warnings are suppressed there).
func hasJSONFlag(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "-json" || strings.HasPrefix(a, "--json=") {
			return true
		}
	}
	return false
}

// marshalStatDetail renders a detail map as a compact JSON object (""
// for nothing to record).
func marshalStatDetail(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	buf, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(buf)
}
