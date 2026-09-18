// Package cli implements Ebb's stdlib-flag subcommand dispatch, exit
// codes and the human/JSON presentation contract (Foundation §17).
//
// Presentation rules: human-readable output goes to stderr; with --json
// a single envelope object goes to stdout and human output is
// suppressed. Every controlled exit emits exactly one terminal result.
//
// Testability: Main takes explicit args, writers and a Deps value of
// function-typed seams, so tests drive the dispatch matrix without
// processes or filesystem mutation beyond their own fixtures.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"ebb/internal/adapters/ecosystem"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/restore"
)

// Exit codes are Ebb's public process contract (Foundation §17.5).
const (
	ExitOK            = 0   // requested outcome completed
	ExitUsage         = 2   // invalid arguments, schema or unsupported command feature
	ExitBlocked       = 3   // blocked before mutation by policy/capability/trust/stopped-writers
	ExitCaptureVerify = 4   // capture or integrity verification failed
	ExitInterrupted   = 5   // interrupted/partial destructive operation
	ExitRebuildFailed = 6   // preserved files recovered; reconstruction failed/blocked
	ExitVault         = 7   // vault/unlock/provider unavailable
	ExitShortfall     = 8   // no useful gain or reclaim target shortfall
	ExitCancelled     = 130 // controlled user cancellation
)

// Version is the Ebb build version reported by `ebb version`.
const Version = "0.1.0-dev"

// ResticTarget is the backend version this build is conformant with
// (D002/D003; probed against restic 0.19.1).
const ResticTarget = "0.19.1"

// Deps carries the integration seams. RealDeps wires the production
// implementations (platform probe, hardened git observer, tracked-files
// adapter, metadata-first inventory scanner, restic store, lifecycle and
// restore coordinators, catalog/registry openers over the state dir, and
// the terminal/signal environment); the CLI layer itself never touches
// the filesystem for scanning or business logic.
type Deps struct {
	// NewProbe returns the native platform probe used for root
	// identity, volume usage and per-entry facts.
	NewProbe func() domain.PlatformProbe
	// ObserveGit produces the Git topology observation for a root
	// (diagnostics riding alongside preserved bytes; Foundation §9.1).
	ObserveGit func(ctx context.Context, root string) (domain.GitObservation, error)
	// GitTracked returns the set of Git-tracked root-relative paths
	// (F53 evidence source).
	GitTracked func(ctx context.Context, root string) (map[string]bool, error)
	// ScanInventory inventories a workspace root without running
	// project code (Foundation §8.1); the real implementation scans
	// metadata-first (Hash=false).
	ScanInventory func(ctx context.Context, probe domain.PlatformProbe, root string) (domain.InventorySummary, []domain.Entry, error)

	// ---- durable-state / lifecycle seams (Wave E) ----

	// StateDir returns Ebb's per-user state directory, creating it when
	// absent (production: vault.EnsureConfigDir — os.UserConfigDir()/ebb;
	// the catalog and vaults.json live there).
	StateDir func() (string, error)
	// OpenCatalog opens (creating if necessary) the SQLite catalog at
	// path (production: catalog.Open).
	OpenCatalog func(path string) (*catalog.Catalog, error)
	// NewStore constructs the snapshot-store backend plus its release
	// function (production: resticstore.New("restic") and its Close).
	NewStore func() (domain.SnapshotStore, func(), error)
	// NewLifecycle constructs the lifecycle coordinator (production:
	// lifecycle.New). The lifecycle.Dependencies arrive fully wired by
	// the CLI; the seam exists so tests can intercept construction
	// failures and future wrappers.
	NewLifecycle func(lifecycle.Dependencies) (*lifecycle.Coordinator, error)
	// NewRestoreOp constructs the restore opener (production:
	// restore.New).
	NewRestoreOp func(restore.Dependencies) (*restore.Opener, error)
	// DetectEcosystem runs existence-only regenerate-group detection
	// over a workspace root (production: ecosystem.Detect). Used by
	// `ebb init` for SUGGESTIONS; never writes an Ebbfile.
	DetectEcosystem func(root string) (ecosystem.Detection, error)
	// StdinIsTerminal reports whether stdin is an interactive terminal
	// (production: os.Stdin.Stat() mode check). Interactive prompts are
	// gated on it; a non-terminal stdin NEVER blocks on reading.
	StdinIsTerminal func() bool
	// ReadLine reads one line from stdin (production: bufio over
	// os.Stdin). Used by the interactive confirmations; tests inject a
	// fake reader.
	ReadLine func() (string, error)
	// NewSignalContext returns the command context plus its stop
	// function (production: signal.NotifyContext for SIGINT/SIGTERM).
	// A cancellation maps to exit 130 with the journal keeping the last
	// durable phase (Foundation §17.5).
	NewSignalContext func() (context.Context, func())
}

// ErrNotIntegrated marks seams that are not wired (a zero-value Deps);
// dispatch maps it to exit 2 ("unsupported command feature").
var ErrNotIntegrated = errNotIntegrated{}

type errNotIntegrated struct{}

func (errNotIntegrated) Error() string { return "not yet integrated (wave B)" }

// DefaultDeps returns the default dependency set of a real process: the
// production wiring of RealDeps. (Wave A's stubs are gone; a zero-value
// Deps still degrades each seam to ErrNotIntegrated.)
func DefaultDeps() Deps { return RealDeps() }

// Streams bundles the process output streams.
type Streams struct {
	Out io.Writer // JSON machine output (stdout)
	Err io.Writer // human output (stderr)
}

// Envelope is the machine result object (Foundation §17.2). Warnings
// and Errors are always present as arrays, never null. The Wave E fields
// (Phase, WorkspaceID, SnapshotID, Conditions, Bytes) carry the §17.2
// operation facts; each is omitted when the command produced no value
// for it.
type Envelope struct {
	OperationID string        `json:"operation_id,omitempty"`
	Command     string        `json:"command"`
	Phase       string        `json:"phase,omitempty"`
	WorkspaceID string        `json:"workspace_id,omitempty"`
	SnapshotID  string        `json:"snapshot_id,omitempty"`
	Outcome     string        `json:"outcome"`
	Conditions  []string      `json:"conditions,omitempty"`
	Bytes       *BytesSummary `json:"bytes,omitempty"`
	Details     any           `json:"details,omitempty"`
	Warnings    []string      `json:"warnings"`
	Errors      []string      `json:"errors"`
}

// BytesSummary carries the §17.2 byte counters, one field per meaning
// the command actually measured (omitted at zero).
type BytesSummary struct {
	Preserved      int64 `json:"preserved,omitempty"`
	Omitted        int64 `json:"omitted,omitempty"`
	Restored       int64 `json:"restored,omitempty"`
	FreedObserved  int64 `json:"freed_observed,omitempty"`
	FreedEstimated int64 `json:"freed_estimated,omitempty"`
}

// newEnvelope builds an envelope with non-nil warning/error arrays.
func newEnvelope(command, outcome string) Envelope {
	return Envelope{Command: command, Outcome: outcome, Warnings: []string{}, Errors: []string{}}
}

// emitJSON writes the envelope as one JSON object followed by a newline
// to w.
func (e Envelope) emitJSON(w io.Writer) error {
	if e.Warnings == nil {
		e.Warnings = []string{}
	}
	if e.Errors == nil {
		e.Errors = []string{}
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(data))
	return err
}

// Main dispatches one command invocation and returns the process exit
// code. It never panics on malformed input.
func Main(args []string, streams Streams, deps Deps) int {
	if streams.Out == nil || streams.Err == nil {
		return ExitUsage
	}
	if len(args) == 0 {
		usage(streams.Err)
		return ExitUsage
	}
	switch args[0] {
	case "version", "VERSION":
		return cmdVersion(args[1:], streams)
	case "init":
		return cmdInit(args[1:], streams, deps)
	case "inspect":
		return cmdInspect(args[1:], streams, deps)
	case "plan":
		return cmdPlan(args[1:], streams, deps)
	case "snapshot":
		return cmdSnapshot(args[1:], streams, deps)
	case "park":
		return cmdPark(args[1:], streams, deps)
	case "trim":
		return cmdTrim(args[1:], streams, deps)
	case "reclaim":
		return cmdReclaim(args[1:], streams, deps)
	case "open":
		return cmdOpen(args[1:], streams, deps)
	case "recover":
		return cmdRecover(args[1:], streams, deps)
	case "status":
		return cmdStatus(args[1:], streams, deps)
	case "doctor":
		return cmdDoctor(args[1:], streams)
	case "help", "-h", "--help":
		usage(streams.Err)
		return ExitOK
	default:
		fmt.Fprintf(streams.Err, "ebb: unknown command %q\n\n", args[0])
		usage(streams.Err)
		return ExitUsage
	}
}

// reorderFlags moves flag tokens (and the value of each name listed in
// valueFlags) before the positional arguments, so the stdlib flag
// package accepts the documented shapes `ebb open <name> --to <dir>`
// and `ebb trim <path> --groups a,b` (stdlib parsing stops at the first
// positional). Only the flags the command itself declares may be listed
// in valueFlags; unknown tokens keep their position and fail normally
// inside flag.Parse.
func reorderFlags(args []string, valueFlags ...string) []string {
	takesValue := func(tok string) bool {
		name := tok
		if eq := strings.IndexByte(tok, '='); eq >= 0 {
			return false // --flag=value is self-contained
		}
		for _, vf := range valueFlags {
			if name == "--"+vf || name == "-"+vf {
				return true
			}
		}
		return false
	}
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			if takesValue(a) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

// usage prints the command summary (to stderr; it is human output).
func usage(w io.Writer) {
	fmt.Fprint(w, `usage: ebb <command> [flags] [path]

commands:
  version                    print ebb version, restic conformance target and go version
  init [path]                enroll a vault and show detected recovery groups (suggestions only)
  inspect [path]             explain scope, costs and blockers without running project code
  plan [path]                compute a reclaim plan (preview only; grants no removal authority)
  snapshot [path]            capture and verify without removing workspace entries
  park [path]                capture, verify and remove the workspace (requires a writer assertion)
  trim [path] --groups a,b   remove explicitly approved generated groups from a live workspace
  reclaim [path] --target N  plan and execute the least disruptive sufficient release: trim, then park only if needed
  open <name-or-snapshot-id> [--to dir]
                             recover a parked/captured workspace (files-only in v1)
  recover <operation-id>     reconcile an interrupted operation from durable evidence
  forget <snapshot-id>       deliberately end a snapshot's recovery obligation (explicit confirmation)
  verify <snapshot-id>       refresh retained-snapshot evidence (coverage; --content adds full readback)
  status [workspace]         show local recorded state (workspaces, snapshots, operations)
  doctor                     report supported capabilities and configuration problems

common flags:
  --json                     emit the machine result envelope on stdout

plan flags:
  --from-inventory <file>    load a saved inventory JSON instead of scanning
  --target <bytes>           space goal, e.g. 25GiB (default: release as much as safely possible)

park flags:
  --assert-writers-stopped   unattended writer assertion (recorded in the operation journal)
  --yes                      accept ordinary prompts (NEVER supplies the writer assertion)

trim flags:
  --groups <ids>             comma-separated regenerate group ids declared by the policy (required)
  --yes                      accept the removal confirmation without a prompt

reclaim flags:
  --target <bytes>           space goal, e.g. 25GiB (default: release as much as safely possible)
  --dry-run                  print the staged plan without effects
  --yes                      accept the trim confirmations (NEVER answers the park escalation)
  --assert-writers-stopped   writer assertion for the park escalation (does not answer its confirmation)

open flags:
  --to <dir>                 destination directory (default: the workspace's recorded root)

recover flags:
  --resume-removal           explicitly resume a blocked/interrupted removal walk

forget flags:
  --yes                      accept the typed-id confirmation (shows the obligation being ended)
  --last-of-parked           acknowledge forgetting the ONLY snapshot of a parked workspace

verify flags:
  --content                  full per-file readback of every preserved byte (expensive; one backend call per file)
`)
}
