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

	"ebb/internal/domain"
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
// adapter, metadata-first inventory scanner); the CLI layer itself
// never touches the filesystem for scanning.
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
// and Errors are always present as arrays, never null.
type Envelope struct {
	OperationID string   `json:"operation_id,omitempty"`
	Command     string   `json:"command"`
	Outcome     string   `json:"outcome"`
	Details     any      `json:"details,omitempty"`
	Warnings    []string `json:"warnings"`
	Errors      []string `json:"errors"`
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
	case "inspect":
		return cmdInspect(args[1:], streams, deps)
	case "plan":
		return cmdPlan(args[1:], streams, deps)
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

// usage prints the command summary (to stderr; it is human output).
func usage(w io.Writer) {
	fmt.Fprint(w, `usage: ebb <command> [flags] [path]

commands:
  version            print ebb version, restic conformance target and go version
  inspect <path>     explain scope, costs and blockers without running project code
  plan <path>        compute a reclaim plan (preview only; grants no removal authority)
  doctor             report supported capabilities and configuration problems

inspect/plan flags:
  --json                    emit the machine result envelope on stdout

plan flags:
  --from-inventory <file>   load a saved inventory JSON instead of scanning
  --target <bytes>          space goal, e.g. 25GiB (default: release as much as safely possible)
`)
}
