// web.go defines the frozen package surface of the Control Center —
// the mirror view types, the Provider seam the CLI wiring layer
// satisfies, the Options bag — and Run, the loopback-only server
// lifecycle behind `ebb stats --web` (Wave 3, task 3B).
//
// SECURITY MODEL (non-negotiable, test-pinned):
//
//   - GET-only: the server answers exactly GET (and HEAD) with data;
//     every other method gets 405 + `Allow: GET`. There are ZERO
//     mutation endpoints — nothing that writes, executes or proxies.
//     The only "action" anywhere is the frontend copying an ebb CLI
//     command to the clipboard.
//   - Bind exclusively to 127.0.0.1 on an ephemeral port.
//   - DNS-rebinding immunity: the Host header of every request must
//     name this exact listener; anything else fails closed with 403.
//     Together the loopback bind and the Host check defeat REMOTE pages
//     and rebound DNS names — and nothing else: loopback is not an
//     authentication boundary, every local account's processes can
//     reach 127.0.0.1.
//   - Local-reader authentication: every Run invocation mints an
//     unguessable 256-bit token (crypto/rand, hex) and serves the
//     entire surface under /<token>/; a request without it — including
//     bare "/" — gets 403 before it learns anything else. The token is
//     what keeps co-located processes (any account on the machine, no
//     port guess needed thanks to the port-less Host spelling) from
//     reading the catalog metadata. It is printed exactly once, as the
//     path of the serving-at URL below, and embedded in the browser
//     opener URL; it never repeats in per-request logs.
//   - Zero external references in served content (go:embed only).
//   - Hardened net/http timeouts and a bounded, clean shutdown.
//
// MERGE-SAFETY: this package deliberately does NOT import
// internal/stats or internal/domain. web.Metrics mirrors
// internal/stats.Metrics 1:1 (identical field set and JSON tags) and
// web.TreeEntryView mirrors the minimal slice of domain.TreeEntry the
// UI needs; the CLI wiring layer maps between the types. While
// internal/stats is built in a parallel worktree this package compiles
// and tests standalone.

package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Metrics mirrors internal/stats.Metrics 1:1 — identical fields and
// JSON tags — so the wiring layer maps field-for-field. If
// internal/stats changes, this mirror must change with it (the JSON
// golden test pins every tag).
type Metrics struct {
	LifetimeReclaimedBytes int64          `json:"lifetime_reclaimed_bytes"`
	LifetimeRestoredBytes  int64          `json:"lifetime_restored_bytes"`
	CurrentlyParkedBytes   int64          `json:"currently_parked_bytes"`
	ActiveWorkspaces       int            `json:"active_workspaces"`
	ParkedWorkspaces       int            `json:"parked_workspaces"`
	SpaceEfficiencyRatio   float64        `json:"space_efficiency_ratio"`
	CleanDeskStreakDays    int            `json:"clean_desk_streak_days"`
	HoardingScore          Score          `json:"hoarding_score"`
	ZombieBytesExorcised   int64          `json:"zombie_gb_exorcised"`
	EstimatedSSDWearSaved  int64          `json:"estimated_ssd_wear_saved"`
	TopCommands            []CommandCount `json:"top_commands"`
	TotalInvocations       int64          `json:"total_invocations"`
	TrackingSince          string         `json:"tracking_since"`
}

// Score is the hoarding-score grade inside Metrics.
type Score struct {
	Grade string `json:"grade"`
	Label string `json:"label"`
}

// CommandCount is one entry of the top-commands leaderboard.
type CommandCount struct {
	Command string `json:"command"`
	Count   int64  `json:"count"`
}

// Comparison is one quirky "for scale" factoid the provider derives
// from a byte count and a rotation seed (total invocations).
type Comparison struct {
	Category string `json:"category"`
	Subject  string `json:"subject"`
	Text     string `json:"text"`
}

// WorkspaceView is one row of the Workspaces table.
type WorkspaceView struct {
	Name           string `json:"name"`
	Status         string `json:"status"` // "active" | "parked"
	Root           string `json:"root"`
	Ecosystem      string `json:"ecosystem"`
	LastActivity   string `json:"last_activity"`
	ReclaimedBytes int64  `json:"reclaimed_bytes"`
	SizeBytes      int64  `json:"size_bytes"`
}

// HistoryEvent is one ledger entry of the History timeline (the
// provider returns them most-recent-first).
type HistoryEvent struct {
	TS        string `json:"ts"`
	Command   string `json:"command"`
	Workspace string `json:"workspace"`
	Outcome   string `json:"outcome"`
	BytesIn   int64  `json:"bytes_in"`
	BytesOut  int64  `json:"bytes_out"`
}

// TreeEntryView is one node of a snapshot listing — the minimal mirror
// of domain.TreeEntry the explorer needs. Kind is "file", "dir" or
// "link".
type TreeEntryView struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // "file" | "dir" | "link"
	Size int64  `json:"size"`
}

// RecommendationView is one analyse finding rendered as a card. Command
// is the copyable CLI line, already sanitized upstream (the provider is
// responsible for POSIX-safe quoting and control-character hygiene,
// mirroring internal/cli's renderCommand discipline); Shielded findings
// render without any copy action at all.
type RecommendationView struct {
	Category         string `json:"category"`
	Root             string `json:"root"`
	Reason           string `json:"reason"`
	Command          string `json:"command"`
	ReclaimableBytes int64  `json:"reclaimable_bytes"`
	Shielded         bool   `json:"shielded"`
}

// Provider is the read-only data seam the CLI wiring layer satisfies
// (mapping internal/stats + catalog state onto the mirror views). Every
// method must be side-effect free: the Control Center never mutates
// workspace state.
type Provider interface {
	Metrics() (Metrics, error)
	ComparisonForBytes(n int64, rotation uint64) Comparison
	Workspaces() ([]WorkspaceView, error)
	History(limit int) ([]HistoryEvent, error) // most-recent-first; limit<=0 → all (the server passes explicit caps)
	SnapshotTree(id string) ([]TreeEntryView, error)
	Recommendations() ([]RecommendationView, error)
}

// Options tunes one Run invocation. Out receives the single progress
// line ("serving at <tokened-url>" — the one place the per-run token is
// ever printed); Err receives request logs (method, token-stripped
// path, status — never bodies). Both may be nil.
type Options struct {
	Out, Err io.Writer
	// OpenBrowser attempts the OS opener after the listen succeeds.
	OpenBrowser bool
	// LaunchBrowser is the opener seam (tests inject it); nil uses the
	// GOOS default: windows rundll32 url.dll,FileProtocolHandler; linux
	// xdg-open; anything else a no-op. Failure is non-fatal — the URL is
	// already printed.
	LaunchBrowser func(url string) error
}

// shutdownGrace bounds the graceful-shutdown window so Run returns
// promptly after context cancellation even with a stalled connection.
const shutdownGrace = 1500 * time.Millisecond

// Run starts the read-only Control Center on 127.0.0.1 with an
// ephemeral port and a freshly minted per-run URL token, and blocks
// until ctx is cancelled, then shuts down cleanly and returns nil. The
// single progress line goes to o.Out; a failed browser launch is logged
// to o.Err and never fatal.
func Run(ctx context.Context, p Provider, o Options) error {
	if p == nil {
		return errors.New("web: nil provider")
	}
	out, errw := o.Out, o.Err
	if out == nil {
		out = io.Discard
	}
	if errw == nil {
		errw = io.Discard
	}

	// Security model (local-reader gate): 32 crypto/rand bytes,
	// hex-encoded — an unguessable 256-bit path segment every reader
	// must already know. Co-located processes that can reach 127.0.0.1
	// but never saw the printed URL get 403 on everything.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return fmt.Errorf("web: minting per-run URL token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	// Security model #2: loopback-only, ephemeral port — never a
	// wildcard bind, never a fixed port another process could pre-claim.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("web: listen on 127.0.0.1:0: %w", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	logf := func(format string, args ...any) {
		fmt.Fprintf(errw, "web: "+format+"\n", args...)
	}

	// Security model #5: hardened server on top of the GET-only,
	// Host-checked, token-gated handler.
	srv := &http.Server{
		Handler:           newServer(p, port, token, logf),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       75 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	// The one line the token ever appears in: the serving URL and the
	// opener URL both carry it as their path.
	baseURL := fmt.Sprintf("http://127.0.0.1:%d/%s/", port, token)
	fmt.Fprintf(out, "serving at %s\n", baseURL)

	if o.OpenBrowser {
		launch := o.LaunchBrowser
		if launch == nil {
			launch = openBrowser
		}
		if lerr := launch(baseURL); lerr != nil {
			fmt.Fprintf(errw, "web: opening browser failed: %v — open %s manually\n", lerr, baseURL)
		}
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if serr := srv.Shutdown(shutdownCtx); serr != nil {
		// Bounded grace exhausted: close hard rather than hang the CLI.
		_ = srv.Close()
	}
	if serr := <-serveErr; serr != nil && !errors.Is(serr, http.ErrServerClosed) {
		return fmt.Errorf("web: server: %w", serr)
	}
	return nil
}
