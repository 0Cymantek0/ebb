// cmd_stats_web.go is the `ebb stats --web` wiring: statsWebProvider
// adapts one opened CLI session (catalog + snapshot store + vault
// machinery) onto internal/web's frozen read-only Provider seam. Every
// method is side-effect free — the control center never mutates
// workspace state, so neither may its data source.
//
// Honesty rules: fields the underlying data does not carry stay empty
// rather than invented (workspace ecosystem/last-activity are "" — the
// catalog summaries carry only name/status/size and the workspace rows
// a root path); unknown snapshot-entry kinds render as their honest
// string; recommendations reuse the dashboard's ONE bounded shallow
// analyse scan, so the terminal view and the web view can never
// disagree about what was scanned.

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/stats"
	"github.com/0Cymantek0/ebb/internal/vault"
	"github.com/0Cymantek0/ebb/internal/web"
)

// statsWebProvider serves the control center from one session. ctx is
// the command's signal context: a Ctrl+C cancels in-flight store reads
// along with the server.
type statsWebProvider struct {
	deps Deps
	sess *session
	ctx  context.Context
}

// Metrics recomputes the dashboard live per request (the journal is
// small; freshness beats caching a stale dashboard in a long-lived
// server).
func (p *statsWebProvider) Metrics() (web.Metrics, error) {
	events, err := p.sess.cat.ListStatEvents(p.ctx, 0)
	if err != nil {
		return web.Metrics{}, fmt.Errorf("reading the stats journal: %w", err)
	}
	summaries, err := p.sess.cat.ListWorkspaceSummaries()
	if err != nil {
		return web.Metrics{}, fmt.Errorf("reading workspace summaries: %w", err)
	}
	facts, _ := gatherScanFacts(p.ctx, p.deps) // scan degradation warns on the terminal stream, never blocks the view
	return webMetrics(stats.Compute(events, summaries, facts)), nil
}

// ComparisonForBytes maps the stats package's deterministic offline
// comparison onto the web mirror.
func (p *statsWebProvider) ComparisonForBytes(n int64, rotation uint64) web.Comparison {
	c := stats.PickForBytes(n, rotation)
	return web.Comparison{Category: c.Category, Subject: c.Subject, Text: c.Text}
}

// Workspaces maps the catalog's workspace summaries (name/status/park
// size) joined with the workspace rows' root paths. Ecosystem,
// last-activity and per-workspace reclaimed bytes are not recorded
// anywhere in v1 and stay honestly empty.
func (p *statsWebProvider) Workspaces() ([]web.WorkspaceView, error) {
	summaries, err := p.sess.cat.ListWorkspaceSummaries()
	if err != nil {
		return nil, fmt.Errorf("reading workspace summaries: %w", err)
	}
	roots := map[string]string{}
	if rows, lerr := p.sess.cat.ListWorkspaces(); lerr == nil {
		for _, w := range rows {
			if w.RootPath != "" {
				if _, dup := roots[w.Name]; !dup {
					roots[w.Name] = w.RootPath
				}
			}
		}
	}
	out := make([]web.WorkspaceView, 0, len(summaries))
	for _, s := range summaries {
		out = append(out, web.WorkspaceView{
			Name:      s.Name,
			Status:    webWorkspaceStatus(s.Status),
			Root:      roots[s.Name],
			SizeBytes: s.Size, // 0 = no park event recorded a size; never a fake number
		})
	}
	return out, nil
}

// History maps the stats journal, most-recent-first, with the recorded
// outcome (from the event's detail JSON) surfaced when present.
func (p *statsWebProvider) History(limit int) ([]web.HistoryEvent, error) {
	events, err := p.sess.cat.ListStatEvents(p.ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("reading the stats journal: %w", err)
	}
	out := make([]web.HistoryEvent, 0, len(events))
	for _, e := range events {
		out = append(out, web.HistoryEvent{
			TS:        e.TS,
			Command:   e.Command,
			Workspace: e.Workspace,
			Outcome:   statEventOutcome(e.Detail),
			BytesIn:   e.BytesIn,
			BytesOut:  e.BytesOut,
		})
	}
	return out, nil
}

// SnapshotTree lists one snapshot's payload tree through the hardened
// vault passfile machinery every store read uses (the password reaches
// the backend only via the ephemeral passfile; Foundation §13.1) — but
// resolved NON-interactively: a request handler must never block on
// terminal I/O, so the credential comes from env or the OS keyring
// only (wave-4 K3; withVaultPassfileNonInteractive). When no such
// source holds the secret the facet refuses honestly with the §5.5
// vault-locked wording instead of hanging the handler on a prompt the
// browser user never sees. The web server has already validated the
// id's shape server-side; here it must still resolve against the
// catalog — an id that is well-formed but unknown is an honest error,
// not empty data.
func (p *statsWebProvider) SnapshotTree(id string) ([]web.TreeEntryView, error) {
	snapID, perr := domain.ParseID(id)
	if perr != nil {
		return nil, fmt.Errorf("snapshot %s: %v", id, perr)
	}
	// domain.ParseID returns the generic ID shape; the catalog keys
	// snapshots by the named SnapshotID alias of the same 32-hex string.
	snapKey := domain.SnapshotID(snapID)
	snap, gerr := p.sess.cat.GetSnapshot(snapKey)
	if gerr != nil {
		return nil, fmt.Errorf("snapshot %s: no such snapshot in the catalog", id)
	}
	if snap.PayloadBackendID == "" {
		return nil, fmt.Errorf("snapshot %s: no payload was captured under this id", id)
	}
	var entries []domain.TreeEntry
	if verr := p.sess.withVaultPassfileNonInteractive(p.ctx, func(repoDir, passfile string) error {
		var err error
		entries, err = p.sess.store.Ls(p.ctx, repoDir, passfile, snap.PayloadBackendID)
		return err
	}); verr != nil {
		var locked *vault.NoSourceError
		if errors.As(verr, &locked) {
			// The vault-locked refusal already carries the §5.5 guidance
			// (set EBB_VAULT_PASSWORD / store the password in the OS
			// keyring) and the vault id; the facet names its own
			// unavailability rather than burying it under "listing".
			return nil, fmt.Errorf("snapshot tree unavailable: vault locked — %v", verr)
		}
		return nil, fmt.Errorf("listing snapshot %s: %v", id, verr)
	}
	out := make([]web.TreeEntryView, 0, len(entries))
	for _, e := range entries {
		out = append(out, web.TreeEntryView{
			Name: baseElement(e.Path),
			Kind: webTreeKind(e.Kind),
			Size: e.Size,
		})
	}
	return out, nil
}

// Recommendations maps the SAME bounded shallow analyse scan the
// dashboard's clutter facts use (runShallowScan — one engine shape, one
// budget) into copyable recommendation cards. No configured roots →
// an empty list (the web view shows its own empty state); an
// infrastructure failure → the error (the server reports a 500 for this
// facet — acceptable and honest). Commands are the analyse surface's
// already-sanitized POSIX-quoted copy lines; an unquotable path
// withholds the command entirely (F4), and shielded findings still
// render (with their shield) minus any copy action.
func (p *statsWebProvider) Recommendations() ([]web.RecommendationView, error) {
	rep, configured, _, err := runShallowScan(p.ctx, p.deps)
	if err != nil {
		return nil, fmt.Errorf("scanning configured roots: %w", err)
	}
	if !configured {
		return []web.RecommendationView{}, nil
	}
	out := []web.RecommendationView{}
	for _, proj := range rep.Projects {
		rec := proj.Recommendation
		if rec.Kind == "" && len(rec.Command) == 0 && rec.Reason == "" {
			continue // no recommendation for this project
		}
		view := web.RecommendationView{
			Category:         string(proj.Category),
			Root:             proj.Root,
			Reason:           rec.Reason,
			ReclaimableBytes: proj.FootprintBytes, // shallow estimate, labeled as such upstream
			Shielded:         proj.Shielded(),
		}
		if len(rec.Command) > 0 && !view.Shielded {
			if cmdLine, ok := renderCommand(rec.Command); ok {
				view.Command = cmdLine
			}
		}
		out = append(out, view)
	}
	return out, nil
}

// ---- pure mapping helpers ------------------------------------------------------

// webMetrics maps stats.Metrics onto web's 1:1 mirror field-for-field.
// web.Metrics deliberately lacks stats' additive ScanAvailable flag
// (the web UI derives its own clutter hints from recommendations), so
// the mapping is total but not bijective.
func webMetrics(m stats.Metrics) web.Metrics {
	return web.Metrics{
		LifetimeReclaimedBytes: m.LifetimeReclaimedBytes,
		LifetimeRestoredBytes:  m.LifetimeRestoredBytes,
		CurrentlyParkedBytes:   m.CurrentlyParkedBytes,
		ActiveWorkspaces:       m.ActiveWorkspaces,
		ParkedWorkspaces:       m.ParkedWorkspaces,
		SpaceEfficiencyRatio:   m.SpaceEfficiencyRatio,
		CleanDeskStreakDays:    m.CleanDeskStreakDays,
		HoardingScore:          web.Score{Grade: m.HoardingScore.Grade, Label: m.HoardingScore.Label},
		ZombieBytesExorcised:   m.ZombieBytesExorcised,
		EstimatedSSDWearSaved:  m.EstimatedSSDWearSaved,
		TopCommands:            webCommands(m.TopCommands),
		TotalInvocations:       m.TotalInvocations,
		TrackingSince:          m.TrackingSince,
	}
}

func webCommands(cmds []stats.CommandCount) []web.CommandCount {
	if cmds == nil {
		return nil
	}
	out := make([]web.CommandCount, len(cmds))
	for i, c := range cmds {
		out[i] = web.CommandCount{Command: c.Command, Count: c.Count}
	}
	return out
}

// webWorkspaceStatus maps catalog statuses onto the view vocabulary;
// anything unexpected keeps its honest lowercased string.
func webWorkspaceStatus(status string) string {
	switch status {
	case catalog.WorkspaceLive:
		return "active"
	case catalog.WorkspaceParked:
		return "parked"
	case catalog.WorkspaceUnbound:
		return "unbound"
	}
	return strings.ToLower(status)
}

// webTreeKind maps domain entry kinds onto the explorer's three-kind
// vocabulary; exotic kinds (mount points, fifos, ...) keep their honest
// string rather than being lied about as files.
func webTreeKind(k domain.EntryKind) string {
	switch k {
	case domain.KindFile:
		return "file"
	case domain.KindDir:
		return "dir"
	case domain.KindSymlink, domain.KindJunction:
		return "link"
	}
	return strings.ToLower(string(k))
}

// baseElement returns a store-normalized path's last element, tolerant
// of both separators.
func baseElement(p string) string {
	p = strings.TrimRight(p, "/\\")
	if p == "" {
		return ""
	}
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// statEventOutcome extracts the recorded outcome ("failed") from a
// stats event's detail JSON; "" when the event recorded none (the
// success case stores no outcome key).
func statEventOutcome(detail string) string {
	if detail == "" {
		return ""
	}
	var d struct {
		Outcome string `json:"outcome"`
	}
	if json.Unmarshal([]byte(detail), &d) != nil {
		return ""
	}
	return d.Outcome
}
