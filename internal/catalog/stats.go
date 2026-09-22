// stats.go holds the stats_events accessors (schemaV4, Wave 3): the
// append-only invocation journal behind `ebb stats`. One row is appended
// per dispatched CLI verb at command completion (success or failure) with
// the command's byte flows when it bore them. The table is telemetry
// only: it never gates a destructive decision and stores no secrets —
// byte counts, the verb, a workspace label and detail objects the CLI
// itself minted.
//
// Like the rest of the v1 catalog the API is synchronous; the ctx
// parameter exists to satisfy the frozen Wave 3 seam shape and is
// deliberately not threaded into database/sql (see the package comment).

package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// StatEvent is one stats_events row: one dispatched CLI invocation.
type StatEvent struct {
	// ID is a 32-hex identifier minted by AppendStatEvent when empty.
	ID string
	// TS is the RFC3339 UTC completion timestamp (minted when empty).
	TS string
	// Command is the CLI verb ("reclaim", "park", ...); never empty.
	Command string
	// Workspace is the workspace label the invocation targeted ("" when
	// none — a workspace-free verb or an unresolvable argument).
	Workspace string
	// BytesIn counts bytes restored/materialized onto the machine (open,
	// restore, freeze --restore).
	BytesIn int64
	// BytesOut counts bytes reclaimed/freed from the machine (trim,
	// reclaim, park, delete, gc, freeze) as the command's own accounting
	// reported them.
	BytesOut int64
	// Detail is an optional compact JSON object the CLI minted (e.g.
	// {"outcome":"failed"} or {"stale":true}). Never external text.
	Detail string
}

// AppendStatEvent inserts one stats event. A missing ID is minted as a
// fresh 32-hex domain id; a missing TS becomes now (RFC3339Nano UTC). An
// empty command is refused — the verb is the one field the dashboard
// groups by.
func (c *Catalog) AppendStatEvent(ctx context.Context, e StatEvent) error {
	_ = ctx // v1 catalog is synchronous (package comment)
	if e.Command == "" {
		return errors.New("catalog: stat event command required")
	}
	if e.ID == "" {
		e.ID = string(domain.NewID())
	}
	if e.TS == "" {
		e.TS = domain.FormatTime(time.Now())
	}
	return withTx(c.db, func(tx *sql.Tx) error {
		const q = `INSERT INTO stats_events (id, ts, command, workspace, bytes_in, bytes_out, detail)
			VALUES (?, ?, ?, ?, ?, ?, ?)`
		if _, err := tx.Exec(q, e.ID, e.TS, e.Command, nullStr(e.Workspace),
			e.BytesIn, e.BytesOut, nullStr(e.Detail)); err != nil {
			return fmt.Errorf("catalog: append stat event %s: %w", e.ID, err)
		}
		return nil
	})
}

// ListStatEvents returns stats events most-recent-first. limit <= 0
// returns every event; a positive limit caps the result at the newest
// limit rows. Ordering is (ts, rowid) descending: ts is RFC3339 UTC and
// rowid breaks ties between events that share a timestamp by insertion
// order, so the result is deterministic.
func (c *Catalog) ListStatEvents(ctx context.Context, limit int) ([]StatEvent, error) {
	_ = ctx // v1 catalog is synchronous (package comment)
	q := `SELECT id, ts, command, workspace, bytes_in, bytes_out, detail
		FROM stats_events ORDER BY ts DESC, rowid DESC`
	var args []any
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := c.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("catalog: list stat events: %w", err)
	}
	defer rows.Close()
	var out []StatEvent
	for rows.Next() {
		var e StatEvent
		var workspace, detail sql.NullString
		if err := rows.Scan(&e.ID, &e.TS, &e.Command, &workspace, &e.BytesIn, &e.BytesOut, &detail); err != nil {
			return nil, fmt.Errorf("catalog: list stat events: %w", err)
		}
		e.Workspace, e.Detail = workspace.String, detail.String
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list stat events: %w", err)
	}
	return out, nil
}

// WorkspaceSummary is one workspace row reduced to the three fields the
// stats dashboard needs: identity label, liveness status and the size in
// bytes.
//
// Size has no dedicated column in the schemaV1 workspaces table, so it is
// derived from the stats journal itself: the bytes_out of the workspace's
// MOST RECENT park event (a parked workspace's size at park time — the
// number `ebb park` reported when it removed the tree). 0 means "no park
// event ever recorded it" (a workspace parked before Wave 3, or never
// parked); callers that must not show fake zeros treat 0 as unknown.
type WorkspaceSummary struct {
	Name   string
	Status string // WorkspaceLive | WorkspaceParked | WorkspaceUnbound
	Size   int64  // latest park event's bytes_out; 0 = not recorded
}

// ListWorkspaceSummaries returns every workspace with its status and
// latest-recorded park size, ordered by name then id (the same ordering
// as ListWorkspaces). It is the `ws` input of stats.Compute.
func (c *Catalog) ListWorkspaceSummaries() ([]WorkspaceSummary, error) {
	const q = `SELECT w.name, w.status,
		COALESCE((SELECT se.bytes_out FROM stats_events se
			WHERE se.command = 'park' AND se.workspace = w.name
			ORDER BY se.ts DESC, se.rowid DESC LIMIT 1), 0) AS size
		FROM workspaces w ORDER BY w.name, w.id`
	rows, err := c.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("catalog: list workspace summaries: %w", err)
	}
	defer rows.Close()
	var out []WorkspaceSummary
	for rows.Next() {
		var s WorkspaceSummary
		if err := rows.Scan(&s.Name, &s.Status, &s.Size); err != nil {
			return nil, fmt.Errorf("catalog: list workspace summaries: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("catalog: list workspace summaries: %w", err)
	}
	return out, nil
}
