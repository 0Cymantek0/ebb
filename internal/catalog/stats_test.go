package catalog

import (
	"context"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// TestAppendStatEventMintsIDAndTS verifies the minting rules: an empty id
// becomes a 32-hex domain id, an empty ts becomes a non-empty RFC3339
// UTC timestamp, and both caller-supplied values survive verbatim.
func TestAppendStatEventMintsIDAndTS(t *testing.T) {
	c := open(t)
	if err := c.AppendStatEvent(context.Background(), StatEvent{
		Command: "reclaim", Workspace: "cliws", BytesOut: 4096,
		Detail: `{"stale":true}`,
	}); err != nil {
		t.Fatalf("AppendStatEvent: %v", err)
	}
	got, err := c.ListStatEvents(context.Background(), 0)
	if err != nil {
		t.Fatalf("ListStatEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("events = %d, want 1", len(got))
	}
	ev := got[0]
	if len(ev.ID) != 32 || strings.ContainsAny(ev.ID, "ghijklmnopqrstuvwxyz-") {
		t.Errorf("minted id = %q, want 32 lowercase hex chars", ev.ID)
	}
	if ev.TS == "" || !strings.HasSuffix(ev.TS, "Z") {
		t.Errorf("minted ts = %q, want RFC3339 UTC ending in Z", ev.TS)
	}
	if ev.Command != "reclaim" || ev.Workspace != "cliws" || ev.BytesOut != 4096 || ev.Detail != `{"stale":true}` {
		t.Errorf("roundtrip mismatch: %+v", ev)
	}

	// Caller-supplied id/ts are preserved verbatim.
	if err := c.AppendStatEvent(context.Background(), StatEvent{
		ID: "0123456789abcdef0123456789abcdef", TS: "2020-01-01T00:00:00Z", Command: "park",
	}); err != nil {
		t.Fatalf("AppendStatEvent (explicit id): %v", err)
	}
	got, _ = c.ListStatEvents(context.Background(), 0)
	if len(got) != 2 {
		t.Fatalf("events = %d, want 2", len(got))
	}
	if got[1].ID != "0123456789abcdef0123456789abcdef" || got[1].TS != "2020-01-01T00:00:00Z" {
		t.Errorf("explicit id/ts not preserved: %+v", got[1])
	}
}

// TestAppendStatEventRequiresCommand pins the one validation rule: the
// verb is the field the dashboard groups by, so it is never empty.
func TestAppendStatEventRequiresCommand(t *testing.T) {
	c := open(t)
	if err := c.AppendStatEvent(context.Background(), StatEvent{}); err == nil {
		t.Fatal("empty command accepted, want refusal")
	}
}

// TestListStatEventsOrderAndLimit verifies most-recent-first ordering and
// the limit<=0-means-all contract.
func TestListStatEventsOrderAndLimit(t *testing.T) {
	c := open(t)
	ctx := context.Background()
	seed := []StatEvent{
		{TS: "2026-01-01T00:00:00Z", Command: "park", BytesOut: 100},
		{TS: "2026-01-02T00:00:00Z", Command: "open", BytesIn: 100},
		{TS: "2026-01-03T00:00:00Z", Command: "trim", BytesOut: 50},
	}
	for _, e := range seed {
		if err := c.AppendStatEvent(ctx, e); err != nil {
			t.Fatalf("AppendStatEvent %+v: %v", e, err)
		}
	}
	got, err := c.ListStatEvents(ctx, 0)
	if err != nil {
		t.Fatalf("ListStatEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("all: %d events, want 3", len(got))
	}
	want := []string{"trim", "open", "park"}
	for i, w := range want {
		if got[i].Command != w {
			t.Errorf("order[%d] = %s, want %s", i, got[i].Command, w)
		}
	}
	top, err := c.ListStatEvents(ctx, 2)
	if err != nil {
		t.Fatalf("ListStatEvents(2): %v", err)
	}
	if len(top) != 2 || top[0].Command != "trim" || top[1].Command != "open" {
		t.Errorf("limit=2 returned %+v", top)
	}
}

// TestListStatEventsSameTSInsertionOrder: two events sharing a timestamp
// order newest-insert-first (the rowid tiebreak keeps the result
// deterministic).
func TestListStatEventsSameTSInsertionOrder(t *testing.T) {
	c := open(t)
	ctx := context.Background()
	ts := "2026-05-05T05:05:05Z"
	for _, cmd := range []string{"first", "second"} {
		if err := c.AppendStatEvent(ctx, StatEvent{TS: ts, Command: cmd}); err != nil {
			t.Fatalf("AppendStatEvent %s: %v", cmd, err)
		}
	}
	got, _ := c.ListStatEvents(ctx, 0)
	if len(got) != 2 || got[0].Command != "second" || got[1].Command != "first" {
		t.Errorf("same-ts order = %+v, want second then first", got)
	}
}

// TestListWorkspaceSummariesParkedSize verifies the summary shape: status
// counts come from the workspaces table and Size is the workspace's MOST
// RECENT park event bytes_out (0 when none was recorded).
func TestListWorkspaceSummariesParkedSize(t *testing.T) {
	c := open(t)
	ctx := context.Background()
	live := liveWorkspace(t, c, "live-ws")

	parked := Workspace{
		ID: domain.WorkspaceID(domain.NewID()), Name: "parked-ws", Status: WorkspaceParked,
		RootPath: `C:\dev\parked-ws`, RootIdentity: "vol-1/file-parked-ws",
	}
	if err := c.UpsertWorkspace(parked); err != nil {
		t.Fatalf("UpsertWorkspace: %v", err)
	}
	// Two park events for the same workspace: the newest wins.
	for _, e := range []StatEvent{
		{TS: "2026-01-01T00:00:00Z", Command: "park", Workspace: "parked-ws", BytesOut: 111},
		{TS: "2026-02-01T00:00:00Z", Command: "park", Workspace: "parked-ws", BytesOut: 222},
		{TS: "2026-01-15T00:00:00Z", Command: "open", Workspace: "parked-ws", BytesIn: 999},
	} {
		if err := c.AppendStatEvent(ctx, e); err != nil {
			t.Fatalf("AppendStatEvent %+v: %v", e, err)
		}
	}

	got, err := c.ListWorkspaceSummaries()
	if err != nil {
		t.Fatalf("ListWorkspaceSummaries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("summaries = %d, want 2", len(got))
	}
	// Ordered by name: live-ws before parked-ws.
	if got[0].Name != "live-ws" || got[0].Status != WorkspaceLive || got[0].Size != 0 {
		t.Errorf("live summary = %+v, want size 0 (no park event)", got[0])
	}
	if got[1].Name != "parked-ws" || got[1].Status != WorkspaceParked || got[1].Size != 222 {
		t.Errorf("parked summary = %+v, want latest park bytes_out 222", got[1])
	}
	if live == "" {
		t.Fatal("unreachable")
	}
}
