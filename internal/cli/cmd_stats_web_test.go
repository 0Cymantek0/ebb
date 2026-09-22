// cmd_stats_web_test.go drives the Wave 3 wiring: the --share card
// export (file + envelope shapes), the flag exclusions, the
// statsWebProvider mapping fidelity (metrics, workspaces, history,
// snapshot tree, recommendations over the shared shallow scan), and one
// end-to-end --web run over the real loopback listener.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/stats"
	"ebb/internal/vault"
	"ebb/internal/web"
)

// ---- flag matrix --------------------------------------------------------------

// TestStatsFlagExclusions: --web refuses --share and --json; --out
// without --share is a usage error.
func TestStatsFlagExclusions(t *testing.T) {
	h := newEHarness(t)
	tests := []struct {
		name string
		args []string
	}{
		{"web+share", []string{"stats", "--web", "--share"}},
		{"share+web", []string{"stats", "--share", "--web"}},
		{"json+web", []string{"stats", "--json", "--web"}},
		{"web+json", []string{"stats", "--web", "--json"}},
		{"out without share", []string{"stats", "--out", "card.png"}},
	}
	for _, tt := range tests {
		code, _, stderr := h.run(tt.args...)
		if code != ExitUsage {
			t.Errorf("%s: code = %d, want ExitUsage (stderr %s)", tt.name, code, stderr)
		}
		if stderr == "" {
			t.Errorf("%s: no usage explanation printed", tt.name)
		}
	}
}

// ---- --share -------------------------------------------------------------------

// TestStatsShareWritesCard: the card lands at --out as a decodable PNG,
// the human output names the path, and the invocation is recorded
// without the card path leaking into the workspace label.
func TestStatsShareWritesCard(t *testing.T) {
	h := newEHarness(t)
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-09-01T10:00:00Z", Command: "park", Workspace: "cliws", BytesOut: 3 << 30,
	})
	cardPath := filepath.Join(t.TempDir(), "card.png")

	code, stdout, stderr := h.run("stats", "--share", "--out", cardPath)
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	if stdout != "" {
		t.Errorf("human run wrote to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, cardPath) {
		t.Errorf("human output does not name the card path:\n%s", stderr)
	}
	if !strings.Contains(stderr, "share card") {
		t.Errorf("human output lacks the share hint:\n%s", stderr)
	}
	b, err := os.ReadFile(cardPath)
	if err != nil {
		t.Fatalf("card not written: %v", err)
	}
	if !bytes.HasPrefix(b, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		t.Error("card lacks the PNG magic bytes")
	}

	// The recording layer must treat --out's VALUE as a flag value, not
	// a positional workspace label (stats takes no positional, so the
	// label is the recorder's generic "workspace" default — never the
	// card path or its base name).
	events := h.statEventsOf()
	if len(events) != 1 || events[0].Command != "stats" {
		t.Fatalf("events = %+v, want exactly the stats invocation", events)
	}
	if events[0].Workspace != "workspace" || strings.Contains(events[0].Workspace, "card") {
		t.Errorf("workspace label = %q, want the no-positional default", events[0].Workspace)
	}
}

// TestStatsShareJSONEnvelope: --json --share is allowed; the envelope
// outcome is ok and the conditions carry the written path.
func TestStatsShareJSONEnvelope(t *testing.T) {
	h := newEHarness(t)
	cardPath := filepath.Join(t.TempDir(), "card.json.png")
	code, stdout, _ := h.run("stats", "--json", "--share", "--out", cardPath)
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	env := envelopeOf(t, stdout)
	if env["outcome"] != "ok" {
		t.Errorf("outcome = %v, want ok", env["outcome"])
	}
	found := false
	for _, c := range env["conditions"].([]any) {
		if s, ok := c.(string); ok && s == "card:"+cardPath {
			found = true
		}
	}
	if !found {
		t.Errorf("conditions %v lack the card path", env["conditions"])
	}
	if _, err := os.Stat(cardPath); err != nil {
		t.Errorf("card not written in json mode: %v", err)
	}
}

// ---- provider adapter ----------------------------------------------------------

// seedWebWorld seeds the catalog with everything the provider maps:
// events (one failed), workspace rows (live with a root, parked, and a
// summary size via a park event), and one catalog snapshot backed by
// the fake store.
func seedWebWorld(t *testing.T, h *eHarness) (snapID domain.SnapshotID, backendID string) {
	t.Helper()
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-08-30T10:00:00Z", Command: "park", Workspace: "parkedws", BytesOut: 2 << 30,
	})
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-08-31T10:00:00Z", Command: "open", Workspace: "parkedws", BytesIn: 512 << 20,
	})
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-09-01T10:00:00Z", Command: "recover", Workspace: "gone", Detail: `{"outcome":"failed"}`,
	})

	liveID := domain.WorkspaceID(domain.NewID())
	parkedID := domain.WorkspaceID(domain.NewID())
	if err := h.cat().UpsertWorkspace(catalog.Workspace{
		ID: liveID, Name: "livews", RootPath: filepath.Join(h.wsRoot, "..", "livews"), Status: catalog.WorkspaceLive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := h.cat().UpsertWorkspace(catalog.Workspace{
		ID: parkedID, Name: "parkedws", Status: catalog.WorkspaceParked,
	}); err != nil {
		t.Fatal(err)
	}

	// A snapshot the fake store can list: poke the store directly (the
	// test owns the fake) and record the matching catalog row.
	backendID = string(domain.NewID())
	h.store.mu.Lock()
	h.store.snaps[backendID] = &eFakeSnap{
		files: map[string][]byte{"cliws/src/app.go": []byte("package main")},
		dirs:  map[string]bool{"cliws": true, "cliws/src": true},
		links: map[string]string{"cliws/current": "src"},
	}
	h.store.mu.Unlock()
	snapID = domain.SnapshotID(domain.NewID())
	if _, err := h.cat().RecordSnapshot(catalog.Snapshot{
		ID: snapID, WorkspaceID: liveID, PayloadBackendID: backendID, SealBackendID: string(domain.NewID()),
		Kind: catalog.SnapshotKindSnapshot, Pinned: true,
	}); err != nil {
		t.Fatal(err)
	}
	return snapID, backendID
}

// equalWebCommands compares the mapped top-commands leaderboard with
// the stats-computed one.
func equalWebCommands(got []web.CommandCount, want []stats.CommandCount) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i].Command != want[i].Command || got[i].Count != want[i].Count {
			return false
		}
	}
	return true
}

// newProvider opens a session over the harness deps and wraps it.
func newProvider(t *testing.T, h *eHarness) *statsWebProvider {
	t.Helper()
	sess, err := openSession(h.deps)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	t.Cleanup(sess.close)
	return &statsWebProvider{deps: h.deps, sess: sess, ctx: context.Background()}
}

// TestStatsWebProviderMetricsMapping: Metrics() equals an independent
// stats.Compute over the same journal/summaries, field-for-field (the
// clock-sensitive streak is asserted only to be non-negative).
func TestStatsWebProviderMetricsMapping(t *testing.T) {
	h := newEHarness(t)
	seedWebWorld(t, h)
	p := newProvider(t, h)

	got, err := p.Metrics()
	if err != nil {
		t.Fatalf("Metrics: %v", err)
	}
	events, _ := h.cat().ListStatEvents(nil, 0)
	summaries, _ := h.cat().ListWorkspaceSummaries()
	want := stats.Compute(events, summaries, stats.ScanFacts{})

	if got.LifetimeReclaimedBytes != want.LifetimeReclaimedBytes ||
		got.LifetimeRestoredBytes != want.LifetimeRestoredBytes ||
		got.CurrentlyParkedBytes != want.CurrentlyParkedBytes ||
		got.ActiveWorkspaces != want.ActiveWorkspaces ||
		got.ParkedWorkspaces != want.ParkedWorkspaces ||
		got.SpaceEfficiencyRatio != want.SpaceEfficiencyRatio ||
		got.ZombieBytesExorcised != want.ZombieBytesExorcised ||
		got.EstimatedSSDWearSaved != want.EstimatedSSDWearSaved ||
		got.TotalInvocations != want.TotalInvocations ||
		got.TrackingSince != want.TrackingSince ||
		got.HoardingScore != (web.Score{Grade: want.HoardingScore.Grade, Label: want.HoardingScore.Label}) ||
		!equalWebCommands(got.TopCommands, want.TopCommands) {
		t.Errorf("mapping drifted:\n got %+v\nwant %+v", got, webMetrics(want))
	}
	if got.LifetimeReclaimedBytes != 2<<30 || got.LifetimeRestoredBytes != 512<<20 {
		t.Errorf("byte totals = %d/%d, want 2 GiB / 512 MiB", got.LifetimeReclaimedBytes, got.LifetimeRestoredBytes)
	}
	if got.ActiveWorkspaces != 1 || got.ParkedWorkspaces != 1 {
		t.Errorf("workspace counts = %d/%d, want 1/1", got.ActiveWorkspaces, got.ParkedWorkspaces)
	}
	if got.CleanDeskStreakDays < 0 {
		t.Errorf("streak = %d", got.CleanDeskStreakDays)
	}
	if len(got.TopCommands) != len(want.TopCommands) {
		t.Errorf("topCommands = %+v, want %+v", got.TopCommands, want.TopCommands)
	}

	// ComparisonForBytes delegates to the deterministic engine.
	n := int64(3 << 30)
	c := p.ComparisonForBytes(n, 7)
	ref := stats.PickForBytes(n, 7)
	if c != (web.Comparison{Category: ref.Category, Subject: ref.Subject, Text: ref.Text}) {
		t.Errorf("ComparisonForBytes = %+v, want %+v", c, ref)
	}
}

// TestStatsWebProviderWorkspaces: rows carry name/status/root/size with
// the catalog's park-derived size, and unknown fields stay empty.
func TestStatsWebProviderWorkspaces(t *testing.T) {
	h := newEHarness(t)
	seedWebWorld(t, h)
	ws, err := newProvider(t, h).Workspaces()
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}
	byName := map[string]web.WorkspaceView{}
	for _, w := range ws {
		byName[w.Name] = w
	}
	live, ok := byName["livews"]
	if !ok {
		t.Fatalf("livews missing from %v", ws)
	}
	if live.Status != "active" || live.Root == "" {
		t.Errorf("livews = %+v, want status active and a root path", live)
	}
	if live.Ecosystem != "" || live.LastActivity != "" || live.ReclaimedBytes != 0 {
		t.Errorf("livews invented data it cannot know: %+v", live)
	}
	parked, ok := byName["parkedws"]
	if !ok {
		t.Fatalf("parkedws missing from %v", ws)
	}
	if parked.Status != "parked" || parked.SizeBytes != 2<<30 {
		t.Errorf("parkedws = %+v, want status parked and the latest park size", parked)
	}
}

// TestStatsWebProviderHistory: most-recent-first ordering, limit
// honored, and the recorded failure outcome surfaced.
func TestStatsWebProviderHistory(t *testing.T) {
	h := newEHarness(t)
	seedWebWorld(t, h)
	hist, err := newProvider(t, h).History(2)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("len = %d, want the limit 2", len(hist))
	}
	if hist[0].TS < hist[1].TS {
		t.Errorf("history not most-recent-first: %+v", hist)
	}
	full, _ := newProvider(t, h).History(0)
	if len(full) != 3 {
		t.Fatalf("unlimited history len = %d, want 3", len(full))
	}
	var failed *web.HistoryEvent
	for i := range full {
		if full[i].Command == "recover" {
			failed = &full[i]
		}
	}
	if failed == nil || failed.Outcome != "failed" {
		t.Errorf("failed event outcome not surfaced: %+v", failed)
	}
	var okOne *web.HistoryEvent
	for i := range full {
		if full[i].Command == "park" {
			okOne = &full[i]
		}
	}
	if okOne == nil || okOne.Outcome != "" || okOne.BytesOut != 2<<30 {
		t.Errorf("park event = %+v, want no outcome and 2 GiB out", okOne)
	}
}

// TestStatsWebProviderSnapshotTree: the tree flows through the real
// vault-passfile machinery and the fake store's Ls, with kinds mapped
// and names reduced to their last path element.
func TestStatsWebProviderSnapshotTree(t *testing.T) {
	h := newEHarness(t)
	snapID, _ := seedWebWorld(t, h)
	entries, err := newProvider(t, h).SnapshotTree(string(snapID))
	if err != nil {
		t.Fatalf("SnapshotTree: %v", err)
	}
	kinds := map[string]string{}
	for _, e := range entries {
		kinds[e.Name] = e.Kind
	}
	for name, want := range map[string]string{
		"cliws": "dir", "src": "dir", "app.go": "file", "current": "link",
	} {
		if kinds[name] != want {
			t.Errorf("entry %q kind = %q, want %q (all: %v)", name, kinds[name], want, kinds)
		}
	}
	// Unknown-but-well-formed ids are errors, not empty data.
	if _, err := newProvider(t, h).SnapshotTree(string(domain.NewID())); err == nil {
		t.Error("unknown snapshot id returned no error")
	}
	// Malformed ids are refused before the catalog.
	if _, err := newProvider(t, h).SnapshotTree("deadbeef;rm"); err == nil {
		t.Error("malformed snapshot id returned no error")
	}
}

// TestStatsWebProviderSnapshotTreeVaultLockedRefusal is the wave-4 K3
// regression: with NO credential source available (env unset, no
// OS-keyring entry for the harness's randomly-id'd vault),
// SnapshotTree must refuse QUICKLY with the honest vault-locked wording
// naming both background fixes (EBB_VAULT_PASSWORD / OS keyring) and
// the vault id — never block a request handler on the terminal prompt
// rung that Password would open on a TTY stdin. The vault-level tests
// (TestPasswordNonInteractiveRefusesEvenOnTTY) pin the no-prompt
// structurally; this pins the provider seam and the message.
func TestStatsWebProviderSnapshotTreeVaultLockedRefusal(t *testing.T) {
	h := newEHarness(t)
	snapID, _ := seedWebWorld(t, h)
	def, err := vault.New(filepath.Join(h.stateDir, vault.RegistryFile)).Default()
	if err != nil {
		t.Fatalf("read default vault: %v", err)
	}
	p := newProvider(t, h)

	// Happy path first, with the harness's env credential in place: the
	// same provider lists entries normally.
	if entries, err := p.SnapshotTree(string(snapID)); err != nil || len(entries) == 0 {
		t.Fatalf("happy path with env credential: entries=%d err=%v (must list)", len(entries), err)
	}

	// Neutralize the env source the harness seeded. t.Setenv cannot
	// reliably UNSET on every platform, so the chain's documented
	// contract is used instead: an EMPTY EBB_VAULT_PASSWORD means unset
	// (envPassword in internal/vault — the same technique as the vault
	// package's own tests). The keyring rung finds no entry for the
	// random vault id (the vault seams are package-private by design,
	// so this lookup hits the real store read-only; nothing is written).
	t.Setenv(vault.EnvPassword, "")

	type treeResult struct {
		entries []web.TreeEntryView
		err     error
	}
	done := make(chan treeResult, 1)
	go func() {
		entries, err := p.SnapshotTree(string(snapID))
		done <- treeResult{entries: entries, err: err}
	}()
	select {
	case res := <-done:
		if res.err == nil {
			t.Fatalf("no credential source must refuse, got %d entries", len(res.entries))
		}
		if len(res.entries) != 0 {
			t.Errorf("refusal must carry no partial entries: %v", res.entries)
		}
		msg := res.err.Error()
		for _, want := range []string{
			"snapshot tree unavailable: vault locked",
			vault.EnvPassword,
			"keyring",
			def.ID,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("refusal %q lacks %q", msg, want)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SnapshotTree blocked on credential resolution — the prompt rung must be absent from the web facet's chain")
	}
}

// TestStatsWebProviderRecommendations: unconfigured roots → empty list
// and no error; a configured stale project yields a card with the
// analyse surface's sanitized copy command.
func TestStatsWebProviderRecommendations(t *testing.T) {
	h := newEHarness(t)
	p := newProvider(t, h)

	recs, err := p.Recommendations()
	if err != nil {
		t.Fatalf("unconfigured Recommendations: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("unconfigured roots returned %d recommendations, want 0", len(recs))
	}

	parent := t.TempDir()
	stale := filepath.Join(parent, "stale-app")
	if err := os.MkdirAll(filepath.Join(stale, "node_modules", "left-pad"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "node_modules", "left-pad", "index.js"), []byte("module.exports=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Staleness evidence is the newest mtime among the project's
	// TOP-LEVEL entries — age the node_modules mount point itself.
	old := time.Now().Add(-45 * 24 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(stale, "node_modules"), old, old); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := h.run("config", "add", "projects_dir", parent); code != ExitOK {
		t.Fatalf("config add code = %d, stderr = %s", code, stderr)
	}

	recs, err = newProvider(t, h).Recommendations()
	if err != nil {
		t.Fatalf("configured Recommendations: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("stale project produced no recommendation")
	}
	found := false
	for _, r := range recs {
		if r.Root == stale {
			found = true
			if r.Category != "stale" {
				t.Errorf("category = %q, want stale", r.Category)
			}
			wantCmd, _ := renderCommand([]string{"ebb", "reclaim", stale})
			if r.Command != wantCmd {
				t.Errorf("command = %q, want the sanitized %q", r.Command, wantCmd)
			}
			if r.Shielded {
				t.Error("unshielded project reported as shielded")
			}
		}
	}
	if !found {
		t.Errorf("no recommendation for %s in %+v", stale, recs)
	}
}

// ---- end-to-end --web ------------------------------------------------------------

// TestStatsWebEndToEndRun drives the real web.Run loop through Main:
// the serving-at line appears on the human stream, /api/overview
// answers through the real loopback listener with the mapped data, and
// cancelling the harness signal context (the SIGINT stand-in) shuts the
// server down cleanly with exit 130.
func TestStatsWebEndToEndRun(t *testing.T) {
	h := newEHarness(t)
	seedWebWorld(t, h)

	var errb strings.Builder
	done := make(chan int, 1)
	go func() {
		done <- Main([]string{"stats", "--web"}, Streams{Out: io.Discard, Err: &errb}, h.deps)
	}()

	// Wait for the serving line, then talk to the server.
	baseURL := ""
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if s := errb.String(); strings.Contains(s, "serving at ") {
			baseURL = strings.TrimSpace(strings.SplitN(s, "serving at ", 2)[1])
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if baseURL == "" {
		h.cancelSig()
		t.Fatalf("server never announced its URL:\n%s", errb.String())
	}

	resp, err := http.Get(baseURL + "api/overview")
	if err != nil {
		h.cancelSig()
		t.Fatalf("GET /api/overview: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status = %d: %s", resp.StatusCode, body)
	}
	var payload struct {
		Metrics web.Metrics `json:"metrics"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("overview JSON: %v\n%s", err, body)
	}
	if payload.Metrics.LifetimeReclaimedBytes != 2<<30 {
		t.Errorf("overview reclaimed = %d, want the seeded 2 GiB", payload.Metrics.LifetimeReclaimedBytes)
	}

	// SIGINT: cancel, expect a bounded clean shutdown and exit 130.
	h.cancelSig()
	select {
	case code := <-done:
		if code != ExitCancelled {
			t.Errorf("exit code = %d, want %d (cancelled)", code, ExitCancelled)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("stats --web did not return within 4s of cancellation")
	}

	// The single dispatch-time recording only: serving requests wrote
	// nothing to the journal.
	events := h.statEventsOf()
	if len(events) != 1 || events[0].Command != "stats" {
		t.Errorf("events = %+v, want exactly one dispatch-time stats event", events)
	}
}

// TestStatsWebRefusesJSONQuickly: the exclusion fires before any
// session is opened (pure usage path — also covered by the matrix, this
// pins the fast-fail ordering through a Deps with a broken StateDir).
func TestStatsWebRefusesJSONQuickly(t *testing.T) {
	deps := Deps{StateDir: func() (string, error) {
		return "", fmt.Errorf("unreachable in a usage failure")
	}}
	code := Main([]string{"stats", "--web", "--json"},
		Streams{Out: io.Discard, Err: io.Discard}, deps)
	if code != ExitUsage {
		t.Errorf("code = %d, want ExitUsage before any session work", code)
	}
}
