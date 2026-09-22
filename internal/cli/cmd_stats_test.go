// cmd_stats_test.go drives `ebb stats` and the Wave 3 recording layer
// end to end through the eHarness world: dashboard happy path (human
// and --json shapes), the status alias equivalence, per-verb event
// recording (byte-bearing success, invocation-only failure, the stats
// and status verbs themselves) and the clutter-scan facts over the
// configured projects_dir.

package cli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
)

// seedStatsEvent appends one journal event through the harness catalog.
func seedStatsEvent(t *testing.T, h *eHarness, e catalog.StatEvent) {
	t.Helper()
	if err := h.cat().AppendStatEvent(nil, e); err != nil {
		t.Fatalf("seed stat event: %v", err)
	}
}

// TestStatsDashboardHuman: seeded events and a parked workspace render
// the dashboard with real numbers, both comparison markers and the
// tracking-since anchor.
func TestStatsDashboardHuman(t *testing.T) {
	h := newEHarness(t)
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-08-30T10:00:00Z", Command: "park", Workspace: "cliws",
		BytesOut: 3<<30 + 400<<20,
	})
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-08-31T10:00:00Z", Command: "open", Workspace: "cliws", BytesIn: 400 << 20,
	})
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-09-01T10:00:00Z", Command: "trim", Workspace: "web", BytesOut: 220 << 20, Detail: `{"stale":true}`,
	})
	seedStatsEvent(t, h, catalog.StatEvent{TS: "2026-09-02T10:00:00Z", Command: "stats"})

	code, _, stderr := h.run("stats")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"Ebb Developer Space Economy",
		"Lifetime reclaimed",
		"3.6 GiB", // 3 GiB + 400 MiB + 220 MiB reclaimed
		"400.0 MiB",
		"Space efficiency",
		"Hoarding score",
		"Zombie bytes exorcised",
		"220.0 MiB",
		"tracking since 2026-08-30",
		"✦",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("dashboard lacks %q:\n%s", want, stderr)
		}
	}
	assertNoSecrets(t, stderr)
}

// TestStatsJSONEnvelopeShape: the --json machine surface — §17.2
// envelope keys, the metrics object's frozen spellings and the two
// comparisons.
func TestStatsJSONEnvelopeShape(t *testing.T) {
	h := newEHarness(t)
	seedStatsEvent(t, h, catalog.StatEvent{
		TS: "2026-08-30T10:00:00Z", Command: "park", Workspace: "cliws", BytesOut: 1 << 30,
	})
	seedStatsEvent(t, h, catalog.StatEvent{TS: "2026-08-31T10:00:00Z", Command: "stats"})

	code, stdout, stderr := h.run("stats", "--json")
	if code != ExitOK {
		t.Fatalf("code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	if env["command"] != "stats" || env["outcome"] != "ok" {
		t.Errorf("envelope command/outcome = %v/%v", env["command"], env["outcome"])
	}
	det, ok := env["details"].(map[string]any)
	if !ok {
		t.Fatalf("details missing: %v", env["details"])
	}
	m, ok := det["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("metrics object missing: %v", det)
	}
	for _, key := range []string{
		"lifetime_reclaimed_bytes", "lifetime_restored_bytes", "currently_parked_bytes",
		"active_workspaces", "parked_workspaces", "space_efficiency_ratio",
		"clean_desk_streak_days", "hoarding_score", "zombie_gb_exorcised",
		"estimated_ssd_wear_saved", "top_commands", "total_invocations", "tracking_since",
	} {
		if _, ok := m[key]; !ok {
			t.Errorf("metrics lacks frozen key %q: %v", key, m)
		}
	}
	if got := m["lifetime_reclaimed_bytes"].(float64); got != 1<<30 {
		t.Errorf("lifetime_reclaimed_bytes = %v, want %d", got, 1<<30)
	}
	if got := m["total_invocations"].(float64); got != 2 {
		t.Errorf("total_invocations = %v, want 2", got)
	}
	cmps, ok := det["comparisons"].([]any)
	if !ok || len(cmps) != 2 {
		t.Fatalf("comparisons = %v", det["comparisons"])
	}
	for _, c := range cmps {
		cm, ok := c.(map[string]any)
		if !ok {
			t.Fatalf("comparison = %v", c)
		}
		text, _ := cm["text"].(string)
		if text == "" {
			t.Errorf("comparison carries no text: %v", cm)
		}
	}
	// The current run has not recorded itself yet (recording happens at
	// completion): the journal saw exactly the two seeded events.
}

// TestStatsUnknownsWithoutScan: no projects_dir configured — the
// hoarding grade is the honest unknown and the streak is marked.
func TestStatsUnknownsWithoutScan(t *testing.T) {
	h := newEHarness(t)
	code, stdout, _ := h.run("stats", "--json")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	env := envelopeOf(t, stdout)
	m := env["details"].(map[string]any)["metrics"].(map[string]any)
	if m["scan_available"] != false {
		t.Errorf("scan_available = %v, want false", m["scan_available"])
	}
	score := m["hoarding_score"].(map[string]any)
	if score["grade"] != "" {
		t.Errorf("grade = %v, want empty (unknown)", score["grade"])
	}
}

// TestStatsScanFactsFromProjectsDir: a configured projects_dir holding
// a stale project (untouched >30d with regenerable output) feeds the
// clutter facts: scan_available true, the streak resets and the
// hoarding rubric grades real clutter.
func TestStatsScanFactsFromProjectsDir(t *testing.T) {
	h := newEHarness(t)
	parent := t.TempDir()
	stale := filepath.Join(parent, "stale-app")
	if err := os.MkdirAll(filepath.Join(stale, "node_modules", "left-pad"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "node_modules", "left-pad", "index.js"), []byte("module.exports=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-45 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(stale, "node_modules", "left-pad", "index.js"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	if code, _, stderr := h.run("config", "add", "projects_dir", parent); code != ExitOK {
		t.Fatalf("config add code = %d, stderr = %s", code, stderr)
	}
	seedStatsEvent(t, h, catalog.StatEvent{TS: "2026-09-01T10:00:00Z", Command: "stats"})

	code, stdout, _ := h.run("stats", "--json")
	if code != ExitOK {
		t.Fatalf("code = %d", code)
	}
	env := envelopeOf(t, stdout)
	m := env["details"].(map[string]any)["metrics"].(map[string]any)
	if m["scan_available"] != true {
		t.Fatalf("scan_available = %v, want true (conditions: %v)", m["scan_available"], env["conditions"])
	}
	if got := m["clean_desk_streak_days"].(float64); got != 0 {
		t.Errorf("streak = %v, want 0 (clutter found)", got)
	}
	score := m["hoarding_score"].(map[string]any)
	if score["grade"] == "" {
		t.Errorf("grade unknown despite scanned roots: %v", score)
	}
}

// TestStatusAliasEquivalence: `ebb status` and `ebb stats` produce
// byte-identical output and exit codes (recording suspended for the
// comparison so both see the same journal).
func TestStatusAliasEquivalence(t *testing.T) {
	h := newEHarness(t)
	seedStatsEvent(t, h, catalog.StatEvent{TS: "2026-08-30T10:00:00Z", Command: "park", Workspace: "cliws", BytesOut: 1 << 30})

	rec := h.deps.RecordStatEvent
	h.deps.RecordStatEvent = nil
	codeStats, outStats, errStats := h.run("stats")
	codeStatus, outStatus, errStatus := h.run("status")
	h.deps.RecordStatEvent = rec

	if codeStats != codeStatus || outStats != outStatus || errStats != errStatus {
		t.Errorf("alias mismatch:\ncode %d vs %d\nstdout %q vs %q\nstderr-diff %v",
			codeStats, codeStatus, outStats, outStatus, errStats != errStatus)
	}
	if !strings.Contains(errStats, "Ebb Developer Space Economy") {
		t.Errorf("alias did not render the dashboard:\n%s", errStats)
	}

	// Same equivalence under --json.
	h.deps.RecordStatEvent = nil
	codeStats, outStats, errStats = h.run("stats", "--json")
	codeStatus, outStatus, errStatus = h.run("status", "--json")
	h.deps.RecordStatEvent = rec
	if codeStats != codeStatus || outStats != outStatus || errStats != errStatus {
		t.Errorf("json alias mismatch: %d vs %d, %q vs %q", codeStats, codeStatus, outStats, outStatus)
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(outStats), &probe); err != nil {
		t.Fatalf("status --json is not one envelope: %v\n%s", err, outStats)
	}
}

// TestStatsRecordsItsOwnVerb: stats and status invocations are recorded
// as their own verbs, command-only (no bytes, no failed outcome).
func TestStatsRecordsItsOwnVerb(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("stats"); code != ExitOK {
		t.Fatal("stats failed")
	}
	if code, _, _ := h.run("status"); code != ExitOK {
		t.Fatal("status failed")
	}
	events := h.statEventsOf()
	if len(events) != 2 {
		t.Fatalf("recorded events = %+v, want two", events)
	}
	if events[0].Command != "stats" || events[1].Command != "status" {
		t.Errorf("verbs = %s/%s, want stats then status", events[0].Command, events[1].Command)
	}
	for _, e := range events {
		if e.BytesIn != 0 || e.BytesOut != 0 {
			t.Errorf("%s recorded bytes it never bore: %+v", e.Command, e)
		}
		if e.Detail != "" {
			t.Errorf("%s recorded unexpected detail %q", e.Command, e.Detail)
		}
	}
}

// TestTrimSuccessRecordsBytesOut: a byte-bearing success records the
// envelope's own accounting (trim's preserved removal-plan bytes) under
// the workspace label.
func TestTrimSuccessRecordsBytesOut(t *testing.T) {
	h := newEHarness(t)
	code, stdout, _ := h.run("trim", "--groups", "deps", "--yes", "--json", h.wsRoot)
	if code != ExitOK {
		t.Fatalf("trim code = %d", code)
	}
	env := envelopeOf(t, stdout)
	preserved := int64(0)
	if b, ok := env["bytes"].(map[string]any); ok {
		preserved = int64(b["preserved"].(float64))
	}
	if preserved <= 0 {
		t.Fatalf("trim envelope carried no preserved bytes: %v", env["bytes"])
	}
	events := h.statEventsOf()
	if len(events) != 1 {
		t.Fatalf("events = %+v, want exactly the trim invocation", events)
	}
	e := events[0]
	if e.Command != "trim" {
		t.Errorf("command = %s, want trim", e.Command)
	}
	if e.BytesOut != preserved {
		t.Errorf("bytes_out = %d, want the envelope's preserved %d", e.BytesOut, preserved)
	}
	if e.BytesIn != 0 {
		t.Errorf("trim recorded bytes_in = %d", e.BytesIn)
	}
	if e.Workspace != "cliws" {
		t.Errorf("workspace = %q, want cliws", e.Workspace)
	}
	if e.Detail != "" {
		t.Errorf("success recorded detail %q, want none", e.Detail)
	}
}

// TestFailureRecordsInvocationOnly: a usage failure records the verb
// with {"outcome":"failed"} and no bytes.
func TestFailureRecordsInvocationOnly(t *testing.T) {
	h := newEHarness(t)
	if code, _, _ := h.run("recover", "not-an-id"); code != ExitUsage {
		t.Fatalf("code = %d, want %d", code, ExitUsage)
	}
	events := h.statEventsOf()
	if len(events) != 1 {
		t.Fatalf("events = %+v, want the failed recover invocation", events)
	}
	e := events[0]
	if e.Command != "recover" || e.BytesIn != 0 || e.BytesOut != 0 {
		t.Errorf("failed event = %+v", e)
	}
	if e.Detail != `{"outcome":"failed"}` {
		t.Errorf("detail = %q, want failed outcome", e.Detail)
	}
}

// TestStatEventBytesMapping pins the per-verb envelope→event byte
// mapping (the frozen accounting table in statrec.go).
func TestStatEventBytesMapping(t *testing.T) {
	tests := []struct {
		verb    string
		bytes   BytesSummary
		wantIn  int64
		wantOut int64
	}{
		{"trim", BytesSummary{Preserved: 900}, 0, 900},
		{"park", BytesSummary{FreedObserved: 100, FreedEstimated: 200, Preserved: 300}, 0, 100},
		{"park", BytesSummary{FreedEstimated: 200, Preserved: 300}, 0, 200},
		{"reclaim", BytesSummary{FreedEstimated: 200}, 0, 200},
		{"gc", BytesSummary{FreedObserved: 50}, 0, 50},
		{"delete", BytesSummary{Preserved: 700}, 0, 700},
		{"open", BytesSummary{Restored: 42}, 42, 0},
		{"restore", BytesSummary{Restored: 42, FreedObserved: 9}, 42, 0},
		{"freeze", BytesSummary{Preserved: 5}, 0, 5},
		{"freeze", BytesSummary{Restored: 5}, 5, 0},
		{"stats", BytesSummary{Restored: 5, Preserved: 6, FreedObserved: 7}, 0, 0},
	}
	for _, tt := range tests {
		in, out := statEventBytes(tt.verb, &tt.bytes)
		if in != tt.wantIn || out != tt.wantOut {
			t.Errorf("statEventBytes(%s, %+v) = %d/%d, want %d/%d", tt.verb, tt.bytes, in, out, tt.wantIn, tt.wantOut)
		}
	}
	in, out := statEventBytes("park", nil)
	if in != 0 || out != 0 {
		t.Errorf("nil summary recorded bytes %d/%d", in, out)
	}
}

// TestRecordDispatchDetailPlumbing: the emit()-to-recorder sink, the
// dry-run suppression and the stale-detail merge, driven through one
// synthetic nested reclaim (the analyse batch path's shape).
func TestRecordDispatchDetailPlumbing(t *testing.T) {
	var events []catalog.StatEvent
	deps := Deps{RecordStatEvent: func(e catalog.StatEvent) error {
		events = append(events, e)
		return nil
	}}
	sink := Streams{Out: io.Discard, Err: io.Discard}

	// Success with bytes and the stale mark.
	code := recordDispatchDetail(deps, sink, "reclaim", []string{"stale-proj", "--yes"},
		map[string]any{"stale": true},
		func() int {
			env := newEnvelope("reclaim", "ok")
			env.Bytes = &BytesSummary{FreedObserved: 5000}
			emit(env, false, sink, "")
			return ExitOK
		})
	if code != ExitOK {
		t.Fatalf("wrapped code = %d", code)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	e := events[0]
	if e.Command != "reclaim" || e.BytesOut != 5000 || e.Workspace != "stale-proj" {
		t.Errorf("stale reclaim event = %+v", e)
	}
	if e.Detail != `{"stale":true}` {
		t.Errorf("detail = %q, want the stale mark only", e.Detail)
	}

	// A dry run records no bytes (a preview reclaimed nothing).
	events = nil
	recordDispatchDetail(deps, sink, "reclaim", []string{"stale-proj", "--dry-run"}, nil, func() int {
		env := newEnvelope("reclaim", "dry-run")
		env.Conditions = []string{"dry-run"}
		env.Bytes = &BytesSummary{FreedEstimated: 5000}
		emit(env, false, sink, "")
		return ExitOK
	})
	if len(events) != 1 || events[0].BytesOut != 0 {
		t.Errorf("dry run recorded bytes: %+v", events)
	}

	// A failed stale reclaim merges both detail keys.
	events = nil
	recordDispatchDetail(deps, sink, "reclaim", []string{"stale-proj", "--yes"},
		map[string]any{"stale": true},
		func() int {
			emit(newEnvelope("reclaim", "blocked"), false, sink, "")
			return ExitBlocked
		})
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	if !strings.Contains(events[0].Detail, `"outcome":"failed"`) || !strings.Contains(events[0].Detail, `"stale":true`) {
		t.Errorf("failure detail = %q, want outcome+stale merged", events[0].Detail)
	}

	// A command that never emits still records the invocation.
	events = nil
	recordDispatchDetail(deps, sink, "version", nil, nil, func() int { return ExitOK })
	if len(events) != 1 || events[0].Command != "version" || events[0].Detail != "" {
		t.Errorf("emit-less invocation = %+v", events)
	}
}

// TestRecordFailureWarnsHumanOnly: an unwritable recorder never fails
// the command; the warning appears on the human stream only.
func TestRecordFailureWarnsHumanOnly(t *testing.T) {
	h := newEHarness(t)
	h.deps.RecordStatEvent = func(e catalog.StatEvent) error {
		return errors.New("journal on fire")
	}
	code, _, stderr := h.run("stats")
	if code != ExitOK {
		t.Fatalf("recording failure changed the exit code: %d", code)
	}
	if !strings.Contains(stderr, "stats event not recorded") {
		t.Errorf("human run lacks the recording warning:\n%s", stderr)
	}

	h.deps.RecordStatEvent = func(e catalog.StatEvent) error {
		return errors.New("journal on fire")
	}
	code, stdout, stderr := h.run("stats", "--json")
	if code != ExitOK {
		t.Fatalf("json run code = %d", code)
	}
	if strings.Contains(stderr, "stats event not recorded") || strings.Contains(stdout, "stats event not recorded") {
		t.Errorf("--json run surfaced the recording warning (stdout %q stderr %q)", stdout, stderr)
	}
}
