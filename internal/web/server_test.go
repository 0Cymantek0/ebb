// server_test.go exercises the Control Center HTTP surface against a
// fake Provider through the real handler: the security model (method
// matrix, Host enforcement, snapshot-id validation, query strictness),
// the embedded-asset guarantees (non-empty, zero external URLs), the
// JSON shape contracts and the provider-error paths.

package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---- fake Provider ---------------------------------------------------------

type cmpCall struct {
	n   int64
	rot uint64
}

// fakeProvider is the deterministic Provider double for every test in
// the package (independent of internal/stats — the mirror contract is
// what is under test, not the mapping).
type fakeProvider struct {
	metrics            Metrics
	metricsErr         error
	workspaces         []WorkspaceView
	workspacesErr      error
	history            []HistoryEvent
	historyErr         error
	tree               map[string][]TreeEntryView
	treeErr            error
	recommendations    []RecommendationView
	recommendationsErr error

	mu           sync.Mutex
	historyCalls []int
	treeCalls    []string
	cmpCalls     []cmpCall
}

func (f *fakeProvider) Metrics() (Metrics, error) { return f.metrics, f.metricsErr }

func (f *fakeProvider) ComparisonForBytes(n int64, rotation uint64) Comparison {
	f.mu.Lock()
	f.cmpCalls = append(f.cmpCalls, cmpCall{n, rotation})
	f.mu.Unlock()
	return Comparison{
		Category: "scale",
		Subject:  fmt.Sprintf("%d bytes", n),
		Text:     fmt.Sprintf("That is like %d bytes rotating every %d invocations.", n, rotation),
	}
}

func (f *fakeProvider) Workspaces() ([]WorkspaceView, error) { return f.workspaces, f.workspacesErr }

func (f *fakeProvider) History(limit int) ([]HistoryEvent, error) {
	f.mu.Lock()
	f.historyCalls = append(f.historyCalls, limit)
	f.mu.Unlock()
	return f.history, f.historyErr
}

func (f *fakeProvider) SnapshotTree(id string) ([]TreeEntryView, error) {
	f.mu.Lock()
	f.treeCalls = append(f.treeCalls, id)
	f.mu.Unlock()
	if f.treeErr != nil {
		return nil, f.treeErr
	}
	if f.tree == nil {
		return nil, nil
	}
	return f.tree[id], nil
}

func (f *fakeProvider) Recommendations() ([]RecommendationView, error) {
	return f.recommendations, f.recommendationsErr
}

func (f *fakeProvider) recordedHistoryCalls() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.historyCalls...)
}

func (f *fakeProvider) recordedTreeCalls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.treeCalls...)
}

func (f *fakeProvider) recordedCmpCalls() []cmpCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]cmpCall(nil), f.cmpCalls...)
}

// richProvider returns a fully populated fake for shape tests.
func richProvider() *fakeProvider {
	return &fakeProvider{
		metrics: Metrics{
			LifetimeReclaimedBytes: 10 << 30,
			LifetimeRestoredBytes:  4 << 30,
			CurrentlyParkedBytes:   8 << 30,
			ActiveWorkspaces:       7,
			ParkedWorkspaces:       3,
			SpaceEfficiencyRatio:   0.42,
			CleanDeskStreakDays:    12,
			HoardingScore:          Score{Grade: "B", Label: "casual collector"},
			ZombieBytesExorcised:   2 << 30,
			EstimatedSSDWearSaved:  1 << 30,
			TopCommands:            []CommandCount{{Command: "reclaim", Count: 21}, {Command: "park", Count: 9}},
			TotalInvocations:       77,
			TrackingSince:          "2024-01-02T03:04:05Z",
		},
		workspaces: []WorkspaceView{
			{Name: "alpha", Status: "active", Root: "C:\\dev\\alpha", Ecosystem: "go",
				LastActivity: "2026-09-01T10:00:00Z", ReclaimedBytes: 111, SizeBytes: 222},
			{Name: "beta", Status: "parked", Root: "/home/u/beta", Ecosystem: "node",
				LastActivity: "2026-08-01T10:00:00Z", ReclaimedBytes: 333, SizeBytes: 444},
		},
		history: []HistoryEvent{
			{TS: "2026-09-02T10:00:00Z", Command: "ebb reclaim C:\\dev\\alpha --yes", Workspace: "alpha",
				Outcome: "ok", BytesIn: 0, BytesOut: 5 << 20},
			{TS: "2026-09-01T09:00:00Z", Command: "ebb park /home/u/beta", Workspace: "beta",
				Outcome: "ok", BytesIn: 0, BytesOut: 9 << 20},
		},
		tree: map[string][]TreeEntryView{
			"deadbeefdeadbeef": {{Name: "cmd", Kind: "dir", Size: 0}, {Name: "main.go", Kind: "file", Size: 1234}},
		},
		recommendations: []RecommendationView{
			{Category: "stale", Root: "C:\\dev\\alpha", Reason: "untouched for 45 days",
				Command: "ebb reclaim C:\\dev\\alpha --yes", ReclaimableBytes: 5 << 20, Shielded: false},
			{Category: "worktrees", Root: "C:\\dev\\wt-x", Reason: "merged upstream; dirty worktree",
				Command: "", ReclaimableBytes: 1 << 20, Shielded: true},
		},
	}
}

// ---- helpers -----------------------------------------------------------------

const testPort = 18080

// doReq drives the real handler synchronously with a controlled Host.
func doReq(h http.Handler, method, target, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if host != "" {
		req.Host = host
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// doGet is doReq for GET with the canonical allowed host.
func doGet(h http.Handler, target string) *httptest.ResponseRecorder {
	return doReq(h, http.MethodGet, target, "127.0.0.1:"+itoa(testPort))
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// decodeError asserts the uniform JSON error envelope.
func decodeError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var payload map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body is not a JSON error envelope: %v (body=%q)", err, rec.Body.String())
	}
	if len(payload) != 1 {
		t.Fatalf("error envelope must have exactly one key, got %v", payload)
	}
	msg, ok := payload["error"]
	if !ok || msg == "" {
		t.Fatalf("error envelope missing non-empty error field: %v", payload)
	}
	return msg
}

// ---- security model #1: method matrix -------------------------------------------

func TestMethodMatrix(t *testing.T) {
	h := newServer(richProvider(), testPort, nil)
	paths := []string{
		"/",
		"/static/styles.css",
		"/api/overview",
		"/api/history",
		"/api/tree?id=deadbeefdeadbeef",
	}
	for _, path := range paths {
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
			rec := doReq(h, method, path, "localhost:"+itoa(testPort))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s: got status %d, want 405", method, path, rec.Code)
			}
			if got := rec.Header().Get("Allow"); got != "GET" {
				t.Errorf("%s %s: Allow header = %q, want %q", method, path, got, "GET")
			}
			decodeError(t, rec)
		}
	}
	// GET and HEAD answer with data everywhere.
	for _, path := range paths {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := doReq(h, method, path, "localhost:"+itoa(testPort))
			if rec.Code != http.StatusOK {
				t.Errorf("%s %s: got status %d, want 200", method, path, rec.Code)
			}
		}
	}
}

// HEAD must carry the same headers as GET but no body (the handler
// wraps itself in the same body-discard net/http applies).
func TestHeadCarriesHeadersNoBody(t *testing.T) {
	h := newServer(richProvider(), testPort, nil)
	get := doGet(h, "/api/overview")
	head := doReq(h, http.MethodHead, "/api/overview", "127.0.0.1:"+itoa(testPort))
	if head.Code != http.StatusOK {
		t.Fatalf("HEAD /api/overview: got status %d, want 200", head.Code)
	}
	if head.Body.Len() != 0 {
		t.Errorf("HEAD response must have no body, got %d bytes", head.Body.Len())
	}
	if got := head.Header().Get("Content-Type"); got != get.Header().Get("Content-Type") {
		t.Errorf("HEAD Content-Type = %q, want GET's %q", got, get.Header().Get("Content-Type"))
	}
}

// ---- security model #3: Host enforcement -------------------------------------------

func TestHostEnforcement(t *testing.T) {
	h := newServer(richProvider(), testPort, nil)
	cases := []struct {
		host string
		want int
	}{
		{"127.0.0.1", http.StatusOK},
		{"127.0.0.1:" + itoa(testPort), http.StatusOK},
		{"localhost", http.StatusOK},
		{"localhost:" + itoa(testPort), http.StatusOK},
		{"[::1]", http.StatusOK},
		{"[::1]:" + itoa(testPort), http.StatusOK},
		{"", http.StatusForbidden},
		{"evil.com", http.StatusForbidden},
		{"evil.com:" + itoa(testPort), http.StatusForbidden},
		{"sub.localhost", http.StatusForbidden},
		{"LOCALHOST", http.StatusForbidden}, // strict: browsers send lowercase
		{"127.0.0.1:" + itoa(testPort+1), http.StatusForbidden},
		{"localhost:0", http.StatusForbidden},
		{"10.0.0.1:80", http.StatusForbidden},
		{"192.168.1.5", http.StatusForbidden},
		{"127.0.0.2", http.StatusForbidden},
		{"::1", http.StatusForbidden}, // unbracketed IPv6 is not a valid Host form
		{"[::2]:" + itoa(testPort), http.StatusForbidden},
		{"[localhost]:" + itoa(testPort), http.StatusForbidden},
		{"127.0.0.1:abc", http.StatusForbidden},
		{":8080", http.StatusForbidden},
		{"127.0.0.1:8080:" + itoa(testPort), http.StatusForbidden},
	}
	for _, tc := range cases {
		rec := doReq(h, http.MethodGet, "/api/overview", tc.host)
		if rec.Code != tc.want {
			t.Errorf("Host %q: got status %d, want %d", tc.host, rec.Code, tc.want)
		}
		if tc.want == http.StatusForbidden {
			decodeError(t, rec)
		}
	}
}

// Host enforcement must also hold through a real TCP round trip with
// the server bound at its own port (Run's listener shape).
func TestHostEnforcementOverRealListener(t *testing.T) {
	p := richProvider()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	ts := httptest.NewUnstartedServer(newServer(p, port, nil))
	ts.Listener = ln
	ts.Start()
	defer ts.Close()

	evil, err := http.NewRequest(http.MethodGet, ts.URL+"/api/overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	evil.Host = "evil.com"
	resp, err := ts.Client().Do(evil)
	if err != nil {
		t.Fatalf("request with evil Host: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("evil Host over real listener: got %d, want 403", resp.StatusCode)
	}

	otherPort, err := http.NewRequest(http.MethodGet, ts.URL+"/api/overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPort.Host = fmt.Sprintf("127.0.0.1:%d", port+1)
	resp, err = ts.Client().Do(otherPort)
	if err != nil {
		t.Fatalf("request with wrong port: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong-port Host over real listener: got %d, want 403", resp.StatusCode)
	}

	resp, err = ts.Client().Get(ts.URL + "/api/overview")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("default Host over real listener: got %d, want 200", resp.StatusCode)
	}
}

// ---- /api/tree id validation ---------------------------------------------------------

func TestTreeIDValidation(t *testing.T) {
	p := richProvider()
	h := newServer(p, testPort, nil)
	valid := []string{"deadbeef", "aabbccddeeff0011", strings.Repeat("ab", 32)} // 8, 16, 64 hex
	for _, id := range valid {
		rec := doGet(h, "/api/tree?id="+id)
		if rec.Code != http.StatusOK {
			t.Errorf("id %q (len %d): got status %d, want 200", id, len(id), rec.Code)
		}
	}
	got := p.recordedTreeCalls()
	if len(got) != len(valid) {
		t.Fatalf("provider SnapshotTree called %d times, want %d", len(got), len(valid))
	}
	for i, id := range valid {
		if got[i] != id {
			t.Errorf("provider saw id %q, want %q", got[i], id)
		}
	}

	for _, id := range []string{"../x", "abc", "deadbeef;rm", strings.Repeat("a", 200), "deadbeef%20deadbeef", "0xdeadbeef"} {
		rec := doGet(h, "/api/tree?id="+id)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("id %q: got status %d, want 400", id, rec.Code)
		}
		decodeError(t, rec)
	}
	// Missing id entirely is a usage error too.
	rec := doGet(h, "/api/tree")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing id: got status %d, want 400", rec.Code)
	}
	if n := len(p.recordedTreeCalls()); n != len(valid) {
		t.Errorf("provider SnapshotTree called %d times after rejects, want still %d", n, len(valid))
	}
}

// ---- query strictness ------------------------------------------------------------------

func TestQueryValidation(t *testing.T) {
	h := newServer(richProvider(), testPort, nil)
	bad := []string{
		"/?foo=1",
		"/?refresh=1",
		"/api/overview?foo=1",
		"/api/overview?limit=5",
		"/api/history?limit=5&foo=1",
		"/api/history?foo=1",
		"/api/history?limit=1&limit=2",
		"/api/tree?id=deadbeefdeadbeef&extra=1",
		"/api/tree?id=deadbeefdeadbeef&id=deadbeefdeadbeef",
		"/static/styles.css?v=2",
		"/static/app.js?cache=bust",
	}
	for _, target := range bad {
		rec := doGet(h, target)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s: got status %d, want 400", target, rec.Code)
		}
		decodeError(t, rec)
	}
	good := []string{"/", "/api/overview", "/api/history?limit=7", "/static/styles.css"}
	for _, target := range good {
		rec := doGet(h, target)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %q: got status %d, want 200", target, rec.Code)
		}
	}
}

// ---- 404 + content types + security headers -----------------------------------------------

func TestNotFoundIsJSON(t *testing.T) {
	h := newServer(richProvider(), testPort, nil)
	for _, path := range []string{"/nope", "/api/nope", "/static/nope.css", "/static/", "/static/../styles.css", "/index.html", "/api/"} {
		rec := doGet(h, path)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: got status %d, want 404", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
			t.Errorf("GET %s: Content-Type = %q, want JSON", path, got)
		}
		decodeError(t, rec)
	}
}

func TestContentTypesAndSecurityHeaders(t *testing.T) {
	h := newServer(richProvider(), testPort, nil)
	cases := []struct {
		target      string
		contentType string
	}{
		{"/", "text/html; charset=utf-8"},
		{"/static/styles.css", "text/css; charset=utf-8"},
		{"/static/app.js", "text/javascript; charset=utf-8"},
		{"/static/logo.svg", "image/svg+xml"},
		{"/api/overview", "application/json; charset=utf-8"},
		{"/api/history", "application/json; charset=utf-8"},
		{"/api/tree?id=deadbeefdeadbeef", "application/json; charset=utf-8"},
		{"/api/nope", "application/json; charset=utf-8"},
	}
	for _, tc := range cases {
		rec := doGet(h, tc.target)
		if got := rec.Header().Get("Content-Type"); got != tc.contentType {
			t.Errorf("GET %s: Content-Type = %q, want %q", tc.target, got, tc.contentType)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("GET %s: X-Content-Type-Options = %q, want nosniff", tc.target, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s: Cache-Control = %q, want no-store", tc.target, got)
		}
		// Same-origin only: no CORS headers on anything.
		for k := range rec.Header() {
			if strings.HasPrefix(strings.ToLower(k), "access-control-") {
				t.Errorf("GET %s: unexpected CORS header %q", tc.target, k)
			}
		}
	}
}

// ---- embedded assets: present, non-empty, zero external URLs ---------------------------------

func scanExternalURLs(t *testing.T, name string, body []byte) {
	t.Helper()
	lower := strings.ToLower(string(body))
	for _, scheme := range []string{"http://", "https://"} {
		idx := 0
		for {
			i := strings.Index(lower[idx:], scheme)
			if i < 0 {
				break
			}
			start := idx + i
			// The single tolerated family: w3.org XML namespaces (SVG).
			if !strings.HasPrefix(lower[start:], "http://www.w3.org/") {
				end := start + 80
				if end > len(lower) {
					end = len(lower)
				}
				t.Errorf("%s: external URL reference at offset %d: %q", name, start, lower[start:end])
			}
			idx = start + len(scheme)
		}
	}
}

func TestAssetsEmbeddedNonEmptyAndLocalhostOnly(t *testing.T) {
	seen := map[string]bool{}
	err := fs.WalkDir(embeddedAssets, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		seen[p] = true
		b, rerr := embeddedAssets.ReadFile(p)
		if rerr != nil {
			t.Errorf("read embedded %s: %v", p, rerr)
			return nil
		}
		if len(b) == 0 {
			t.Errorf("embedded asset %s is empty", p)
		}
		scanExternalURLs(t, p, b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded assets: %v", err)
	}
	for _, want := range []string{"assets/index.html", "assets/styles.css", "assets/app.js", "assets/logo.svg"} {
		if !seen[want] {
			t.Errorf("embedded asset missing: %s (have %v)", want, seen)
		}
	}

	// The same scan over the bytes actually SERVED (index + every
	// static route).
	h := newServer(richProvider(), testPort, nil)
	var served []byte
	for _, target := range []string{"/", "/static/styles.css", "/static/app.js", "/static/logo.svg"} {
		rec := doGet(h, target)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", target, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s: served body is empty", target)
		}
		served = append(served, rec.Body.Bytes()...)
	}
	scanExternalURLs(t, "served bytes", served)

	// index.html must reference exactly the local static routes.
	html := string(indexHTML)
	for _, ref := range []string{`href="/static/logo.svg"`, `href="/static/styles.css"`, `src="/static/app.js"`} {
		if !strings.Contains(html, ref) {
			t.Errorf("index.html missing local asset reference %q", ref)
		}
	}
}

// ---- JSON shape contracts ---------------------------------------------------------------------

func TestMetricsMirrorJSONTags(t *testing.T) {
	m := Metrics{
		LifetimeReclaimedBytes: 1, LifetimeRestoredBytes: 2, CurrentlyParkedBytes: 3,
		ActiveWorkspaces: 4, ParkedWorkspaces: 5, SpaceEfficiencyRatio: 0.5,
		CleanDeskStreakDays:  6,
		HoardingScore:        Score{Grade: "A", Label: "tidy"},
		ZombieBytesExorcised: 7, EstimatedSSDWearSaved: 8,
		TopCommands:      []CommandCount{{Command: "reclaim", Count: 9}},
		TotalInvocations: 10, TrackingSince: "2024-01-01T00:00:00Z",
	}
	got, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"lifetime_reclaimed_bytes":1,"lifetime_restored_bytes":2,"currently_parked_bytes":3,` +
		`"active_workspaces":4,"parked_workspaces":5,"space_efficiency_ratio":0.5,` +
		`"clean_desk_streak_days":6,"hoarding_score":{"grade":"A","label":"tidy"},` +
		`"zombie_gb_exorcised":7,"estimated_ssd_wear_saved":8,` +
		`"top_commands":[{"command":"reclaim","count":9}],"total_invocations":10,` +
		`"tracking_since":"2024-01-01T00:00:00Z"}`
	if string(got) != want {
		t.Errorf("Metrics JSON tags drifted:\n got %s\nwant %s", got, want)
	}
}

func TestOverviewJSONShape(t *testing.T) {
	p := richProvider()
	h := newServer(p, testPort, nil)
	rec := doGet(h, "/api/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatalf("overview is not JSON: %v", err)
	}
	for _, key := range []string{"metrics", "comparison_reclaimed", "comparison_restored", "workspaces", "recommendations"} {
		if _, ok := top[key]; !ok {
			t.Errorf("overview missing key %q (has %v)", key, keysOf(top))
		}
	}
	if len(top) != 5 {
		t.Errorf("overview has %d keys, want exactly 5: %v", len(top), keysOf(top))
	}

	// metrics sub-object carries the frozen tag set 1:1.
	var metrics map[string]json.RawMessage
	if err := json.Unmarshal(top["metrics"], &metrics); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"lifetime_reclaimed_bytes", "lifetime_restored_bytes", "currently_parked_bytes",
		"active_workspaces", "parked_workspaces", "space_efficiency_ratio",
		"clean_desk_streak_days", "hoarding_score", "zombie_gb_exorcised",
		"estimated_ssd_wear_saved", "top_commands", "total_invocations", "tracking_since",
	} {
		if _, ok := metrics[key]; !ok {
			t.Errorf("metrics missing key %q", key)
		}
	}
	var score map[string]json.RawMessage
	if err := json.Unmarshal(metrics["hoarding_score"], &score); err != nil {
		t.Fatal(err)
	}
	if _, ok := score["grade"]; !ok {
		t.Error("hoarding_score missing grade")
	}
	if _, ok := score["label"]; !ok {
		t.Error("hoarding_score missing label")
	}

	// Comparisons are provider-derived from the lifetime totals with
	// rotation = TotalInvocations (spec: /api/overview).
	calls := p.recordedCmpCalls()
	if len(calls) != 2 {
		t.Fatalf("ComparisonForBytes called %d times, want 2", len(calls))
	}
	if calls[0].n != p.metrics.LifetimeReclaimedBytes {
		t.Errorf("comparison #1 bytes = %d, want LifetimeReclaimedBytes %d", calls[0].n, p.metrics.LifetimeReclaimedBytes)
	}
	if calls[1].n != p.metrics.LifetimeRestoredBytes {
		t.Errorf("comparison #2 bytes = %d, want LifetimeRestoredBytes %d", calls[1].n, p.metrics.LifetimeRestoredBytes)
	}
	for i, c := range calls {
		if c.rot != uint64(p.metrics.TotalInvocations) {
			t.Errorf("comparison #%d rotation = %d, want TotalInvocations %d", i+1, c.rot, p.metrics.TotalInvocations)
		}
	}

	// Workspace rows carry the view fields.
	var ws []map[string]json.RawMessage
	if err := json.Unmarshal(top["workspaces"], &ws); err != nil {
		t.Fatal(err)
	}
	if len(ws) != 2 {
		t.Fatalf("workspaces len = %d, want 2", len(ws))
	}
	for _, key := range []string{"name", "status", "root", "ecosystem", "last_activity", "reclaimed_bytes", "size_bytes"} {
		if _, ok := ws[0][key]; !ok {
			t.Errorf("workspace row missing key %q", key)
		}
	}

	// Recommendations carry category/root/reason/command/reclaimable_bytes/shielded.
	var recs []map[string]json.RawMessage
	if err := json.Unmarshal(top["recommendations"], &recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("recommendations len = %d, want 2", len(recs))
	}
	for _, key := range []string{"category", "root", "reason", "command", "reclaimable_bytes", "shielded"} {
		if _, ok := recs[0][key]; !ok {
			t.Errorf("recommendation missing key %q", key)
		}
	}
}

// A negative TotalInvocations (corrupt ledger) must degrade to rotation
// 0, not wrap to a huge uint64.
func TestOverviewRotationClampsNegativeInvocations(t *testing.T) {
	p := richProvider()
	p.metrics.TotalInvocations = -3
	h := newServer(p, testPort, nil)
	rec := doGet(h, "/api/overview")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	for i, c := range p.recordedCmpCalls() {
		if c.rot != 0 {
			t.Errorf("comparison #%d rotation = %d, want 0", i+1, c.rot)
		}
	}
}

func TestHistoryJSONShapeAndLimitClamping(t *testing.T) {
	p := richProvider()
	h := newServer(p, testPort, nil)

	// Shape: {"events":[...]} with the frozen event fields.
	rec := doGet(h, "/api/history?limit=10")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatal(err)
	}
	if len(top) != 1 {
		t.Fatalf("history payload keys = %v, want exactly [events]", keysOf(top))
	}
	var events []map[string]json.RawMessage
	if err := json.Unmarshal(top["events"], &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events len = %d, want 2", len(events))
	}
	for _, key := range []string{"ts", "command", "workspace", "outcome", "bytes_in", "bytes_out"} {
		if _, ok := events[0][key]; !ok {
			t.Errorf("history event missing key %q", key)
		}
	}

	// Clamping: 0/omitted → default 500; big → cap 5000; explicit → exact.
	cases := []struct {
		param string
		want  int
	}{
		{"", defaultHistoryLimit},
		{"0", defaultHistoryLimit},
		{"1", 1},
		{"42", 42},
		{"5000", maxHistoryLimit},
		{"99999", maxHistoryLimit},
		{"+12+", 12}, // query "+" decodes to space; server trims it
	}
	for _, tc := range cases {
		p.mu.Lock()
		p.historyCalls = nil
		p.mu.Unlock()
		target := "/api/history"
		if tc.param != "" {
			target += "?limit=" + tc.param
		}
		rec := doGet(h, target)
		if rec.Code != http.StatusOK {
			t.Errorf("limit=%q: status %d, want 200", tc.param, rec.Code)
			continue
		}
		calls := p.recordedHistoryCalls()
		if len(calls) != 1 || calls[0] != tc.want {
			t.Errorf("limit=%q: provider saw %v, want [%d]", tc.param, calls, tc.want)
		}
	}

	// Invalid limits are usage errors.
	for _, param := range []string{"-5", "abc", "3.5", ""} {
		rec := doGet(h, "/api/history?limit="+param)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%q: status %d, want 400", param, rec.Code)
		}
		decodeError(t, rec)
	}

	// An empty ledger marshals as [], never null.
	empty := &fakeProvider{}
	rec = doGet(newServer(empty, testPort, nil), "/api/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"events":[]`) {
		t.Errorf("empty history must marshal as [], got %s", rec.Body.String())
	}
}

func TestTreeJSONShape(t *testing.T) {
	h := newServer(richProvider(), testPort, nil)
	rec := doGet(h, "/api/tree?id=deadbeefdeadbeef")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &top); err != nil {
		t.Fatal(err)
	}
	if len(top) != 2 {
		t.Fatalf("tree payload keys = %v, want exactly [id entries]", keysOf(top))
	}
	var id string
	if err := json.Unmarshal(top["id"], &id); err != nil || id != "deadbeefdeadbeef" {
		t.Fatalf("tree id = %q err=%v, want deadbeefdeadbeef", id, err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(top["entries"], &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(entries))
	}
	for _, key := range []string{"name", "kind", "size"} {
		if _, ok := entries[0][key]; !ok {
			t.Errorf("tree entry missing key %q", key)
		}
	}

	// Unknown id marshals as [] entries, never null.
	rec = doGet(h, "/api/tree?id=00000000")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"entries":[]`) {
		t.Errorf("empty tree must marshal as [], got %s", rec.Body.String())
	}
}

// ---- provider failures are the only 500s --------------------------------------------------------

func TestProviderErrorsAreJSON500(t *testing.T) {
	cases := []struct {
		name   string
		prov   *fakeProvider
		target string
		want   string
	}{
		{"metrics", &fakeProvider{metricsErr: errors.New("ledger unreadable")}, "/api/overview", "metrics"},
		{"workspaces", &fakeProvider{workspacesErr: errors.New("catalog busy")}, "/api/overview", "workspaces"},
		{"recommendations", &fakeProvider{recommendationsErr: errors.New("scan stale")}, "/api/overview", "recommendations"},
		{"history", &fakeProvider{historyErr: errors.New("ledger locked")}, "/api/history", "history"},
		{"tree", &fakeProvider{treeErr: errors.New("backend unavailable")}, "/api/tree?id=deadbeefdeadbeef", "snapshot tree"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doGet(newServer(tc.prov, testPort, nil), tc.target)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
				t.Errorf("Content-Type = %q, want JSON", got)
			}
			msg := decodeError(t, rec)
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error %q does not name the failing facet %q", msg, tc.want)
			}
		})
	}
}

// ---- request logging (method, path, status — never bodies) ------------------------------------------

func TestRequestLoggingNeverBodies(t *testing.T) {
	var log strings.Builder
	h := newServer(richProvider(), testPort, func(format string, args ...any) {
		fmt.Fprintf(&log, format+"\n", args...)
	})
	doGet(h, "/api/overview")
	doGet(h, "/api/nope")
	doReq(h, http.MethodPost, "/api/overview", "127.0.0.1:"+itoa(testPort))
	out := log.String()
	for _, want := range []string{"GET /api/overview 200\n", "GET /api/nope 404\n", "POST /api/overview 405\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("request log missing %q; log=%q", want, out)
		}
	}
	// The sentinel metric value must never appear — bodies are not logged.
	if strings.Contains(out, "casual collector") {
		t.Errorf("request log leaked a response body value: %q", out)
	}
}

// ---- helpers ----------------------------------------------------------------------------------------

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
