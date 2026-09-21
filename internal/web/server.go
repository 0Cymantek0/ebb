// server.go is the complete HTTP surface of the Control Center: a
// GET-only handler with Host-header enforcement (DNS-rebinding
// immunity), strict query validation, JSON error envelopes and
// go:embed-ed assets. Run constructs it with the bound port; tests
// construct it directly with an injected port.
//
// The surface in full (everything GET, everything read-only):
//
//	/                  → embedded index.html
//	/static/*          → embedded css/js/svg (fixed set, map-served —
//	                    no filesystem lookup, so traversal is impossible)
//	/api/overview      → {metrics, comparison_reclaimed,
//	                    comparison_restored, workspaces, recommendations}
//	/api/history?limit → {events:[...]} (default 500, cap 5000, min 1)
//	/api/tree?id=hex   → {id, entries:[...]} (id: 8-64 hex chars)

package web

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// Endpoint paths (the complete route table).
const (
	pathIndex    = "/"
	pathOverview = "/api/overview"
	pathHistory  = "/api/history"
	pathTree     = "/api/tree"
	staticPrefix = "/static/"
)

// History paging contract: default 500, hard cap 5000. 0 (or omitted)
// selects the default; negatives and non-numbers are usage errors; the
// server always passes an explicit positive limit to the Provider.
const (
	defaultHistoryLimit = 500
	maxHistoryLimit     = 5000
)

// snapIDPattern is the ONLY accepted snapshot id shape: 8-64 hex
// characters. It excludes traversal, separators and shell
// metacharacters by construction ("deadbeef;rm" fails, as does anything
// with a dot).
var snapIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8,64}$`)

// server is the Control Center HTTP handler. port is the actual port of
// the listener it is served from; every request's Host header must name
// 127.0.0.1 / localhost / [::1] with exactly that port. logf receives
// one line per request (method, path, status — never bodies); nil
// disables logging.
type server struct {
	provider Provider
	port     int
	logf     func(format string, args ...any)
}

// newServer builds the handler for a provider serving on the given
// local port.
func newServer(p Provider, port int, logf func(string, ...any)) http.Handler {
	return &server{provider: p, port: port, logf: logf}
}

// statusRecorder captures the response status for request logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// bodyless discards body writes while keeping headers — the wrapper
// net/http's real server applies to HEAD responses, mirrored here so
// direct-handler tests observe identical behavior.
type bodyless struct{ http.ResponseWriter }

func (bodyless) Write(p []byte) (int, error) { return len(p), nil }

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	// Hardening headers on EVERY response, errors included. No CORS
	// headers are ever set: same-origin only.
	rec.Header().Set("X-Content-Type-Options", "nosniff")
	rec.Header().Set("Cache-Control", "no-store")
	defer func() {
		if s.logf != nil {
			s.logf("%s %s %d", r.Method, r.URL.Path, rec.status)
		}
	}()

	// Security model #3: DNS-rebinding immunity — the Host header must
	// name this exact loopback listener before anything else is even
	// looked at.
	if !allowedHost(r.Host, s.port) {
		s.writeError(rec, http.StatusForbidden, "forbidden: host does not name this local listener")
		return
	}
	// Security model #1: GET-only (HEAD shares the headers, no body).
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		rec.Header().Set("Allow", "GET")
		s.writeError(rec, http.StatusMethodNotAllowed, "method not allowed: this dashboard is strictly read-only (GET only)")
		return
	}

	out := http.ResponseWriter(rec)
	if r.Method == http.MethodHead {
		out = bodyless{rec}
	}

	switch r.URL.Path {
	case pathIndex:
		if !s.checkQuery(out, r) {
			return
		}
		s.serveAsset(out, indexHTML, "text/html; charset=utf-8")
	case pathOverview:
		if !s.checkQuery(out, r) {
			return
		}
		s.handleOverview(out)
	case pathHistory:
		if !s.checkQuery(out, r, "limit") {
			return
		}
		s.handleHistory(out, r)
	case pathTree:
		if !s.checkQuery(out, r, "id") {
			return
		}
		s.handleTree(out, r)
	default:
		if strings.HasPrefix(r.URL.Path, staticPrefix) {
			s.handleStatic(out, r)
			return
		}
		s.writeError(out, http.StatusNotFound, "not found: "+r.URL.Path)
	}
}

// ---- static + index ------------------------------------------------------

// handleStatic serves the fixed embedded asset set. The name is only
// ever a map key — there is no filesystem lookup, so path traversal has
// nothing to traverse.
func (s *server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, staticPrefix)
	a, ok := staticAssets[name]
	if !ok {
		s.writeError(w, http.StatusNotFound, "not found: "+r.URL.Path)
		return
	}
	if !s.checkQuery(w, r) {
		return
	}
	s.serveAsset(w, a.body, a.contentType)
}

// serveAsset writes pre-loaded embedded bytes with a fixed
// Content-Type (never sniffed, never filesystem-backed).
func (s *server) serveAsset(w http.ResponseWriter, body []byte, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// ---- /api/overview --------------------------------------------------------

// overviewPayload is the /api/overview body: the whole dashboard in one
// GET — metrics, the two quirky comparisons (keyed off the lifetime
// totals, rotation seeded by total invocations), the workspace roster
// and the analyse recommendations.
type overviewPayload struct {
	Metrics             Metrics              `json:"metrics"`
	ComparisonReclaimed Comparison           `json:"comparison_reclaimed"`
	ComparisonRestored  Comparison           `json:"comparison_restored"`
	Workspaces          []WorkspaceView      `json:"workspaces"`
	Recommendations     []RecommendationView `json:"recommendations"`
}

func (s *server) handleOverview(w http.ResponseWriter) {
	m, err := s.provider.Metrics()
	if err != nil {
		s.writeProviderError(w, "metrics", err)
		return
	}
	ws, err := s.provider.Workspaces()
	if err != nil {
		s.writeProviderError(w, "workspaces", err)
		return
	}
	recs, err := s.provider.Recommendations()
	if err != nil {
		s.writeProviderError(w, "recommendations", err)
		return
	}
	rotation := uint64(0)
	if m.TotalInvocations > 0 {
		rotation = uint64(m.TotalInvocations)
	}
	if ws == nil {
		ws = []WorkspaceView{}
	}
	if recs == nil {
		recs = []RecommendationView{}
	}
	s.writeJSON(w, http.StatusOK, overviewPayload{
		Metrics:             m,
		ComparisonReclaimed: s.provider.ComparisonForBytes(m.LifetimeReclaimedBytes, rotation),
		ComparisonRestored:  s.provider.ComparisonForBytes(m.LifetimeRestoredBytes, rotation),
		Workspaces:          ws,
		Recommendations:     recs,
	})
}

// ---- /api/history ---------------------------------------------------------

// historyPayload is the /api/history body.
type historyPayload struct {
	Events []HistoryEvent `json:"events"`
}

func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	limit := defaultHistoryLimit
	if vals, ok := r.URL.Query()["limit"]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(vals[0]))
		if err != nil || n < 0 {
			s.writeError(w, http.StatusBadRequest,
				"invalid limit: provide an integer between 1 and 5000 (0 or omitted = default 500)")
			return
		}
		if n == 0 {
			n = defaultHistoryLimit
		}
		if n > maxHistoryLimit {
			n = maxHistoryLimit
		}
		limit = n
	}
	events, err := s.provider.History(limit)
	if err != nil {
		s.writeProviderError(w, "history", err)
		return
	}
	if events == nil {
		events = []HistoryEvent{}
	}
	s.writeJSON(w, http.StatusOK, historyPayload{Events: events})
}

// ---- /api/tree ------------------------------------------------------------

// treePayload is the /api/tree body.
type treePayload struct {
	ID      string          `json:"id"`
	Entries []TreeEntryView `json:"entries"`
}

func (s *server) handleTree(w http.ResponseWriter, r *http.Request) {
	vals, ok := r.URL.Query()["id"]
	if !ok || len(vals) != 1 || !snapIDPattern.MatchString(vals[0]) {
		s.writeError(w, http.StatusBadRequest,
			"invalid snapshot id: expected 8 to 64 hexadecimal characters")
		return
	}
	id := vals[0]
	entries, err := s.provider.SnapshotTree(id)
	if err != nil {
		s.writeProviderError(w, "snapshot tree", err)
		return
	}
	if entries == nil {
		entries = []TreeEntryView{}
	}
	s.writeJSON(w, http.StatusOK, treePayload{ID: id, Entries: entries})
}

// ---- shared helpers -------------------------------------------------------

// checkQuery enforces the strict query contract: on known paths only
// the listed parameters (each exactly once) are accepted; anything else
// is a 400 usage error. Called with no allowed names it means "no
// parameters at all" (/, /static/*, /api/overview).
func (s *server) checkQuery(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for name, vals := range r.URL.Query() {
		if !sliceContains(allowed, name) {
			s.writeError(w, http.StatusBadRequest, "unknown query parameter: "+name)
			return false
		}
		if len(vals) != 1 {
			s.writeError(w, http.StatusBadRequest, "repeated query parameter: "+name)
			return false
		}
	}
	return true
}

// writeJSON emits an API response: application/json with charset;
// nosniff and no-store were already set by ServeHTTP. Body writes
// during HEAD are discarded by the bodyless wrapper.
func (s *server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError is the uniform JSON error envelope {"error": "..."}.
func (s *server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, struct {
		Error string `json:"error"`
	}{Error: msg})
}

// writeProviderError reports a failed data read as a JSON 500 prefixed
// by the facet name; provider errors are the only 500s this surface
// can produce.
func (s *server) writeProviderError(w http.ResponseWriter, facet string, err error) {
	s.writeError(w, http.StatusInternalServerError, facet+": "+err.Error())
}

// sliceContains reports whether the list holds s (case list is tiny;
// no generality needed).
func sliceContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// ---- Host enforcement -----------------------------------------------------

// allowedHost reports whether the request's Host header names exactly
// this listener: 127.0.0.1, localhost or [::1], each optionally with
// the bound port. Any other host — a rebound DNS name, another port,
// an address the listener does not serve — fails closed (the handler
// answers 403 before routing anything).
func allowedHost(host string, port int) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	name, portStr := host, ""
	if strings.HasPrefix(host, "[") {
		// Bracketed form: only the IPv6 loopback literal is acceptable.
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return false
		}
		name = host[1:end]
		if name != "::1" {
			return false
		}
		rest := host[end+1:]
		if rest != "" {
			if rest[0] != ':' {
				return false
			}
			portStr = rest[1:]
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		name, portStr = host[:i], host[i+1:]
	}
	switch name {
	case "127.0.0.1", "localhost", "::1":
	default:
		return false
	}
	if portStr == "" {
		return true // the port is optional in a Host header
	}
	p, err := strconv.Atoi(portStr)
	return err == nil && p == port
}
