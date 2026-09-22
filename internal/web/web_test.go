// web_test.go exercises the Run lifecycle: loopback-only bind on an
// ephemeral port, the per-run URL token in the serving-at line (64 hex
// chars, unique per invocation), the tokened serving URL, the
// browser-launch seam (exactly once, with the tokened URL, failure
// non-fatal), Host enforcement and the token gate through the real
// listener, request logging to Options.Err and the bounded clean
// shutdown on context cancellation.

package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// startRun launches Run in a goroutine and waits for the "serving at"
// progress line, returning the bound base URL and a stop function that
// cancels the context and asserts a bounded, nil-error return.
func startRun(t *testing.T, p Provider, o Options) (baseURL string, stop func()) {
	t.Helper()
	if o.Out == nil {
		o.Out = io.Discard
	}
	out, ok := o.Out.(*strings.Builder)
	if !ok {
		out = &strings.Builder{}
		o.Out = out
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, p, o) }()

	deadline := time.Now().Add(2 * time.Second)
	line := ""
	for time.Now().Before(deadline) {
		if s := out.String(); strings.Contains(s, "serving at ") {
			line = strings.TrimSpace(strings.SplitN(s, "serving at ", 2)[1])
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if line == "" {
		cancel()
		t.Fatal("Run never printed the serving-at line within 2s")
	}

	stop = func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned error after shutdown: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("Run did not return within 2s of context cancellation")
		}
	}
	return line, stop
}

func TestRunServesLoopbackAndShutsDown(t *testing.T) {
	p := richProvider()
	baseURL, stop := startRun(t, p, Options{Out: &strings.Builder{}})
	defer stop()

	// The bound address is exactly 127.0.0.1 with a real ephemeral port,
	// and the URL path carries the per-run token in its canonical form
	// /<64 lowercase hex chars>/.
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("serving line is not a URL: %q: %v", baseURL, err)
	}
	if u.Hostname() != "127.0.0.1" {
		t.Errorf("bound host = %q, want 127.0.0.1", u.Hostname())
	}
	if u.Port() == "" || u.Port() == "0" {
		t.Errorf("bound port = %q, want a real ephemeral port", u.Port())
	}
	token := strings.Trim(u.Path, "/")
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(token) {
		t.Errorf("serving URL path = %q, want /<64 lowercase hex chars>/ (the per-run token)", u.Path)
	}

	// Data is served end-to-end through the real listener, under the token.
	resp, err := http.Get(baseURL + "api/overview")
	if err != nil {
		t.Fatalf("GET /api/overview: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/overview: status %d, want 200", resp.StatusCode)
	}
	var payload overviewPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("overview decode: %v", err)
	}
	if payload.Metrics.ActiveWorkspaces != p.metrics.ActiveWorkspaces {
		t.Errorf("overview carried ActiveWorkspaces %d, want %d",
			payload.Metrics.ActiveWorkspaces, p.metrics.ActiveWorkspaces)
	}
}

// tokenOf extracts the per-run token from a serving URL (the single
// 64-hex path segment).
func tokenOf(t *testing.T, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse %q: %v", baseURL, err)
	}
	return strings.Trim(u.Path, "/")
}

// Every Run invocation must mint a DIFFERENT unguessable token: two
// sequential servers (each started and stopped through startRun, so
// there is no timing race) carry distinct 64-hex path segments — the
// entropy sanity for the local-reader gate.
func TestRunMintsUniqueTokens(t *testing.T) {
	u1, stop1 := startRun(t, richProvider(), Options{Out: &strings.Builder{}})
	tok1 := tokenOf(t, u1)
	stop1()

	u2, stop2 := startRun(t, richProvider(), Options{Out: &strings.Builder{}})
	tok2 := tokenOf(t, u2)
	defer stop2()

	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for name, tok := range map[string]string{"first": tok1, "second": tok2} {
		if !hex64.MatchString(tok) {
			t.Errorf("%s token %q is not 64 lowercase hex chars", name, tok)
		}
	}
	if tok1 == tok2 {
		t.Errorf("two Run invocations minted the same token %q — the per-run gate would be guessable across sessions", tok1)
	}
}

// The token is the local-reader gate over the REAL listener: a request
// that reaches the loopback origin but drops the token path — the exact
// shape a co-located scanner sends — is refused on every surface,
// while the same request under the token succeeds.
func TestRunTokenlessRequestsRefused(t *testing.T) {
	baseURL, stop := startRun(t, richProvider(), Options{Out: &strings.Builder{}})
	defer stop()

	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse %q: %v", baseURL, err)
	}
	origin := u.Scheme + "://" + u.Host // loopback origin, no path
	client := &http.Client{Timeout: 2 * time.Second}
	for _, path := range []string{"/", "/api/overview", "/api/history", "/static/app.js"} {
		resp, err := client.Get(origin + path)
		if err != nil {
			t.Fatalf("tokenless GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("tokenless GET %s: status %d, want 403 (body %s)", path, resp.StatusCode, body)
		}
		if strings.Contains(string(body), `"workspaces"`) {
			t.Errorf("tokenless GET %s leaked metadata: %s", path, body)
		}
	}
	// The port-less Host spelling changes nothing: the token, not the
	// port, is the gate.
	req, err := http.NewRequest(http.MethodGet, origin+"/api/overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "127.0.0.1"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("tokenless GET with port-less Host: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("tokenless GET with port-less Host: status %d, want 403", resp.StatusCode)
	}
}

// Shutdown must be bounded: stop() itself asserts Run returns within
// 2s of cancellation with a nil error.
func TestRunShutdownTimeBounded(t *testing.T) {
	_, stop := startRun(t, richProvider(), Options{Out: &strings.Builder{}})
	stop()
}

func TestRunBrowserLaunchSeam(t *testing.T) {
	t.Run("launched exactly once with the exact URL", func(t *testing.T) {
		seen := make(chan string, 4)
		baseURL, stop := startRun(t, richProvider(), Options{
			Out:         &strings.Builder{},
			OpenBrowser: true,
			LaunchBrowser: func(u string) error {
				seen <- u
				return nil
			},
		})
		defer stop()

		select {
		case got := <-seen:
			if got != baseURL {
				t.Errorf("LaunchBrowser got %q, want %q", got, baseURL)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("LaunchBrowser was never called")
		}
		// Still serving after the launch.
		resp, err := http.Get(baseURL + "api/overview")
		if err != nil {
			t.Fatalf("GET after launch: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET after launch: status %d, want 200", resp.StatusCode)
		}
		select {
		case extra := <-seen:
			t.Errorf("LaunchBrowser called more than once (extra %q)", extra)
		case <-time.After(300 * time.Millisecond):
		}
	})

	t.Run("launch failure is non-fatal", func(t *testing.T) {
		var errLog strings.Builder
		baseURL, stop := startRun(t, richProvider(), Options{
			Out:         &strings.Builder{},
			Err:         &errLog,
			OpenBrowser: true,
			LaunchBrowser: func(string) error {
				return errors.New("no desktop")
			},
		})
		defer stop()
		resp, err := http.Get(baseURL + "api/overview")
		if err != nil {
			t.Fatalf("GET after failed launch: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET after failed launch: status %d, want 200", resp.StatusCode)
		}
		if !strings.Contains(errLog.String(), "opening browser failed") {
			t.Errorf("launch failure not logged to Err: %q", errLog.String())
		}
	})
}

// Host enforcement and the 405 contract through Run's own listener,
// with tampered Host headers on the wire.
func TestRunSecurityOverRealListener(t *testing.T) {
	baseURL, stop := startRun(t, richProvider(), Options{Out: &strings.Builder{}})
	defer stop()

	client := &http.Client{Timeout: 2 * time.Second}
	hosts := map[string]int{
		"evil.com":        http.StatusForbidden,
		"sub.localhost:1": http.StatusForbidden,
		fmt.Sprintf("10.0.0.1:%s", mustPort(t, baseURL)): http.StatusForbidden,
		"localhost":                     http.StatusOK,
		"[::1]:" + mustPort(t, baseURL): http.StatusOK,
	}
	for host, want := range hosts {
		req, err := http.NewRequest(http.MethodGet, baseURL+"api/overview", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET with Host %q: %v", host, err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("GET with Host %q: status %d, want %d", host, resp.StatusCode, want)
		}
	}

	// Mutation verbs stay refused over the real listener too.
	req, err := http.NewRequest(http.MethodDelete, baseURL+"api/overview", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: status %d, want 405", resp.StatusCode)
	}
	if allow := resp.Header.Get("Allow"); allow != "GET" {
		t.Errorf("DELETE Allow header = %q, want GET", allow)
	}
}

func TestRunLogsRequestsToErr(t *testing.T) {
	var errLog strings.Builder
	baseURL, stop := startRun(t, richProvider(), Options{
		Out: &strings.Builder{},
		Err: &errLog,
	})
	defer stop()

	resp, err := http.Get(baseURL + "api/overview")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(errLog.String(), "GET /api/overview 200") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(errLog.String(), "GET /api/overview 200") {
		t.Errorf("request log line missing; Err=%q", errLog.String())
	}
	// Bodies never reach the log (the fake's hoarding label is payload
	// data)...
	if strings.Contains(errLog.String(), "casual collector") {
		t.Errorf("request log leaked payload: %q", errLog.String())
	}
	// ...and neither does the per-run token: request lines carry the
	// token-stripped path, so the token appears exactly once per Run —
	// in the serving-at line — and never in the paste-prone log.
	if strings.Contains(errLog.String(), tokenOf(t, baseURL)) {
		t.Errorf("request log leaked the per-run token: %q", errLog.String())
	}
}

func TestRunNilProviderFails(t *testing.T) {
	if err := Run(context.Background(), nil, Options{}); err == nil {
		t.Error("Run(nil provider) must fail, got nil")
	}
}

func mustPort(t *testing.T, baseURL string) string {
	t.Helper()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse %q: %v", baseURL, err)
	}
	return u.Port()
}
