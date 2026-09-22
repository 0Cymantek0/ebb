package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// entry is a test entry on the main root.
func entry(path string, kind domain.EntryKind, route domain.Route, size int64, evidence ...string) domain.Entry {
	return domain.Entry{
		Root:        domain.RootMain,
		Path:        path,
		Kind:        kind,
		Route:       route,
		LogicalSize: size,
		Ownership:   domain.OwnershipOwned,
		Sensitivity: domain.SensitivityOrdinary,
		Evidence:    evidence,
	}
}

// testPolicy returns a valid policy with one pnpm group over
// node_modules, one custom group over dist, a preserve rule and a
// sensitive rule.
func testPolicy() Policy {
	return Policy{
		Version:   1,
		Workspace: Workspace{Name: "t"},
		Rules:     Rules{Network: NetworkApprovedActions, Unknown: UnknownPreserve},
		Preserve: []Preserve{
			{Patterns: []string{"research/**"}, Reason: "original material"},
		},
		Sensitive: []Sensitive{
			{Paths: []string{".env"}, Patterns: []string{".env.*"}},
		},
		Regenerate: []Regenerate{
			{ID: "node-deps", Adapter: AdapterPNPM, Root: ".", Outputs: []string{"node_modules"},
				Inputs: []string{"package.json", "pnpm-lock.yaml"}, Network: GroupNetworkAllowed},
			{ID: "build-dist", Adapter: AdapterCustom, Root: ".", Outputs: []string{"dist"},
				Inputs: []string{"package.json"}, Network: GroupNetworkOfflineArtifacts,
				Command: []string{"make", "dist"}},
		},
	}
}

func findEntry(t *testing.T, res Resolved, path string) domain.Entry {
	t.Helper()
	for _, e := range res.Entries {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("entry %q not found", path)
	return domain.Entry{}
}

func findGroup(res Resolved, id string) (GroupDecision, bool) {
	for _, g := range res.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return GroupDecision{}, false
}

// TestResolveRouting is the main route table: precedence from preserve
// and reconstruct down to the conservative default.
func TestResolveRouting(t *testing.T) {
	pol := testPolicy()
	entries := []domain.Entry{
		entry("package.json", domain.KindFile, "", 200, "git:tracked"),
		entry("pnpm-lock.yaml", domain.KindFile, "", 400, "git:tracked"),
		entry(".env", domain.KindFile, "", 50),
		entry(".env.prod", domain.KindFile, "", 60),
		entry("research", domain.KindDir, "", 0),
		entry("research/notes.md", domain.KindFile, "", 1000),
		entry("node_modules", domain.KindDir, "", 0),
		entry("node_modules/.pnpm/x/index.js", domain.KindFile, "", 3000000),
		entry("dist", domain.KindDir, "", 0),
		entry("dist/app.js", domain.KindFile, "", 500000),
		entry("src/main.go", domain.KindFile, "", 5000, "git:tracked"),
		entry("untracked/thing.bin", domain.KindFile, "", 700),
	}

	res, err := Resolve(entries, pol)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	cases := []struct {
		path      string
		wantRoute domain.Route
		wantSens  domain.Sensitivity
		wantEv    string // evidence substring
	}{
		{"package.json", domain.RoutePreserve, domain.SensitivityOrdinary, "policy:regenerate-input=build-dist"}, // first group by id
		{"pnpm-lock.yaml", domain.RoutePreserve, domain.SensitivityOrdinary, "policy:regenerate-input=node-deps"},
		{".env", domain.RoutePreserve, domain.SensitivitySensitive, "policy:sensitive=sensitive[0].paths[0]"},
		{".env.prod", domain.RoutePreserve, domain.SensitivitySensitive, "policy:sensitive=sensitive[0].patterns[0]"},
		{"research/notes.md", domain.RoutePreserve, domain.SensitivityOrdinary, "policy:preserve=preserve[0].patterns[0]"},
		{"research", domain.RoutePreserve, domain.SensitivityOrdinary, "policy:preserve=preserve[0].patterns[0]"},
		{"node_modules/.pnpm/x/index.js", domain.RouteReconstruct, domain.SensitivityOrdinary, "policy:regenerate=node-deps"},
		{"dist/app.js", domain.RouteReconstruct, domain.SensitivityOrdinary, "policy:regenerate=build-dist"},
		{"src/main.go", domain.RoutePreserve, domain.SensitivityOrdinary, "policy:default-preserve"},
		{"untracked/thing.bin", domain.RoutePreserve, domain.SensitivityOrdinary, "policy:default-preserve"},
	}
	for _, tt := range cases {
		e := findEntry(t, res, tt.path)
		if e.Route != tt.wantRoute {
			t.Errorf("%s: route = %q, want %q", tt.path, e.Route, tt.wantRoute)
		}
		if e.Sensitivity != tt.wantSens {
			t.Errorf("%s: sensitivity = %q, want %q", tt.path, e.Sensitivity, tt.wantSens)
		}
		found := false
		for _, ev := range e.Evidence {
			if strings.Contains(ev, tt.wantEv) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: evidence %v lacks %q", tt.path, e.Evidence, tt.wantEv)
		}
	}

	for _, id := range []string{"node-deps", "build-dist"} {
		g, ok := findGroup(res, id)
		if !ok || !g.Applicable {
			t.Fatalf("group %s should be applicable: %+v", id, g)
		}
	}
}

// TestResolvePreserveDirContainment: an entry inside a directory that
// itself matched a preserve pattern is preserved even though the child
// path does not match any pattern directly.
func TestResolvePreserveDirContainment(t *testing.T) {
	pol := testPolicy()
	pol.Preserve[0].Patterns = []string{"vendor"} // literal-style glob, dir only
	entries := []domain.Entry{
		entry("vendor", domain.KindDir, "", 0),
		entry("vendor/lib/odd*name.bin", domain.KindFile, "", 10),
	}
	res, err := Resolve(entries, pol)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	e := findEntry(t, res, "vendor/lib/odd*name.bin")
	if e.Route != domain.RoutePreserve {
		t.Fatalf("contained entry route = %q", e.Route)
	}
	hasDirEv := false
	for _, ev := range e.Evidence {
		if ev == "policy:preserve-dir=vendor" {
			hasDirEv = true
		}
	}
	if !hasDirEv {
		t.Fatalf("missing preserve-dir evidence: %v", e.Evidence)
	}
}

// TestResolveF53Cancellation covers every cancellation cause: tracked
// source, explicit preservation overlap, shared ownership and an
// unsafe entry kind. The whole group must flip to preservation with an
// issue recorded.
func TestResolveF53Cancellation(t *testing.T) {
	tests := []struct {
		name string
		bad  domain.Entry
	}{
		{"tracked file inside outputs", entry("node_modules/pkg/notes.txt", domain.KindFile, "", 10, "git:tracked")},
		{"git admin (nested repo) inside outputs", entry("node_modules/pkg/.git", domain.KindDir, "", 0, "git:admin:nested")},
		{"shared ownership inside outputs", func() domain.Entry {
			e := entry("node_modules/pkg/data.db", domain.KindFile, "", 10)
			e.Ownership = domain.OwnershipShared
			return e
		}()},
		{"unsafe kind inside outputs", entry("node_modules/pkg/pipe", domain.KindFIFO, "", 0)},
		{"preserve pattern overlap", entry("node_modules/research/keep.md", domain.KindFile, "", 10)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := testPolicy()
			// Make the preserve pattern cover node_modules/research/**.
			pol.Preserve[0].Patterns = []string{"research/**", "node_modules/research/**"}
			entries := []domain.Entry{
				entry("node_modules", domain.KindDir, "", 0),
				entry("node_modules/pkg/index.js", domain.KindFile, "", 1000),
				tt.bad,
				entry("dist/app.js", domain.KindFile, "", 500),
			}
			res, err := Resolve(entries, pol)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			g, ok := findGroup(res, "node-deps")
			if !ok {
				t.Fatal("group missing")
			}
			if g.Applicable || !g.Cancelled {
				t.Fatalf("group not cancelled: %+v", g)
			}
			if g.Canceller != tt.bad.Path {
				t.Fatalf("canceller = %q, want %q", g.Canceller, tt.bad.Path)
			}
			e := findEntry(t, res, "node_modules/pkg/index.js")
			if e.Route != domain.RoutePreserve {
				t.Fatalf("member route = %q, want preserve after cancellation", e.Route)
			}
			foundIssue := false
			for _, iss := range res.Issues {
				if iss.Code == IssueRegenCancelled && iss.Path == tt.bad.Path {
					foundIssue = true
				}
			}
			if !foundIssue {
				t.Fatalf("no cancellation issue for %q: %+v", tt.bad.Path, res.Issues)
			}
			// The other group is unaffected (Foundation §17.4: a
			// modified group blocks only its own trim).
			g2, _ := findGroup(res, "build-dist")
			if !g2.Applicable {
				t.Fatalf("unrelated group cancelled: %+v", g2)
			}
		})
	}
}

// TestResolveSensitiveNeverRoutes: a sensitive file inside applicable
// outputs still reconstructs; sensitivity only flags handling.
func TestResolveSensitiveNeverRoutes(t *testing.T) {
	pol := testPolicy()
	pol.Regenerate = pol.Regenerate[:1]
	pol.Sensitive[0].Patterns = append(pol.Sensitive[0].Patterns, "node_modules/creds/**")
	entries := []domain.Entry{
		entry("node_modules", domain.KindDir, "", 0),
		entry("node_modules/creds/token", domain.KindFile, "", 10),
	}
	res, err := Resolve(entries, pol)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	e := findEntry(t, res, "node_modules/creds/token")
	if e.Sensitivity != domain.SensitivitySensitive {
		t.Fatalf("sensitivity = %q", e.Sensitivity)
	}
	if e.Route != domain.RouteReconstruct {
		t.Fatalf("route = %q (sensitivity must not route)", e.Route)
	}
}

// TestResolveRespectsHigherRoutes: locally recorded discard, external
// and retained-artifact routes are respected, never downgraded — and
// policy v1 itself never produces them.
func TestResolveRespectsHigherRoutes(t *testing.T) {
	pol := testPolicy()
	entries := []domain.Entry{
		entry("node_modules", domain.KindDir, "", 0),
		entry("node_modules/cache/tmp", domain.KindFile, domain.RouteDiscard, 10),
		{Root: domain.RootMain, Path: "linked-data", Kind: domain.KindJunction,
			Route: domain.RouteExternal, Ownership: domain.OwnershipReferenceOnly},
		entry("dump.sql", domain.KindFile, domain.RouteRetainedArtifact, 20),
	}
	res, err := Resolve(entries, pol)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := map[string]domain.Route{
		"node_modules/cache/tmp": domain.RouteDiscard,
		"linked-data":            domain.RouteExternal,
		"dump.sql":               domain.RouteRetainedArtifact,
	}
	for path, r := range want {
		if e := findEntry(t, res, path); e.Route != r {
			t.Fatalf("%s route = %q, want %q", path, e.Route, r)
		}
	}
}

// TestResolveMetaRootAndInvalidEntries: meta-root entries bypass policy
// matching; entries with invalid roots or paths are preserved and
// reported, never dropped or panicked on.
func TestResolveMetaRootAndInvalidEntries(t *testing.T) {
	pol := testPolicy()
	entries := []domain.Entry{
		{Root: domain.RootMeta, Path: "meta/op.json", Kind: domain.KindFile, Route: "",
			Ownership: domain.OwnershipOwned, Sensitivity: domain.SensitivityOrdinary},
		{Root: domain.RootID("bogus"), Path: "x", Kind: domain.KindFile, Route: "",
			Ownership: domain.OwnershipOwned, Sensitivity: domain.SensitivityOrdinary},
		entry("bad\\path", domain.KindFile, "", 5),
		entry("a\u0000b", domain.KindFile, "", 5),
	}
	res, err := Resolve(entries, pol)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, e := range res.Entries {
		if e.Route != domain.RoutePreserve {
			t.Fatalf("%q route = %q, want preserve", e.Path, e.Route)
		}
	}
	codes := map[string]int{}
	for _, iss := range res.Issues {
		codes[iss.Code]++
	}
	if codes[IssueEntryRootInvalid] != 1 || codes[IssueEntryPathInvalid] != 2 {
		t.Fatalf("issue codes = %v", codes)
	}
}

// TestResolveConflictingOutputs: two groups claiming the same output
// path (equal or nested) is an error.
func TestResolveConflictingOutputs(t *testing.T) {
	tests := []struct {
		name    string
		outA    []string
		outB    []string
		wantSub string
	}{
		{"same output", []string{"node_modules"}, []string{"node_modules"}, "overlaps"},
		{"nested output", []string{"node_modules"}, []string{"node_modules/.pnpm"}, "overlaps"},
		{"reverse nesting", []string{"a/b/c"}, []string{"a/b"}, "overlaps"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol := testPolicy()
			pol.Regenerate = []Regenerate{
				{ID: "a", Adapter: AdapterPNPM, Root: ".", Outputs: tt.outA,
					Inputs: []string{"in-a"}, Network: GroupNetworkAllowed},
				{ID: "b", Adapter: AdapterNPM, Root: ".", Outputs: tt.outB,
					Inputs: []string{"in-b"}, Network: GroupNetworkAllowed},
			}
			_, err := Resolve(nil, pol)
			if err == nil || !strings.Contains(err.Error(), "conflicting regenerate output ownership") ||
				!strings.Contains(err.Error(), tt.wantSub) {
				t.Fatalf("want output-conflict error, got %v", err)
			}
		})
	}
}

// TestResolveActionCycle: inputs/outputs overlap creating a dependency
// cycle is an error, including the self-cycle.
func TestResolveActionCycle(t *testing.T) {
	pol := testPolicy()
	pol.Regenerate = []Regenerate{
		{ID: "solo", Adapter: AdapterPNPM, Root: ".",
			Outputs: []string{"gen"}, Inputs: []string{"gen/src"}, Network: GroupNetworkAllowed},
	}
	if _, err := Resolve(nil, pol); err == nil ||
		!strings.Contains(err.Error(), "own outputs") {
		t.Fatalf("self-cycle not rejected: %v", err)
	}

	pol.Regenerate = []Regenerate{
		{ID: "alpha", Adapter: AdapterPNPM, Root: ".",
			Outputs: []string{"gen-a"}, Inputs: []string{"gen-b/out"}, Network: GroupNetworkAllowed},
		{ID: "beta", Adapter: AdapterUV, Root: ".",
			Outputs: []string{"gen-b"}, Inputs: []string{"gen-a/tmpl"}, Network: GroupNetworkAllowed},
	}
	_, err := Resolve(nil, pol)
	if err == nil || !strings.Contains(err.Error(), "action cycle") {
		t.Fatalf("two-cycle not rejected: %v", err)
	}

	// A DAG (no cycle) is fine.
	pol.Regenerate = []Regenerate{
		{ID: "alpha", Adapter: AdapterPNPM, Root: ".",
			Outputs: []string{"gen-a"}, Inputs: []string{"src"}, Network: GroupNetworkAllowed},
		{ID: "beta", Adapter: AdapterUV, Root: ".",
			Outputs: []string{"gen-b"}, Inputs: []string{"gen-a/tmpl"}, Network: GroupNetworkAllowed},
	}
	if _, err := Resolve(nil, pol); err != nil {
		t.Fatalf("valid DAG rejected: %v", err)
	}
}

// TestDiscardUnreachableFromPolicyV1: no v1 policy construct can route
// an entry to discard. Discard authority lives outside the Ebbfile.
func TestDiscardUnreachableFromPolicyV1(t *testing.T) {
	pol, err := ParseFile("testdata/full.toml")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	entries := []domain.Entry{
		entry("research/a", domain.KindFile, "", 1),
		entry(".env", domain.KindFile, "", 1),
		entry("node_modules/x", domain.KindFile, "", 1),
		entry("dist/y", domain.KindFile, "", 1),
		entry("unknown/z", domain.KindFile, "", 1),
		entry("anything", domain.KindDir, "", 0),
	}
	res, err := Resolve(entries, pol)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, e := range res.Entries {
		if e.Route == domain.RouteDiscard {
			t.Fatalf("policy v1 produced RouteDiscard for %q", e.Path)
		}
		if e.Route == "" {
			t.Fatalf("entry %q left unrouted", e.Path)
		}
	}
}

// TestResolveDoesNotMutateInput verifies the caller's slice and the
// backing arrays of evidence are never mutated (Resolve copies).
func TestResolveDoesNotMutateInput(t *testing.T) {
	pol := testPolicy()
	ev := make([]string, 1, 8)
	ev[0] = "git:tracked"
	entries := []domain.Entry{entry("node_modules/x", domain.KindFile, "", 1, ev...)}
	before := append([]domain.Entry(nil), entries...)
	beforeEv := append([]string(nil), ev...)

	if _, err := Resolve(entries, pol); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !reflect.DeepEqual(entries, before) {
		t.Fatalf("input entries mutated: %+v", entries)
	}
	if !reflect.DeepEqual(ev, beforeEv) {
		t.Fatalf("evidence backing array mutated: %v", ev)
	}
}

// TestResolveGroupOrderDeterministic: group decisions are sorted by id
// regardless of file order.
func TestResolveGroupOrderDeterministic(t *testing.T) {
	pol := testPolicy()
	pol.Regenerate = []Regenerate{
		pol.Regenerate[1], pol.Regenerate[0],
	}
	res, err := Resolve(nil, pol)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Groups[0].ID != "build-dist" || res.Groups[1].ID != "node-deps" {
		t.Fatalf("groups not sorted by id: %+v", res.Groups)
	}
}
