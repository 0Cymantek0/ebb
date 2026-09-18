package planner

import (
	"reflect"
	"strings"
	"testing"

	"ebb/internal/domain"
	"ebb/internal/policy"
)

// alloc returns a pointer to n (test helper for *int64 fields).
func alloc(n int64) *int64 { return &n }

// fentry is a file entry on the main root.
func fentry(path string, logical int64, allocated *int64, route domain.Route) domain.Entry {
	return domain.Entry{
		Root: domain.RootMain, Path: path, Kind: domain.KindFile,
		Route: route, LogicalSize: logical, AllocatedSize: allocated,
		Ownership: domain.OwnershipOwned, Sensitivity: domain.SensitivityOrdinary,
	}
}

// resolvedWithGroups builds a Resolved carrying the given entries and
// applicable groups.
func resolvedWithGroups(entries []domain.Entry, groups ...policy.GroupDecision) policy.Resolved {
	return policy.Resolved{Entries: entries, Groups: groups}
}

func groups(idsOutputs map[string][]string) []policy.GroupDecision {
	var gs []policy.GroupDecision
	// deterministic map iteration is irrelevant: PlanReclaim sorts.
	for id, outs := range idsOutputs {
		gs = append(gs, policy.GroupDecision{ID: id, Adapter: policy.AdapterPNPM,
			Outputs: outs, Applicable: true})
	}
	return gs
}

// baseInput returns a two-group input whose plans are non-trivial:
// node-deps reclaims 3_500_000 bytes (min of member sum 4_000_000 and
// summary 3_500_000), build-dist reclaims 400_000 (min of 500_000 and
// 400_000).
func baseInput() Input {
	entries := []domain.Entry{
		fentry("package.json", 200, alloc(200), domain.RoutePreserve),
		fentry("src/main.go", 5000, alloc(5000), domain.RoutePreserve),
		fentry("node_modules/a.js", 1_000_000, alloc(1_000_000), domain.RouteReconstruct),
		fentry("node_modules/b.js", 3_000_000, alloc(3_000_000), domain.RouteReconstruct),
		fentry("dist/app.js", 500_000, alloc(500_000), domain.RouteReconstruct),
	}
	return Input{
		Summary: domain.InventorySummary{
			ExclReclaimable: map[string]int64{
				"node_modules": 3_500_000,
				"dist":         400_000,
			},
		},
		Resolved: resolvedWithGroups(entries,
			groups(map[string][]string{
				"node-deps":  {"node_modules"},
				"build-dist": {"dist"},
			})...),
		Volume: domain.VolumeUsage{VolumeID: "V1"},
	}
}

// stepKinds extracts the step kind sequence.
func stepKinds(p Plan) []StepKind {
	var ks []StepKind
	for _, s := range p.Steps {
		ks = append(ks, s.Kind)
	}
	return ks
}

// trimOrder lists the group ids of all trim steps in plan order.
func trimOrder(p Plan) []string {
	var ids []string
	for _, s := range p.Steps {
		if s.Kind == StepTrim {
			ids = append(ids, s.Groups...)
		}
	}
	return ids
}

// TestOrderingInvariance: shuffling groups and entries yields an
// identical plan.
func TestOrderingInvariance(t *testing.T) {
	base := baseInput()
	want, err := PlanReclaim(base)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}

	shuffles := []func(in Input) Input{
		func(in Input) Input { // reverse entries, reverse groups
			for i, j := 0, len(in.Resolved.Entries)-1; i < j; i, j = i+1, j-1 {
				in.Resolved.Entries[i], in.Resolved.Entries[j] = in.Resolved.Entries[j], in.Resolved.Entries[i]
			}
			g := in.Resolved.Groups
			g[0], g[1] = g[1], g[0]
			return in
		},
		func(in Input) Input { // swap group order only
			g := in.Resolved.Groups
			g[0], g[1] = g[1], g[0]
			return in
		},
		func(in Input) Input { // rotate entries by two
			es := in.Resolved.Entries
			in.Resolved.Entries = append(append([]domain.Entry(nil), es[2:]...), es[:2]...)
			return in
		},
	}
	for i, shuffle := range shuffles {
		got, err := PlanReclaim(shuffle(base))
		if err != nil {
			t.Fatalf("shuffle %d: %v", i, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle %d changed the plan:\nwant %+v\ngot  %+v", i, want, got)
		}
	}
}

// TestFixedStepOrder: discard precedes trim precedes park, with or
// without a target (a target never reorders precedence).
func TestFixedStepOrder(t *testing.T) {
	in := baseInput()
	in.Resolved.Entries = append(in.Resolved.Entries,
		fentry("tmp/cache.bin", 900_000, alloc(900_000), domain.RouteDiscard))
	in.ParkApproved = true

	noTarget, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	wantKinds := []StepKind{StepDiscard, StepTrim, StepTrim, StepPark}
	if !reflect.DeepEqual(stepKinds(noTarget), wantKinds) {
		t.Fatalf("no-target kinds = %v, want %v", stepKinds(noTarget), wantKinds)
	}
	// Discard first, then trims largest-first.
	if g := trimOrder(noTarget); len(g) != 2 || g[0] != "node-deps" || g[1] != "build-dist" {
		t.Fatalf("trim order = %v", g)
	}

	// A small target stops early but keeps the relative order.
	small := int64(1_000_000)
	in.Target = &small
	withTarget, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if !reflect.DeepEqual(stepKinds(withTarget), []StepKind{StepDiscard, StepTrim}) {
		t.Fatalf("target kinds = %v", stepKinds(withTarget))
	}
	if g := trimOrder(withTarget); len(g) != 1 || g[0] != "node-deps" {
		t.Fatalf("stop-short groups = %v", g)
	}
	if withTarget.Result != ResultSufficient {
		t.Fatalf("result = %q", withTarget.Result)
	}
}

// TestTargetStopShort: once the cumulative estimate reaches the target,
// no further steps are added.
func TestTargetStopShort(t *testing.T) {
	in := baseInput()
	target := int64(3_000_000)
	in.Target = &target
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if len(p.Steps) != 1 || p.Steps[0].Kind != StepTrim || p.Steps[0].Groups[0] != "node-deps" {
		t.Fatalf("steps = %+v", p.Steps)
	}
	if p.Achieved["V1"] != 3_500_000 {
		t.Fatalf("achieved = %v", p.Achieved)
	}
	if p.Result != ResultSufficient {
		t.Fatalf("result = %q", p.Result)
	}
}

// TestShortfallMath: target beyond every safe route with park not
// approved reports the exact gap per volume and adds no park step.
func TestShortfallMath(t *testing.T) {
	in := baseInput()
	target := int64(4_500_000)
	in.Target = &target
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if p.Result != ResultShortfall {
		t.Fatalf("result = %q", p.Result)
	}
	if gap, ok := p.Shortfall["V1"]; !ok || gap != 600_000 { // 4.5M - (3.5M + 0.4M)
		t.Fatalf("shortfall = %v", p.Shortfall)
	}
	for _, s := range p.Steps {
		if s.Kind == StepPark {
			t.Fatal("park step added without approval")
		}
	}
	found := false
	for _, w := range p.Warnings {
		if strings.Contains(w, "not approved") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing shortfall warning: %v", p.Warnings)
	}
}

// TestShortfallEvenWithPark: with park approved but still short, the
// exact gap survives.
func TestShortfallEvenWithPark(t *testing.T) {
	in := baseInput()
	target := int64(100_000_000)
	in.Target = &target
	in.ParkApproved = true
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if p.Result != ResultShortfall {
		t.Fatalf("result = %q", p.Result)
	}
	total := int64(0)
	for _, s := range p.Steps {
		total += stepTotal(s)
	}
	if gap := p.Shortfall["V1"]; gap != target-total {
		t.Fatalf("gap %d != target-total %d", gap, target-total)
	}
	var park *Step
	for i := range p.Steps {
		if p.Steps[i].Kind == StepPark {
			park = &p.Steps[i]
		}
	}
	if park == nil {
		t.Fatal("approved park missing from plan")
	}
	if !park.Escalation || !park.RequiresApproval || !park.RequiresStoppedWriters {
		t.Fatalf("park step missing escalation flags: %+v", park)
	}
}

// TestApprovalNeverWeakenedByTarget: the same shortfall target with and
// without park approval differs only by the park step; the approval
// requirement is never implied by the target, and the shared prefix of
// steps is identical in content and order.
func TestApprovalNeverWeakenedByTarget(t *testing.T) {
	in := baseInput()
	target := int64(50_000_000)
	in.Target = &target

	unapproved, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	for _, s := range unapproved.Steps {
		if s.Kind == StepPark {
			t.Fatal("target manufactured park approval")
		}
	}

	in.ParkApproved = true
	approved, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	n := len(unapproved.Steps)
	if len(approved.Steps) != n+1 {
		t.Fatalf("approved plan should add exactly one park step: %d vs %d", len(approved.Steps), n)
	}
	if !reflect.DeepEqual(approved.Steps[:n], unapproved.Steps) {
		t.Fatal("target changed the non-park steps")
	}
	if !approved.Steps[n].RequiresApproval {
		t.Fatal("park step lost its approval requirement")
	}
}

// TestNoGain: nothing applicable, nothing discardable, park not
// approved.
func TestNoGain(t *testing.T) {
	in := Input{
		Resolved: resolvedWithGroups([]domain.Entry{
			fentry("a.txt", 10, alloc(10), domain.RoutePreserve),
		}),
		Volume: domain.VolumeUsage{VolumeID: "V1"},
	}
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if p.Result != ResultNoGain || len(p.Steps) != 0 || len(p.Reasons) == 0 {
		t.Fatalf("plan = %+v", p)
	}

	// With a target the no-gain plan also names the gap.
	target := int64(1000)
	in.Target = &target
	p, err = PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if p.Result != ResultNoGain {
		t.Fatalf("result = %q", p.Result)
	}
	if p.Shortfall["V1"] != 1000 {
		t.Fatalf("shortfall = %v", p.Shortfall)
	}
}

// TestNoGainCancelledGroupReportsReason: a cancelled group produces a
// reason, not a step.
func TestNoGainCancelledGroupReportsReason(t *testing.T) {
	in := Input{
		Resolved: policy.Resolved{
			Entries: []domain.Entry{fentry("node_modules/x", 5, alloc(5), domain.RoutePreserve)},
			Groups: []policy.GroupDecision{{
				ID: "node-deps", Adapter: policy.AdapterPNPM, Outputs: []string{"node_modules"},
				Applicable: false, Cancelled: true, Reason: "tracked source (F53)", Canceller: "node_modules/x",
			}},
		},
		Volume: domain.VolumeUsage{VolumeID: "V1"},
	}
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if p.Result != ResultNoGain {
		t.Fatalf("result = %q", p.Result)
	}
	found := false
	for _, r := range p.Reasons {
		if strings.Contains(r, "node-deps") && strings.Contains(r, "F53") {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons = %v", p.Reasons)
	}
}

// TestDehydrationUnsupported: requested dehydration is reported as an
// unsupported step and never counts toward a target.
func TestDehydrationUnsupported(t *testing.T) {
	in := baseInput()
	in.DehydrateRequested = true
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	var dh *Step
	for i := range p.Steps {
		if p.Steps[i].Kind == StepDehydrate {
			dh = &p.Steps[i]
		}
	}
	if dh == nil {
		t.Fatal("dehydration step missing")
	}
	if !dh.Unsupported || !dh.EstimateUnknown || len(dh.Blockers) == 0 || dh.Blockers[0] != "EBB_E_DEHYDRATION_UNSUPPORTED" {
		t.Fatalf("dehydration step = %+v", dh)
	}
	if stepTotal(*dh) != 0 {
		t.Fatal("unsupported step claimed bytes")
	}
	// Dehydration sits after trims in the fixed order.
	if ks := stepKinds(p); ks[len(ks)-1] != StepDehydrate {
		t.Fatalf("kinds = %v", ks)
	}
}

// TestConservativeEstimate: when the summary figure and the member sum
// disagree, the smaller number is reported (round down, never up).
func TestConservativeEstimate(t *testing.T) {
	in := baseInput()
	// Member sum for node_modules is 4_000_000; summary says 3_500_000.
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	for _, s := range p.Steps {
		if s.Kind == StepTrim && s.Groups[0] == "node-deps" {
			if s.Reclaimable["V1"] != 3_500_000 {
				t.Fatalf("estimate = %v, want the smaller 3_500_000", s.Reclaimable)
			}
		}
	}

	// Member sum smaller than the summary: members win.
	in.Summary.ExclReclaimable["node_modules"] = 9_000_000
	p, err = PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	for _, s := range p.Steps {
		if s.Kind == StepTrim && s.Groups[0] == "node-deps" && s.Reclaimable["V1"] != 4_000_000 {
			t.Fatalf("estimate = %v, want member sum 4_000_000", s.Reclaimable)
		}
	}
}

// TestUnknownEstimateOmitted: a group with no members and no summary
// key omits numbers and is marked unknown.
func TestUnknownEstimateOmitted(t *testing.T) {
	in := Input{
		Resolved: resolvedWithGroups(nil,
			policy.GroupDecision{ID: "ghost", Adapter: policy.AdapterPNPM,
				Outputs: []string{"gen"}, Applicable: true}),
		Volume: domain.VolumeUsage{VolumeID: "V1"},
	}
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if len(p.Steps) != 1 || !p.Steps[0].EstimateUnknown || len(p.Steps[0].Reclaimable) != 0 {
		t.Fatalf("steps = %+v", p.Steps)
	}
	if p.Result != ResultSufficient {
		t.Fatalf("unknown estimate is still a useful step: %q", p.Result)
	}
}

// TestLogicalFallbackAndBlockers: entries without allocated sizes fall
// back to logical bytes; blocking entries under a group's tree become
// step blockers.
func TestLogicalFallbackAndBlockers(t *testing.T) {
	entries := []domain.Entry{
		{Root: domain.RootMain, Path: "gen", Kind: domain.KindDir, Route: domain.RouteReconstruct,
			Ownership: domain.OwnershipOwned, Sensitivity: domain.SensitivityOrdinary},
		fentry("gen/big.bin", 7_000, nil, domain.RouteReconstruct), // allocated unknown
	}
	in := Input{
		Summary: domain.InventorySummary{Blocking: []string{"gen/locked.file"}},
		Resolved: resolvedWithGroups(entries,
			policy.GroupDecision{ID: "g", Adapter: policy.AdapterPNPM, Outputs: []string{"gen"}, Applicable: true}),
		Volume: domain.VolumeUsage{VolumeID: "V1"},
	}
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if p.Steps[0].Reclaimable["V1"] != 7_000 {
		t.Fatalf("logical fallback = %v", p.Steps[0].Reclaimable)
	}
	if len(p.Steps[0].Blockers) != 1 || p.Steps[0].Blockers[0] != "blocked-entry:gen/locked.file" {
		t.Fatalf("blockers = %v", p.Steps[0].Blockers)
	}
}

// TestNegativeTargetRejected: invalid input errors.
func TestNegativeTargetRejected(t *testing.T) {
	neg := int64(-1)
	if _, err := PlanReclaim(Input{Target: &neg}); err == nil {
		t.Fatal("negative target accepted")
	}
}

// TestDefaultVolumeKey: a zero VolumeUsage reports under "default".
func TestDefaultVolumeKey(t *testing.T) {
	in := baseInput()
	in.Volume = domain.VolumeUsage{}
	p, err := PlanReclaim(in)
	if err != nil {
		t.Fatalf("PlanReclaim: %v", err)
	}
	if _, ok := p.Achieved["default"]; !ok {
		t.Fatalf("achieved = %v", p.Achieved)
	}
}
