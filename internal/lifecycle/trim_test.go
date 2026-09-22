package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// TestTrimRoundTrip: the §17.3 sequence over the standard fixture. After
// trim: group outputs gone, empty parents removed while non-empty ones
// are retained, inputs intact, TRIM_DONE, correct reclaim command, and P
// contains the removal manifest plus byte-exact input copies.
func TestTrimRoundTrip(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	opts := trimOpts(t, ws, "deps")
	opts.ApprovalReady = func(groupID string) error { return nil }
	res, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	if err != nil {
		t.Fatalf("trim: %v", err)
	}

	// Outputs removed; empty parents removed; non-empty parents retained.
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
	mustLstatErrNotExist(t, filepath.Join(root, "vendor", "dist"))
	mustExist(t, filepath.Join(root, "vendor", "LICENSE.txt"))
	mustExist(t, filepath.Join(root, "package.json"))
	mustExist(t, filepath.Join(root, "pnpm-lock.yaml"))
	mustExist(t, filepath.Join(root, "notes.md"))

	if got := h.phaseOf(t, h.opIDOf(t, ws)); got != catalog.PhaseTrimDone {
		t.Errorf("phase = %q, want TRIM_DONE", got)
	}
	if len(res.Groups) != 1 || res.Groups[0] != "deps" {
		t.Errorf("groups = %v, want [deps]", res.Groups)
	}
	if len(res.ReclaimCommands) != 1 || !equalStrings(res.ReclaimCommands[0], []string{"pnpm", "install", "--frozen-lockfile"}) {
		t.Errorf("reclaim commands = %v", res.ReclaimCommands)
	}
	// Members: node_modules tree (5 entries) + vendor/dist tree (2).
	if res.EntriesRemoved != 7 {
		t.Errorf("entries removed = %d, want 7", res.EntriesRemoved)
	}
	// The workspace stays live.
	if w, err := h.coord().cat.GetWorkspace(ws); err != nil || w.Status != catalog.WorkspaceLive {
		t.Errorf("workspace should stay live after trim: %+v err=%v", w, err)
	}

	// P contains the removal manifest and byte-exact input copies
	// (asserted through the store, like an independent restore worker).
	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	if len(snaps) != 1 || snaps[0].Kind != catalog.SnapshotKindTrim {
		t.Fatalf("trim snapshot row wrong: %+v", snaps)
	}
	P := snaps[0].PayloadBackendID
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	raw, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, P, prefix+"/"+removalManifestName)
	if err != nil {
		t.Fatalf("dump removal manifest: %v", err)
	}
	var plan trimPlanDoc
	if err := decodeStrictJSON(raw, &plan); err != nil {
		t.Fatalf("removal manifest: %v", err)
	}
	if len(plan.Groups) != 1 || plan.Groups[0].GroupID != "deps" {
		t.Fatalf("plan groups = %+v", plan.Groups)
	}
	g := plan.Groups[0]
	if !equalStrings(g.ReclaimCommand, []string{"pnpm", "install", "--frozen-lockfile"}) {
		t.Errorf("plan reclaim command = %v", g.ReclaimCommand)
	}
	// D034/D033: every new trim manifest records the live (drift-
	// reconcilable) recreate argv for ecosystem adapters.
	if !equalStrings(g.RecreateLive, []string{"pnpm", "install"}) {
		t.Errorf("plan recreate_live = %v, want [pnpm install]", g.RecreateLive)
	}
	if len(g.Members) != 7 {
		t.Errorf("plan members = %d, want 7", len(g.Members))
	}
	for _, in := range g.RecipeInputs {
		if in.Missing {
			t.Errorf("input %s recorded missing though present", in.Path)
			continue
		}
		got, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, P, prefix+"/"+in.Copy)
		if err != nil {
			t.Fatalf("dump input copy %s: %v", in.Copy, err)
		}
		orig := map[string]string{
			"package.json":   fixturePackageJSON,
			"pnpm-lock.yaml": fixtureLock,
		}[in.Path]
		if string(got) != orig {
			t.Errorf("input copy %s differs from the original bytes", in.Path)
		}
	}
	// The manifest declares the trim scope.
	mb, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, P, prefix+"/"+manifestName)
	if err != nil {
		t.Fatal(err)
	}
	var md manifestDoc
	if err := decodeStrictJSON(mb, &md); err != nil {
		t.Fatal(err)
	}
	if md.Contract.Scope != scopeTrimPlan {
		t.Errorf("manifest scope = %q, want %q", md.Contract.Scope, scopeTrimPlan)
	}
}

// TestTrimUnapprovedGroupBlocked: ApprovalReady refusing one group aborts
// the WHOLE trim before any durable side effect (never a silent partial
// trim).
func TestTrimUnapprovedGroupBlocked(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	opts := trimOpts(t, ws, "deps")
	opts.ApprovalReady = func(groupID string) error {
		return errors.New("approval revoked: rebuild command changed since plan freeze")
	}
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var blocked *ErrDestructiveBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("expected ErrDestructiveBlocked, got %v", err)
	}
	if !strings.Contains(blocked.Error(), "deps") {
		t.Errorf("blocked reason must name the group: %v", blocked)
	}
	// Nothing removed, no operation left behind.
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
	if n := activeCount(t, h.coord(), ws); n != 0 {
		t.Errorf("active ops after refused trim = %d, want 0", n)
	}
}

// TestTrimMemberModifiedAfterFreeze: a member whose bytes changed after
// the plan was sealed blocks removal with BlockDigestChanged; the phase
// stays TRIM_SEALING and all members are retained.
func TestTrimMemberModifiedAfterFreeze(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	before := digestTree(t, root)

	armed, mutated := false, false
	h.store.onSnapshot = func(tags map[string]string) error {
		if tags["ebb-kind"] == "seal" {
			armed = true
		}
		return nil
	}
	h.probe.onRootIdentity = func(p string) (domain.RootIdentity, error, bool) {
		// The first live-root identity probe after the seal is the trim
		// tail's re-probe — mutate the first-walked member right then.
		if armed && !mutated && p == root {
			mutated = true
			_ = os.WriteFile(filepath.Join(root, "vendor", "dist", "gen.js"), []byte("writer raced the trim\n"), 0o644)
		}
		return domain.RootIdentity{}, nil, false
	}

	opts := trimOpts(t, ws, "deps")
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var blocked *ErrRemovalBlocked
	if !errors.As(err, &blocked) || blocked.Code != BlockDigestChanged {
		t.Fatalf("expected ErrRemovalBlocked{%s}, got %v", BlockDigestChanged, err)
	}
	if got := h.phaseOf(t, h.opIDOf(t, ws)); got != catalog.PhaseTrimSealing {
		t.Errorf("phase = %q, want TRIM_SEALING preserved", got)
	}
	// Members retained (the mutation itself aside).
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
	mustExist(t, filepath.Join(root, "vendor", "dist", "gen.js"))
	after := digestTree(t, root)
	for path := range before {
		if _, ok := after[path]; !ok {
			t.Errorf("member %s removed despite the block", path)
		}
	}
}

// TestTrimUnknownGroup: an id that is not a declared regenerate group is
// an options error before anything durable happens.
func TestTrimUnknownGroup(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	opts := trimOpts(t, ws, "does-not-exist")
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var invalid *ErrInvalidOptions
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrInvalidOptions, got %v", err)
	}
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
}

// TestTrimZeroMembersEverywhere: requesting only a group whose outputs do
// not exist fails the operation with a clear error and removes nothing.
func TestTrimZeroMembersEverywhere(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	// A workspace with NO generated output at all (not the standard
	// fixture): the requested group's outputs do not exist on disk.
	root := filepath.Join(h.base, "work", "empty-ws")
	if err := os.MkdirAll(filepath.Join(root, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep", "a.txt"), []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := trimOpts(t, ws, "deps")
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	if err == nil || !strings.Contains(err.Error(), "nothing to trim") {
		t.Fatalf("expected nothing-to-trim failure, got %v", err)
	}
	mustExist(t, filepath.Join(root, "keep", "a.txt"))
	if n := activeCount(t, h.coord(), ws); n != 0 {
		t.Errorf("operation not canceled after empty trim: %d active", n)
	}
}

// TestTrimRecoverSealingResumes: a crash during the trim removal (context
// canceled after the seal) leaves TRIM_SEALING; Recover rebuilds the
// member set from the retained removal manifest and completes TRIM_DONE
// idempotently.
func TestTrimRecoverSealingResumes(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	ctx, cancel := context.WithCancel(context.Background())
	armed := false
	h.store.onSnapshot = func(tags map[string]string) error {
		if tags["ebb-kind"] == "seal" {
			armed = true
		}
		return nil
	}
	h.probe.onRootIdentity = func(p string) (domain.RootIdentity, error, bool) {
		if armed && p == root {
			armed = false // fire once: cancel before the removal walk starts
			cancel()
		}
		return domain.RootIdentity{}, nil, false
	}
	opts := trimOpts(t, ws, "deps")
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(ctx, h.vault, root, opts)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled before removal, got %v", err)
	}
	ops, _ := h.coord().cat.ActiveOperations(ws)
	if len(ops) != 1 || ops[0].Phase != catalog.PhaseTrimSealing {
		t.Fatalf("expected one TRIM_SEALING op, got %+v", ops)
	}

	rep, rerr := h.coord().Recover(context.Background(), h.vault, ops[0].ID)
	if rerr != nil {
		t.Fatalf("recover: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseAfter != catalog.PhaseTrimDone {
		t.Errorf("phase after recover = %q, want TRIM_DONE", rep.PhaseAfter)
	}
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
	mustLstatErrNotExist(t, filepath.Join(root, "vendor", "dist"))
	mustExist(t, filepath.Join(root, "package.json"))
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
