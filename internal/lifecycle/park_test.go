package lifecycle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/inventory"
)

// volumeNoiseFloor estimates concurrent free-space drift on the volume
// holding path: samples FreeToCaller n times and returns the max spread.
// The measurement window of the observed park delta spans the whole
// sequence, so drift measured here for a few milliseconds is a LOWER
// bound on the real noise; callers scale it.
func volumeNoiseFloor(t *testing.T, probe *wrapProbe, path string, n int) int64 {
	t.Helper()
	var minFree, maxFree int64
	for i := 0; i < n; i++ {
		u, err := probe.VolumeUsage(path)
		if err != nil {
			t.Fatalf("noise sample: %v", err)
		}
		if i == 0 || u.FreeToCaller < minFree {
			minFree = u.FreeToCaller
		}
		if i == 0 || u.FreeToCaller > maxFree {
			maxFree = u.FreeToCaller
		}
		time.Sleep(15 * time.Millisecond)
	}
	return maxFree - minFree
}

// TestParkRoundTrip: the full §12.2 sequence. After park: root gone,
// operation PARKED→DONE (terminal), workspace parked, snapshot pinned,
// volume deltas reported, no scratch leftovers.
func TestParkRoundTrip(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	// The observed volume delta measures FreeToCaller on the machine's
	// shared temp volume, so concurrent activity (the full `go test ./...`
	// run, any background process) is noise in the measurement. Sample
	// the drift before parking and size the plausibility bound from it;
	// a broken measurement (zero, or negative by the workspace's own
	// bytes) still fails by orders of magnitude.
	noise := volumeNoiseFloor(t, h.probe, root, 8)

	res, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws))
	if err != nil {
		t.Fatalf("park: %v", err)
	}
	mustLstatErrNotExist(t, root)

	c := h.coord()
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseDone {
		t.Errorf("phase = %q, want DONE (PARKED must not block the workspace forever)", got)
	}
	if n := activeCount(t, c, ws); n != 0 {
		t.Errorf("active operations = %d, want 0", n)
	}
	w, err := c.cat.GetWorkspace(ws)
	if err != nil {
		t.Fatal(err)
	}
	if w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace status = %q, want parked", w.Status)
	}
	if w.RootPath != "" {
		t.Errorf("parked workspace still bound to root %q", w.RootPath)
	}
	snaps, _ := c.cat.ListSnapshots(ws)
	if len(snaps) != 1 || !snaps[0].Pinned || snaps[0].Kind != catalog.SnapshotKindPark {
		t.Fatalf("snapshot row wrong: %+v", snaps)
	}

	// Volume accounting: the estimate is the exact logical sum of all
	// file bytes; the observed delta is measured (never assumed).
	var wantBytes int64
	for _, content := range []string{fixturePackageJSON, fixtureLock, fixtureNotes, fixtureAjs, fixtureXjs, fixtureGen, fixtureLicense} {
		wantBytes += int64(len(content))
	}
	if res.VolumeDeltaEstimated != wantBytes {
		t.Errorf("estimated delta = %d, want %d", res.VolumeDeltaEstimated, wantBytes)
	}
	// Tolerate same-volume overhead (Ebb's own temp writes: fake-store
	// copies, catalog, op dir) plus the measured concurrent-drift noise
	// floor; the delta must still not be negative beyond that.
	if limit := -(int64(1<<20) + 4*noise); res.VolumeDeltaObserved < limit {
		t.Errorf("observed delta implausibly negative: %d (tolerance %d, noise floor %d)",
			res.VolumeDeltaObserved, limit, noise)
	}

	parent := filepath.Dir(root)
	des, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range des {
		if strings.HasPrefix(d.Name(), ".ebb-") {
			t.Errorf("scratch object %s left behind after park", d.Name())
		}
	}

	// A completed park unblocks the workspace: a fresh capture binding
	// the same workspace id must not hit ErrOpInProgress.
	if _, err := h.coord().Snapshot(context.Background(), h.vault, filepath.Join(h.base, "work"), snapshotOpts(ws)); err != nil {
		var inprog *ErrOpInProgress
		if errors.As(err, &inprog) {
			t.Errorf("completed park still blocks the workspace: %v", err)
		} else {
			t.Logf("rebind capture ended with non-F37 error (acceptable): %v", err)
		}
	}
}

// TestParkSourceChangedAfterSeal: a writer mutating the source after the
// seal readback (injected at the exact sequence point via the probe)
// invalidates removal (§12.2 step 6): ErrSourceChanged, root intact, P/S
// retained and pinned, operation fails at SEALED.
func TestParkSourceChangedAfterSeal(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	before := digestTree(t, root)

	armed, mutated := false, false
	h.store.onSnapshot = func(tags map[string]string) error {
		if tags["ebb-kind"] == "seal" {
			armed = true // after seal capture; readback + SEALED commit follow
		}
		return nil
	}
	h.probe.onRootIdentity = func(p string) (domain.RootIdentity, error, bool) {
		// The next identity probe of the live root after the seal is the
		// revalidation (step 6) — mutate the source right then.
		if armed && !mutated && p == root {
			mutated = true
			f, err := os.OpenFile(filepath.Join(root, "notes.md"), os.O_WRONLY|os.O_APPEND, 0o644)
			if err == nil {
				_, _ = f.WriteString("late writer mutation\n")
				_ = f.Close()
			}
		}
		return domain.RootIdentity{}, nil, false
	}

	_, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws))
	if err == nil || !mutated {
		t.Fatalf("expected failure after late mutation (mutated=%v), got err=%v", mutated, err)
	}
	var sc *ErrSourceChanged
	if !errors.As(err, &sc) {
		t.Fatalf("expected ErrSourceChanged, got %v", err)
	}

	// Root intact (only the test's own mutation differs), snapshot retained.
	after := digestTree(t, root)
	for path := range before {
		if _, ok := after[path]; !ok {
			t.Errorf("source entry %s was removed — removal must be refused", path)
		}
	}
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
	if got := h.phaseOf(t, h.opIDOf(t, ws)); got != catalog.PhaseSealed {
		t.Errorf("phase = %q, want SEALED", got)
	}
	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	if len(snaps) != 1 || !snaps[0].Pinned || snaps[0].SealBackendID == "" {
		t.Errorf("sealed P/S pair not retained pinned: %+v", snaps)
	}
}

// TestParkQuarantineIdentityMismatchReverts: if the renamed quarantine
// does not carry the sealed identity (fault probe), the original name is
// restored and nothing is removed (F32/I13).
func TestParkQuarantineIdentityMismatchReverts(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	before := digestTree(t, root)

	h.probe.onRootIdentity = func(p string) (domain.RootIdentity, error, bool) {
		if p != root {
			// The only non-root identity probe in the park tail is the
			// post-rename quarantine check — answer with a foreign identity.
			return domain.RootIdentity{VolumeID: "FAKE", FileID: "FAKE"}, nil, true
		}
		return domain.RootIdentity{}, nil, false
	}

	_, err := h.coord().Park(context.Background(), h.vault, root, parkOpts(ws))
	var jm *ErrJournalMismatch
	if !errors.As(err, &jm) {
		t.Fatalf("expected ErrJournalMismatch, got %v", err)
	}
	requireSameTree(t, before, digestTree(t, root))
	parent := filepath.Dir(root)
	des, _ := os.ReadDir(parent)
	for _, d := range des {
		if strings.HasPrefix(d.Name(), quarantinePrefix) {
			t.Errorf("quarantine %s still present after revert", d.Name())
		}
	}
}

// TestPermitDigestChangeBlocks drives the removal permit directly on a
// hand-built state (revalidation would catch a mutation earlier in the
// real sequence; this isolates the permit's own per-entry guard): a file
// whose digest changed since the seal blocks with BlockDigestChanged and
// everything from that point on is retained.
func TestPermitDigestChangeBlocks(t *testing.T) {
	h := newHarness(t)
	root := h.workspace("ws")

	res := inventory.Scan(context.Background(), h.probe.inner, root, inventory.Options{Hash: true})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	allowed := make(map[string]domain.Entry, len(res.Entries))
	for _, e := range res.Entries {
		allowed[e.Path] = e
	}
	ident, err := h.probe.inner.RootIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	opID := domain.OperationID(domain.NewID())
	permit, err := newRemovalPermit(opID, domain.SnapshotID(domain.NewID()), root, ident, allowed)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate the alphabetically-deepest file (walked first: children
	// before parents in reverse canonical order).
	if err := os.WriteFile(filepath.Join(root, "vendor", "dist", "gen.js"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = permit.execute(context.Background(), h.probe.inner, nil, nil)
	var blocked *ErrRemovalBlocked
	if !errors.As(err, &blocked) || blocked.Code != BlockDigestChanged {
		t.Fatalf("expected ErrRemovalBlocked{%s}, got %v", BlockDigestChanged, err)
	}
	if !strings.HasSuffix(filepath.ToSlash(blocked.Path), "vendor/dist/gen.js") {
		t.Errorf("blocked at unexpected path %s", blocked.Path)
	}
	// Everything else is retained: the walk stopped at the first mismatch.
	mustExist(t, filepath.Join(root, "vendor", "dist", "gen.js"))
	mustExist(t, filepath.Join(root, "package.json"))
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
}

// TestParkCancelMidRemovalAndRecover — the crash-recovery keystone. The
// context is canceled mid-walk (hook after N removals): partial removal,
// error returned, phase stays REMOVING (not REMOVAL_BLOCKED — a canceled
// walk is an interruption). A FRESH coordinator's Recover rebuilds the
// evidence from the catalog + P + journal and completes idempotently
// (already-removed entries skip).
func TestParkCancelMidRemovalAndRecover(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	removed := 0
	h.probe.onProbeFile = func(path string) {
		if strings.Contains(filepath.ToSlash(path), quarantinePrefix) {
			removed++
			if removed == 3 {
				cancel() // mid-walk, after 3 entries were walked
			}
		}
	}

	_, err := h.coord().Park(ctx, h.vault, root, parkOpts(ws))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseRemoving {
		t.Errorf("phase after cancel = %q, want REMOVING (cancellation is not a block)", got)
	}
	// Partial removal: the walk removed some entries; the rest remain.
	quar := filepath.Join(filepath.Dir(root), quarantinePrefix+string(opID))
	if _, err := os.Lstat(quar); err != nil {
		t.Fatalf("quarantine missing: %v", err)
	}

	// New process: fresh coordinator + fresh catalog handle.
	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("recover: %v", rerr)
	}
	if rep.PhaseAfter != catalog.PhaseDone {
		t.Errorf("phase after recover = %q, want DONE (report: %+v)", rep.PhaseAfter, rep)
	}
	mustLstatErrNotExist(t, root)
	mustLstatErrNotExist(t, quar)
	if got := h.phaseOf(t, opID); got != catalog.PhaseDone {
		t.Errorf("journal phase = %q, want DONE", got)
	}
	c := h.coord()
	if w, err := c.cat.GetWorkspace(ws); err != nil || w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace status after recovered park: %+v err=%v", w, err)
	}
	if rep.LastRemovedPath == "" || rep.LastRemovedCount == 0 {
		t.Errorf("report should carry last removed entry from the journal, got %q/%d", rep.LastRemovedPath, rep.LastRemovedCount)
	}
}

// TestRecoverQuarantinedResumesToParked: a crash between the quarantine
// rename and the removal walk (context canceled at the post-rename
// identity probe; the phase commit to QUARANTINED precedes the walk)
// leaves the op QUARANTINED with the root moved. Recover resumes the
// authorized walk to PARKED→DONE.
func TestRecoverQuarantinedResumesToParked(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	before := digestTree(t, root)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.probe.onRootIdentity = func(p string) (domain.RootIdentity, error, bool) {
		if p != root {
			// First non-root probe in the sequence: the quarantine check.
			cancel()
		}
		return domain.RootIdentity{}, nil, false
	}
	_, err := h.coord().Park(ctx, h.vault, root, parkOpts(ws))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled at the quarantine gate, got %v", err)
	}
	opID := h.opIDOf(t, ws)
	if got := h.phaseOf(t, opID); got != catalog.PhaseQuarantined {
		t.Fatalf("phase = %q, want QUARANTINED", got)
	}
	// The root is renamed; nothing inside it was removed yet.
	mustLstatErrNotExist(t, root)
	quar := filepath.Join(filepath.Dir(root), quarantinePrefix+string(opID))
	requireSameTree(t, before, digestTree(t, quar))

	rep, rerr := h.coord().Recover(context.Background(), h.vault, opID)
	if rerr != nil {
		t.Fatalf("recover: %v (report %+v)", rerr, rep)
	}
	if rep.PhaseAfter != catalog.PhaseDone {
		t.Errorf("phase after recover = %q, want DONE", rep.PhaseAfter)
	}
	mustLstatErrNotExist(t, quar)
	c := h.coord()
	if w, err := c.cat.GetWorkspace(ws); err != nil || w.Status != catalog.WorkspaceParked {
		t.Errorf("workspace not parked after recovery: %+v err=%v", w, err)
	}
}
