// wave5_selection_test.go drives the Wave 5 selection/custody refusals:
// E10 (`ebb open <name>` must restore the NEWEST sealed park/snapshot,
// never the ascending-list first match, and must refuse a created_at
// tie) and E12 (the workspace-name binding must never silently rebind a
// recorded root that differs from the capture root; a duplicated name is
// an ambiguity refusal at open, and the open receipt names the exact
// snapshot it restored).

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// seedNamedWorkspace inserts one workspace row directly (the unit-level
// seam for identity/selection tests; no capture machinery involved).
func seedNamedWorkspace(t *testing.T, h *eHarness, id domain.WorkspaceID, name, root, status string) {
	t.Helper()
	if err := h.cat().UpsertWorkspace(catalog.Workspace{
		ID: id, Name: name, RootPath: root, Status: status,
	}); err != nil {
		t.Fatal(err)
	}
}

// seedSealedSnapshot records a sealed snapshot row. The backend ids are
// opaque strings: target resolution only reads the catalog, never the
// store.
func seedSealedSnapshot(t *testing.T, h *eHarness, id domain.SnapshotID, wsID domain.WorkspaceID, kind, createdAt string) {
	t.Helper()
	if _, err := h.cat().RecordSnapshot(catalog.Snapshot{
		ID: id, WorkspaceID: wsID, CreatedAt: createdAt,
		PayloadBackendID: string(domain.NewID()), SealBackendID: string(domain.NewID()),
		Kind: kind, Pinned: true,
	}); err != nil {
		t.Fatal(err)
	}
}

// newSelectionSession opens one session over the harness deps.
func newSelectionSession(t *testing.T, h *eHarness) *session {
	t.Helper()
	sess, err := openSession(h.deps)
	if err != nil {
		t.Fatalf("openSession: %v", err)
	}
	t.Cleanup(sess.close)
	return sess
}

// TestResolveOpenTargetSelectsNewestSealedPark: three sealed parks in
// ascending creation order — the open target is the NEWEST one (E10; the
// ascending ListSnapshots order used to make the first match, i.e. the
// OLDEST park, win).
func TestResolveOpenTargetSelectsNewestSealedPark(t *testing.T) {
	h := newEHarness(t)
	wsID := domain.WorkspaceID(domain.NewID())
	seedNamedWorkspace(t, h, wsID, "cliws",
		filepath.Clean(filepath.Join(h.wsRoot, "..", "ws")), catalog.WorkspaceLive)
	oldest := domain.SnapshotID(domain.NewID())
	mid := domain.SnapshotID(domain.NewID())
	newest := domain.SnapshotID(domain.NewID())
	seedSealedSnapshot(t, h, oldest, wsID, catalog.SnapshotKindPark, "2026-09-01T10:00:00Z")
	seedSealedSnapshot(t, h, mid, wsID, catalog.SnapshotKindPark, "2026-09-02T10:00:00Z")
	seedSealedSnapshot(t, h, newest, wsID, catalog.SnapshotKindPark, "2026-09-03T10:00:00Z")

	sess := newSelectionSession(t, h)
	got, _, err := resolveOpenTarget(sess, "cliws")
	if err != nil {
		t.Fatalf("resolveOpenTarget: %v", err)
	}
	if got != newest {
		t.Fatalf("resolveOpenTarget picked snapshot %s, want the NEWEST sealed park %s", got, newest)
	}
}

// TestResolveOpenTargetPrefersParkOverNewerSnapshot: park-kind precedence
// is preserved — any sealed park beats any sealed plain snapshot, even a
// strictly newer one.
func TestResolveOpenTargetPrefersParkOverNewerSnapshot(t *testing.T) {
	h := newEHarness(t)
	wsID := domain.WorkspaceID(domain.NewID())
	seedNamedWorkspace(t, h, wsID, "cliws",
		filepath.Clean(filepath.Join(h.wsRoot, "..", "ws")), catalog.WorkspaceLive)
	park := domain.SnapshotID(domain.NewID())
	plain := domain.SnapshotID(domain.NewID())
	seedSealedSnapshot(t, h, park, wsID, catalog.SnapshotKindPark, "2026-09-01T10:00:00Z")
	seedSealedSnapshot(t, h, plain, wsID, catalog.SnapshotKindSnapshot, "2026-09-05T10:00:00Z")

	sess := newSelectionSession(t, h)
	got, _, err := resolveOpenTarget(sess, "cliws")
	if err != nil {
		t.Fatalf("resolveOpenTarget: %v", err)
	}
	if got != park {
		t.Fatalf("resolveOpenTarget picked %s, want the park %s (park-kind precedence must hold over a newer plain snapshot)", got, park)
	}
}

// TestResolveOpenTargetTieRefuses: two sealed parks sharing the exact
// same created_at string cannot be ordered by recency — the resolution
// must refuse as ambiguous, naming both ids and the shared timestamp and
// pointing at the explicit snapshot id escape hatch.
func TestResolveOpenTargetTieRefuses(t *testing.T) {
	h := newEHarness(t)
	wsID := domain.WorkspaceID(domain.NewID())
	seedNamedWorkspace(t, h, wsID, "cliws",
		filepath.Clean(filepath.Join(h.wsRoot, "..", "ws")), catalog.WorkspaceLive)
	a := domain.SnapshotID(domain.NewID())
	b := domain.SnapshotID(domain.NewID())
	const tie = "2026-09-03T10:00:00Z"
	seedSealedSnapshot(t, h, a, wsID, catalog.SnapshotKindPark, tie)
	seedSealedSnapshot(t, h, b, wsID, catalog.SnapshotKindPark, tie)

	sess := newSelectionSession(t, h)
	_, _, err := resolveOpenTarget(sess, "cliws")
	if err == nil {
		t.Fatal("resolveOpenTarget must refuse a created_at tie, got nil error")
	}
	for _, want := range []string{"EBB_E_OPEN_AMBIGUOUS_TARGET", string(a), string(b), tie, "snapshot id"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("tie refusal lacks %q:\n%s", want, err.Error())
		}
	}
	if got := classifyExitCode(err); got != ExitBlocked {
		t.Errorf("classifyExitCode(tie refusal) = %d, want %d (blocked)", got, ExitBlocked)
	}
}

// TestOpenReceiptNamesSnapshotIDKindAndCreated: the open success receipt
// must name WHICH state came back — snapshot id, kind and creation
// timestamp — in both the human report and the JSON envelope details
// (E10 receipt).
func TestOpenReceiptNamesSnapshotIDKindAndCreated(t *testing.T) {
	h := newGHarness(t)
	parkID := parkG(t, h)
	snap, err := h.cat().GetSnapshot(parkID)
	if err != nil {
		t.Fatal(err)
	}
	h.tty = false

	// JSON mode: the envelope details carry all three fields additively.
	code, stdout, stderr := h.run("open", "cliws", "--to", gDest(t), "--json", "--files-only")
	if code != ExitOK {
		t.Fatalf("open --json code = %d, stderr = %s", code, stderr)
	}
	env := envelopeOf(t, stdout)
	details, ok := env["details"].(map[string]any)
	if !ok {
		t.Fatalf("envelope lacks a details object: %v", env)
	}
	for field, want := range map[string]string{
		"snapshot_id":         string(parkID),
		"snapshot_kind":       snap.Kind,
		"snapshot_created_at": snap.CreatedAt,
	} {
		if got, _ := details[field].(string); got != want {
			t.Errorf("details[%q] = %q, want %q", field, got, want)
		}
	}

	// Human mode: the receipt line names all three too.
	h.resetSignalContext()
	code, _, stderr = h.run("open", "cliws", "--to", gDest(t), "--files-only")
	if code != ExitOK {
		t.Fatalf("open code = %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		string(parkID),
		"(kind " + snap.Kind + ", created " + snap.CreatedAt,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("human receipt lacks %q:\n%s", want, stderr)
		}
	}
}

// TestOpenDuplicateNameRefuses: a target name matching several workspace
// rows (any status) is an ambiguity refusal (E12 listing half) naming
// each candidate's id, status and root — never a silent "parked row
// wins" pick.
func TestOpenDuplicateNameRefuses(t *testing.T) {
	h := newEHarness(t)
	idA := domain.WorkspaceID(domain.NewID())
	idB := domain.WorkspaceID(domain.NewID())
	rootA := filepath.Clean(filepath.Join(h.wsRoot, "..", "project-a"))
	rootB := filepath.Clean(filepath.Join(h.wsRoot, "..", "project-b"))
	seedNamedWorkspace(t, h, idA, "cliws", rootA, catalog.WorkspaceLive)
	seedNamedWorkspace(t, h, idB, "cliws", rootB, catalog.WorkspaceParked)
	// Both rows hold a sealed park, so the refusal is about the ambiguous
	// NAME, not a missing snapshot.
	seedSealedSnapshot(t, h, domain.SnapshotID(domain.NewID()), idA, catalog.SnapshotKindPark, "2026-09-01T10:00:00Z")
	seedSealedSnapshot(t, h, domain.SnapshotID(domain.NewID()), idB, catalog.SnapshotKindPark, "2026-09-02T10:00:00Z")
	h.tty = false

	code, _, stderr := h.run("open", "cliws", "--to", gDest(t))
	if code != ExitBlocked {
		t.Fatalf("open with a duplicated name must refuse blocked, got code %d, stderr = %s", code, stderr)
	}
	for _, want := range []string{
		"EBB_E_OPEN_AMBIGUOUS_TARGET", string(idA), string(idB), rootA, rootB, "snapshot id",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("duplicate-name refusal lacks %q:\n%s", want, stderr)
		}
	}
}

// TestParkDifferentRootSameNameDoesNotRebindRow: the E12 accident end to
// end — a LIVE workspace row named "cliws" is recorded at one root while
// a DIFFERENT directory (same Ebbfile workspace name) is parked. The
// name-only fallback used to adopt the pre-existing row so
// lifecycle.beginOperation silently rewrote its RootPath. openCapture-
// Command now resolves STRICTLY: the whole capture command refuses with
// the EBB_E_WORKSPACE_IDENTITY_MISMATCH blocked error and the row stays
// untouched (surfaced refusal, not just unreachable rebind).
func TestParkDifferentRootSameNameDoesNotRebindRow(t *testing.T) {
	h := newEHarness(t)
	ghostID := domain.WorkspaceID(domain.NewID())
	ghostRoot := filepath.Clean(filepath.Join(h.wsRoot, "..", "ghost"))
	seedNamedWorkspace(t, h, ghostID, "cliws", ghostRoot, catalog.WorkspaceLive)
	h.tty = false

	code, _, stderr := h.run("park", "--assert-writers-stopped", h.wsRoot)
	if code != ExitBlocked {
		t.Fatalf("park code = %d, want the blocked exit %d (stderr = %s)", code, ExitBlocked, stderr)
	}
	if !strings.Contains(stderr, CodeWorkspaceIdentityMismatch) {
		t.Fatalf("park refusal must carry %s, stderr = %s", CodeWorkspaceIdentityMismatch, stderr)
	}
	if !strings.Contains(stderr, ghostRoot) {
		t.Fatalf("park refusal must name the recorded root %s, stderr = %s", ghostRoot, stderr)
	}
	row, err := h.cat().GetWorkspace(ghostID)
	if err != nil {
		t.Fatal(err)
	}
	if row.RootPath != ghostRoot || row.Status != catalog.WorkspaceLive {
		t.Fatalf("E12 rebind: the pre-existing row was mutated (RootPath = %q, status = %q); want untouched (%q, LIVE)",
			row.RootPath, row.Status, ghostRoot)
	}
}

// TestResolveWorkspaceIDSameRootAllowed: the legitimate recapture — the
// same root under the same name still rebinds the SAME workspace id.
func TestResolveWorkspaceIDSameRootAllowed(t *testing.T) {
	h := newEHarness(t)
	id := domain.WorkspaceID(domain.NewID())
	root := filepath.Clean(filepath.Join(h.wsRoot, "..", "elsewhere"))
	seedNamedWorkspace(t, h, id, "cliws", root, catalog.WorkspaceLive)
	sess := newSelectionSession(t, h)

	got, err := sess.resolveWorkspaceIDRefusing("cliws", root)
	if err != nil {
		t.Fatalf("same-root recapture must be allowed: %v", err)
	}
	if got != id {
		t.Fatalf("same-root recapture id = %s, want the recorded %s", got, id)
	}
	if wrapped := sess.resolveWorkspaceID("cliws", root); wrapped != id {
		t.Fatalf("wrapper id = %s, want %s", wrapped, id)
	}
	// A spelling that cleans to the same path is still the same root.
	dotted := filepath.Clean(filepath.Join(root, "sub", ".."))
	got2, err := sess.resolveWorkspaceIDRefusing("cliws", dotted)
	if err != nil || got2 != id {
		t.Fatalf("cleaned same-root match: id = %s, err = %v, want %s, nil", got2, err, id)
	}
}

// TestResolveWorkspaceIDRootMismatchRefuses: a live row with the same
// name recorded at a DIFFERENT root (another directory/drive — drives
// are not portable across test machines, the differing absolute path is
// the point) must be refused, never adopted; the catalog row's recorded
// root stays untouched after the refusal.
func TestResolveWorkspaceIDRootMismatchRefuses(t *testing.T) {
	h := newEHarness(t)
	id := domain.WorkspaceID(domain.NewID())
	recorded := filepath.Clean(filepath.Join(h.wsRoot, "..", "original"))
	seedNamedWorkspace(t, h, id, "cliws", recorded, catalog.WorkspaceLive)
	sess := newSelectionSession(t, h)
	moved := filepath.Clean(filepath.Join(h.wsRoot, "..", "moved-elsewhere"))

	got, err := sess.resolveWorkspaceIDRefusing("cliws", moved)
	if err == nil {
		t.Fatalf("root mismatch must refuse, got id %s", got)
	}
	if got != "" {
		t.Fatalf("a refused match must not hand out the old id, got %s", got)
	}
	for _, want := range []string{"EBB_E_WORKSPACE_IDENTITY_MISMATCH", string(id), recorded, moved} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rebind refusal lacks %q:\n%s", want, err.Error())
		}
	}
	if gotCode := classifyExitCode(err); gotCode != ExitBlocked {
		t.Errorf("classifyExitCode(rebind refusal) = %d, want %d (blocked)", gotCode, ExitBlocked)
	}
	// The refusal fires BEFORE any lifecycle write: the row is untouched.
	row, gerr := h.cat().GetWorkspace(id)
	if gerr != nil {
		t.Fatal(gerr)
	}
	if row.RootPath != recorded {
		t.Fatalf("recorded RootPath mutated by the refused capture: %q, want %q", row.RootPath, recorded)
	}
	// The lossy wrapper degrades a refusal to a fresh workspace (empty
	// id), never to the old id — the silent rebind is unreachable.
	if wrapped := sess.resolveWorkspaceID("cliws", moved); wrapped != "" {
		t.Fatalf("wrapper must degrade a refused match to a fresh workspace, got %s", wrapped)
	}
}

// TestResolveOpenTargetTieAcrossRepresentations: the SAME instant in two
// RFC3339Nano spellings (".123Z" vs ".123000000Z" — RecordSnapshot does
// not normalize supplied timestamps) is a tie by INSTANT, not by bytes;
// exact-string tie detection used to silently pick one of them.
func TestResolveOpenTargetTieAcrossRepresentations(t *testing.T) {
	h := newEHarness(t)
	wsID := domain.WorkspaceID(domain.NewID())
	seedNamedWorkspace(t, h, wsID, "cliws", h.wsRoot, catalog.WorkspaceLive)
	seedSealedSnapshot(t, h, domain.SnapshotID(domain.NewID()), wsID, catalog.SnapshotKindPark, "2026-09-01T10:00:00.123Z")
	seedSealedSnapshot(t, h, domain.SnapshotID(domain.NewID()), wsID, catalog.SnapshotKindPark, "2026-09-01T10:00:00.123000000Z")
	sess := newSelectionSession(t, h)

	_, _, err := resolveOpenTarget(sess, "cliws")
	if err == nil {
		t.Fatal("same-instant different-spelling timestamps must refuse as ambiguous, got nil error")
	}
	if !strings.Contains(err.Error(), CodeOpenAmbiguousTarget) {
		t.Fatalf("refusal must carry %s, got: %v", CodeOpenAmbiguousTarget, err)
	}
}

// TestResolveOpenTargetInvalidTimestampFailsClosed: an unparseable
// created_at on an eligible sealed row is corrupt evidence — selection
// must fail closed with the invalid-timestamp code, never fall back to
// lexical ordering.
func TestResolveOpenTargetInvalidTimestampFailsClosed(t *testing.T) {
	h := newEHarness(t)
	wsID := domain.WorkspaceID(domain.NewID())
	seedNamedWorkspace(t, h, wsID, "cliws", h.wsRoot, catalog.WorkspaceLive)
	seedSealedSnapshot(t, h, domain.SnapshotID(domain.NewID()), wsID, catalog.SnapshotKindPark, "2026-09-01T10:00:00Z")
	bad := domain.SnapshotID(domain.NewID())
	seedSealedSnapshot(t, h, bad, wsID, catalog.SnapshotKindPark, "not-a-timestamp")
	sess := newSelectionSession(t, h)

	_, _, err := resolveOpenTarget(sess, "cliws")
	if err == nil {
		t.Fatal("unparseable created_at must fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), CodeOpenTimestampInvalid) {
		t.Fatalf("refusal must carry %s, got: %v", CodeOpenTimestampInvalid, err)
	}
	if !strings.Contains(err.Error(), string(bad)) {
		t.Fatalf("refusal must name the corrupt row %s, got: %v", bad, err)
	}
}
