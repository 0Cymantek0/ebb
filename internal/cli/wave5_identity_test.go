// wave5_identity_test.go pins the Wave 5 same-path replacement guard on
// top of E12: a directory DELETED and REPLACED at the same path (new
// native identity) must never adopt the old workspace row, even though
// name and root path still match exactly. The catalog row records the
// native root identity (workspaces.root_identity), so strict resolution
// compares it against the DISCOVERED identity of the capture root:
// same identity → same workspace (the legitimate recapture), no recorded
// identity → back-compat adopt (this capture stamps it), different
// identity → blocked refusal naming both identities, row untouched.

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// identA/identB are two distinct native identities for one path: A is
// what the catalog row recorded, B is what the probe reports after the
// directory at that path was replaced.
var (
	identA = domain.RootIdentity{VolumeID: "vol-x", FileID: "file-a"}
	identB = domain.RootIdentity{VolumeID: "vol-x", FileID: "file-b"}
)

// seedIdentifiedWorkspace inserts one workspace row WITH its recorded
// native root identity (the post-D060 row shape).
func seedIdentifiedWorkspace(t *testing.T, h *eHarness, id domain.WorkspaceID, name, root, identity, status string) {
	t.Helper()
	if err := h.cat().UpsertWorkspace(catalog.Workspace{
		ID: id, Name: name, RootPath: root, RootIdentity: identity, Status: status,
	}); err != nil {
		t.Fatal(err)
	}
}

// assertRowUntouched reads the row and asserts path, identity and status
// survived a refused resolution (refusals fire BEFORE any lifecycle
// write; the old row's history must stay bound to the old directory).
func assertRowUntouched(t *testing.T, h *eHarness, id domain.WorkspaceID, name, root, identity, status string) {
	t.Helper()
	row, err := h.cat().GetWorkspace(id)
	if err != nil {
		t.Fatal(err)
	}
	if row.RootPath != root || row.RootIdentity != identity || row.Status != status {
		t.Fatalf("the refused capture mutated workspace %s: path %q identity %q status %q, want (%q, %q, %q)",
			id, row.RootPath, row.RootIdentity, row.Status, root, identity, status)
	}
}

// TestReplacedDirectorySamePathRefuses: the P1 hole — the row records
// identity A at path P; the directory at P was deleted and recreated
// (live identity B). Strict resolution must refuse with
// EBB_E_WORKSPACE_IDENTITY_MISMATCH naming BOTH identities and both
// escape routes, hand out no workspace id, and leave the row untouched.
// (Name+path matching alone still adopted here: the same
// identity-corruption class E12 stopped for path MOVEMENT, via path
// REUSE.)
func TestReplacedDirectorySamePathRefuses(t *testing.T) {
	h := newEHarness(t)
	id := domain.WorkspaceID(domain.NewID())
	root := filepath.Clean(filepath.Join(h.wsRoot, "..", "replaced"))
	seedIdentifiedWorkspace(t, h, id, "cliws", root, identA.String(), catalog.WorkspaceLive)
	sess := newSelectionSession(t, h)

	got, err := sess.resolveWorkspaceIDRefusing("cliws", root, identB)
	if err == nil {
		t.Fatalf("a replaced directory at the same path must refuse, got id %s", got)
	}
	if got != "" {
		t.Fatalf("a refused match must not hand out the old id, got %s", got)
	}
	for _, want := range []string{
		CodeWorkspaceIdentityMismatch, string(id), root,
		identA.String(), identB.String(), "replaced",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("replaced-directory refusal lacks %q:\n%s", want, err.Error())
		}
	}
	if gotCode := classifyExitCode(err); gotCode != ExitBlocked {
		t.Errorf("classifyExitCode(replaced-directory refusal) = %d, want %d (blocked)", gotCode, ExitBlocked)
	}
	assertRowUntouched(t, h, id, "cliws", root, identA.String(), catalog.WorkspaceLive)
}

// TestReplacedDirectoryCaptureRefusedEndToEnd: the same accident through
// the real capture commands — the row records a native identity the
// directory NO LONGER has (it was deleted and recreated; the REAL probe
// reports the live object's identity, consistent for discovery and the
// scanner's own revalidation), so `ebb snapshot` and `ebb park` refuse
// blocked naming the code and both identities, and the seeded row
// survives both refusals bit-for-bit.
func TestReplacedDirectoryCaptureRefusedEndToEnd(t *testing.T) {
	h := newEHarness(t)
	id := domain.WorkspaceID(domain.NewID())
	seedIdentifiedWorkspace(t, h, id, "cliws", h.wsRoot, identA.String(), catalog.WorkspaceLive)
	// The identity the REAL platform probe reports for the live
	// directory — necessarily different from the seeded identA (real
	// identities are volume-serial/file-index encodings).
	live, err := h.probe.inner.RootIdentity(h.wsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if live == identA {
		t.Fatalf("fixture collision: the seeded identity equals the live one")
	}
	h.tty = false

	for _, cmd := range []string{"snapshot", "park"} {
		args := []string{cmd}
		if cmd == "park" {
			args = append(args, "--assert-writers-stopped")
		}
		args = append(args, h.wsRoot)
		code, _, stderr := h.run(args...)
		if code != ExitBlocked {
			t.Fatalf("%s code = %d, want blocked %d (stderr = %s)", cmd, code, ExitBlocked, stderr)
		}
		for _, want := range []string{CodeWorkspaceIdentityMismatch, identA.String(), live.String(), "replaced"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%s refusal lacks %q:\n%s", cmd, want, stderr)
			}
		}
		assertRowUntouched(t, h, id, "cliws", h.wsRoot, identA.String(), catalog.WorkspaceLive)
	}
}

// TestSameIdentityRecaptureAllowed: the legitimate flow stays open — the
// SAME directory (recorded identity == discovered identity) recaptures
// under the same name and keeps the SAME workspace id, at the unit seam
// and end to end (where the first capture stamps the row's identity and
// the second one matches against it).
func TestSameIdentityRecaptureAllowed(t *testing.T) {
	h := newEHarness(t)
	id := domain.WorkspaceID(domain.NewID())
	root := filepath.Clean(filepath.Join(h.wsRoot, "..", "same"))
	seedIdentifiedWorkspace(t, h, id, "cliws", root, identA.String(), catalog.WorkspaceLive)
	sess := newSelectionSession(t, h)

	got, err := sess.resolveWorkspaceIDRefusing("cliws", root, identA)
	if err != nil {
		t.Fatalf("same-identity recapture must be allowed: %v", err)
	}
	if got != id {
		t.Fatalf("same-identity recapture id = %s, want the recorded %s", got, id)
	}
}

// TestSameIdentityRecaptureEndToEndKeepsWorkspace: two captures of the
// same directory under the same name resolve to ONE workspace id — the
// first capture stamps the discovered native identity on the row, the
// second matches against it (the back-compat adopt-and-stamp loop).
func TestSameIdentityRecaptureEndToEndKeepsWorkspace(t *testing.T) {
	h := newEHarness(t)
	h.tty = false

	code, stdout, stderr := h.run("snapshot", h.wsRoot, "--json")
	if code != ExitOK {
		t.Fatalf("first snapshot code = %d, stderr = %s", code, stderr)
	}
	first := envString(t, envelopeOf(t, stdout), "workspace_id")

	code, stdout, stderr = h.run("snapshot", h.wsRoot, "--json")
	if code != ExitOK {
		t.Fatalf("second snapshot code = %d, stderr = %s", code, stderr)
	}
	if second := envString(t, envelopeOf(t, stdout), "workspace_id"); second != first {
		t.Fatalf("the recapture did not keep the workspace: %s != %s", first, second)
	}

	// The row carries the stamped native identity (beginOperation wrote
	// it; the strict second pass matched against it).
	row := h.workspaceRowOf("cliws")
	if row.RootIdentity == "" {
		t.Fatalf("the recapture flow must stamp the native identity on the row, got empty")
	}
}

// TestUnidentifiedRowBackCompatAdoptAndStamp: a row recorded BEFORE
// identity stamping (RootIdentity empty) at the same name+path still
// adopts — and the very capture that adopts it stamps the discovered
// identity (asserted via the end-to-end loop in
// TestSameIdentityRecaptureEndToEndKeepsWorkspace; here at the unit
// seam).
func TestUnidentifiedRowBackCompatAdoptAndStamp(t *testing.T) {
	h := newEHarness(t)
	id := domain.WorkspaceID(domain.NewID())
	root := filepath.Clean(filepath.Join(h.wsRoot, "..", "legacy"))
	seedNamedWorkspace(t, h, id, "cliws", root, catalog.WorkspaceLive)
	sess := newSelectionSession(t, h)

	got, err := sess.resolveWorkspaceIDRefusing("cliws", root, identA)
	if err != nil {
		t.Fatalf("a pre-stamping row must still adopt at the same name+path: %v", err)
	}
	if got != id {
		t.Fatalf("back-compat adopt id = %s, want %s", got, id)
	}
}
