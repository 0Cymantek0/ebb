package restore

// The §12.5 contract tests. Every fault case asserts the full safety
// posture: what was published (or not), what staging remains (or not),
// the durable operation phase, and the workspace/snapshot rows.

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

func TestNewRefusesNilSeams(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	if _, err := New(Dependencies{Cat: f.cat, Probe: f.probe}); err == nil {
		t.Fatal("New must refuse a nil Store")
	}
	if _, err := New(Dependencies{Store: f.store, Probe: f.probe}); err == nil {
		t.Fatal("New must refuse a nil Catalog")
	}
	if _, err := New(Dependencies{Store: f.store, Cat: f.cat}); err == nil {
		t.Fatal("New must refuse a nil Probe")
	}
}

// Round trip: files + symlink/junction + empty dir + nested tree are
// restored to an absent destination, byte-compared by the TEST's own
// walker, the op completes to DONE (files-only), the workspace goes live with a
// fresh identity, the staging is cleaned, and the snapshot stays pinned.
func TestOpenRoundTrip(t *testing.T) {
	f := buildFixture(t, fixtureSpec{recipeGroup: true})
	dest := filepath.Join(f.parent, "restored")
	o := newOpener(f)

	res, err := f.open(context.Background(), o, Options{Destination: dest, FilesOnly: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// Independent byte-for-byte comparison against the fixture source.
	assertTreesByteEqual(t, f.srcRoot, dest)

	if res.Destination != dest {
		t.Fatalf("result destination %q, want %q", res.Destination, dest)
	}
	var wantEntries int64
	for _, e := range f.entries {
		if e.Route == domain.RoutePreserve {
			wantEntries++
		}
	}
	if res.EntriesRestored != wantEntries {
		t.Fatalf("EntriesRestored = %d, want %d", res.EntriesRestored, wantEntries)
	}
	if res.BytesRestored != f.preservedBytes() {
		t.Fatalf("BytesRestored = %d, want %d", res.BytesRestored, f.preservedBytes())
	}
	if res.OperationID == "" || res.SnapshotID != f.snapID || res.WorkspaceID != f.wsID {
		t.Fatalf("result identity fields incomplete: %+v", res)
	}

	// Staging fully cleaned.
	assertNoStageDirs(t, f.parent)

	// Durable state: op DONE (a files-only open completes: nothing
	// outstanding — D006 convention), workspace live at dest with a
	// fresh identity, snapshot still pinned (I07).
	op, err := f.cat.GetOperation(res.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Phase != catalog.PhaseDone {
		t.Fatalf("operation phase %q, want DONE", op.Phase)
	}
	if op.Kind != catalog.OpKindOpen {
		t.Fatalf("operation kind %q, want open", op.Kind)
	}
	ws, err := f.cat.GetWorkspace(f.wsID)
	if err != nil {
		t.Fatalf("get workspace: %v", err)
	}
	if ws.Status != catalog.WorkspaceLive || ws.RootPath != dest {
		t.Fatalf("workspace status/root = %q/%q, want live/%q", ws.Status, ws.RootPath, dest)
	}
	ident, err := f.probe.RootIdentity(dest)
	if err != nil {
		t.Fatalf("probe identity of dest: %v", err)
	}
	if ws.RootIdentity != ident.String() {
		t.Fatalf("workspace root identity %q, want the freshly probed %q (I13 re-bind)", ws.RootIdentity, ident.String())
	}
	snap, err := f.cat.GetSnapshot(f.snapID)
	if err != nil {
		t.Fatalf("get snapshot: %v", err)
	}
	if !snap.Pinned {
		t.Fatal("snapshot must stay pinned after opening (I07)")
	}

	// The empty dir and the link survived publication.
	fi, err := os.Lstat(filepath.Join(dest, "emptydir"))
	if err != nil || !fi.IsDir() {
		t.Fatalf("emptydir missing at destination: %v", err)
	}
	wantLink, err := os.Readlink(filepath.Join(f.srcRoot, "link"))
	if err != nil {
		t.Fatalf("fixture link text: %v", err)
	}
	gotLink, err := os.Readlink(filepath.Join(dest, "link"))
	if err != nil {
		t.Fatalf("restored link: %v", err)
	}
	if wantLink != gotLink {
		t.Fatalf("link text %q, want %q", gotLink, wantLink)
	}

	// Rebuild hints: the pnpm group with the ecosystem recipe constant.
	if len(res.RebuildHints) != 1 {
		t.Fatalf("RebuildHints = %+v, want exactly the node-dependencies group", res.RebuildHints)
	}
	h := res.RebuildHints[0]
	if h.GroupID != "node-dependencies" ||
		strings.Join(h.Command, " ") != "pnpm install --frozen-lockfile" ||
		strings.Join(h.Inputs, ",") != "package.json,pnpm-lock.yaml" ||
		h.Network != "allowed" {
		t.Fatalf("unexpected rebuild hint: %+v", h)
	}
}

// A custom action command overrides the ecosystem recipe constant.
func TestOpenRebuildHintCustomCommand(t *testing.T) {
	f := buildFixture(t, fixtureSpec{recipeGroup: true,
		customCommand: []string{"./tools/rebuild.sh", "--offline"}})
	dest := filepath.Join(f.parent, "restored")
	res, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if len(res.RebuildHints) != 1 || strings.Join(res.RebuildHints[0].Command, " ") != "./tools/rebuild.sh --offline" {
		t.Fatalf("custom command hint not carried: %+v", res.RebuildHints)
	}
}

// FilesOnly=false on a manifest WITHOUT action definitions (the
// hint-only fixture) completes directly FILES_READY -> DONE: a legacy
// payload is never executed, and nothing is left outstanding.
func TestOpenFilesOnlyFalseWithoutDefinitionsCompletes(t *testing.T) {
	f := buildFixture(t, fixtureSpec{recipeGroup: true})
	dest := filepath.Join(f.parent, "restored")
	res, err := f.open(context.Background(), newOpener(f), Options{Destination: dest})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if res.Phase != catalog.PhaseDone {
		t.Fatalf("phase = %q, want DONE (hint-only manifests never rebuild)", res.Phase)
	}
	if len(res.RebuildHints) != 1 {
		t.Fatalf("rebuild hints = %v, want the hint-only group reported", res.RebuildHints)
	}
	if len(res.Actions) != 0 {
		t.Fatalf("no action may run from a hint-only manifest: %+v", res.Actions)
	}
}

// Oracle catches a silently dropped file: nothing published, staging
// removed, operation failed at RESTORING.
func TestOpenOracleCatchesDroppedFile(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	f.store.restoreDrop["/"+f.wsPrefix+"/sub/b.txt"] = true
	dest := filepath.Join(f.parent, "restored")

	_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var verr *ErrVerification
	if !errors.As(err, &verr) || verr.Check != "oracle" {
		t.Fatalf("err = %v, want ErrVerification{oracle}", err)
	}
	joined := strings.Join(verr.Details, "; ")
	if !strings.Contains(joined, "sub/b.txt") {
		t.Fatalf("oracle details must name the dropped path: %v", verr.Details)
	}
	if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing may be published; dest state: %v", err)
	}
	assertNoStageDirs(t, f.parent)
	assertSingleFailedRestoringOp(t, f, "oracle")
}

// Oracle catches corrupted content: same contract as the dropped file.
func TestOpenOracleCatchesCorruptedContent(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	f.store.restoreCorrupt["/"+f.wsPrefix+"/a.txt"] = "tampered bytes"
	dest := filepath.Join(f.parent, "restored")

	_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var verr *ErrVerification
	if !errors.As(err, &verr) || verr.Check != "oracle" {
		t.Fatalf("err = %v, want ErrVerification{oracle}", err)
	}
	if !strings.Contains(strings.Join(verr.Details, "; "), "a.txt") {
		t.Fatalf("oracle details must name the corrupted path: %v", verr.Details)
	}
	if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nothing may be published; dest state: %v", err)
	}
	assertNoStageDirs(t, f.parent)
	assertSingleFailedRestoringOp(t, f, "oracle")
}

// The backend failing mid-restore leaves nothing staged and the
// operation failed at RESTORING.
func TestOpenRestoreFailsMidway(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	f.store.restoreErr = &domain.StoreError{Class: domain.StoreErrSource,
		Err: errors.New("simulated mid-restore failure")}
	dest := filepath.Join(f.parent, "restored")

	_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if err == nil || !strings.Contains(err.Error(), "simulated mid-restore failure") {
		t.Fatalf("err = %v, want the store failure surfaced", err)
	}
	assertNoStageDirs(t, f.parent)
	if _, lerr := os.Lstat(dest); !errors.Is(lerr, os.ErrNotExist) {
		t.Fatalf("nothing may be published; dest state: %v", lerr)
	}
	assertSingleFailedRestoringOp(t, f, "materialize")
}

// Receipt naming a different payload id: ErrSealInvalid before anything
// is staged or journaled.
func TestOpenReceiptPayloadMismatch(t *testing.T) {
	f := buildFixture(t, fixtureSpec{receiptPayload: strings.Repeat("dead", 16)})
	dest := filepath.Join(f.parent, "restored")

	_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var serr *ErrSealInvalid
	if !errors.As(err, &serr) {
		t.Fatalf("err = %v, want ErrSealInvalid", err)
	}
	assertNoStageDirs(t, f.parent)
	assertNoOperations(t, f)
}

// Tampered manifest bytes fail the digest comparison against the seal
// (I12: never trust a listing without comparing bytes).
func TestOpenManifestDigestMismatch(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	manifestPath := "/" + f.opDirName + "/" + manifestName
	f.store.dumpTamper[manifestPath] = func(b []byte) []byte { return append(b, 'x') }
	dest := filepath.Join(f.parent, "restored")

	_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var verr *ErrVerification
	if !errors.As(err, &verr) || verr.Check != "documents" {
		t.Fatalf("err = %v, want ErrVerification{documents}", err)
	}
	assertNoStageDirs(t, f.parent)
	assertNoOperations(t, f)
}

// Unknown fields are rejected by strict parsing: receipt (seal invalid)
// and inventory record (documents), the latter with digests recomputed
// so ONLY strictness can catch it.
func TestOpenStrictParseUnknownFields(t *testing.T) {
	t.Run("receipt", func(t *testing.T) {
		f := buildFixture(t, fixtureSpec{extraReceiptFld: true})
		dest := filepath.Join(f.parent, "restored")
		_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
		var serr *ErrSealInvalid
		if !errors.As(err, &serr) || !strings.Contains(strings.Join(serr.Details, "; "), "strict") {
			t.Fatalf("err = %v, want ErrSealInvalid naming strict parsing", err)
		}
		assertNoStageDirs(t, f.parent)
		assertNoOperations(t, f)
	})
	t.Run("inventory line", func(t *testing.T) {
		f := buildFixture(t, fixtureSpec{extraInvLine: true})
		dest := filepath.Join(f.parent, "restored")
		_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
		var verr *ErrVerification
		if !errors.As(err, &verr) || verr.Check != "documents" {
			t.Fatalf("err = %v, want ErrVerification{documents}", err)
		}
		if !strings.Contains(strings.Join(verr.Details, "; "), "strict") {
			t.Fatalf("details must name strict parsing: %v", verr.Details)
		}
		assertNoStageDirs(t, f.parent)
		assertNoOperations(t, f)
	})
}

// A seal snapshot whose listing hides the receipt cannot be validated.
func TestOpenSealReceiptHiddenByLs(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	f.store.lsHide["/"+sealPrefix+string(f.opID)+"/"+receiptName] = true
	dest := filepath.Join(f.parent, "restored")

	_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var serr *ErrSealInvalid
	if !errors.As(err, &serr) {
		t.Fatalf("err = %v, want ErrSealInvalid", err)
	}
	assertNoStageDirs(t, f.parent)
	assertNoOperations(t, f)
}

// Occupied destination: a nonempty unrelated directory is refused
// untouched.
func TestOpenDestinationOccupied(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")
	mustMkdir(t, dest)
	writeFile(t, filepath.Join(dest, "occupant.txt"), []byte("do not touch\n"))

	_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var oerr *ErrDestinationOccupied
	if !errors.As(err, &oerr) || oerr.Code() != CodeDestOccupied {
		t.Fatalf("err = %v, want ErrDestinationOccupied", err)
	}
	got, rerr := os.ReadFile(filepath.Join(dest, "occupant.txt"))
	if rerr != nil || string(got) != "do not touch\n" {
		t.Fatalf("occupant mutated: %q %v", got, rerr)
	}
	names := stageDirs(t, f.parent)
	if len(names) > 0 {
		// Occupied is detected in preflight, before staging.
		t.Fatalf("no staging expected, found %v", names)
	}
	assertNoOperations(t, f)
}

// An existing EMPTY destination directory is acceptable.
func TestOpenDestinationEmptyDirAccepted(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")
	mustMkdir(t, dest)

	if _, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true}); err != nil {
		t.Fatalf("open: %v", err)
	}
	assertTreesByteEqual(t, f.srcRoot, dest)
	assertNoStageDirs(t, f.parent)
}

// Insufficient space: blocked before staging with both numbers named.
func TestOpenInsufficientSpace(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")

	limited := &spaceProbe{PlatformProbe: f.probe, free: 5}
	o, err := New(Dependencies{Store: f.store, Cat: f.cat, Probe: limited})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = f.open(context.Background(), o, Options{Destination: dest, FilesOnly: true})
	var serr *ErrInsufficientSpace
	if !errors.As(err, &serr) {
		t.Fatalf("err = %v, want ErrInsufficientSpace", err)
	}
	if serr.Free != 5 || serr.Needed != f.preservedBytes() {
		t.Fatalf("space error numbers = %d free / %d needed, want 5 / %d", serr.Free, serr.Needed, f.preservedBytes())
	}
	if !strings.Contains(serr.Error(), "5") || !strings.Contains(serr.Error(), "preserved content") {
		t.Fatalf("error must name both numbers: %q", serr.Error())
	}
	assertNoStageDirs(t, f.parent)
	assertNoOperations(t, f)
}

// Wrong kinds and missing ids are refused precisely.
func TestOpenRefusesNonOpenableSnapshots(t *testing.T) {
	cases := []struct {
		name string
		spec fixtureSpec
		want string
	}{
		{"trim kind", fixtureSpec{kind: catalog.SnapshotKindTrim}, "removal plan"},
		{"seal kind", fixtureSpec{kind: catalog.SnapshotKindSeal}, "seal-only"},
		{"missing seal id", fixtureSpec{noSealID: true}, "seal backend id is empty"},
		{"missing payload id", fixtureSpec{omitPayloadID: true}, "unsealed payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildFixture(t, tc.spec)
			dest := filepath.Join(f.parent, "restored")
			_, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
			var nerr *ErrNotOpenable
			if !errors.As(err, &nerr) {
				t.Fatalf("err = %v, want ErrNotOpenable", err)
			}
			if !strings.Contains(nerr.Error(), tc.want) {
				t.Fatalf("err = %v, want reason containing %q", err, tc.want)
			}
			assertNoStageDirs(t, f.parent)
			assertNoOperations(t, f)
		})
	}
}

// Unknown snapshot id: ErrNotOpenable.
func TestOpenUnknownSnapshot(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	o := newOpener(f)
	_, err := o.Open(context.Background(), f.vault, domain.SnapshotID(domain.NewID()),
		Options{Destination: filepath.Join(f.parent, "restored"), FilesOnly: true})
	var nerr *ErrNotOpenable
	if !errors.As(err, &nerr) {
		t.Fatalf("err = %v, want ErrNotOpenable", err)
	}
}

// A relative destination is a caller mistake.
func TestOpenRelativeDestinationRefused(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	_, err := f.open(context.Background(), newOpener(f), Options{Destination: "relative/dest", FilesOnly: true})
	var oerr *ErrInvalidOptions
	if !errors.As(err, &oerr) {
		t.Fatalf("err = %v, want ErrInvalidOptions", err)
	}
	assertNoStageDirs(t, f.parent)
	assertNoOperations(t, f)
}

// Publish race (F35): a destination occupant appearing between
// preflight and publish leaves the staged tree KEPT and the operation
// RESTORING; a second Open recognizes the interrupted staging, cancels
// the stale operation and redoes the open cleanly.
func TestOpenPublishRaceAndRecovery(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")

	f.store.restoreHook = func() error {
		// Fires during staging materialization — after preflight.
		mustMkdir(t, dest)
		return writeFileForHook(t, filepath.Join(dest, "racer.txt"), []byte("racing occupant\n"))
	}
	res, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var perr *ErrPublishBlocked
	if !errors.As(err, &perr) || perr.Code() != CodePublishBlocked {
		t.Fatalf("err = %v, want ErrPublishBlocked", err)
	}
	// Staging KEPT for recovery; op left RESTORING; occupant untouched.
	left := stageDirs(t, f.parent)
	if len(left) != 1 {
		t.Fatalf("staged tree must be kept after a blocked publish, found %v", left)
	}
	op, gerr := f.cat.GetOperation(res.OperationID)
	if gerr != nil {
		t.Fatalf("get operation: %v", gerr)
	}
	if op.Phase != catalog.PhaseRestoring {
		t.Fatalf("phase %q, want RESTORING", op.Phase)
	}
	if op.LastError == "" {
		t.Fatal("blocked publish must be recorded on the journal row")
	}
	if got, rerr := os.ReadFile(filepath.Join(dest, "racer.txt")); rerr != nil || string(got) != "racing occupant\n" {
		t.Fatalf("racing occupant mutated: %q %v", got, rerr)
	}

	// The occupant goes away; a fresh Open recovers: recognizes the
	// stale staging, cancels the stale op, redoes cleanly.
	if err := os.RemoveAll(dest); err != nil {
		t.Fatalf("remove racing occupant: %v", err)
	}
	f.store.restoreHook = nil
	res2, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if err != nil {
		t.Fatalf("recovery open: %v", err)
	}
	assertTreesByteEqual(t, f.srcRoot, dest)
	assertNoStageDirs(t, f.parent)

	stale, err := f.cat.GetOperation(res.OperationID)
	if err != nil {
		t.Fatalf("get stale operation: %v", err)
	}
	if stale.Phase != catalog.PhaseCanceled {
		t.Fatalf("stale operation phase %q, want CANCELED", stale.Phase)
	}
	op2, err := f.cat.GetOperation(res2.OperationID)
	if err != nil {
		t.Fatalf("get operation 2: %v", err)
	}
	if op2.Phase != catalog.PhaseDone {
		t.Fatalf("operation 2 phase %q, want DONE", op2.Phase)
	}
	warned := false
	for _, w := range res2.Warnings {
		if strings.Contains(w, string(res.OperationID)) {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("recovery must report the stale operation id in warnings: %v", res2.Warnings)
	}
}

// An active open operation whose staging is already gone (e.g. after an
// oracle failure) is reconciled: stale op canceled, fresh open
// succeeds, nothing unrecognized overwritten.
func TestOpenActiveOpWithoutStagingReconciled(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")

	// First open fails at the oracle (staging removed, op left active
	// at RESTORING).
	f.store.restoreDrop["/"+f.wsPrefix+"/.env"] = true
	res1, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if err == nil {
		t.Fatal("first open must fail at the oracle")
	}
	assertNoStageDirs(t, f.parent)

	// Second open reconciles the stale operation and succeeds.
	f.store.restoreDrop = map[string]bool{}
	res2, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if err != nil {
		t.Fatalf("reconciled open: %v", err)
	}
	assertTreesByteEqual(t, f.srcRoot, dest)
	stale, err := f.cat.GetOperation(res1.OperationID)
	if err != nil {
		t.Fatalf("get stale op: %v", err)
	}
	if stale.Phase != catalog.PhaseCanceled {
		t.Fatalf("stale phase %q, want CANCELED", stale.Phase)
	}
	op2, err := f.cat.GetOperation(res2.OperationID)
	if err != nil || op2.Phase != catalog.PhaseDone {
		t.Fatalf("second op phase: %v %q, want DONE", err, op2.Phase)
	}
}

// A destination occupied by a PREVIOUSLY PUBLISHED Ebb open (op now
// DONE) is refused with the operation named, never overwritten.
func TestOpenDestinationHoldingPublishedEbbOpen(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")

	res, err := f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_, err = f.open(context.Background(), newOpener(f), Options{Destination: dest, FilesOnly: true})
	var oerr *ErrDestinationOccupied
	if !errors.As(err, &oerr) {
		t.Fatalf("err = %v, want ErrDestinationOccupied", err)
	}
	if !strings.Contains(oerr.Occupant, string(res.OperationID)) {
		t.Fatalf("occupant description must name the publishing operation: %q", oerr.Occupant)
	}
	// The published tree is untouched.
	assertTreesByteEqual(t, f.srcRoot, dest)
	assertNoStageDirs(t, f.parent)
}

// ---- shared assertions ---------------------------------------------------

func assertSingleFailedRestoringOp(t *testing.T, f *fixture, wantMsg string) {
	t.Helper()
	active, err := f.cat.ActiveOperations(f.wsID)
	if err != nil {
		t.Fatalf("active operations: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("active operations = %d, want the single failed open", len(active))
	}
	op := active[0]
	if op.Phase != catalog.PhaseRestoring {
		t.Fatalf("failed operation phase %q, want RESTORING", op.Phase)
	}
	if !strings.Contains(op.LastError, wantMsg) {
		t.Fatalf("last error %q must mention %q", op.LastError, wantMsg)
	}
}

func assertNoOperations(t *testing.T, f *fixture) {
	t.Helper()
	active, err := f.cat.ActiveOperations(f.wsID)
	if err != nil {
		t.Fatalf("active operations: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("no operation should exist yet; found %d (%v)", len(active), active[0].ID)
	}
}

// spaceProbe overrides VolumeUsage with a fixed free byte count.
type spaceProbe struct {
	domain.PlatformProbe
	free int64
}

func (p *spaceProbe) VolumeUsage(path string) (domain.VolumeUsage, error) {
	return domain.VolumeUsage{FreeToCaller: p.free, VolumeFree: p.free, Total: p.free + 1, VolumeID: "limited"}, nil
}

// writeFileForHook is writeFile for use inside fault hooks (which cannot
// take *testing.T helpers that call t.Helper on a different goroutine
// path — the hook runs synchronously, so a plain error return suffices).
func writeFileForHook(t *testing.T, path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}
