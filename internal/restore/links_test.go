package restore

// Wave F link-staging contract tests: the backend stage excludes link
// nodes (and the op dir), the restore layer recreates every retained
// link from the retained inventory's LinkTarget, privilege refusals
// fail the open BEFORE publish with the typed blocker, and a link
// recreated with the WRONG text is caught by the independent oracle
// (the sabotage check).

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/platform"
)

// fixtureLink returns the fixture's link entry (kind + retained text).
func fixtureLink(t *testing.T, f *fixture) domain.Entry {
	t.Helper()
	for _, e := range f.entries {
		if isLinkKind(e.Kind) {
			return e
		}
	}
	t.Fatal("fixture carries no link entry; fixture wiring broken")
	return domain.Entry{}
}

// recordingCreator delegates to the platform creator and records calls.
type recordingCreator struct {
	calls []struct {
		kind   domain.EntryKind
		path   string
		target string
	}
}

func (r *recordingCreator) create(kind domain.EntryKind, path, target string) error {
	r.calls = append(r.calls, struct {
		kind   domain.EntryKind
		path   string
		target string
	}{kind, path, target})
	return platform.CreateLink(kind, path, target)
}

// typedPrivilegeRefusal simulates the platform creator's
// LinkPrivilegeError structurally (restore must not import platform).
type typedPrivilegeRefusal struct{ path string }

func (e *typedPrivilegeRefusal) Error() string {
	return "simulated: creating this link requires SeCreateSymbolicLinkPrivilege"
}

func (e *typedPrivilegeRefusal) LinkPrivilegeBlocked() bool { return true }

// TestOpenExcludesLinksFromStageAndRecreatesThem: the open succeeds on
// an unprivileged machine; the STORE never touched the link node
// (exclusion contract), the LAYER recreated it with the exact retained
// text, and the full round trip still publishes.
func TestOpenExcludesLinksFromStageAndRecreatesThem(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	link := fixtureLink(t, f)
	dest := filepath.Join(f.parent, "restored")

	rec := &recordingCreator{}
	res, err := f.open(context.Background(), newOpenerWithCreator(f, rec.create), Options{Destination: dest, FilesOnly: true})
	if err != nil {
		t.Fatalf("open with native link recreation: %v", err)
	}

	// The link exists at the destination with the EXACT retained text.
	got, rerr := os.Readlink(filepath.Join(dest, filepath.FromSlash(link.Path)))
	if rerr != nil || got != link.LinkTarget {
		t.Fatalf("recreated link text = %q (%v), want the retained %q", got, rerr, link.LinkTarget)
	}
	assertTreesByteEqual(t, f.srcRoot, dest)

	// The store was asked to skip exactly the link node and the op dir.
	f.store.mu.Lock()
	calls := append([][]string(nil), f.store.excludeCalls...)
	materialized := append([]string(nil), f.store.linksMaterialized...)
	f.store.mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("RestoreExcluding calls = %d, want exactly 1", len(calls))
	}
	want := map[string]bool{f.opDirName: true, f.wsPrefix + "/" + link.Path: true}
	if len(calls[0]) != len(want) {
		t.Fatalf("excludes = %v, want exactly %v", calls[0], want)
	}
	for _, ex := range calls[0] {
		if !want[ex] {
			t.Fatalf("unexpected exclude %q (want exactly %v)", ex, want)
		}
	}
	if len(materialized) != 0 {
		t.Fatalf("the store materialized link nodes itself (%v); links must be excluded from the backend stage", materialized)
	}

	// The layer recreated exactly the fixture link, with the retained
	// kind and target.
	if len(rec.calls) != 1 {
		t.Fatalf("creator calls = %+v, want exactly the fixture link", rec.calls)
	}
	c := rec.calls[0]
	if c.kind != link.Kind || c.target != link.LinkTarget {
		t.Fatalf("creator call = %+v, want kind %q target %q", c, link.Kind, link.LinkTarget)
	}
	wantStaged := strings.ReplaceAll(filepath.Join(dest, filepath.FromSlash(link.Path)), dest, "") // path shape sanity
	if !strings.HasSuffix(filepath.ToSlash(c.path), link.Path) {
		t.Fatalf("creator path %q must address staged entry %q (shape %q)", c.path, link.Path, wantStaged)
	}

	// The published tree carries no op-dir documents (excluded, and only
	// the workspace prefix is published anyway).
	if _, err := os.Lstat(filepath.Join(dest, f.opDirName)); !os.IsNotExist(err) {
		t.Errorf("op dir must not be staged/published (stat err = %v)", err)
	}
	if res.OperationID == "" {
		t.Fatal("open result must carry the operation id")
	}
}

// TestOpenPrivilegeBlockedSymlinkFailsBeforePublish: when the creator
// refuses links for privilege, the open fails with the typed blocker
// naming the entry and the two options, publishes NOTHING, removes the
// staging, and journals the operation at RESTORING.
func TestOpenPrivilegeBlockedSymlinkFailsBeforePublish(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	link := fixtureLink(t, f)
	dest := filepath.Join(f.parent, "restored")

	refusing := func(kind domain.EntryKind, path, target string) error {
		return &typedPrivilegeRefusal{path: path}
	}
	_, err := f.open(context.Background(), newOpenerWithCreator(f, refusing), Options{Destination: dest, FilesOnly: true})
	var lb *ErrLinksBlocked
	if !errors.As(err, &lb) || lb.Code() != CodeLinksBlocked {
		t.Fatalf("err = %v, want ErrLinksBlocked (%s)", err, CodeLinksBlocked)
	}
	if len(lb.PrivilegeBlocked) != 1 || lb.PrivilegeBlocked[0] != link.Path {
		t.Fatalf("PrivilegeBlocked = %v, want exactly [%s]", lb.PrivilegeBlocked, link.Path)
	}
	msg := lb.Error()
	for _, want := range []string{link.Path, "SeCreateSymbolicLinkPrivilege", "elevated", "Developer Mode", "nothing was published"} {
		if !strings.Contains(msg, want) {
			t.Errorf("blocker message must mention %q: %q", want, msg)
		}
	}
	if _, serr := os.Lstat(dest); !os.IsNotExist(serr) {
		t.Fatalf("nothing may be published (stat err = %v)", serr)
	}
	assertNoStageDirs(t, f.parent)
	assertSingleFailedRestoringOp(t, f, link.Path)
}

// TestOpenLinkRecreateFailureOther: a non-privilege recreation failure
// (e.g. I/O) is the same typed blocker's Failures list, never a silent
// partial publish.
func TestOpenLinkRecreateFailureOther(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	link := fixtureLink(t, f)
	dest := filepath.Join(f.parent, "restored")

	failing := func(kind domain.EntryKind, path, target string) error {
		return errors.New("simulated I/O failure")
	}
	_, err := f.open(context.Background(), newOpenerWithCreator(f, failing), Options{Destination: dest, FilesOnly: true})
	var lb *ErrLinksBlocked
	if !errors.As(err, &lb) {
		t.Fatalf("err = %v, want ErrLinksBlocked", err)
	}
	if len(lb.Failures) != 1 || !strings.Contains(lb.Failures[0], link.Path) {
		t.Fatalf("Failures = %v, want the link path named", lb.Failures)
	}
	if len(lb.PrivilegeBlocked) != 0 {
		t.Fatalf("PrivilegeBlocked = %v, want none", lb.PrivilegeBlocked)
	}
	if _, serr := os.Lstat(dest); !os.IsNotExist(serr) {
		t.Fatalf("nothing may be published (stat err = %v)", serr)
	}
	assertNoStageDirs(t, f.parent)
	assertSingleFailedRestoringOp(t, f, link.Path)
}

// TestOpenOracleCatchesWrongLinkText is the sabotage check: a creator
// that "succeeds" but writes the WRONG target text must be caught by
// the independent oracle (E10), never published.
func TestOpenOracleCatchesWrongLinkText(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	link := fixtureLink(t, f)
	dest := filepath.Join(f.parent, "restored")

	sabotage := func(kind domain.EntryKind, path, target string) error {
		return platform.CreateLink(kind, path, target+"-tampered")
	}
	_, err := f.open(context.Background(), newOpenerWithCreator(f, sabotage), Options{Destination: dest, FilesOnly: true})
	var verr *ErrVerification
	if !errors.As(err, &verr) || verr.Check != "oracle" {
		t.Fatalf("err = %v, want ErrVerification{oracle}", err)
	}
	joined := strings.Join(verr.Details, "; ")
	if !strings.Contains(joined, link.Path) || !strings.Contains(joined, "link text") {
		t.Fatalf("oracle details must name the link text mismatch: %v", verr.Details)
	}
	if _, serr := os.Lstat(dest); !os.IsNotExist(serr) {
		t.Fatalf("nothing may be published (stat err = %v)", serr)
	}
	assertNoStageDirs(t, f.parent)
}

// TestOpenLegacyStoreKeepsLegacyStaging: a store WITHOUT the
// RestoreExcluding capability follows the pre-Wave-F contract — subtree
// restore with the store materializing links itself; the native link
// creator must not run.
func TestOpenLegacyStoreKeepsLegacyStaging(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	dest := filepath.Join(f.parent, "restored")

	legacy := struct{ domain.SnapshotStore }{f.store} // embeds the interface: extra methods hidden
	o, err := New(Dependencies{Store: legacy, Cat: f.cat, Probe: f.probe, CreateLink: func(kind domain.EntryKind, path, target string) error {
		t.Errorf("creator must not run on the legacy staging path (%s)", path)
		return nil
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := f.open(context.Background(), o, Options{Destination: dest, FilesOnly: true}); err != nil {
		t.Fatalf("legacy open: %v", err)
	}
	assertTreesByteEqual(t, f.srcRoot, dest)
	f.store.mu.Lock()
	calls := len(f.store.excludeCalls)
	f.store.mu.Unlock()
	if calls != 0 {
		t.Fatalf("legacy store must not receive exclusion calls, got %d", calls)
	}
}

// TestStdlibCreateLinkMapsPrivilegeRefusal pins the DEFAULT creator's
// errno mapping on Windows: an unprivileged os.Symlink refusal surfaces
// the typed privilege contract (so an unwired production binary reports
// the precise blocker instead of a raw errno).
func TestStdlibCreateLinkMapsPrivilegeRefusal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "tgt")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	err := stdlibCreateLink(domain.KindSymlink, filepath.Join(dir, "sl"), target)
	if err == nil {
		t.Skip("this environment can create symlinks; the privilege mapping cannot be exercised")
	}
	var pb privilegeBlockedLink
	if !errors.As(err, &pb) || !pb.LinkPrivilegeBlocked() {
		t.Fatalf("err = %v, want the structural privilege contract", err)
	}
	if !strings.Contains(err.Error(), "SeCreateSymbolicLinkPrivilege") {
		t.Fatalf("error must name the capability: %v", err)
	}
}
