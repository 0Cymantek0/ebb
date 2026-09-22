package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// Verified-descent seam tests (SCAN-RACE-1). These exercise the
// scanner's domain.VerifiedDirProbe wiring with in-package fakes; the
// real native round trip (open → identity check → enumeration) is
// covered in internal/platform.

// fakeReplacedError is the mismatch error shape native probes promise:
// it satisfies interface{ IdentityMismatch() bool }.
type fakeReplacedError struct{ rel string }

func (e fakeReplacedError) Error() string { return "fake: directory " + e.rel + " replaced" }

// IdentityMismatch marks the error as a detected substitution.
func (fakeReplacedError) IdentityMismatch() bool { return true }

// fakeIdentifiedDir stands in for a native verified handle: enumeration
// is captured at open time (path-based read inside the fake only).
type fakeIdentifiedDir struct {
	des      []os.DirEntry
	identity string
}

func (d fakeIdentifiedDir) Identity() string                { return d.identity }
func (d fakeIdentifiedDir) ReadDir() ([]os.DirEntry, error) { return d.des, nil }
func (fakeIdentifiedDir) Close() error                      { return nil }

// verifiedProbe layers domain.VerifiedDirProbe over fakeProbe: every
// descent goes through OpenDirVerified; the directory named by failRel
// (root-relative, nil = none, "" = root) reports replacement.
type verifiedProbe struct {
	*fakeProbe
	failRel *string
	opens   map[string]string // rel -> expected identity seen at open
}

// failOn arms replacement reporting for one root-relative directory.
func (p *verifiedProbe) failOn(rel string) { p.failRel = &rel }

func newVerifiedProbe(t *testing.T) (*verifiedProbe, string) {
	t.Helper()
	fp, root := newFakeProbe(t)
	return &verifiedProbe{fakeProbe: fp, opens: make(map[string]string)}, root
}

// relOf maps an absolute child path back to the root-relative key the
// scanner uses (fakeProbe.rel returns the full path for the root
// itself, which is wrong for descent bookkeeping).
func relOf(root, abs string) string {
	a, r := filepath.Clean(abs), filepath.Clean(root)
	if a == r {
		return ""
	}
	return filepath.ToSlash(strings.TrimPrefix(a, r+string(os.PathSeparator)))
}

func (p *verifiedProbe) OpenDirVerified(abs, expected string) (domain.IdentifiedDir, error) {
	rel := relOf(p.root, abs)
	p.opens[rel] = expected
	if p.failRel != nil && rel == *p.failRel {
		return nil, fakeReplacedError{rel: rel}
	}
	des, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	return fakeIdentifiedDir{des: des, identity: expected}, nil
}

func TestScanVerifiedDirDescentPositive(t *testing.T) {
	p, root := newVerifiedProbe(t)
	mkdir(t, filepath.Join(root, "a", "b"))
	writeFile(t, filepath.Join(root, "a", "x.txt"), "x")
	writeFile(t, filepath.Join(root, "a", "b", "y.txt"), "y")
	mkdir(t, filepath.Join(root, "empty"))
	writeFile(t, filepath.Join(root, "top.txt"), "top")
	// fsFacts leaves directory identities empty; give the fakes stable
	// ones so every descent exercises the verified route.
	p.facts["a"] = &domain.FileFacts{FileIdentity: "ID-A"}
	p.facts["a/b"] = &domain.FileFacts{FileIdentity: "ID-AB"}
	p.facts["empty"] = &domain.FileFacts{FileIdentity: "ID-EMPTY"}

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	checkCanonical(t, res)

	// Every directory — including the root — descended through
	// OpenDirVerified, with the classification-time identity.
	wantOpens := map[string]string{
		"":      "fakevol:" + filepath.Clean(root), // composed RootIdentity spelling
		"a":     "ID-A",
		"a/b":   "ID-AB",
		"empty": "ID-EMPTY",
	}
	if !reflect.DeepEqual(p.opens, wantOpens) {
		t.Fatalf("opens = %v, want %v", p.opens, wantOpens)
	}

	// Golden: the verified walk reports the same entries as the legacy
	// path-based walk of the same tree.
	legacy := Scan(context.Background(), p.fakeProbe, root, Options{})
	if legacy.Err != nil {
		t.Fatalf("legacy scan: %v", legacy.Err)
	}
	if !reflect.DeepEqual(res.Entries, legacy.Entries) {
		t.Fatalf("verified entries = %+v, want legacy %+v", res.Entries, legacy.Entries)
	}
}

func TestScanVerifiedDirReplacedBlocks(t *testing.T) {
	p, root := newVerifiedProbe(t)
	mkdir(t, filepath.Join(root, "p", "deep"))
	writeFile(t, filepath.Join(root, "p", "child.txt"), "c")
	writeFile(t, filepath.Join(root, "p", "deep", "leaf.txt"), "l")
	writeFile(t, filepath.Join(root, "other.txt"), "o")
	p.facts["p"] = &domain.FileFacts{FileIdentity: "ID-P"}
	p.failOn("p")

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan must continue past a replaced directory: %v", res.Err)
	}
	checkCanonical(t, res)

	// The blocking issue names P; children never appear.
	if got := issueCodes(res, "p"); !reflect.DeepEqual(got, []string{IssueDirReplaced}) {
		t.Fatalf("p issues = %v", got)
	}
	if !reflect.DeepEqual(res.Summary.Blocking, []string{"p"}) {
		t.Fatalf("Blocking = %v", res.Summary.Blocking)
	}
	for _, e := range res.Entries {
		if strings.HasPrefix(e.Path, "p/") {
			t.Fatalf("enumerated child of replaced directory: %q", e.Path)
		}
	}
	// The directory itself stays recorded (never silently skipped), as a
	// dir with the replacement evidence, and the accounting flips its
	// outcome to blocking.
	e := entryOf(t, res, "p")
	if e.Kind != domain.KindDir {
		t.Fatalf("p kind = %q", e.Kind)
	}
	found := false
	for _, ev := range e.Evidence {
		if ev == evidenceScan+":"+IssueDirReplaced {
			found = true
		}
	}
	if !found {
		t.Fatalf("p evidence = %v, want the replacement tag", e.Evidence)
	}
	entryOf(t, res, "other.txt")
	if res.Summary.Preserved != res.Summary.TotalEntries-1 {
		t.Fatalf("Preserved = %d of %d, want exactly the replaced dir excluded",
			res.Summary.Preserved, res.Summary.TotalEntries)
	}
}

func TestScanVerifiedRootReplacedFailsClosed(t *testing.T) {
	p, root := newVerifiedProbe(t)
	writeFile(t, filepath.Join(root, "x.txt"), "x")
	p.failOn("") // the root itself

	res := Scan(context.Background(), p, root, Options{})
	if res.Err == nil {
		t.Fatal("an unverified root must fail the scan, not walk a different object")
	}
	if !errors.Is(res.Err, domain.ErrScanIncomplete) {
		t.Fatalf("err = %v, want ErrScanIncomplete in chain", res.Err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("entries = %v, want none from an untrusted root", res.Entries)
	}
}

func TestScanVerifiedDirEmptyIdentityFallsBack(t *testing.T) {
	p, root := newVerifiedProbe(t)
	// No identity overlay: the probe implements VerifiedDirProbe but
	// classification produced no identity for the child directory — the
	// descent must fall back to the legacy path-based enumeration.
	mkdir(t, filepath.Join(root, "noid"))
	writeFile(t, filepath.Join(root, "noid", "inside.txt"), "i")

	res := Scan(context.Background(), p, root, Options{})
	if res.Err != nil {
		t.Fatalf("scan: %v", res.Err)
	}
	entryOf(t, res, "noid/inside.txt")
	if _, ok := p.opens["noid"]; ok {
		t.Fatal("descent without a classification identity must not call OpenDirVerified")
	}
	if _, ok := p.opens[""]; !ok {
		t.Fatal("root descent (composed identity) must use OpenDirVerified")
	}
}

func TestIsDirIdentityMismatch(t *testing.T) {
	if isDirIdentityMismatch(nil) {
		t.Fatal("nil is not a mismatch")
	}
	if isDirIdentityMismatch(errors.New("plain")) {
		t.Fatal("plain error is not a mismatch")
	}
	wrapped := fmt.Errorf("open: %w", fakeReplacedError{rel: "p"})
	if !isDirIdentityMismatch(wrapped) {
		t.Fatal("wrapped mismatch error must be detected")
	}
}
