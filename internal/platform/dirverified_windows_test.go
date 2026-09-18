//go:build windows

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ebb/internal/domain"
	"ebb/internal/inventory"
)

// isMismatch mirrors the scanner's structural detection of
// domain.VerifiedDirProbe mismatch errors (interface assertion, no
// cross-package error type needed).
func isMismatch(err error) bool {
	var m interface{ IdentityMismatch() bool }
	return errors.As(err, &m) && m.IdentityMismatch()
}

// TestOpenDirVerifiedIdentitySpelling pins the invariant the whole
// SCAN-RACE-1 fix rests on: the classification-time identity
// (FileFacts.FileIdentity), the RootIdentity components, and the
// verified handle's Identity() are the SAME spelling. Any drift between
// them would make every verified descent mismatch.
func TestOpenDirVerifiedIdentitySpelling(t *testing.T) {
	dir := t.TempDir()
	a := makeDir(t, dir, "a")
	b := makeDir(t, a, "b")
	empty := makeDir(t, dir, "empty")
	file := writeFixtureFile(t, dir, "f.txt", "content")
	probe := windowsProbe{}

	for _, d := range []string{dir, a, b, empty} {
		facts, err := probe.ProbeFile(d)
		if err != nil {
			t.Fatalf("ProbeFile(%s): %v", d, err)
		}
		if facts.FileIdentity == "" {
			t.Fatalf("ProbeFile(%s): directory identity empty — descent verification impossible", d)
		}
		h, err := probe.OpenDirVerified(d, facts.FileIdentity)
		if err != nil {
			t.Fatalf("OpenDirVerified(%s): %v", d, err)
		}
		if got := h.Identity(); got != facts.FileIdentity {
			t.Errorf("%s: handle identity %q != classification identity %q", d, got, facts.FileIdentity)
		}
		des, err := h.ReadDir()
		h.Close()
		if err != nil {
			t.Fatalf("ReadDir(%s): %v", d, err)
		}
		want, err := os.ReadDir(d)
		if err != nil {
			t.Fatalf("os.ReadDir(%s): %v", d, err)
		}
		var gotNames, wantNames []string
		for _, de := range des {
			gotNames = append(gotNames, de.Name())
		}
		for _, de := range want {
			wantNames = append(wantNames, de.Name())
		}
		if !reflect.DeepEqual(gotNames, wantNames) {
			t.Errorf("%s: handle enumeration %v != path enumeration %v", d, gotNames, wantNames)
		}

		ri, err := probe.RootIdentity(d)
		if err != nil {
			t.Fatalf("RootIdentity(%s): %v", d, err)
		}
		if composed := ri.VolumeID + ":" + ri.FileID; composed != facts.FileIdentity {
			t.Errorf("%s: RootIdentity composition %q != FileIdentity %q", d, composed, facts.FileIdentity)
		}
	}

	// A garbage expectation must mismatch, not verify.
	if _, err := probe.OpenDirVerified(dir, "0:0"); err == nil || !isMismatch(err) {
		t.Fatalf("wrong expected identity: err = %v, want identity mismatch", err)
	}
	// An empty expectation is an invalid argument.
	if _, err := probe.OpenDirVerified(dir, ""); err == nil {
		t.Fatal("empty expected identity must be refused")
	}
	// A non-directory is refused even with a matching identity.
	ff, err := probe.ProbeFile(file)
	if err != nil {
		t.Fatalf("ProbeFile(%s): %v", file, err)
	}
	if _, err := probe.OpenDirVerified(file, ff.FileIdentity); err == nil {
		t.Fatal("regular file must not be openable as a verified directory")
	}
}

// TestOpenDirVerifiedDetectsSubstitution is the direct platform-level
// PoC of SCAN-RACE-1: facts captured on a real directory, the path then
// swapped for a junction to an outside tree. os.Open follows the
// junction, so the opened handle is the TARGET's — and that is exactly
// what the identity check must catch before any enumeration.
func TestOpenDirVerifiedDetectsSubstitution(t *testing.T) {
	victim := t.TempDir()
	vfile := writeFixtureFile(t, victim, "victim-secret.txt", "victim content")
	root := t.TempDir()
	p := makeDir(t, root, "P")
	writeFixtureFile(t, p, "original.txt", "original content")
	probe := windowsProbe{}

	facts, err := probe.ProbeFile(p)
	if err != nil {
		t.Fatalf("ProbeFile(P): %v", err)
	}
	ident := facts.FileIdentity

	// Substitute AFTER classification, inside the race window.
	renamed := p + ".swapped"
	if err := os.Rename(p, renamed); err != nil {
		t.Fatalf("rename P aside: %v", err)
	}
	makeJunction(t, filepath.Dir(p), filepath.Base(p), victim) // skips if unavailable
	t.Cleanup(func() { os.Remove(p) })                         // remove the LINK only

	_, err = probe.OpenDirVerified(p, ident)
	if err == nil {
		t.Fatal("substituted directory passed verification")
	}
	if !isMismatch(err) {
		t.Fatalf("err = %v, want an identity mismatch", err)
	}

	// Positive control: with the TARGET's identity the same junction
	// verifies — the check compares identities, it does not refuse
	// junction-followed opens categorically.
	vf, err := probe.ProbeFile(victim)
	if err != nil {
		t.Fatalf("ProbeFile(victim): %v", err)
	}
	h, err := probe.OpenDirVerified(p, vf.FileIdentity)
	if err != nil {
		t.Fatalf("positive control through the junction: %v", err)
	}
	des, rerr := h.ReadDir()
	h.Close()
	if rerr != nil {
		t.Fatalf("ReadDir through junction handle: %v", rerr)
	}
	if len(des) != 1 || des[0].Name() != "victim-secret.txt" {
		t.Fatalf("positive control enumerated %v", des)
	}
	// The victim was never touched.
	if data, err := os.ReadFile(vfile); err != nil || string(data) != "victim content" {
		t.Fatalf("victim content changed: %v %q", err, data)
	}
}

// verifiedNative is the full native seam the scanner consumes.
type verifiedNative interface {
	domain.PlatformProbe
	domain.VerifiedDirProbe
}

// raceProbe reproduces the SCAN-RACE-1 attack from inside the probe
// seam: it delegates EVERYTHING to the real Windows probe — including
// OpenDirVerified, never bypassing the check — but on the first
// ProbeFile(P) it captures the original directory's facts, swaps P for
// a junction to the victim tree, and returns the ORIGINAL facts. The
// scanner's classification then describes a directory that no longer
// exists at that path.
type raceProbe struct {
	t       *testing.T
	inner   verifiedNative
	hook    string // absolute path substituted on first ProbeFile
	victim  string
	swapped bool
}

func (p *raceProbe) RootIdentity(path string) (domain.RootIdentity, error) {
	return p.inner.RootIdentity(path)
}

func (p *raceProbe) VolumeUsage(path string) (domain.VolumeUsage, error) {
	return p.inner.VolumeUsage(path)
}

func (p *raceProbe) ProbeFile(path string) (domain.FileFacts, error) {
	facts, err := p.inner.ProbeFile(path)
	if err != nil {
		return domain.FileFacts{}, err
	}
	if !p.swapped && filepath.Clean(path) == filepath.Clean(p.hook) {
		p.swapped = true
		if err := os.Rename(path, path+".swapped"); err != nil {
			return domain.FileFacts{}, fmt.Errorf("race: rename aside: %w", err)
		}
		makeJunction(p.t, filepath.Dir(path), filepath.Base(path), p.victim)
	}
	return facts, nil // the ORIGINAL directory's facts
}

// OpenDirVerified always delegates to the real probe — a wrapper that
// bypassed it would prove nothing about the production code path.
func (p *raceProbe) OpenDirVerified(path, expectedIdentity string) (domain.IdentifiedDir, error) {
	return p.inner.OpenDirVerified(path, expectedIdentity)
}

// TestScanRaceJunctionSubstitution is the scanner-level regression for
// SCAN-RACE-1: a junction substituted between classification and
// enumeration must produce the EBB_SCAN_DIR_REPLACED blocking issue on
// that directory, must NOT enumerate the victim tree, and must not
// abort the scan (other entries are still reported).
func TestScanRaceJunctionSubstitution(t *testing.T) {
	victim := t.TempDir()
	vfile := writeFixtureFile(t, victim, "victim-secret.txt", "do not leak")
	root := t.TempDir()
	p := makeDir(t, root, "P")
	writeFixtureFile(t, p, "original.txt", "original content")
	writeFixtureFile(t, root, "aaa.txt", "a")
	writeFixtureFile(t, root, "zzz.txt", "z")

	probe := &raceProbe{t: t, inner: windowsProbe{}, hook: p, victim: victim}
	t.Cleanup(func() { os.Remove(p) }) // junction link only; harmless if the race never fired

	res := inventory.Scan(context.Background(), probe, root, inventory.Options{})
	if res.Err != nil {
		t.Fatalf("scan must complete despite the race: %v", res.Err)
	}
	if !res.Summary.Complete() {
		t.Fatalf("accounting incomplete: %+v", res.Summary)
	}

	// The blocking issue names P.
	var found bool
	for _, is := range res.Summary.Issues {
		if is.Path == "P" && is.Code == inventory.IssueDirReplaced {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing %s on P; issues = %+v", inventory.IssueDirReplaced, res.Summary.Issues)
	}
	if !reflect.DeepEqual(res.Summary.Blocking, []string{"P"}) {
		t.Fatalf("Blocking = %v, want [P]", res.Summary.Blocking)
	}

	// Canonical entries: P recorded as a dir, siblings untouched, and NO
	// child of P (neither the victim's nor the original's — children are
	// simply not enumerated).
	var got []string
	for _, e := range res.Entries {
		got = append(got, e.Path)
		if strings.HasPrefix(e.Path, "P/") {
			t.Fatalf("entry from a replaced directory leaked into the inventory: %q", e.Path)
		}
	}
	t.Logf("scanned paths: %v", got)
	if want := []string{"P", "aaa.txt", "zzz.txt"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	if e := res.Entries[0]; e.Path != "P" || e.Kind != domain.KindDir {
		t.Fatalf("P entry = %+v", e)
	}

	// The victim tree was neither enumerated nor touched.
	if data, err := os.ReadFile(vfile); err != nil || string(data) != "do not leak" {
		t.Fatalf("victim content changed: %v %q", err, data)
	}
	if _, err := os.Stat(filepath.Join(p+".swapped", "original.txt")); err != nil {
		t.Fatalf("original directory was not merely renamed aside: %v", err)
	}
}

// TestScanVerifiedMatchesPathBased is the golden comparison: over a
// quiescent tree, scanning through the verified-handle route reports
// exactly the entries the legacy path-based route reports.
func TestScanVerifiedMatchesPathBased(t *testing.T) {
	root := t.TempDir()
	a := makeDir(t, root, "a")
	b := makeDir(t, a, "b")
	writeFixtureFile(t, a, "x.txt", "x")
	writeFixtureFile(t, b, "y.txt", "y")
	writeFixtureFile(t, b, ".hidden", "h")
	makeDir(t, root, "empty")

	verified := inventory.Scan(context.Background(), windowsProbe{}, root, inventory.Options{})
	// The path-based arm wraps the same probe facts in a type that does
	// NOT implement domain.VerifiedDirProbe, forcing the legacy descent.
	pathBased := inventory.Scan(context.Background(),
		struct{ domain.PlatformProbe }{windowsProbe{}}, root, inventory.Options{})

	if verified.Err != nil {
		t.Fatalf("verified scan: %v", verified.Err)
	}
	if pathBased.Err != nil {
		t.Fatalf("path-based scan: %v", pathBased.Err)
	}
	if !reflect.DeepEqual(verified.Entries, pathBased.Entries) {
		t.Fatalf("verified entries:\n%+v\nwant path-based:\n%+v", verified.Entries, pathBased.Entries)
	}
	if len(verified.Summary.Issues) != 0 {
		t.Fatalf("unexpected issues on a quiescent tree: %+v", verified.Summary.Issues)
	}
	if !verified.Summary.Complete() || !pathBased.Summary.Complete() {
		t.Fatalf("accounting: verified %+v path-based %+v", verified.Summary, pathBased.Summary)
	}
}
