//go:build linux

package platform

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"ebb/internal/domain"
	"ebb/internal/inventory"
)

// isMismatch mirrors the scanner's structural detection of
// domain.VerifiedDirProbe mismatch errors. (The Windows twin lives in
// dirverified_windows_test.go; exactly one of the two compiles.)
func isMismatch(err error) bool {
	var m interface{ IdentityMismatch() bool }
	return errors.As(err, &m) && m.IdentityMismatch()
}

// TestOpenDirVerifiedIdentitySpelling pins classification identity ==
// RootIdentity composition == verified handle identity (dev:ino).
func TestOpenDirVerifiedIdentitySpelling(t *testing.T) {
	dir := t.TempDir()
	a := makeDir(t, dir, "a")
	b := makeDir(t, a, "b")
	empty := makeDir(t, dir, "empty")
	file := writeFixtureFile(t, dir, "f.txt", "content")
	probe := linuxProbe{}

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
		// The seam's contract is SET equality through the verified handle,
		// not order: os.File.ReadDir yields entries in raw directory order
		// (getdents64 on Linux — ext4 hashes, NOT sorted; NTFS B-trees
		// happen to be), while os.ReadDir sorts by filename. Comparing
		// unsorted-vs-sorted only passes on filesystems whose directory
		// order is sorted; sort both sides before DeepEqual.
		sort.Strings(gotNames)
		sort.Strings(wantNames)
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

	if _, err := probe.OpenDirVerified(dir, "0:0"); err == nil || !isMismatch(err) {
		t.Fatalf("wrong expected identity: err = %v, want identity mismatch", err)
	}
	if _, err := probe.OpenDirVerified(dir, ""); err == nil {
		t.Fatal("empty expected identity must be refused")
	}
	ff, err := probe.ProbeFile(file)
	if err != nil {
		t.Fatalf("ProbeFile(%s): %v", file, err)
	}
	if _, err := probe.OpenDirVerified(file, ff.FileIdentity); err == nil {
		t.Fatal("regular file must not be openable as a verified directory")
	}
}

// verifiedNative is the full native seam the scanner consumes.
type verifiedNative interface {
	domain.PlatformProbe
	domain.VerifiedDirProbe
}

// raceProbe reproduces the SCAN-RACE-1 attack through the probe seam
// (Linux arm: symlink substitution needs no privilege).
type raceProbe struct {
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
		if err := os.Symlink(p.victim, path); err != nil {
			return domain.FileFacts{}, fmt.Errorf("race: symlink: %w", err)
		}
	}
	return facts, nil // the ORIGINAL directory's facts
}

// OpenDirVerified always delegates to the real probe.
func (p *raceProbe) OpenDirVerified(path, expectedIdentity string) (domain.IdentifiedDir, error) {
	return p.inner.OpenDirVerified(path, expectedIdentity)
}

// TestScanRaceSymlinkSubstitution is the Linux regression for
// SCAN-RACE-1 (see the Windows twin in dirverified_windows_test.go).
func TestScanRaceSymlinkSubstitution(t *testing.T) {
	victim := t.TempDir()
	vfile := writeFixtureFile(t, victim, "victim-secret.txt", "do not leak")
	root := t.TempDir()
	p := makeDir(t, root, "P")
	writeFixtureFile(t, p, "original.txt", "original content")
	writeFixtureFile(t, root, "aaa.txt", "a")
	writeFixtureFile(t, root, "zzz.txt", "z")

	probe := &raceProbe{inner: linuxProbe{}, hook: p, victim: victim}
	t.Cleanup(func() { os.Remove(p) }) // symlink only; harmless if the race never fired

	res := inventory.Scan(context.Background(), probe, root, inventory.Options{})
	if res.Err != nil {
		t.Fatalf("scan must complete despite the race: %v", res.Err)
	}
	if !res.Summary.Complete() {
		t.Fatalf("accounting incomplete: %+v", res.Summary)
	}
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
	var got []string
	for _, e := range res.Entries {
		got = append(got, e.Path)
		if strings.HasPrefix(e.Path, "P/") {
			t.Fatalf("entry from a replaced directory leaked into the inventory: %q", e.Path)
		}
	}
	if want := []string{"P", "aaa.txt", "zzz.txt"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
	if e := res.Entries[0]; e.Path != "P" || e.Kind != domain.KindDir {
		t.Fatalf("P entry = %+v", e)
	}
	if data, err := os.ReadFile(vfile); err != nil || string(data) != "do not leak" {
		t.Fatalf("victim content changed: %v %q", err, data)
	}
	if _, err := os.Stat(filepath.Join(p+".swapped", "original.txt")); err != nil {
		t.Fatalf("original directory was not merely renamed aside: %v", err)
	}
}

// TestScanVerifiedMatchesPathBased: verified-handle route == legacy
// path-based route over a quiescent tree.
func TestScanVerifiedMatchesPathBased(t *testing.T) {
	root := t.TempDir()
	a := makeDir(t, root, "a")
	b := makeDir(t, a, "b")
	writeFixtureFile(t, a, "x.txt", "x")
	writeFixtureFile(t, b, "y.txt", "y")
	writeFixtureFile(t, b, ".hidden", "h")
	makeDir(t, root, "empty")

	verified := inventory.Scan(context.Background(), linuxProbe{}, root, inventory.Options{})
	pathBased := inventory.Scan(context.Background(),
		struct{ domain.PlatformProbe }{linuxProbe{}}, root, inventory.Options{})

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
}
