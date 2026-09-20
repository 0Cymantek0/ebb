package lifecycle

// Wave 1 adversarial carve-out PoCs (D034). These are FIXED-direction
// regression pins in the DEFAULT suite: each asserts the hostile shape
// is REFUSED (or safely contained) by the carve-out gates; a failing
// test prints "CARVE-POC CONFIRMED" and means a gate opened.
//
//	a  hostile canceller path semantics — refused before any copy
//	b  2001 tiny cancellers — entry budget refuses the group
//	c  one 65 MiB canceller — byte budget refuses the group
//	d  canceller link pointing outside the root — text captured, never
//	   followed, only the link removed
//	e  nested .git admin tree inside outputs (git:admin) — carved as
//	   plain files within budget, byte-exact round-trip
//	f  case collision between a carved path and a member path — refused
//	g  carve without the consent flag — group skipped, nothing removed
//	h  unicode / long paths — carve + byte-exact round-trip

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/domain"
)

// synthCarveEntry builds one resolved-shape entry for pure
// classification PoCs (hostile shapes the scanner itself would never
// produce, but retained documents might).
func synthCarveEntry(path string, kind domain.EntryKind, digest string, evidence ...string) domain.Entry {
	return domain.Entry{
		Root: domain.RootMain, Path: path, Kind: kind, Digest: digest,
		Ownership: domain.OwnershipOwned, Sensitivity: domain.SensitivityOrdinary,
		Route: domain.RoutePreserve, Evidence: evidence,
	}
}

// TestPoCCarveHostilePathRefused (a): a canceller whose path carries
// traversal/drive/backslash/NUL semantics cannot reach the overlay
// writer — entry validation refuses the group first. This is impossible
// via the scanner's own entries (domain validation) and is pinned here
// for the retained-document and direct-call paths.
func TestPoCCarveHostilePathRefused(t *testing.T) {
	hostile := []string{
		"node_modules/../escape.txt",
		"node_modules/sub\\backslash.txt",
		"node_modules/a\x00b.txt",
	}
	for _, p := range hostile {
		entries := []domain.Entry{
			synthCarveEntry(p, domain.KindFile, strings.Repeat("a", 64), "git:tracked"),
			synthCarveEntry("node_modules/bulk.js", domain.KindFile, strings.Repeat("b", 64), "policy:regenerate-cancelled=deps"),
		}
		cls := classifyCarveOut(entries, []string{"node_modules"})
		if len(cls.Refusals) == 0 {
			t.Fatalf("CARVE-POC(a) CONFIRMED: hostile path %q passed carve classification", p)
		}
		if blocker := carvePlanBlocker("deps", cls); blocker == "" || !strings.Contains(blocker, "carve-out is refused") {
			t.Fatalf("CARVE-POC(a) CONFIRMED: plan builder accepted hostile path %q (blocker %q)", p, blocker)
		}
		// The hostile entry must not appear as carved or bulk.
		for _, e := range append(append([]domain.Entry{}, cls.Carved...), cls.Bulk...) {
			if e.Path == p {
				t.Fatalf("CARVE-POC(a) CONFIRMED: hostile path %q reached the plan sets", p)
			}
		}
	}
}

// carveBulkFixture writes the minimal trim inputs plus one bulk file.
func carveBulkFixture(t *testing.T, root string) {
	t.Helper()
	for rel, content := range map[string]string{
		"package.json":           fixturePackageJSON,
		"pnpm-lock.yaml":         fixtureLock,
		"node_modules/bulk/a.js": carveBulkA,
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPoCCarveEntryBudgetRefused (b): 2001 tiny cancellers exceed the
// 2000-entry carve budget — the group is refused with honest text and
// nothing is removed.
func TestPoCCarveEntryBudgetRefused(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "budget-count")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	carveBulkFixture(t, root)
	dir := filepath.Join(root, "node_modules", "many")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < CarveOutMaxEntries+1; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%04d.txt", i))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pol := carvePolicy(t)
	pol.Preserve[0].Patterns = []string{"node_modules/many/**"}
	opts := snapshotOpts(ws)
	opts.Policy = pol
	opts.DoTrim = []string{"deps"}
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var blocked *ErrDestructiveBlocked
	if !errors.As(err, &blocked) || !strings.Contains(blocked.Error(), "entry budget") {
		t.Fatalf("CARVE-POC(b) CONFIRMED: 2001 cancellers not refused by the entry budget: %v", err)
	}
	mustExist(t, filepath.Join(root, "node_modules", "bulk", "a.js"))
	if n := activeCount(t, h.coord(), ws); n != 0 {
		t.Errorf("active ops after refused carve = %d, want 0", n)
	}
}

// TestPoCCarveByteBudgetRefused (c): one 65 MiB canceller exceeds the
// 64 MiB byte budget — refused, nothing removed.
func TestPoCCarveByteBudgetRefused(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "budget-bytes")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	carveBulkFixture(t, root)
	big := filepath.Join(root, "node_modules", "kept", "big.bin")
	if err := os.MkdirAll(filepath.Dir(big), 0o755); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, CarveOutMaxBytes+(1<<20)) // 65 MiB
	if err := os.WriteFile(big, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var blocked *ErrDestructiveBlocked
	if !errors.As(err, &blocked) || !strings.Contains(blocked.Error(), "byte budget") {
		t.Fatalf("CARVE-POC(c) CONFIRMED: a 65 MiB canceller not refused by the byte budget: %v", err)
	}
	mustExist(t, big)
	mustExist(t, filepath.Join(root, "node_modules", "bulk", "a.js"))
}

// TestPoCCarveOutsideLinkTextOnlyNeverFollowed (d): a canceller link
// pointing outside the root is captured as link TEXT (never followed),
// and removal deletes the link only.
func TestPoCCarveOutsideLinkTextOnlyNeverFollowed(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "link-poc")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	carveBulkFixture(t, root)
	outside := filepath.Join(h.base, "poc-outside-target.txt")
	if err := os.WriteFile(outside, []byte(carveOutsideTxt), 0o644); err != nil {
		t.Fatal(err)
	}
	kind := makeOutsideLink(t, root, "node_modules/kept/outside-link", relTargetTo(root, outside))

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("link carve trim: %v", err)
	}

	plan := dumpTrimPlanFromP(t, h, ws)
	g := plan.Groups[0]
	var rec *overlayPatchRecord
	for i, r := range g.OverlayPatches {
		if r.Path == "node_modules/kept/outside-link" {
			rec = &g.OverlayPatches[i]
		}
	}
	if rec == nil {
		t.Fatalf("CARVE-POC(d): the outside link was not carved: %+v", g.OverlayPatches)
	}
	if rec.Kind != overlayKindLink || rec.Digest != "" || !strings.HasSuffix(rec.Copy, linkSidecarSuffix) {
		t.Fatalf("CARVE-POC(d): link record shape wrong: %+v", rec)
	}
	// Sidecar content == link text, != target content.
	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	payload := snaps[len(snaps)-1].PayloadBackendID
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	sidecar, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, payload, prefix+"/"+rec.Copy)
	if err != nil {
		t.Fatal(err)
	}
	if string(sidecar) == carveOutsideTxt {
		t.Fatalf("CARVE-POC(d) CONFIRMED: the link was followed — the sidecar holds target content")
	}
	if _, serr := os.Lstat(outside); serr != nil {
		t.Fatalf("CARVE-POC(d) CONFIRMED: the outside target was damaged: %v", serr)
	}
	if b, rerr := os.ReadFile(outside); rerr != nil || string(b) != carveOutsideTxt {
		t.Fatalf("CARVE-POC(d) CONFIRMED: the outside target content changed")
	}
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
	if kind != domain.KindSymlink && kind != domain.KindJunction {
		t.Skipf("link kind %q not exercised on this platform", kind)
	}
}

// TestPoCCarveNestedGitAdminTreeByteExact (e): a nested .git
// administration tree inside the outputs (git:admin via the path-derived
// evidence) cancels the group; with consent it is carved as plain files
// within budget and round-trips byte-exactly.
func TestPoCCarveNestedGitAdminTreeByteExact(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "nested-git")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	carveBulkFixture(t, root)
	adminFiles := map[string]string{
		"node_modules/nested/.git/HEAD":              "ref: refs/heads/main\n",
		"node_modules/nested/.git/config":            "[core]\n\trepositoryformatversion = 0\n",
		"node_modules/nested/.git/objects/ab/cdef01": "\x00GIT OBJECT BYTES\xff\xfe",
	}
	for rel, content := range adminFiles {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Without consent: refused (F53 whole-group preservation stands).
	optsNo := trimOpts(t, ws, "deps") // plain policy: the .git tree itself cancels
	optsNo.ApprovalReady = func(string) error { return nil }
	var blocked *ErrDestructiveBlocked
	if _, err := h.coord().Trim(context.Background(), h.vault, root, optsNo); !errors.As(err, &blocked) {
		t.Fatalf("nested .git must cancel the group without carve consent, got %v", err)
	}

	// With consent: the admin tree is carved as plain files.
	opts := trimOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("nested .git carve trim: %v", err)
	}
	plan := dumpTrimPlanFromP(t, h, ws)
	g := plan.Groups[0]
	if len(g.OverlayPatches) != len(adminFiles) {
		t.Fatalf("CARVE-POC(e): carved %d admin files, want %d: %+v", len(g.OverlayPatches), len(adminFiles), g.OverlayPatches)
	}
	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	payload := snaps[len(snaps)-1].PayloadBackendID
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	for _, r := range g.OverlayPatches {
		if r.Kind != overlayKindFile {
			t.Fatalf("CARVE-POC(e): admin tree entry %s carved as %q, want a plain file", r.Path, r.Kind)
		}
		got, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, payload, prefix+"/"+r.Copy)
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(r.Copy, overlayDirName+"/deps/")
		if string(got) != adminFiles[rel] {
			t.Fatalf("CARVE-POC(e) CONFIRMED: admin file %s did not round-trip byte-exactly", rel)
		}
	}
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
}

// TestPoCCarveCaseCollisionRefused (f): a carved path that collides
// case-insensitively with a member path is refused (the overlay copy
// and the manifest would silently merge on a case-insensitive
// filesystem).
func TestPoCCarveCaseCollisionRefused(t *testing.T) {
	entries := []domain.Entry{
		synthCarveEntry("node_modules/Pkg/Fix.js", domain.KindFile, strings.Repeat("a", 64), "policy:preserve=preserve[0].patterns[0]"),
		synthCarveEntry("node_modules/pkg/fix.js", domain.KindFile, strings.Repeat("b", 64), "policy:regenerate-cancelled=deps"),
	}
	cls := classifyCarveOut(entries, []string{"node_modules"})
	if len(cls.Refusals) != 0 || len(cls.Carved) != 1 || len(cls.Bulk) != 1 {
		t.Fatalf("classification unexpected: %+v", cls)
	}
	if blocker := carvePlanBlocker("deps", cls); blocker == "" || !strings.Contains(blocker, "collision") {
		t.Fatalf("CARVE-POC(f) CONFIRMED: case collision accepted (blocker %q)", blocker)
	}
	// No collision → accepted (control).
	ctl := classifyCarveOut([]domain.Entry{
		synthCarveEntry("node_modules/Pkg/Fix.js", domain.KindFile, strings.Repeat("a", 64), "policy:preserve=preserve[0].patterns[0]"),
		synthCarveEntry("node_modules/pkg/other.js", domain.KindFile, strings.Repeat("b", 64), "policy:regenerate-cancelled=deps"),
	}, []string{"node_modules"})
	if blocker := carvePlanBlocker("deps", ctl); blocker != "" {
		t.Fatalf("control misclassified as blocked: %q", blocker)
	}
}

// TestPoCCarveWithoutConsentNothingRemoved (g): no consent flag — the
// group is skipped and the ENTIRE source tree is untouched (digest
// before == after), with no snapshot claimed.
func TestPoCCarveWithoutConsentNothingRemoved(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "no-consent")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)
	before := digestTree(t, root)

	opts := carveOpts(t, ws, "deps")
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var blocked *ErrDestructiveBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("CARVE-POC(g) CONFIRMED: unconsented carve not refused: %v", err)
	}
	requireSameTree(t, before, digestTree(t, root))
	snaps, _ := h.coord().cat.ListSnapshots(ws)
	if len(snaps) != 0 {
		t.Fatalf("CARVE-POC(g) CONFIRMED: a refused carve left %d snapshot row(s)", len(snaps))
	}
}

// TestPoCCarveUnicodeLongPathsRoundTrip (h): unicode and long paths
// carve and round-trip byte-exactly.
func TestPoCCarveUnicodeLongPathsRoundTrip(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "unicode")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	carveBulkFixture(t, root)
	unicodeRel := "node_modules/kept/ünïcode-パッケージ/文件.js"
	longSeg := strings.Repeat("l", 140)
	longRel := "node_modules/kept/" + longSeg + "/deep" + strings.Repeat("d", 60) + "/payload.bin"
	for rel, content := range map[string]string{
		unicodeRel: "ユニコード内容 — unicode content\n",
		longRel:    "long path payload\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("unicode/long carve trim: %v", err)
	}
	plan := dumpTrimPlanFromP(t, h, ws)
	g := plan.Groups[0]
	if len(g.OverlayPatches) != 2 {
		t.Fatalf("CARVE-POC(h): carved %d entries, want 2: %+v", len(g.OverlayPatches), g.OverlayPatches)
	}
	want := map[string]string{
		unicodeRel: "ユニコード内容 — unicode content\n",
		longRel:    "long path payload\n",
	}
	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	payload := snaps[len(snaps)-1].PayloadBackendID
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	for _, r := range g.OverlayPatches {
		got, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, payload, prefix+"/"+r.Copy)
		if err != nil {
			t.Fatalf("dump %s: %v", r.Copy, err)
		}
		if string(got) != want[r.Path] {
			t.Fatalf("CARVE-POC(h) CONFIRMED: %s did not round-trip byte-exactly", r.Path)
		}
	}
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
}
