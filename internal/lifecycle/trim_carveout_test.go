package lifecycle

// Wave 1 granular carve-out coverage (D034; Foundation §7.4 and the
// F10/F53 amendment): consent gating, canceller discovery (preserve
// rules and git evidence), overlay capture into the sealed payload,
// frozen-schema encoding, budgets, and the recreate_live argv.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/inventory"
	"ebb/internal/policy"
)

// carvePolicyTOML declares the deps group over node_modules plus an
// explicit preservation rule covering the vendor-patch subtree inside
// the outputs (the F10 shape: local edits inside node_modules).
const carvePolicyTOML = `
version = 1

[workspace]
name = "fixture"

[policy]
network = "approved-actions"
unknown = "preserve"

[[preserve]]
patterns = ["node_modules/kept/**"]
reason = "vendor patch that must round-trip (F10)"

[[regenerate]]
id = "deps"
adapter = "pnpm"
root = "."
outputs = ["node_modules"]
inputs = ["package.json", "pnpm-lock.yaml"]
network = "allowed"
`

const (
	carveFix        = "// local vendor patch — must round-trip byte-exact\n"
	carveDeepNote   = "deep note\n"
	carveBulkA      = "module a;\nexport const a = 1;\n"
	carveBulkIndex  = "module.exports = () => 1;\n"
	carveOutsideTxt = "precious data outside the workspace root\n"
)

func carvePolicy(t *testing.T) policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(carvePolicyTOML))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func carveOpts(t *testing.T, ws domain.WorkspaceID, groups ...string) CaptureOptions {
	t.Helper()
	o := snapshotOpts(ws)
	o.Policy = carvePolicy(t)
	o.DoTrim = groups
	return o
}

// writeCarveFixture builds the carve workspace: two bulk files, two
// preserved (carve-able) files under node_modules/kept.
func writeCarveFixture(t *testing.T, root string) {
	t.Helper()
	files := map[string]string{
		"package.json":                    fixturePackageJSON,
		"pnpm-lock.yaml":                  fixtureLock,
		"notes.md":                        fixtureNotes,
		"node_modules/a.js":               carveBulkA,
		"node_modules/left-pad/index.js":  carveBulkIndex,
		"node_modules/kept/fix.js":        carveFix,
		"node_modules/kept/deep/note.txt": carveDeepNote,
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// dumpTrimPlanFromP reads the retained removal manifest out of the
// sealed payload (like the independent restore worker will).
func dumpTrimPlanFromP(t *testing.T, h *harness, ws domain.WorkspaceID) trimPlanDoc {
	t.Helper()
	c := h.coord()
	snaps, err := c.cat.ListSnapshots(ws)
	if err != nil || len(snaps) == 0 {
		t.Fatalf("no snapshots for %s (err %v)", ws, err)
	}
	P := snaps[len(snaps)-1].PayloadBackendID
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	raw, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, P, prefix+"/"+removalManifestName)
	if err != nil {
		t.Fatalf("dump removal manifest: %v", err)
	}
	var plan trimPlanDoc
	if err := decodeStrictJSON(raw, &plan); err != nil {
		t.Fatalf("strict-parse removal manifest: %v", err)
	}
	return plan
}

// TestTrimCarveOutRoundTrip: with consent, a group cancelled by a
// preserve rule inside its outputs is carved (overlay patches sealed in
// P, byte-exact) and the whole group is removed; the manifest freezes
// the overlay records AND recreate_live; the group stays Cancelled in
// the resolved policy (policy semantics untouched).
func TestTrimCarveOutRoundTrip(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "carve")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)

	// The resolved policy keeps reporting whole-group cancellation —
	// carve-out is a lifecycle-level interpretation layered on top.
	scanRes := inventory.Scan(context.Background(), h.probe.PlatformProbe, root, inventory.Options{Hash: true})
	if scanRes.Err != nil {
		t.Fatalf("pre-scan: %v", scanRes.Err)
	}
	pre, err := policy.Resolve(scanRes.Entries, carvePolicy(t))
	if err != nil {
		t.Fatal(err)
	}
	if pre.Groups[0].Applicable || !pre.Groups[0].Cancelled || pre.Groups[0].Canceller != "node_modules/kept" {
		t.Fatalf("policy.Resolve semantics changed: %+v", pre.Groups[0])
	}

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	res, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	if err != nil {
		t.Fatalf("trim with carve-out: %v", err)
	}

	// The whole group (bulk + carved + emptied dirs) is gone; the
	// workspace's non-output material stays.
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
	mustExist(t, filepath.Join(root, "package.json"))
	mustExist(t, filepath.Join(root, "pnpm-lock.yaml"))
	mustExist(t, filepath.Join(root, "notes.md"))
	if got := h.phaseOf(t, h.opIDOf(t, ws)); got != catalog.PhaseTrimDone {
		t.Errorf("phase = %q, want TRIM_DONE", got)
	}
	// node_modules tree: dir + a.js + left-pad + index.js + kept + fix.js
	// + kept/deep + note.txt = 8 removals.
	if res.EntriesRemoved != 8 {
		t.Errorf("entries removed = %d, want 8 (bulk + carved + dirs)", res.EntriesRemoved)
	}
	foundCarveWarning := false
	for _, w := range res.Snapshot.Warnings {
		if strings.Contains(w, "carve-out (D034)") {
			foundCarveWarning = true
		}
	}
	if !foundCarveWarning {
		t.Errorf("result warnings must report the carve: %v", res.Snapshot.Warnings)
	}

	plan := dumpTrimPlanFromP(t, h, ws)
	if len(plan.Groups) != 1 {
		t.Fatalf("plan groups = %d", len(plan.Groups))
	}
	g := plan.Groups[0]

	// Frozen schema: overlay_patches carries exactly the two carved
	// files with op-dir copy pointers and sealed digests.
	if len(g.OverlayPatches) != 2 {
		t.Fatalf("overlay patches = %+v, want 2 records", g.OverlayPatches)
	}
	byPath := map[string]overlayPatchRecord{}
	for _, r := range g.OverlayPatches {
		byPath[r.Path] = r
	}
	fix, ok := byPath["node_modules/kept/fix.js"]
	if !ok {
		t.Fatalf("fix.js not carved: %+v", g.OverlayPatches)
	}
	if fix.Kind != overlayKindFile || fix.Copy != "overlay/deps/node_modules/kept/fix.js" {
		t.Errorf("fix.js record = %+v", fix)
	}
	if fix.Digest != digestBytes([]byte(carveFix)) {
		t.Errorf("fix.js digest = %s, want the sealed fixture digest", fix.Digest)
	}

	// Members include the carved entries (removal walk + resume cover
	// them) and the bulk; the doc's record count covers everything.
	memberPaths := map[string]bool{}
	for _, m := range g.Members {
		memberPaths[m.Path] = true
		if m.Entry.Route != domain.RoutePreserve && m.Entry.Route != domain.RouteReconstruct {
			t.Errorf("member %s carries route %q the permit cannot cover", m.Path, m.Entry.Route)
		}
	}
	for _, want := range []string{
		"node_modules", "node_modules/a.js", "node_modules/left-pad/index.js",
		"node_modules/kept/fix.js", "node_modules/kept/deep/note.txt",
	} {
		if !memberPaths[want] {
			t.Errorf("member set lacks %s: %v", want, memberPaths)
		}
	}

	// recreate_live is frozen for the ecosystem adapter; the frozen
	// lockfile recipe stays in reclaim_command.
	if !equalStrings(g.RecreateLive, []string{"pnpm", "install"}) {
		t.Errorf("recreate_live = %v, want [pnpm install]", g.RecreateLive)
	}
	if !equalStrings(g.ReclaimCommand, []string{"pnpm", "install", "--frozen-lockfile"}) {
		t.Errorf("reclaim_command = %v", g.ReclaimCommand)
	}

	// The overlay copies are inside P and byte-exact (the restore-side
	// contract: reapply after the recipe).
	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	payload := snaps[len(snaps)-1].PayloadBackendID
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	for path, want := range map[string]string{
		"node_modules/kept/fix.js":        carveFix,
		"node_modules/kept/deep/note.txt": carveDeepNote,
	} {
		rec := byPath[path]
		got, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, payload, prefix+"/"+rec.Copy)
		if err != nil {
			t.Fatalf("dump overlay copy %s: %v", rec.Copy, err)
		}
		if string(got) != want {
			t.Errorf("overlay copy of %s differs from the original bytes", path)
		}
	}
}

// TestTrimCarveOutWithoutConsentBlocked: no opts.CarveOut, no carve —
// the group is refused exactly as before, with text naming the missing
// authorization, and nothing is removed.
func TestTrimCarveOutWithoutConsentBlocked(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "carve")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)

	opts := carveOpts(t, ws, "deps")
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var blocked *ErrDestructiveBlocked
	if !errors.As(err, &blocked) {
		t.Fatalf("expected ErrDestructiveBlocked, got %v", err)
	}
	if !strings.Contains(blocked.Error(), "--carve-out") {
		t.Errorf("refusal must name the missing --carve-out authorization: %v", blocked)
	}
	if !strings.Contains(blocked.Error(), "deps") {
		t.Errorf("refusal must name the group: %v", blocked)
	}
	mustExist(t, filepath.Join(root, "node_modules", "kept", "fix.js"))
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
	if n := activeCount(t, h.coord(), ws); n != 0 {
		t.Errorf("active ops after refused carve trim = %d, want 0", n)
	}
}

// TestTrimCarveOutGitTrackedEvidenceParity: lifecycle's own resolution
// must see the CLI's git-index observation. With GitTrackedPaths naming
// a bulk file, the group cancels and the file is carved; without the
// observation the group is applicable and the same file is ordinary
// bulk (no overlay).
func TestTrimCarveOutGitTrackedEvidenceParity(t *testing.T) {
	h := newHarness(t)

	// With the tracked observation: cancelled + carved.
	wsA := newWSID()
	rootA := filepath.Join(h.base, "work", "tracked-a")
	if err := os.MkdirAll(rootA, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, rootA)
	optsA := trimOpts(t, wsA, "deps") // plain policy, no preserve rule
	optsA.GitTrackedPaths = []string{"node_modules/a.js"}
	optsA.CarveOut = true
	optsA.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, rootA, optsA); err != nil {
		t.Fatalf("trim with tracked carve: %v", err)
	}
	planA := dumpTrimPlanFromP(t, h, wsA)
	if len(planA.Groups) != 1 || len(planA.Groups[0].OverlayPatches) != 1 ||
		planA.Groups[0].OverlayPatches[0].Path != "node_modules/a.js" {
		t.Fatalf("tracked file not carved exactly once: %+v", planA.Groups[0].OverlayPatches)
	}
	mustLstatErrNotExist(t, filepath.Join(rootA, "node_modules"))

	// Without the observation: applicable, plain bulk trim, no overlay.
	wsB := newWSID()
	rootB := filepath.Join(h.base, "work", "tracked-b")
	if err := os.MkdirAll(rootB, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, rootB)
	optsB := trimOpts(t, wsB, "deps")
	optsB.CarveOut = true // harmless without cancellers
	optsB.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, rootB, optsB); err != nil {
		t.Fatalf("trim without tracked evidence: %v", err)
	}
	planB := dumpTrimPlanFromP(t, h, wsB)
	if len(planB.Groups) != 1 || len(planB.Groups[0].OverlayPatches) != 0 {
		t.Fatalf("--carve-out without cancellers must be harmless (no overlays): %+v", planB.Groups[0].OverlayPatches)
	}
}

// TestTrimCarveOutLinkSidecar: a preserved link inside the outputs is
// carved as link TEXT (a .ebb-link sidecar regular file holding the
// target), removed with the group, and never followed.
func TestTrimCarveOutLinkSidecar(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "link-carve")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)
	outside := filepath.Join(h.base, "outside-data.txt")
	if err := os.WriteFile(outside, []byte(carveOutsideTxt), 0o644); err != nil {
		t.Fatal(err)
	}
	kind := makeOutsideLink(t, root, "node_modules/kept/outside-link", relTargetTo(root, outside))

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("trim with link carve: %v", err)
	}

	plan := dumpTrimPlanFromP(t, h, ws)
	g := plan.Groups[0]
	var linkRec *overlayPatchRecord
	for i, r := range g.OverlayPatches {
		if r.Path == "node_modules/kept/outside-link" {
			linkRec = &g.OverlayPatches[i]
		}
	}
	if linkRec == nil {
		t.Fatalf("link not carved: %+v", g.OverlayPatches)
	}
	if linkRec.Kind != overlayKindLink {
		t.Errorf("link record kind = %q, want %q", linkRec.Kind, overlayKindLink)
	}
	if linkRec.Digest != "" {
		t.Errorf("link record digest = %q, want empty (links carry no content digest)", linkRec.Digest)
	}
	if !strings.HasSuffix(linkRec.Copy, ".ebb-link") {
		t.Errorf("link record copy = %q, want an .ebb-link sidecar", linkRec.Copy)
	}
	// The sidecar's content is the link's target TEXT — never the
	// target's content.
	c := h.coord()
	snaps, _ := c.cat.ListSnapshots(ws)
	payload := snaps[len(snaps)-1].PayloadBackendID
	prefix := "/" + opDirName(h.opIDOf(t, ws))
	sidecar, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile, payload, prefix+"/"+linkRec.Copy)
	if err != nil {
		t.Fatalf("dump link sidecar: %v", err)
	}
	if string(sidecar) == carveOutsideTxt {
		t.Fatalf("F-LINK REGRESSION: the link was FOLLOWED — the sidecar holds the target's content")
	}
	// The recorded target text must actually point at the outside file
	// (absolute junction form or relative symlink form both resolve
	// there lexically via the scan's recorded text).
	var member *inventoryRecord
	for i, m := range g.Members {
		if m.Path == "node_modules/kept/outside-link" {
			member = &g.Members[i]
		}
	}
	if member == nil {
		t.Fatalf("link missing from the member set: %+v", g.Members)
	}
	if member.Kind != kind {
		t.Errorf("member kind = %q, want the created link kind %q", member.Kind, kind)
	}
	if string(sidecar) != member.LinkTarget {
		t.Errorf("sidecar text %q != sealed link target %q", string(sidecar), member.LinkTarget)
	}
	// The link itself is gone; the outside target is untouched.
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
	mustExist(t, outside)
	if b, rerr := os.ReadFile(outside); rerr != nil || string(b) != carveOutsideTxt {
		t.Errorf("outside target damaged: %v", rerr)
	}
}

// TestTrimCarveOutOverlayTamperFailsVerification: the overlay copies
// are ordinary op-dir bytes — tampering one between the selection walk
// and the payload capture must fail payload verification and cancel the
// operation with the source intact (§11.3/§11.4).
func TestTrimCarveOutOverlayTamperFailsVerification(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "tamper")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)

	h.store.onSnapshot = func(tags map[string]string) error {
		if tags["ebb-kind"] != "payload" {
			return nil
		}
		// The op dir is on disk; corrupt one overlay copy before the
		// store copies the tree (pre-capture tamper). The tags carry
		// this operation's id directly.
		p := filepath.Join(filepath.Dir(root), opDirName(domain.OperationID(tags["ebb-op"])),
			"overlay", "deps", "node_modules", "kept", "fix.js")
		return os.WriteFile(p, []byte("tampered overlay bytes\n"), 0o600)
	}

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var verr *ErrVerification
	if !errors.As(err, &verr) {
		t.Fatalf("expected ErrVerification from the tampered overlay copy, got %v", err)
	}
	// Nothing removed; the carved file survives on disk.
	mustExist(t, filepath.Join(root, "node_modules", "kept", "fix.js"))
	mustExist(t, filepath.Join(root, "node_modules", "a.js"))
}

// TestTrimCarveOutSourceChangedUnderOverlay: a carved file changing
// between the scan and the overlay copy fails the trim as
// ErrSourceChanged — the overlay must capture exactly the sealed bytes.
func TestTrimCarveOutSourceChangedUnderOverlay(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "changed")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)

	armed := false
	h.probe.onProbeFile = func(path string) {
		// Mutate the carved file right after the scan hashed it (the
		// scan probes every entry; fire on the LAST probed entry).
		if armed || !strings.HasSuffix(filepath.ToSlash(path), "notes.md") {
			return
		}
		armed = true
		_ = os.WriteFile(filepath.Join(root, "node_modules", "kept", "fix.js"), []byte("writer raced the carve\n"), 0o644)
	}

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	_, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	var sc *ErrSourceChanged
	if !errors.As(err, &sc) {
		t.Fatalf("expected ErrSourceChanged, got %v", err)
	}
	if !strings.Contains(err.Error(), "node_modules/kept/fix.js") {
		t.Errorf("refusal must name the changed carved file: %v", err)
	}
	mustExist(t, filepath.Join(root, "node_modules", "kept", "fix.js"))
}

// TestTrimCarveOutDirOnlyCanceller: a preserved directory with NO
// carve-able file inside is not itself captured (the recipe recreates
// the tree) — the carve proceeds with zero overlay records.
func TestTrimCarveOutDirOnlyCanceller(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "dironly")
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "kept-empty", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixtureNoKept(t, root)

	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
	opts.ApprovalReady = func(string) error { return nil }
	res, err := h.coord().Trim(context.Background(), h.vault, root, opts)
	if err != nil {
		t.Fatalf("dir-only canceller carve: %v", err)
	}
	plan := dumpTrimPlanFromP(t, h, ws)
	if len(plan.Groups) != 1 || len(plan.Groups[0].OverlayPatches) != 0 {
		t.Fatalf("dir-only canceller must produce zero overlay records: %+v", plan.Groups[0].OverlayPatches)
	}
	if res.EntriesRemoved == 0 {
		t.Errorf("nothing removed in dir-only carve")
	}
	mustLstatErrNotExist(t, filepath.Join(root, "node_modules"))
}

// writeCarveFixtureNoKept is the carve fixture without the kept files
// but with the preserved empty directory tree.
func writeCarveFixtureNoKept(t *testing.T, root string) {
	t.Helper()
	writeCarveFixture(t, root)
	for _, rel := range []string{
		filepath.Join("node_modules", "kept", "fix.js"),
		filepath.Join("node_modules", "kept", "deep", "note.txt"),
	} {
		if err := os.Remove(filepath.Join(root, rel)); err != nil {
			t.Fatal(err)
		}
	}
}

// TestLiveRecreateCommand pins the per-adapter live-recipe mapping
// (custom commands and pip have NO live variant).
func TestLiveRecreateCommand(t *testing.T) {
	cases := []struct {
		name string
		g    policy.Regenerate
		want []string
	}{
		{"pnpm", policy.Regenerate{Adapter: policy.AdapterPNPM}, []string{"pnpm", "install"}},
		{"npm", policy.Regenerate{Adapter: policy.AdapterNPM}, []string{"npm", "install"}},
		{"uv", policy.Regenerate{Adapter: policy.AdapterUV}, []string{"uv", "sync"}},
		{"pip", policy.Regenerate{Adapter: policy.AdapterPip}, nil},
		{"custom-command", policy.Regenerate{Adapter: policy.AdapterCustom, Command: []string{"make", "gen"}}, nil},
		{"pnpm-with-command", policy.Regenerate{Adapter: policy.AdapterPNPM, Command: []string{"./gen.sh"}}, nil},
		{"unknown", policy.Regenerate{Adapter: "nope"}, nil},
	}
	for _, tc := range cases {
		if got := liveRecreateCommand(tc.g); !equalStrings(got, tc.want) && !(len(got) == 0 && len(tc.want) == 0) {
			t.Errorf("%s: liveRecreateCommand = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestTrimRecreateLiveOmittedForCustomCommand: a custom-command group
// records no recreate_live (field omitted from the JSON).
func TestTrimRecreateLiveOmittedForCustomCommand(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")

	pol := trimPolicy(t)
	pol.Regenerate[0].Adapter = policy.AdapterCustom
	pol.Regenerate[0].Command = []string{"make", "gen-deps"}
	opts := snapshotOpts(ws)
	opts.Policy = pol
	opts.DoTrim = []string{"deps"}
	opts.ApprovalReady = func(string) error { return nil }
	if _, err := h.coord().Trim(context.Background(), h.vault, root, opts); err != nil {
		t.Fatalf("custom trim: %v", err)
	}
	plan := dumpTrimPlanFromP(t, h, ws)
	if len(plan.Groups) != 1 {
		t.Fatalf("plan groups = %d", len(plan.Groups))
	}
	if plan.Groups[0].RecreateLive != nil {
		t.Errorf("custom command group recorded recreate_live = %v, want omitted", plan.Groups[0].RecreateLive)
	}
	if !equalStrings(plan.Groups[0].ReclaimCommand, []string{"make", "gen-deps"}) {
		t.Errorf("reclaim_command = %v, want the declared command", plan.Groups[0].ReclaimCommand)
	}
}

// TestTrimCarveOutRecoverSealingResumes: a carved trim interrupted
// mid-removal (TRIM_SEALING) resumes from the retained removal manifest
// and removes the CARVED entries too — recover.go needed no change
// because carved entries are members (the frozen schema's audit trail
// is the restore contract, not the resume mechanism).
func TestTrimCarveOutRecoverSealingResumes(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := filepath.Join(h.base, "work", "carve-resume")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCarveFixture(t, root)

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
	opts := carveOpts(t, ws, "deps")
	opts.CarveOut = true
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
	mustExist(t, filepath.Join(root, "package.json"))
}

// ---- helpers --------------------------------------------------------------

// makeOutsideLink creates a link at rel (root-relative) pointing at the
// outside path. Prefers a real symlink; on Windows without the symlink
// privilege falls back to an unprivileged junction (both are link kinds
// whose target text the scanner records). Reports the created kind.
func makeOutsideLink(t *testing.T, root, rel string, targetAbs string) domain.EntryKind {
	t.Helper()
	linkPath := filepath.Join(root, filepath.FromSlash(rel))
	serr := os.Symlink(targetAbs, linkPath)
	if serr == nil {
		return domain.KindSymlink
	}
	if runtime.GOOS == "windows" {
		out, jerr := exec.Command("cmd", "/c", "mklink", "/J", linkPath, targetAbs).CombinedOutput()
		if jerr != nil {
			t.Skipf("cannot create symlink (%v) or junction (%v: %s); link fixture unavailable", serr, jerr, out)
		}
		return domain.KindJunction
	}
	t.Skipf("cannot create symlink: %v", serr)
	return ""
}

// relTargetTo renders an absolute target as a relative spelling from
// the link's directory (exercises relative link text).
func relTargetTo(root, targetAbs string) string {
	linkDir := filepath.Join(root, "node_modules", "kept")
	rel, err := filepath.Rel(linkDir, targetAbs)
	if err != nil {
		return targetAbs
	}
	return rel
}
