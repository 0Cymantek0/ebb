package restore

// liverestore_test.go drives the D033 live-restore driver: the strict
// trim-document reader, the drift detector, the manifest-union merger,
// the Git/outputs gates, the overlay reapplication and the end-to-end
// driver against the fake store + a real sqlite catalog + a scripted
// action runner.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/actions"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/platform"
)

// ---- trimdocs strict reader -------------------------------------------------

func TestReadTrimDocsHappyPathWithNewFields(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		recreateLive: []string{"pnpm", "install"},
		overlayFiles: map[string]string{"node_modules/left-pad/index.js": "// patched\n"},
		overlayLinks: map[string]string{"node_modules/.bin/tool": "../lib/tool.js"},
		recordedGit:  recGit, liveGit: liveGit,
	})
	docs, err := readTrimDocs(context.Background(), f.store, f.vault, f.payloadID, string(f.trimOpID),
		f.manifestDigest, f.planDigest)
	if err != nil {
		t.Fatalf("readTrimDocs: %v", err)
	}
	if len(docs.plan.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(docs.plan.Groups))
	}
	g := docs.plan.Groups[0]
	if g.GroupID != lrGroupName || len(g.RecreateLive) != 2 || g.RecreateLive[0] != "pnpm" {
		t.Fatalf("group/recreate_live not round-tripped: %+v", g)
	}
	if len(g.OverlayPatches) != 2 {
		t.Fatalf("overlay patches = %d, want 2", len(g.OverlayPatches))
	}
	if docs.manifest.GitObservations.HeadBranch != recGit.HeadBranch {
		t.Fatalf("git observations not round-tripped: %+v", docs.manifest.GitObservations)
	}
}

func TestReadTrimDocsToleratesOlderManifestsWithoutNewFields(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	raw := f.planBytes
	if strings.Contains(string(raw), "recreate_live") || strings.Contains(string(raw), "overlay_patches") {
		t.Fatalf("fixture unexpectedly wrote the new fields:\n%s", raw)
	}
	docs, err := readTrimDocs(context.Background(), f.store, f.vault, f.payloadID, string(f.trimOpID),
		f.manifestDigest, f.planDigest)
	if err != nil {
		t.Fatalf("older manifest refused: %v", err)
	}
	if len(docs.plan.Groups[0].OverlayPatches) != 0 || len(docs.plan.Groups[0].RecreateLive) != 0 {
		t.Fatalf("older manifest should parse to zero-value extensions")
	}
}

func TestReadTrimDocsRefusals(t *testing.T) {
	recGit, liveGit := noDriftGit()
	base := func(mut func(spec *trimFixtureSpec)) trimFixtureSpec {
		spec := trimFixtureSpec{recordedGit: recGit, liveGit: liveGit}
		mut(&spec)
		return spec
	}
	cases := []struct {
		name string
		spec trimFixtureSpec
		want string
	}{
		{"unknown schema version", base(func(s *trimFixtureSpec) { s.planSchemaVersion = 99 }),
			"schema_version"},
		{"unknown field in plan", base(func(s *trimFixtureSpec) { s.unknownPlanField = true }),
			"strict parsing"},
		{"hostile traversal overlay path", base(func(s *trimFixtureSpec) { s.hostileOverlayPath = "../evil.js" }),
			"'..'"},
		{"hostile absolute overlay path", base(func(s *trimFixtureSpec) { s.hostileOverlayPath = "/etc/passwd" }),
			"absolute"},
		{"hostile backslash overlay path", base(func(s *trimFixtureSpec) { s.hostileOverlayPath = `a\b.js` }),
			"backslash"},
		{"hostile ADS colon overlay path", base(func(s *trimFixtureSpec) { s.hostileOverlayPath = "file.js:stream" }),
			"colon"},
		{"hostile drive-prefix overlay path", base(func(s *trimFixtureSpec) { s.hostileOverlayPath = "C:/evil.js" }),
			"drive prefix"},
		{"hostile NUL overlay path", base(func(s *trimFixtureSpec) { s.hostileOverlayPath = "a\x00b" }),
			"NUL"},
		{"hostile device-name overlay path", base(func(s *trimFixtureSpec) { s.hostileOverlayPath = "node_modules/con.js" }),
			"device-name"},
		{"hostile escaping overlay copy", base(func(s *trimFixtureSpec) {
			s.hostileOverlayPath = "node_modules/ok.js"
			s.hostileOverlayCopy = "inputs/" + lrGroupName + "/../../package.json"
		}), "not under"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildTrimFixture(t, tc.spec)
			_, err := readTrimDocs(context.Background(), f.store, f.vault, f.payloadID, string(f.trimOpID),
				f.manifestDigest, f.planDigest)
			if err == nil {
				t.Fatalf("expected refusal, got docs")
			}
			var ver *ErrVerification
			if !errors.As(err, &ver) || ver.Check != "trim-documents" {
				t.Fatalf("expected *ErrVerification{trim-documents}, got %T: %v", err, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestReadTrimDocsDigestWitness(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	// Tamper the served manifest bytes (I12/D017: the digest must catch it).
	f.store.dumpTamper["/"+f.opDir+"/"+manifestName] = func(b []byte) []byte {
		return append(b, ' ')
	}
	_, err := readTrimDocs(context.Background(), f.store, f.vault, f.payloadID, string(f.trimOpID),
		f.manifestDigest, f.planDigest)
	if err == nil || !strings.Contains(err.Error(), "tampering suspected") {
		t.Fatalf("expected digest-witness refusal, got %v", err)
	}
	// A row without digests cannot witness anything.
	_, err = readTrimDocs(context.Background(), f.store, f.vault, f.payloadID, string(f.trimOpID), "", "")
	if err == nil || !strings.Contains(err.Error(), "cannot be witnessed") {
		t.Fatalf("expected unwitnessed-row refusal, got %v", err)
	}
}

// ---- drift detector -----------------------------------------------------------

func TestDetectDrift(t *testing.T) {
	recGit, liveGit := noDriftGit()
	frozen := `{"name":"livews","dependencies":{"left-pad":"1.0.0","recorded-only":"2.0.0"}}`
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenPackageJSON: frozen,
		missingInputs:     []string{"extra-manifest.json"},
		recordedGit:       recGit, liveGit: liveGit,
	})
	// Drift the live file, delete the lockfile, add the missing input.
	writeFile(t, filepath.Join(f.wsRoot, "package.json"), []byte(`{"name":"livews","dependencies":{"left-pad":"1.1.0"}}`))
	if err := os.Remove(filepath.Join(f.wsRoot, "pnpm-lock.yaml")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.wsRoot, "extra-manifest.json"), []byte("{}"))

	drift := detectDrift(f.wsRoot, f.planGroups(t))
	if len(drift) != 3 {
		t.Fatalf("drift entries = %d (%+v), want 3", len(drift), drift)
	}
	byPath := map[string]DriftEntry{}
	for _, d := range drift {
		byPath[d.Path] = d
	}
	if d := byPath["package.json"]; d.State != "differs" || d.Group != lrGroupName {
		t.Fatalf("package.json drift = %+v, want differs", d)
	}
	if d := byPath["pnpm-lock.yaml"]; d.State != "missing" {
		t.Fatalf("pnpm-lock.yaml drift = %+v, want missing", d)
	}
	if d := byPath["extra-manifest.json"]; d.State != "new" {
		t.Fatalf("extra-manifest.json drift = %+v, want new", d)
	}
	// An undrifted world reports nothing.
	f2 := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	if d := detectDrift(f2.wsRoot, f2.planGroups(t)); len(d) != 0 {
		t.Fatalf("undrifted world reported %+v", d)
	}
}

// planGroups re-reads the fixture's own removal plan for drift tests.
func (f *trimFixture) planGroups(t *testing.T) []removalGroupReader {
	t.Helper()
	var plan trimPlanDocReader
	if err := decodeStrict(f.planBytes, &plan); err != nil {
		t.Fatalf("re-parse fixture plan: %v", err)
	}
	return plan.Groups
}

// planWithOverlays returns a copy of the fixture plan whose single group
// carries exactly these overlay patches.
func (f *trimFixture) planWithOverlays(t *testing.T, patches []overlayPatchReader) trimPlanDocReader {
	t.Helper()
	return trimPlanDocReader{
		SchemaVersion: schemaVersionCurrent, OperationID: string(f.trimOpID), SnapshotID: string(f.snapID),
		Groups: []removalGroupReader{{
			GroupID: lrGroupName, Adapter: lrGroupAdapter, Root: ".",
			Outputs: []string{"node_modules"}, ReclaimCommand: []string{"pnpm", "install", "--frozen-lockfile"},
			RecipeInputs:   f.planGroups(t)[0].RecipeInputs,
			OverlayPatches: patches,
		}},
	}
}

// reloadPlan rewrites the removal manifest in the op dir, re-snapshots
// the payload and repoints the trim op's backend ref + snapshot row at
// the new digests (tests that need a plan the spec knobs cannot
// express).
func (f *trimFixture) reloadPlan(t *testing.T, plan trimPlanDocReader) {
	t.Helper()
	pb, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pb = append(pb, '\n')
	f.planBytes, f.planDigest = pb, digestBytes(pb)
	writeFile(t, filepath.Join(f.parent, f.opDir, removalManifestName), f.planBytes)
	payload, err := f.store.Snapshot(context.Background(), f.vault.RepoDir, f.parent, []string{f.opDir},
		f.vault.Passfile, map[string]string{"ebb-kind": "payload"})
	if err != nil {
		t.Fatalf("reload payload snapshot: %v", err)
	}
	if _, err := f.cat.RecordSnapshot(catalog.Snapshot{
		ID: domain.SnapshotID(domain.NewID()), WorkspaceID: f.wsID,
		PayloadBackendID: payload.BackendID, ManifestDigest: f.manifestDigest,
		InventoryDigest: f.planDigest, Kind: catalog.SnapshotKindTrim,
	}); err != nil {
		t.Fatalf("reload snapshot row: %v", err)
	}
	if err := f.cat.SetBackendRefs(f.trimOpID, payload.BackendID, ""); err != nil {
		t.Fatalf("reload backend refs: %v", err)
	}
	f.payloadID = payload.BackendID
}

// ---- manifest union -----------------------------------------------------------

func TestUnionJSONManifest(t *testing.T) {
	live := []byte(`{
  "name": "app",
  "dependencies": {"left-pad": "1.0.0"},
  "devDependencies": {"typescript": "5.0.0"}
}
`)
	frozen := []byte(`{
  "name": "app-old",
  "dependencies": {"left-pad": "0.9.0", "chalk": "2.0.0"},
  "devDependencies": {"typescript": "4.0.0", "vitest": "1.0.0"},
  "peerDependencies": {"react": "*"}
}
`)
	out, notes, ok := unionJSONManifest(live, frozen)
	if !ok {
		t.Fatalf("union refused: %v", notes)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unioned document does not parse: %v\n%s", err, out)
	}
	deps := doc["dependencies"].(map[string]any)
	if deps["left-pad"] != "1.0.0" { // live wins on the direct conflict
		t.Fatalf("live version did not win: %v", deps)
	}
	if deps["chalk"] != "2.0.0" { // recorded-only key added
		t.Fatalf("recorded-only key not added: %v", deps)
	}
	dev := doc["devDependencies"].(map[string]any)
	if dev["typescript"] != "5.0.0" || dev["vitest"] != "1.0.0" {
		t.Fatalf("dev section not unioned (dev vs prod must stay separate): %v / %v", dev, deps)
	}
	if doc["peerDependencies"].(map[string]any)["react"] != "*" {
		t.Fatalf("peerDependencies not unioned: %v", doc)
	}
	if doc["name"] != "app" { // non-dependency fields stay live
		t.Fatalf("unrelated field changed: %v", doc["name"])
	}
	var conflict, added bool
	for _, n := range notes {
		if strings.Contains(n, "keeping live 1.0.0 (recorded 0.9.0)") {
			conflict = true
		}
		if strings.Contains(n, "added 1 recorded package") {
			added = true
		}
	}
	if !conflict || !added {
		t.Fatalf("union decisions not reported: %v", notes)
	}

	// Malformed live file: merge unavailable, never an error.
	_, notes2, ok2 := unionJSONManifest([]byte("{not json"), frozen)
	if ok2 {
		t.Fatalf("malformed live file must refuse the union")
	}
	if len(notes2) == 0 {
		t.Fatalf("refusal must carry the reason")
	}
}

func TestUnionCargoTOML(t *testing.T) {
	live := []byte(`[package]
name = "app"

[dependencies]
left-pad = "1"

[dev-dependencies]
tempfile = "3"
`)
	frozen := []byte(`[package]
name = "app-old"

[dependencies]
left-pad = "0.9"
serde = "1"

[build-dependencies]
cc = "1"
`)
	out, notes, ok := unionCargoTOML(live, frozen)
	if !ok {
		t.Fatalf("union refused: %v", notes)
	}
	s := string(out)
	if !strings.Contains(s, `left-pad = "1"`) {
		t.Fatalf("live version did not win:\n%s", s)
	}
	if !strings.Contains(s, `serde = "1"`) {
		t.Fatalf("recorded-only dependency not added:\n%s", s)
	}
	if !strings.Contains(s, "[build-dependencies]") || !strings.Contains(s, `cc = "1"`) {
		t.Fatalf("missing build-dependencies table not adopted:\n%s", s)
	}
	if !strings.Contains(s, `tempfile = "3"`) {
		t.Fatalf("dev-dependencies lost:\n%s", s)
	}
	// The union output must itself round-trip through the parser.
	if _, err := parseTOMLFile(out); err != nil {
		t.Fatalf("unioned Cargo.toml does not re-parse: %v", err)
	}
}

func TestUnionPyprojectTOML(t *testing.T) {
	live := []byte(`[project]
name = "app"
dependencies = [
    "requests>=2",
]

[tool.uv]
dev-dependencies = [
    "pytest>=8",
]
`)
	frozen := []byte(`[project]
name = "app-old"
dependencies = [
    "requests>=2",
    "httpx>=0.27",
]

[tool.uv.sources]
httpx = { workspace = true }
`)
	out, notes, ok := unionPyprojectTOML(live, frozen)
	if !ok {
		t.Fatalf("union refused: %v", notes)
	}
	s := string(out)
	if !strings.Contains(s, `"httpx>=0.27"`) {
		t.Fatalf("recorded-only dependency not added:\n%s", s)
	}
	if !strings.Contains(s, "[tool.uv.sources]") || !strings.Contains(s, "httpx = { workspace = true }") {
		t.Fatalf("uv sources table not unioned:\n%s", s)
	}
	if !strings.Contains(s, `"pytest>=8"`) {
		t.Fatalf("dev-dependencies lost:\n%s", s)
	}
	// Non-array dependencies value: merge unavailable (honest fallback).
	liveBad := []byte("[project]\ndependencies = 3\n")
	if _, _, ok2 := unionPyprojectTOML(liveBad, frozen); ok2 {
		t.Fatalf("malformed dependencies value must refuse the union")
	}
}

// ---- gates ----------------------------------------------------------------------

func TestOutputsAllPresentAndResumableOp(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	if outputsAllPresent(f.wsRoot, f.planGroups(t)) {
		t.Fatalf("absent outputs must not count as present")
	}
	mustMkdir(t, filepath.Join(f.wsRoot, "node_modules"))
	if outputsAllPresent(f.wsRoot, f.planGroups(t)) {
		t.Fatalf("EMPTY output directory must not count as present")
	}
	writeFile(t, filepath.Join(f.wsRoot, "node_modules", "x.js"), []byte("x"))
	if !outputsAllPresent(f.wsRoot, f.planGroups(t)) {
		t.Fatalf("populated outputs must count as present")
	}

	ops, err := f.cat.ListOperations(f.wsID)
	if err != nil {
		t.Fatal(err)
	}
	if hasResumableRestoreOp(ops) {
		t.Fatalf("no restore op exists yet")
	}
	// A FAILED restore op makes the rerun a resume.
	rop, err := f.cat.BeginOperation(f.wsID, catalog.OpKindRestore, f.wsRoot, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.cat.AdvanceOperation(rop, catalog.PhasePlanned, catalog.PhaseRestorePlanning); err != nil {
		t.Fatal(err)
	}
	if err := f.cat.AdvanceOperation(rop, catalog.PhaseRestorePlanning, catalog.PhaseRestoreRunning); err != nil {
		t.Fatal(err)
	}
	if err := f.cat.AdvanceOperation(rop, catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed); err != nil {
		t.Fatal(err)
	}
	ops, err = f.cat.ListOperations(f.wsID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasResumableRestoreOp(ops) {
		t.Fatalf("a FAILED restore op must mark the workspace resumable")
	}
}

func TestLiveRestoreNothingToRestore(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "orphan")
	mustMkdir(t, root)
	store := newFakeStore()
	fcat := openCatalog(t, filepath.Join(base, "cat.db"))
	if _, err := NewLiveRestorer(LiveDependencies{Store: store, Cat: fcat, Probe: nil}); err == nil {
		t.Fatal("Probe is required; NewLiveRestorer must refuse")
	}
	o, err := NewLiveRestorer(LiveDependencies{Store: store, Cat: fcat, Probe: platform.New()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = o.LiveRestore(context.Background(), VaultRef{RepoDir: base, Passfile: "p"}, root, LiveRestoreOptions{})
	var nothing *ErrNothingToRestore
	if !errors.As(err, &nothing) {
		t.Fatalf("expected ErrNothingToRestore, got %v", err)
	}
}

func TestLiveRestoreAlreadyRestoredGate(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	mustMkdir(t, filepath.Join(f.wsRoot, "node_modules"))
	writeFile(t, filepath.Join(f.wsRoot, "node_modules", "x.js"), []byte("x"))
	o := f.newLiveRestorer(&lrRunner{})
	_, err := o.LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var already *ErrAlreadyRestored
	if !errors.As(err, &already) {
		t.Fatalf("expected ErrAlreadyRestored, got %v", err)
	}
}

// ---- Git gate ---------------------------------------------------------------------

func TestLiveRestoreGitConflictFailsClosed(t *testing.T) {
	recGit, _ := noDriftGit()
	live := recGit
	live.MergeInProgress = true
	live.UnmergedEntries = 2
	// A prompt is wired: the conflict gate must STILL refuse.
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: live})
	f.prompt = &lrPrompt{branch: BranchRebuildCurrent}
	o := f.newLiveRestorer(&lrRunner{})
	_, err := o.LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var conflict *ErrGitConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("expected ErrGitConflict (fail closed even interactively), got %v", err)
	}
	if !strings.Contains(err.Error(), "MERGE_HEAD") || !strings.Contains(err.Error(), "unmerged") {
		t.Fatalf("conflict details incomplete: %v", err)
	}
}

func TestLiveRestoreBranchMismatchNonInteractiveRefuses(t *testing.T) {
	recGit, _ := noDriftGit()
	live := recGit
	live.HeadBranch = "main"
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: live})
	o := f.newLiveRestorer(&lrRunner{})
	_, err := o.LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var mm *ErrBranchMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("expected ErrBranchMismatch, got %v", err)
	}
	if !strings.Contains(err.Error(), "feature-x") || !strings.Contains(err.Error(), "main") {
		t.Fatalf("mismatch must name both branches: %v", err)
	}
}

func TestLiveRestoreBranchMismatchInteractiveChoices(t *testing.T) {
	recGit, _ := noDriftGit()
	live := recGit
	live.HeadBranch = "main"

	// [1] switch back: nothing runs; the exact git switch command is named.
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: live})
	f.prompt = &lrPrompt{branch: BranchSwitchBack}
	runner := &lrRunner{}
	o := f.newLiveRestorer(runner)
	_, err := o.LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var advice *ErrBranchSwitchAdvice
	if !errors.As(err, &advice) {
		t.Fatalf("expected ErrBranchSwitchAdvice, got %v", err)
	}
	if strings.Join(advice.SwitchArgv, " ") != "git switch feature-x" {
		t.Fatalf("switch argv = %v", advice.SwitchArgv)
	}
	if len(runner.definitions()) != 0 {
		t.Fatalf("nothing may run on the switch-back choice")
	}

	// [3] cancel: declined, nothing runs.
	f2 := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: live})
	f2.prompt = &lrPrompt{branch: BranchCancel}
	runner2 := &lrRunner{}
	o2 := f2.newLiveRestorer(runner2)
	_, err = o2.LiveRestore(context.Background(), f2.vault, f2.wsRoot, LiveRestoreOptions{})
	var declined *ErrRestoreDeclined
	if !errors.As(err, &declined) {
		t.Fatalf("expected ErrRestoreDeclined, got %v", err)
	}
	if len(runner2.definitions()) != 0 {
		t.Fatalf("nothing may run on cancel")
	}

	// [2] rebuild current: proceeds and completes.
	f3 := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: live})
	f3.prompt = &lrPrompt{branch: BranchRebuildCurrent}
	runner3 := &lrRunner{}
	o3 := f3.newLiveRestorer(runner3)
	res, err := o3.LiveRestore(context.Background(), f3.vault, f3.wsRoot, LiveRestoreOptions{})
	if err != nil {
		t.Fatalf("rebuild-current choice must proceed: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone || len(runner3.definitions()) != 1 {
		t.Fatalf("res.Phase = %s, runner calls = %d", res.Phase, len(runner3.definitions()))
	}
}

func TestLiveRestoreDetachedCommitComparison(t *testing.T) {
	// Recorded detached at commit X; live detached at X → parity, proceeds.
	recGit := domain.GitObservation{IsRepo: true, Detached: true, HeadCommit: "c0ffee0000c0ffee0000c0ffee0000c0ffee0000"}
	liveSame := recGit
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveSame})
	runner := &lrRunner{}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err != nil || res.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("same detached commit must proceed: %v", err)
	}
	// Live moved to another commit (still detached): mismatch.
	liveMoved := recGit
	liveMoved.HeadCommit = "deadbeef00deadbeef00deadbeef00deadbeef00"
	f2 := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveMoved})
	_, err = f2.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f2.vault, f2.wsRoot, LiveRestoreOptions{})
	var mm *ErrBranchMismatch
	if !errors.As(err, &mm) || !mm.Detached {
		t.Fatalf("expected detached mismatch, got %v", err)
	}
}

// ---- drift + strategy --------------------------------------------------------------

func TestLiveRestoreStrategyRequiredWithoutChoice(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenPackageJSON: `{"name":"livews","dependencies":{"left-pad":"1.0.0","chalk":"2.0.0"}}`,
		recordedGit:       recGit, liveGit: liveGit,
	})
	o := f.newLiveRestorer(&lrRunner{})
	_, err := o.LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var req *ErrStrategyRequired
	if !errors.As(err, &req) {
		t.Fatalf("expected ErrStrategyRequired, got %v", err)
	}
	if len(req.Drift) != 1 || req.Drift[0].Path != "package.json" {
		t.Fatalf("strategy error must carry the drift table: %+v", req.Drift)
	}
}

func TestLiveRestoreNoDriftRunsFrozenRecipe(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	runner := &lrRunner{}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err != nil {
		t.Fatalf("no-drift restore failed: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("phase = %s, want RESTORE_DONE", res.Phase)
	}
	defs := runner.definitions()
	if len(defs) != 1 {
		t.Fatalf("runner calls = %d, want 1", len(defs))
	}
	if strings.Join(defs[0].Argv, " ") != "pnpm install --frozen-lockfile" {
		t.Fatalf("frozen argv not used verbatim: %v", defs[0].Argv)
	}
	if defs[0].ID != fmt.Sprintf("restore-%s-%s", f.trimOpID, lrGroupName) {
		t.Fatalf("action id = %s", defs[0].ID)
	}
	if defs[0].WorkingRoot != "." || defs[0].Timeout != liveRestoreTimeout || defs[0].Network != actions.NetworkAllowed {
		t.Fatalf("definition contract drifted: %+v", defs[0])
	}
	// The action ran under the restore op with journaling.
	op, err := f.cat.GetOperation(res.OperationID)
	if err != nil || op.Phase != catalog.PhaseRestoreDone || op.Kind != catalog.OpKindRestore {
		t.Fatalf("op row = %+v err=%v", op, err)
	}
	// Outputs materialized; protected files untouched.
	if b, err := os.ReadFile(filepath.Join(f.wsRoot, "node_modules", "built.txt")); err != nil || string(b) != "rebuilt\n" {
		t.Fatalf("recipe output missing: %q %v", b, err)
	}
	if b, _ := os.ReadFile(filepath.Join(f.wsRoot, ".env")); string(b) != "SECRET=live\n" {
		t.Fatalf("protected .env changed: %q", b)
	}
	// No backup files were created (no drift).
	matches, _ := filepath.Glob(filepath.Join(f.wsRoot, "*.bak-drift-*"))
	if len(matches) != 0 {
		t.Fatalf("unexpected backups: %v", matches)
	}
}

func TestLiveRestoreMergeStrategyUnionsAndRunsLiveCommand(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenPackageJSON: `{"name":"livews","dependencies":{"left-pad":"1.0.0","chalk":"2.0.0"}}`,
		recreateLive:      []string{"pnpm", "install"},
		recordedGit:       recGit, liveGit: liveGit,
	})
	runner := &lrRunner{}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyMerge})
	if err != nil {
		t.Fatalf("merge restore failed: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone || res.Strategy != StrategyMerge {
		t.Fatalf("res = %+v", res)
	}
	// The unioned manifest carries both dependencies (live wins on left-pad).
	b, err := os.ReadFile(filepath.Join(f.wsRoot, "package.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unioned manifest unparseable: %s", b)
	}
	deps := doc["dependencies"].(map[string]any)
	if deps["left-pad"] != "1.0.0" || deps["chalk"] != "2.0.0" {
		t.Fatalf("merge did not union: %s", b)
	}
	// The safety backup exists with the pre-merge live bytes.
	backups, _ := filepath.Glob(filepath.Join(f.wsRoot, "package.json.bak-drift-*"))
	if len(backups) != 1 {
		t.Fatalf("expected exactly one drift backup, got %v", backups)
	}
	// The drifted group ran the recreate_live argv, not the frozen one.
	defs := runner.definitions()
	if len(defs) != 1 || strings.Join(defs[0].Argv, " ") != "pnpm install" {
		t.Fatalf("recreate_live argv not used: %+v", defs)
	}
}

func TestLiveRestoreMergeUnavailableFallsBackToLiveFile(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		// A drifted input whose format is outside the union scope.
		extraFrozenInputs: map[string]string{"requirements.txt": "left-pad==1.0.0\nchalk==2.0.0\n"},
		recordedGit:       recGit, liveGit: liveGit,
	})
	writeFile(t, filepath.Join(f.wsRoot, "requirements.txt"), []byte("left-pad==1.1.0\n"))
	runner := &lrRunner{}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyMerge})
	if err != nil {
		t.Fatalf("merge with an out-of-scope input must fall back, not fail: %v", err)
	}
	// The live requirements.txt is kept untouched (no union, no backup needed
	// for a file Ebb did not write).
	b, _ := os.ReadFile(filepath.Join(f.wsRoot, "requirements.txt"))
	if string(b) != "left-pad==1.1.0\n" {
		t.Fatalf("live out-of-scope input was modified: %q", b)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "merge unavailable for requirements.txt") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("fallback not reported: %v", res.Warnings)
	}
}

func TestLiveRestoreBaselineWritesFrozenBytes(t *testing.T) {
	recGit, liveGit := noDriftGit()
	frozen := "{\n  \"name\": \"livews\",\n  \"dependencies\": {\n    \"left-pad\": \"1.0.0\"\n  }\n}\n"
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenPackageJSON: frozen,
		recordedGit:       recGit, liveGit: liveGit,
	})
	runner := &lrRunner{}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyBaseline})
	if err != nil {
		t.Fatalf("baseline restore failed: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(f.wsRoot, "package.json"))
	if string(b) != frozen {
		t.Fatalf("frozen bytes not written back: %q", b)
	}
	backups, _ := filepath.Glob(filepath.Join(f.wsRoot, "package.json.bak-drift-*"))
	if len(backups) != 1 {
		t.Fatalf("baseline must back up the live file first, got %v", backups)
	}
	// Baseline runs the FROZEN lockfile-pinned recipe.
	defs := runner.definitions()
	if strings.Join(defs[0].Argv, " ") != "pnpm install --frozen-lockfile" {
		t.Fatalf("baseline must use the frozen recipe: %v", defs[0].Argv)
	}
	if res.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("phase = %s", res.Phase)
	}
}

// ---- failure + resume ---------------------------------------------------------------

func TestLiveRestoreRecipeFailureLandsFailedAndRerunResumes(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	runner := &lrRunner{fn: func(def actions.Definition, wsRoot string) (actions.Result, error) {
		return actions.Result{ExitCode: 3, OutputExcerpt: "--- stderr ---\nEPERM"}, nil
	}}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var failed *ErrLiveRestoreFailed
	if !errors.As(err, &failed) || failed.OperationID != res.OperationID {
		t.Fatalf("expected ErrLiveRestoreFailed, got %v", err)
	}
	op, gerr := f.cat.GetOperation(res.OperationID)
	if gerr != nil || op.Phase != catalog.PhaseRestoreFailed || op.LastError == "" {
		t.Fatalf("op row = %+v err=%v — must sit at RESTORE_FAILED with the failure recorded", op, gerr)
	}

	// The failed outputs exist but the FAILED op makes the rerun a resume
	// (no ErrAlreadyRestored), and the rerun supersedes the dead row.
	mustMkdir(t, filepath.Join(f.wsRoot, "node_modules"))
	writeFile(t, filepath.Join(f.wsRoot, "node_modules", "partial.txt"), []byte("partial"))
	runnerOK := &lrRunner{}
	res2, err := f.newLiveRestorer(runnerOK).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err != nil {
		t.Fatalf("rerun after failure must resume: %v", err)
	}
	if res2.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("rerun phase = %s", res2.Phase)
	}
	prev, gerr := f.cat.GetOperation(res.OperationID)
	if gerr != nil || prev.Phase != catalog.PhaseCanceled {
		t.Fatalf("superseded op phase = %s (want CANCELED): %+v", prev.Phase, prev)
	}
}

func TestLiveRestoreProtectedGateCatchesRecipeDamage(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	runner := &lrRunner{fn: func(def actions.Definition, wsRoot string) (actions.Result, error) {
		// A hostile recipe that edits a protected file AND removes one.
		writeFile(t, filepath.Join(wsRoot, ".env"), []byte("SECRET=pwned\n"))
		_ = os.Remove(filepath.Join(wsRoot, "src", "app.js"))
		for _, out := range def.Outputs {
			_ = os.MkdirAll(filepath.Join(wsRoot, filepath.FromSlash(out)), 0o755)
		}
		return actions.Result{ExitCode: 0}, nil
	}}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var failed *ErrLiveRestoreFailed
	if !errors.As(err, &failed) {
		t.Fatalf("expected ErrLiveRestoreFailed, got %v", err)
	}
	var prot *ErrProtectedChanged
	if !errors.As(err, &prot) {
		t.Fatalf("the cause must be the protected gate: %v", err)
	}
	joined := strings.Join(prot.Changes, " | ")
	if !strings.Contains(joined, ".env") || !strings.Contains(joined, "src/app.js") {
		t.Fatalf("gate must name the damaged paths: %v", prot.Changes)
	}
	// Never undone: the modified file keeps the recipe's bytes.
	if b, _ := os.ReadFile(filepath.Join(f.wsRoot, ".env")); string(b) != "SECRET=pwned\n" {
		t.Fatalf("a caught change must never be rolled back: %q", b)
	}
	op, _ := f.cat.GetOperation(res.OperationID)
	if op.Phase != catalog.PhaseRestoreFailed {
		t.Fatalf("op phase = %s, want RESTORE_FAILED", op.Phase)
	}
}

// ---- overlays -------------------------------------------------------------------------

func TestLiveRestoreAppliesOverlaysAfterRecipes(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		overlayFiles: map[string]string{"node_modules/left-pad/index.js": "// patched\n"},
		recordedGit:  recGit, liveGit: liveGit,
	})
	// The recipe "downloads" the standard file; the overlay must win.
	runner := &lrRunner{fn: func(def actions.Definition, wsRoot string) (actions.Result, error) {
		for _, out := range def.Outputs {
			p := filepath.Join(wsRoot, filepath.FromSlash(out))
			if err := os.MkdirAll(p, 0o755); err != nil {
				return actions.Result{ExitCode: -1}, err
			}
		}
		writeFile(t, filepath.Join(wsRoot, "node_modules", "left-pad", "index.js"), []byte("// standard\n"))
		return actions.Result{ExitCode: 0}, nil
	}}
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err != nil {
		t.Fatalf("overlay restore failed: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(f.wsRoot, "node_modules", "left-pad", "index.js")); string(b) != "// patched\n" {
		t.Fatalf("overlay not applied on top of the downloaded file: %q", b)
	}
	if len(res.OverlaysApplied) != 1 || res.OverlaysApplied[0] != "node_modules/left-pad/index.js" {
		t.Fatalf("applied overlays = %v", res.OverlaysApplied)
	}
}

func TestLiveRestoreOverlayDigestMismatchRefused(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		overlayFiles: map[string]string{"node_modules/left-pad/index.js": "// patched\n"},
		recordedGit:  recGit, liveGit: liveGit,
	})
	f.store.dumpTamper["/"+f.opDir+"/overlay/"+lrGroupName+"/node_modules/left-pad/index.js"] =
		func(b []byte) []byte { return []byte("// tampered\n") }
	_, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var failed *ErrLiveRestoreFailed
	if !errors.As(err, &failed) || !strings.Contains(err.Error(), "tampering suspected") {
		t.Fatalf("expected digest-mismatch failure, got %v", err)
	}
}

func TestLiveRestoreOverlayOutsideOutputsRefused(t *testing.T) {
	recGit, liveGit := noDriftGit()
	// Hand-build a plan whose overlay patch sits outside the group's
	// outputs: the path itself is portable, so only the confinement check
	// can catch it (defense in depth behind the parse-time gate).
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	writeFile(t, filepath.Join(f.parent, f.opDir, "overlay", lrGroupName, "outside.txt"), []byte("x"))
	f.reloadPlan(t, f.planWithOverlays(t, []overlayPatchReader{{
		Path: "outside.txt", Copy: "overlay/" + lrGroupName + "/outside.txt",
		Digest: digestBytes([]byte("x")), Kind: overlayKindFile,
	}}))
	_, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err == nil || !strings.Contains(err.Error(), "does not lie under group") {
		t.Fatalf("expected confinement refusal, got %v", err)
	}
}

func TestLiveRestoreRecreatesOverlayLink(t *testing.T) {
	recGit, liveGit := noDriftGit()
	// The link target must exist as a directory: on an unprivileged
	// Windows host the symlink creation is privilege-blocked and the
	// driver's junction fallback (absolute directory targets only) must
	// carry the recreation; on privileged hosts the true symlink runs.
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	// The target lives OUTSIDE the group's outputs (so the outputs-present
	// gate stays honest) and pre-exists as a directory.
	target := filepath.Join(f.wsRoot, "vendor-lib")
	mustMkdir(t, target)
	writeFile(t, filepath.Join(target, "tool.js"), []byte("tool\n"))
	writeFile(t, filepath.Join(f.parent, f.opDir, "overlay", lrGroupName, filepath.FromSlash("node_modules/.bin/tool-dir")), []byte(target))
	plan := f.planWithOverlays(t, []overlayPatchReader{{
		Path: "node_modules/.bin/tool-dir", Copy: "overlay/" + lrGroupName + "/node_modules/.bin/tool-dir",
		Kind: overlayKindLink,
	}})
	f.reloadPlan(t, plan)

	res, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err != nil {
		t.Fatalf("link overlay restore failed: %v", err)
	}
	p := filepath.Join(f.wsRoot, "node_modules", ".bin", "tool-dir")
	got, lerr := os.Readlink(p)
	if lerr != nil {
		t.Skipf("link recreation unavailable on this host (%v); skipping link assertion", lerr)
	}
	if got != target {
		t.Fatalf("recreated link text = %q, want %q", got, target)
	}
	if len(res.OverlaysApplied) != 1 {
		t.Fatalf("applied = %v", res.OverlaysApplied)
	}
}

// ---- dry run --------------------------------------------------------------------------

func TestLiveRestoreDryRunHasNoEffects(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenPackageJSON: `{"name":"livews","dependencies":{"left-pad":"1.0.0","chalk":"2.0.0"}}`,
		recreateLive:      []string{"pnpm", "install"},
		overlayFiles:      map[string]string{"node_modules/left-pad/index.js": "// patched\n"},
		recordedGit:       recGit, liveGit: liveGit,
	})
	runner := &lrRunner{}
	before := walkTree(t, f.wsRoot)
	res, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}
	if len(runner.definitions()) != 0 {
		t.Fatalf("dry run must not execute recipes")
	}
	if !treesEqual(t, before, walkTree(t, f.wsRoot)) {
		t.Fatalf("dry run mutated the workspace")
	}
	ops, _ := f.cat.ListOperations(f.wsID)
	for _, op := range ops {
		if op.Kind == catalog.OpKindRestore {
			t.Fatalf("dry run created a restore operation row: %+v", op)
		}
	}
	// The preview reports the drift, the commands and the overlays. With
	// no strategy chosen the drifted group shows the frozen command (the
	// strategy warning says a choice is required).
	if len(res.Drift) != 1 || len(res.Groups) != 1 {
		t.Fatalf("preview incomplete: %+v", res)
	}
	if strings.Join(res.Groups[0].Command, " ") != "pnpm install --frozen-lockfile" {
		t.Fatalf("strategy-less preview must show the frozen command: %v", res.Groups[0].Command)
	}
	if len(res.Groups[0].Overlays) != 1 {
		t.Fatalf("overlay list missing from the preview: %+v", res.Groups[0])
	}
	// A drifted dry run without a strategy reports the requirement as a
	// warning rather than refusing.
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "needs --strategy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("strategy requirement not reported: %v", res.Warnings)
	}
	// With a strategy the preview shows the strategy-relevant command.
	res2, err := f.newLiveRestorer(runner).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{DryRun: true, Strategy: StrategyMerge})
	if err != nil {
		t.Fatalf("dry run with strategy failed: %v", err)
	}
	if strings.Join(res2.Groups[0].Command, " ") != "pnpm install" {
		t.Fatalf("strategy preview must show the live command: %v", res2.Groups[0].Command)
	}
}

// treesEqual compares two walkTree snapshots (path→fact maps).
func treesEqual(t *testing.T, a, b map[string]string) bool {
	t.Helper()
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
