package restore

// pocs_wave1restore_test.go — proof-of-compromise regressions for the
// Wave 1 adversarial review of `ebb restore` (findings F1, F2, F4, F5
// and the F3 driver half):
//
//   - F1: the native resolver behind a merge/current recreate_live
//     command legitimately rewrites lockfile inputs; the protected-file
//     gate exempts (and warns) instead of false-failing, while baseline
//     stays strict on the same runner behavior;
//   - F2: the pyproject array-key union declines to rewrite any section
//     carrying comments, blanks or multi-line string bodies, keeping the
//     live file byte-for-byte (the honest fallback);
//   - F4: `"dependencies": null` unions without a nil-map panic;
//   - F5: manifest-derived write paths that fail the strict portable
//     gate (NTFS ADS colon, `.` segments) are refused per-input with the
//     keep-live fallback and nothing is written;
//   - F3: a headless rerun that returns ErrStrategyRequired still
//     supersedes the workspace's dead restore rows.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/catalog"
)

// ---- F1: native lockfile rewrite under merge/current ----------------------

// lockfileRewritingRunner materializes the outputs like the default fake
// and additionally rewrites the workspace lockfile — what a plain
// `pnpm install` does once the unioned package.json no longer matches
// the recorded lockfile.
func lockfileRewritingRunner() *lrRunner {
	return &lrRunner{fn: func(def actions.Definition, wsRoot string) (actions.Result, error) {
		for _, out := range def.Outputs {
			p := filepath.Join(wsRoot, filepath.FromSlash(out))
			if err := os.MkdirAll(p, 0o755); err != nil {
				return actions.Result{ExitCode: -1}, err
			}
			if err := os.WriteFile(filepath.Join(p, "built.txt"), []byte("rebuilt\n"), 0o644); err != nil {
				return actions.Result{ExitCode: -1}, err
			}
		}
		if err := os.WriteFile(filepath.Join(wsRoot, "pnpm-lock.yaml"),
			[]byte("lockfileVersion: '9.0'\n\nregenerated: true\n"), 0o644); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
		return actions.Result{ExitCode: 0}, nil
	}}
}

// TestLiveRestoreMergeExemptsNativeLockfileRewrite pins F1's live-variant
// semantics: the group drifted (package.json), runs its recreate_live
// argv, and the lockfile — which NEVER drifted — is rewritten by the
// native resolver. The restore must succeed with an explicit warning,
// not fail the protected-file gate.
func TestLiveRestoreMergeExemptsNativeLockfileRewrite(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		// package.json drifts (the union trigger); pnpm-lock.yaml does NOT.
		frozenPackageJSON: `{"name":"livews","dependencies":{"left-pad":"1.0.0","chalk":"2.0.0"}}`,
		recreateLive:      []string{"pnpm", "install"},
		recordedGit:       recGit, liveGit: liveGit,
	})
	res, err := f.newLiveRestorer(lockfileRewritingRunner()).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyMerge})
	if err != nil {
		t.Fatalf("merge restore must tolerate the native lockfile rewrite: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("phase = %s, want RESTORE_DONE", res.Phase)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "input pnpm-lock.yaml rewritten by the native resolver (expected under merge/current)") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("the lockfile rewrite must be reported as a warning: %v", res.Warnings)
	}
	if b, _ := os.ReadFile(filepath.Join(f.wsRoot, "pnpm-lock.yaml")); !strings.Contains(string(b), "regenerated: true") {
		t.Fatalf("the resolver's lockfile bytes must survive (never rolled back): %q", b)
	}
}

// TestLiveRestoreBaselineStaysStrictOnLockfileRewrite pins the OTHER half
// of F1's asymmetry: the same runner behavior under the baseline
// strategy (frozen `pnpm install --frozen-lockfile`) FAILS the
// protected-file gate — frozen commands must not touch their inputs.
func TestLiveRestoreBaselineStaysStrictOnLockfileRewrite(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenPackageJSON: `{"name":"livews","dependencies":{"left-pad":"1.0.0","chalk":"2.0.0"}}`,
		recreateLive:      []string{"pnpm", "install"},
		recordedGit:       recGit, liveGit: liveGit,
	})
	res, err := f.newLiveRestorer(lockfileRewritingRunner()).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyBaseline})
	var failed *ErrLiveRestoreFailed
	if !errors.As(err, &failed) {
		t.Fatalf("baseline must fail the gate on the same runner behavior, got %v", err)
	}
	var prot *ErrProtectedChanged
	if !errors.As(err, &prot) || !strings.Contains(strings.Join(prot.Changes, " | "), "pnpm-lock.yaml") {
		t.Fatalf("the cause must name the rewritten lockfile: %v", err)
	}
	op, gerr := f.cat.GetOperation(res.OperationID)
	if gerr != nil || op.Phase != catalog.PhaseRestoreFailed {
		t.Fatalf("op = %+v err=%v — baseline strictness must land RESTORE_FAILED", op, gerr)
	}
}

// ---- F2: the array-key union declines sections it cannot re-render -------
//
// A multi-line ARRAY is an entry block and survives; comments, blank
// lines and the bodies of multi-line basic strings are rest lines whose
// deletion would corrupt the document, so any of them declines the
// union (keep-live fallback, byte-for-byte).
func TestUnionPyprojectDeclinesSectionsWithRestLines(t *testing.T) {
	frozen := []byte(`[project]
name = "livews"
dependencies = [
    "requests>=2",
    "httpx>=0.27",
]
`)
	cases := []struct {
		name string
		live string
	}{
		{"comment in [project]", `[project]
# team convention: keep runtime deps minimal
name = "livews"
dependencies = [
    "requests>=2",
]
`},
		{"multi-line basic string body", `[project]
name = "livews"
description = """
A long description
spanning several lines.
"""
dependencies = [
    "requests>=2",
]
`},
		{"blank line inside [project]", `[project]
name = "livews"

dependencies = [
    "requests>=2",
]
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, notes, ok := unionPyprojectTOML([]byte(tc.live), frozen)
			if ok {
				t.Fatalf("union must decline a section carrying rest lines, wrote:\n%s", out)
			}
			joined := strings.Join(notes, "; ")
			if !strings.Contains(joined, "cannot preserve") || !strings.Contains(joined, "merge unavailable") {
				t.Fatalf("decline must explain itself, got: %v", notes)
			}
		})
	}
}

// TestLiveRestoreMergeDeclinedKeepsPyprojectByteForByte pins F2 at the
// driver level: a drifted pyproject.toml whose [project] carries a
// comment declines the union, the live file survives byte-for-byte, the
// fallback is a warning, and the restore still completes.
func TestLiveRestoreMergeDeclinedKeepsPyprojectByteForByte(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		extraFrozenInputs: map[string]string{"pyproject.toml": `[project]
name = "livews"
dependencies = [
    "requests>=2",
    "httpx>=0.27",
]
`},
		recreateLive: []string{"uv", "sync"},
		recordedGit:  recGit, liveGit: liveGit,
	})
	livePyproject := []byte(`[project]
# team convention: keep runtime deps minimal
name = "livews"
dependencies = [
    "requests>=2",
]
`)
	writeFile(t, filepath.Join(f.wsRoot, "pyproject.toml"), livePyproject)

	res, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyMerge})
	if err != nil {
		t.Fatalf("a declined union is a fallback, not a failure: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("phase = %s, want RESTORE_DONE", res.Phase)
	}
	got, rerr := os.ReadFile(filepath.Join(f.wsRoot, "pyproject.toml"))
	if rerr != nil || string(got) != string(livePyproject) {
		t.Fatalf("live pyproject.toml must survive byte-for-byte: err=%v bytes=%q", rerr, got)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "merge unavailable for pyproject.toml") && strings.Contains(w, "cannot preserve") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("fallback not reported: %v", res.Warnings)
	}
	// No backup was made for a file Ebb did not write.
	if matches, _ := filepath.Glob(filepath.Join(f.wsRoot, "pyproject.toml.bak-drift-*")); len(matches) != 0 {
		t.Fatalf("unexpected backups for a declined union: %v", matches)
	}
}

// ---- F4: JSON null dependency sections -------------------------------------

// TestUnionJSONManifestNullSections pins F4: a `"dependencies": null`
// section (either side) unions without panicking on a nil map; recorded
// keys are added into the normalized empty map.
func TestUnionJSONManifestNullSections(t *testing.T) {
	live := []byte(`{"name":"app","dependencies":null,"devDependencies":{"typescript":"5.0.0"}}`)
	frozen := []byte(`{"name":"app-old","dependencies":{"chalk":"2.0.0"}}`)
	out, _, ok := unionJSONManifest(live, frozen)
	if !ok {
		t.Fatal("union must not refuse a null section")
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unioned document does not parse: %v\n%s", err, out)
	}
	deps, isMap := doc["dependencies"].(map[string]any)
	if !isMap || deps["chalk"] != "2.0.0" {
		t.Fatalf("recorded deps not added into the null section: %v", doc["dependencies"])
	}
	if doc["devDependencies"].(map[string]any)["typescript"] != "5.0.0" {
		t.Fatalf("live sections must pass through: %v", doc)
	}
	// Recorded null on the other side: also no panic.
	out2, _, ok2 := unionJSONManifest(live, []byte(`{"name":"x","dependencies":null}`))
	if !ok2 {
		t.Fatal("recorded null section must not refuse the union")
	}
	if !strings.Contains(string(out2), `"typescript": "5.0.0"`) {
		t.Fatalf("live content lost with a recorded null: %s", out2)
	}
}

// ---- F5: non-portable manifest-derived write paths --------------------------

// planWithExtraInputs returns a copy of the fixture plan whose single
// group carries additional hand-built recipe inputs (hostile PATHS with
// SAFE frozen-copy names, the exact shape a doctored manifest would
// need to reach the write path).
func (f *trimFixture) planWithExtraInputs(t *testing.T, extra []recipeInputReader) trimPlanDocReader {
	t.Helper()
	g := f.planGroups(t)[0]
	g.RecipeInputs = append(append([]recipeInputReader{}, g.RecipeInputs...), extra...)
	return trimPlanDocReader{
		SchemaVersion: schemaVersionCurrent, OperationID: string(f.trimOpID), SnapshotID: string(f.snapID),
		Groups: []removalGroupReader{g},
	}
}

// hostileInputFixture installs one hostile input record whose frozen
// copy lives under a SAFE op-dir name (so readTrimDocs accepts it) while
// the live path is non-portable.
func hostileInputFixture(t *testing.T, f *trimFixture, path, copyName, content string) {
	t.Helper()
	b := []byte(content)
	writeFile(t, filepath.Join(f.parent, f.opDir, "inputs", lrGroupName, copyName), b)
	f.reloadPlan(t, f.planWithExtraInputs(t, []recipeInputReader{{
		Path: path, Copy: "inputs/" + lrGroupName + "/" + copyName, Digest: digestBytes(b),
	}}))
}

// TestLiveRestoreRefusesColonInputPath pins F5's ADS channel: a colon at
// position >1 passes the read-time path contract but must be refused at
// write time (baseline attempted to write the frozen bytes back), with
// the keep-live fallback warning and NOTHING written.
func TestLiveRestoreRefusesColonInputPath(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	hostileInputFixture(t, f, "evil:name.json", "safe-colon-copy.json", "{\"deps\":{}}\n")

	res, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyBaseline})
	if err != nil {
		t.Fatalf("refusing a hostile input is a fallback, not a failure: %v", err)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "baseline unavailable for evil:name.json") && strings.Contains(w, "colon") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("refusal not reported: %v", res.Warnings)
	}
	// Nothing written: neither the ADS spelling nor its base file exists
	// (on NTFS the unfixed code would open a stream ON "evil").
	for _, p := range []string{"evil:name.json", "evil"} {
		if _, serr := os.Lstat(filepath.Join(f.wsRoot, p)); serr == nil {
			t.Fatalf("hostile input %s was written despite the strict gate", p)
		}
	}
}

// TestLiveRestoreRefusesDotSegmentInputPath pins F5's `.`-segment gap
// under merge: the path is refused, nothing is written, and the restore
// completes on the fallback.
func TestLiveRestoreRefusesDotSegmentInputPath(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	hostileInputFixture(t, f, "dir/./pkg.json", "safe-dot-copy.json", "{}\n")

	res, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot,
		LiveRestoreOptions{Strategy: StrategyMerge})
	if err != nil {
		t.Fatalf("refusing a hostile input is a fallback, not a failure: %v", err)
	}
	if res.Phase != catalog.PhaseRestoreDone {
		t.Fatalf("phase = %s, want RESTORE_DONE", res.Phase)
	}
	warned := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "merge unavailable for dir/./pkg.json") {
			warned = true
		}
	}
	if !warned {
		t.Fatalf("refusal not reported: %v", res.Warnings)
	}
	if _, serr := os.Lstat(filepath.Join(f.wsRoot, "dir")); serr == nil {
		t.Fatal("the '.'-segment input path was written despite the strict gate")
	}
}

// ---- F3 (driver half): headless refusal still supersedes dead rows ----------

// TestLiveRestoreHeadlessRefusalStillSupersedesDeadRow pins F3's driver
// ordering: a headless rerun over drift with no --strategy returns
// ErrStrategyRequired WITHOUT opening an operation — and must STILL
// close the workspace's dead restore rows so later destructive work is
// not blocked.
func TestLiveRestoreHeadlessRefusalStillSupersedesDeadRow(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		frozenPackageJSON: `{"name":"livews","dependencies":{"left-pad":"1.0.0","chalk":"2.0.0"}}`,
		recordedGit:       recGit, liveGit: liveGit,
	})
	// A dead restore row exactly as a crash or a failed execution leaves it.
	deadOp, err := f.cat.BeginOperation(f.wsID, catalog.OpKindRestore, f.wsRoot, "", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]string{
		{catalog.PhasePlanned, catalog.PhaseRestorePlanning},
		{catalog.PhaseRestorePlanning, catalog.PhaseRestoreRunning},
		{catalog.PhaseRestoreRunning, catalog.PhaseRestoreFailed},
	} {
		if err := f.cat.AdvanceOperation(deadOp, step[0], step[1]); err != nil {
			t.Fatal(err)
		}
	}

	_, err = f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var req *ErrStrategyRequired
	if !errors.As(err, &req) {
		t.Fatalf("expected ErrStrategyRequired, got %v", err)
	}
	prev, gerr := f.cat.GetOperation(deadOp)
	if gerr != nil || prev.Phase != catalog.PhaseCanceled {
		t.Fatalf("dead row must be superseded despite the refusal: phase=%s err=%v", prev.Phase, gerr)
	}
	active, aerr := f.cat.ActiveOperations(f.wsID)
	if aerr != nil || len(active) != 0 {
		t.Fatalf("workspace must carry no active operations after the supersede: %v (%v)", active, aerr)
	}
}

// ---- F7/F9 reader side: witnessed link sidecars + permission bits ------

// TestLiveRestoreWitnessedLinkSidecarTamperRefused pins F7's reader side:
// a post-amendment link record (non-empty digest over the .ebb-link
// sidecar's target-text bytes) whose payload sidecar disagrees is vault
// tampering and must refuse exactly like a tampered file overlay.
func TestLiveRestoreWitnessedLinkSidecarTamperRefused(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	writeFile(t, filepath.Join(f.parent, f.opDir, "overlay", lrGroupName, "node_modules", "kept", "link.ebb-link"),
		[]byte("../lib/tool.js"))
	f.reloadPlan(t, f.planWithOverlays(t, []overlayPatchReader{{
		Path: "node_modules/kept/link", Copy: "overlay/" + lrGroupName + "/node_modules/kept/link.ebb-link",
		Digest: digestBytes([]byte("C:/attacker/controlled/target")), Kind: overlayKindLink,
	}}))
	_, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	var failed *ErrLiveRestoreFailed
	if !errors.As(err, &failed) || !strings.Contains(err.Error(), "tampering suspected") {
		t.Fatalf("expected sidecar-digest failure, got %v", err)
	}
	if _, lerr := os.Lstat(filepath.Join(f.wsRoot, "node_modules", "kept", "link")); lerr == nil {
		t.Fatal("tampered link was recreated despite the witness mismatch")
	}
}

// TestLiveRestoreAppliesRecordedOverlayMode pins F9's reader side: the
// captured permission bits come back with the file (exec shims stay
// executable on POSIX); a legacy 0 mode keeps the safe default.
func TestLiveRestoreAppliesRecordedOverlayMode(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{recordedGit: recGit, liveGit: liveGit})
	content := []byte("#!/bin/sh\necho shim\n")
	writeFile(t, filepath.Join(f.parent, f.opDir, "overlay", lrGroupName, "node_modules", "kept", "tool"), content)
	f.reloadPlan(t, f.planWithOverlays(t, []overlayPatchReader{{
		Path: "node_modules/kept/tool", Copy: "overlay/" + lrGroupName + "/node_modules/kept/tool",
		Digest: digestBytes(content), Kind: overlayKindFile, Mode: 0o755,
	}}))
	if _, err := f.newLiveRestorer(&lrRunner{}).LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{}); err != nil {
		t.Fatalf("restore with recorded mode failed: %v", err)
	}
	p := filepath.Join(f.wsRoot, "node_modules", "kept", "tool")
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, rerr := os.ReadFile(p); rerr != nil || !bytes.Equal(b, content) {
		t.Fatalf("overlay content wrong: %v", rerr)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %o, want 755", fi.Mode().Perm())
	}
}
