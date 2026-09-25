package restore

// trimfixture_test.go builds a sealed trim record for the live-restore
// tests: a live workspace root, a frozen op dir carrying manifest.json,
// removal-manifest.json and the recipe-input/overlay copies, a payload
// snapshot in the fake store, and REAL catalog rows (workspace, trim
// snapshot with seal-time digests, trim operation walked to TRIM_DONE).
// The documents are minted BY HAND with correct digests — the fixtures
// depend only on the frozen formats, never on lifecycle's writers
// (the same discipline as fixture_test.go).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/actions/approvalstore"
	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/platform"
)

// trimFixtureSpec knobs for the case each test needs.
type trimFixtureSpec struct {
	// frozenPackageJSON overrides the frozen copy of package.json
	// (defaults to the live bytes: no drift).
	frozenPackageJSON string
	// extraFrozenInputs maps additional frozen inputs (path → content).
	extraFrozenInputs map[string]string
	// missingInputs are recorded missing at trim time (no frozen copy).
	missingInputs []string
	// recreateLive is the group's recreate_live argv (nil/empty omits
	// the field entirely — the older-manifest shape).
	recreateLive []string
	// secondGroup adds a second removal-plan group ("py-reqs", pip,
	// outputs ["vendor"], inputs ["requirements.txt"]) so multi-group
	// gates (per-group output presence, per-group definitions) can be
	// exercised.
	secondGroup bool
	// frozenDef attaches the wave-5 frozen action `definition` to the
	// FIRST group (the shape a real wave-5 trim freezes) and records the
	// matching trim-time approval for it. Nil = legacy manifest (no
	// definition field — the pre-wave shape most tests exercise).
	frozenDef *actionDefinitionDoc
	// noTrimApproval skips recording the trim-time approval for the
	// frozen definition (approval-missing refusals).
	noTrimApproval bool
	// overlayFiles maps root-relative patch paths → file content.
	overlayFiles map[string]string
	// overlayLinks maps root-relative patch paths → link target text.
	overlayLinks map[string]string
	// hostileOverlayPath injects a structurally hostile overlay path
	// straight into the removal manifest (parse-time refusal case).
	hostileOverlayPath string
	// hostileOverlayCopy injects a hostile frozen-copy path.
	hostileOverlayCopy string
	// planSchemaVersion overrides removal-manifest schema_version.
	planSchemaVersion int
	// unknownPlanField injects an unknown field into the removal
	// manifest JSON (strict-reader negative).
	unknownPlanField bool
	// recordedGit / liveGit drive the Git gate.
	recordedGit domain.GitObservation
	liveGit     domain.GitObservation
}

// trimFixture is one assembled world.
type trimFixture struct {
	t         *testing.T
	parent    string
	wsRoot    string
	opDir     string
	wsID      domain.WorkspaceID
	trimOpID  domain.OperationID
	snapID    domain.SnapshotID
	payloadID string

	manifestBytes  []byte
	manifestDigest string
	planBytes      []byte
	planDigest     string

	livePackageJSON []byte

	cat   *catalog.Catalog
	store *fakeStore
	vault VaultRef
	probe domain.PlatformProbe

	// liveGit is served by the ObserveGit seam.
	liveGit domain.GitObservation
	// prompt is the injected Prompter (nil = non-interactive).
	prompt Prompter

	// approver is the REAL approvalstore document backing the driver's
	// approval pre-pass (wave-5 D4); the trim-time approval for a frozen
	// definition is recorded into it at build time.
	approver *approvalstore.FileApprover
	// resolver is the injected ApprovalResolver. The default records
	// every pending approval exactly as resolved (simulating user
	// consent, like --legacy-approve / an interactive yes); tests
	// override it (nil = non-interactive, or a fail-loud sentinel).
	resolver ApprovalResolver
	// toolPath is the fake recipe binary the fixture put on PATH
	// (rewriting its bytes simulates tool drift for the approval gate).
	toolPath string
}

const (
	lrGroupName    = "node-dependencies"
	lrGroupAdapter = "pnpm"
	lrPass         = "lr-pass"
)

// buildTrimFixture assembles the world for one test.
func buildTrimFixture(t *testing.T, spec trimFixtureSpec) *trimFixture {
	t.Helper()
	ctx := context.Background()
	f := &trimFixture{
		t:        t,
		parent:   t.TempDir(),
		wsID:     domain.WorkspaceID(domain.NewID()),
		trimOpID: domain.OperationID(domain.NewID()),
		snapID:   domain.SnapshotID(domain.NewID()),
		probe:    platform.New(),
		liveGit:  spec.liveGit,
	}
	f.wsRoot = filepath.Join(f.parent, "livews")

	// The recipe binary: a REAL resolvable+hashable executable on PATH
	// so the driver's approval pre-pass pins a genuine tool identity
	// (the fake runner never execs it). Rewriting its bytes after the
	// fixture is built simulates tool drift (approval-stale refusals).
	f.toolPath = fakeToolOnPath(t, lrGroupAdapter)

	// The approval store + the default permissive resolver (records
	// every pending approval exactly as resolved — simulated consent).
	f.approver = approvalstore.New(filepath.Join(f.parent, "approvals.json"))
	f.resolver = func(ctx context.Context, pending []PendingApproval) error {
		for _, p := range pending {
			if _, err := f.approver.Approve(p.Def, p.Tool, p.InputDigests, "fixture-consent"); err != nil {
				return err
			}
		}
		return nil
	}

	// ---- catalog: workspace + trim operation row (the op id names the
	// op dir, so it must exist before the frozen documents are minted).
	f.cat = openCatalog(t, filepath.Join(f.parent, "catalog.db"))
	if err := f.cat.UpsertWorkspace(catalog.Workspace{
		ID: f.wsID, Name: "livews", RootPath: f.wsRoot, Status: catalog.WorkspaceLive,
	}); err != nil {
		t.Fatalf("fixture workspace row: %v", err)
	}
	trimOpID, err := f.cat.BeginOperation(f.wsID, catalog.OpKindTrim, f.wsRoot, "", "")
	if err != nil {
		t.Fatalf("fixture trim op: %v", err)
	}
	f.trimOpID = trimOpID
	f.opDir = opPrefix + string(f.trimOpID)

	// ---- the live workspace -------------------------------------------
	f.livePackageJSON = []byte(`{
  "name": "livews",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "left-pad": "1.0.0"
  },
  "devDependencies": {
    "typescript": "5.0.0"
  }
}
`)
	mustMkdir(t, f.wsRoot)
	writeFile(t, filepath.Join(f.wsRoot, "package.json"), f.livePackageJSON)
	writeFile(t, filepath.Join(f.wsRoot, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"))
	writeFile(t, filepath.Join(f.wsRoot, ".env"), []byte("SECRET=live\n"))
	writeFile(t, filepath.Join(f.wsRoot, "src", "app.js"), []byte("console.log('app')\n"))
	for _, p := range spec.missingInputs {
		// Recorded-missing inputs stay absent from the live root unless a
		// test writes them afterwards.
		_ = p
	}

	// ---- the frozen op dir --------------------------------------------
	opPath := filepath.Join(f.parent, f.opDir)
	mustMkdir(t, opPath)

	frozenPkg := f.livePackageJSON
	if spec.frozenPackageJSON != "" {
		frozenPkg = []byte(spec.frozenPackageJSON)
	}
	inputs := []recipeInputReader{
		{Path: "package.json", Copy: "inputs/" + lrGroupName + "/package.json", Digest: digestBytes(frozenPkg)},
		{Path: "pnpm-lock.yaml", Copy: "inputs/" + lrGroupName + "/pnpm-lock.yaml", Digest: digestBytes([]byte("lockfileVersion: '9.0'\n"))},
	}
	writeFile(t, filepath.Join(opPath, "inputs", lrGroupName, "package.json"), frozenPkg)
	writeFile(t, filepath.Join(opPath, "inputs", lrGroupName, "pnpm-lock.yaml"), []byte("lockfileVersion: '9.0'\n"))
	for path, content := range spec.extraFrozenInputs {
		b := []byte(content)
		writeFile(t, filepath.Join(opPath, "inputs", lrGroupName, filepath.FromSlash(path)), b)
		inputs = append(inputs, recipeInputReader{Path: path,
			Copy: "inputs/" + lrGroupName + "/" + path, Digest: digestBytes(b)})
	}
	for _, path := range spec.missingInputs {
		inputs = append(inputs, recipeInputReader{Path: path, Missing: true})
	}

	var patches []overlayPatchReader
	for path, content := range spec.overlayFiles {
		b := []byte(content)
		writeFile(t, filepath.Join(opPath, "overlay", lrGroupName, filepath.FromSlash(path)), b)
		patches = append(patches, overlayPatchReader{Path: path,
			Copy: "overlay/" + lrGroupName + "/" + path, Digest: digestBytes(b), Kind: overlayKindFile})
	}
	for path, target := range spec.overlayLinks {
		writeFile(t, filepath.Join(opPath, "overlay", lrGroupName, filepath.FromSlash(path)), []byte(target))
		patches = append(patches, overlayPatchReader{Path: path,
			Copy: "overlay/" + lrGroupName + "/" + path, Kind: overlayKindLink})
	}
	if spec.hostileOverlayPath != "" || spec.hostileOverlayCopy != "" {
		p := overlayPatchReader{Path: spec.hostileOverlayPath, Copy: spec.hostileOverlayCopy,
			Digest: digestBytes([]byte("x")), Kind: overlayKindFile}
		patches = append(patches, p)
	}
	sortOverlayPatches(patches)

	members := []trimMemberReader{
		{Entry: domain.Entry{Root: domain.RootMain, Path: "node_modules/left-pad/index.js",
			Kind: domain.KindFile, LogicalSize: 3, Digest: digestBytes([]byte("pad")), Ownership: domain.OwnershipOwned,
			Route: domain.RouteReconstruct}, Group: lrGroupName},
	}

	schemaVersion := schemaVersionCurrent
	if spec.planSchemaVersion != 0 {
		schemaVersion = spec.planSchemaVersion
	}
	groups := []removalGroupReader{{
		GroupID: lrGroupName, Adapter: lrGroupAdapter, Root: ".",
		Outputs:        []string{"node_modules"},
		ReclaimCommand: []string{"pnpm", "install", "--frozen-lockfile"},
		RecipeInputs:   inputs,
		Members:        members,
	}}
	if spec.secondGroup {
		reqs := []byte("left-pad==1.0.0\n")
		writeFile(t, filepath.Join(opPath, "inputs", "py-reqs", "requirements.txt"), reqs)
		writeFile(t, filepath.Join(f.wsRoot, "requirements.txt"), reqs)
		groups = append(groups, removalGroupReader{
			GroupID: "py-reqs", Adapter: "pip", Root: ".",
			Outputs:        []string{"vendor"},
			ReclaimCommand: []string{"python", "-m", "pip", "install", "-r", "requirements.txt"},
			RecipeInputs: []recipeInputReader{{
				Path: "requirements.txt", Copy: "inputs/py-reqs/requirements.txt",
				Digest: digestBytes(reqs),
			}},
			Members: []trimMemberReader{{
				Entry: domain.Entry{Root: domain.RootMain, Path: "vendor/lib.js",
					Kind: domain.KindFile, LogicalSize: 4, Digest: digestBytes([]byte("lib!")),
					Ownership: domain.OwnershipOwned, Route: domain.RouteReconstruct},
				Group: "py-reqs",
			}},
		})
	}
	plan := trimPlanDocReader{
		SchemaVersion: schemaVersion,
		OperationID:   string(f.trimOpID),
		SnapshotID:    string(f.snapID),
		Groups:        groups,
	}
	if len(spec.recreateLive) > 0 {
		plan.Groups[0].RecreateLive = spec.recreateLive
	}
	if spec.frozenDef != nil {
		plan.Groups[0].Definition = spec.frozenDef
	}
	if patches != nil {
		plan.Groups[0].OverlayPatches = patches
	}
	pb, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pb = append(pb, '\n')
	if spec.unknownPlanField {
		pb = append(pb, []byte("\n{\"inject\": true}\n")...)
	}
	f.planBytes, f.planDigest = pb, digestBytes(pb)
	writeFile(t, filepath.Join(opPath, removalManifestName), f.planBytes)

	manifest := manifestDoc{
		SchemaVersion: schemaVersionCurrent,
		SnapshotID:    string(f.snapID),
		WorkspaceID:   string(f.wsID),
		CreatedAt:     domain.FormatTime(time.Now()),
		Producer:      "trim-fixture",
		Contract: contractDoc{
			Scope: trimScope, Consistency: "best-effort-live", Fidelity: []string{"file-bytes"},
			Network: "approved-actions", TargetCompatibility: "native-v1",
		},
		Roots: []manifestRoot{
			{ID: string(domain.RootMain), Ownership: "owned", SourcePath: f.wsRoot, BackendPrefix: "livews"},
			{ID: string(domain.RootMeta), Ownership: "owned", BackendPrefix: f.opDir},
		},
		Inventory: manifestInventoryRef{
			Path: removalManifestName, Digest: f.planDigest,
			Count: int64(len(members)), Bytes: int64(len(f.planBytes)),
		},
		Policy:           manifestPolicy{Frozen: "# frozen\n", FrozenDigest: digestBytes([]byte("# frozen\n"))},
		GitObservations:  spec.recordedGit,
		Capabilities:     manifestCapabilities{Captured: []string{"file-bytes"}},
		RequiredFeatures: []string{},
	}
	mb, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.manifestBytes, f.manifestDigest = append(mb, '\n'), digestBytes(append(mb, '\n'))
	writeFile(t, filepath.Join(opPath, manifestName), f.manifestBytes)
	writeFile(t, filepath.Join(opPath, "policy.toml"), []byte("# frozen\n"))

	// ---- payload snapshot (exactly the op dir: §17.3/§11.4) ------------
	f.store = newFakeStore()
	f.vault = VaultRef{RepoDir: filepath.Join(f.parent, "repo"), Passfile: filepath.Join(f.parent, "pass")}
	writeFile(t, f.vault.Passfile, []byte(lrPass))
	payload, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent, []string{f.opDir}, f.vault.Passfile,
		map[string]string{"ebb-kind": "payload"})
	if err != nil {
		t.Fatalf("fixture payload snapshot: %v", err)
	}
	f.payloadID = payload.BackendID

	// ---- catalog rows ----------------------------------------------------
	if _, err := f.cat.RecordSnapshot(catalog.Snapshot{
		ID: f.snapID, WorkspaceID: f.wsID,
		PayloadBackendID: f.payloadID, SealBackendID: "seal-" + f.payloadID[:8],
		ManifestDigest: f.manifestDigest, InventoryDigest: f.planDigest,
		Kind: catalog.SnapshotKindTrim,
	}); err != nil {
		t.Fatalf("fixture snapshot row: %v", err)
	}
	for _, step := range [][2]string{
		{catalog.PhasePlanned, catalog.PhaseTrimPlanned},
		{catalog.PhaseTrimPlanned, catalog.PhaseTrimSealing},
		{catalog.PhaseTrimSealing, catalog.PhaseTrimDone},
	} {
		if err := f.cat.AdvanceOperation(f.trimOpID, step[0], step[1]); err != nil {
			t.Fatalf("fixture trim walk %s: %v", step[1], err)
		}
	}
	if err := f.cat.SetBackendRefs(f.trimOpID, f.payloadID, ""); err != nil {
		t.Fatalf("fixture backend refs: %v", err)
	}

	// ---- trim-time approval for the frozen definition (wave-5 D3
	// simulated): the exact frozen contract, the resolved tool identity
	// and the digests of the present declared inputs.
	if spec.frozenDef != nil && !spec.noTrimApproval {
		def, derr := defrostDefinition(spec.frozenDef)
		if derr != nil {
			t.Fatalf("fixture frozen definition invalid: %v", derr)
		}
		tool, terr := actions.ResolveTool(def.Argv[0])
		if terr != nil {
			t.Fatalf("fixture tool resolution: %v", terr)
		}
		digests := make(map[string]string, len(def.Inputs))
		for _, rel := range def.Inputs {
			d, derr := actions.DigestFile(filepath.Join(f.wsRoot, filepath.FromSlash(rel)))
			if derr != nil {
				t.Fatalf("fixture approval input %s: %v", rel, derr)
			}
			digests[rel] = d
		}
		if _, aerr := f.approver.Approve(def, tool, digests, "fixture:trim-approval"); aerr != nil {
			t.Fatalf("fixture trim approval: %v", aerr)
		}
	}
	return f
}

// fakeToolOnPath writes a resolvable+hashable fake executable named
// name into a fresh PATH-front directory (pnpm.bat on Windows —
// LookPath resolves it through PATHEXT — a +x script elsewhere). The
// fake runner never execs it; the driver's approval pre-pass only
// resolves and hashes it, exactly as it would a real toolchain.
func fakeToolOnPath(t *testing.T, name string) string {
	t.Helper()
	bin := t.TempDir()
	full := name
	if runtime.GOOS == "windows" {
		full = name + ".bat"
	}
	p := filepath.Join(bin, full)
	writeFile(t, p, []byte("@echo off\r\nrem fixture tool\r\n"))
	if runtime.GOOS != "windows" {
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return p
}

func sortOverlayPatches(p []overlayPatchReader) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Path < p[j-1].Path; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

// newLiveRestorer wires the driver over the fixture: the REAL approval
// store built by the fixture plus its resolver (permissive by default;
// tests override). runner may be nil for dry runs.
func (f *trimFixture) newLiveRestorer(runner ActionRunner) *LiveRestorer {
	f.t.Helper()
	o, err := NewLiveRestorer(LiveDependencies{
		Store: f.store, Cat: f.cat, Probe: f.probe, CreateLink: platform.CreateLink,
		Runner:   runner,
		Approver: f.approver,
		Approve:  f.resolver,
		ObserveGit: func(ctx context.Context, root string) (domain.GitObservation, error) {
			return f.liveGit, nil
		},
		Prompt: f.prompt,
		Clock:  func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		f.t.Fatalf("NewLiveRestorer: %v", err)
	}
	return o
}

// lrRunner is the scripted fake runner: it records definitions and by
// default materializes every declared output.
type lrRunner struct {
	mu    sync.Mutex
	calls []actions.Definition
	fn    func(def actions.Definition, wsRoot string) (actions.Result, error)
}

func (r *lrRunner) Run(ctx context.Context, def actions.Definition, wsRoot string, appr actions.Approver, capture actions.OutputSink) (actions.Result, error) {
	r.mu.Lock()
	r.calls = append(r.calls, def)
	fn := r.fn
	r.mu.Unlock()
	if fn != nil {
		return fn(def, wsRoot)
	}
	for _, out := range def.Outputs {
		p := filepath.Join(wsRoot, filepath.FromSlash(out))
		if err := os.MkdirAll(p, 0o755); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
		if err := os.WriteFile(filepath.Join(p, "built.txt"), []byte("rebuilt\n"), 0o644); err != nil {
			return actions.Result{ExitCode: -1}, err
		}
	}
	return actions.Result{ExitCode: 0}, nil
}

func (r *lrRunner) definitions() []actions.Definition {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]actions.Definition(nil), r.calls...)
}

// lrPrompt is a scriptable Prompter.
type lrPrompt struct {
	branch       BranchChoice
	branchFn     func(m BranchMismatch) (BranchChoice, error)
	strategy     Strategy
	stratFn      func(drift []DriftEntry) (Strategy, error)
	seenDrift    []DriftEntry
	seenMismatch *BranchMismatch
}

func (p *lrPrompt) ChooseBranch(ctx context.Context, m BranchMismatch) (BranchChoice, error) {
	p.seenMismatch = &m
	if p.branchFn != nil {
		return p.branchFn(m)
	}
	return p.branch, nil
}

func (p *lrPrompt) ChooseStrategy(ctx context.Context, drift []DriftEntry) (Strategy, error) {
	p.seenDrift = append([]DriftEntry(nil), drift...)
	if p.stratFn != nil {
		return p.stratFn(drift)
	}
	return p.strategy, nil
}

// noDriftGit returns a recorded/live observation pair in parity on a
// feature branch.
func noDriftGit() (recorded, live domain.GitObservation) {
	recorded = domain.GitObservation{IsRepo: true, HeadBranch: "feature-x", HeadCommit: "aaaa0000bbbb1111cccc2222dddd3333eeee4444"}
	live = recorded
	return
}
