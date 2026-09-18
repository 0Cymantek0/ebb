package lifecycle

// Capture (Foundation §12.2 steps 1-5) — the NON-destructive half of
// the parking sequence, shared by `ebb snapshot`, `ebb park` and the
// trim capture. Step numbers in comments map to §12.2:
//
//	step 1  resolve identities, locks, policy; destination overlap
//	step 2  stopped-writers condition, discovery, complete inventory
//	step 3  record CAPTURING durably; capture payload P (no removal)
//	step 4  record P's backend id; coverage + full readback
//	step 5  write seal S and read it back; commit SEALED
//
// The seal is the only thing that can ever authorize removal (§11.3),
// and even then only after revalidation (§12.2 step 6).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ebb/internal/actions"
	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/inventory"
	"ebb/internal/policy"
)

// captureState carries one capture's durable facts between steps. It is
// deliberately explicit: every field is evidence a later step (or
// Recover) relies on, so nothing is inferred twice.
type captureState struct {
	opID     domain.OperationID
	wsID     domain.WorkspaceID
	snapID   domain.SnapshotID
	kind     string // operation kind (catalog vocabulary)
	snapKind string // snapshot kind recorded at seal time

	rootAbs   string
	parent    string
	wsPrefix  string // base name of the root: the backend tree prefix (D003)
	rootIdent domain.RootIdentity

	scan     inventory.Result
	resolved policy.Resolved
	entries  []domain.Entry // resolved, canonical order, main root

	opDir     string
	opDirName string
	sealDir   string

	journal *opJournal
	vault   VaultRef
	repoID  string
	opts    CaptureOptions

	// Document bytes/digests (hashed over the exact bytes written).
	manifestBytes   []byte
	manifestDigest  string
	inventoryBytes  []byte
	inventoryDigest string
	frozenPolicy    []byte

	selection selectionPlan
	payload   domain.SnapshotRef
	seal      domain.SnapshotRef

	// trimPlan is non-nil only for trim operations (built by Trim).
	trimPlan []trimGroupPlan

	warnings []string

	// Volume observation for the park tail (§12.2 step 9).
	beforeFree   int64
	beforeVolume string
}

// selectionPlan is the literal restic selection (§11.2): exact paths
// only, never a non-empty directory as shorthand for selected files.
type selectionPlan struct {
	// relPaths are parent-relative forward-slash entries (D003):
	// "<wsPrefix>/..." plus the whole op dir as "<opDirName>".
	relPaths []string
	// expected is the exact expected snapshot tree (coverage, §11.4).
	expected map[string]expectedNode
	// readback is the authoritative preserved-content set (§11.4).
	readback []readbackFile
}

// Snapshot executes the non-destructive capture sequence (§12.2 steps
// 1-5, terminal at DONE): capture, verify, seal — and never remove
// anything. The source tree is byte-identical before and after.
func (c *Coordinator) Snapshot(ctx context.Context, vault VaultRef, root string, opts CaptureOptions) (SnapshotResult, error) {
	// `ebb snapshot` runs the parking sequence's capture half; the
	// journal kind is "park" (the catalog has no "snapshot" operation
	// kind — package doc) while the retained snapshot is kind
	// "snapshot".
	st, err := c.capture(ctx, vault, root, opts, catalog.OpKindPark, catalog.SnapshotKindSnapshot)
	if st != nil {
		defer st.journal.close() // no sequence end may leave the file held open
	}
	if err != nil {
		return SnapshotResult{}, err
	}
	if err := c.advance(st.opID, catalog.PhaseSealed, catalog.PhaseDone, st.journal); err != nil {
		return SnapshotResult{}, err
	}
	st.journal.step("done", "snapshot complete")
	c.cleanupScratch(st)
	return st.result(), nil
}

// capture runs §12.2 steps 1-5 and leaves the operation SEALED (or
// failed/canceled). destructive=true applies the extra preflight
// blockers that only matter when removal will follow.
func (c *Coordinator) capture(ctx context.Context, vault VaultRef, root string, opts CaptureOptions, opKind, snapKind string) (*captureState, error) {
	// ---- §12.2 step 1: identities, locks, policy, overlap ----------
	st, err := c.openCapture(ctx, vault, root, opts, opKind, snapKind)
	if err != nil {
		return nil, err
	}
	fail := func(phase string, err error) (*captureState, error) {
		c.failOperation(st.opID, phase, err.Error())
		st.journal.step("failed", err.Error())
		return st, err
	}

	// ---- §12.2 step 2: discovery + complete inventory ---------------
	if err := c.scanAndResolve(ctx, st, opts.Park); err != nil {
		return fail(catalog.PhasePlanned, err)
	}

	// ---- §12.2 step 3: record CAPTURING; write op dir; capture P ----
	if err := c.advance(st.opID, catalog.PhasePlanned, catalog.PhaseCapturing, st.journal); err != nil {
		return st, err
	}
	if err := c.writeOpDir(st); err != nil {
		return fail(catalog.PhaseCapturing, err)
	}
	if err := c.buildSelection(st); err != nil {
		return fail(catalog.PhaseCapturing, err)
	}
	if err := c.assertD003(st); err != nil {
		return fail(catalog.PhaseCapturing, err)
	}
	P, err := c.store.Snapshot(ctx, vault.RepoDir, st.parent, st.selection.relPaths, vault.Passfile, map[string]string{
		"ebb-op":   string(st.opID),
		"ebb-kind": "payload",
		"ws":       string(st.wsID),
	})
	if err != nil {
		// A source-read failure may have stored an INCOMPLETE snapshot
		// (restic stores it unmarked — probe Q4a). The store's error
		// names it; Ebb never references such an id. The op dir is
		// Ebb-derived scratch (nothing irreplaceable) and is removed.
		c.failOperation(st.opID, catalog.PhaseCapturing, err.Error())
		st.journal.step("payload-failed", err.Error())
		_ = removeEbbOwned(st.opDir)
		return st, fmt.Errorf("lifecycle: payload capture failed: %w", err)
	}
	st.payload = P
	st.journal.step("payload-captured", P.BackendID)
	if err := c.cat.SetBackendRefs(st.opID, P.BackendID, ""); err != nil {
		return fail(catalog.PhaseCapturing, fmt.Errorf("lifecycle: record payload ref: %w", err))
	}

	// ---- §12.2 step 4: coverage + full readback ---------------------
	if err := c.verifyPayload(ctx, st, []string{st.wsPrefix, st.opDirName}); err != nil {
		// §11.3: a payload with no valid seal is an incomplete
		// operation, not garbage to erase. It can still contain useful
		// captured work: P is retained (recorded unsealed + pinned),
		// never forgotten. The local op dir is KEPT as the clean copy
		// of the manifest/inventory while P's own integrity is in
		// doubt.
		c.failOperation(st.opID, catalog.PhaseCapturing, err.Error())
		st.journal.step("verification-failed", err.Error())
		var verr *ErrVerification
		if errors.As(err, &verr) {
			if _, rerr := c.cat.RecordSnapshot(catalog.Snapshot{
				ID: st.snapID, WorkspaceID: st.wsID,
				PayloadBackendID: P.BackendID, VaultID: c.vaultIDFor(st.repoID, vault),
				ManifestDigest: st.manifestDigest, InventoryDigest: st.inventoryDigest,
				Kind: snapKind,
			}); rerr != nil {
				err = fmt.Errorf("%w (additionally recording unsealed payload: %v)", err, rerr)
			}
			if aerr := c.cat.AdvanceOperation(st.opID, catalog.PhaseCapturing, catalog.PhaseCanceled); aerr != nil {
				err = fmt.Errorf("%w (additionally canceling operation: %v)", err, aerr)
			}
			return st, fmt.Errorf("%w; %w", err, errPayloadIncomplete)
		}
		return st, err
	}
	if err := c.advance(st.opID, catalog.PhaseCapturing, catalog.PhasePayloadCommitted, st.journal); err != nil {
		return st, err
	}

	// ---- §12.2 step 5: seal S, read it back, commit SEALED ----------
	if err := c.sealPayload(ctx, st, catalog.PhasePayloadCommitted, catalog.PhaseSealed); err != nil {
		// P is verified but unsealed; the operation stays
		// PAYLOAD_COMMITTED so Recover can resume sealing from evidence.
		c.failOperation(st.opID, catalog.PhasePayloadCommitted, err.Error())
		st.journal.step("seal-failed", err.Error())
		return st, err
	}
	return st, nil
}

// openCapture performs step 1: validation, identity resolution, vault
// readiness, the workspace lock check and the durable operation begin.
func (c *Coordinator) openCapture(ctx context.Context, vault VaultRef, root string, opts CaptureOptions, opKind, snapKind string) (*captureState, error) {
	if strings.TrimSpace(root) == "" {
		return nil, &ErrInvalidOptions{Detail: "root path is required"}
	}
	// Exact captured action definitions (§16.2): a graph that cannot run
	// (invalid definition, duplicate id, dependency cycle, dangling
	// DependsOn) fails the capture up front — never freeze a manifest
	// whose actions could not execute on open.
	if err := actions.ValidateGraph(opts.ActionDefs); err != nil {
		return nil, &ErrInvalidOptions{Detail: fmt.Sprintf("action definitions: %v", err)}
	}
	if opts.Park && strings.TrimSpace(opts.WriterAssertion) == "" {
		return nil, &ErrInvalidOptions{Detail: "Park requires WriterAssertion (the recorded assert-writers-stopped source, Foundation §17.2)"}
	}
	if opts.WorkspaceName == "" {
		opts.WorkspaceName = filepath.Base(filepath.Clean(mustAbs(root)))
	}
	rootAbs := filepath.Clean(mustAbs(root))
	fi, err := os.Stat(rootAbs)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: root: %w", err)
	}
	if !fi.IsDir() {
		return nil, &ErrInvalidOptions{Detail: fmt.Sprintf("root %s is not a directory", rootAbs)}
	}
	parent := filepath.Dir(rootAbs)
	if parent == rootAbs {
		// D003: a drive root has no parent to anchor cwd-relative
		// capture; refuse rather than reverting to the absolute layout.
		return nil, &ErrDestructiveBlocked{Reasons: []string{
			fmt.Sprintf("root %s is a drive root; cwd-relative capture (D003) requires a parent directory — refuse capture", rootAbs)}}
	}
	if err := preflight(rootAbs, vault); err != nil {
		return nil, err
	}

	// Vault readiness: initialize when new, tolerate "already
	// initialized", surface everything else before anything durable
	// happens on the source side.
	if err := c.store.Init(ctx, vault.RepoDir, vault.Passfile); err != nil {
		var se *domain.StoreError
		if !(errors.As(err, &se) && se.Class == domain.StoreErrRepo && strings.Contains(se.Error(), "already initialized")) {
			return nil, fmt.Errorf("lifecycle: vault init: %w", err)
		}
	}
	repoID, err := c.store.RepoID(ctx, vault.RepoDir, vault.Passfile)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: vault identity: %w", err)
	}

	ident, err := c.probe.RootIdentity(rootAbs)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: root identity: %w", err)
	}
	wsID, opID, err := c.beginOperation(ctx, rootAbs, ident, opts, opKind)
	if err != nil {
		return nil, err
	}
	j, jerr := openJournal(parent, opID)
	if jerr != nil {
		// The catalog phase transitions remain the durable authority;
		// proceeding without the progress journal is acceptable.
		j = nil
	}
	j.step("begin", string(opKind))

	st := &captureState{
		opID: opID, wsID: wsID, snapID: domain.SnapshotID(domain.NewID()),
		kind: opKind, snapKind: snapKind,
		rootAbs: rootAbs, parent: parent, wsPrefix: filepath.Base(rootAbs),
		rootIdent: ident, journal: j, vault: vault, repoID: repoID, opts: opts,
		opDir:     filepath.Join(parent, opDirName(opID)),
		opDirName: opDirName(opID),
		sealDir:   filepath.Join(parent, sealDirName(opID)),
	}
	if usage, uerr := c.probe.VolumeUsage(rootAbs); uerr == nil {
		st.beforeFree, st.beforeVolume = usage.FreeToCaller, usage.VolumeID
	}
	if err := c.cat.RegisterVault(catalog.Vault{ID: c.vaultIDFor(repoID, vault), Path: vault.RepoDir, RepoID: repoID}); err != nil {
		return nil, fmt.Errorf("lifecycle: register vault: %w", err)
	}
	return st, nil
}

// vaultIDFor derives the stable vault row id for one repository. The
// catalog has no lookup-by-path; a digest-derived id keeps repeated
// captures bound to one vault row without inventing a second registry.
func (c *Coordinator) vaultIDFor(repoID string, vault VaultRef) domain.VaultID {
	return VaultIDFor(repoID, vault.RepoDir)
}

// VaultIDFor is the single exported authority for the catalog vault-row
// id derivation (repoID + cleaned absolute repo dir). `ebb gc` uses it to
// attribute catalog snapshot rows to a registry-resolved vault; keeping
// the derivation here means gc and capture can never disagree about
// which vault a row belongs to.
func VaultIDFor(repoID, repoDir string) domain.VaultID {
	return domain.VaultID(digestBytes([]byte("ebb:vault:" + repoID + ":" + filepath.Clean(mustAbs(repoDir))))[:32])
}

// scanAndResolve performs step 2's discovery: a full no-follow scan with
// hashing, policy resolution, and — when removal will follow — the
// destructive blockers that must refuse the operation up front.
func (c *Coordinator) scanAndResolve(ctx context.Context, st *captureState, destructive bool) error {
	res := inventory.Scan(ctx, c.probe, st.rootAbs, inventory.Options{Hash: true})
	if res.Err != nil {
		return fmt.Errorf("lifecycle: %w", res.Err)
	}
	st.scan = res
	resolved, err := policy.Resolve(res.Entries, st.opts.Policy)
	if err != nil {
		return fmt.Errorf("lifecycle: resolve policy: %w", err)
	}
	st.resolved = resolved
	st.entries = resolved.Entries

	if !destructive {
		// A plain snapshot may proceed; blockers become warnings and
		// exclusions (the entries are simply not captured).
		for _, b := range res.Summary.Blocking {
			st.warnings = append(st.warnings, fmt.Sprintf("blocking entry %s not captured (v1 fidelity gap); see scan issues", b))
		}
		return nil
	}

	var reasons []string
	for _, b := range res.Summary.Blocking {
		reasons = append(reasons, fmt.Sprintf("scan blocker at %s (placeholder/ADS/special/reparse v1 gap)", b))
	}
	for _, code := range st.opts.Git.DestructiveParkBlockers() {
		reasons = append(reasons, code)
	}
	for _, e := range st.entries {
		if e.Route != domain.RoutePreserve && e.Route != domain.RouteReconstruct {
			// v1 policy cannot produce these; an adapter-recorded
			// external/discard route is not covered by a park seal.
			reasons = append(reasons, fmt.Sprintf("entry %s carries route %q not covered by a park seal", e.Path, e.Route))
		}
	}
	if len(reasons) > 0 {
		return &ErrDestructiveBlocked{Reasons: reasons}
	}
	return nil
}

// writeOpDir writes the private operation directory (§11.2): manifest,
// inventory, frozen policy. It is a sibling of the root (D003), never
// inside any captured tree, and the source tree is not copied into it.
func (c *Coordinator) writeOpDir(st *captureState) error {
	if err := os.MkdirAll(st.opDir, 0o700); err != nil {
		return fmt.Errorf("lifecycle: op dir: %w", err)
	}
	frozen, err := freezePolicy(st.opts.Policy)
	if err != nil {
		return err
	}
	st.frozenPolicy = frozen
	if err := os.WriteFile(filepath.Join(st.opDir, policyFrozenName), frozen, 0o600); err != nil {
		return fmt.Errorf("lifecycle: write frozen policy: %w", err)
	}
	invBytes, invDigest, err := buildInventoryBytes(st.entries)
	if err != nil {
		return err
	}
	st.inventoryBytes, st.inventoryDigest = invBytes, invDigest
	if err := os.WriteFile(filepath.Join(st.opDir, inventoryName), invBytes, 0o600); err != nil {
		return fmt.Errorf("lifecycle: write inventory: %w", err)
	}
	// Every derived definition must belong to a resolved group: an
	// orphan definition could never run at open time and would mean the
	// CLI derivation and the resolved policy disagree.
	if len(st.opts.ActionDefs) > 0 {
		known := make(map[string]bool, len(st.resolved.Groups))
		for _, g := range st.resolved.Groups {
			known[g.ID] = true
		}
		for _, d := range st.opts.ActionDefs {
			if !known[d.ID] {
				return fmt.Errorf("lifecycle: action definition %q matches no regenerate group of the resolved policy", d.ID)
			}
		}
	}
	manifest := buildManifest(
		st.snapID, st.wsID, domain.FormatTime(c.now()),
		st.rootAbs, st.rootIdent, st.wsPrefix, st.opDirName,
		invBytes, invDigest, st.entries,
		frozen, resolvedRoutesDigest(st.entries, groupIDs(st.resolved)),
		st.opts.Policy, st.resolved, st.scan.Summary.Issues, st.scan.Summary.Blocking,
		st.opts, st.snapKind == catalog.SnapshotKindTrim,
	)
	manifestBytes, err := writeJSONDoc(filepath.Join(st.opDir, manifestName), manifest)
	if err != nil {
		return fmt.Errorf("lifecycle: write manifest: %w", err)
	}
	st.manifestBytes, st.manifestDigest = manifestBytes, digestBytes(manifestBytes)
	st.journal.step("op-dir-written", st.opDir)
	return nil
}

func groupIDs(r policy.Resolved) []string {
	ids := make([]string, 0, len(r.Groups))
	for _, g := range r.Groups {
		ids = append(ids, g.ID)
	}
	return ids
}

// buildSelection derives the literal restic selection (§11.2):
//
//   - EVERY preserved regular file by exact path;
//   - every symlink/junction/mount-point entry;
//   - every EMPTY directory;
//   - one sanctioned exception: a directory whose entire recursive
//     content is preserved, with zero omitted entries and zero boundary
//     links inside, may be listed as the directory (verified against the
//     scan; when in doubt files are listed individually);
//   - plus the whole op dir (Ebb-authored, link-free by construction).
//
// No cap: large selections stream into the store's list file; restic
// handles arbitrary lengths.
//
// The listing and the expected/readback evidence are deliberately
// separate computations: every entry that ends up captured — individually
// listed or implicitly via a shorthand ancestor's recursion — must appear
// in the coverage expectation and (for files) the readback set (§11.4).
// expectedTreeAndReadback derives that set purely from the resolved
// inventory; Recover reuses it to re-verify P from P's own documents.
func (c *Coordinator) buildSelection(st *captureState) error {
	omitted := make(map[string]bool)
	for _, e := range st.entries {
		if e.Route != domain.RoutePreserve {
			omitted[e.Path] = true
		}
	}
	shorthandOK := func(dir string) bool {
		prefix := dir + "/"
		for _, e := range st.entries {
			if !strings.HasPrefix(e.Path, prefix) {
				continue
			}
			switch e.Kind {
			case domain.KindFile:
				if e.Route != domain.RoutePreserve || e.Digest == "" {
					return false // omitted or unhashed (placeholder): never shorthand
				}
			case domain.KindDir:
				if e.Route != domain.RoutePreserve {
					// Listing the parent recurses into this directory:
					// omitted content must never ride along implicitly.
					return false
				}
			default:
				return false // any link/special inside disqualifies
			}
		}
		return true
	}

	plan := selectionPlan{}
	covered := map[string]bool{}

	for _, e := range st.entries {
		if covered[e.Path] || omitted[e.Path] {
			continue
		}
		switch e.Kind {
		case domain.KindDir:
			if shorthandOK(e.Path) {
				plan.relPaths = append(plan.relPaths, st.wsPrefix+"/"+e.Path)
				prefix := e.Path + "/"
				for _, other := range st.entries {
					if strings.HasPrefix(other.Path, prefix) {
						covered[other.Path] = true
					}
				}
			} else {
				// Non-empty dir with links or omitted descendants:
				// metadata arrives implicitly via listed children
				// (restic materializes ancestor nodes).
				continue
			}
		case domain.KindFile:
			if e.Digest == "" {
				// Placeholder-suspect preserved file: opening it would
				// hydrate (§8.1). Not captured; warning recorded.
				st.warnings = append(st.warnings, fmt.Sprintf(
					"preserved file %s not captured: unhashed (cloud-placeholder suspicion); content must never be opened (Foundation §8.1)", e.Path))
				continue
			}
			plan.relPaths = append(plan.relPaths, st.wsPrefix+"/"+e.Path)
		case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
			plan.relPaths = append(plan.relPaths, st.wsPrefix+"/"+e.Path)
		default:
			// Blocking special kinds reach here only for plain
			// snapshots (destructive preflight refused them).
			st.warnings = append(st.warnings, fmt.Sprintf(
				"entry %s of kind %s not captured (v1 backend cannot represent it losslessly)", e.Path, e.Kind))
		}
	}

	// Expected tree + readback from every captured entry (shared with
	// Recover's P re-verification).
	expected, readback := expectedTreeAndReadback(st.entries, st.wsPrefix)
	plan.expected = expected
	plan.readback = append(plan.readback, readback...)

	// The op dir: fully preserved by construction; listed as one entry.
	opFiles, err := walkLocalTree(st.opDir)
	if err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}
	plan.relPaths = append(plan.relPaths, st.opDirName)
	for rel, fact := range opFiles {
		treePath := "/" + st.opDirName + "/" + rel
		addExpectedPath(plan.expected, treePath, expectedNode{Kind: fact.Kind, Size: fact.Size})
		if fact.Kind == domain.KindFile {
			plan.readback = append(plan.readback, readbackFile{SnapPath: treePath, Digest: fact.Digest})
		}
	}
	st.selection = plan
	return nil
}

// assertD003 re-asserts the capture-list contract client-side (defense
// in depth; the store enforces it too): every entry is relative to the
// root's PARENT, forward-slashed, no absolute or mixed forms.
func (c *Coordinator) assertD003(st *captureState) error {
	for i, p := range st.selection.relPaths {
		if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") || strings.Contains(p, "\\") ||
			(len(p) >= 2 && p[1] == ':') || strings.Contains(p, "..") {
			return fmt.Errorf("lifecycle: capture entry %d %q violates the D003 cwd-relative contract", i, p)
		}
	}
	return nil
}

// verifyPayload performs step 4's two §11.4 checks against P. prefixes are
// the declared tree prefixes of this capture (park/snapshot: workspace root
// + op dir; trim: op dir only — §11.4 readback scope follows authority).
func (c *Coordinator) verifyPayload(ctx context.Context, st *captureState, prefixes []string) error {
	ls, err := c.store.Ls(ctx, st.vault.RepoDir, st.vault.Passfile, st.payload.BackendID)
	if err != nil {
		return fmt.Errorf("lifecycle: listing payload: %w", err)
	}
	if err := verifyCoverage(ls, st.selection.expected, prefixes); err != nil {
		return err
	}
	if err := verifyReadback(ctx, c.store, st.vault.RepoDir, st.vault.Passfile, st.payload.BackendID, st.selection.readback); err != nil {
		return err
	}
	st.journal.step("payload-verified", st.payload.BackendID)
	return nil
}

// sealPayload performs step 5: write the receipt (P now read back and
// checked), capture the small seal snapshot S, read S back byte-exactly,
// then commit the retained P/S pair (§11.3) to the catalog and commit the
// seal-complete phase. fromPhase/toPhase carry the caller's phase
// vocabulary: park/snapshot seal PAYLOAD_COMMITTED→SEALED; a trim seals
// TRIM_PLANNED→TRIM_SEALING (its seal commit IS the TRIM_SEALING gate
// that authorizes removal).
func (c *Coordinator) sealPayload(ctx context.Context, st *captureState, fromPhase, toPhase string) error {
	if err := os.MkdirAll(st.sealDir, 0o700); err != nil {
		return fmt.Errorf("lifecycle: seal dir: %w", err)
	}
	checks := []string{checkCoverageComplete, checkPayloadReadback}
	if st.snapKind == catalog.SnapshotKindTrim {
		// §11.4: a trim's authoritative material is the removal plan;
		// its readback is named on the receipt.
		checks = append(checks, checkRemovalPlanReadback)
	}
	receipt := buildReceipt(
		st.snapID, st.wsID, st.repoID, st.payload.BackendID,
		st.manifestDigest, st.inventoryDigest, st.opID,
		manifestScope(st), domain.FormatTime(c.now()),
		checks,
	)
	receiptBytes, err := writeJSONDoc(filepath.Join(st.sealDir, receiptName), receipt)
	if err != nil {
		return fmt.Errorf("lifecycle: write receipt: %w", err)
	}

	S, err := c.store.Snapshot(ctx, st.vault.RepoDir, st.parent, []string{sealDirName(st.opID)}, st.vault.Passfile, map[string]string{
		"ebb-op":   string(st.opID),
		"ebb-kind": "seal",
		"ws":       string(st.wsID),
	})
	if err != nil {
		return fmt.Errorf("lifecycle: seal capture failed (payload P remains retained): %w", err)
	}
	st.seal = S
	st.journal.step("seal-captured", S.BackendID)

	// Coverage of S: exactly the seal dir + receipt.
	expected := map[string]expectedNode{}
	addExpectedPath(expected, "/"+sealDirName(st.opID)+"/"+receiptName, expectedNode{Kind: domain.KindFile, Size: int64(len(receiptBytes))})
	ls, err := c.store.Ls(ctx, st.vault.RepoDir, st.vault.Passfile, S.BackendID)
	if err != nil {
		return fmt.Errorf("lifecycle: listing seal: %w", err)
	}
	if err := verifyCoverage(ls, expected, []string{sealDirName(st.opID)}); err != nil {
		return err
	}
	// Ebb reads S back before authorizing anything (§11.3).
	got, err := c.store.DumpFile(ctx, st.vault.RepoDir, st.vault.Passfile, S.BackendID, "/"+sealDirName(st.opID)+"/"+receiptName)
	if err != nil {
		return fmt.Errorf("lifecycle: seal readback: %w", err)
	}
	if digestBytes(got) != digestBytes(receiptBytes) {
		return &ErrVerification{Check: "readback", Details: []string{
			fmt.Sprintf("seal receipt bytes read back differ from written bytes (wrote %d bytes digest %s, read %d bytes digest %s)",
				len(receiptBytes), digestBytes(receiptBytes), len(got), digestBytes(got))}}
	}

	// Commit the retained pair, then the seal-complete phase.
	if _, err := c.cat.RecordSnapshot(catalog.Snapshot{
		ID: st.snapID, WorkspaceID: st.wsID, CreatedAt: domain.FormatTime(c.now()),
		PayloadBackendID: st.payload.BackendID, SealBackendID: S.BackendID,
		VaultID: c.vaultIDFor(st.repoID, st.vault), ManifestDigest: st.manifestDigest,
		InventoryDigest: st.inventoryDigest, Kind: st.snapKind,
	}); err != nil {
		return fmt.Errorf("lifecycle: record snapshot: %w", err)
	}
	if err := c.cat.SetBackendRefs(st.opID, st.payload.BackendID, S.BackendID); err != nil {
		return fmt.Errorf("lifecycle: record seal ref: %w", err)
	}
	if err := c.advance(st.opID, fromPhase, toPhase, st.journal); err != nil {
		return err
	}
	st.journal.step("sealed", st.payload.BackendID+"/"+S.BackendID)
	return nil
}

func manifestScope(st *captureState) string {
	if st.snapKind == catalog.SnapshotKindTrim {
		return scopeTrimPlan
	}
	return scopeSingleOwnedRoot
}

// advance is the CAS phase transition with journaling; a CAS conflict
// is always fatal to the operation (concurrent mutation is exactly what
// the serialized-CLI lock exists to prevent).
func (c *Coordinator) advance(opID domain.OperationID, from, to string, j *opJournal) error {
	if err := c.cat.AdvanceOperation(opID, from, to); err != nil {
		return fmt.Errorf("lifecycle: advance %s: %s -> %s: %w", opID, from, to, err)
	}
	if j != nil {
		j.step("phase:"+to, "")
	}
	return nil
}

// cleanupScratch removes the captured op/seal dirs and the journal after
// the seal verified and the sequence completed (their content lives in
// the retained snapshots; the live copies are redundant). The journal is
// closed before its file is removed.
func (c *Coordinator) cleanupScratch(st *captureState) {
	if err := st.journal.close(); err != nil {
		st.warnings = append(st.warnings, fmt.Sprintf("close journal failed: %v", err))
	}
	for _, p := range []string{st.opDir, st.sealDir} {
		if err := removeEbbOwned(p); err != nil {
			st.warnings = append(st.warnings, fmt.Sprintf("cleanup %s failed: %v", p, err))
		}
	}
	if err := removeEbbOwned(journalPath(st.parent, st.opID)); err != nil {
		st.warnings = append(st.warnings, fmt.Sprintf("cleanup journal failed: %v", err))
	}
}

// result summarizes the capture.
func (st *captureState) result() SnapshotResult {
	res := SnapshotResult{
		SnapshotID: st.snapID,
		BackendIDs: [2]string{st.payload.BackendID, st.seal.BackendID},
		Warnings:   append([]string(nil), st.warnings...),
	}
	for _, e := range st.entries {
		if e.Route == domain.RoutePreserve {
			res.EntriesPreserved++
			if e.Kind == domain.KindFile {
				res.PreservedBytes += e.LogicalSize
			}
		} else {
			res.EntriesOmitted++
		}
	}
	return res
}

// expectedLogicalBytes estimates the reclaimable bytes (all file bytes
// in the inventory — preserved and omitted alike leave the live root
// when it is parked).
func (st *captureState) expectedLogicalBytes() int64 {
	var total int64
	for _, e := range st.entries {
		if e.Kind == domain.KindFile {
			total += e.LogicalSize
		}
	}
	return total
}
