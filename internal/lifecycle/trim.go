package lifecycle

// Trim (Foundation §17.3) — the narrower destructive operation. A trim
// removes only explicitly approved generated groups from a LIVE root; it
// never quarantines the whole root and never claims to have backed up the
// entire remaining workspace. The authoritative retained material of a
// trim is exactly its removal plan plus byte-copies of the groups' recipe
// inputs (§11.4: readback scope follows authority), sealed like any other
// capture before a single byte is removed.
//
// Phase model: the catalog's dedicated trim vocabulary (records.go) —
// TRIM_PLANNED covers validation, plan freeze, op-dir write, payload P
// capture/verify and seal S (the seal commit IS the TRIM_SEALING
// transition); TRIM_SEALING gates removal from the live root; TRIM_DONE
// is terminal. BeginOperation always opens an operation at PLANNED, so
// the first durable act of a trim is the PLANNED→TRIM_PLANNED relabel
// (the catalog's closed vocabulary is not modified from here).

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/policy"
)

// trimGroupPlan is one requested group's frozen removal declaration.
type trimGroupPlan struct {
	GroupID string
	Adapter string
	Root    string
	Outputs []string
	Inputs  []string
	Reclaim []string
	// LiveRecreate is the non-lockfile recreate argv (D033/D034),
	// frozen into the removal manifest's recreate_live field.
	LiveRecreate []string
	Members      []domain.Entry
	// Carved are the group's carve-out entries (D034): cancelling
	// file/link entries captured as overlay patches. They are also
	// appended to Members — the removal walk and its Recover resume
	// must cover them like any member — while writeOverlayCopies emits
	// their overlayPatchRecords for the restore side.
	Carved []domain.Entry
}

// Trim executes the trim sequence over the live root: validate approvals,
// scan+resolve, freeze and seal the removal plan, then remove only the
// approved groups' members from the live root (Foundation §17.3).
func (c *Coordinator) Trim(ctx context.Context, vault VaultRef, root string, opts CaptureOptions) (TrimResult, error) {
	// ---- Validation before any durable side effect -------------------
	if len(opts.DoTrim) == 0 {
		return TrimResult{}, &ErrInvalidOptions{Detail: "Trim requires at least one group id in DoTrim"}
	}
	var unknown []string
	for _, id := range opts.DoTrim {
		if !policyHasGroup(opts.Policy, id) {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		return TrimResult{}, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"DoTrim names unknown regenerate group(s) %s; the resolved policy declares %s",
			strings.Join(unknown, ", "), strings.Join(policyGroupIDs(opts.Policy), ", "))}
	}
	if opts.ApprovalReady == nil {
		// Approval authority is a caller-supplied callback by design; no
		// callback means no group may be considered approved (§7.3).
		return TrimResult{}, &ErrDestructiveBlocked{Reasons: []string{
			"trim refused: no ApprovalReady callback supplied; removal of a generated group requires its recorded approval"}}
	}
	var blocked []string
	for _, id := range opts.DoTrim {
		if err := opts.ApprovalReady(id); err != nil {
			blocked = append(blocked, fmt.Sprintf("group %s not approved for removal: %v", id, err))
		}
	}
	if len(blocked) > 0 {
		// Never a silent partial trim: one unapproved group aborts all.
		return TrimResult{}, &ErrDestructiveBlocked{Reasons: blocked}
	}

	// ---- Open the journaled operation (kind trim) --------------------
	st, err := c.openCapture(ctx, vault, root, opts, catalog.OpKindTrim, catalog.SnapshotKindTrim)
	if st != nil {
		defer st.journal.close() // no sequence end may leave the file held open
	}
	if err != nil {
		return TrimResult{}, err
	}
	fail := func(phase string, err error) (TrimResult, error) {
		c.failOperation(st.opID, phase, err.Error())
		st.journal.step("failed", err.Error())
		return TrimResult{}, err
	}
	// cancelTrim records a refused-before-removal failure as CANCELED so
	// the workspace is not left locked by a dead operation (F37).
	cancel := func(err error) (TrimResult, error) {
		c.failOperation(st.opID, catalog.PhaseTrimPlanned, err.Error())
		if aerr := c.cat.AdvanceOperation(st.opID, catalog.PhaseTrimPlanned, catalog.PhaseCanceled); aerr != nil {
			err = fmt.Errorf("%w (additionally canceling operation: %v)", err, aerr)
		}
		st.journal.step("canceled", err.Error())
		return TrimResult{}, err
	}

	// BeginOperation journals every operation at PLANNED; relabel into the
	// dedicated trim vocabulary immediately (catalog API is untouched).
	if err := c.advance(st.opID, catalog.PhasePlanned, catalog.PhaseTrimPlanned, st.journal); err != nil {
		return TrimResult{}, err
	}

	// ---- Scan + resolve the live root --------------------------------
	// Scan blockers (placeholder/ADS/special/reparse) block a trim ONLY
	// inside a requested group's outputs; elsewhere the workspace stays
	// put and they are warnings. Git park blockers do not apply (the
	// root, its .git included, stays live).
	if err := c.scanAndResolve(ctx, st, false); err != nil {
		return cancel(err)
	}
	if reasons := trimScanBlockers(st, opts.DoTrim); len(reasons) > 0 {
		return cancel(&ErrDestructiveBlocked{Reasons: reasons})
	}
	// F53 evidence parity (D034): the CLI resolves routes over
	// git-annotated entries; re-annotate this trim's own scan with the
	// caller's git observation and re-resolve, so the authoritative plan
	// sees the same cancellers the approval surface offered (and a
	// Git-tracked file inside the outputs cancels the group here too).
	if err := applyGitEvidence(st); err != nil {
		return cancel(err)
	}

	// ---- Build the removal plan --------------------------------------
	plan, skipped, err := buildTrimPlan(st, opts.DoTrim)
	if err != nil {
		return cancel(err)
	}
	st.trimPlan = plan
	for _, id := range skipped {
		st.warnings = append(st.warnings, fmt.Sprintf(
			"trim group %s skipped: no reconstruct-routed members found under its outputs (already removed?)", id))
	}
	st.journal.step("trim-plan", fmt.Sprintf("%d group(s), %d member(s)", len(plan), trimPlanMemberCount(plan)))

	// ---- Write the op dir (D003 sibling; plan + inputs only) ---------
	if err := c.writeTrimOpDir(st); err != nil {
		return fail(catalog.PhaseTrimPlanned, err)
	}
	if err := c.buildTrimSelection(st); err != nil {
		return fail(catalog.PhaseTrimPlanned, err)
	}
	if err := c.assertD003(st); err != nil {
		return fail(catalog.PhaseTrimPlanned, err)
	}

	// ---- Capture P (the op dir), verify, seal ------------------------
	P, err := c.store.Snapshot(ctx, vault.RepoDir, st.parent, st.selection.relPaths, vault.Passfile, map[string]string{
		"ebb-op":   string(st.opID),
		"ebb-kind": "payload",
		"ws":       string(st.wsID),
	})
	if err != nil {
		c.failOperation(st.opID, catalog.PhaseTrimPlanned, err.Error())
		st.journal.step("payload-failed", err.Error())
		_ = removeEbbOwned(st.opDir)
		return TrimResult{}, fmt.Errorf("lifecycle: trim payload capture failed: %w", err)
	}
	st.payload = P
	st.journal.step("payload-captured", P.BackendID)
	if err := c.cat.SetBackendRefs(st.opID, P.BackendID, ""); err != nil {
		return fail(catalog.PhaseTrimPlanned, fmt.Errorf("lifecycle: record payload ref: %w", err))
	}

	if err := c.verifyPayload(ctx, st, []string{st.opDirName}); err != nil {
		// §11.3: P exists but is not a verified capture — retain it
		// unsealed+pinned, cancel the operation, keep the op dir.
		c.failOperation(st.opID, catalog.PhaseTrimPlanned, err.Error())
		st.journal.step("verification-failed", err.Error())
		var verr *ErrVerification
		if errors.As(err, &verr) {
			if _, rerr := c.cat.RecordSnapshot(catalog.Snapshot{
				ID: st.snapID, WorkspaceID: st.wsID,
				PayloadBackendID: P.BackendID, VaultID: c.vaultIDFor(st.repoID, vault),
				ManifestDigest: st.manifestDigest, InventoryDigest: st.inventoryDigest,
				Kind: catalog.SnapshotKindTrim,
			}); rerr != nil {
				err = fmt.Errorf("%w (additionally recording unsealed payload: %v)", err, rerr)
			}
			if aerr := c.cat.AdvanceOperation(st.opID, catalog.PhaseTrimPlanned, catalog.PhaseCanceled); aerr != nil {
				err = fmt.Errorf("%w (additionally canceling operation: %v)", err, aerr)
			}
			return TrimResult{}, fmt.Errorf("%w; %w", err, errPayloadIncomplete)
		}
		return TrimResult{}, err
	}

	// The seal commit is the TRIM_SEALING transition: from here the
	// removal plan is sealed and removal is authorized (after the
	// identity re-probe below).
	if err := c.sealPayload(ctx, st, catalog.PhaseTrimPlanned, catalog.PhaseTrimSealing); err != nil {
		c.failOperation(st.opID, catalog.PhaseTrimPlanned, err.Error())
		st.journal.step("seal-failed", err.Error())
		return TrimResult{}, err
	}

	// ---- Removal from the LIVE root (§17.3; no quarantine) -----------
	removed, err := c.trimRemoval(ctx, st)
	if err != nil {
		return TrimResult{}, err
	}
	if err := c.advance(st.opID, catalog.PhaseTrimSealing, catalog.PhaseTrimDone, st.journal); err != nil {
		return TrimResult{}, err
	}
	st.journal.step("trim-done", fmt.Sprintf("groups=%d removed=%d", len(plan), removed))
	c.cleanupScratch(st)

	groups := make([]string, 0, len(plan))
	cmds := make([][]string, 0, len(plan))
	carved := make([]int, 0, len(plan))
	for _, gp := range plan {
		groups = append(groups, gp.GroupID)
		cmds = append(cmds, gp.Reclaim)
		carved = append(carved, len(gp.Carved))
	}
	res := st.result()
	return TrimResult{Snapshot: res, Groups: groups, EntriesRemoved: removed,
		ReclaimCommands: cmds, CarvedEntries: carved}, nil
}

// trimRemoval removes the frozen member set from the live root. Every
// member is re-digested by the permit immediately before its removal
// (E08); a block leaves the phase at TRIM_SEALING with the remaining
// members intact and P/S pinned. It reports how many authorized entries
// are now gone (removed by this walk or already absent).
func (c *Coordinator) trimRemoval(ctx context.Context, st *captureState) (int, error) {
	if err := ctx.Err(); err != nil {
		err = fmt.Errorf("lifecycle: removal not started: %w", err)
		c.failOperation(st.opID, catalog.PhaseTrimSealing, err.Error())
		return 0, err
	}
	// The live root must still be the root that was scanned and sealed
	// (F32/I13: a replaced directory at the same pathname never inherits
	// the seal's authority).
	now, err := c.probe.RootIdentity(st.rootAbs)
	if err != nil {
		err = fmt.Errorf("lifecycle: identity probe of live root: %w", err)
		c.failOperation(st.opID, catalog.PhaseTrimSealing, err.Error())
		return 0, err
	}
	if now != st.rootIdent {
		err = &ErrSourceChanged{Diff: []string{fmt.Sprintf(
			"live root %s identity %s differs from the sealed identity %s; trim removal refused", st.rootAbs, now, st.rootIdent)}}
		c.failOperation(st.opID, catalog.PhaseTrimSealing, err.Error())
		return 0, err
	}

	allowed := make(map[string]domain.Entry)
	var outputs []string
	for _, gp := range st.trimPlan {
		for _, e := range gp.Members {
			// D034: carved entries are members too, so they JOIN the
			// permit's allowed set here — each is re-digested (or, for
			// links, re-verified by target text) immediately before its
			// removal, exactly like every other member.
			allowed[e.Path] = e
		}
		outputs = append(outputs, gp.Outputs...)
	}
	permit, err := newRemovalPermit(st.opID, st.snapID, st.rootAbs, st.rootIdent, allowed)
	if err != nil {
		c.failOperation(st.opID, catalog.PhaseTrimSealing, err.Error())
		return 0, err
	}
	stats, err := permit.execute(ctx, c.probe, st.journal, nil)
	if err != nil {
		// Phase deliberately unchanged (TRIM_SEALING is the trim's
		// removal-gate phase; there is no trim-specific blocked phase).
		c.failOperation(st.opID, catalog.PhaseTrimSealing, err.Error())
		return 0, err
	}
	if err := permit.removeEmptyAncestors(outputs, st.journal); err != nil {
		c.failOperation(st.opID, catalog.PhaseTrimSealing, err.Error())
		return 0, err
	}
	gone := stats.Removed + stats.SkippedGone
	st.journal.step("trim-removed", fmt.Sprintf("removed=%d skipped-gone=%d", stats.Removed, stats.SkippedGone))
	return gone, nil
}

// buildTrimPlan freezes the per-group member sets from the resolved
// inventory. A group with zero members is skipped (returned separately);
// zero members across ALL requested groups fails the operation (nothing
// would be removed — never a no-op trim masquerading as success).
//
// D034 carve-out: a requested group that policy cancelled (F53) may be
// carved instead of refused, but ONLY when opts.CarveOut carries the
// recorded consent AND every carve candidate's path is in the approved
// list opts.CarveOutPaths (F8: consent is pinned to the exact paths the
// consent surface displayed — lifecycle re-derives the carve set from
// its own scan, so a canceller that appeared between the two scans
// refuses the group instead of being removed unseen). The cancelling
// file/link entries become overlay patches (captured into the op dir
// and sealed with P) and join the member set; the clean bulk under the
// outputs is removed normally. Without consent — or when the carve is
// refused (un-carve-able entry, budget, case collision or approved-list
// drift) — the group is blocked exactly as before, with text that names
// the missing --carve-out authorization or the honest refusal reason.
func buildTrimPlan(st *captureState, groupIDs []string) (plan []trimGroupPlan, skipped []string, err error) {
	decisions := make(map[string]bool, len(st.resolved.Groups))
	reasons := make(map[string]string, len(st.resolved.Groups))
	for _, d := range st.resolved.Groups {
		decisions[d.ID] = d.Applicable
		if !d.Applicable {
			reasons[d.ID] = d.Reason
			if d.Canceller != "" {
				reasons[d.ID] = fmt.Sprintf("%s (cancelling entry %s)", d.Reason, d.Canceller)
			}
		}
	}
	var blocked []string
	for _, id := range groupIDs {
		if applicable, ok := decisions[id]; ok && !applicable {
			cls := classifyCarveOut(st.entries, policyGroupByID(st.opts.Policy, id).Outputs)
			switch {
			case st.opts.CarveOut:
				if r := carvePlanBlocker(id, cls); r != "" {
					blocked = append(blocked, r)
				} else if r := carveConsentBlocker(id, cls, st.opts.CarveOutPaths); r != "" {
					// F8: the approved-list drift check runs only for an
					// otherwise carve-able group (shape/budget honesty
					// first); drift refuses it with the pinned-set text.
					blocked = append(blocked, r)
				}
			case len(cls.Refusals) > 0:
				blocked = append(blocked, fmt.Sprintf(
					"regenerate group %s is not applicable for removal: %s; carve-out refused: %s",
					id, reasons[id], strings.Join(cls.Refusals, "; ")))
			default:
				blocked = append(blocked, fmt.Sprintf(
					"regenerate group %s is not applicable for removal: %s; carve-out consent was not given (D034): rerun with --carve-out (or answer the interactive carve confirmation) to capture the cancelling entries as an overlay patch and remove them after capture",
					id, reasons[id]))
			}
		}
	}
	if len(blocked) > 0 {
		return nil, nil, &ErrDestructiveBlocked{Reasons: blocked}
	}

	for _, id := range groupIDs {
		g := policyGroupByID(st.opts.Policy, id)
		gp := trimGroupPlan{
			GroupID: id, Adapter: string(g.Adapter), Root: g.Root,
			Outputs: g.Outputs, Inputs: g.Inputs, Reclaim: reclaimCommand(g),
			LiveRecreate: liveRecreateCommand(g),
		}
		if decisions[id] {
			for _, e := range st.entries {
				if e.Route == domain.RouteReconstruct && groupOf(e) == id {
					gp.Members = append(gp.Members, e)
				}
			}
		} else {
			// Carve-out group (consent checked above): the clean bulk
			// plus the carved cancellers are the removal members; the
			// canceller entries additionally become overlay patches.
			cls := classifyCarveOut(st.entries, g.Outputs)
			gp.Members = append(gp.Members, cls.Bulk...)
			gp.Members = append(gp.Members, cls.Carved...)
			domain.SortEntries(gp.Members)
			gp.Carved = cls.Carved
		}
		if len(gp.Members) == 0 {
			skipped = append(skipped, id)
			continue
		}
		plan = append(plan, gp)
	}
	if len(plan) == 0 {
		return nil, skipped, &ErrInvalidOptions{Detail: fmt.Sprintf(
			"nothing to trim: none of the requested group(s) %s has reconstruct-routed members under its outputs", strings.Join(groupIDs, ", "))}
	}
	return plan, skipped, nil
}

func trimPlanMemberCount(plan []trimGroupPlan) int {
	n := 0
	for _, gp := range plan {
		n += len(gp.Members)
	}
	return n
}

// trimScanBlockers applies the trim-specific scan-blocker rule: a blocking
// entry (placeholder/ADS/special/reparse gap) blocks the trim only when it
// lies inside a requested group's outputs; outside them the workspace
// stays live and the blocker is a warning (already recorded by
// scanAndResolve).
func trimScanBlockers(st *captureState, groupIDs []string) []string {
	var outputs []string
	for _, id := range groupIDs {
		outputs = append(outputs, policyGroupByID(st.opts.Policy, id).Outputs...)
	}
	var reasons []string
	for _, b := range st.scan.Summary.Blocking {
		if underAnyRelPrefix(outputs, b) {
			reasons = append(reasons, fmt.Sprintf(
				"scan blocker at %s lies inside a requested trim group's outputs (placeholder/ADS/special/reparse v1 gap)", b))
		}
	}
	return reasons
}

// writeTrimOpDir writes the trim op dir: manifest.json (scope
// trim-removal-plan), removal-manifest.json (the frozen plan, including
// any D034 overlay patches and the recreate_live argv), policy.toml and
// byte-copies of each group's recipe inputs plus each group's carved
// overlay entries. It contains ONLY these — a trim does not capture the
// whole workspace (§17.3).
func (c *Coordinator) writeTrimOpDir(st *captureState) error {
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

	var groups []removalManifestDoc
	for _, gp := range st.trimPlan {
		inputs, err := copyRecipeInputs(st, gp)
		if err != nil {
			return err
		}
		overlays, err := writeOverlayCopies(st, gp)
		if err != nil {
			return err
		}
		if len(overlays) > 0 {
			var carvedBytes int64
			for _, e := range gp.Carved {
				carvedBytes += e.LogicalSize
			}
			st.warnings = append(st.warnings, fmt.Sprintf(
				"carve-out (D034): %d entr(y/ies) (%d bytes) of group %s captured to the vault overlay and removed with the group; restore reapplies them after the recreate recipe",
				len(overlays), carvedBytes, gp.GroupID))
		}
		members := make([]inventoryRecord, 0, len(gp.Members))
		for _, e := range gp.Members {
			members = append(members, inventoryRecord{Entry: e, Group: gp.GroupID})
		}
		groups = append(groups, removalManifestDoc{
			GroupID: gp.GroupID, Adapter: gp.Adapter, Root: gp.Root,
			Outputs: gp.Outputs, ReclaimCommand: gp.Reclaim,
			RecipeInputs: inputs, Members: members,
			OverlayPatches: overlays, RecreateLive: gp.LiveRecreate,
		})
	}
	doc := trimPlanDoc{
		SchemaVersion: schemaVersionCurrent,
		OperationID:   string(st.opID),
		SnapshotID:    string(st.snapID),
		Groups:        groups,
	}
	rmBytes, err := writeJSONDoc(filepath.Join(st.opDir, removalManifestName), doc)
	if err != nil {
		return fmt.Errorf("lifecycle: write removal manifest: %w", err)
	}
	st.inventoryBytes, st.inventoryDigest = rmBytes, digestBytes(rmBytes)

	manifest := buildManifest(
		st.snapID, st.wsID, domain.FormatTime(c.now()),
		st.rootAbs, st.rootIdent, st.wsPrefix, st.opDirName,
		rmBytes, st.inventoryDigest, st.entries,
		frozen, resolvedRoutesDigest(st.entries, groupIDs(st.resolved)),
		st.opts.Policy, st.resolved, st.scan.Summary.Issues, st.scan.Summary.Blocking,
		st.opts, true,
	)
	// The manifest's inventory reference points at the removal manifest
	// for a trim; its record count is therefore the member count, not the
	// full resolved-entry count buildManifest derived from `entries`.
	manifest.Inventory.Count = int64(trimPlanMemberCount(st.trimPlan))
	manifestBytes, err := writeJSONDoc(filepath.Join(st.opDir, manifestName), manifest)
	if err != nil {
		return fmt.Errorf("lifecycle: write manifest: %w", err)
	}
	st.manifestBytes, st.manifestDigest = manifestBytes, digestBytes(manifestBytes)
	st.journal.step("trim-op-dir-written", st.opDir)
	return nil
}

// copyRecipeInputs byte-copies each declared input that exists under the
// live root into inputs/<group>/<path> and returns the digested record.
// Missing inputs are recorded as absent (never guessed).
func copyRecipeInputs(st *captureState, gp trimGroupPlan) ([]recipeInput, error) {
	var out []recipeInput
	for _, in := range gp.Inputs {
		rec := recipeInput{Path: in}
		src := filepath.Join(st.rootAbs, filepath.FromSlash(in))
		b, err := os.ReadFile(src)
		switch {
		case err == nil:
			rel := inputsDirName + "/" + gp.GroupID + "/" + in
			dst := filepath.Join(st.opDir, filepath.FromSlash(rel))
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return nil, fmt.Errorf("lifecycle: recipe input %s: %w", in, err)
			}
			if err := os.WriteFile(dst, b, 0o600); err != nil {
				return nil, fmt.Errorf("lifecycle: recipe input %s: %w", in, err)
			}
			rec.Copy = rel
			rec.Digest = digestBytes(b)
		case errors.Is(err, fs.ErrNotExist):
			rec.Missing = true
		default:
			return nil, fmt.Errorf("lifecycle: recipe input %s: %w", in, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// buildTrimSelection derives the trim capture selection: exactly the op
// dir. The workspace root is deliberately absent (§17.3/§11.4 — the
// untouched remainder is not claimed as retained).
func (c *Coordinator) buildTrimSelection(st *captureState) error {
	plan := selectionPlan{expected: map[string]expectedNode{}}
	plan.relPaths = []string{st.opDirName}
	opFiles, err := walkLocalTree(st.opDir)
	if err != nil {
		return fmt.Errorf("lifecycle: %w", err)
	}
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

// ---- small policy lookups (frozen policy is the authority) -----------

func policyHasGroup(p policy.Policy, id string) bool {
	return policyGroupByID(p, id).ID != ""
}

func policyGroupByID(p policy.Policy, id string) policy.Regenerate {
	for _, g := range p.Regenerate {
		if g.ID == id {
			return g
		}
	}
	return policy.Regenerate{}
}

func policyGroupIDs(p policy.Policy) []string {
	ids := make([]string, 0, len(p.Regenerate))
	for _, g := range p.Regenerate {
		ids = append(ids, g.ID)
	}
	return ids
}

// underAnyRelPrefix reports whether a root-relative slash path equals or
// lies below one of the prefixes.
func underAnyRelPrefix(prefixes []string, path string) bool {
	for _, p := range prefixes {
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}
