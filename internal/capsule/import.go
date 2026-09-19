package capsule

// import.go — the §15.3 import half of the capsule protocol, the mirror
// of Export (D024): register a capsule's retained payload snapshot in a
// selected destination vault WITHOUT publishing a working directory.
//
//	init: validate params, own a working directory on the destination
//	  volume (.ebb-import-<opID>, removed always — this package removes
//	  nothing outside it and its own ephemeral passfile)
//	→ space preflight: re-verify the container (verifyPackage — the
//	  declared repository totals were cross-checked against the actual
//	  entries at write time) and refuse before extraction when the
//	  destination volume holds less than 2× the capsule's repository
//	  bytes (§15.3 "show that cost before extraction": v1 needs
//	  temporary space for the extraction plus the copy into the vault)
//	→ extract the repository under the owned working dir (bounded,
//	  §15.3 hostile-input discipline)
//	→ unlock the extracted repository with the CAPSULE passphrase (an
//	  ephemeral passfile, never argv) and classify it by tags: exactly
//	  one payload + exactly one seal, anything else refuses
//	→ locate the capsule's destination seal by tree shape
//	  (.ebb-seal-<32hex>/receipt.json), strict-parse it, and cross-check
//	  it against the extracted repository's own identity (a seal minted
//	  for another repository refuses — D023 discipline)
//	→ re-derive the payload's retained evidence from its OWN bytes
//	  through the backend (restore.LoadCapsuleEvidence — I12: never
//	  trust a claimed digest), refuse trim-kind payloads, and close the
//	  replication loop (the payload's manifest identities must equal the
//	  seal's source claims)
//	→ identity hook (params.Identified): invoked ONCE here — capsule
//	  verification done, trim gate passed, replication loop closed, no
//	  gate or mutation run yet. The CLI adopts the capsule's LOGICAL
//	  workspace id here (its EnsureWorkspace); an error aborts with
//	  nothing mutated
//	→ duplicate gate (params.Known — the CLI's catalog knowledge):
//	  already-known manifests return WITHOUT any vault mutation
//	→ copy the payload through the backend into the destination vault,
//	  discovering the destination id by List diff (exactly one new id;
//	  restic copy can skip silently — probe C10)
//	→ verify destination coverage + full content readback against the
//	  capsule-derived evidence through the shared lifecycle executors
//	  (the same gates a capture used)
//	→ write a NEW local seal in the DESTINATION vault — lifecycle's
//	  §16.4 receiptDoc wire form, re-declared here as a local strict
//	  writer (the cross-package frozen-format contract restore uses as
//	  a reader; pinned by a golden test against lifecycle's own writer)
//	  — then read it back byte-exact. The seal records the CAPTURE's
//	  operation id (derived from the payload's frozen op dir) in its
//	  staging-dir name, its operation_id field and its ebb-op tag, NOT
//	  the import's own transport op id: every lifecycle-shaped receipt
//	  consumer (restore's loadSeal→loadDocuments, discovery's
//	  requireOpDir) re-derives the payload's frozen .ebb-op-<32hex> dir
//	  from the RECEIPT's operation_id, so the I13 dir==receipt rule
//	  holds for the imported pair exactly as for a native capture, and
//	  the pair loads under loadSeal/loadDocuments/DiscoverVault
//	  unchanged. Provenance of the import itself stays in
//	  Verification.Scope ("capsule-import"), ToolVersions and the
//	  caller's journal (the import operation id).
//	→ on any failure at or after the copy, best-effort Forget of what
//	  this import created in the destination vault, List-verified gone
//	  (D015: forget of a nonexistent id exits 0 silently — verify by
//	  List); a failed rollback is reported honestly, never hidden
//
// The capsule passphrase reaches the backend only through an ephemeral
// 0600 passfile with the exact bytes (ephemeralPassfile) — never argv,
// never logs, never a result field. The destination vault's own
// passfile is the CLI's (DestPassfile, likewise ephemeral and owned by
// the caller).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/lifecycle"
	"ebb/internal/restore"
)

// Import step names reported through ImportParams.Phase (the CLI maps
// them to the catalog's IMPORT_* phases: extracting covers the
// container verification, headroom check and extraction stage of
// IMPORT_PLANNED; copying → IMPORT_COPYING; verifying →
// IMPORT_VERIFYING). PhaseCopying / PhaseVerifying are shared with
// Export — the steps mean the same thing on both transports.
const (
	// PhaseExtracting reports the container verification, headroom
	// check and extraction stage in flight.
	PhaseExtracting = "extracting"
)

// ImportParams parameterizes one import.
type ImportParams struct {
	// Store is the backend seam (required).
	Store Store
	// CapsulePath is the foreign container file (required; must exist
	// and be a regular file — validated up front).
	CapsulePath string
	// Passphrase is the capsule's recovery secret (required; the CLI
	// owns sourcing it — never argv). It is handed to the backend only
	// through an ephemeral passfile inside the owned working dir.
	Passphrase string
	// DestRepoDir is the destination vault's repository directory
	// (required; an existing, registered vault).
	DestRepoDir string
	// DestPassfile is the destination vault's ephemeral passfile
	// (required; owned by the caller, exactly like export's
	// SourcePassfile).
	DestPassfile string
	// DestRepoID is the destination vault's backend repository
	// identity (required; the caller resolves it once through
	// Store.RepoID — the same contract as export's SourceRepoID).
	DestRepoID string
	// OperationID journals this import: it names the transport's owned
	// working directory (.ebb-import-<opID>). It is deliberately NOT the
	// id the new local seal records — the seal carries the CAPTURE's
	// operation id so the imported pair behaves exactly like a native
	// capture under every lifecycle-shaped receipt consumer (see
	// writeImportSeal); the import's own identity stays in
	// Verification.Scope, ToolVersions and the caller's journal.
	OperationID domain.OperationID
	// Phase is an optional journal hook invoked at each step boundary.
	Phase func(step string) error
	// Progress receives human progress lines (stderr in the CLI).
	Progress io.Writer
	// Clock is injectable; defaults to time.Now.
	Clock func() time.Time
	// EbbVersion labels the produced receipt (CLI's Version).
	EbbVersion string
	// FreeSpace reports quota-aware available bytes for the volume
	// containing a path (the §15.3 headroom probe). Optional; defaults
	// to the build-tagged stdlib implementation (GetDiskFreeSpaceExW /
	// statfs — see freespace_*.go). Injectable for tests and unusual
	// mounts.
	FreeSpace func(path string) (int64, error)
	// Identified is an optional hook invoked ONCE after capsule
	// verification and the trim gate — the replication loop is closed,
	// the payload's logical identities are settled — and BEFORE the
	// Known duplicate gate and any destination-vault mutation. The CLI
	// uses it to adopt the capsule's LOGICAL workspace id (identity
	// continuity, §16.1: multiple snapshots of one producer workspace
	// must group under ONE workspace) by ensuring the workspace row
	// exists while nothing has been mutated yet; an error aborts the
	// import with zero vault mutations.
	Identified func(id ImportIdentity) error
	// Known is the CLI-owned duplicate gate: invoked after capsule
	// verification (and after Identified), before ANY destination-vault
	// mutation. Return (true, nil) when the logical snapshot is already
	// registered with THIS manifest digest → the import returns
	// AlreadyKnown without touching the vault; return an error to
	// refuse (e.g. same id, different digest); (false, nil) proceeds.
	Known func(snapshotID, manifestDigest string) (bool, error)
}

// ImportIdentity is the verified logical identity of the payload a
// capsule carries, reported to ImportParams.Identified after capsule
// verification (every field re-derived from the payload's own bytes and
// cross-checked against the capsule seal) and before any gate or
// mutation.
type ImportIdentity struct {
	// SnapshotID / WorkspaceID are the manifest's logical identities —
	// the workspace id is the one the CLI ADOPTS locally.
	SnapshotID  string
	WorkspaceID string
	// WorkspaceName is the manifest main-root backend prefix (D003).
	WorkspaceName string
	// Kind is park|snapshot (trim was refused before the hook fires).
	Kind string
	// ManifestDigest is the re-derived manifest digest (equal to the
	// capsule seal's claim).
	ManifestDigest string
}

// ImportResult reports one completed (or already-known) import.
type ImportResult struct {
	// AlreadyKnown: the duplicate gate recognized the logical snapshot
	// with the same manifest digest; the destination vault was NOT
	// touched (no payload, no seal).
	AlreadyKnown      bool
	LogicalSnapshotID domain.SnapshotID
	WorkspaceID       domain.WorkspaceID
	// WorkspaceName is the manifest main-root backend prefix (D003) —
	// the workspace tree prefix inside the payload, not a host path.
	WorkspaceName string
	// Kind is park|snapshot (trim is refused with ErrTrimCapsule).
	Kind string
	// CreatedAt is the manifest's capture timestamp.
	CreatedAt string
	// ManifestDigest / InventoryDigest are re-derived from the
	// payload's own bytes (equal to the capsule seal's claims on
	// success).
	ManifestDigest  string
	InventoryDigest string
	// CapsuleRepoID is the repository identity inside the capsule.
	CapsuleRepoID string
	// DestinationPayload is the payload's NEW backend id in the
	// destination vault (discovered, never assumed — ids change on
	// cross-repository copy, R38).
	DestinationPayload string
	// DestinationSeal is the NEW local seal's backend id.
	DestinationSeal string
	// PreservedEntries / PreservedBytes summarize the retained set.
	PreservedEntries int64
	PreservedBytes   int64
	// RepoBytes is the capsule's declared (and container-verified)
	// repository size — the number the headroom check budgeted.
	RepoBytes int64
	// Checks are the named checks the local seal recorded (§16.4).
	Checks []string
	// Warnings carries non-blocking observations (empty in v1).
	Warnings []string
}

func (p *ImportParams) now() time.Time {
	if p.Clock != nil {
		return p.Clock()
	}
	return time.Now()
}

func (p *ImportParams) progress(format string, a ...any) {
	if p.Progress != nil {
		fmt.Fprintf(p.Progress, format, a...)
	}
}

func (p *ImportParams) phase(step string) error {
	if p.Phase == nil {
		return nil
	}
	return p.Phase(step)
}

// Import runs the full §15.3 protocol. On any error before the copy
// step the destination vault is untouched; on a failure at or after
// the copy, everything this import created there is best-effort
// forgotten and List-verified gone (a failed rollback is reported, so
// a leaked backend id can never be hidden). The capsule file is never
// modified. The owned working directory (.ebb-import-<opID> beside the
// destination repo) is ALWAYS removed on return — outside it this
// package removes nothing but its own ephemeral passfile.
func Import(ctx context.Context, params ImportParams) (ImportResult, error) {
	if err := validateImportParams(&params); err != nil {
		return ImportResult{}, err
	}

	workDir := filepath.Join(filepath.Dir(params.DestRepoDir), ".ebb-import-"+string(params.OperationID))
	// Own-artifact cleanup, export's contract: the name is ours, so a
	// crash leftover of the SAME operation is pre-removed (extraction
	// creates files O_EXCL and would otherwise trip over it), and the
	// directory is removed on every return.
	_ = os.RemoveAll(workDir)
	defer func() { _ = os.RemoveAll(workDir) }()
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return ImportResult{}, fmt.Errorf("capsule: create import working dir: %w", err)
	}

	res := ImportResult{}

	// ---- space preflight (§15.3: show the cost BEFORE extraction) ----
	params.progress("import %s: verifying the capsule container and destination headroom\n", params.OperationID)
	check, err := verifyPackage(params.CapsulePath)
	if err != nil {
		return ImportResult{}, &ErrNotACapsule{Path: params.CapsulePath, Details: []string{err.Error()}}
	}
	res.RepoBytes = check.ExportDoc.RepoBytes
	freeOf := params.FreeSpace
	if freeOf == nil {
		freeOf = capsuleFreeSpace
	}
	free, err := freeOf(params.DestRepoDir)
	if err != nil {
		return ImportResult{}, fmt.Errorf("capsule: probe free space on the destination volume of %s: %w", params.DestRepoDir, err)
	}
	if need := 2 * check.ExportDoc.RepoBytes; free < need {
		return ImportResult{}, &ErrImportSpace{
			Volume: params.DestRepoDir, FreeBytes: free, NeedBytes: need, RepoBytes: check.ExportDoc.RepoBytes}
	}

	if err := params.phase(PhaseExtracting); err != nil {
		return ImportResult{}, err
	}
	params.progress("import %s: extracting the capsule repository (headroom %d bytes free, %d budgeted)\n",
		params.OperationID, free, 2*check.ExportDoc.RepoBytes)
	extractedRepo := filepath.Join(workDir, repoPrefix)
	if err := extractRepository(params.CapsulePath, extractedRepo, check.ExportDoc.RepoBytes); err != nil {
		return ImportResult{}, &ErrNotACapsule{Path: params.CapsulePath, Details: []string{err.Error()}}
	}

	err = ephemeralPassfile(workDir, params.Passphrase, func(capsulePassfile string) error {
		return importUnlocked(ctx, &params, workDir, extractedRepo, capsulePassfile, &res)
	})
	if err != nil {
		return ImportResult{}, err
	}
	return res, nil
}

// importUnlocked runs steps 5-11 of §15.3 against the extracted
// repository, unlocked through the ephemeral capsule passfile. It fills
// res as facts are established; on success after the duplicate gate it
// guarantees the destination holds exactly the verified payload plus
// the new local seal.
func importUnlocked(ctx context.Context, params *ImportParams, workDir, extractedRepo, capsulePassfile string, res *ImportResult) error {
	// ---- unlock + classify the capsule repository -------------------
	params.progress("import %s: unlocking and classifying the capsule repository\n", params.OperationID)
	capsuleRepoID, err := params.Store.RepoID(ctx, extractedRepo, capsulePassfile)
	if err != nil {
		var se *domain.StoreError
		if errors.As(err, &se) && se.Class == domain.StoreErrAuth {
			return &ErrCapsuleUnlock{Path: params.CapsulePath, Err: err}
		}
		return &ErrNotACapsule{Path: params.CapsulePath, Details: []string{
			fmt.Sprintf("the extracted repository could not be opened: %v", err)}}
	}
	res.CapsuleRepoID = capsuleRepoID

	payloadID, sealID, err := classifyCapsuleRepo(ctx, params.Store, extractedRepo, capsulePassfile, params.CapsulePath)
	if err != nil {
		return err
	}

	// ---- the capsule's own destination seal (§16.4/F43) -------------
	seal, err := readCapsuleSeal(ctx, params.Store, extractedRepo, capsulePassfile, sealID)
	if err != nil {
		return err
	}
	var sealProblems []string
	if seal.PayloadBackendID != payloadID {
		sealProblems = append(sealProblems, fmt.Sprintf(
			"the capsule seal names payload %s, but the repository holds payload %s", seal.PayloadBackendID, payloadID))
	}
	if seal.BackendRepoID != capsuleRepoID {
		sealProblems = append(sealProblems, fmt.Sprintf(
			"the capsule seal was minted for repository %s, but this repository is %s — a seal from another repository refuses (D023 discipline)",
			seal.BackendRepoID, capsuleRepoID))
	}
	if len(sealProblems) > 0 {
		return &ErrVerification{Check: "capsule-seal", Details: sealProblems}
	}

	// ---- re-derive the payload's evidence from its own bytes --------
	ev, err := restore.LoadCapsuleEvidence(ctx, params.Store,
		restore.VaultRef{RepoDir: extractedRepo, Passfile: capsulePassfile},
		payloadID, seal.ManifestDigest, seal.InventoryDigest)
	if err != nil {
		return asCapsuleEvidence(err)
	}
	if ev.Manifest.Kind == catalog.SnapshotKindTrim {
		return &ErrTrimCapsule{
			Path: params.CapsulePath, SnapshotID: string(ev.SnapshotID), WorkspaceID: string(ev.WorkspaceID)}
	}
	// Close the replication loop the loader deliberately leaves to the
	// caller: the payload's own manifest must BE the snapshot the seal
	// certifies, not merely carry the certified digests.
	var replProblems []string
	if seal.Source.LogicalSnapshotID != string(ev.SnapshotID) {
		replProblems = append(replProblems, fmt.Sprintf(
			"the capsule seal certifies source snapshot %s, but the payload's manifest declares %s",
			seal.Source.LogicalSnapshotID, ev.SnapshotID))
	}
	if seal.WorkspaceID != string(ev.WorkspaceID) {
		replProblems = append(replProblems, fmt.Sprintf(
			"the capsule seal names workspace %s, but the payload's manifest declares %s",
			seal.WorkspaceID, ev.WorkspaceID))
	}
	if len(replProblems) > 0 {
		return &ErrVerification{Check: "capsule-seal", Details: replProblems}
	}

	res.LogicalSnapshotID = ev.SnapshotID
	res.WorkspaceID = ev.WorkspaceID
	res.WorkspaceName = ev.WsPrefix
	res.Kind = ev.Manifest.Kind
	res.CreatedAt = ev.Manifest.CreatedAt
	res.ManifestDigest = ev.Manifest.ManifestDigest
	res.InventoryDigest = ev.Manifest.InventoryDigest
	res.PreservedEntries = ev.PreservedEntries
	res.PreservedBytes = ev.PreservedBytes

	// ---- identity hook: before every gate, before any mutation -------
	if params.Identified != nil {
		if ierr := params.Identified(ImportIdentity{
			SnapshotID:     string(ev.SnapshotID),
			WorkspaceID:    string(ev.WorkspaceID),
			WorkspaceName:  ev.WsPrefix,
			Kind:           ev.Manifest.Kind,
			ManifestDigest: ev.Manifest.ManifestDigest,
		}); ierr != nil {
			return fmt.Errorf("capsule: the identity hook refused the import (nothing was mutated): %w", ierr)
		}
	}

	// ---- duplicate gate: nothing below this point runs when known ---
	if params.Known != nil {
		known, kerr := params.Known(string(ev.SnapshotID), ev.Manifest.ManifestDigest)
		if kerr != nil {
			return fmt.Errorf("capsule: the duplicate gate refused the import (nothing was mutated): %w", kerr)
		}
		if known {
			res.AlreadyKnown = true
			params.progress("import %s: snapshot %s is already registered with manifest digest %s; nothing to do\n",
				params.OperationID, ev.SnapshotID, ev.Manifest.ManifestDigest)
			return nil
		}
	}

	// ---- copy the payload into the destination vault ----------------
	if err := params.phase(PhaseCopying); err != nil {
		return err
	}
	params.progress("import %s: copying the payload into the destination vault (ids may change; the destination id is discovered)\n", params.OperationID)
	before, err := params.Store.List(ctx, params.DestRepoDir, params.DestPassfile)
	if err != nil {
		return fmt.Errorf("capsule: list destination vault: %w", err)
	}
	if err := params.Store.Copy(ctx, extractedRepo, capsulePassfile,
		params.DestRepoDir, params.DestPassfile, []string{payloadID}); err != nil {
		return fmt.Errorf("capsule: copy payload into the destination vault: %w", err)
	}
	after, err := params.Store.List(ctx, params.DestRepoDir, params.DestPassfile)
	if err != nil {
		return fmt.Errorf("capsule: list destination vault after copy: %w", err)
	}
	dstPayload, err := discoverCopiedPayload(before, after)
	if err != nil {
		return err
	}
	res.DestinationPayload = dstPayload

	// Everything from here on has created/mutated state in the
	// destination vault; a failure must roll back (step 12).
	created := []string{dstPayload}
	verifyErr := func() error {
		// ---- verify the destination payload (§11.4 gates) -----------
		if err := params.phase(PhaseVerifying); err != nil {
			return err
		}
		params.progress("import %s: verifying destination coverage and full content readback\n", params.OperationID)
		expected, readbackFiles := expectedTreeForEvidence(ev)
		ls, err := params.Store.Ls(ctx, params.DestRepoDir, params.DestPassfile, dstPayload)
		if err != nil {
			return fmt.Errorf("capsule: list destination payload: %w", err)
		}
		if err := lifecycle.VerifyCoverage(ls, expected, []string{ev.WsPrefix, ev.OpDirName}); err != nil {
			return asExportCheck(err)
		}
		if err := lifecycle.VerifyReadback(ctx, params.Store, params.DestRepoDir,
			params.DestPassfile, dstPayload, readbackFiles); err != nil {
			return asExportCheck(err)
		}

		// ---- NEW local seal in the destination vault ----------------
		params.progress("import %s: writing the local seal and reading it back\n", params.OperationID)
		sealID, werr := writeImportSeal(ctx, params, workDir, ev, dstPayload)
		// writeImportSeal returns the captured seal id whenever the
		// snapshot EXISTS, even on a readback failure — the rollback
		// below must be able to forget it (an id-less leak is worse
		// than a failed import).
		if sealID != "" {
			res.DestinationSeal = sealID
			created = append(created, sealID)
		}
		if werr != nil {
			return werr
		}
		return nil
	}()
	if verifyErr != nil {
		return rollbackDestination(ctx, params, created, verifyErr)
	}

	res.Checks = []string{checkCoverage, checkPayloadReadback, checkSealReadback, checkContainer}
	params.progress("import %s: payload %s and local seal %s registered in the destination vault\n",
		params.OperationID, dstPayload, res.DestinationSeal)
	return nil
}

// validateImportParams mirrors validateParams: caller-side mistakes
// are refused before anything is created.
func validateImportParams(p *ImportParams) error {
	switch {
	case p.Store == nil:
		return ErrInvalidParams("store seam is required")
	case p.CapsulePath == "":
		return ErrInvalidParams("capsule path is required")
	case p.Passphrase == "":
		return ErrInvalidParams("capsule passphrase is required")
	case p.DestRepoDir == "":
		return ErrInvalidParams("destination vault repo dir is required")
	case p.DestPassfile == "":
		return ErrInvalidParams("destination vault passfile is required")
	case p.DestRepoID == "":
		return ErrInvalidParams("destination repository id is required (resolve it with Store.RepoID)")
	case p.OperationID == "":
		return ErrInvalidParams("operation id is required")
	}
	abs, err := filepath.Abs(p.CapsulePath)
	if err != nil {
		return ErrInvalidParams(fmt.Sprintf("capsule path: %v", err))
	}
	p.CapsulePath = abs
	if fi, err := os.Stat(p.CapsulePath); err != nil {
		return ErrInvalidParams(fmt.Sprintf("capsule %s: %v", p.CapsulePath, err))
	} else if !fi.Mode().IsRegular() {
		return ErrInvalidParams(fmt.Sprintf("capsule %s is not a regular file", p.CapsulePath))
	}
	if fi, err := os.Stat(p.DestRepoDir); err != nil || !fi.IsDir() {
		return ErrInvalidParams(fmt.Sprintf("destination repository %s is not an existing directory", p.DestRepoDir))
	}
	return nil
}

// classifyCapsuleRepo enforces the fresh-capsule-repository contract:
// exactly one ebb-kind=payload and one ebb-kind=seal snapshot, both
// full 64-hex backend ids; zero payloads, duplicates of either kind,
// or any untagged snapshot refuse as ErrNotACapsule (D023 discipline:
// never resolve ambiguity, never guess).
func classifyCapsuleRepo(ctx context.Context, store Store, repoDir, passfile, capsulePath string) (payloadID, sealID string, err error) {
	refs, err := store.List(ctx, repoDir, passfile)
	if err != nil {
		return "", "", &ErrNotACapsule{Path: capsulePath, Details: []string{
			fmt.Sprintf("listing the extracted repository: %v", err)}}
	}
	var payloads, seals, untagged []string
	for _, r := range refs {
		switch r.Tags["ebb-kind"] {
		case "payload":
			payloads = append(payloads, r.BackendID)
		case "seal":
			seals = append(seals, r.BackendID)
		default:
			untagged = append(untagged, r.BackendID)
		}
	}
	refuse := func(detail string) error {
		return &ErrNotACapsule{Path: capsulePath, Details: []string{detail}}
	}
	switch {
	case len(untagged) > 0:
		sort.Strings(untagged)
		return "", "", refuse(fmt.Sprintf(
			"the extracted repository holds %d snapshot(s) without an ebb-kind tag (%s); a fresh capsule repository holds exactly one payload and one seal",
			len(untagged), strings.Join(untagged, ", ")))
	case len(payloads) == 0:
		return "", "", refuse("the extracted repository holds no ebb-kind=payload snapshot")
	case len(payloads) > 1:
		sort.Strings(payloads)
		return "", "", refuse(fmt.Sprintf(
			"the extracted repository holds %d ebb-kind=payload snapshots (%s); a fresh capsule repository holds exactly one",
			len(payloads), strings.Join(payloads, ", ")))
	case len(seals) == 0:
		return "", "", refuse("the extracted repository holds no ebb-kind=seal snapshot")
	case len(seals) > 1:
		sort.Strings(seals)
		return "", "", refuse(fmt.Sprintf(
			"the extracted repository holds %d ebb-kind=seal snapshots (%s); a fresh capsule repository holds exactly one",
			len(seals), strings.Join(seals, ", ")))
	}
	for _, pair := range [][2]string{{"payload", payloads[0]}, {"seal", seals[0]}} {
		if !isFullHex64(pair[1]) {
			return "", "", refuse(fmt.Sprintf(
				"the %s snapshot id %q is not a full 64-hex backend id", pair[0], pair[1]))
		}
	}
	return payloads[0], seals[0], nil
}

// readCapsuleSeal locates the capsule's destination-seal receipt BY
// TREE SHAPE (exactly one .ebb-seal-<32hex>/receipt.json file node —
// never a content search), dumps its bytes and strict-parses it. The
// seal directory's embedded operation id must equal the receipt's own
// operation id (the I13 shape rule restore's loadSeal applies to
// lifecycle receipts; the exporter writes them equal by construction).
func readCapsuleSeal(ctx context.Context, store Store, repoDir, passfile, sealID string) (destinationSeal, error) {
	ls, err := store.Ls(ctx, repoDir, passfile, sealID)
	if err != nil {
		return destinationSeal{}, &ErrVerification{Check: "capsule-seal", Details: []string{
			fmt.Sprintf("listing the capsule's seal snapshot %s: %v", sealID, err)}}
	}
	var receiptPath, dirOpID string
	matches := 0
	for _, e := range ls {
		if e.Kind != domain.KindFile {
			continue
		}
		dir, base := path.Split(strings.TrimPrefix(e.Path, "/"))
		if base != sealDocName {
			continue
		}
		id, ok := hexDirID(strings.TrimSuffix(dir, "/"))
		if !ok {
			continue
		}
		matches++
		receiptPath, dirOpID = e.Path, id
	}
	switch {
	case matches == 0:
		return destinationSeal{}, &ErrVerification{Check: "capsule-seal", Details: []string{
			fmt.Sprintf("no %s<32hex>/%s node found in the capsule's seal snapshot %s", sealDirPrefix, sealDocName, sealID)}}
	case matches > 1:
		return destinationSeal{}, &ErrVerification{Check: "capsule-seal", Details: []string{
			fmt.Sprintf("%d candidate receipt nodes in the capsule's seal snapshot %s; the seal is ambiguous", matches, sealID)}}
	}
	raw, err := store.DumpFile(ctx, repoDir, passfile, sealID, receiptPath)
	if err != nil {
		return destinationSeal{}, &ErrVerification{Check: "capsule-seal", Details: []string{
			fmt.Sprintf("reading the capsule seal receipt %s: %v", receiptPath, err)}}
	}
	seal, err := parseDestinationSeal(raw)
	if err != nil {
		return destinationSeal{}, &ErrVerification{Check: "capsule-seal", Details: []string{err.Error()}}
	}
	if seal.OperationID != dirOpID {
		return destinationSeal{}, &ErrVerification{Check: "capsule-seal", Details: []string{
			fmt.Sprintf("the seal receipt's operation_id %q does not match the id embedded in its seal directory %q",
				seal.OperationID, dirOpID)}}
	}
	return seal, nil
}

// hexDirID validates and returns the operation id embedded in a
// .ebb-seal-<32hex> directory name ("" , false when the name is not
// that shape).
func hexDirID(name string) (string, bool) {
	id, ok := strings.CutPrefix(name, sealDirPrefix)
	if !ok || !isHex32(id) {
		return "", false
	}
	return id, true
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// isFullHex64 reports whether s is a full 64-hex-character backend
// snapshot id (restic prints full ids in --json listings; anything
// shorter is a short id and never a usable identity).
func isFullHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// discoverCopiedPayload finds the ONE new backend id the copy created
// in the destination vault. Zero new ids means restic silently skipped
// the copy (probe C10: copying a missing id exits 0!) — an unprovable
// copy refuses; more than one is ambiguous discovery. The discovered
// id's tags must still say ebb-kind=payload (copy preserves tags,
// probe C2/C3).
func discoverCopiedPayload(before, after []domain.SnapshotRef) (string, error) {
	seenBefore := make(map[string]bool, len(before))
	for _, r := range before {
		seenBefore[r.BackendID] = true
	}
	tags := make(map[string]map[string]string, len(after))
	var newIDs []string
	for _, r := range after {
		if seenBefore[r.BackendID] {
			continue
		}
		newIDs = append(newIDs, r.BackendID)
		tags[r.BackendID] = r.Tags
	}
	switch {
	case len(newIDs) == 1:
		id := newIDs[0]
		if tags[id]["ebb-kind"] != "payload" {
			return "", &ErrCopyIntegrity{Details: []string{
				fmt.Sprintf("the copy created snapshot %s, but its ebb-kind tag is %q (expected \"payload\")", id, tags[id]["ebb-kind"])}}
		}
		return id, nil
	case len(newIDs) == 0:
		return "", &ErrCopyIntegrity{Details: []string{
			"the destination vault holds no new snapshot after the copy — restic copy can skip silently (a nonexistent source id exits 0), so the copy could not be proven"}}
	default:
		sort.Strings(newIDs)
		return "", &ErrCopyIntegrity{Details: []string{
			fmt.Sprintf("the copy created %d new snapshots (%s); exactly one was expected and ambiguity is never resolved",
				len(newIDs), strings.Join(newIDs, ", "))}}
	}
}

// rollbackDestination is the step-12 controlled-failure hygiene: forget
// everything this import created in the destination vault and VERIFY
// by List that it is gone (D015 lesson: forget of a nonexistent id
// exits 0 silently — only the listing proves removal). Any failure of
// the rollback itself is appended to the returned error honestly; a
// leaked backend id is never hidden.
func rollbackDestination(ctx context.Context, params *ImportParams, created []string, cause error) error {
	if len(created) == 0 {
		return cause
	}
	sort.Strings(created)
	names := strings.Join(created, ", ")
	if ferr := params.Store.Forget(ctx, params.DestRepoDir, params.DestPassfile, created); ferr != nil {
		return fmt.Errorf(
			"%w — ROLLBACK FAILED: backend snapshot(s) %s may remain in the destination vault (forget: %v); inspect and remove them explicitly",
			cause, names, ferr)
	}
	refs, lerr := params.Store.List(ctx, params.DestRepoDir, params.DestPassfile)
	if lerr != nil {
		return fmt.Errorf(
			"%w — rollback forget succeeded but could not be VERIFIED (listing the destination vault: %v); backend snapshot(s) %s may remain; inspect them explicitly",
			cause, lerr, names)
	}
	var leaked []string
	for _, r := range refs {
		for _, id := range created {
			if r.BackendID == id {
				leaked = append(leaked, id)
			}
		}
	}
	if len(leaked) > 0 {
		return fmt.Errorf(
			"%w — ROLLBACK INCOMPLETE: %s still listed in the destination vault after forget; inspect and remove explicitly",
			cause, strings.Join(leaked, ", "))
	}
	return cause
}

// asCapsuleEvidence re-expresses the shared evidence core's refusal as
// the capsule's named-check error (the underlying detail lines are
// preserved verbatim; non-verification infra errors pass through).
func asCapsuleEvidence(err error) error {
	var rv *restore.ErrVerification
	if errors.As(err, &rv) {
		return &ErrVerification{Check: "capsule-" + rv.Check, Details: rv.Details}
	}
	return err
}

// ---- the local import seal (lifecycle's §16.4 receiptDoc) -------------

// Named checks recorded on the import seal (§16.4: a verification
// result names its checks — only the checks ACTUALLY performed before
// the seal snapshot was written; "container-verified" is the
// verifyPackage structural + totals gate every import ran in its
// preflight).
const (
	checkContainer = "container-verified"
	importScope    = "capsule-import"
	// opDirPrefix is the payload's frozen op-dir prefix (lifecycle's
	// shape, D003): ".ebb-op-<32hex>".
	opDirPrefix = ".ebb-op-"
)

// importReceiptDoc is lifecycle's §16.4 seal-receipt wire form
// (internal/lifecycle/manifest.go receiptDoc), re-declared here as a
// LOCAL STRICT WRITER — the same cross-package frozen-format contract
// internal/restore uses as a reader: the writer of record is
// lifecycle's, and any drift between the two is caught by the golden
// test that pins this document's field names against a receipt
// lifecycle itself wrote. capsule must not import the removal-authority
// package's writers, only its exported verification executors.
type importReceiptDoc struct {
	SchemaVersion    int              `json:"schema_version"`
	SnapshotID       string           `json:"snapshot_id"`
	WorkspaceID      string           `json:"workspace_id"`
	BackendRepoID    string           `json:"backend_repo_id"`
	PayloadBackendID string           `json:"payload_backend_id"`
	ManifestDigest   string           `json:"manifest_digest"`
	InventoryDigest  string           `json:"inventory_digest"`
	RequiredFeatures []string         `json:"required_features"`
	Verification     sealVerification `json:"verification"`
	OperationID      string           `json:"operation_id"`
	Retention        string           `json:"retention"`
}

// buildImportReceipt assembles the receipt. Field values: the LOGICAL
// identities from the payload's own manifest, the DESTINATION vault's
// repository id and the DISCOVERED destination payload id, the
// re-derived digests, and only the checks the import actually
// performed. Retention is pinned (import never implies forget).
func buildImportReceipt(ev restore.Evidence, dstRepoID, dstPayloadID, opID string, at time.Time, checks []string, ebbVersion string) importReceiptDoc {
	tools := map[string]string{"ebb-capsule": ProducerEbb}
	if ebbVersion != "" {
		tools["ebb"] = ebbVersion
	}
	return importReceiptDoc{
		SchemaVersion:    sealSchemaVersion,
		SnapshotID:       string(ev.SnapshotID),
		WorkspaceID:      string(ev.WorkspaceID),
		BackendRepoID:    dstRepoID,
		PayloadBackendID: dstPayloadID,
		ManifestDigest:   ev.Manifest.ManifestDigest,
		InventoryDigest:  ev.Manifest.InventoryDigest,
		RequiredFeatures: []string{},
		Verification: sealVerification{
			Checks: checks, Scope: importScope,
			Time: at.UTC().Format(time.RFC3339Nano), ToolVersions: tools,
		},
		OperationID: opID,
		Retention:   "pinned",
	}
}

// marshalImportReceipt serializes strictly (the bytes captured into
// the destination vault are the bytes read back byte-exact).
func marshalImportReceipt(d importReceiptDoc) ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("capsule: marshal import receipt: %w", err)
	}
	return append(b, '\n'), nil
}

// captureOpID derives the CAPTURE's operation id from the payload's
// frozen op dir name (".ebb-op-<32hex>", located by tree shape when the
// evidence was loaded and bound to the manifest's own meta-root claim).
// The local import seal must record THIS id — not the import's own
// transport op id — because every lifecycle-shaped receipt consumer
// (restore's loadSeal→loadDocuments, discovery's requireOpDir)
// re-derives the payload's frozen op dir from the RECEIPT's operation_id
// field: with the capture's id in the seal dir name, the receipt's
// operation_id and the ebb-op tag, the I13 dir==receipt rule holds for
// the imported pair exactly as for a native capture.
func captureOpID(ev restore.Evidence) (domain.OperationID, error) {
	id, ok := strings.CutPrefix(ev.OpDirName, opDirPrefix)
	if !ok || !isHex32(id) {
		return "", &ErrVerification{Check: "capsule-documents", Details: []string{
			fmt.Sprintf("the payload's frozen op dir %q is not %s<32hex>; the local seal cannot record the capture's operation id",
				ev.OpDirName, opDirPrefix)}}
	}
	return domain.OperationID(id), nil
}

// writeImportSeal stages the receipt under the owned working dir,
// captures it as a small snapshot in the DESTINATION vault
// (cwd-relative, the D003 shape writeDestinationSeal uses) and reads
// it back byte-exact. The seal carries the CAPTURE's operation id (see
// captureOpID) in its staging-dir name, its operation_id field and its
// ebb-op tag — the import's own operation id names only the transport
// working dir. The returned id is non-empty whenever the seal SNAPSHOT
// exists — including the readback-failure returns — so the caller's
// rollback can forget it.
func writeImportSeal(ctx context.Context, params *ImportParams, workDir string, ev restore.Evidence, dstPayloadID string) (string, error) {
	capOpID, err := captureOpID(ev)
	if err != nil {
		return "", err
	}
	sealDir := filepath.Join(workDir, sealDirPrefix+string(capOpID))
	if err := os.MkdirAll(sealDir, 0o700); err != nil {
		return "", fmt.Errorf("capsule: seal staging dir: %w", err)
	}
	receipt := buildImportReceipt(ev, params.DestRepoID, dstPayloadID,
		string(capOpID), params.now(),
		[]string{checkCoverage, checkPayloadReadback, checkSealReadback, checkContainer}, params.EbbVersion)
	sealBytes, err := marshalImportReceipt(receipt)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(sealDir, sealDocName), sealBytes, 0o600); err != nil {
		return "", fmt.Errorf("capsule: write import receipt: %w", err)
	}
	ref, err := params.Store.Snapshot(ctx, params.DestRepoDir, filepath.Dir(sealDir),
		[]string{filepath.Base(sealDir)}, params.DestPassfile, map[string]string{
			"ebb-op":   string(capOpID),
			"ebb-kind": "seal",
			"ws":       string(ev.WorkspaceID),
		})
	if err != nil {
		return "", fmt.Errorf("capsule: capture import seal: %w", err)
	}
	// Seal readback: dump the receipt and compare the exact bytes.
	treePath := "/" + filepath.Base(sealDir) + "/" + sealDocName
	got, err := params.Store.DumpFile(ctx, params.DestRepoDir, params.DestPassfile, ref.BackendID, treePath)
	if err != nil {
		return ref.BackendID, fmt.Errorf("capsule: import seal readback: %w", err)
	}
	if !bytes.Equal(got, sealBytes) {
		return ref.BackendID, &ErrVerification{Check: checkSealReadback, Details: []string{
			fmt.Sprintf("import seal bytes read back differ from written bytes (%d vs %d bytes)", len(got), len(sealBytes))}}
	}
	return ref.BackendID, nil
}
