// Package capsule produces Ebb's portable recovery capsules (Foundation
// §15): a ZIP64 container of STORED entries holding a FRESH, independent
// restic repository that contains ONLY the selected payload snapshot
// plus a NEW destination seal, verified end to end before publication.
//
// The export protocol (§15.2) implemented by Export:
//
//	init a new private repository under a new independent passphrase
//	→ copy the payload snapshot through the backend (ids change; the
//	  destination payload id is DISCOVERED by tags, never assumed, R38)
//	→ verify destination coverage + full content readback against the
//	  ORIGINAL retained inventory digests (the same lifecycle gates the
//	  capture itself used — shared executors, no reimplementation)
//	→ write a NEW destination seal whose receipt records the source
//	  logical identity + source manifest digest (§16.4) and the
//	  destination repo/payload ids (F43), then read it back byte-exact
//	→ prove the encryption domain is independent (the SOURCE passphrase
//	  must FAIL to open the destination repository)
//	→ package the complete repository into <output>.partial
//	→ re-open the package with a fresh reader, validate it structurally,
//	  extract it, and open the extracted repository read-only: list the
//	  snapshots, re-read the seal, and confirm the payload manifest
//	  digest equals the source's
//	→ publish by no-clobber rename to the final output path
//
// The source snapshot is never modified, forgotten, or even re-pinned
// here: taking and releasing the duration pin is the caller's (CLI)
// job — this package has NO deletion authority outside its own
// working/partial artifacts.
//
// The generated capsule passphrase is the user's recovery secret. It is
// returned in Result for one-time display by the CLI and must NEVER be
// written to a log, envelope, or persistent store by any caller.
package capsule

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/lifecycle"
	"github.com/0Cymantek0/ebb/internal/restore"
)

// Store is the storage seam capsule needs: the common snapshot-store
// contract plus the cross-repository copy capability (interface-
// segregated the way domain.TreeTarDumper is; satisfied by
// *resticstore.Store, substitutable by fakes in tests).
type Store interface {
	domain.SnapshotStore
	Copy(ctx context.Context, srcRepoDir, srcPassfile, dstRepoDir, dstPassfile string, snapIDs []string) error
}

// Export step names reported through Params.Phase (the CLI maps them to
// its durable journal transitions).
const (
	PhaseCopying   = "copying"   // destination repo initialized; payload copy in flight
	PhaseVerifying = "verifying" // destination coverage/readback/seal in flight
	PhasePackaging = "packaging" // container write + package verification in flight
)

// Params parameterizes one export.
type Params struct {
	// Store is the backend (required).
	Store Store
	// Snapshot is the source snapshot's catalog row (required; the CLI
	// has already refused trim/seal kinds and unsealed payloads).
	Snapshot catalog.Snapshot
	// Evidence is the source's retained evidence, loaded and
	// digest-verified by the caller through restore.LoadRetainedEvidence
	// (which cross-checks the catalog row — the D020 witness binding).
	Evidence restore.Evidence
	// SourceRepoDir / SourcePassfile locate the source vault for the
	// copy and the independence check; SourceRepoID is the source
	// vault's backend repository identity (the caller resolves it once
	// through Store.RepoID — the catalog's vault id is a one-way digest).
	SourceRepoDir  string
	SourcePassfile string
	SourceRepoID   string
	// OutputPath is the final capsule path; the partial lives beside it
	// as OutputPath+".partial" so publication is a same-volume rename.
	OutputPath string
	// OperationID journals this export (also recorded in the destination
	// seal receipt and the partial's identification manifest).
	OperationID domain.OperationID
	// Phase is an optional journal hook invoked at each step boundary.
	Phase func(step string) error
	// Progress receives human progress lines (stderr in the CLI).
	Progress io.Writer
	// Clock is injectable; defaults to time.Now.
	Clock func() time.Time
	// EbbVersion labels the produced documents (CLI's Version).
	EbbVersion string
}

// Result reports one completed export. Passphrase is the capsule's
// recovery secret: display it ONCE, never serialize it.
type Result struct {
	OutputPath          string
	CapsuleBytes        int64
	PayloadLogicalBytes int64 // source preserved bytes (informational)
	DestinationRepoID   string
	DestinationPayload  string
	DestinationSeal     string
	Passphrase          string
	Checks              []string // the named checks the destination seal recorded
	Warnings            []string
}

func (p *Params) now() time.Time {
	if p.Clock != nil {
		return p.Clock()
	}
	return time.Now()
}

func (p *Params) progress(format string, a ...any) {
	if p.Progress != nil {
		fmt.Fprintf(p.Progress, format, a...)
	}
}

func (p *Params) phase(step string) error {
	if p.Phase == nil {
		return nil
	}
	return p.Phase(step)
}

// Export runs the full §15.2 protocol. On any error nothing is
// published: the partial and the working directory are removed (the
// package's own artifacts only), and the source snapshot is untouched.
// A crash between steps can leave the partial behind — it carries the
// ebb-export.json identification manifest, and the next export to the
// same output path refuses until it is explicitly removed.
func Export(ctx context.Context, params Params) (Result, error) {
	if err := validateParams(&params); err != nil {
		return Result{}, err
	}

	outDir := filepath.Dir(params.OutputPath)
	partialPath := params.OutputPath + ".partial"
	workDir := filepath.Join(outDir, ".ebb-export-"+string(params.OperationID))
	startedAt := params.now()

	// Own-artifact cleanup: on failure remove partial + work dir; on
	// success remove the work dir only (the capsule is the artifact).
	// Everything this package removes lives under these two names.
	published := false
	defer func() {
		_ = os.RemoveAll(workDir)
		if !published {
			_ = os.Remove(partialPath)
		}
	}()

	res := Result{OutputPath: params.OutputPath}
	if fi, err := os.Stat(params.SourceRepoDir); err != nil || !fi.IsDir() {
		return Result{}, ErrInvalidParams(fmt.Sprintf("source repository %s is not an existing directory", params.SourceRepoDir))
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("capsule: create working dir: %w", err)
	}

	passphrase, err := GeneratePassphrase()
	if err != nil {
		return Result{}, err
	}

	repoDir := filepath.Join(workDir, repoPrefix)
	sealDir := filepath.Join(workDir, sealDirPrefix+string(params.OperationID))

	err = ephemeralPassfile(workDir, passphrase, func(dstPassfile string) error {
		// ---- §15.2: fresh destination repository, new key material ----
		params.progress("export %s: initializing a fresh independent repository\n", params.OperationID)
		if err := os.MkdirAll(repoDir, 0o700); err != nil {
			return fmt.Errorf("capsule: create destination repo dir: %w", err)
		}
		if err := params.Store.Init(ctx, repoDir, dstPassfile); err != nil {
			return fmt.Errorf("capsule: init destination repository: %w", err)
		}
		dstRepoID, err := params.Store.RepoID(ctx, repoDir, dstPassfile)
		if err != nil {
			return fmt.Errorf("capsule: destination repository identity: %w", err)
		}
		res.DestinationRepoID = dstRepoID

		if err := params.phase(PhaseCopying); err != nil {
			return err
		}

		// ---- copy ONLY the payload; the old seal is never copied ------
		params.progress("export %s: copying the payload snapshot (ids may change; the destination id is discovered)\n", params.OperationID)
		if err := params.Store.Copy(ctx, params.SourceRepoDir, params.SourcePassfile, repoDir, dstPassfile,
			[]string{params.Snapshot.PayloadBackendID}); err != nil {
			return fmt.Errorf("capsule: copy payload: %w", err)
		}
		dstPayloadID, err := discoverPayload(ctx, params.Store, repoDir, dstPassfile, params.Snapshot.PayloadBackendID)
		if err != nil {
			return err
		}
		res.DestinationPayload = dstPayloadID

		if err := params.phase(PhaseVerifying); err != nil {
			return err
		}

		// ---- destination coverage + content readback (§11.4 gates) ----
		expected, readbackFiles := expectedDestinationTree(&params)
		ls, err := params.Store.Ls(ctx, repoDir, dstPassfile, dstPayloadID)
		if err != nil {
			return fmt.Errorf("capsule: list destination payload: %w", err)
		}
		if err := lifecycle.VerifyCoverage(ls, expected, []string{params.Evidence.WsPrefix, params.Evidence.OpDirName}); err != nil {
			return asExportCheck(err)
		}
		if err := lifecycle.VerifyReadback(ctx, params.Store, repoDir, dstPassfile, dstPayloadID, readbackFiles); err != nil {
			return asExportCheck(err)
		}

		// ---- NEW destination seal (§16.4/F43), read back byte-exact ---
		dstSealID, sealBytes, err := writeDestinationSeal(ctx, &params, repoDir, sealDir, dstPassfile, dstRepoID, dstPayloadID)
		if err != nil {
			return err
		}
		res.DestinationSeal = dstSealID

		// ---- independent-encryption-domain check (§13.1) --------------
		// The SOURCE passphrase must FAIL against the destination repo.
		if _, serr := params.Store.RepoID(ctx, repoDir, params.SourcePassfile); serr == nil {
			return &ErrVerification{Check: checkIndependence, Details: []string{
				"the source vault passphrase successfully opened the destination repository; the capsule would not be an independent encryption domain — refusing to publish"}}
		} else {
			var se *domain.StoreError
			if !errors.As(serr, &se) || se.Class != domain.StoreErrAuth {
				return fmt.Errorf("capsule: independence check: %w", serr)
			}
		}

		if err := params.phase(PhasePackaging); err != nil {
			return err
		}

		// ---- package + strong verification before publication ---------
		params.progress("export %s: packaging and verifying the container\n", params.OperationID)
		size, err := writePackage(partialPath, repoDir, formatTime(startedAt), string(params.OperationID), string(params.Snapshot.ID), params.producerLabel())
		if err != nil {
			return err
		}
		res.CapsuleBytes = size
		check, err := verifyPackage(partialPath)
		if err != nil {
			return err
		}
		extractDir := filepath.Join(workDir, "extracted")
		if err := extractRepository(partialPath, extractDir, check.ExportDoc.RepoBytes); err != nil {
			return err
		}
		if err := verifyExtractedRepo(ctx, &params, extractDir, dstPassfile, dstRepoID, dstPayloadID, dstSealID, sealBytes); err != nil {
			return err
		}

		// ---- no-clobber publication ----------------------------------
		if _, serr := os.Lstat(params.OutputPath); serr == nil {
			return &ErrOutputOccupied{Path: params.OutputPath}
		} else if !errors.Is(serr, os.ErrNotExist) {
			return fmt.Errorf("capsule: inspect output path: %w", serr)
		}
		if err := os.Rename(partialPath, params.OutputPath); err != nil {
			return fmt.Errorf("capsule: publish capsule: %w", err)
		}
		published = true
		res.Passphrase = passphrase
		res.PayloadLogicalBytes = params.Evidence.PreservedBytes
		res.Checks = []string{checkCoverage, checkPayloadReadback, checkIndependence, checkSealReadback}
		params.progress("export %s: capsule published at %s\n", params.OperationID, params.OutputPath)
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// asExportCheck re-expresses a failed shared lifecycle §11.4 gate as
// the capsule's named-check error so every export failure carries the
// uniform check vocabulary (the underlying details are preserved
// verbatim; non-verification infra errors pass through unchanged).
func asExportCheck(err error) error {
	var lv *lifecycle.ErrVerification
	if errors.As(err, &lv) {
		return &ErrVerification{Check: "destination-" + lv.Check, Details: lv.Details}
	}
	return err
}

func (p *Params) producerLabel() string {
	if p.EbbVersion != "" {
		return "ebb " + p.EbbVersion
	}
	return ProducerEbb
}

// digestOf is the byte-exact SHA-256 hex digest (§16.1: hash the
// stored bytes, never a re-serialized copy).
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func validateParams(p *Params) error {
	switch {
	case p.Store == nil:
		return ErrInvalidParams("store seam is required")
	case p.Snapshot.ID == "":
		return ErrInvalidParams("snapshot is required")
	case p.Snapshot.PayloadBackendID == "" || p.Snapshot.SealBackendID == "":
		return ErrInvalidParams("snapshot must be sealed (payload and seal backend ids)")
	case p.Evidence.SnapshotID == "" || p.Evidence.Manifest.ManifestDigest == "":
		return ErrInvalidParams("retained evidence is required (load it with restore.LoadRetainedEvidence)")
	case p.Evidence.WsPrefix == "" || p.Evidence.OpDirName == "":
		return ErrInvalidParams("evidence tree prefixes are required")
	case p.SourceRepoDir == "" || p.SourcePassfile == "":
		return ErrInvalidParams("source vault repo dir and passfile are required")
	case p.SourceRepoID == "":
		return ErrInvalidParams("source repository id is required (resolve it with Store.RepoID)")
	case p.OperationID == "":
		return ErrInvalidParams("operation id is required")
	}
	if p.OutputPath == "" {
		return ErrInvalidParams("output path is required")
	}
	abs, err := filepath.Abs(p.OutputPath)
	if err != nil {
		return ErrInvalidParams(fmt.Sprintf("output path: %v", err))
	}
	p.OutputPath = abs
	outDir := filepath.Dir(abs)
	if fi, err := os.Stat(outDir); err != nil || !fi.IsDir() {
		return ErrInvalidParams(fmt.Sprintf("output directory %s does not exist (create it first)", outDir))
	}
	if _, err := os.Lstat(p.OutputPath); err == nil {
		return &ErrOutputOccupied{Path: p.OutputPath}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidParams(fmt.Sprintf("inspect output path: %v", err))
	}
	if _, err := os.Lstat(p.OutputPath + ".partial"); err == nil {
		return &ErrPartialExists{Path: p.OutputPath + ".partial"}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrInvalidParams(fmt.Sprintf("inspect partial path: %v", err))
	}
	return nil
}

// discoverPayload finds the copied payload snapshot in the destination
// repository. Copy preserves the source tags (probe C2/C3), so the
// discovery key is the Ebb tag set; the fresh repo must hold EXACTLY
// ONE ebb-kind=payload snapshot — zero means restic silently skipped
// the copy (probe C10: copy of a missing id exits 0!), more than one
// means the repo was not fresh.
func discoverPayload(ctx context.Context, store Store, repoDir, passfile, srcPayloadID string) (string, error) {
	refs, err := store.List(ctx, repoDir, passfile)
	if err != nil {
		return "", fmt.Errorf("capsule: list destination repository: %w", err)
	}
	var payloads []string
	for _, r := range refs {
		if r.Tags["ebb-kind"] == "payload" {
			payloads = append(payloads, r.BackendID)
		}
	}
	switch {
	case len(payloads) == 1:
		// Probe C2 pinned that ids CAN change on copy (and did live);
		// discovery never depends on id equality either way.
		return payloads[0], nil
	case len(payloads) == 0:
		return "", &ErrVerification{Check: checkCoverage, Details: []string{
			fmt.Sprintf("the destination repository holds no ebb-kind=payload snapshot after copying %s (restic copy can skip silently; nothing was copied)", srcPayloadID)}}
	default:
		return "", &ErrVerification{Check: checkCoverage, Details: []string{
			fmt.Sprintf("the destination repository holds %d payload snapshots; a fresh capsule repo must hold exactly one", len(payloads))}}
	}
}

// expectedDestinationTree derives the §11.4 expectation for the
// DESTINATION payload from the source's retained evidence — the same
// pure derivation `ebb verify` uses (lifecycle.ExpectedTreeFor), plus
// the op-dir documents with their digest-gated lengths.
func expectedDestinationTree(p *Params) (map[string]lifecycle.ExpectedNode, []lifecycle.ReadbackFile) {
	return expectedTreeForEvidence(p.Evidence)
}

// expectedTreeForEvidence is the evidence-shaped core of
// expectedDestinationTree, shared by Export (source retained evidence)
// and Import (capsule-re-derived evidence) so both transports verify a
// destination payload against ONE derivation — a re-verification that
// disagreed with the capture's own would be vacuous (Learnings, Wave D).
func expectedTreeForEvidence(ev restore.Evidence) (map[string]lifecycle.ExpectedNode, []lifecycle.ReadbackFile) {
	expected, readback := lifecycle.ExpectedTreeFor(ev.Retained, ev.WsPrefix)
	addDoc := func(name string, length int64, digest string) {
		path := "/" + ev.OpDirName + "/" + name
		segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
		for i := 1; i < len(segs); i++ {
			expected["/"+strings.Join(segs[:i], "/")] = lifecycle.ExpectedNode{Kind: domain.KindDir}
		}
		expected[path] = lifecycle.ExpectedNode{Kind: domain.KindFile, Size: length}
		readback = append(readback, lifecycle.ReadbackFile{SnapPath: path, Digest: digest})
	}
	addDoc("manifest.json", ev.Manifest.ManifestBytes, ev.Manifest.ManifestDigest)
	addDoc(ev.Manifest.InventoryPath, ev.Manifest.InventoryBytes, ev.Manifest.InventoryDigest)
	addDoc("policy.toml", ev.Manifest.PolicyBytes, ev.Manifest.PolicyDigest)
	return expected, readback
}

// writeDestinationSeal stages the receipt, captures it as a small
// snapshot in the DESTINATION repository (cwd-relative, D003 shape) and
// reads it back byte-exact — the same discipline as the source seal.
func writeDestinationSeal(ctx context.Context, p *Params, repoDir, sealDir, passfile, dstRepoID, dstPayloadID string) (sealID string, sealBytes []byte, err error) {
	if err := os.MkdirAll(sealDir, 0o700); err != nil {
		return "", nil, fmt.Errorf("capsule: seal staging dir: %w", err)
	}
	seal := buildDestinationSeal(
		string(p.Snapshot.ID), string(p.Snapshot.WorkspaceID),
		p.SourceRepoID, p.Snapshot.PayloadBackendID,
		dstRepoID, dstPayloadID,
		p.Evidence.Manifest.ManifestDigest, p.Evidence.Manifest.InventoryDigest,
		string(p.OperationID), p.now(),
		[]string{checkCoverage, checkPayloadReadback, checkIndependence},
		p.EbbVersion,
	)
	sealBytes, err = marshalSealDoc(seal)
	if err != nil {
		return "", nil, err
	}
	if err := os.WriteFile(filepath.Join(sealDir, sealDocName), sealBytes, 0o600); err != nil {
		return "", nil, fmt.Errorf("capsule: write destination seal: %w", err)
	}
	ref, err := p.Store.Snapshot(ctx, repoDir, filepath.Dir(sealDir), []string{filepath.Base(sealDir)}, passfile, map[string]string{
		"ebb-op":   string(p.OperationID),
		"ebb-kind": "seal",
		"ws":       string(p.Snapshot.WorkspaceID),
	})
	if err != nil {
		return "", nil, fmt.Errorf("capsule: capture destination seal: %w", err)
	}
	// Seal readback: dump the receipt and compare the exact bytes.
	treePath := "/" + filepath.Base(sealDir) + "/" + sealDocName
	got, err := p.Store.DumpFile(ctx, repoDir, passfile, ref.BackendID, treePath)
	if err != nil {
		return "", nil, fmt.Errorf("capsule: destination seal readback: %w", err)
	}
	if string(got) != string(sealBytes) {
		return "", nil, &ErrVerification{Check: checkSealReadback, Details: []string{
			fmt.Sprintf("destination seal bytes read back differ from written bytes (%d vs %d bytes)", len(got), len(sealBytes))}}
	}
	return ref.BackendID, sealBytes, nil
}

// verifyExtractedRepo is the strong pre-publication check: open the
// repository EXTRACTED FROM THE PACKAGE (not the pre-package original)
// read-only with the generated passphrase and confirm the identity
// chain: same repo id, exactly the payload+seal pair, the seal receipt
// strict-parses and names the destination ids, and the payload's
// manifest/inventory documents still hash to the SOURCE digests.
func verifyExtractedRepo(ctx context.Context, p *Params, extractedRepo, passfile, dstRepoID, dstPayloadID, dstSealID string, wantSealBytes []byte) error {
	gotRepoID, err := p.Store.RepoID(ctx, extractedRepo, passfile)
	if err != nil {
		return fmt.Errorf("capsule: open extracted repository: %w", err)
	}
	if gotRepoID != dstRepoID {
		return &ErrVerification{Check: "container-extraction", Details: []string{
			fmt.Sprintf("extracted repository id %s differs from the packaged repository id %s", gotRepoID, dstRepoID)}}
	}
	refs, err := p.Store.List(ctx, extractedRepo, passfile)
	if err != nil {
		return fmt.Errorf("capsule: list extracted repository: %w", err)
	}
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.BackendID)
	}
	sort.Strings(ids)
	want := []string{dstPayloadID, dstSealID}
	sort.Strings(want)
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		return &ErrVerification{Check: "container-extraction", Details: []string{
			fmt.Sprintf("extracted repository holds snapshots %v; expected exactly the destination pair %v", ids, want)}}
	}
	// Re-read the seal from the extracted repository.
	treePath := "/" + sealDirPrefix + string(p.OperationID) + "/" + sealDocName
	sealRaw, err := p.Store.DumpFile(ctx, extractedRepo, passfile, dstSealID, treePath)
	if err != nil {
		return fmt.Errorf("capsule: extracted seal readback: %w", err)
	}
	if string(sealRaw) != string(wantSealBytes) {
		return &ErrVerification{Check: checkSealReadback, Details: []string{
			"the seal receipt inside the packaged capsule differs from the receipt written before packaging"}}
	}
	seal, err := parseDestinationSeal(sealRaw)
	if err != nil {
		return err
	}
	if seal.PayloadBackendID != dstPayloadID || seal.BackendRepoID != dstRepoID {
		return &ErrVerification{Check: checkSealReadback, Details: []string{
			fmt.Sprintf("extracted seal names repo %s / payload %s; expected %s / %s (F43: destination ids)",
				seal.BackendRepoID, seal.PayloadBackendID, dstRepoID, dstPayloadID)}}
	}
	if seal.Source.ManifestDigest != p.Evidence.Manifest.ManifestDigest {
		return &ErrVerification{Check: checkSealReadback, Details: []string{
			fmt.Sprintf("extracted seal's source manifest digest %s differs from the source evidence digest %s", seal.Source.ManifestDigest, p.Evidence.Manifest.ManifestDigest)}}
	}
	// Confirm the payload manifest digest matches the source's, from the
	// packaged artifact itself.
	manifestRaw, err := p.Store.DumpFile(ctx, extractedRepo, passfile, dstPayloadID, "/"+p.Evidence.OpDirName+"/manifest.json")
	if err != nil {
		return fmt.Errorf("capsule: extracted payload manifest readback: %w", err)
	}
	if got := digestOf(manifestRaw); got != p.Evidence.Manifest.ManifestDigest {
		return &ErrVerification{Check: "container-extraction", Details: []string{
			fmt.Sprintf("packaged payload manifest digest %s differs from the source manifest digest %s", got, p.Evidence.Manifest.ManifestDigest)}}
	}
	invRaw, err := p.Store.DumpFile(ctx, extractedRepo, passfile, dstPayloadID, "/"+p.Evidence.OpDirName+"/"+p.Evidence.Manifest.InventoryPath)
	if err != nil {
		return fmt.Errorf("capsule: extracted payload inventory readback: %w", err)
	}
	if got := digestOf(invRaw); got != p.Evidence.Manifest.InventoryDigest {
		return &ErrVerification{Check: "container-extraction", Details: []string{
			fmt.Sprintf("packaged payload inventory digest %s differs from the source inventory digest %s", got, p.Evidence.Manifest.InventoryDigest)}}
	}
	return nil
}
