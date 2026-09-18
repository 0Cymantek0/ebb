// rebuild_catalog.go implements `ebb init --rebuild-catalog` (Foundation
// §11.5, §16.5; acceptance gate F39): when the local catalog is lost or
// corrupt but a registered vault (and its unlock secret) remains, rebuild
// a working catalog from vault discovery. The command NEVER deletes or
// drops anything: workspaces and snapshots are imported additively via
// catalog.ImportDiscoveredSnapshot, every reconstructed workspace is
// UNBOUND (a seal proves a retained snapshot exists, not that the source
// was removed), and every snapshot is pinned (I07 — absence of pin
// records can never license release). An existing non-empty catalog is
// refused without --force-rebuild, and even then the rebuild only
// MERGES: duplicates are reported, rows are never overwritten in their
// identity-bearing fields (the import's ON CONFLICT clauses refresh
// backend facts only).
//
// Exit contract: 0 with a rebuilt catalog; 2 usage (unwired seams, flag
// mistakes); 3 blocked (non-empty catalog without --force-rebuild); 4 the
// vault itself failed verification after a working unlock (the discovery
// walk could not trust what it read); 7 vault resolution/unlock failures
// (existing init classes).

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ebb/internal/catalog"
	"ebb/internal/domain"
	"ebb/internal/restore"
	"ebb/internal/vault"
)

// CodeRebuildNeedsForce is the §5.5 code for refusing to rebuild over an
// existing non-empty catalog without the explicit --force-rebuild.
const CodeRebuildNeedsForce = "EBB_E_REBUILD_NEEDS_FORCE"

// rebuildWorkspace is one reconstructed workspace in the report.
type rebuildWorkspace struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"` // always UNBOUND (§16.5)
	Snapshots int    `json:"snapshots"`
	// Kinds summarizes the adopted snapshot kinds (park/trim/snapshot).
	Kinds []string `json:"kinds,omitempty"`
}

// rebuildUnsealed is one unsealed payload recorded pinned-not-adopted.
type rebuildUnsealed struct {
	SnapshotID       string `json:"snapshot_id"`
	WorkspaceID      string `json:"workspace_id"`
	PayloadBackendID string `json:"payload_backend_id"`
	Kind             string `json:"kind"`
	CreatedAt        string `json:"created_at,omitempty"`
}

// rebuildSuspicious is one refused candidate (retained, never deleted).
type rebuildSuspicious struct {
	BackendID        string   `json:"backend_id"`
	PayloadBackendID string   `json:"payload_backend_id,omitempty"`
	SnapshotID       string   `json:"snapshot_id,omitempty"`
	WorkspaceID      string   `json:"workspace_id,omitempty"`
	Reasons          []string `json:"reasons"`
}

// rebuildDetails is the --json payload of a rebuild.
type rebuildDetails struct {
	Vault            string              `json:"vault"`
	VaultID          string              `json:"vault_id"`
	RepoDir          string              `json:"repo_dir"`
	RepoID           string              `json:"repo_id,omitempty"`
	Catalog          string              `json:"catalog"`
	Forced           bool                `json:"forced"`     // ran with --force-rebuild over a non-empty catalog
	Duplicates       int                 `json:"duplicates"` // rows that already existed (merge-discover)
	Workspaces       []rebuildWorkspace  `json:"workspaces"`
	SnapshotsAdopted int                 `json:"snapshots_adopted"`
	Unsealed         []rebuildUnsealed   `json:"unsealed_payloads"`
	Suspicious       []rebuildSuspicious `json:"suspicious_refused"`
	Unrecognized     int                 `json:"unrecognized_snapshots"`
	NextStep         string              `json:"next_step"`
}

// runCatalogRebuild executes the rebuild flow inside cmdInit once a
// session exists. It resolves the default vault, verifies the unlock,
// enforces the non-empty-catalog gate, walks the vault through
// restore.DiscoverVault and imports the findings. streamErr mirrors
// init's human-output convention (progress on stderr).
func runCatalogRebuild(sess *session, streams Streams, deps Deps, jsonOut, forceRebuild bool) int {
	env := newEnvelope("init", "error")
	ctx, stop := commandContext(deps)
	defer stop()

	reg := sess.registry()
	v, verr := reg.Default()
	if verr != nil {
		if errors.Is(verr, vault.ErrNotFound) {
			return emitFailure(env, jsonOut, streams, ExitVault, blockerMessage(
				CodeNoVault, "init --rebuild-catalog",
				fmt.Sprintf("no vault is registered in %s; discovery needs a vault to walk (the user must still know the vault location and unlock secret, §11.5)", sess.cfgDir),
				"Safe action: run plain `ebb init` to enroll the vault first, then rerun `ebb init --rebuild-catalog`"))
		}
		return emitFailure(env, jsonOut, streams, ExitBlocked,
			fmt.Sprintf("init --rebuild-catalog: vault registry: %v", verr))
	}

	// A working unlock is a precondition (§11.5: the user must still know
	// the unlock secret). Existing init wording/classes apply.
	ok, uerr := vault.Unlock(ctx, sess.cfgDir, v.ID, sess.store)
	if uerr != nil || !ok {
		return emitFailure(env, jsonOut, streams, ExitVault, fmt.Sprintf(
			"%s: default vault %s (%s) could not be unlocked: %v. Safe action: fix the credential source (%s env, OS credential store) and rerun `ebb init --rebuild-catalog`",
			CodeUnlockRejected, v.Name, v.ID, uerr, vault.EnvPassword))
	}

	// Existing-catalog gate: refuse a non-empty catalog without the
	// explicit acknowledgement; never drop data either way.
	wsCount, snapCount, cerr := sess.cat.Counts()
	if cerr != nil {
		return emitFailure(env, jsonOut, streams, ExitBlocked,
			fmt.Sprintf("init --rebuild-catalog: reading catalog %s: %v. Safe action: if the catalog file is corrupt, move it aside and rerun (the rebuild never deletes data)",
				sess.catalogPath(), cerr))
	}
	details := rebuildDetails{
		Vault: v.Name, VaultID: v.ID, RepoDir: v.RepoDir, RepoID: v.RepoID,
		Catalog: sess.catalogPath(), Forced: forceRebuild,
		Workspaces: []rebuildWorkspace{}, Unsealed: []rebuildUnsealed{},
		Suspicious: []rebuildSuspicious{}, NextStep: "",
	}
	if wsCount > 0 || snapCount > 0 {
		if !forceRebuild {
			return emitFailure(env, jsonOut, streams, ExitBlocked, blockerMessage(
				CodeRebuildNeedsForce, "init --rebuild-catalog",
				fmt.Sprintf("the catalog at %s already holds %d workspace(s) and %d snapshot(s); rebuilding over it is refused to avoid surprising an intact catalog",
					details.Catalog, wsCount, snapCount),
				"Safe action: if the catalog is intact, no rebuild is needed; if you are sure, rerun with --force-rebuild (the rebuild only merges and reports duplicates — it never drops rows)"))
		}
	}

	dErr := sess.withVaultPassfile(ctx, func(repoDir, passfile string) error {
		return rebuildFromVault(ctx, sess, v, repoDir, passfile, &details)
	})
	if dErr != nil {
		// The unlock already worked, so a backend failure here means the
		// vault itself failed verification during the walk — §17.5's
		// capture/integrity class (4), not a vault-availability problem.
		return emitFailure(env, jsonOut, streams, ExitCaptureVerify,
			fmt.Sprintf("init --rebuild-catalog: vault verification failed during discovery (nothing was deleted, and any partial imports are pinned): %s", codedWithSafeAction(dErr)))
	}

	details.NextStep = rebuildNextStep(details)
	env.Outcome = "ok"
	env.Conditions = []string{"catalog-rebuilt", "workspaces-UNBOUND", "snapshots-pinned"}
	env.Details = details
	emit(env, jsonOut, streams, renderRebuildHuman(details))
	return ExitOK
}

// rebuildFromVault performs the discovery walk and the additive imports.
// It runs inside withVaultPassfile (repoDir/passfile bound).
func rebuildFromVault(ctx context.Context, sess *session, v *vault.Vault, repoDir, passfile string, details *rebuildDetails) error {
	// The repository id both cross-checks receipts (a seal minted for
	// another vault is suspicious) and rebuilds the catalog's vaults row.
	repoID := v.RepoID
	if fresh, err := sess.store.RepoID(ctx, repoDir, passfile); err == nil && fresh != "" {
		repoID = fresh
	}
	details.RepoID = repoID

	disc, derr := restore.DiscoverVault(ctx, sess.store, restore.VaultRef{RepoDir: repoDir, Passfile: passfile}, repoID)
	if derr != nil {
		// Vault-verification class: wrap so classifyExitCode maps to 4
		// (the walk itself could not trust the repository).
		return &restore.ErrVerification{Check: "discovery", Details: []string{derr.Error()}}
	}

	// Re-register the vault row FIRST (snapshots carry the FK). The row
	// id derivation mirrors lifecycle's vaultIDFor exactly — both so
	// merge-discover matches the ids the original captures recorded, and
	// so rebuilt snapshot rows carry capture's vault_id convention.
	vaultRowID := rebuiltVaultID(repoID, repoDir)
	if err := sess.cat.RegisterVault(catalog.Vault{
		ID:   vaultRowID,
		Path: repoDir, RepoID: repoID,
	}); err != nil {
		return fmt.Errorf("register vault row: %w", err)
	}

	discovered := fmt.Sprintf("discovered:%s", time.Now().UTC().Format("2006-01-02"))
	byWorkspace := map[domain.WorkspaceID]*rebuildWorkspace{}
	for i := range disc.Pairs {
		p := disc.Pairs[i]
		if existed, _ := snapshotExists(sess, domain.SnapshotID(p.SnapshotID)); existed {
			details.Duplicates++
		}
		if err := sess.cat.ImportDiscoveredSnapshot(p.WorkspaceID, p.WorkspaceName, catalog.Snapshot{
			ID: p.SnapshotID, CreatedAt: p.CreatedAt,
			PayloadBackendID: p.PayloadBackendID, SealBackendID: p.SealBackendID,
			VaultID: vaultRowID, ManifestDigest: p.ManifestDigest,
			InventoryDigest: p.InventoryDigest, Kind: p.Kind,
			PinReasons: []string{discovered},
		}); err != nil {
			return &restore.ErrVerification{Check: "discovery", Details: []string{
				fmt.Sprintf("importing discovered snapshot %s: %v", p.SnapshotID, err)}}
		}
		ws := byWorkspace[p.WorkspaceID]
		if ws == nil {
			ws = &rebuildWorkspace{ID: string(p.WorkspaceID), Name: p.WorkspaceName,
				Status: catalog.WorkspaceUnbound, Kinds: []string{}}
			byWorkspace[p.WorkspaceID] = ws
			details.Workspaces = append(details.Workspaces, *ws)
		}
		ws.Snapshots++
		ws.Kinds = appendKind(ws.Kinds, p.Kind)
		details.SnapshotsAdopted++
	}

	for _, u := range disc.Unsealed {
		if existed, _ := snapshotExists(sess, domain.SnapshotID(u.SnapshotID)); existed {
			details.Duplicates++
		}
		// §11.3: an unsealed payload is an incomplete operation, not
		// garbage — recorded pinned with an empty seal id (the shape
		// forget refuses and open-selection skips), reported, never
		// adopted as a verified snapshot.
		if err := sess.cat.ImportDiscoveredSnapshot(u.WorkspaceID, u.WorkspaceName, catalog.Snapshot{
			ID: u.SnapshotID, CreatedAt: u.CreatedAt,
			PayloadBackendID: u.PayloadBackendID,
			VaultID:          vaultRowID, ManifestDigest: u.ManifestDigest,
			InventoryDigest: u.InventoryDigest, Kind: u.Kind,
			PinReasons: []string{discovered + ":unsealed"},
		}); err != nil {
			return &restore.ErrVerification{Check: "discovery", Details: []string{
				fmt.Sprintf("recording unsealed payload %s: %v", u.PayloadBackendID, err)}}
		}
		details.Unsealed = append(details.Unsealed, rebuildUnsealed{
			SnapshotID: string(u.SnapshotID), WorkspaceID: string(u.WorkspaceID),
			PayloadBackendID: u.PayloadBackendID, Kind: u.Kind, CreatedAt: u.CreatedAt,
		})
	}

	for _, s := range disc.Suspicious {
		details.Suspicious = append(details.Suspicious, rebuildSuspicious{
			BackendID: s.BackendID, PayloadBackendID: s.PayloadBackendID,
			SnapshotID: s.SnapshotID, WorkspaceID: s.WorkspaceID,
			Reasons: s.Reasons,
		})
	}
	details.Unrecognized = len(disc.Unrecognized)
	return nil
}

// snapshotExists reports whether the logical snapshot id is already in
// the catalog (duplicate accounting for merge-discover). Read failures
// count as not-existing; the import itself surfaces hard errors.
func snapshotExists(sess *session, id domain.SnapshotID) (bool, error) {
	_, err := sess.cat.GetSnapshot(id)
	if errors.Is(err, catalog.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// rebuiltVaultID mirrors lifecycle's vaultIDFor derivation (capture.go):
// the stable vault row id for one repository, so rows rebuilt by
// discovery carry exactly the id the original captures recorded.
func rebuiltVaultID(repoID, repoDir string) domain.VaultID {
	abs, err := filepath.Abs(repoDir)
	if err != nil {
		abs = repoDir
	}
	sum := sha256.Sum256([]byte("ebb:vault:" + repoID + ":" + filepath.Clean(abs)))
	return domain.VaultID(hex.EncodeToString(sum[:])[:32])
}

// appendKind adds kind to kinds when absent (report summary helper).
func appendKind(kinds []string, kind string) []string {
	for _, k := range kinds {
		if k == kind {
			return kinds
		}
	}
	return append(kinds, kind)
}

// rebuildNextStep names the explicit, non-destructive continuation.
func rebuildNextStep(d rebuildDetails) string {
	var b strings.Builder
	b.WriteString("nothing destructive is possible from UNBOUND state; next: `ebb open <workspace> --to <dir>` to restore (a destination must be named — UNBOUND has no root path)")
	if len(d.Unsealed) > 0 {
		b.WriteString("; review the unsealed payloads with `ebb status` (incomplete captures, kept pinned)")
	}
	if len(d.Suspicious) > 0 {
		b.WriteString("; the refused candidates are retained untouched in the vault (repair mode, §11.5)")
	}
	return b.String()
}

// renderRebuildHuman renders the rebuild report for the human stream.
func renderRebuildHuman(d rebuildDetails) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("catalog rebuilt from vault %s (%s) at %s\n", d.Vault, d.VaultID, d.RepoDir)
	line("  catalog: %s\n", d.Catalog)
	if d.Forced {
		line("  forced merge over a non-empty catalog; %d duplicate row(s) reported, none dropped\n", d.Duplicates)
	}
	if len(d.Workspaces) == 0 {
		line("  no sealed pairs discovered — the vault holds no Ebb workspaces\n")
	} else {
		line("  workspaces rebuilt (status UNBOUND — a seal proves a snapshot exists, not that the source was removed):\n")
		for _, w := range d.Workspaces {
			line("    %s [%s] — %d snapshot(s) adopted, kinds: %s\n",
				w.Name, w.Status, w.Snapshots, strings.Join(w.Kinds, ", "))
			line("      id %s\n", w.ID)
		}
	}
	for _, u := range d.Unsealed {
		line("  unsealed payload kept pinned (incomplete operation, not garbage): snapshot %s payload %s kind %s\n",
			u.SnapshotID, u.PayloadBackendID, u.Kind)
	}
	for _, s := range d.Suspicious {
		line("  SUSPICIOUS — refused and retained (vault tampering or corruption suspected): %s\n", s.BackendID)
		if s.PayloadBackendID != "" {
			line("    payload %s\n", s.PayloadBackendID)
		}
		for _, r := range s.Reasons {
			line("    %s\n", r)
		}
	}
	if d.Unrecognized > 0 {
		line("  %d vault snapshot(s) carried no Ebb tags: unrecognized, left untouched\n", d.Unrecognized)
	}
	line("next: %s\n", d.NextStep)
	return b.String()
}
