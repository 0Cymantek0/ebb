package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ebb/internal/domain"
)

// open opens a catalog in a fresh temp dir.
func open(t *testing.T) *Catalog {
	t.Helper()
	c, err := Open(filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

// liveWorkspace inserts and returns a live workspace with a root.
func liveWorkspace(t *testing.T, c *Catalog, name string) domain.WorkspaceID {
	t.Helper()
	id := domain.WorkspaceID(domain.NewID())
	w := Workspace{
		ID:           id,
		Name:         name,
		RootPath:     `C:\dev\` + name,
		RootIdentity: "vol-1/file-" + name,
		Status:       WorkspaceLive,
	}
	if err := c.UpsertWorkspace(w); err != nil {
		t.Fatalf("UpsertWorkspace: %v", err)
	}
	return id
}

func mustSnapshot(t *testing.T, c *Catalog, ws domain.WorkspaceID, kind string) domain.SnapshotID {
	t.Helper()
	id, err := c.RecordSnapshot(Snapshot{WorkspaceID: ws, Kind: kind, ManifestDigest: "manifest-" + kind})
	if err != nil {
		t.Fatalf("RecordSnapshot: %v", err)
	}
	return id
}

func TestDurabilityPragmasApplied(t *testing.T) {
	c := open(t)
	liveWorkspace(t, c, "pragmas") // force some real work first

	// Every pooled connection must carry the §16.5 durability settings.
	// They are verified through the same pool the API uses, after real
	// statements have run, so the checked connection is a serving one.
	var journalMode string
	var synchronous, foreignKeys, busyTimeout int64
	err := c.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode)
	if err != nil {
		t.Fatalf("journal_mode: %v", err)
	}
	if err := c.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatalf("synchronous: %v", err)
	}
	if err := c.db.QueryRow(`PRAGMA foreign_keys`).Scan(&foreignKeys); err != nil {
		t.Fatalf("foreign_keys: %v", err)
	}
	if err := c.db.QueryRow(`PRAGMA busy_timeout`).Scan(&busyTimeout); err != nil {
		t.Fatalf("busy_timeout: %v", err)
	}
	if journalMode != "delete" {
		t.Fatalf("journal_mode: got %s, want delete", journalMode)
	}
	if synchronous != 3 { // 3 = EXTRA
		t.Fatalf("synchronous: got %d, want 3 (EXTRA)", synchronous)
	}
	if foreignKeys != 1 {
		t.Fatalf("foreign_keys: got %d, want 1", foreignKeys)
	}
	if busyTimeout != 5000 {
		t.Fatalf("busy_timeout: got %d, want 5000", busyTimeout)
	}

	// DELETE journal mode leaves no persistent -wal side file behind.
	path := filepath.Join(t.TempDir(), "walcheck.db")
	c2, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer c2.Close()
	mustSnapshot(t, c2, liveWorkspace(t, c2, "wal"), SnapshotKindPark)
	if _, err := os.Stat(path + "-wal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected -wal side file present (journal_mode not DELETE?): %v", err)
	}
}

func TestOpenMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")

	c1, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	var versions int
	if err := c1.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if want := len(migrations); versions != want {
		t.Fatalf("after first open: got %d applied migrations, want %d", versions, want)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Second open must apply nothing new and still enforce FKs (proof the
	// pragmas ran on the new pool's connections).
	c2, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer c2.Close()
	if err := c2.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&versions); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if versions != len(migrations) {
		t.Fatalf("after second open: got %d applied migrations, want %d", versions, len(migrations))
	}
	if _, err := c2.RecordSnapshot(Snapshot{WorkspaceID: domain.WorkspaceID("bogus"), Kind: SnapshotKindPark}); err == nil {
		t.Fatal("FK not enforced on reopened catalog: bogus workspace snapshot accepted")
	}
}

func TestAllTablesPresent(t *testing.T) {
	c := open(t)
	rows, err := c.db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	want := []string{
		"action_runs", "approvals", "docker_images", "operations", "replicas",
		"retention_intents", "schema_migrations", "snapshots", "vaults", "workspaces",
	}
	if len(got) != len(want) {
		t.Fatalf("tables: got %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tables: got %v, want %v", got, want)
		}
	}
}

func TestForeignKeyEnforced(t *testing.T) {
	c := open(t)
	if _, err := c.RecordSnapshot(Snapshot{WorkspaceID: domain.WorkspaceID("0000dead"), Kind: SnapshotKindPark}); err == nil {
		t.Fatal("expected FK violation for snapshot with bogus workspace, got nil")
	}
	if _, err := c.BeginOperation(domain.WorkspaceID("0000dead"), OpKindPark, `C:\w`, "vol/1", "d"); err == nil {
		t.Fatal("expected FK violation for operation with bogus workspace, got nil")
	}
	if err := c.QuickCheck(); err != nil {
		t.Fatalf("QuickCheck after refused FK inserts: %v", err)
	}
}

func TestAdvanceOperationCASConcurrent(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "cas")
	opID, err := c.BeginOperation(ws, OpKindPark, `C:\dev\cas`, "vol-1/file-1", "intent-d")
	if err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}

	const racers = 8
	start := make(chan struct{})
	results := make([]error, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = c.AdvanceOperation(opID, PhasePlanned, PhaseCapturing)
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrCASConflict):
			// expected loser outcome
		default:
			t.Fatalf("racer %d: unexpected error: %v", i, err)
		}
	}
	if wins != 1 {
		t.Fatalf("CAS: %d racers won, want exactly 1 (errors: %v)", wins, results)
	}

	op, err := c.GetOperation(opID)
	if err != nil {
		t.Fatalf("GetOperation: %v", err)
	}
	if op.Phase != PhaseCapturing {
		t.Fatalf("phase after CAS race: got %s, want %s", op.Phase, PhaseCapturing)
	}
	if op.Generation != 2 {
		t.Fatalf("generation after one CAS advance: got %d, want 2", op.Generation)
	}

	// A stale-phase advance is also a conflict, deterministically.
	if err := c.AdvanceOperation(opID, PhasePlanned, PhaseCapturing); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale advance: got %v, want ErrCASConflict", err)
	}
	// An unknown operation is ErrNotFound, not a conflict.
	if err := c.AdvanceOperation(domain.OperationID("0000beef"), PhasePlanned, PhaseCapturing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown op advance: got %v, want ErrNotFound", err)
	}
	// The phase vocabulary is closed: typo'd phases are refused.
	if err := c.AdvanceOperation(opID, PhaseCapturing, "CAPTURING "); err == nil {
		t.Fatal("typo'd to-phase accepted")
	}
}

func TestUnpinLastPinnedRefusal(t *testing.T) {
	c := open(t)

	// Live workspace, single pinned snapshot: refusal without force.
	wsLive := liveWorkspace(t, c, "guarded")
	s1 := mustSnapshot(t, c, wsLive, SnapshotKindPark)
	err := c.Unpin(s1, "retention policy", false)
	if !errors.Is(err, ErrLastPinned) {
		t.Fatalf("last-pinned unpin without force: got %v, want ErrLastPinned", err)
	}
	got, err := c.GetSnapshot(s1)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if !got.Pinned {
		t.Fatal("refused unpin changed pinned state")
	}

	// Force with an explicit reason overrides and records the reason.
	const forced = "operator verified vault copy 3x after recovery drill"
	if err := c.Unpin(s1, forced, true); err != nil {
		t.Fatalf("forced unpin: %v", err)
	}
	got, err = c.GetSnapshot(s1)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if got.Pinned {
		t.Fatal("forced unpin left snapshot pinned")
	}
	found := false
	for _, r := range got.PinReasons {
		if r == "unpin:"+forced {
			found = true
		}
	}
	if !found {
		t.Fatalf("forced unpin did not record reason; audit list = %v", got.PinReasons)
	}

	// Parked workspace: unpinning the only pinned snapshot needs no force.
	wsParked := domain.WorkspaceID(domain.NewID())
	if err := c.UpsertWorkspace(Workspace{ID: wsParked, Name: "archived", Status: WorkspaceParked}); err != nil {
		t.Fatalf("UpsertWorkspace: %v", err)
	}
	s2 := mustSnapshot(t, c, wsParked, SnapshotKindPark)
	if err := c.Unpin(s2, "superseded", false); err != nil {
		t.Fatalf("unpin sole pinned snapshot of parked workspace: %v", err)
	}

	// Live workspace with two pinned snapshots: unpinning one is allowed.
	wsTwo := liveWorkspace(t, c, "twosnaps")
	s3 := mustSnapshot(t, c, wsTwo, SnapshotKindPark)
	s4 := mustSnapshot(t, c, wsTwo, SnapshotKindPark)
	if err := c.Unpin(s3, "superseded by newer seal", false); err != nil {
		t.Fatalf("unpin one of two pinned: %v", err)
	}
	if err := c.Unpin(s4, "now the last one", false); !errors.Is(err, ErrLastPinned) {
		t.Fatalf("unpin of remaining pinned: got %v, want ErrLastPinned", err)
	}
	// Pin re-arms the guard and audits its reason.
	if err := c.Pin(s3, "export in flight"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	got3, err := c.GetSnapshot(s3)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	if !got3.Pinned || !contains(got3.PinReasons, "pin:export in flight") || !contains(got3.PinReasons, PinReasonCreation) {
		t.Fatalf("pin audit wrong: %v", got3.PinReasons)
	}

	// Unknown snapshot and empty reasons are refused.
	if err := c.Unpin(domain.SnapshotID("0000cafe"), "x", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown snapshot unpin: got %v, want ErrNotFound", err)
	}
	if err := c.Unpin(s3, "", true); err == nil {
		t.Fatal("empty unpin reason accepted")
	}
	if err := c.Pin(s3, ""); err == nil {
		t.Fatal("empty pin reason accepted")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestJournalRoundTrip(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "journal")
	const (
		root   = `C:\dev\journal`
		ident  = "vol-42/file-7"
		intent = "intent-digest-abc"
	)
	opID, err := c.BeginOperation(ws, OpKindPark, root, ident, intent)
	if err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}
	// §12.2 happy-path walk, with backend refs recorded on the way.
	steps := [][2]string{
		{PhasePlanned, PhaseCapturing},
		{PhaseCapturing, PhasePayloadCommitted},
		{PhasePayloadCommitted, PhaseSealed},
		{PhaseSealed, PhaseQuarantined},
		{PhaseQuarantined, PhaseRemoving},
		{PhaseRemoving, PhaseParked},
	}
	for _, s := range steps {
		if err := c.AdvanceOperation(opID, s[0], s[1]); err != nil {
			t.Fatalf("advance %s->%s: %v", s[0], s[1], err)
		}
	}
	if err := c.SetBackendRefs(opID, "payload-backend-id", "seal-backend-id"); err != nil {
		t.Fatalf("SetBackendRefs: %v", err)
	}

	op, err := c.GetOperation(opID)
	if err != nil {
		t.Fatalf("GetOperation: %v", err)
	}
	if op.Phase != PhaseParked {
		t.Fatalf("phase: got %s, want %s", op.Phase, PhaseParked)
	}
	if op.Generation != int64(len(steps)+1) {
		t.Fatalf("generation: got %d, want %d", op.Generation, len(steps)+1)
	}
	if op.WorkspaceID != ws || op.Kind != OpKindPark || op.SourceRoot != root ||
		op.SourceIdentity != ident || op.IntentDigest != intent {
		t.Fatalf("round trip lost identity fields: %+v", op)
	}
	if op.PayloadSnap != "payload-backend-id" || op.SealSnap != "seal-backend-id" {
		t.Fatalf("backend refs: got %q/%q", op.PayloadSnap, op.SealSnap)
	}

	// FailOperation records the error and KEEPS the phase.
	if err := c.FailOperation(opID, PhaseParked, "late-write detected in quarantine"); err != nil {
		t.Fatalf("FailOperation: %v", err)
	}
	op, err = c.GetOperation(opID)
	if err != nil {
		t.Fatalf("GetOperation after fail: %v", err)
	}
	if op.Phase != PhaseParked {
		t.Fatalf("FailOperation changed phase: got %s", op.Phase)
	}
	if op.LastError != "late-write detected in quarantine" {
		t.Fatalf("LastError: got %q", op.LastError)
	}
	// FailOperation is phase-guarded too.
	if err := c.FailOperation(opID, PhaseCapturing, "stale"); !errors.Is(err, ErrCASConflict) {
		t.Fatalf("stale FailOperation: got %v, want ErrCASConflict", err)
	}

	// PARKED is not terminal: the workspace still has an active row.
	active, err := c.ActiveOperations(ws)
	if err != nil {
		t.Fatalf("ActiveOperations: %v", err)
	}
	if len(active) != 1 || active[0].ID != opID {
		t.Fatalf("active ops: got %+v, want the parked op", active)
	}
	// A terminal advance removes it from the active set.
	if err := c.AdvanceOperation(opID, PhaseParked, PhaseDone); err != nil {
		t.Fatalf("advance to DONE: %v", err)
	}
	active, err = c.ActiveOperations(ws)
	if err != nil {
		t.Fatalf("ActiveOperations: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("active ops after DONE: got %d, want 0", len(active))
	}
}

func TestApprovalExactMatch(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "approvals")
	const (
		action = "rebuild-venv"
		argv   = "argv-sha256-aaa"
		inputs = `{"lock":"sha256-111","py":"sha256-222"}`
	)
	id, err := c.RecordApproval(Approval{
		WorkspaceID:  ws,
		ActionID:     action,
		ArgvDigest:   argv,
		InputDigests: inputs,
		ToolIdentity: "python:3.12.6",
		Network:      "none",
	})
	if err != nil {
		t.Fatalf("RecordApproval: %v", err)
	}

	got, err := c.FindApproval(ws, action, argv, inputs)
	if err != nil {
		t.Fatalf("FindApproval exact: %v", err)
	}
	if got.ID != id || got.ActionID != action || got.ArgvDigest != argv ||
		got.InputDigests != inputs || got.ToolIdentity != "python:3.12.6" || got.RevokedAt != "" {
		t.Fatalf("approval round trip: %+v", got)
	}

	// Wrong argv digest is a different approval (Foundation §7.3).
	if _, err := c.FindApproval(ws, action, "argv-sha256-bbb", inputs); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong argv digest matched: got %v, want ErrNotFound", err)
	}
	// Wrong input digests too.
	if _, err := c.FindApproval(ws, action, argv, `{"lock":"sha256-333","py":"sha256-222"}`); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong input digests matched: got %v, want ErrNotFound", err)
	}
	// Wrong action.
	if _, err := c.FindApproval(ws, "rebuild-node-modules", argv, inputs); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong action matched: got %v, want ErrNotFound", err)
	}

	// Revocation removes the match, permanently.
	if err := c.RevokeApproval(id); err != nil {
		t.Fatalf("RevokeApproval: %v", err)
	}
	if _, err := c.FindApproval(ws, action, argv, inputs); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked approval matched: got %v, want ErrNotFound", err)
	}
	// Re-revoking is an idempotent no-op; an unknown id is ErrNotFound.
	if err := c.RevokeApproval(id); err != nil {
		t.Fatalf("re-revoke: %v", err)
	}
	if err := c.RevokeApproval(domain.ID("0000bad0")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown: got %v, want ErrNotFound", err)
	}

	// A fresh approval for the same tuple matches again after revocation.
	if _, err := c.RecordApproval(Approval{
		WorkspaceID: ws, ActionID: action, ArgvDigest: argv, InputDigests: inputs,
	}); err != nil {
		t.Fatalf("RecordApproval #2: %v", err)
	}
	if _, err := c.FindApproval(ws, action, argv, inputs); err != nil {
		t.Fatalf("FindApproval after re-approval: %v", err)
	}
}

func TestRetentionIntentLifecycle(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "retention")
	snap := mustSnapshot(t, c, ws, SnapshotKindPark)

	// Unknown snapshot refuses intent creation.
	if _, err := c.CreateRetentionIntent(domain.SnapshotID("0000f1ce"), "user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("intent for unknown snapshot: got %v, want ErrNotFound", err)
	}

	id, err := c.CreateRetentionIntent(snap, "user")
	if err != nil {
		t.Fatalf("CreateRetentionIntent: %v", err)
	}
	pending, err := c.PendingRetentionIntents()
	if err != nil {
		t.Fatalf("PendingRetentionIntents: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending: got %d, want 1", len(pending))
	}
	ri := pending[0]
	if ri.ID != id || ri.SnapshotID != snap || !ri.Acknowledged || ri.CompletedAt != "" || ri.RequestedBy != "user" {
		t.Fatalf("intent round trip: %+v", ri)
	}

	if err := c.CompleteRetentionIntent(id); err != nil {
		t.Fatalf("CompleteRetentionIntent: %v", err)
	}
	pending, err = c.PendingRetentionIntents()
	if err != nil {
		t.Fatalf("PendingRetentionIntents: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending after completion: got %d, want 0", len(pending))
	}
	var completedAt sql.NullString
	if err := c.db.QueryRow(`SELECT completed_at FROM retention_intents WHERE id = ?`, string(id)).Scan(&completedAt); err != nil {
		t.Fatalf("read completed_at: %v", err)
	}
	if !completedAt.Valid {
		t.Fatal("completed_at still NULL after completion")
	}
	if _, err := time.Parse(time.RFC3339Nano, completedAt.String); err != nil {
		t.Fatalf("completed_at not RFC3339Nano: %q: %v", completedAt.String, err)
	}
	// Idempotent completion; unknown id refuses.
	if err := c.CompleteRetentionIntent(id); err != nil {
		t.Fatalf("re-complete: %v", err)
	}
	if err := c.CompleteRetentionIntent(domain.ID("0000d1ce")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("complete unknown: got %v, want ErrNotFound", err)
	}
}

func TestImportDiscoveredSnapshotAndWorkspacesForVault(t *testing.T) {
	c := open(t)
	vaultID := domain.VaultID(domain.NewID())
	if err := c.RegisterVault(Vault{ID: vaultID, Path: `D:\vaults\main`, RepoID: "restic-123"}); err != nil {
		t.Fatalf("RegisterVault: %v", err)
	}
	gotVault, err := c.GetVault(vaultID)
	if err != nil {
		t.Fatalf("GetVault: %v", err)
	}
	if gotVault.Kind != "local" || gotVault.RepoID != "restic-123" || gotVault.RegisteredAt == "" {
		t.Fatalf("vault round trip: %+v", gotVault)
	}

	// An empty vault holds evidence for no workspace.
	if ws, err := c.WorkspacesForVault(vaultID); err != nil || len(ws) != 0 {
		t.Fatalf("WorkspacesForVault empty: %v %v", ws, err)
	}

	wsID := domain.WorkspaceID(domain.NewID())
	const snapID = domain.SnapshotID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	s := Snapshot{
		ID:               snapID,
		WorkspaceID:      wsID, // ImportDiscoveredSnapshot rebinds this itself
		PayloadBackendID: "payload-9",
		SealBackendID:    "seal-9",
		VaultID:          vaultID,
		ManifestDigest:   "manifest-d",
		InventoryDigest:  "inventory-d",
		Kind:             SnapshotKindSeal,
		CreatedAt:        domain.FormatTime(time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)),
	}
	if err := c.ImportDiscoveredSnapshot(wsID, "recovered-proj", s); err != nil {
		t.Fatalf("ImportDiscoveredSnapshot: %v", err)
	}

	// The rebuilt workspace is UNBOUND, never a guessed status (§16.5).
	ws, err := c.GetWorkspace(wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	if ws.Status != WorkspaceUnbound {
		t.Fatalf("rebuilt workspace status: got %s, want %s", ws.Status, WorkspaceUnbound)
	}
	if ws.Name != "recovered-proj" || ws.RootPath != "" || ws.RootIdentity != "" {
		t.Fatalf("rebuilt workspace fields: %+v", ws)
	}

	snaps, err := c.ListSnapshots(wsID)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("snapshots after import: got %d, want 1", len(snaps))
	}
	got := snaps[0]
	if !got.Pinned || !contains(got.PinReasons, PinReasonCreation) {
		t.Fatalf("imported snapshot not pinned with creation reason: %+v", got)
	}
	if got.Kind != SnapshotKindSeal || got.PayloadBackendID != "payload-9" || got.SealBackendID != "seal-9" {
		t.Fatalf("imported snapshot facts: %+v", got)
	}

	forWs, err := c.WorkspacesForVault(vaultID)
	if err != nil {
		t.Fatalf("WorkspacesForVault: %v", err)
	}
	if len(forWs) != 1 || forWs[0] != wsID {
		t.Fatalf("WorkspacesForVault: got %v, want [%s]", forWs, wsID)
	}

	// Re-import COMPARES, never merges (Wave J J4): a candidate with a
	// different payload id is a witness divergence, refused with the row
	// untouched; the exact same facts re-import as a benign duplicate.
	// Either way the pin state is never disturbed.
	if err := c.Pin(snapID, "audit-hold"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	s.PayloadBackendID = "payload-9b"
	err = c.ImportDiscoveredSnapshot(wsID, "recovered-proj", s)
	if err == nil {
		t.Fatal("divergent re-import accepted — the witness is re-anchorable")
	}
	var div *ErrWitnessDivergence
	if !errors.As(err, &div) {
		t.Fatalf("divergent re-import error is not ErrWitnessDivergence: %v", err)
	}
	s.PayloadBackendID = "payload-9"
	if err := c.ImportDiscoveredSnapshot(wsID, "recovered-proj", s); err != nil {
		t.Fatalf("benign re-import: %v", err)
	}
	if snaps, err = c.ListSnapshots(wsID); err != nil {
		t.Fatalf("ListSnapshots after re-import: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("re-import duplicated snapshot: got %d rows", len(snaps))
	}
	got = snaps[0]
	if !got.Pinned || !contains(got.PinReasons, "pin:audit-hold") {
		t.Fatalf("re-import disturbed pin state: %+v", got)
	}
	if got.PayloadBackendID != "payload-9" {
		t.Fatalf("re-import changed the payload id: %q", got.PayloadBackendID)
	}
}

func TestQuickCheckHealthyAndCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ws := liveWorkspace(t, c, "qc")
	mustSnapshot(t, c, ws, SnapshotKindPark)
	if _, err := c.BeginOperation(ws, OpKindPark, `C:\dev\qc`, "vol/1", "d"); err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}
	if err := c.QuickCheck(); err != nil {
		t.Fatalf("QuickCheck on healthy catalog: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Deliberate external corruption: junk over the db file. Reopening
	// (and QuickCheck, if open were to succeed) must report an error,
	// never panic.
	junk := make([]byte, 4096)
	for i := range junk {
		junk[i] = byte('A' + i%26)
	}
	if err := os.WriteFile(path, junk, 0o644); err != nil {
		t.Fatalf("corrupt db file: %v", err)
	}
	c2, err := Open(path)
	if err == nil {
		defer c2.Close()
		if err := c2.QuickCheck(); err == nil {
			t.Fatal("neither Open nor QuickCheck detected external corruption")
		}
	}
}

func TestConcurrentWriterReaderTwoHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	writer, err := Open(path)
	if err != nil {
		t.Fatalf("writer Open: %v", err)
	}
	defer writer.Close()
	reader, err := Open(path)
	if err != nil {
		t.Fatalf("reader Open: %v", err)
	}
	defer reader.Close()

	ws := liveWorkspace(t, writer, "concurrent")
	seedOp, err := writer.BeginOperation(ws, OpKindOpen, `C:\dev\conc`, "vol/1", "d0")
	if err != nil {
		t.Fatalf("seed BeginOperation: %v", err)
	}

	const iterations = 40
	errc := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			opID, err := writer.BeginOperation(ws, OpKindPark,
				fmt.Sprintf(`C:\dev\conc\%d`, i), "vol/1", fmt.Sprintf("intent-%d", i))
			if err != nil {
				errc <- fmt.Errorf("writer begin %d: %w", i, err)
				return
			}
			if err := writer.AdvanceOperation(opID, PhasePlanned, PhaseCanceled); err != nil {
				errc <- fmt.Errorf("writer advance %d: %w", i, err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations*3; i++ {
			if _, err := reader.ActiveOperations(ws); err != nil {
				errc <- fmt.Errorf("reader active %d: %w", i, err)
				return
			}
			if _, err := reader.GetOperation(seedOp); err != nil {
				errc <- fmt.Errorf("reader get %d: %w", i, err)
				return
			}
		}
	}()
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
}

func TestTimestampsRFC3339NanoUTC(t *testing.T) {
	c := open(t)
	wsID := liveWorkspace(t, c, "timestamps")
	snapID := mustSnapshot(t, c, wsID, SnapshotKindPark)
	opID, err := c.BeginOperation(wsID, OpKindPark, `C:\dev\ts`, "vol/1", "d")
	if err != nil {
		t.Fatalf("BeginOperation: %v", err)
	}
	if err := c.AdvanceOperation(opID, PhasePlanned, PhaseCapturing); err != nil {
		t.Fatalf("AdvanceOperation: %v", err)
	}

	check := func(what, ts string) {
		t.Helper()
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			t.Fatalf("%s timestamp %q not RFC3339Nano: %v", what, ts, err)
		}
		if _, offset := parsed.Zone(); offset != 0 {
			t.Fatalf("%s timestamp %q not UTC (offset %d)", what, ts, offset)
		}
	}
	ws, err := c.GetWorkspace(wsID)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	check("workspace.created_at", ws.CreatedAt)
	snap, err := c.GetSnapshot(snapID)
	if err != nil {
		t.Fatalf("GetSnapshot: %v", err)
	}
	check("snapshot.created_at", snap.CreatedAt)
	op, err := c.GetOperation(opID)
	if err != nil {
		t.Fatalf("GetOperation: %v", err)
	}
	check("operation.started_at", op.StartedAt)
	check("operation.updated_at", op.UpdatedAt)
	if op.UpdatedAt <= op.StartedAt {
		t.Fatalf("updated_at %q not after started_at %q", op.UpdatedAt, op.StartedAt)
	}
}

func TestWorkspaceUpsertRoundTrip(t *testing.T) {
	c := open(t)
	id := domain.WorkspaceID(domain.NewID())
	if err := c.UpsertWorkspace(Workspace{ID: id, Name: "first"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := c.GetWorkspace(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != WorkspaceUnbound {
		t.Fatalf("default status: got %s, want %s", got.Status, WorkspaceUnbound)
	}
	first := got.CreatedAt

	// Rebind: same identity, new name/root/status, created_at preserved.
	if err := c.UpsertWorkspace(Workspace{
		ID: id, Name: "second", RootPath: `E:\moved`, RootIdentity: "vol-9/file-9", Status: WorkspaceLive,
	}); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	got, err = c.GetWorkspace(id)
	if err != nil {
		t.Fatalf("get after rebind: %v", err)
	}
	if got.Name != "second" || got.RootPath != `E:\moved` || got.Status != WorkspaceLive {
		t.Fatalf("rebind lost fields: %+v", got)
	}
	if got.CreatedAt != first {
		t.Fatalf("rebind changed created_at: %q -> %q", first, got.CreatedAt)
	}

	// Invalid status and empty id are refused.
	if err := c.UpsertWorkspace(Workspace{ID: id, Name: "x", Status: "zombie"}); err == nil {
		t.Fatal("invalid status accepted")
	}
	if err := c.UpsertWorkspace(Workspace{Name: "noid"}); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := c.GetWorkspace(domain.WorkspaceID("0000e11e")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown workspace: got %v, want ErrNotFound", err)
	}

	// ListSnapshots returns creation order and ErrNotFound propagates.
	s1 := mustSnapshot(t, c, id, SnapshotKindPark)
	time.Sleep(2 * time.Millisecond) // distinct RFC3339Nano creation times
	s2 := mustSnapshot(t, c, id, SnapshotKindSnapshot)
	if _, err := c.RecordSnapshot(Snapshot{ID: s2, WorkspaceID: id, Kind: SnapshotKindPark}); err == nil {
		t.Fatal("duplicate snapshot id accepted")
	}
	snaps, err := c.ListSnapshots(id)
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 2 || snaps[0].ID != s1 || snaps[1].ID != s2 {
		t.Fatalf("ListSnapshots order: got [%s %s], want [%s %s]",
			snaps[0].ID, snaps[1].ID, s1, s2)
	}
	if snaps[0].Kind != SnapshotKindPark || snaps[1].Kind != SnapshotKindSnapshot {
		t.Fatalf("kinds: got %s/%s", snaps[0].Kind, snaps[1].Kind)
	}
	if _, err := c.GetSnapshot(domain.SnapshotID("00005e77")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown snapshot: got %v, want ErrNotFound", err)
	}
	if _, err := c.RecordSnapshot(Snapshot{WorkspaceID: id, Kind: "dump"}); err == nil {
		t.Fatal("invalid snapshot kind accepted")
	}
	if _, err := c.BeginOperation(id, "explode", "r", "i", "d"); err == nil {
		t.Fatal("invalid operation kind accepted")
	}
}

// TestEnsureWorkspaceNeverModifies — the capsule-import identity
// adoption primitive (§16.1): EnsureWorkspace creates the row once
// (UNBOUND, no root) and every later call is a NO-OP — a differing name
// never renames, and a LIVE row's status is never clobbered (the exact
// never-modify semantics ImportDiscoveredSnapshot's workspace insert
// uses).
func TestEnsureWorkspaceNeverModifies(t *testing.T) {
	c := open(t)
	id := domain.WorkspaceID(domain.NewID())

	// Creates once.
	if err := c.EnsureWorkspace(id, "capsule-ws"); err != nil {
		t.Fatalf("EnsureWorkspace: %v", err)
	}
	got, err := c.GetWorkspace(id)
	if err != nil {
		t.Fatalf("GetWorkspace: %v", err)
	}
	if got.Name != "capsule-ws" || got.Status != WorkspaceUnbound || got.RootPath != "" || got.RootIdentity != "" {
		t.Fatalf("ensured workspace fields: %+v", got)
	}
	if got.CreatedAt == "" {
		t.Fatal("ensured workspace has no created_at")
	}
	first := got

	// Second call with a DIFFERENT name no-ops entirely.
	if err := c.EnsureWorkspace(id, "renamed-elsewhere"); err != nil {
		t.Fatalf("second EnsureWorkspace: %v", err)
	}
	got, err = c.GetWorkspace(id)
	if err != nil {
		t.Fatalf("GetWorkspace after second call: %v", err)
	}
	if got != first {
		t.Fatalf("second EnsureWorkspace modified the row: %+v (was %+v)", got, first)
	}

	// Never touches status: a LIVE row stays LIVE, name and root intact.
	live := domain.WorkspaceID(domain.NewID())
	if err := c.UpsertWorkspace(Workspace{
		ID: live, Name: "declared", RootPath: `D:\ws`, Status: WorkspaceLive,
	}); err != nil {
		t.Fatalf("UpsertWorkspace: %v", err)
	}
	if err := c.EnsureWorkspace(live, "capsule-ws"); err != nil {
		t.Fatalf("EnsureWorkspace over a live row: %v", err)
	}
	got, err = c.GetWorkspace(live)
	if err != nil {
		t.Fatalf("GetWorkspace live: %v", err)
	}
	if got.Status != WorkspaceLive || got.Name != "declared" || got.RootPath != `D:\ws` {
		t.Fatalf("EnsureWorkspace clobbered a live row: %+v", got)
	}

	// Argument mistakes refuse.
	if err := c.EnsureWorkspace("", "n"); err == nil {
		t.Fatal("empty id accepted")
	}
	if err := c.EnsureWorkspace(domain.WorkspaceID(domain.NewID()), ""); err == nil {
		t.Fatal("empty name accepted")
	}

	// Exactly one workspace row was created by this test's Ensure calls.
	wss, err := c.ListWorkspaces()
	if err != nil {
		t.Fatalf("ListWorkspaces: %v", err)
	}
	var ensured int
	for _, w := range wss {
		if w.ID == id || w.ID == live {
			ensured++
		}
	}
	if ensured != 2 {
		t.Fatalf("workspace rows for id/live = %d, want 2 (no duplicates)", ensured)
	}
}
