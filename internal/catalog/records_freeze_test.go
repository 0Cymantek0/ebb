package catalog

// records_freeze_test.go pins the docker_images durable rows (schemaV3,
// D040 tier 3): append-only freeze history, verified/removed stamping
// discipline, and the refusal to record a daemon removal for an
// UNVERIFIED freeze (removal authority requires proven evidence).

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"ebb/internal/domain"
)

func newFreezeCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := Open(filepath.Join(t.TempDir(), "catalog.db"))
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	// Freeze rows bind to a registered vault row (FK enforced), exactly
	// like snapshot rows do.
	if err := c.RegisterVault(Vault{
		ID:           domain.VaultID("11111111111111111111111111111111"),
		Path:         filepath.Join(t.TempDir(), "repo"),
		RepoID:       "fake-repo-id",
		RegisteredAt: "2026-09-21T00:00:00Z",
	}); err != nil {
		t.Fatalf("register vault: %v", err)
	}
	return c
}

func freezeRow(imageID string) DockerImage {
	return DockerImage{
		ImageID:    imageID,
		VaultID:    domain.VaultID("11111111111111111111111111111111"),
		SnapshotID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Filename:   "docker-image-" + imageID + ".tar",
		SHA256:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Bytes:      4096,
	}
}

func TestRecordAndFindDockerImages(t *testing.T) {
	c := newFreezeCatalog(t)

	id1, err := c.RecordDockerImage(freezeRow("sha256:deadbeef"))
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if len(id1) != 32 {
		t.Fatalf("entry id = %q, want 32 hex chars", id1)
	}

	got, err := c.GetDockerImage(id1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ImageID != "sha256:deadbeef" || got.Pinned != true || got.VerifiedAt != "" || got.DaemonRemovedAt != "" {
		t.Fatalf("row = %+v (want pinned, unverified, not removed at record time)", got)
	}

	// Unknown entry id.
	if _, err := c.GetDockerImage(domain.ID(strings.Repeat("z", 32))); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id err = %v, want ErrNotFound", err)
	}

	// Find by image id: oldest first, append-only duplicates preserved.
	if _, err := c.RecordDockerImage(freezeRow("sha256:deadbeef")); err != nil {
		t.Fatalf("re-freeze record: %v", err)
	}
	rows, err := c.FindDockerImages("sha256:deadbeef")
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != id1 || rows[1].ID == id1 {
		t.Fatalf("find order = %+v", rows)
	}
	if none, err := c.FindDockerImages("sha256:missing"); err != nil || len(none) != 0 {
		t.Fatalf("find missing = %v, %v", none, err)
	}

	// Validation: no snapshot/filename/digest/bytes, no row.
	bad := freezeRow("sha256:x")
	bad.SHA256 = ""
	if _, err := c.RecordDockerImage(bad); err == nil {
		t.Fatal("row without digest must be rejected")
	}
	bad2 := freezeRow("sha256:y")
	bad2.Bytes = 0
	if _, err := c.RecordDockerImage(bad2); err == nil {
		t.Fatal("row without bytes must be rejected")
	}
	if _, err := c.RecordDockerImage(DockerImage{ImageID: ""}); err == nil {
		t.Fatal("row without image id must be rejected")
	}
}

// TestCountsSeesDockerImages: Counts must count docker_images rows. The
// freeze rows are the difference between "the catalog was lost" and
// "this machine only ever froze images" — doctor's lost-catalog
// heuristic and the rebuild non-empty-catalog gate both read these
// numbers (W2-4 regression).
func TestCountsSeesDockerImages(t *testing.T) {
	c := newFreezeCatalog(t)

	ct, err := c.Counts()
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if ct.Workspaces != 0 || ct.Snapshots != 0 || ct.DockerImages != 0 {
		t.Fatalf("fresh counts = %+v, want all zero", ct)
	}

	if _, err := c.RecordDockerImage(freezeRow("sha256:aaaa")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := c.RecordDockerImage(freezeRow("sha256:bbbb")); err != nil {
		t.Fatalf("record: %v", err)
	}
	ct, err = c.Counts()
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if ct.DockerImages != 2 || ct.Workspaces != 0 || ct.Snapshots != 0 {
		t.Fatalf("counts = %+v, want 0 workspace, 0 snapshot, 2 docker images", ct)
	}
}

func TestDockerImageVerifyAndRemoveStamps(t *testing.T) {
	c := newFreezeCatalog(t)

	id, err := c.RecordDockerImage(freezeRow("sha256:cafe"))
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	// Removal BEFORE verification is refused — the freeze is not yet
	// proven evidence, so no daemon-side removal may be recorded.
	if err := c.MarkDockerImageRemoved(id, "2026-09-21T00:00:00Z"); err == nil {
		t.Fatal("removal of an unverified freeze must be refused by the catalog too")
	}

	if err := c.MarkDockerImageVerified(id, "2026-09-21T00:00:01Z"); err != nil {
		t.Fatalf("verify stamp: %v", err)
	}
	got, _ := c.GetDockerImage(id)
	if got.VerifiedAt != "2026-09-21T00:00:01Z" || got.DaemonRemovedAt != "" {
		t.Fatalf("verified row = %+v", got)
	}

	if err := c.MarkDockerImageRemoved(id, "2026-09-21T00:00:02Z"); err != nil {
		t.Fatalf("removal stamp: %v", err)
	}
	got, _ = c.GetDockerImage(id)
	if got.DaemonRemovedAt != "2026-09-21T00:00:02Z" || got.VerifiedAt == "" {
		t.Fatalf("removed row = %+v", got)
	}

	// Unknown ids are NotFound, not silent no-ops.
	if err := c.MarkDockerImageVerified(domain.ID(strings.Repeat("q", 32)), "t"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("verify unknown err = %v, want ErrNotFound", err)
	}
	if err := c.MarkDockerImageRemoved(domain.ID(strings.Repeat("q", 32)), "t"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove unknown err = %v, want ErrNotFound", err)
	}

	// Empty timestamps are argument mistakes.
	if err := c.MarkDockerImageVerified(id, ""); err == nil {
		t.Fatal("empty verification timestamp must be rejected")
	}
}

// TestSchemaV3MigrationOnExistingDB proves a v2 database upgrades in
// place to v3 without touching existing rows (forward-only migrations).
func TestSchemaV3MigrationOnExistingDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.db")

	c, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Simulate a pre-v3 database: drop the v3 table and rewind the
	// recorded version, then reopen — migrate must recreate it.
	if _, err := c.db.Exec(`DROP TABLE docker_images`); err != nil {
		t.Fatalf("drop v3 table: %v", err)
	}
	if _, err := c.db.Exec(`DELETE FROM schema_migrations WHERE version = 3`); err != nil {
		t.Fatalf("rewind version: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	c2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen (migrate v2->v3): %v", err)
	}
	defer c2.Close()
	if err := c2.RegisterVault(Vault{
		ID:           domain.VaultID("11111111111111111111111111111111"),
		Path:         filepath.Join(dir, "repo"),
		RepoID:       "fake-repo-id",
		RegisteredAt: "2026-09-21T00:00:00Z",
	}); err != nil {
		t.Fatalf("register vault after migration: %v", err)
	}
	if _, err := c2.RecordDockerImage(freezeRow("sha256:migrated")); err != nil {
		t.Fatalf("record after migration: %v", err)
	}
	rows, err := c2.ListDockerImages()
	if err != nil || len(rows) != 1 || rows[0].ImageID != "sha256:migrated" {
		t.Fatalf("post-migration rows = %+v, %v", rows, err)
	}
}
