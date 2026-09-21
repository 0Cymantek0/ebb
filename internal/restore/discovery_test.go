package restore

// discovery_test.go pins DiscoverVault's snapshot classification for
// freeze blobs (W2-4): the snapshots `ebb freeze` writes (tags ebb:v1 +
// op:freeze via BackupStdin) must land in the named FreezeImages
// category — retained and reported, never mistaken for workspace
// payloads and never silently counted as unrecognized foreign snapshots.
// After a catalog loss their docker_images rows are gone and cannot be
// rebuilt from the tags; discovery classifying them by name is what lets
// the rebuild report that honestly instead of fabricating rows.

import (
	"context"
	"testing"
)

// TestDiscoverVaultClassifiesFreezeSnapshots: a freeze-tagged blob
// (ebb:v1 + op:freeze + image:<token>, the exact tag set encodeTags
// produces around the freezer's op/image tags) is reported under
// FreezeImages without disturbing the workspace pair discovery.
func TestDiscoverVaultClassifiesFreezeSnapshots(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	ctx := context.Background()

	freeze, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent,
		[]string{f.wsPrefix}, f.vault.Passfile, map[string]string{
			"ebb": "v1", "op": "freeze", "image": "sha256_frozenimage",
		})
	if err != nil {
		t.Fatalf("freeze blob snapshot: %v", err)
	}

	disc, derr := DiscoverVault(ctx, f.store, f.vault, "fake-repo-id")
	if derr != nil {
		t.Fatalf("DiscoverVault: %v", derr)
	}
	if len(disc.Pairs) != 1 {
		t.Fatalf("pairs = %d, want the fixture pair only", len(disc.Pairs))
	}
	if len(disc.FreezeImages) != 1 || disc.FreezeImages[0] != freeze.BackendID {
		t.Fatalf("freeze images = %v, want exactly [%s]", disc.FreezeImages, freeze.BackendID)
	}
	if len(disc.Unrecognized) != 0 {
		t.Fatalf("unrecognized = %v, want none (the freeze blob is classified, not unknown)", disc.Unrecognized)
	}
	if len(disc.Suspicious) != 0 || len(disc.Unsealed) != 0 {
		t.Fatalf("suspicious = %v, unsealed = %v, want none of either", disc.Suspicious, disc.Unsealed)
	}
	// The blob is retained untouched.
	if _, ok := f.store.snaps[freeze.BackendID]; !ok {
		t.Fatal("the freeze blob was deleted from the store")
	}
}

// TestDiscoverVaultFreezeTagNeedsEbbBaseTag: op:freeze WITHOUT the
// ebb:v1 base tag is not Ebb's snapshot — the strict pair keeps it in
// Unrecognized (tags are hints, and only ebb:v1 + op:freeze names a
// freeze blob).
func TestDiscoverVaultFreezeTagNeedsEbbBaseTag(t *testing.T) {
	f := buildFixture(t, fixtureSpec{})
	ctx := context.Background()

	if _, err := f.store.Snapshot(ctx, f.vault.RepoDir, f.parent,
		[]string{f.wsPrefix}, f.vault.Passfile, map[string]string{"op": "freeze"}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	disc, derr := DiscoverVault(ctx, f.store, f.vault, "fake-repo-id")
	if derr != nil {
		t.Fatalf("DiscoverVault: %v", derr)
	}
	if len(disc.FreezeImages) != 0 {
		t.Fatalf("freeze images = %v, want none (no ebb:v1 base tag)", disc.FreezeImages)
	}
	if len(disc.Unrecognized) != 1 {
		t.Fatalf("unrecognized = %v, want the bare op:freeze snapshot reported as unrecognized", disc.Unrecognized)
	}
}
