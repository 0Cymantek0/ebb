package restore

// The independent-oracle verification of Foundation §12.5 step 7 — the
// core safety property this package exists to enforce. The restore
// encoder's own success (exit status, tree listing, byte counts) is
// never accepted as evidence that the staged tree is complete: a fresh
// inventory.Scan — an oracle that shares no code path with the encoder
// — re-observes the staged tree and is compared EXACTLY against the
// retained inventory (path sets, kinds, file digests, link texts).
// This is the E10 defense: a backend that silently drops or corrupts a
// file is caught HERE, before anything is published.

import (
	"context"
	"fmt"

	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/inventory"
)

// verifyStaged scans the staged workspace tree with hashing and
// compares it exactly to the retained preserve set. ANY mismatch is a
// typed ErrVerification{Check: "oracle"}; the caller then removes the
// staging and never publishes.
func (o *Opener) verifyStaged(ctx context.Context, stagedDir string, retained []domain.Entry) error {
	res := inventory.Scan(ctx, oracleProbe{inner: o.probe}, stagedDir, inventory.Options{Hash: true})
	if res.Err != nil {
		return &ErrVerification{Check: "oracle", Details: []string{
			fmt.Sprintf("scan of staged tree %s did not complete: %v", stagedDir, res.Err)}}
	}
	diff := compareStagedToRetained(res.Entries, retained)
	if len(diff) > 0 {
		return &ErrVerification{Check: "oracle", Details: diff}
	}
	return nil
}

// compareStagedToRetained diffs the fresh scan of the staged tree
// against the retained inventory entries. It mirrors lifecycle's
// compareScanToSealed semantics (local implementation; the two must
// stay behaviorally aligned but share no code): every retained entry
// must exist with the same kind, files with the same content digest,
// links with the same literal text, and nothing else may exist.
// Metadata the fidelity contract excludes (mtimes, inode-equivalents,
// ownership labels) is deliberately not compared.
func compareStagedToRetained(actual, retained []domain.Entry) []string {
	var diff []string
	retainedByPath := make(map[string]domain.Entry, len(retained))
	for _, e := range retained {
		retainedByPath[e.Path] = e
	}
	actualByPath := make(map[string]domain.Entry, len(actual))
	for _, e := range actual {
		actualByPath[e.Path] = e
	}
	for _, e := range retained {
		got, ok := actualByPath[e.Path]
		if !ok {
			diff = append(diff, fmt.Sprintf("%s: retained %s missing from the staged tree", e.Path, e.Kind))
			continue
		}
		if got.Kind != e.Kind {
			diff = append(diff, fmt.Sprintf("%s: staged kind %q, retained %q", e.Path, got.Kind, e.Kind))
			continue
		}
		switch e.Kind {
		case domain.KindFile:
			if got.Digest != e.Digest {
				diff = append(diff, fmt.Sprintf("%s: staged content digest %s, retained %s", e.Path, got.Digest, e.Digest))
			}
		case domain.KindSymlink, domain.KindJunction, domain.KindMountPoint:
			if got.LinkTarget != e.LinkTarget {
				diff = append(diff, fmt.Sprintf("%s: staged link text %q, retained %q", e.Path, got.LinkTarget, e.LinkTarget))
			}
		}
	}
	for _, e := range actual {
		if _, ok := retainedByPath[e.Path]; !ok {
			diff = append(diff, fmt.Sprintf("%s: staged entry not present in the retained inventory", e.Path))
		}
	}
	return diff
}
