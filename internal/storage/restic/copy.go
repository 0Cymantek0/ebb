package resticstore

import (
	"context"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// copy.go implements cross-repository snapshot copying for portable
// capsules (Foundation §15.2). All behavior here is pinned against the
// live probe of restic 0.19.1 (lab/restic-probe/copy/FINDINGS.md):
//
//   - 0.19.1 has NO --repo2/--password-file2. The DESTINATION repository
//     rides the global flags: --repo in argv plus RESTIC_PASSWORD_FILE in
//     the environment (exactly what envFor builds). The SOURCE repository
//     uses the dedicated --from-repo and --from-password-file flags. Only
//     passfile PATHS ever appear in argv; no secret does.
//   - Copy of a nonexistent snapshot id exits 0 with `Ignoring "…": no
//     matching ID found` on stderr (the forget pattern). Copy exit 0
//     therefore proves nothing by itself: this method converts an
//     Ignoring line into a typed failure, and the caller (internal/
//     capsule) additionally verifies the destination state by List +
//     tag discovery before trusting anything.
//   - Snapshot ids CHANGE on copy (the copy records the source id in an
//     `original` field and preserves tags); discovery is the caller's
//     job, never id equality.
//   - Exit codes: 1 generic, 10 destination missing (not initialized),
//     11 locked, 12 wrong password (map: exitClass + failResult).
//
// Copy does not belong on domain.SnapshotStore: cross-repository
// transfer is a capsule-export capability, not part of the
// capture/verify/restore contract every store implementation (including
// test fakes) must carry. It is interface-segregated like TreeTarDumper;
// internal/capsule consumes domain.SnapshotStore + this method.
type Copier interface {
	Copy(ctx context.Context, srcRepoDir, srcPassfile, dstRepoDir, dstPassfile string, snapIDs []string) error
}

// Copy transfers the listed snapshot ids from the source repository to
// the destination repository. Both passwords travel via ephemeral
// passfile paths only: the destination's through RESTIC_PASSWORD_FILE
// (envFor), the source's through --from-password-file (an argv PATH, not
// a secret). The destination repository must already be initialized
// (Init); copying into an uninitialized directory fails with exit 10.
//
// Every snapshot id is validated client-side as a full 64-hex id before
// any subprocess runs (D005: a "--"-prefixed id must never become a
// restic flag).
func (s *Store) Copy(ctx context.Context, srcRepoDir, srcPassfile, dstRepoDir, dstPassfile string, snapIDs []string) error {
	if len(snapIDs) == 0 {
		return storeErr(domain.StoreErrUsage, "resticstore: copy: no snapshot ids")
	}
	for i, id := range snapIDs {
		if !isHexID(id, 64) {
			return storeErr(domain.StoreErrUsage, "resticstore: copy: snapshot id %d %q is not a full 64-hex id", i, id)
		}
	}
	env, err := s.envFor(dstPassfile)
	if err != nil {
		return storeErr(domain.StoreErrUnknown, "resticstore: %v", err)
	}
	argv := append([]string{
		"--repo", dstRepoDir,
		"copy",
		"--from-repo", srcRepoDir,
		"--from-password-file", srcPassfile,
	}, snapIDs...)

	res, rerr := s.run(ctx, "", env, argv...)
	if rerr != nil {
		return storeErr(domain.StoreErrUnknown, "resticstore: %w (stderr: %s)", rerr, excerpt(res.stderr, 2048))
	}
	if res.exit != 0 {
		return s.failResult(res, "copy")
	}
	// restic copy silently skips unknown ids with exit 0 (probe C10,
	// mirroring forget). A skipped id means the source vault does not
	// hold the snapshot the caller believes it holds — surface it as a
	// typed failure instead of letting verification discover an
	// under-populated destination later.
	if line, skipped := ignoredSnapshot(res.stderr); skipped {
		return storeErr(domain.StoreErrSource,
			"resticstore: copy: %s (the snapshot is absent from the source repository; nothing was transferred for it)", line)
	}
	return nil
}

// ignoredSnapshot scans copy stderr for the `Ignoring "<id>"` line
// restic emits when asked to copy a snapshot that does not exist in the
// source repository, while still exiting 0. Two live-pinned message
// forms (lab/restic-probe/copy + adapter conformance): a PREFIX id
// yields `Ignoring "…": no matching ID found for prefix "…"`, a FULL
// 64-hex id yields `Ignoring "…": failed to load snapshot …: open …:
// The system cannot find the file specified.` — the stable token is the
// `Ignoring "` prefix itself.
func ignoredSnapshot(stderr []byte) (string, bool) {
	for _, line := range strings.Split(string(stderr), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Ignoring \"") {
			return line, true
		}
	}
	return "", false
}

// interface assertion: the concrete store carries the capsule capability.
var _ Copier = (*Store)(nil)
