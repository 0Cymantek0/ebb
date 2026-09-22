package resticstore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// Prune asks the backend to reclaim storage that is no longer referenced
// by ANY snapshot in the repository (Foundation §11.6: Ebb never
// maintains blob reference counts or deletes packfiles — it asks restic
// and verifies). The argv is the literal `prune` with no retention
// flags: restic's prune defaults reclaim all unreferenced data
// (probe-pinned: after forgetting one of two snapshots, "unused size
// after prune: 0 B"), so `--max-unused`/`--keep-*` would only WEAKEN
// that. Retention is Ebb's explicit forget, never a prune-side policy.
//
// Safety assertion (the gc-side equivalent of forget's List
// verification, D015): restic prune NEVER removes snapshots — so the
// adapter proves it per call. The snapshot id set is listed BEFORE the
// prune and AFTER it and must be IDENTICAL. Any difference — or a failed
// post-prune list — is a typed StoreErrIntegrity (Ebb exit 4: the
// outcome could not be proven safe), reporting both sets. A failed
// PRE-prune list propagates its own class (repo/auth; nothing ran yet).
//
// DryRun (restic prune --dry-run, probe-pinned): exits 0, prints the
// same summary prefixed "Would have made the following changes:", and
// provably mutates nothing. The same snapshot-set assertion still runs —
// cheap, and it proves the no-mutation claim beyond restic's word.
//
// Locking honesty (Foundation §12.1): prune takes an exclusive restic
// lock; a concurrently-running restic process (even one holding only a
// shared backup lock) makes it fail with exit 11 + "repository is
// already locked" on stderr. That surfaces typed as StoreErrRepo with
// the never-unlock note; the adapter never runs `restic unlock`.
//
// Output: prune has NO JSON mode (--json is accepted but ignored —
// probe-pinned), so the reclaim estimate is parsed from the text
// summary's "total prune: N blobs / X" line.
func (s *Store) Prune(ctx context.Context, repoDir, passfile string, opts domain.PruneOptions) (domain.PruneStats, error) {
	stats := domain.PruneStats{DryRun: opts.DryRun}

	before, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		return stats, err
	}

	argv := []string{"prune"}
	if opts.DryRun {
		argv = append(argv, "--dry-run")
	}
	res, rerr := s.runRepo(ctx, repoDir, passfile, argv...)
	if rerr != nil {
		return stats, rerr
	}
	if res.exit != 0 {
		err := s.failResult(res, "prune")
		// Probe-pinned: a locked repo exits 11 with "unable to create
		// lock in backend: repository is already locked" on stderr — 11
		// is not in the generic exit-class table, and a locked vault is
		// a repo-availability failure (Ebb exit 7), not an unknown.
		if repoLocked(res.stderr) {
			var se *domain.StoreError
			if errors.As(err, &se) {
				se.Class = domain.StoreErrRepo
			}
		}
		return stats, err
	}
	stats.ReclaimableBytes = parsePruneEstimate(res.stdout)

	after, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		return stats, storeErr(domain.StoreErrIntegrity,
			"resticstore: prune exited 0 but the post-prune verification list failed, so snapshot survival is NOT verified (treat the vault as suspect): %v", err)
	}
	beforeIDs, afterIDs := snapshotIDSet(before), snapshotIDSet(after)
	if !equalIDSets(beforeIDs, afterIDs) {
		return stats, storeErr(domain.StoreErrIntegrity,
			"resticstore: prune exited 0 but the snapshot set CHANGED — prune must never remove snapshots; before=%s after=%s. Treat the vault as suspect and inspect it before any further gc/forget",
			formatIDSet(beforeIDs), formatIDSet(afterIDs))
	}
	return stats, nil
}

// snapshotIDSet reduces refs to their sorted full backend ids.
func snapshotIDSet(refs []domain.SnapshotRef) []string {
	ids := make([]string, 0, len(refs))
	for _, r := range refs {
		ids = append(ids, r.BackendID)
	}
	sort.Strings(ids)
	return ids
}

func equalIDSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// formatIDSet renders an id set for an error message, bounded so a large
// vault cannot produce a megabyte error string.
func formatIDSet(ids []string) string {
	const limit = 20
	parts := append([]string(nil), ids...)
	if len(parts) > limit {
		parts = append(parts[:limit:limit], fmt.Sprintf("…(+%d more)", len(ids)-limit))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// parsePruneEstimate extracts the backend's own reclaim estimate from
// prune's text summary: the "total prune: N blobs / X" line (probe: it
// equals "this removes" + "to delete" and is the bytes a real prune
// frees; sizes are human-formatted "1.997 KiB" style). 0 when no
// parseable line exists — the caller treats 0 as "estimate unreported",
// never as "nothing reclaimable".
func parsePruneEstimate(stdout []byte) int64 {
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "total prune:") {
			continue
		}
		// "total prune:             3 blobs / 1.997 KiB"
		slash := strings.LastIndexByte(line, '/')
		if slash < 0 {
			continue
		}
		if n, ok := parseHumanBytes(line[slash+1:]); ok {
			return n
		}
	}
	return 0
}

// parseHumanBytes parses restic's human size forms: "570 B", "1.997 KiB",
// "12.5 MiB", "2 GiB", "1 TiB", "512 PiB" (decimal fractions, binary
// multiples — probe-pinned spellings).
func parseHumanBytes(s string) (int64, bool) {
	fields := strings.Fields(strings.TrimSpace(s))
	if len(fields) != 2 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || v < 0 {
		return 0, false
	}
	var mult float64 = 1
	switch fields[1] {
	case "B":
		mult = 1
	case "KiB":
		mult = 1 << 10
	case "MiB":
		mult = 1 << 20
	case "GiB":
		mult = 1 << 30
	case "TiB":
		mult = 1 << 40
	case "PiB":
		mult = 1 << 50
	case "EiB":
		mult = 1 << 60
	default:
		return 0, false
	}
	n := v * mult
	if math.IsInf(n, 0) || n > float64(math.MaxInt64) {
		return 0, false
	}
	return int64(math.Round(n)), true
}

// compile-time seam check: the Store is the optional domain.RepoPruner
// exactly the way it is the optional TreeTarDumper (D007 shape).
var _ domain.RepoPruner = (*Store)(nil)
