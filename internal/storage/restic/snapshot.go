package resticstore

import (
	"context"
	"fmt"
	"os"
	"strings"

	"ebb/internal/domain"
)

// Snapshot captures exactly the listed baseDir-relative paths and
// returns the backend snapshot reference.
//
// Layout (D003): the restic subprocess runs with cwd = baseDir and a
// --files-from-raw NUL list of relative entries, so the snapshot tree
// prefixes are exactly /<first-segment>/... with no synthetic /C/...
// ancestor chain (which would carry real ACLs back on restore).
//
// Failure contract (Foundation §11.2): the capture is failed when the
// exit code is non-zero OR stderr carries any per-file error record OR
// the summary is a dry-run — EVEN THOUGH restic still stored a
// snapshot in the repo in the source-error case. The incomplete
// snapshot is unmarked (probe Q4a); the returned error names its id so
// callers can treat it as suspect, never as a capture. A returned id
// never authorizes removal.
func (s *Store) Snapshot(ctx context.Context, repoDir, baseDir string, relPaths []string, passfile string, tags map[string]string) (domain.SnapshotRef, error) {
	clean, err := ValidateRelPaths(relPaths)
	if err != nil {
		return domain.SnapshotRef{}, err
	}
	tagArgs, tagMap, err := encodeTags(tags)
	if err != nil {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUsage, "resticstore: %v", err)
	}
	if fi, err := os.Stat(baseDir); err != nil || !fi.IsDir() {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUsage, "resticstore: baseDir %q is not an existing directory", baseDir)
	}

	tmp, err := os.MkdirTemp("", "ebb-restic-list-")
	if err != nil {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUnknown, "resticstore: capture temp dir: %v", err)
	}
	defer os.RemoveAll(tmp)
	listFile, err := writeListFile(tmp, clean)
	if err != nil {
		return domain.SnapshotRef{}, err
	}

	env, err := s.envFor(passfile)
	if err != nil {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUnknown, "resticstore: %v", err)
	}
	argv := append([]string{
		"--repo", repoDir,
		"backup", "--json",
		"--host", backupHost,
	}, tagArgs...)
	argv = append(argv, "--files-from-raw", listFile)

	res, rerr := s.run(ctx, baseDir, env, argv...)
	if rerr != nil {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUnknown, "resticstore: %w", rerr)
	}

	summary, _, perr := parseBackupSummary(res.stdout)
	sc := scanStderr(res.stderr)

	failed := res.exit != 0 || perr != nil || len(sc.errRecords) > 0
	if !failed && summary != nil && summary.DryRun {
		// We never pass --dry-run; a dry-run summary means the command
		// was not what Snapshot issued (probe Q3: dry-run ids are
		// prospective and no snapshot exists).
		failed = true
	}
	if failed {
		class := classForFailure(res.exit, res.stderr)
		if res.exit == 0 && len(sc.errRecords) > 0 {
			class = domain.StoreErrSource
		}
		var b strings.Builder
		fmt.Fprintf(&b, "restic backup failed (exit %d)", res.exit)
		if perr != nil {
			fmt.Fprintf(&b, ": %v", perr)
		}
		if summary != nil && summary.SnapshotID != "" {
			fmt.Fprintf(&b, "; an INCOMPLETE snapshot %s was stored and must never be used as a capture", summary.SnapshotID)
		}
		for _, m := range sc.errRecords {
			fmt.Fprintf(&b, "\n  source error: %s", m)
		}
		if sc.exitMsg != "" {
			fmt.Fprintf(&b, "\n  exit_error: %s", sc.exitMsg)
		}
		if repoLocked(res.stderr) {
			fmt.Fprintf(&b, "\n  repository is locked by another process; Ebb never removes backend locks automatically")
		}
		fmt.Fprintf(&b, "\nstderr:\n%s", excerpt(res.stderr, stderrExcerptLimit))
		return domain.SnapshotRef{}, storeErr(class, "%s", b.String())
	}

	if !isHexID(summary.SnapshotID, 64) {
		return domain.SnapshotRef{}, storeErr(domain.StoreErrUnknown,
			"resticstore: backup summary snapshot_id %q is not a full 64-hex id", summary.SnapshotID)
	}
	return domain.SnapshotRef{
		BackendID: summary.SnapshotID,
		ShortID:   summary.SnapshotID[:8],
		Time:      summary.BackupEnd,
		Paths:     clean,
		Tags:      tagMap,
	}, nil
}
