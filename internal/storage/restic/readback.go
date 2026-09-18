package resticstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"ebb/internal/domain"
)

// Ls lists one snapshot's tree. Paths are restic tree paths
// (forward-slash, rooted at "/", e.g. "/ws/file.txt" for the D003
// relative layout). The leading snapshot header record of ls --json is
// skipped; only node records are returned. Unknown node types are
// surfaced conservatively (see mapNodeKind).
func (s *Store) Ls(ctx context.Context, repoDir, passfile, snapID string) ([]domain.TreeEntry, error) {
	if !isSnapshotID(snapID) {
		return nil, storeErr(domain.StoreErrUsage, "resticstore: snapshot id %q is not 8-64 hex characters", snapID)
	}
	res, err := s.runRepo(ctx, repoDir, passfile, "ls", "--json", snapID)
	if err != nil {
		return nil, err
	}
	if res.exit != 0 {
		return nil, refineLsError(s.failResult(res, "ls"), snapID)
	}
	entries, perr := parseLs(res.stdout)
	if perr != nil {
		return nil, storeErr(domain.StoreErrUnknown, "resticstore: %v", perr)
	}
	return entries, nil
}

// refineLsError upgrades "no matching ID" failures (exit 1,
// exit_error "no matching ID found for prefix" — pinned live) to
// StoreErrUsage: the snapshot argument was bad, not the repository.
func refineLsError(err error, snapID string) error {
	var se *domain.StoreError
	if !errors.As(err, &se) {
		return err
	}
	if se.Class == domain.StoreErrUnknown &&
		(strings.Contains(se.Error(), "no matching ID found") ||
			strings.Contains(se.Error(), "no snapshot matched")) {
		return storeErr(domain.StoreErrUsage, "resticstore: snapshot id %q not found in repository", snapID)
	}
	return err
}

// DumpFile streams one file's content out of the snapshot. path uses
// forward slashes relative to the snapshot tree root (a leading "/" is
// added when missing). The producer's exit status is checked in
// addition to stream completion: a truncated stream with a non-zero
// exit is an error, never a partial success. A zero-length result with
// exit 0 is valid (an empty stored file dumps zero bytes).
//
// restic refuses to dump symlink/junction nodes ("cannot dump file …
// should be a file" — probe Q6); that is reported as StoreErrUsage.
func (s *Store) DumpFile(ctx context.Context, repoDir, passfile, snapID, path string) ([]byte, error) {
	dump, err := normalizeDumpPath(path)
	if err != nil {
		return nil, err
	}
	if !isSnapshotID(snapID) {
		return nil, storeErr(domain.StoreErrUsage, "resticstore: snapshot id %q is not 8-64 hex characters", snapID)
	}
	res, rerr := s.runRepo(ctx, repoDir, passfile, "dump", snapID, dump)
	if rerr != nil {
		return nil, storeErr(domain.StoreErrUnknown, "resticstore: %w", rerr)
	}
	if res.exit != 0 {
		low := strings.ToLower(string(res.stderr))
		class := classForFailure(res.exit, res.stderr)
		switch {
		case strings.Contains(low, "cannot dump file"):
			class = domain.StoreErrUsage
		case strings.Contains(low, "not found in snapshot"):
			class = domain.StoreErrUsage
		}
		return nil, storeErr(class,
			"restic dump %s %s failed (exit %d); %d bytes received before failure\nstderr:\n%s",
			snapID, dump, res.exit, len(res.stdout), excerpt(res.stderr, stderrExcerptLimit))
	}
	return res.stdout, nil
}

// normalizeDumpPath validates and canonicalizes a dump path.
func normalizeDumpPath(p string) (string, error) {
	if p == "" {
		return "", storeErr(domain.StoreErrUsage, "resticstore: empty dump path")
	}
	if strings.ContainsRune(p, 0) {
		return "", storeErr(domain.StoreErrUsage, "resticstore: dump path contains NUL")
	}
	if strings.Contains(p, "\\") {
		return "", storeErr(domain.StoreErrUsage, "resticstore: dump path %q must use forward slashes", p)
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == ".." {
			return "", storeErr(domain.StoreErrUsage, "resticstore: dump path %q contains '..'", p)
		}
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p, nil
}

// Restore materializes a snapshot (optionally restricted to subtree)
// into dest. It never partially-succeeds silently: exit 0 is the only
// success; any non-zero exit returns a StoreError even though restic
// may have already created files under dest.
//
// Classification of the non-zero cases (probe Q7): a failed
// reparse-point materialization ("ignoring error for …: symlink …") is
// a content failure — the entry does not exist in the output at all —
// and maps to StoreErrSource; metadata-only failures (e.g. "failed to
// restore timestamp") map to StoreErrUnknown. Lock-held failures carry
// an explicit never-auto-unlock note.
func (s *Store) Restore(ctx context.Context, repoDir, passfile, snapID, subtree, dest string) error {
	if !isSnapshotID(snapID) {
		return storeErr(domain.StoreErrUsage, "resticstore: snapshot id %q is not 8-64 hex characters", snapID)
	}
	argv := []string{"restore", snapID, "--target", dest}
	if subtree != "" {
		norm, err := normalizeDumpPath(subtree)
		if err != nil {
			return err
		}
		argv = append(argv, "--include", strings.TrimPrefix(norm, "/"))
	}
	res, err := s.runRepo(ctx, repoDir, passfile, argv...)
	if err != nil {
		return err
	}
	if res.exit == 0 {
		return nil
	}
	class := domain.StoreErrUnknown
	sc := s.restoreFailures(res.stderr)
	if sc.contentFailures > 0 {
		class = domain.StoreErrSource
	}
	var b strings.Builder
	fmt.Fprintf(&b, "restic restore %s to %s failed (exit %d)", snapID, dest, res.exit)
	if sc.contentFailures > 0 {
		fmt.Fprintf(&b, "; %d entr(ies) failed to materialize (content missing from output)", sc.contentFailures)
	}
	if sc.metadataFailures > 0 {
		fmt.Fprintf(&b, "; %d metadata-only failure(s)", sc.metadataFailures)
	}
	if repoLocked(res.stderr) {
		fmt.Fprintf(&b, " — repository is locked by another process; Ebb never removes backend locks automatically")
	}
	fmt.Fprintf(&b, "\nstderr:\n%s", excerpt(res.stderr, stderrExcerptLimit))
	return storeErr(class, "%s", b.String())
}

// restoreOutcome summarizes restore stderr failure lines.
type restoreOutcome struct {
	contentFailures  int
	metadataFailures int
}

// restoreFailures classifies "ignoring error for <path>: <cause>"
// lines: timestamp (and similar attribute) failures are metadata-only;
// everything else — notably symlink/junction creation without
// SeCreateSymbolicLinkPrivilege — means the entry itself is absent.
func (s *Store) restoreFailures(stderr []byte) restoreOutcome {
	var o restoreOutcome
	for _, line := range strings.Split(string(stderr), "\n") {
		if !strings.Contains(line, "ignoring error for") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "failed to restore timestamp") ||
			strings.Contains(low, "failed to restore permissions") ||
			strings.Contains(low, "failed to restore attributes") {
			o.metadataFailures++
			continue
		}
		o.contentFailures++
	}
	return o
}

// Forget removes explicit snapshot IDs. restic's forget output does
// NOT echo the removed ids ("[0:00] 100.00%  1 / 1 files deleted" —
// pinned live), and — worse — forgetting a nonexistent id ALSO exits 0
// after printing "Ignoring … failed to load snapshot" on stderr
// (pinned live): a silent no-op. The adapter therefore verifies with
// List before and after: every id must exist beforehand (else
// StoreErrUsage — never silently accept a typo) and be gone afterwards
// (else StoreErrUnknown — the removal did not happen).
func (s *Store) Forget(ctx context.Context, repoDir, passfile string, snapIDs []string) error {
	if len(snapIDs) == 0 {
		return storeErr(domain.StoreErrUsage, "resticstore: Forget requires at least one snapshot id")
	}
	for _, id := range snapIDs {
		if !isSnapshotID(id) {
			return storeErr(domain.StoreErrUsage, "resticstore: snapshot id %q is not 8-64 hex characters", id)
		}
	}

	present := func(refs []domain.SnapshotRef, id string) bool {
		for _, r := range refs {
			if r.BackendID == id || (len(id) < 64 && strings.HasPrefix(r.BackendID, id)) {
				return true
			}
		}
		return false
	}

	before, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		return err
	}
	for _, id := range snapIDs {
		if !present(before, id) {
			return storeErr(domain.StoreErrUsage,
				"resticstore: forget target %s is not present in the repository (refusing silent no-op; restic itself exits 0 here)", id)
		}
	}

	argv := append([]string{"forget"}, snapIDs...)
	res, err := s.runRepo(ctx, repoDir, passfile, argv...)
	if err != nil {
		return err
	}
	if res.exit != 0 {
		return s.failResult(res, "forget")
	}

	after, err := s.List(ctx, repoDir, passfile)
	if err != nil {
		return storeErr(domain.StoreErrUnknown,
			"resticstore: forget exited 0 but post-verification list failed: %v", err)
	}
	for _, id := range snapIDs {
		if present(after, id) {
			return storeErr(domain.StoreErrUnknown,
				"resticstore: forget exited 0 but snapshot %s is still present in the repository", id)
		}
	}
	return nil
}

// isSnapshotID accepts full 64-hex ids and restic's short prefixes.
func isSnapshotID(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
