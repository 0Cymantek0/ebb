package resticstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
)

// runRepo runs one restic command against repoDir with the passfile
// environment. It reports infra failures only (spawn, cancelation,
// timeout); a non-zero restic exit is returned in the result so each
// command can apply its own classification.
func (s *Store) runRepo(ctx context.Context, repoDir, passfile string, argv ...string) (cmdResult, error) {
	env, err := s.envFor(passfile)
	if err != nil {
		return cmdResult{}, storeErr(domain.StoreErrUnknown, "resticstore: %v", err)
	}
	full := append([]string{"--repo", repoDir}, argv...)
	res, rerr := s.run(ctx, "", env, full...)
	if rerr != nil {
		return res, storeErr(domain.StoreErrUnknown, "resticstore: %w (stderr: %s)", rerr, excerpt(res.stderr, 2048))
	}
	return res, nil
}

// failResult builds the typed error for a non-zero restic exit,
// including lock detection and a bounded stderr excerpt.
func (s *Store) failResult(res cmdResult, command string) error {
	class := classForFailure(res.exit, res.stderr)
	sc := scanStderr(res.stderr)
	var b strings.Builder
	fmt.Fprintf(&b, "restic %s failed (exit %d)", command, res.exit)
	if sc.exitMsg != "" {
		fmt.Fprintf(&b, ": %s", sc.exitMsg)
	}
	if repoLocked(res.stderr) {
		fmt.Fprintf(&b, " — repository is locked by another process; Ebb never removes backend locks automatically (no `restic unlock`)")
	}
	fmt.Fprintf(&b, "\nstderr:\n%s", excerpt(res.stderr, stderrExcerptLimit))
	return storeErr(class, "%s", b.String())
}

// Init creates a new empty repository at dir. The adapter is stateless:
// nothing is cached or persisted; use RepoID to obtain the identity.
// init has no JSON output mode; re-initializing an existing repository
// fails with exit 1 "config file already exists" (pinned live) and is
// reported as StoreErrRepo.
func (s *Store) Init(ctx context.Context, dir, passfile string) error {
	env, err := s.envFor(passfile)
	if err != nil {
		return storeErr(domain.StoreErrUnknown, "resticstore: %v", err)
	}
	res, rerr := s.run(ctx, "", env, "--repo", dir, "init")
	if rerr != nil {
		return storeErr(domain.StoreErrUnknown, "resticstore: %w", rerr)
	}
	if res.exit == 0 {
		return nil
	}
	if strings.Contains(string(res.stderr), "config file already exists") {
		return storeErr(domain.StoreErrRepo, "resticstore: repository at %s already initialized", dir)
	}
	return s.failResult(res, "init")
}

// RepoID returns the repository identity from `cat config`. The config
// file is encrypted at rest (probe Q9), so the id is only obtainable
// through the CLI with the password; it is derived on every call.
func (s *Store) RepoID(ctx context.Context, repoDir, passfile string) (string, error) {
	res, err := s.runRepo(ctx, repoDir, passfile, "cat", "config")
	if err != nil {
		return "", err
	}
	if res.exit != 0 {
		return "", s.failResult(res, "cat config")
	}
	id, perr := parseRepoID(res.stdout)
	if perr != nil {
		return "", storeErr(domain.StoreErrUnknown, "resticstore: %v (stdout: %s)", perr, truncate(strings.TrimSpace(string(res.stdout)), 200))
	}
	return id, nil
}

// List returns snapshot summaries for the repo. An empty repo yields
// an empty slice and no error (`snapshots --json` prints `[]` and
// exits 0 — pinned live against 0.19.1).
//
// Paths are reported exactly as restic recorded them: native,
// cwd-resolved absolute form (backslashes on Windows). The manifest
// bijection is confirmed against Ls tree paths, never derived from
// this field.
func (s *Store) List(ctx context.Context, repoDir, passfile string) ([]domain.SnapshotRef, error) {
	res, err := s.runRepo(ctx, repoDir, passfile, "snapshots", "--json")
	if err != nil {
		return nil, err
	}
	if res.exit != 0 {
		return nil, s.failResult(res, "snapshots")
	}
	refs, perr := parseSnapshots(res.stdout)
	if perr != nil {
		return nil, storeErr(domain.StoreErrUnknown, "resticstore: %v", perr)
	}
	return refs, nil
}
