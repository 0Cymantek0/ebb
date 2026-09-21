// app.go is the composition root of the CLI: the production dependency
// set (RealDeps) and the shared discovery pipeline both `inspect` and
// `plan` run before presentation. Foundation §8.1: inspect is
// metadata-first — identity, volume, Git topology, tracked files and a
// no-digest inventory walk; content hashing belongs to the capture pass.

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"ebb/internal/adapters/docker"
	"ebb/internal/adapters/ecosystem"
	gitadapter "ebb/internal/adapters/git"
	"ebb/internal/analyse"
	"ebb/internal/catalog"
	"ebb/internal/cli/tui"
	"ebb/internal/domain"
	"ebb/internal/inventory"
	"ebb/internal/lifecycle"
	"ebb/internal/platform"
	"ebb/internal/policy"
	"ebb/internal/restore"
	resticstore "ebb/internal/storage/restic"
	"ebb/internal/vault"
)

// RealDeps wires the production dependency set: the native platform
// probe, the hardened Git observer and tracked-files adapter, the real
// metadata-first inventory scanner, the Wave E durable-state seams
// (vault.EnsureConfigDir state dir, SQLite catalog, restic store,
// lifecycle/restore constructors, ecosystem detection) and the terminal
// environment (stdin-tty detection, line reading, SIGINT/SIGTERM
// context).
//
// Wave 2 analyse seams: the lock probe adapts the native
// platform.WriterInspector (Restart Manager on Windows). The git
// survey and docker engine seams stay nil until their Wave 2 adapters
// land (WB/WC); `ebb analyse` degrades honestly with a warning in the
// meantime and the orchestrator wires them at merge.
func RealDeps() Deps {
	deps := Deps{
		NewProbe:   platform.New,
		ObserveGit: gitadapter.Observe,
		GitTracked: gitadapter.TrackedFiles,
		ScanInventory: func(ctx context.Context, probe domain.PlatformProbe, root string) (domain.InventorySummary, []domain.Entry, error) {
			// Hash=false: digests are deferred to the capture pass
			// (Foundation §8.1 two passes).
			res := inventory.Scan(ctx, probe, root, inventory.Options{Hash: false})
			return res.Summary, res.Entries, res.Err
		},
		StateDir:    vault.EnsureConfigDir,
		OpenCatalog: catalog.Open,
		NewStore: func() (domain.SnapshotStore, func(), error) {
			// Resolve the backend through PATH ourselves and hand New an
			// absolute path; a missing binary is a provider-unavailable
			// block. (resticstore.New PATH-resolves bare names itself
			// since the W2-7 fix; this keeps the failure typed here.)
			bin, lerr := exec.LookPath("restic")
			if lerr != nil {
				return nil, nil, vaultError(fmt.Errorf("restic binary not found on PATH (capture backend prerequisite; `ebb doctor` reports tool details)"))
			}
			s := resticstore.New(bin)
			return s, s.Close, nil
		},
		NewLifecycle: lifecycle.New,
		NewRestoreOp: restore.New,
		DetectEcosystem: func(root string) (ecosystem.Detection, error) {
			return ecosystem.Detect(root)
		},
		PickWorkspace: func(ctx context.Context, title string, rows []WorkspaceChoice, out io.Writer) (int, error) {
			trows := make([]tui.Row, len(rows))
			for i, r := range rows {
				trows[i] = tui.Row{Label: r.Name, Detail: r.Detail, Right: r.Right}
			}
			return tui.Select(ctx, tui.StdioTerminal(os.Stdin, out), tui.SelectModel{
				Title:  title,
				Rows:   trows,
				Footer: []string{"↑/↓ navigate", "Enter open", "Esc cancel"},
			})
		},
		StdinIsTerminal: statModelessTTY,
		ReadLine: func() (string, error) {
			// One bounded line from stdin; interactive callers have
			// already verified stdin is a terminal.
			r := bufio.NewReader(io.LimitReader(os.Stdin, 4096))
			line, err := r.ReadString('\n')
			if err != nil && line == "" {
				return "", err
			}
			return strings.TrimRight(line, "\r\n"), nil
		},
		NewSignalContext: func() (context.Context, func()) {
			// SIGINT (Ctrl+C, both platforms) and SIGTERM cancel the
			// command context; coordinators keep the last durable phase
			// and the CLI maps the cancellation to exit 130 (§17.5).
			return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		},
	}
	// Analyse lock probe: the native writer inspector when the platform
	// offers one (Restart Manager); absent capabilities degrade to the
	// engine's open probe (never a false [LOCKED]).
	if insp, err := platform.NewWriterInspector(); err == nil {
		deps.AnalyseLockProbe = writerInspectorAsLockProbe{insp}
	}
	// Git survey: the hardened adapter's SurveyRepo (D037), converted
	// field-for-field into the analyse-side frozen shape.
	deps.AnalyseGitSurvey = gitSurveyorAdapter{}
	// Docker engine: wired only when a docker binary is on PATH; absence
	// keeps the seam nil and `ebb analyse --docker` degrades honestly.
	if bin, lerr := exec.LookPath("docker"); lerr == nil {
		deps.AnalyseDocker = dockerEngineAdapter{eng: dockeradapter.New(bin)}
	}
	// Wave 3 stats recording: one best-effort event append per
	// dispatched verb, through a short-lived catalog open over the SAME
	// state-dir seam the session machinery honors (so test overrides of
	// StateDir keep telemetry inside the test world). Failures are the
	// caller's to warn about, never the command's to fail on.
	deps.RecordStatEvent = func(e catalog.StatEvent) error {
		dir, err := deps.StateDir()
		if err != nil {
			return fmt.Errorf("stats event: state dir: %w", err)
		}
		cat, err := catalog.Open(filepath.Join(dir, vault.CatalogFile))
		if err != nil {
			return fmt.Errorf("stats event: open catalog: %w", err)
		}
		defer cat.Close()
		return cat.AppendStatEvent(context.Background(), e)
	}
	return deps
}

// gitSurveyorAdapter converts gitadapter.RepoSummary into the
// analyse-side frozen interface type (field-for-field; the two packages
// must never import each other).
type gitSurveyorAdapter struct{}

func (gitSurveyorAdapter) SurveyRepo(ctx context.Context, root string) (analyse.RepoSummary, error) {
	rs, err := gitadapter.SurveyRepo(ctx, root)
	if err != nil {
		return analyse.RepoSummary{}, err
	}
	return analyse.RepoSummary{
		IsRepo: rs.IsRepo, Branch: rs.Branch, HeadCommit: rs.HeadCommit,
		Detached: rs.Detached, DirtyWorktree: rs.DirtyWorktree,
		UnmergedEntries: rs.UnmergedEntries, IsWorktree: rs.IsWorktree,
		WorktreeMain: rs.WorktreeMain, MergedUpstream: rs.MergedUpstream,
		UnpushedCommits: rs.UnpushedCommits, LastActivityAt: rs.LastActivityAt,
		StaleMergedBranches: rs.StaleMergedBranches, LFSObjectsBytes: rs.LFSObjectsBytes,
		Warnings: rs.Warnings,
	}, nil
}

// dockerEngineAdapter converts the docker adapter's report into the
// analyse-side frozen interface type.
type dockerEngineAdapter struct{ eng *dockeradapter.Engine }

func (a dockerEngineAdapter) Report(ctx context.Context, workspaceRoots []string) (analyse.DockerReport, error) {
	dr, err := a.eng.Report(ctx, workspaceRoots)
	if err != nil {
		return analyse.DockerReport{}, err
	}
	tiers := make([]analyse.DockerTier, len(dr.Tiers))
	for i, t := range dr.Tiers {
		items := make([]analyse.DockerItem, len(t.Items))
		for j, it := range t.Items {
			items[j] = analyse.DockerItem{ID: it.ID, Detail: it.Detail, Shield: it.Shield}
		}
		tiers[i] = analyse.DockerTier{Tier: t.Tier, Title: t.Title, Items: items, CopyCommand: t.CopyCommand}
	}
	return analyse.DockerReport{
		Available: dr.Available, Tiers: tiers,
		HostSlack: dr.HostSlack, SlackCommand: dr.SlackCommand, Warnings: dr.Warnings,
	}, nil
}

// writerInspectorAsLockProbe adapts platform.WriterInspector to
// analyse.LockProbe (the analyse package stays platform-neutral; the
// CLI owns the injection).
type writerInspectorAsLockProbe struct{ insp platform.WriterInspector }

func (a writerInspectorAsLockProbe) InspectWriters(paths []string) ([]analyse.LockWriter, error) {
	writers, err := a.insp.InspectWriters(paths)
	if err != nil {
		return nil, err
	}
	out := make([]analyse.LockWriter, 0, len(writers))
	for _, w := range writers {
		out = append(out, analyse.LockWriter{Name: w.Name, PID: w.PID})
	}
	return out, nil
}

// cliError carries the process exit code for a pipeline failure so the
// command layer never guesses classifications.
type cliError struct {
	code int
	err  error
}

func (e *cliError) Error() string { return e.err.Error() }
func (e *cliError) Unwrap() error { return e.err }

func usageError(err error) error   { return &cliError{code: ExitUsage, err: err} }
func blockedError(err error) error { return &cliError{code: ExitBlocked, err: err} }
func vaultError(err error) error   { return &cliError{code: ExitVault, err: err} }

// discovery is everything the shared pipeline produced for one root.
type discovery struct {
	Root     string
	Ident    domain.RootIdentity
	Volume   domain.VolumeUsage
	Obs      domain.GitObservation
	Summary  domain.InventorySummary
	Entries  []domain.Entry
	Policy   policy.Policy
	Resolved policy.Resolved

	// TrackedEntries/AdminEntries count entries that received the
	// git:tracked / git:admin evidence tokens.
	TrackedEntries int
	AdminEntries   int

	Warnings []string
}

// runDiscovery performs the shared live pipeline for a workspace root:
// resolve + stat the path, probe root identity and volume usage, observe
// Git topology, print the first-progress line, scan the tree
// metadata-first, annotate Git evidence on entries, parse policy and
// resolve routes. Progress (the "scanning..." line) goes to progress,
// which is the human stream even in --json mode (Foundation §14.4:
// visible progress within one second; full progress streaming with
// per-phase events is later work).
//
// Failure classification: usage-class failures (bad Ebbfile, resolve
// error) wrap ExitUsage; blocked-class failures (missing path,
// unidentifiable root, incomplete scan) wrap ExitBlocked. Degradeable
// observations (volume usage, git) become Warnings, never failures.
func runDiscovery(ctx context.Context, deps Deps, rootArg string, progress io.Writer) (discovery, error) {
	var d discovery

	root, err := filepath.Abs(rootArg)
	if err != nil {
		return d, usageError(fmt.Errorf("resolving path %q: %w", rootArg, err))
	}
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return d, blockedError(fmt.Errorf("path not found: %s", rootArg))
		}
		return d, blockedError(fmt.Errorf("stat %s: %v", root, err))
	}
	d.Root = root

	// Platform seam.
	newProbe := deps.NewProbe
	if newProbe == nil {
		return d, usageError(fmt.Errorf("platform probe %w", ErrNotIntegrated))
	}
	probe := newProbe()

	ident, err := probe.RootIdentity(root)
	if err != nil {
		return d, blockedError(fmt.Errorf("root identity for %s: %v", root, err))
	}
	d.Ident = ident

	if usage, err := probe.VolumeUsage(root); err != nil {
		d.Warnings = append(d.Warnings, fmt.Sprintf("volume usage unavailable: %v", err))
	} else {
		d.Volume = usage
	}

	// Git topology (diagnostics; failure degrades to a warning).
	if deps.ObserveGit == nil {
		d.Warnings = append(d.Warnings, "git observation "+ErrNotIntegrated.Error())
	} else if obs, err := deps.ObserveGit(ctx, root); err != nil {
		d.Warnings = append(d.Warnings, fmt.Sprintf("git observation unavailable: %v", err))
	} else {
		d.Obs = obs
		d.Warnings = append(d.Warnings, obs.Warnings...)
	}

	// Foundation §14.4 acceptance target: something visible within one
	// second. Per-entry/progress streaming is deliberately later work.
	if progress != nil {
		fmt.Fprintf(progress, "scanning %s...\n", root)
	}

	scan := deps.ScanInventory
	if scan == nil {
		return d, usageError(fmt.Errorf("inventory scan %w", ErrNotIntegrated))
	}
	summary, entries, err := scan(ctx, probe, root)
	if err != nil {
		return d, blockedError(fmt.Errorf("inventory scan %s: %w", root, err))
	}
	d.Summary, d.Entries = summary, entries

	// Tracked-files annotation feeds policy.Resolve's F53 cancellation
	// (internal/policy sourceEvidenceToken).
	if deps.GitTracked == nil {
		d.Warnings = append(d.Warnings, "git tracked-files "+ErrNotIntegrated.Error())
	} else if tracked, err := deps.GitTracked(ctx, root); err != nil {
		d.Warnings = append(d.Warnings, fmt.Sprintf("git tracked-files unavailable: %v", err))
	} else {
		rootAdminInside := d.Obs.IsRepo && d.Obs.AdminInsideRoot
		d.TrackedEntries, d.AdminEntries = annotateGitEvidence(entries, tracked, rootAdminInside)
	}

	// Policy: an explicit Ebbfile must parse strictly; when absent the
	// conservative defaults apply (Foundation §7.1).
	pol, polErr := policy.ParseFile(filepath.Join(root, "Ebbfile.toml"))
	switch {
	case polErr == nil:
	case errors.Is(polErr, os.ErrNotExist):
		pol = policy.Default(workspaceLabel(root))
	default:
		return d, usageError(polErr)
	}
	d.Policy = pol

	resolved, err := policy.Resolve(entries, pol)
	if err != nil {
		return d, usageError(err)
	}
	d.Resolved = resolved
	return d, nil
}

// annotateGitEvidence attaches the F53 evidence tokens policy.Resolve
// consumes: `git:tracked` for paths in the root repository's index and
// `git:admin` for entries inside a Git administration directory. The
// root repository's top-level `.git/` is annotated only when its
// administration is contained in the root (AdminInsideRoot); a NESTED
// repository's `.git` (e.g. one inside node_modules) is inside the root
// by construction and is always annotated — its mount point must not be
// ommissible. Tokens are the exact strings internal/policy matches with
// the `git:tracked`/`git:admin` prefixes.
func annotateGitEvidence(entries []domain.Entry, tracked map[string]bool, rootAdminInside bool) (trackedN, adminN int) {
	for i := range entries {
		e := &entries[i]
		if tracked[e.Path] {
			addEntryEvidence(e, "git:tracked")
			trackedN++
		}
		if underGitAdmin(e.Path, rootAdminInside) {
			addEntryEvidence(e, "git:admin")
			adminN++
		}
	}
	return trackedN, adminN
}

// addEntryEvidence appends tokens without mutating the backing array of
// the entry's existing slice (same discipline as policy.addEvidence).
func addEntryEvidence(e *domain.Entry, tokens ...string) {
	merged := make([]string, 0, len(e.Evidence)+len(tokens))
	merged = append(merged, e.Evidence...)
	merged = append(merged, tokens...)
	e.Evidence = merged
}

// underGitAdmin reports whether the root-relative path lies inside a Git
// administration directory: a `.git` path segment. A FIRST segment
// `.git` counts only when the root repository's admin dir is inside the
// root (AdminInsideRoot); later `.git` segments are nested repositories
// whose administration is inside the root by construction.
func underGitAdmin(p string, rootAdminInside bool) bool {
	if p == "" {
		return false
	}
	first := true
	for len(p) > 0 {
		var seg string
		if i := strings.IndexByte(p, '/'); i >= 0 {
			seg, p = p[:i], p[i+1:]
		} else {
			seg, p = p, ""
		}
		if seg == ".git" {
			if first {
				return rootAdminInside
			}
			return true
		}
		first = false
	}
	return false
}
