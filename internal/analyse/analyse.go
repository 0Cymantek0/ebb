// Package analyse implements `ebb analyse` (product evolution plan §11,
// ADR D037): autonomous discovery of developer workspaces under
// configured parent roots, shallow non-destructive footprint probing,
// staleness/merge classification, and batch reclamation
// recommendations rendered as copyable commands.
//
// Everything in this package is READ-ONLY. The engine never mutates a
// workspace: it stats known output roots, reads directory listings,
// reads one workspace manifest when a monorepo boundary must be proven,
// and consumes injected seams (git survey, docker engine, lock probe).
// Destructive action belongs to the CLI's explicit batch flags, which
// delegate to `git worktree remove` and the existing ebb lifecycle
// commands — never to this package.
//
// Platform neutrality: the package never imports internal/platform. The
// Restart-Manager lock probe is consumed through LockProbe; the CLI
// injects the native adapter.
//
// Honesty rules (Foundation §14.1): footprint numbers are SHALLOW
// logical estimates (top-level entries of known output roots; never a
// recursive walk) and every surface that shows them labels them
// "estimated". A missing git survey degrades to mtime evidence with a
// warning, never to invented facts.
package analyse

import (
	"context"
	"sort"
	"sync"
	"time"
)

// RepoSummary is one workspace's Git topology facts for categorization.
// The concrete subprocess observer lives in internal/adapters/git
// (Wave 2 WB); analyse defines and consumes the seam. The Go field set
// is the frozen Wave 2 interface; the JSON tags only define the
// envelope's machine spelling and add no fields.
type RepoSummary struct {
	IsRepo              bool      `json:"IsRepo"`
	Branch              string    `json:"Branch,omitempty"` // display form, "" on detached
	HeadCommit          string    `json:"HeadCommit,omitempty"`
	Detached            bool      `json:"Detached,omitempty"`
	DirtyWorktree       bool      `json:"DirtyWorktree,omitempty"`
	UnmergedEntries     int64     `json:"UnmergedEntries,omitempty"` // >0 means in-flight conflict
	IsWorktree          bool      `json:"IsWorktree,omitempty"`      // linked worktree of a main checkout
	WorktreeMain        string    `json:"WorktreeMain,omitempty"`    // the main checkout's path when IsWorktree
	MergedUpstream      bool      `json:"MergedUpstream,omitempty"`  // HEAD commit is an ancestor of the upstream/default branch
	UnpushedCommits     int64     `json:"UnpushedCommits,omitempty"` // @{u}..HEAD count; -1 = no upstream configured
	LastActivityAt      time.Time `json:"LastActivityAt,omitempty"`  // best-evidence last developer activity (HEAD commit time; zero = unknown)
	StaleMergedBranches []string  `json:"StaleMergedBranches,omitempty"`
	LFSObjectsBytes     int64     `json:"LFSObjectsBytes,omitempty"` // -1 unknown/unavailable
	Warnings            []string  `json:"Warnings,omitempty"`
}

// GitSurveyor observes one workspace root's Git topology. SurveyRepo
// must be read-only (git plumbing invocation; never a mutating git
// command).
type GitSurveyor interface {
	SurveyRepo(ctx context.Context, root string) (RepoSummary, error)
}

// DockerTier is one tier of the D040 seven-tier Docker squeeze-out
// taxonomy (0..6). The concrete engine lives in
// internal/adapters/docker (Wave 2 WC); analyse defines and consumes
// the seam.
type DockerTier struct {
	Tier        int // 0..6 per D040
	Title       string
	Items       []DockerItem
	CopyCommand string // one copyable native command applying this tier's recommendation
}

// DockerItem is one reclaimable-or-shielded Docker object.
type DockerItem struct {
	ID     string // image id / volume name / container id
	Detail string // size, age, correlation note
	Shield string // non-empty = protected, never recommended for removal
}

// DockerReport is the Docker engine's aggregate result.
type DockerReport struct {
	Available    bool
	Tiers        []DockerTier
	HostSlack    int64  // Windows VHDX physical-vs-logical slack bytes; 0 unknown
	SlackCommand string // copyable compaction command sequence
	Warnings     []string
}

// DockerEngine reports workspace-correlated Docker reclamation tiers
// for the given workspace roots. Read-only.
type DockerEngine interface {
	Report(ctx context.Context, workspaceRoots []string) (DockerReport, error)
}

// LockWriter is one process observed holding an open handle on a
// probed path (diagnostics evidence only — never authorization).
type LockWriter struct {
	Name string
	PID  uint32
}

// LockProbe lists processes holding handles on paths (the CLI injects
// the native platform.WriterInspector behind this; analyse stays
// platform-neutral). Best-effort by contract: errors are swallowed and
// never produce lock claims.
type LockProbe interface {
	InspectWriters(paths []string) ([]LockWriter, error)
}

// Category is the §11.3 classification vocabulary. The four actionable
// groups match the plan's mockup; the remaining values are honest
// non-actionable buckets so every scanned project has exactly one
// category.
type Category string

// Accepted categories.
const (
	// CategoryBloatedActive: active within ActiveWindow and an estimated
	// footprint above BloatedBytes (heavy regenerable output on a live
	// project).
	CategoryBloatedActive Category = "bloated-active"
	// CategoryStale: untouched between StaleAfter and AbandonedAfter.
	CategoryStale Category = "stale"
	// CategoryAbandoned: untouched beyond AbandonedAfter; parking is the
	// recommendation.
	CategoryAbandoned Category = "abandoned"
	// CategoryMergedWorktree: linked worktree merged upstream with a
	// clean tree; native `git worktree remove` is the recommendation.
	CategoryMergedWorktree Category = "merged-worktree"
	// CategoryActive: recent and not bloated (healthy; no recommendation).
	CategoryActive Category = "active"
	// CategoryQuiet: older than ActiveWindow but not yet StaleAfter (no
	// recommendation; honest gap between the thresholds).
	CategoryQuiet Category = "quiet"
	// CategoryOffline: the project's parent root was missing at scan
	// time; no facts were gathered.
	CategoryOffline Category = "offline"
	// CategoryUnknown: age evidence unavailable (no git activity date and
	// no usable mtime); never guessed into an actionable bucket.
	CategoryUnknown Category = "unknown"
)

// Shield labels displayed on project rows and enforced by batch gates
// (plan §11.5B/§11.5C).
const (
	ShieldUnpushed = "[UNPUSHED COMMITS]" // advise park/push; NEVER deletion
	ShieldConflict = "[CONFLICT]"         // in-flight merge/rebase; skipped in batches
	ShieldDirty    = "[DIRTY]"            // uncommitted changes; no worktree removal
	ShieldLocked   = "[LOCKED]"           // active file locks; skipped in batches
	// NoteOffline prefixes the per-project offline note.
	NoteOffline = "[OFFLINE]"
)

// OutputRoot is one known regenerable output folder found in (or under)
// a project, with its shallow logical size estimate.
type OutputRoot struct {
	// Name is the folder's conventional name ("node_modules", ...).
	Name string `json:"name"`
	// Path is project-relative with '/' separators ("apps/web/node_modules").
	Path string `json:"path"`
	// Bytes is the shallow logical estimate: the sum of the immediate
	// entries' logical sizes. Directories contribute their own stat size
	// (≈0 on NTFS/ext4), so deep trees are UNDER-counted — the estimate
	// is a lower bound, labeled as such everywhere it is shown.
	Bytes int64 `json:"bytes"`
}

// Recommendation is one project's copyable action.
type Recommendation struct {
	// Kind: "reclaim" | "park" | "worktree-remove" | "push-or-park" | ""
	// ("" = no recommendation).
	Kind string `json:"kind,omitempty"`
	// Command is the copyable argv (["ebb","reclaim","<path>"] or
	// ["git","worktree","remove","<path>"]).
	Command []string `json:"command,omitempty"`
	// Reason explains the recommendation in one sentence.
	Reason string `json:"reason,omitempty"`
}

// Project is one scanned workspace record.
type Project struct {
	// Root is the project's absolute path; Name its base element.
	Root string `json:"root"`
	Name string `json:"name"`
	// ParentRoot is the configured root the project was found under.
	ParentRoot string `json:"parent_root"`
	// Offline: the project was listed under a root that could not be
	// read (drive missing). No facts were gathered.
	Offline bool `json:"offline,omitempty"`
	// Ecosystems lists marker-derived labels ("Node", "Rust", ...).
	Ecosystems []string `json:"ecosystems,omitempty"`
	// IsMonorepo: a repository boundary (workspace manifest) makes the
	// tree one atomic project; sub-packages are aggregated, never split.
	IsMonorepo bool `json:"is_monorepo,omitempty"`
	// OutputRoots are the present known output folders with estimates.
	OutputRoots []OutputRoot `json:"output_roots,omitempty"`
	// FootprintBytes sums OutputRoots (shallow logical estimate).
	FootprintBytes int64 `json:"footprint_bytes"`
	// FootprintEstimate is the honesty label carried on every surface
	// that shows FootprintBytes (e.g. "shallow logical estimate").
	FootprintEstimate string `json:"footprint_estimate,omitempty"`
	// LastActivityAt is the best-evidence activity time (git HEAD time,
	// else newest top-level mtime; zero = unknown).
	LastActivityAt time.Time `json:"last_activity_at,omitempty"`
	// AgeDays is now-LastActivityAt in days (-1 unknown).
	AgeDays float64 `json:"age_days"`
	// Repo carries the git survey facts (zero value when not a repo or
	// the surveyor is unwired).
	Repo RepoSummary `json:"repo"`
	// Category is the classification (always set, even offline).
	Category Category `json:"category"`
	// Shields lists the active shield labels.
	Shields []string `json:"shields,omitempty"`
	// Notes carries per-project annotations ([OFFLINE] drive note, lock
	// holder, git survey degradation, ...).
	Notes []string `json:"notes,omitempty"`
	// Recommendation is the copyable action (zero when none).
	Recommendation Recommendation `json:"recommendation"`
	// Warnings carries probe-level warnings for this project.
	Warnings []string `json:"warnings,omitempty"`
}

// Shielded reports whether any batch-blocking shield is active.
func (p Project) Shielded() bool { return len(p.Shields) > 0 }

// Totals aggregates the report's byte estimates. Every field is an
// estimated footprint sum, never a measured volume delta.
type Totals struct {
	// FootprintBytes sums every project's estimated footprint.
	FootprintBytes int64 `json:"footprint_bytes"`
	// ReclaimableStale sums unshielded stale projects (the --reclaim-stale
	// population).
	ReclaimableStale int64 `json:"reclaimable_stale"`
	// ParkableAbandoned sums abandoned projects (park is advised for
	// shielded ones too — it is the safe route for unpushed work).
	ParkableAbandoned int64 `json:"parkable_abandoned"`
	// WorktreeBytes sums merged+clean+unshielded worktrees (the
	// --prune-worktrees population).
	WorktreeBytes int64 `json:"worktree_bytes"`
	// RecoverableTotal = ReclaimableStale + ParkableAbandoned +
	// WorktreeBytes (estimated).
	RecoverableTotal int64 `json:"recoverable_total"`
}

// Report is one analyse scan's full result (the --json details object).
type Report struct {
	// Roots are the scanned parent roots (configured or explicit).
	Roots []string `json:"roots"`
	// Scanned counts every project record (including offline ones).
	Scanned int `json:"scanned"`
	// OfflineRoots lists roots that could not be read (drive missing).
	OfflineRoots []string `json:"offline_roots,omitempty"`
	// Projects is the deterministic listing, ordered by (root, name).
	Projects []Project `json:"projects"`
	// Categories counts projects per category.
	Categories map[string]int `json:"categories"`
	// Totals carries the estimated byte aggregates.
	Totals Totals `json:"totals"`
	// Docker is the appended Docker report (present only with --docker
	// and a wired engine).
	Docker *DockerReport `json:"docker,omitempty"`
	// Warnings carries report-level warnings (degraded seams, unreadable
	// children, ...).
	Warnings []string `json:"warnings"`
}

// Engine is the analyse scanner. The zero value is NOT ready: at
// minimum Now or the default clock must resolve; use NewEngine.
type Engine struct {
	// Git surveys repository topology; nil degrades to non-git facts
	// with one report-level warning per scan.
	Git GitSurveyor
	// Docker reports Docker tiers; nil (or a report with
	// Available=false) degrades to an honest unavailability warning.
	Docker DockerEngine
	// Lock probes active file locks; nil falls back to the open probe
	// (sharing-violation evidence only). Best-effort either way.
	Lock LockProbe
	// Now is the classification clock (injectable for boundary tests);
	// nil uses time.Now.
	Now func() time.Time
	// Workers bounds scan parallelism (default 8; ≤1 serializes).
	Workers int

	// Threshold overrides (zero = the named defaults in classify.go).
	// Exists so tests exercise boundaries without fabricating bytes.
	ActiveWindowOverride   time.Duration
	StaleAfterOverride     time.Duration
	AbandonedAfterOverride time.Duration
	BloatedBytesOverride   int64
}

// NewEngine returns an engine with the given seams and defaults.
func NewEngine(git GitSurveyor, docker DockerEngine, lock LockProbe) *Engine {
	return &Engine{Git: git, Docker: docker, Lock: lock}
}

// DefaultWorkers is the bounded scan parallelism (plan §11.5F targets
// <2s across 200 projects; the pool keeps stat storms off the scheduler).
const DefaultWorkers = 8

// Scan classifies every immediate child directory of roots. It never
// returns an error for environmental facts (offline roots, unreadable
// children, degraded seams) — those become OfflineRoots/Warnings so one
// bad root never hides the rest of the report. ctx cancellation stops
// dispatching new projects; already-collected results are returned.
func (e *Engine) Scan(ctx context.Context, roots []string) Report {
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	rep := Report{
		Roots:        append([]string(nil), roots...),
		Categories:   map[string]int{},
		Projects:     []Project{},
		OfflineRoots: []string{},
		Warnings:     []string{},
	}

	// Collect candidates sequentially (cheap ReadDir per root), then
	// probe in parallel.
	type candidate struct{ parent, path, name string }
	var candidates []candidate
	for _, root := range roots {
		entries, err := readDirNames(root)
		if err != nil {
			if isNotExist(err) {
				rep.OfflineRoots = append(rep.OfflineRoots, root)
				rep.Projects = append(rep.Projects, offlineProject(root))
				continue
			}
			rep.Warnings = append(rep.Warnings, "root "+root+": "+err.Error())
			continue
		}
		for _, c := range entries {
			if c.isLink {
				// Opaque leaf (§11.5E): a link child may escape the root;
				// it is never followed and never becomes a project.
				rep.Warnings = append(rep.Warnings,
					"skipped link child "+joinPath(root, c.name)+" (opaque; links are never followed out of the scan root)")
				continue
			}
			candidates = append(candidates, candidate{parent: root, path: joinPath(root, c.name), name: c.name})
		}
	}

	workers := e.Workers
	if workers <= 0 {
		workers = DefaultWorkers
	}
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		sem      = make(chan struct{}, workers)
		surveyed bool
	)
	for _, cand := range candidates {
		if ctx.Err() != nil {
			rep.Warnings = append(rep.Warnings, "scan interrupted: "+ctx.Err().Error())
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c candidate) {
			defer wg.Done()
			defer func() { <-sem }()
			p := e.scanProject(ctx, c.parent, c.path, c.name, now, &surveyed, &mu)
			mu.Lock()
			rep.Projects = append(rep.Projects, p)
			mu.Unlock()
		}(cand)
	}
	wg.Wait()

	if ctx.Err() != nil {
		rep.Warnings = append(rep.Warnings, "scan cancelled: "+ctx.Err().Error())
	}

	// One honest degradation note when repositories were seen but no
	// surveyor is wired (per-project noise would drown the report).
	mu.Lock()
	sawRepo := surveyed
	mu.Unlock()
	if sawRepo && e.Git == nil {
		rep.Warnings = append(rep.Warnings,
			"git survey unavailable (engine not wired): repository facts (branch, staleness, worktree merge state) were not gathered; staleness fell back to directory mtimes")
	}

	sort.Slice(rep.Projects, func(i, j int) bool {
		if rep.Projects[i].ParentRoot != rep.Projects[j].ParentRoot {
			return rep.Projects[i].ParentRoot < rep.Projects[j].ParentRoot
		}
		return rep.Projects[i].Name < rep.Projects[j].Name
	})
	rep.Scanned = len(rep.Projects)
	for _, p := range rep.Projects {
		rep.Categories[string(p.Category)]++
		if p.Offline {
			continue
		}
		rep.Totals.FootprintBytes += p.FootprintBytes
		switch {
		case p.Category == CategoryStale && !p.Shielded():
			// Reclaim (trim) is a deletion-class action: only unshielded
			// stale projects count.
			rep.Totals.ReclaimableStale += p.FootprintBytes
		case p.Category == CategoryAbandoned:
			// Park is advised for shielded abandoned too (parking is the
			// safe route for unpushed work), so no shield filter here.
			rep.Totals.ParkableAbandoned += p.FootprintBytes
		case p.Category == CategoryMergedWorktree && !p.Shielded():
			rep.Totals.WorktreeBytes += p.FootprintBytes
		}
	}
	rep.Totals.RecoverableTotal = rep.Totals.ReclaimableStale + rep.Totals.ParkableAbandoned + rep.Totals.WorktreeBytes
	return rep
}

// scanProject probes one candidate directory and classifies it.
// surveyed/mu track whether any repository was seen (for the single
// report-level degradation warning).
func (e *Engine) scanProject(ctx context.Context, parent, path, name string, now time.Time, surveyed *bool, mu *sync.Mutex) Project {
	p := Project{
		ParentRoot: parent, Root: path, Name: name,
		FootprintEstimate: FootprintEstimateLabel,
	}
	facts, err := probeShallow(ctx, path, e.Lock)
	if err != nil {
		// Unreadable child (permissions, interim state): honest record,
		// no crash, no facts invented.
		p.Category = CategoryUnknown
		p.Notes = append(p.Notes, "unreadable: "+err.Error())
		return p
	}
	p.Ecosystems = facts.ecosystems
	p.IsMonorepo = facts.isMonorepo
	p.OutputRoots = facts.outputs
	p.FootprintBytes = facts.footprint
	p.LastActivityAt = facts.mtimeEvidence

	if facts.hasGit && e.Git != nil {
		mu.Lock()
		*surveyed = true
		mu.Unlock()
		sum, serr := e.Git.SurveyRepo(ctx, path)
		if serr != nil {
			p.Warnings = append(p.Warnings, "git survey failed: "+serr.Error())
		} else {
			// Envelope contract: slices are never null.
			if sum.Warnings == nil {
				sum.Warnings = []string{}
			}
			if sum.StaleMergedBranches == nil {
				sum.StaleMergedBranches = []string{}
			}
			p.Repo = sum
			p.Warnings = append(p.Warnings, sum.Warnings...)
			if !sum.LastActivityAt.IsZero() {
				p.LastActivityAt = sum.LastActivityAt
			}
		}
	} else if facts.hasGit {
		mu.Lock()
		*surveyed = true
		mu.Unlock()
	}

	if !p.LastActivityAt.IsZero() {
		p.AgeDays = now.Sub(p.LastActivityAt).Hours() / 24
	}
	if facts.locked {
		p.Shields = append(p.Shields, ShieldLocked)
		p.Notes = append(p.Notes, facts.lockNote)
	}
	classify(&p, now, e.thresholds())
	return p
}

// offlineProject is the placeholder record for a child of an offline
// root (the root itself carries the [OFFLINE] grouping).
func offlineProject(root string) Project {
	return Project{
		Root: root, Name: baseName(root), ParentRoot: root,
		Offline: true, Category: CategoryOffline,
		Notes: []string{NoteOffline + " scan root is not readable (drive missing or unmounted); no facts were gathered"},
	}
}

// thresholds resolves the effective classification thresholds.
func (e *Engine) thresholds() classifyThresholds {
	t := defaultThresholds
	if e.ActiveWindowOverride > 0 {
		t.activeWindow = e.ActiveWindowOverride
	}
	if e.StaleAfterOverride > 0 {
		t.staleAfter = e.StaleAfterOverride
	}
	if e.AbandonedAfterOverride > 0 {
		t.abandonedAfter = e.AbandonedAfterOverride
	}
	if e.BloatedBytesOverride > 0 {
		t.bloatedBytes = e.BloatedBytesOverride
	}
	return t
}
