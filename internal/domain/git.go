package domain

// GitObservation records repository topology and diagnostic state
// (Foundation §9.1-9.2). Observations ride alongside preserved bytes;
// they never substitute for them and never authorize anything.
type GitObservation struct {
	// IsRepo: a Git admin directory/file was found at or above the root.
	IsRepo bool `json:"is_repo"`

	// GitDir is the resolved absolute .git path (may be a file for
	// worktrees/submodules). CommonDir is the resolved common dir.
	GitDir    string `json:"git_dir,omitempty"`
	CommonDir string `json:"common_dir,omitempty"`

	// AdminInsideRoot: the repository's administration is contained
	// within the owned root (ordinary self-contained repo).
	AdminInsideRoot bool `json:"admin_inside_root"`

	// HEAD state
	HeadCommit string `json:"head_commit,omitempty"` // "" on unborn
	HeadBranch string `json:"head_branch,omitempty"` // "" on detached
	Detached   bool   `json:"detached"`
	Unborn     bool   `json:"unborn"`

	// Working state summaries (counts, not content)
	StagedEntries    int64 `json:"staged_entries"`   // index entries
	DirtyWorktree    bool  `json:"dirty_worktree"`   // porcelain v2 saw changes
	UnmergedEntries  int64 `json:"unmerged_entries"` // conflict stages
	StashCount       int64 `json:"stash_count"`
	UntrackedEntries int64 `json:"untracked_entries"`

	// In-progress operations detected via admin files
	MergeInProgress      bool `json:"merge_in_progress"`
	RebaseInProgress     bool `json:"rebase_in_progress"`
	CherryPickInProgress bool `json:"cherry_pick_in_progress"`
	RevertInProgress     bool `json:"revert_in_progress"`

	// Topology
	Remotes []GitRemote `json:"remotes,omitempty"`
	// Worktrees lists ALL entries of `worktree list --porcelain`,
	// including the main (or bare) worktree. DestructiveParkBlockers
	// treats >1 entry as shared Git administration (§9.2), so the main
	// entry must be included for a single linked worktree to fire the
	// blocker.
	Worktrees      []GitWorktree `json:"worktrees,omitempty"`
	HasShallow     bool          `json:"has_shallow"`
	HasAlternates  bool          `json:"has_alternates"`       // objects/info/alternates present
	IsPartialClone bool          `json:"is_partial_clone"`     // promisor remote configured
	HasLFS         bool          `json:"has_lfs"`              // filter.lfs config or .git/lfs present
	Submodules     []string      `json:"submodules,omitempty"` // names from .gitmodules (parsed as INI, never initialized)

	// ObjectFormat from config (sha1/object-format).
	ObjectFormat string `json:"object_format,omitempty"`

	// GitVersion records the exact git that produced these observations
	// (hardening recipe is version-specific; see D004).
	GitVersion string `json:"git_version,omitempty"`

	// Warnings are non-fatal anomalies (corrupt-looking state preserved
	// as bytes, reflog oddities, ...).
	Warnings []string `json:"warnings,omitempty"`
}

// GitRemote is one configured remote (name + URLs; never credentials).
type GitRemote struct {
	Name string `json:"name"`
	URL  string `json:"url"` // may be redacted upstream by config parsing
	Push string `json:"push,omitempty"`
}

// GitWorktree is one linked worktree from `worktree list --porcelain`.
type GitWorktree struct {
	Path     string `json:"path"`
	Head     string `json:"head,omitempty"`
	Branch   string `json:"branch,omitempty"`
	Bare     bool   `json:"bare"`
	Detached bool   `json:"detached"`
}

// DestructiveParkBlockers derives the v1 policy blockers from topology
// (Foundation §9.2 support matrix). It returns stable blocker codes.
func (g GitObservation) DestructiveParkBlockers() []string {
	var b []string
	if g.IsRepo && !g.AdminInsideRoot {
		b = append(b, "EBB_E_GIT_ADMIN_OUTSIDE_ROOT")
	}
	if len(g.Worktrees) > 1 {
		// shared administration serving multiple worktrees
		b = append(b, "EBB_E_SHARED_GIT")
	}
	if g.HasAlternates {
		b = append(b, "EBB_E_GIT_ALTERNATES")
	}
	return b
}
