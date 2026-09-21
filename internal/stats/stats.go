// Package stats implements the compute/render core of `ebb stats` (Wave
// 3, product plan task 3A): the Developer Space Economy dashboard.
//
// The package is deliberately pure — Metrics is computed from plain
// slices (catalog events, workspace summaries, shallow-scan facts), the
// comparison engine is deterministic over an embedded offline catalog,
// and the renderer produces a plain UTF-8 box no terminal needs ANSI
// support for. Nothing here touches the filesystem, the catalog or the
// network; the CLI owns all IO.
package stats

// Score is the hoarding-score rubric verdict.
type Score struct {
	// Grade is one of A+ A B C D F, or "" when the rubric could not be
	// applied (no shallow-scan facts).
	Grade string `json:"grade"`
	// Label is the human word for the grade ("Minimalist", ...), or the
	// unknown-scan guidance sentence when Grade is "".
	Label string `json:"label"`
}

// CommandCount is one verb's invocation count.
type CommandCount struct {
	Command string `json:"command"`
	Count   int64  `json:"count"`
}

// Metrics is the dashboard's full model (the `ebb stats --json` metrics
// object). Field names and json tags are the frozen Wave 3 contract.
type Metrics struct {
	// LifetimeReclaimedBytes = Σ stats-event bytes_out (trim, reclaim,
	// park, delete, gc, freeze), as each command's own accounting
	// reported them.
	LifetimeReclaimedBytes int64 `json:"lifetime_reclaimed_bytes"`
	// LifetimeRestoredBytes = Σ stats-event bytes_in (open, restore,
	// freeze --restore).
	LifetimeRestoredBytes int64 `json:"lifetime_restored_bytes"`
	// CurrentlyParkedBytes = Σ Size over parked workspace summaries (each
	// is the workspace's latest recorded park bytes_out).
	CurrentlyParkedBytes int64 `json:"currently_parked_bytes"`
	// ActiveWorkspaces / ParkedWorkspaces count workspace summaries by
	// status (live / parked; UNBOUND counts toward neither).
	ActiveWorkspaces int `json:"active_workspaces"`
	ParkedWorkspaces int `json:"parked_workspaces"`
	// SpaceEfficiencyRatio = LifetimeReclaimedBytes /
	// max(1, LifetimeRestoredBytes), rendered with one decimal ("3.7x").
	SpaceEfficiencyRatio float64 `json:"space_efficiency_ratio"`
	// CleanDeskStreakDays = consecutive UTC days, ending today or
	// yesterday (a streak survives until tomorrow), with ≥1 stats event —
	// forced to 0 when the shallow scan found stale artifacts. See
	// ComputeAt for the full rules.
	CleanDeskStreakDays int `json:"clean_desk_streak_days"`
	// HoardingScore is the stale-clutter rubric verdict.
	HoardingScore Score `json:"hoarding_score"`
	// ZombieBytesExorcised = Σ bytes_out over events whose detail marks
	// {"stale":true} (analyse batch reclaims of stale projects). Field
	// name is the frozen json spelling; the value is bytes.
	ZombieBytesExorcised int64 `json:"zombie_gb_exorcised"`
	// EstimatedSSDWearSaved = LifetimeRestoredBytes: an honest simple
	// proxy for flash-write cycles avoided (bytes that returned from the
	// vault without a full re-download or rebuild rewrite). It is a lower
	// bound of the true effect, never a claim of measured wear.
	EstimatedSSDWearSaved int64 `json:"estimated_ssd_wear_saved"`
	// TopCommands = the five most-invoked verbs (ties alphabetical).
	TopCommands []CommandCount `json:"top_commands"`
	// TotalInvocations = every recorded stats event (the "total ebb
	// keystrokes" row).
	TotalInvocations int64 `json:"total_invocations"`
	// TrackingSince = the oldest event's timestamp ("" before the first
	// event).
	TrackingSince string `json:"tracking_since"`
	// ScanAvailable reports whether the shallow clutter scan produced
	// facts (additive Wave 3 field): false means the streak counted
	// usage days only and the renderer marks it as unscanned clutter.
	ScanAvailable bool `json:"scan_available"`
}

// ScanFacts carries the optional shallow-scan-derived clutter facts the
// stats command gathers from the configured projects_dir roots (the
// analyse engine's read-only shallow probe; never a new walker).
type ScanFacts struct {
	// Available is false when no projects_dir is configured or the scan
	// was declined. Every other field is meaningless then.
	Available bool
	// StaleReclaimableBytes is the estimated reclaimable output footprint
	// in artifacts untouched for more than 30 days (shallow logical
	// estimate, labeled as such wherever shown).
	StaleReclaimableBytes int64
	// StaleArtifactCount is the number of stale (≥30d untouched)
	// projects found.
	StaleArtifactCount int
	// WorstStaleAgeDays is the age in days of the oldest stale project
	// (0 when none).
	WorstStaleAgeDays int
}
