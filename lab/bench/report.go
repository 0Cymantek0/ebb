// Reporting: raw results.json plus a human report.md per run. The
// curated cross-run baseline lives in docs/BENCHMARKS.md.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// metaInfo records the environment of one run (Foundation §14.4: record
// hardware, OS/filesystem, backend version, device class with every run).
type metaInfo struct {
	TimestampUTC    string   `json:"timestamp_utc"`
	EbbVersion      string   `json:"ebb_version"`
	ResticVersion   string   `json:"restic_version"`
	ResticBinary    string   `json:"restic_binary"`
	RepoID          string   `json:"repo_id"`
	GoVersion       string   `json:"go_version"`
	GOOS            string   `json:"goos"`
	GOARCH          string   `json:"goarch"`
	CPUModel        string   `json:"cpu_model"`
	NumCPU          int      `json:"num_cpu"`
	DeviceClass     string   `json:"device_class"`
	Scale           float64  `json:"scale"`
	WorkDir         string   `json:"work_dir"`
	OutDir          string   `json:"out_dir"`
	TotalRuntimeSec float64  `json:"total_runtime_sec"`
	PeakRSSBytes    uint64   `json:"peak_rss_bytes"`
	Notes           []string `json:"notes"`
}

// noiseFloor is the pre-run volume free-space drift measurement
// (Learnings: sample drift before measuring; size tolerances from it).
type noiseFloor struct {
	VolumeID string `json:"volume_id"`
	Samples  int    `json:"samples"`
	Min      int64  `json:"min_free_bytes"`
	Max      int64  `json:"max_free_bytes"`
	Drift    int64  `json:"drift_bytes"`
	Error    string `json:"error,omitempty"`
}

// fixtureResult carries every measured number for one fixture. Cells that
// do not apply stay zero/empty; the report renders N/A where the op does
// not apply (none today: every fixture gets the full op sequence).
type fixtureResult struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	DeviceClass string  `json:"device_class"`
	Scale       float64 `json:"scale"`

	// Fixture shape (from the hashed scan).
	EntriesTotal   int64   `json:"entries_total"`
	Files          int64   `json:"files"`
	Dirs           int64   `json:"dirs"`
	Links          int64   `json:"links"`
	HardlinkGroups int     `json:"hardlink_groups"`
	LogicalBytes   int64   `json:"logical_bytes"`
	AllocatedBytes *int64  `json:"allocated_bytes,omitempty"` // nil = not observable
	GenSec         float64 `json:"gen_sec"`

	// Timings (wall clock).
	ScanMetaSec float64 `json:"scan_meta_sec"`
	ScanHashSec float64 `json:"scan_hash_sec"`
	SnapshotSec float64 `json:"snapshot_sec"`
	ReadbackSec float64 `json:"readback_sec"`
	ParkSec     float64 `json:"park_sec"`
	OpenSec     float64 `json:"open_sec"`
	// TarReadbackSec is the same full readback through the D019 streaming
	// tar transport (lifecycle.VerifyReadback), measured separately from
	// the raw per-file DumpFile walk in ReadbackSec.
	TarReadbackSec float64 `json:"tar_readback_sec"`

	// Restic subprocess attribution per op (calls counted by the wrapper;
	// dur is cumulative subprocess time inside the op's wall time).
	SnapshotResticCalls    int     `json:"snapshot_restic_calls"`
	SnapshotResticSec      float64 `json:"snapshot_restic_sec"`
	ReadbackResticCalls    int     `json:"readback_restic_calls"`
	ReadbackResticSec      float64 `json:"readback_restic_sec"`
	TarReadbackFiles       int     `json:"tar_readback_files"`
	TarReadbackResticCalls int     `json:"tar_readback_restic_calls"`
	TarReadbackResticSec   float64 `json:"tar_readback_restic_sec"`
	ParkResticCalls        int     `json:"park_restic_calls"`
	ParkResticSec          float64 `json:"park_restic_sec"`
	OpenResticCalls        int     `json:"open_restic_calls"`
	OpenResticSec          float64 `json:"open_restic_sec"`

	// Op outcomes.
	SnapshotPreserved int64   `json:"snapshot_preserved"`
	SnapshotOmitted   int64   `json:"snapshot_omitted"`
	ReadbackFiles     int     `json:"readback_files"`
	ReadbackBytes     int64   `json:"readback_bytes"`
	ReadbackPerFileMs float64 `json:"readback_per_file_ms"`
	ParkFreeDelta     int64   `json:"park_free_delta_bytes"` // harness measurement
	ParkAPIDelta      int64   `json:"park_api_delta_bytes"`  // ParkResult.VolumeDeltaObserved
	ParkEstimated     int64   `json:"park_estimated_bytes"`  // logical estimate
	OpenEntries       int64   `json:"open_entries"`
	OpenBytes         int64   `json:"open_bytes"`

	// Vault repository size (logical bytes of packed files) after each op.
	RepoAfterInit     int64 `json:"repo_after_init"`
	RepoAfterSnapshot int64 `json:"repo_after_snapshot"`
	RepoAfterPark     int64 `json:"repo_after_park"`
	RepoAfterOpen     int64 `json:"repo_after_open"`

	Warnings []string `json:"warnings,omitempty"`
}

// report is the whole run.
type report struct {
	Meta    metaInfo        `json:"meta"`
	Noise   noiseFloor      `json:"volume_noise_floor"`
	Results []fixtureResult `json:"fixtures"`
}

// baselineNotes explains the interpretation boundaries that must travel
// with every raw run.
func baselineNotes(scale float64) []string {
	return []string{
		"Timings are wall-clock singles (not medians); fixtures are deterministic per (name, scale) but OS caching varies between runs.",
		"Readback numbers reflect the PER-FILE DumpFile transport measured on this baseline date; a streaming-tar transport is being built in parallel and will be re-measured.",
		"Peak RSS covers the harness process only (runtime.MemStats); restic subprocess memory is not included.",
		"Allocated bytes are per-name (FileCompressionInfo/cluster-rounded on Windows); hardlink aliases inside the shared fixture double-count shared allocation.",
		fmt.Sprintf("Default scale %.2f is time-bounded, not the Foundation §14.4 reference corpus size; see docs/BENCHMARKS.md for the --scale mapping to the reference counts.", scale),
	}
}

// writeResults emits results.json and report.md under outDir.
func writeResults(outDir string, rep *report) error {
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(outDir, "results.json"), append(raw, '\n'), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, "report.md"), []byte(renderMarkdown(rep)), 0o644)
}

// renderMarkdown builds the human report.
func renderMarkdown(rep *report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Ebb benchmark run %s\n\n", rep.Meta.TimestampUTC)
	fmt.Fprintf(&b, "- ebb %s; %s\n", rep.Meta.EbbVersion, rep.Meta.ResticVersion)
	fmt.Fprintf(&b, "- %s/%s, %s, %d CPUs, device class: %s\n",
		rep.Meta.GOOS, rep.Meta.GOARCH, rep.Meta.CPUModel, rep.Meta.NumCPU, rep.Meta.DeviceClass)
	fmt.Fprintf(&b, "- scale %.2f; total runtime %.1f s; peak harness RSS %s\n\n",
		rep.Meta.Scale, rep.Meta.TotalRuntimeSec, humanBytes(int64(rep.Meta.PeakRSSBytes)))

	if rep.Noise.Error != "" {
		fmt.Fprintf(&b, "Volume noise floor: unavailable (%s)\n\n", rep.Noise.Error)
	} else {
		fmt.Fprintf(&b, "Volume %s free-space drift before measuring: %s over %d samples — park free-deltas smaller than this are noise.\n\n",
			rep.Noise.VolumeID, humanBytes(rep.Noise.Drift), rep.Noise.Samples)
	}

	b.WriteString("## Timings (wall clock, seconds)\n\n")
	b.WriteString("| fixture | entries | files | scan meta | scan hash | snapshot | readback | park | open |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rep.Results {
		fmt.Fprintf(&b, "| %s | %d | %d | %.2f | %.2f | %.1f | %.1f | %.1f | %.1f |\n",
			r.Name, r.EntriesTotal, r.Files, r.ScanMetaSec, r.ScanHashSec, r.SnapshotSec, r.ReadbackSec, r.ParkSec, r.OpenSec)
	}

	b.WriteString("\n## Restic subprocess attribution\n\n")
	b.WriteString("| fixture | snapshot calls/time | readback calls/time | park calls/time | open calls/time |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, r := range rep.Results {
		fmt.Fprintf(&b, "| %s | %d / %.1fs | %d / %.1fs | %d / %.1fs | %d / %.1fs |\n",
			r.Name, r.SnapshotResticCalls, r.SnapshotResticSec, r.ReadbackResticCalls, r.ReadbackResticSec,
			r.ParkResticCalls, r.ParkResticSec, r.OpenResticCalls, r.OpenResticSec)
	}

	b.WriteString("\n## Bytes\n\n")
	b.WriteString("| fixture | logical | allocated | repo after snapshot | repo after park | repo after open | park free delta | park est. |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range rep.Results {
		alloc := "N/A"
		if r.AllocatedBytes != nil {
			alloc = humanBytes(*r.AllocatedBytes)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			r.Name, humanBytes(r.LogicalBytes), alloc,
			humanBytes(r.RepoAfterSnapshot), humanBytes(r.RepoAfterPark), humanBytes(r.RepoAfterOpen),
			humanBytes(r.ParkFreeDelta), humanBytes(r.ParkEstimated))
	}

	b.WriteString("\n## Per-entry readback overhead (readback seconds / readback files)\n\n")
	b.WriteString("| fixture | readback files | readback s | ms/file |\n")
	b.WriteString("|---|---:|---:|---:|\n")
	for _, r := range rep.Results {
		fmt.Fprintf(&b, "| %s | %d | %.1f | %.0f |\n", r.Name, r.ReadbackFiles, r.ReadbackSec, r.ReadbackPerFileMs)
	}

	b.WriteString("\n## Readback transport comparison (same file set, same digests)\n\n")
	b.WriteString("| fixture | files | per-file DumpFile s | tar transport s | speedup |\n")
	b.WriteString("|---|---:|---:|---:|---:|\n")
	for _, r := range rep.Results {
		speedup := 0.0
		if r.TarReadbackSec > 0 {
			speedup = r.ReadbackSec / r.TarReadbackSec
		}
		fmt.Fprintf(&b, "| %s | %d | %.1f | %.1f | %.1fx |\n", r.Name, r.TarReadbackFiles, r.ReadbackSec, r.TarReadbackSec, speedup)
	}

	var warnings []string
	for _, r := range rep.Results {
		for _, w := range r.Warnings {
			warnings = append(warnings, fmt.Sprintf("%s: %s", r.Name, w))
		}
	}
	if len(warnings) > 0 {
		b.WriteString("\n## Warnings\n\n")
		for _, w := range warnings {
			fmt.Fprintf(&b, "- %s\n", w)
		}
	}
	return b.String()
}

// humanBytes renders sizes in IEC units.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
