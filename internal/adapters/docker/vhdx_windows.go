//go:build windows

// Windows host VHDX slack (tier 5, plan §11.7 D): Docker Desktop keeps
// its guest ext4 filesystem inside a dynamic VHDX under
// %LOCALAPPDATA%\Docker. Deleting content inside Docker frees guest
// blocks but NTFS physical allocation stays at the historical
// high-water mark until compaction. Physical allocation is measured
// through the injected AllocationProbe, which reuses internal/
// platform's GetCompressedFileSizeW-backed capability (Foundation
// §1.2/§14.1: report real allocation, not logical sizes) — no Win32
// code is duplicated here.
package dockeradapter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/platform"
)

// vhdxSlackThreshold: the plan advises compaction only above 5 GiB of
// slack between physical allocation and docker's logical usage.
const vhdxSlackThreshold = 5 << 30

// Search bounds (no unbounded walks; WalkDir's Lstat semantics never
// traverse directory symlinks).
const (
	vhdxMaxDepth   = 5
	vhdxMaxEntries = 20000
	vhdxMaxFiles   = 4
)

var vhdxNames = map[string]bool{"ext4.vhdx": true, "docker_data.vhdx": true}

// platformAllocationProbe adapts internal/platform's probe (the
// Windows AllocatedSize capability behind domain.FileFacts) to the
// engine's seam.
type platformAllocationProbe struct{ probe domain.PlatformProbe }

// defaultAllocationProbe wires the native capability into New.
func defaultAllocationProbe() AllocationProbe {
	return platformAllocationProbe{probe: platform.New()}
}

// AllocatedSize implements AllocationProbe. ok=false means the physical
// allocation was not observable — never interpreted as zero.
func (p platformAllocationProbe) AllocatedSize(path string) (int64, bool) {
	facts, err := p.probe.ProbeFile(path)
	if err != nil || facts.AllocatedSize == nil {
		return 0, false
	}
	return *facts.AllocatedSize, true
}

// hostSlackTier measures tier 5. It returns the tier (nil when nothing
// actionable), the measured slack in bytes (0 when unmeasurable), the
// copyable compaction command, and degradation warnings.
func (e *Engine) hostSlackTier(logicalTotal int64, logicalKnown bool) (*DockerTier, int64, string, []string) {
	var warnings []string
	if e.alloc == nil {
		return nil, 0, "", []string{
			"docker: host VHDX slack not measured (allocation probe unavailable on this build); tier 5 skipped honestly",
		}
	}
	files := findVHDXFiles()
	if len(files) == 0 {
		return nil, 0, "", []string{
			"docker: no Docker Desktop virtual disk found under %LOCALAPPDATA%\\Docker; host slack not measured",
		}
	}
	var physical int64
	var probed int
	for _, f := range files {
		if size, ok := e.alloc.AllocatedSize(f); ok {
			physical += size
			probed++
		} else {
			warnings = append(warnings, fmt.Sprintf("docker: physical allocation of %s not observable; excluded from slack", f))
		}
	}
	if probed == 0 {
		return nil, 0, "", warnings
	}
	if !logicalKnown {
		warnings = append(warnings,
			"docker: logical usage unknown (system df unavailable); host slack not derivable")
		return nil, 0, "", warnings
	}
	slack := physical - logicalTotal
	if slack < 0 {
		// Guest logical usage above physical allocation (compression /
		// sparse effects): there is nothing to reclaim on the host.
		slack = 0
	}
	if slack <= vhdxSlackThreshold {
		return nil, slack, "", warnings
	}
	t := &DockerTier{
		Tier:        TierHostVHDXSlack,
		Title:       "Windows Host VHDX Slack",
		CopyCommand: cmdHostSlack,
		Items: []DockerItem{{
			ID: filepath.Base(files[0]),
			Detail: fmt.Sprintf(
				"Docker Desktop virtual disk %s — physical %s vs docker logical %s (%s reclaimable by WSL compaction)",
				displayPath(files[0]), formatBytes(physical), formatBytes(logicalTotal), formatBytes(slack)),
		}},
	}
	return t, slack, cmdHostSlack, warnings
}

// findVHDXFiles locates Docker Desktop's VHDX with a bounded search:
// the known subpaths first, then a depth- and entry-capped walk that
// never follows links.
func findVHDXFiles() []string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return nil
	}
	root := filepath.Join(base, "Docker")
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil
	}
	found := map[string]bool{}
	for _, rel := range []string{
		filepath.Join("wsl", "data", "ext4.vhdx"),
		filepath.Join("wsl", "disk", "docker_data.vhdx"),
		filepath.Join("wsl", "main", "ext4.vhdx"),
	} {
		cand := filepath.Join(root, rel)
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			found[cand] = true
		}
	}
	if len(found) < vhdxMaxFiles {
		visited := 0
		rootDepth := strings.Count(root, string(filepath.Separator))
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || len(found) >= vhdxMaxFiles {
				return filepath.SkipAll
			}
			if visited++; visited > vhdxMaxEntries {
				return filepath.SkipAll
			}
			if !d.IsDir() {
				if vhdxNames[strings.ToLower(d.Name())] {
					if abs, aerr := filepath.Abs(path); aerr == nil {
						found[abs] = true
					} else {
						found[path] = true
					}
				}
				return nil
			}
			depth := strings.Count(path, string(filepath.Separator)) - rootDepth
			if depth >= vhdxMaxDepth {
				return filepath.SkipDir
			}
			return nil
		})
	}
	if len(found) == 0 {
		return nil
	}
	out := make([]string, 0, len(found))
	for p := range found {
		out = append(out, p)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
