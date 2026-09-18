package domain

import (
	"errors"
	"fmt"
	"sort"
)

// RootIdentity ties a root path to native filesystem identity so a
// replaced directory at the same pathname is never mistaken for the
// original (Foundation §12.1, I13). On Windows this is volume serial +
// file index; on Linux device+inode. The concrete encoding belongs to
// the platform package; here it is opaque but comparable.
type RootIdentity struct {
	VolumeID string `json:"volume_id"`
	FileID   string `json:"file_id"`
}

func (r RootIdentity) String() string { return r.VolumeID + "/" + r.FileID }

// Root is one declared capture root.
type Root struct {
	ID       RootID       `json:"id"`
	Path     string       `json:"path"` // absolute, native separators
	Identity RootIdentity `json:"identity"`
	Ownership Ownership   `json:"ownership"`
}

// VolumeUsage is per-volume space accounting input (Foundation §14.1).
type VolumeUsage struct {
	// FreeToCaller is quota-aware available bytes (GetDiskFreeSpaceEx
	// lpFreeBytesAvailableToCaller; statvfs f_bavail*f_frsize).
	FreeToCaller int64 `json:"free_to_caller"`
	// VolumeFree is total volume free bytes.
	VolumeFree int64 `json:"volume_free"`
	// Total is total capacity.
	Total int64 `json:"total"`
	// VolumeID labels the volume for per-volume reporting.
	VolumeID string `json:"volume_id"`
}

// ScanIssue is a non-fatal observation during discovery that a plan or
// report must surface (cloud placeholder, shared hardlink outside root,
// nonrepresentable name, ...).
type ScanIssue struct {
	Path string `json:"path"`
	Code string `json:"code"` // stable, EBB_SCAN_*
	Note string `json:"note"`
}

// InventorySummary accounts for every in-scope entry: each has exactly
// one outcome — captured, omitted-with-route, or blocking (§8.4).
type InventorySummary struct {
	TotalEntries   int64             `json:"total_entries"`
	Preserved      int64             `json:"preserved"`
	OmittedByRoute map[Route]int64   `json:"omitted_by_route"`
	Blocking       []string          `json:"blocking,omitempty"` // entry paths that block destructive ops
	PreservedBytes int64             `json:"preserved_bytes"`    // logical sum of preserved files
	ExclReclaimable map[string]int64 `json:"excl_reclaimable,omitempty"` // root-path prefix -> bytes exclusively reclaimable
	Issues         []ScanIssue       `json:"issues,omitempty"`
}

// Complete reports whether accounting closes with no unaccounted entry.
func (s InventorySummary) Complete() bool {
	return s.TotalEntries == s.Preserved+sum(s.OmittedByRoute)+int64(len(s.Blocking))
}

func sum(m map[Route]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

// ErrScanIncomplete reports a walk that could not finish; it is fatal
// to any destructive plan (I12).
var ErrScanIncomplete = errors.New("inventory: scan did not complete")

// SortEntries orders entries by (root, path) — the canonical inventory
// stream order (Foundation §16.3).
func SortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Root != es[j].Root {
			return es[i].Root < es[j].Root
		}
		return es[i].Path < es[j].Path
	})
}

// CheckSortedAndUnique validates the canonical stream invariants.
func CheckSortedAndUnique(es []Entry) error {
	for i := 1; i < len(es); i++ {
		a, b := es[i-1], es[i]
		if a.Root == b.Root && a.Path >= b.Path {
			return fmt.Errorf("inventory: %s/%s duplicated or out of order", a.Root, a.Path)
		}
	}
	return nil
}
