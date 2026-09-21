// shallow.go is the read-only probing layer of `ebb analyse` (plan
// §11.2, §11.5E, §11.5F): ecosystem markers by existence, repository
// boundary detection, heavy-folder footprint estimation and staleness
// evidence — all shallow (ReadDir + Lstat), never a recursive walk, and
// never following a symlink or junction out of the scanned tree.

package analyse

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// FootprintEstimateLabel is the honesty label carried on every surface
// that shows a footprint number (Foundation §14.1: shallow estimates
// must never read as measured volume deltas).
const FootprintEstimateLabel = "shallow logical estimate (top-level entries of known output roots; not a full walk)"

// markerEcosystems maps root markers to display labels (plan §11.2).
// Order matters only for label determinism; every present marker
// contributes a label.
var markerEcosystems = []struct {
	marker string
	label  string
}{
	{"pnpm-workspace.yaml", "Node/pnpm-workspace"},
	{"package.json", "Node"},
	{"Cargo.toml", "Rust"},
	{"pyproject.toml", "Python"},
	{"go.mod", "Go"},
	{"build.gradle.kts", "Gradle"},
	{"pom.xml", "Maven"},
}

// markerNames is the marker existence set (spec: existence only at
// depth ≤2; content is read ONLY for the Cargo workspace boundary).
var markerNames = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range markerEcosystems {
		m[e.marker] = true
	}
	return m
}()

// heavyFolders are the known regenerable output roots probed by
// existence + shallow size (plan §11.2).
var heavyFolders = []string{
	"node_modules", "target", ".venv", ".gradle", "build", "dist", ".next", "vendor",
}

// maxMarkerDescend bounds how many subdirectories per level the marker
// search visits (cost control for pathological trees; plan §11.5F).
const maxMarkerDescend = 16

// maxMonorepoScanDirs bounds how many depth-1/depth-2 subdirectories
// the monorepo output-root aggregation visits (cost control; the
// <2s/200-project contract survives pathological monorepos).
const maxMonorepoScanDirs = 64

// isOpaqueLink reports whether a mode is link-shaped: a symlink OR any
// other reparse point (Go reports NTFS junctions as ModeIrregular in
// DirEntry.Type()/Lstat — verified on Go 1.27/Windows; only true
// symlinks carry ModeSymlink). Opaque leaves are never followed out of
// the scanned tree (§11.5E).
func isOpaqueLink(mode fs.FileMode) bool {
	return mode&(fs.ModeSymlink|fs.ModeIrregular) != 0
}

// cargoWorkspaceScanLimit bounds the Cargo.toml prefix read when
// proving a workspace boundary ([workspace] lives at the top of
// realistic manifests).
const cargoWorkspaceScanLimit = 64 << 10

// shallowFacts is everything the shallow probe learned about one
// project directory.
type shallowFacts struct {
	ecosystems    []string
	isMonorepo    bool
	hasGit        bool
	outputs       []OutputRoot
	footprint     int64
	mtimeEvidence time.Time // newest top-level entry mtime; zero = none
	locked        bool
	lockNote      string
}

// probeShallow gathers one project's facts. It returns an error only
// when the root itself is unreadable; everything observable inside is a
// fact or a default, never a failure.
func probeShallow(ctx context.Context, root string, lock LockProbe) (shallowFacts, error) {
	var f shallowFacts

	entries, err := os.ReadDir(root)
	if err != nil {
		return f, err
	}

	// ---- pass 1: root-level facts ----------------------------------
	var markerDirs []fs.DirEntry // depth-1 dirs for the deeper marker search
	for _, ent := range entries {
		name := ent.Name()
		if name == ".git" {
			f.hasGit = true
			continue
		}
		if markerNames[name] && ent.Type().IsRegular() {
			for _, m := range markerEcosystems {
				if m.marker == name {
					f.ecosystems = append(f.ecosystems, m.label)
					break
				}
			}
		}
		if ent.IsDir() {
			markerDirs = append(markerDirs, ent)
		}
		// Staleness evidence: newest mtime among top-level entries.
		if info, ierr := ent.Info(); ierr == nil && !info.ModTime().IsZero() {
			if f.mtimeEvidence.IsZero() || info.ModTime().After(f.mtimeEvidence) {
				f.mtimeEvidence = info.ModTime()
			}
		}
	}

	// Repository boundary (plan §11.5A): a workspace manifest makes the
	// tree ONE atomic project — sub-packages are aggregated, never
	// split. pnpm-workspace.yaml is proven by existence; a Cargo
	// workspace by the [workspace] table in the root manifest.
	if hasFile(entries, "pnpm-workspace.yaml") {
		f.isMonorepo = true
	} else if hasFile(entries, "Cargo.toml") {
		if cargoHasWorkspace(filepath.Join(root, "Cargo.toml")) {
			f.isMonorepo = true
		}
	}

	// ---- markers at depth ≤2 (only when the root had none) ----------
	if len(f.ecosystems) == 0 && !f.hasGit {
		searchMarkersDepth(root, entries, &f.ecosystems)
	}

	// ---- heavy-folder footprint -------------------------------------
	f.outputs, f.footprint = probeOutputRoots(root, entries, f.isMonorepo)

	// ---- lock probe (best-effort, never a false claim) ---------------
	f.locked, f.lockNote = probeLock(root, f.outputs, lock)
	return f, nil
}

// hasFile reports whether the listing holds a regular file by name.
func hasFile(entries []fs.DirEntry, name string) bool {
	for _, ent := range entries {
		if ent.Name() == name && ent.Type().IsRegular() {
			return true
		}
	}
	return false
}

// searchMarkersDepth looks for ecosystem markers in depth-1 and depth-2
// directories (existence only), bounded by maxMarkerDescend per level,
// stopping at the first label found. Opaque links are never entered.
func searchMarkersDepth(root string, entries []fs.DirEntry, ecosystems *[]string) {
	visited := 0
	for _, ent := range entries {
		if *ecosystems != nil || !ent.IsDir() || isOpaqueLink(ent.Type()) {
			continue
		}
		if visited >= maxMarkerDescend {
			return
		}
		visited++
		sub := filepath.Join(root, ent.Name())
		subEntries, err := os.ReadDir(sub)
		if err != nil {
			continue
		}
		for _, se := range subEntries {
			if markerNames[se.Name()] && se.Type().IsRegular() {
				for _, m := range markerEcosystems {
					if m.marker == se.Name() {
						*ecosystems = append(*ecosystems, m.label)
						break
					}
				}
				break
			}
		}
		if *ecosystems != nil {
			return
		}
		// Depth 2.
		deep := 0
		for _, se := range subEntries {
			if !se.IsDir() || isOpaqueLink(se.Type()) {
				continue
			}
			if deep >= maxMarkerDescend {
				break
			}
			deep++
			deepEntries, err := os.ReadDir(filepath.Join(sub, se.Name()))
			if err != nil {
				continue
			}
			for _, de := range deepEntries {
				if markerNames[de.Name()] && de.Type().IsRegular() {
					for _, m := range markerEcosystems {
						if m.marker == de.Name() {
							*ecosystems = append(*ecosystems, m.label)
							break
						}
					}
					return
				}
			}
		}
	}
}

// probeOutputRoots stats the known output folders at the project root
// and — for a monorepo — under the depth-1 and depth-2 subdirectories
// whose caches aggregate into the ONE parent record (plan §11.5A:
// apps/web/node_modules belongs to the monorepo, not to a split
// sub-package). A link-shaped output root is an opaque leaf: noted
// present with a zero estimate, never followed (§11.5E).
func probeOutputRoots(root string, entries []fs.DirEntry, isMonorepo bool) ([]OutputRoot, int64) {
	var (
		out       []OutputRoot
		total     int64
		seenPaths = map[string]bool{}
	)
	add := func(abs string, rel string, name string) {
		if seenPaths[rel] {
			return
		}
		fi, err := os.Lstat(abs)
		if err != nil {
			return
		}
		// The opaque-link test comes BEFORE the IsDir gate: junctions
		// carry ModeIrregular and (Go 1.27/Windows) no ModeDir, so an
		// IsDir-first order silently dropped the documented "noted
		// present with a zero estimate" opaque-leaf branch. A
		// link-shaped output root is an opaque leaf: size 0, never
		// followed (§11.5E) — whichever mode bits it carries.
		if isOpaqueLink(fi.Mode()) {
			seenPaths[rel] = true
			out = append(out, OutputRoot{Name: name, Path: rel, Bytes: 0})
			return
		}
		if !fi.IsDir() {
			return
		}
		seenPaths[rel] = true
		out = append(out, OutputRoot{Name: name, Path: rel, Bytes: shallowLogicalSize(abs)})
	}
	for _, name := range heavyFolders {
		add(filepath.Join(root, name), name, name)
	}
	if isMonorepo {
		visited := 0
		for _, d1 := range entries {
			if !d1.IsDir() || isOpaqueLink(d1.Type()) {
				continue
			}
			if visited++; visited > maxMonorepoScanDirs {
				break
			}
			for _, name := range heavyFolders {
				rel := d1.Name() + "/" + name
				add(filepath.Join(root, rel), rel, name)
			}
			// Depth 2: sub-package caches (apps/web/node_modules).
			sub, err := os.ReadDir(filepath.Join(root, d1.Name()))
			if err != nil {
				continue
			}
			for _, d2 := range sub {
				if !d2.IsDir() || isOpaqueLink(d2.Type()) {
					continue
				}
				if visited++; visited > maxMonorepoScanDirs {
					break
				}
				for _, name := range heavyFolders {
					rel := d1.Name() + "/" + d2.Name() + "/" + name
					add(filepath.Join(root, rel), rel, name)
				}
			}
		}
	}
	for _, o := range out {
		total += o.Bytes
	}
	return out, total
}

// shallowLogicalSize sums the LOGICAL sizes of a directory's immediate
// entries (one ReadDir + one stat per entry; no recursion). Directory
// entries contribute their own stat size (≈0 on NTFS/ext4), so deep
// trees are under-counted — the caller labels the result as an
// estimate. Link-shaped entries are opaque and contribute nothing.
func shallowLogicalSize(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, ent := range entries {
		if isOpaqueLink(ent.Type()) {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		total += info.Size()
	}
	return total
}

// probeLock gathers best-effort lock evidence for one project: the
// injected LockProbe seam (Restart Manager) when wired, else an
// exclusive-intent open probe on one regular file inside the first
// present output root. Failure to probe is silently omitted; ONLY
// sharing-violation-class failures of the open probe count as evidence
// (a read-only file's access-denied is NOT a lock — never a false
// [LOCKED]).
func probeLock(root string, outputs []OutputRoot, lock LockProbe) (bool, string) {
	for _, o := range outputs {
		dir := filepath.Join(root, filepath.FromSlash(o.Path))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.Type().IsRegular() {
				continue
			}
			info, err := ent.Info()
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			file := filepath.Join(dir, ent.Name())
			if lock != nil {
				writers, err := lock.InspectWriters([]string{file})
				if err != nil || len(writers) == 0 {
					// Seam error: omit silently (never a false claim).
					return false, ""
				}
				names := make([]string, 0, len(writers))
				for _, w := range writers {
					if w.Name != "" {
						names = append(names, w.Name)
					}
				}
				if len(names) == 0 {
					names = append(names, "unknown process")
				}
				if len(names) > 2 {
					names = names[:2]
				}
				return true, "locked: " + strings.Join(names, ", ") + " holds an active lock (skipped in batch operations)"
			}
			// Open probe (no content is read or written; the handle is
			// closed immediately).
			fh, err := os.OpenFile(file, os.O_RDWR, 0)
			if err == nil {
				_ = fh.Close()
				return false, ""
			}
			if isSharingViolation(err) {
				return true, "locked: a process holds an exclusive lock on " + o.Path + " (skipped in batch operations)"
			}
			// Any other failure (permissions, absence) is not lock
			// evidence: omit silently.
			return false, ""
		}
	}
	return false, ""
}

// isSharingViolation reports whether err is Windows ERROR_SHARING_VIOLATION
// (32) or the mandatory-lock EAGAIN/EWOULDBLOCK (11) — the only
// open-probe failures that constitute lock evidence. ERROR_PIPE_TYPE_...
// never appears from open(2) on regular files, so the numeric match is
// unambiguous in practice.
func isSharingViolation(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == 32 || errno == 11
}

// cargoHasWorkspace reports whether the manifest declares a [workspace]
// table (repository-boundary evidence for Cargo monorepos). Read is
// bounded to cargoWorkspaceScanLimit bytes; an unreadable manifest is
// conservatively NOT a workspace boundary.
func cargoHasWorkspace(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, cargoWorkspaceScanLimit))
	if err != nil {
		return false
	}
	for _, line := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if bytes.HasPrefix(trimmed, []byte("[workspace")) {
			// [workspace] or [workspace.package] / [workspace.dependencies]
			// all establish the boundary.
			return true
		}
	}
	return false
}

// ---- small path/IO helpers shared with the engine -----------------------

// dirChild is one immediate-child listing fact used for candidate
// collection.
type dirChild struct {
	name   string
	isLink bool
}

// readDirNames lists a root's immediate child directories. Regular
// files are not projects. Symlinks/junctions (any reparse point — Go
// reports NTFS junctions as ModeIrregular, only true symlinks carry
// ModeSymlink) are opaque leaves that could point outside the root
// (§11.5E): they are reported with isLink=true so the caller can note
// the skip and NEVER follow them.
func readDirNames(root string) ([]dirChild, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make([]dirChild, 0, len(entries))
	for _, ent := range entries {
		isLink := isOpaqueLink(ent.Type())
		// A directory OR a link-to-directory shape (link children are
		// surfaced for the skip note; files are simply not projects).
		if ent.IsDir() || isLink {
			out = append(out, dirChild{name: ent.Name(), isLink: isLink})
		}
	}
	return out, nil
}

// isNotExist reports a missing path/class-of-error.
func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// joinPath/basename are filepath wrappers (single place for separators).
func joinPath(root, name string) string { return filepath.Join(root, name) }
func baseName(p string) string          { return filepath.Base(p) }
