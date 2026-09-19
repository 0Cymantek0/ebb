package capsule

// container.go is the portable-capsule transport package (Foundation
// §15.1): a ZIP64 container of STORED (uncompressed) entries holding a
// fresh restic repository plus a small PUBLIC bootstrap descriptor. The
// backend already compresses and encrypts its payload — ZIP is transport
// packaging only; its CRC is not the security or recovery check (the
// restic repository's own authentication is, and the export re-opens
// the packaged repository before publication).
//
// ZIP64: the std archive/zip writer emits ZIP64 structures automatically
// whenever a size, offset or entry count exceeds the classic 32-bit /
// 16-bit limits (per-entry zip64 extra fields and the zip64 end-of-
// central-directory record); the reader accepts both classic and ZIP64
// forms. Small capsules are therefore ordinary-looking ZIPs that every
// ZIP64-capable reader — the only kind bootstrap.json declares — reads.
//
// Container layout (fixed):
//
//	bootstrap.json     public descriptor (§15.1: container version,
//	                   backend family, repo-relative root, minimum
//	                   reader feature set — nothing else)
//	ebb-export.json    interruption-identification manifest (op id,
//	                   source LOGICAL snapshot id, timestamps, declared
//	                   repo entry count and total bytes)
//	repo/**            the complete destination repository, regular
//	                   files and directories only, STORED
//
// The read path (verifyPackage / extractRepository) applies the §15.3
// extraction discipline to our own package: only the bounded set of
// regular files/directories below the declared repo prefix is accepted;
// absolute names, traversal, backslashes, drive-alias spellings, Windows
// device-name basenames, duplicate names, non-STORED methods, length
// inconsistencies and declared-total mismatches are all rejected.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Container layout constants.
const (
	bootstrapName  = "bootstrap.json"
	exportDocName  = "ebb-export.json"
	repoPrefix     = "repo"
	containerVer   = 1
	exportDocKind  = "ebb-export"
	exportStateRun = "verifying" // the only state a written partial can carry
)

// bootstrapDoc is the PUBLIC descriptor (§15.1). It exposes ONLY
// container version, backend family, repository-relative location and
// the minimum reader feature set. Workspace names, original paths, Git
// URLs, inventories and secrets stay inside the encrypted repository —
// none may ever be added here.
type bootstrapDoc struct {
	SchemaVersion     int      `json:"schema_version"`
	Producer          string   `json:"producer"`
	ContainerVersion  int      `json:"container_version"`
	BackendFamily     string   `json:"backend_family"`
	RepoRoot          string   `json:"repo_root"`
	MinReaderFeatures []string `json:"min_reader_features"`
}

// exportManifestDoc identifies an in-flight/abandoned partial (§15.2 "a
// failed export leaves an identifiable partial artifact" — under the
// Wave H contract a CONTROLLED failure removes its own partial, so what
// this document identifies is a crash leftover). It carries logical ids
// and timestamps only, never workspace names, paths or inventory data.
type exportManifestDoc struct {
	SchemaVersion    int    `json:"schema_version"`
	Kind             string `json:"kind"`
	OperationID      string `json:"operation_id"`
	SourceSnapshotID string `json:"source_snapshot_id"`
	StartedAt        string `json:"started_at"`
	State            string `json:"state"`
	ContainerVersion int    `json:"container_version"`
	RepoEntries      int64  `json:"repo_entries"`
	RepoBytes        int64  `json:"repo_bytes"`
}

// walkRepoFiles returns every regular file under repoRoot as
// slash-relative paths, sorted. Anything that is not a regular file or a
// directory — links of any flavor, devices, irregular objects — is
// REJECTED: a restic repository is regular files and directories, so
// anything else means the walk is looking at something it did not create
// (Foundation §15.2: reject/never follow links while walking the repo).
func walkRepoFiles(repoRoot string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(repoRoot, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		switch {
		case info.Mode().IsRegular():
			out = append(out, rel)
		case info.IsDir():
			// directory nodes are represented implicitly by their files'
			// paths on extraction; empty directories inside a restic repo
			// do not exist (pack/index/key/data/keys layout).
		default:
			return fmt.Errorf("capsule: repository walk found non-regular object %s (%s); a restic repository contains only regular files and directories — refusing", rel, info.Mode())
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("capsule: walk repository: %w", err)
	}
	sort.Strings(out)
	return out, nil
}

// writePackage streams the complete capsule into partialPath:
// bootstrap.json, ebb-export.json, then every repository file as a
// STORED entry named repo/<rel>. It returns the capsule's total size.
func writePackage(partialPath, repoRoot string, startedAt, opID, sourceSnapID string, producer string) (int64, error) {
	files, err := walkRepoFiles(repoRoot)
	if err != nil {
		return 0, err
	}
	var repoBytes int64
	for _, rel := range files {
		fi, ferr := os.Lstat(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if ferr != nil {
			return 0, fmt.Errorf("capsule: stat repo file %s: %w", rel, ferr)
		}
		repoBytes += fi.Size()
	}

	f, err := os.OpenFile(partialPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, fmt.Errorf("capsule: create partial %s: %w", partialPath, err)
	}
	zw := zip.NewWriter(f)

	writeDoc := func(name string, doc any) error {
		b, merr := json.MarshalIndent(doc, "", "  ")
		if merr != nil {
			return fmt.Errorf("capsule: marshal %s: %w", name, merr)
		}
		b = append(b, '\n')
		hdr := &zip.FileHeader{Name: name, Method: zip.Store, Modified: time.Now().UTC()}
		w, werr := zw.CreateHeader(hdr)
		if werr != nil {
			return fmt.Errorf("capsule: create %s entry: %w", name, werr)
		}
		if _, werr = w.Write(b); werr != nil {
			return fmt.Errorf("capsule: write %s entry: %w", name, werr)
		}
		return nil
	}

	if err := writeDoc(bootstrapName, bootstrapDoc{
		SchemaVersion:     1,
		Producer:          producer,
		ContainerVersion:  containerVer,
		BackendFamily:     "restic",
		RepoRoot:          repoPrefix,
		MinReaderFeatures: []string{"zip64", "zip-stored-entries", "restic"},
	}); err != nil {
		zw.Close()
		f.Close()
		os.Remove(partialPath)
		return 0, err
	}
	if err := writeDoc(exportDocName, exportManifestDoc{
		SchemaVersion: 1, Kind: exportDocKind,
		OperationID: opID, SourceSnapshotID: sourceSnapID,
		StartedAt: startedAt, State: exportStateRun,
		ContainerVersion: containerVer,
		RepoEntries:      int64(len(files)), RepoBytes: repoBytes,
	}); err != nil {
		zw.Close()
		f.Close()
		os.Remove(partialPath)
		return 0, err
	}

	for _, rel := range files {
		full := filepath.Join(repoRoot, filepath.FromSlash(rel))
		fi, ferr := os.Lstat(full)
		if ferr != nil {
			zw.Close()
			f.Close()
			os.Remove(partialPath)
			return 0, fmt.Errorf("capsule: stat repo file %s: %w", rel, ferr)
		}
		hdr := &zip.FileHeader{
			Name:     repoPrefix + "/" + rel,
			Method:   zip.Store,
			Modified: fi.ModTime().UTC(),
		}
		hdr.SetMode(fi.Mode().Perm())
		w, werr := zw.CreateHeader(hdr)
		if werr != nil {
			zw.Close()
			f.Close()
			os.Remove(partialPath)
			return 0, fmt.Errorf("capsule: create repo entry %s: %w", rel, werr)
		}
		src, oerr := os.Open(full)
		if oerr != nil {
			zw.Close()
			f.Close()
			os.Remove(partialPath)
			return 0, fmt.Errorf("capsule: open repo file %s: %w", rel, oerr)
		}
		if _, cerr := io.Copy(w, src); cerr != nil {
			src.Close()
			zw.Close()
			f.Close()
			os.Remove(partialPath)
			return 0, fmt.Errorf("capsule: store repo file %s: %w", rel, cerr)
		}
		src.Close()
	}

	if err := zw.Close(); err != nil {
		f.Close()
		os.Remove(partialPath)
		return 0, fmt.Errorf("capsule: finalize container: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(partialPath)
		return 0, fmt.Errorf("capsule: sync container: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(partialPath)
		return 0, fmt.Errorf("capsule: close container: %w", err)
	}
	fi, ferr := os.Stat(partialPath)
	if ferr != nil {
		os.Remove(partialPath)
		return 0, fmt.Errorf("capsule: stat container: %w", ferr)
	}
	return fi.Size(), nil
}

// ---- read path (the exporter re-reading its own package) ---------------

// windowsDeviceNames are the reserved DOS device basenames (§13.4
// "Windows device names" rejection; matched case-insensitively with and
// without an extension).
var windowsDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true,
	"COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true,
	"LPT7": true, "LPT8": true, "LPT9": true,
}

// validateEntryName applies the §15.3 bounded-name discipline to one
// container entry. wantRepo selects the repo/… prefix (files only);
// otherwise the name must be one of the two fixed top-level documents.
func validateEntryName(name string, wantRepo bool) error {
	if name == "" {
		return fmt.Errorf("empty entry name")
	}
	if strings.ContainsAny(name, "\\\x00") {
		return fmt.Errorf("entry name %q contains a backslash or NUL (forward slashes only)", name)
	}
	if strings.HasPrefix(name, "/") {
		return fmt.Errorf("absolute entry name %q", name)
	}
	if len(name) >= 2 && name[1] == ':' {
		return fmt.Errorf("drive-alias entry name %q", name)
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" {
			return fmt.Errorf("empty path segment in entry name %q", name)
		}
		if seg == "." || seg == ".." {
			return fmt.Errorf("traversal segment in entry name %q", name)
		}
		// Windows alias surface (§15.3 hostile-input discipline): a colon
		// ANYWHERE in a segment names an alternate data stream on NTFS
		// ("ab:cd" is a stream of file "ab", not a file "ab:cd"), and a
		// trailing dot or space is silently stripped by the filesystem on
		// write. Either would make the extracted path differ from the
		// capsule's declared name — mis-extraction, not a clean refusal —
		// so both are rejected here regardless of the host OS.
		if strings.Contains(seg, ":") {
			return fmt.Errorf("entry name %q segment %q contains a colon (an NTFS alternate-data-stream alias, not a portable file name)", name, seg)
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			return fmt.Errorf("entry name %q segment %q ends in a dot or space (silently stripped by Windows on write)", name, seg)
		}
		// Device-name basenames are reserved on Windows regardless of how
		// many extensions follow: strip EVERY trailing ".<ext>" so that
		// "con.foo.bar" reduces to "con" exactly as "con.txt" does.
		base := seg
		for {
			ext := filepath.Ext(base)
			if ext == "" {
				break
			}
			base = strings.TrimSuffix(base, ext)
		}
		if windowsDeviceNames[strings.ToUpper(base)] {
			return fmt.Errorf("Windows device-name segment %q in entry name %q", seg, name)
		}
	}
	if wantRepo {
		if !strings.HasPrefix(name, repoPrefix+"/") {
			return fmt.Errorf("entry %q is not below the declared repository prefix %q", name, repoPrefix)
		}
		return nil
	}
	if name != bootstrapName && name != exportDocName {
		return fmt.Errorf("unexpected top-level entry %q (only %s and %s may appear besides %s/)", name, bootstrapName, exportDocName, repoPrefix)
	}
	return nil
}

// containerCheck is the verified view of one written package.
type containerCheck struct {
	Bootstrap bootstrapDoc
	ExportDoc exportManifestDoc
}

// verifyPackage reopens partialPath with a FRESH reader and validates
// the container: central-directory readability, bounded entry names, no
// duplicates, STORED methods only, declared-vs-actual lengths, and the
// declared repo entry count / total bytes from ebb-export.json. Reading
// each member to EOF also verifies the ZIP CRC32 (§15.1: transport
// packaging — the CRC gate is structural, not the recovery proof).
func verifyPackage(partialPath string) (containerCheck, error) {
	f, err := os.Open(partialPath)
	if err != nil {
		return containerCheck{}, fmt.Errorf("capsule: reopen partial: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return containerCheck{}, fmt.Errorf("capsule: stat partial: %w", err)
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return containerCheck{}, fmt.Errorf("capsule: container central directory unreadable: %w", err)
	}

	seen := make(map[string]bool, len(zr.File))
	var gotRepoEntries int64
	var gotRepoBytes int64
	var out containerCheck
	for _, zf := range zr.File {
		if seen[zf.Name] {
			return containerCheck{}, fmt.Errorf("capsule: duplicate entry name %q in container", zf.Name)
		}
		seen[zf.Name] = true
		isRepo := strings.HasPrefix(zf.Name, repoPrefix+"/")
		if err := validateEntryName(zf.Name, isRepo); err != nil {
			return containerCheck{}, err
		}
		if zf.Method != zip.Store {
			return containerCheck{}, fmt.Errorf("capsule: entry %q uses compression method %d; the container contract is STORED entries only (§15.1)", zf.Name, zf.Method)
		}
		rc, oerr := zf.Open()
		if oerr != nil {
			return containerCheck{}, fmt.Errorf("capsule: open entry %s: %w", zf.Name, oerr)
		}
		var n int64
		if zf.Name == bootstrapName || zf.Name == exportDocName {
			var buf bytes.Buffer
			n, err = io.Copy(&buf, rc)
			if err == nil && zf.Name == bootstrapName {
				var b bootstrapDoc
				if derr := decodeStrictDoc(buf.Bytes(), zf.Name, &b); derr != nil {
					rc.Close()
					return containerCheck{}, derr
				}
				if berr := checkBootstrap(b); berr != nil {
					rc.Close()
					return containerCheck{}, berr
				}
				out.Bootstrap = b
			} else if err == nil {
				var e exportManifestDoc
				if derr := decodeStrictDoc(buf.Bytes(), zf.Name, &e); derr != nil {
					rc.Close()
					return containerCheck{}, derr
				}
				out.ExportDoc = e
			}
		} else {
			n, err = io.Copy(io.Discard, rc)
		}
		rc.Close()
		if err != nil {
			return containerCheck{}, fmt.Errorf("capsule: read entry %s (CRC/length gate): %w", zf.Name, err)
		}
		if uint64(n) != zf.UncompressedSize64 {
			return containerCheck{}, fmt.Errorf("capsule: entry %s length inconsistency: read %d bytes, central directory declares %d", zf.Name, n, zf.UncompressedSize64)
		}
		if isRepo {
			gotRepoEntries++
			gotRepoBytes += n
		}
	}
	if !seen[bootstrapName] || !seen[exportDocName] {
		return containerCheck{}, fmt.Errorf("capsule: container is missing its %s or %s document", bootstrapName, exportDocName)
	}
	if gotRepoEntries != out.ExportDoc.RepoEntries || gotRepoBytes != out.ExportDoc.RepoBytes {
		return containerCheck{}, fmt.Errorf(
			"capsule: declared repository totals disagree with the container (entries %d vs declared %d; bytes %d vs declared %d)",
			gotRepoEntries, out.ExportDoc.RepoEntries, gotRepoBytes, out.ExportDoc.RepoBytes)
	}
	return out, nil
}

// decodeStrictDoc is the strict JSON reader for container documents
// (unknown fields and trailing data rejected, §16.1).
func decodeStrictDoc(b []byte, name string, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("capsule: strict parse of %s: %w", name, err)
	}
	if dec.More() {
		return fmt.Errorf("capsule: strict parse of %s: trailing data after JSON value", name)
	}
	return nil
}

// checkBootstrap enforces the §15.1 public-descriptor shape: exactly the
// allowed fields with the allowed values for THIS writer generation.
func checkBootstrap(b bootstrapDoc) error {
	if b.SchemaVersion != 1 {
		return fmt.Errorf("capsule: bootstrap schema_version %d is unsupported", b.SchemaVersion)
	}
	if b.ContainerVersion != containerVer {
		return fmt.Errorf("capsule: bootstrap container_version %d is unsupported (reader supports %d)", b.ContainerVersion, containerVer)
	}
	if b.BackendFamily != "restic" {
		return fmt.Errorf("capsule: bootstrap backend_family %q is not supported (v1 reader: restic)", b.BackendFamily)
	}
	if b.RepoRoot != repoPrefix {
		return fmt.Errorf("capsule: bootstrap repo_root %q disagrees with the v1 layout %q", b.RepoRoot, repoPrefix)
	}
	if len(b.MinReaderFeatures) == 0 {
		return fmt.Errorf("capsule: bootstrap declares an empty minimum reader feature set")
	}
	return nil
}

// extractRepository unpacks repo/** from the container into dstDir with
// the repository prefix STRIPPED (dstDir becomes the repository root —
// the caller decides where the declared repo prefix lands), under the
// same bounded-name discipline (§15.3): every name was already
// validated by verifyPackage; extraction refuses to create anything but
// regular files and their parent directories inside the OWN destination.
func extractRepository(containerPath, dstDir string, maxBytes int64) error {
	f, err := os.Open(containerPath)
	if err != nil {
		return fmt.Errorf("capsule: open container for extraction: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("capsule: stat container: %w", err)
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return fmt.Errorf("capsule: reopen container: %w", err)
	}
	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return fmt.Errorf("capsule: create extraction root: %w", err)
	}
	// Defense in depth (HI-2): the headroom gate budgets against the
	// container's declared totals, but a container swapped in between
	// verify and extract must not write more than that budget. Extraction
	// therefore enforces maxBytes itself (cumulative written bytes), so
	// the §15.3 headroom promise holds even if the verified file changed.
	var written int64
	for _, zf := range zr.File {
		if !strings.HasPrefix(zf.Name, repoPrefix+"/") {
			continue // the two public documents are not repository content
		}
		rel := strings.TrimPrefix(zf.Name, repoPrefix+"/")
		if err := validateEntryName(zf.Name, true); err != nil {
			return err
		}
		target := filepath.Join(dstDir, filepath.FromSlash(rel))
		// Defense in depth: the joined target must still resolve inside
		// dstDir lexically after cleaning (validateEntryName already
		// rejected traversal; this catches any future regression).
		if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), filepath.Clean(dstDir)+string(os.PathSeparator)) {
			return fmt.Errorf("capsule: extraction target %s escapes the owned root", rel)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return fmt.Errorf("capsule: create parent of %s: %w", rel, err)
		}
		rc, oerr := zf.Open()
		if oerr != nil {
			return fmt.Errorf("capsule: open entry %s: %w", zf.Name, oerr)
		}
		out, cerr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if cerr != nil {
			rc.Close()
			return fmt.Errorf("capsule: create extracted file %s: %w", rel, cerr)
		}
		// Cap each entry at the remaining budget + 1 so an over-budget
		// write is detected (LimitReader reports EOF at the limit; one
		// extra byte proves there was more).
		remaining := maxBytes - written + 1
		if remaining < 0 {
			remaining = 0
		}
		n, cerr := io.Copy(out, io.LimitReader(rc, remaining))
		if cerr != nil {
			rc.Close()
			out.Close()
			return fmt.Errorf("capsule: extract %s: %w", rel, cerr)
		}
		written += n
		if written > maxBytes {
			rc.Close()
			out.Close()
			return fmt.Errorf("capsule: extraction exceeded the verified byte budget (%d bytes) at %s — the container does not match what the headroom gate accounted; refusing", maxBytes, rel)
		}
		rc.Close()
		if err := out.Close(); err != nil {
			return fmt.Errorf("capsule: close extracted file %s: %w", rel, err)
		}
	}
	return nil
}

// readPartialManifest is the stale-partial identification helper for the
// CLI's refusal path: it reads ebb-export.json out of an existing
// partial without trusting anything else in the file.
func readPartialManifest(path string) (exportManifestDoc, error) {
	f, err := os.Open(path)
	if err != nil {
		return exportManifestDoc{}, fmt.Errorf("capsule: open partial: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return exportManifestDoc{}, fmt.Errorf("capsule: stat partial: %w", err)
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return exportManifestDoc{}, fmt.Errorf("capsule: the file is not a readable capsule partial (no valid ZIP central directory): %w", err)
	}
	for _, zf := range zr.File {
		if zf.Name != exportDocName {
			continue
		}
		rc, oerr := zf.Open()
		if oerr != nil {
			return exportManifestDoc{}, fmt.Errorf("capsule: open %s: %w", exportDocName, oerr)
		}
		defer rc.Close()
		var buf bytes.Buffer
		if _, cerr := io.Copy(&buf, rc); cerr != nil {
			return exportManifestDoc{}, fmt.Errorf("capsule: read %s: %w", exportDocName, cerr)
		}
		var e exportManifestDoc
		if derr := decodeStrictDoc(buf.Bytes(), exportDocName, &e); derr != nil {
			return exportManifestDoc{}, derr
		}
		return e, nil
	}
	return exportManifestDoc{}, errors.New("capsule: partial carries no ebb-export.json identification manifest (unrecognized file)")
}
