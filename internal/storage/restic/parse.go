package resticstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"ebb/internal/domain"
)

// backupSummary is the single final stdout record of `backup --json`
// (probe Q3). snapshot_id is the full 64-hex id; dry_run is defensively
// rejected because Ebb never passes --dry-run but a dry-run summary
// still carries a prospective snapshot_id that proves nothing.
type backupSummary struct {
	MessageType string `json:"message_type"`
	SnapshotID  string `json:"snapshot_id"`
	DryRun      bool   `json:"dry_run"`
	BackupEnd   string `json:"backup_end"`
	TotalFiles  int    `json:"total_files_processed"`
}

// parseBackupSummary scans backup stdout NDJSON. status records are
// counted and ignored; the last summary record wins. A missing summary
// is reported as such (truncated output).
func parseBackupSummary(stdout []byte) (summary *backupSummary, statusCount int, err error) {
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec backupSummary
		if jerr := json.Unmarshal([]byte(line), &rec); jerr != nil {
			continue // tolerate any stray non-JSON noise
		}
		switch rec.MessageType {
		case "status":
			statusCount++
		case "summary":
			s := rec
			summary = &s
		}
	}
	if summary == nil {
		err = fmt.Errorf("no summary record in backup output (%d status records)", statusCount)
	}
	return summary, statusCount, err
}

// snapshotRecord is one element of `snapshots --json` (probe Q5 header
// field set). The paths field keeps the native form exactly as restic
// recorded it (cwd-resolved absolute, backslashes on Windows) — that is
// what the store truthfully knows; the D003 bijection lives in the
// manifest and in the ls tree paths.
type snapshotRecord struct {
	ID       string   `json:"id"`
	ShortID  string   `json:"short_id"`
	Time     string   `json:"time"`
	Hostname string   `json:"hostname"`
	Paths    []string `json:"paths"`
	Tags     []string `json:"tags"`
}

// parseSnapshots parses the `snapshots --json` array. An empty repo
// prints `[]` and exits 0 (pinned live against 0.19.1; the probe's
// "does it error?" question is answered: no).
func parseSnapshots(stdout []byte) ([]domain.SnapshotRef, error) {
	stdout = bytes.TrimSpace(stdout)
	if len(stdout) == 0 {
		return nil, fmt.Errorf("empty snapshots output")
	}
	var recs []snapshotRecord
	if err := json.Unmarshal(stdout, &recs); err != nil {
		return nil, fmt.Errorf("parsing snapshots --json: %w", err)
	}
	out := make([]domain.SnapshotRef, 0, len(recs))
	for _, r := range recs {
		out = append(out, domain.SnapshotRef{
			BackendID: r.ID,
			ShortID:   r.ShortID,
			Time:      r.Time,
			Paths:     r.Paths,
			Tags:      decodeTagList(r.Tags),
		})
	}
	return out, nil
}

// lsNode is one node record of `ls --json` (probe Q5). The first
// record is a snapshot header (message_type "snapshot") and is skipped.
// restic 0.19.1 exposes NO linktarget field in ls output — link text
// must come from dump/restore, so TreeEntry.LinkTarget stays empty.
type lsNode struct {
	MessageType string `json:"message_type"`
	StructType  string `json:"struct_type"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	Mode        uint32 `json:"mode"`
	Permissions string `json:"permissions"`
	Mtime       string `json:"mtime"`
}

// mapNodeKind maps a restic node type to a domain EntryKind.
//
// "file" maps to KindFile and nothing else does. fifo/socket/dev map to
// their domain kinds. Anything unrecognized (e.g. "irregular" or a
// future type) is mapped conservatively to KindOtherReparse — the
// domain's blocker kind for unmodeled special objects (its
// DestructiveSafe is false) — and the raw type is preserved in
// TreeEntry.Mode as "type:<raw>" so no information is invented or lost.
func mapNodeKind(t string) (domain.EntryKind, string) {
	switch t {
	case "file":
		return domain.KindFile, ""
	case "dir":
		return domain.KindDir, ""
	case "symlink":
		return domain.KindSymlink, ""
	case "fifo":
		return domain.KindFIFO, ""
	case "socket":
		return domain.KindSocket, ""
	case "dev", "chardev":
		return domain.KindDevice, ""
	default:
		return domain.KindOtherReparse, "type:" + t
	}
}

// parseLs parses `ls --json` NDJSON into tree entries.
func parseLs(stdout []byte) ([]domain.TreeEntry, error) {
	var out []domain.TreeEntry
	sawHeader := false
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var n lsNode
		if err := json.Unmarshal([]byte(line), &n); err != nil {
			return nil, fmt.Errorf("parsing ls --json line %q: %w", truncate(line, 120), err)
		}
		switch n.MessageType {
		case "snapshot":
			sawHeader = true // leading header record, not a tree node
		case "node":
			kind, modeOverride := mapNodeKind(n.Type)
			mode := n.Permissions
			if modeOverride != "" {
				mode = modeOverride
			} else if mode == "" && n.Mode != 0 {
				mode = fmt.Sprintf("%o", n.Mode)
			}
			out = append(out, domain.TreeEntry{
				Path:    n.Path,
				Kind:    kind,
				Size:    n.Size,
				Mode:    mode,
				ModTime: n.Mtime,
			})
		}
	}
	if !sawHeader && len(out) == 0 {
		return nil, fmt.Errorf("ls output contained neither a snapshot header nor node records")
	}
	return out, nil
}

// repoConfigDoc is the decrypted `cat config` document (probe Q9):
// {"version":2,"id":"<64-hex>","chunker_polynomial":"..."}.
type repoConfigDoc struct {
	Version int    `json:"version"`
	ID      string `json:"id"`
}

func parseRepoID(stdout []byte) (string, error) {
	var doc repoConfigDoc
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &doc); err != nil {
		return "", fmt.Errorf("parsing cat config: %w", err)
	}
	if !isHexID(doc.ID, 64) {
		return "", fmt.Errorf("cat config id %q is not a 64-hex repository id", doc.ID)
	}
	return doc.ID, nil
}

// isHexID reports whether s is exactly n lowercase hex characters
// (restic ids are always lowercase).
func isHexID(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// encodeTags renders the caller's operation tags as restic --tag
// arguments. Every Ebb snapshot additionally carries the fixed
// discovery tag ebb:v1. Tags are flat restic strings; the map is
// encoded as key:value (first colon splits on decode), keys sorted for
// deterministic argv.
func encodeTags(tags map[string]string) (args []string, decoded map[string]string, err error) {
	decoded = map[string]string{baseTagKey: baseTagVal}
	args = []string{"--tag", baseTagKey + ":" + baseTagVal}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := tags[k]
		if !validTagToken(k) {
			return nil, nil, fmt.Errorf("tag key %q must be non-empty [A-Za-z0-9._-]", k)
		}
		if !validTagToken(v) {
			return nil, nil, fmt.Errorf("tag value %q for key %q must be [A-Za-z0-9._-] (empty allowed)", v, k)
		}
		args = append(args, "--tag", k+":"+v)
		decoded[k] = v
	}
	return args, decoded, nil
}

func validTagToken(s string) bool {
	if s == "" {
		return false // RESTIC-TAG-1: the empty string loops zero times and passed
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
		default:
			return false
		}
	}
	return true
}

// decodeTagList converts flat restic tags back to a map: "k:v" splits
// on the first colon; a bare "k" decodes to k:"" (restic forbids
// spaces but not colon-less tags).
func decodeTagList(tags []string) map[string]string {
	if len(tags) == 0 {
		return nil
	}
	m := make(map[string]string, len(tags))
	for _, t := range tags {
		if i := strings.IndexByte(t, ':'); i >= 0 {
			m[t[:i]] = t[i+1:]
		} else {
			m[t] = ""
		}
	}
	return m
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
