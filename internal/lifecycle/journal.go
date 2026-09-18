package lifecycle

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"ebb/internal/domain"
)

// opJournal is the per-operation progress journal (Foundation §16.5:
// "per-entry removal progress can live in a bounded journal table or
// append record linked to the operation"). The catalog's phase
// transitions are the primary durable record; this append-only JSONL
// file adds removal granularity so Recover can report the exact
// last-removed entry and remaining count after a crash mid-walk.
//
// Location: a sibling of the source root (same volume as the op dirs,
// D003), named .ebb-journal-<opID>.jsonl. It is Ebb-owned scratch
// (removeEbbOwned shape-gated) and is removed when the operation
// reaches a terminal phase.
type opJournal struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// journalRecord is one journal line. Step names the sequence step
// (phase transitions, removals); Path carries the affected root-relative
// path when applicable.
type journalRecord struct {
	Time    string `json:"time"`
	Step    string `json:"step"`
	Path    string `json:"path,omitempty"`
	Removed int    `json:"removed,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// openJournal opens (creating) the journal for opID under parent. The
// caller defers close.
func openJournal(parent string, opID domain.OperationID) (*opJournal, error) {
	f, err := os.OpenFile(journalPath(parent, opID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: journal open: %w", err)
	}
	return &opJournal{path: journalPath(parent, opID), f: f}, nil
}

// append writes one record; journal failures are non-fatal (the catalog
// phase remains the authority) but are surfaced to the caller's error
// chain by close.
func (j *opJournal) append(rec journalRecord) {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return // already closed (sequence ended); the catalog is authority
	}
	if rec.Time == "" {
		rec.Time = domain.FormatTime(time.Now())
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_, _ = j.f.Write(append(b, '\n'))
}

// step is shorthand for a phase/step record.
func (j *opJournal) step(step, detail string) {
	j.append(journalRecord{Step: step, Detail: detail})
}

// close flushes the journal file to the OS. Idempotent: every sequence
// end (success and failure) closes it so the file is never left held
// (on Windows an open handle blocks deleting the parent directory).
func (j *opJournal) close() error {
	if j == nil || j.f == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	f := j.f
	j.f = nil
	return f.Close()
}

// readJournal loads every record of the journal for opID, if present.
// A missing journal is not an error (the operation may predate it or
// reached a terminal phase and cleaned up).
func readJournal(parent string, opID domain.OperationID) ([]journalRecord, error) {
	path := journalPath(parent, opID)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("lifecycle: journal read %s: %w", path, err)
	}
	defer f.Close()
	var out []journalRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec journalRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			// A torn final line (crash mid-append) is truncated at the
			// last complete record; earlier records remain evidence.
			break
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("lifecycle: journal scan %s: %w", path, err)
	}
	return out, nil
}

// lastRemoved returns the last removal record's path and count.
func lastRemoved(recs []journalRecord) (string, int) {
	path, n := "", 0
	for _, r := range recs {
		if r.Step == "removed" {
			path, n = r.Path, r.Removed
		}
	}
	return path, n
}
