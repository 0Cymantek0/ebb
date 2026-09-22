// Package approvalstore persists local action approvals (Foundation
// §7.3) as a single JSON document. It is the path-injected store used by
// tests and wave C until the catalog integration lands.
//
// Concurrency: one FileApprover value is safe for concurrent use by many
// goroutines. Saves are crash-atomic — the document is written to an
// exclusively created temporary file, synced, then renamed over the
// destination — so a concurrent reader observes either the old or the
// new document, never a torn one. Read-modify-write races between
// SEPARATE FileApprover values or separate processes can still lose an
// approval; real cross-process locking belongs to the catalog
// integration that replaces this store.
//
// Trust: this package never approves anything by itself. Approve is the
// only entry point that records trust, and it exists for explicit
// UI/coordinator code; Matches only compares. An empty or missing
// document approves nothing.
//
// Migration (Wave G review finding G1): the recorded approval identity
// gained the working root and output ownership
// (actions.Approval.WorkingRoot/Outputs, Foundation §7.3). Documents
// written before those fields existed still parse (the new fields are
// simply absent → empty), but their records compare STALE against every
// definition — actions.ApprovalMatches treats missing output coverage
// as drift, never as a silent match. There is no rewrite step: the
// store is a rebuildable cache of trust decisions, and one honest
// re-prompt per previously approved action is the entire migration cost.
// (The document schema version stays 1: the on-disk shape only gained
// optional fields, and old readers that re-approve rewrite the file
// with the new fields populated.)
//
// Deletion authority: the only filesystem mutations here are the
// temporary file and the rename that replaces this store's own document.
// It never removes or renames anything else. The actions package proper
// has no removal or rename API at all; see its audit tripwire test.
package approvalstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/domain"
)

// docVersion is the approvals document schema version.
const docVersion = 1

// Windows sharing-violation tolerance: Go's file opens on Windows omit
// FILE_SHARE_DELETE, so a concurrent reader of the document can make a
// rename-over-target fail (and vice versa) with a sharing violation or
// access-denied errno. Both sides are short-lived, so a bounded retry
// resolves the race; it never masks a real failure.
const (
	shareRetryAttempts = 100
	shareRetryDelay    = 20 * time.Millisecond
)

const (
	errSharingViolation = syscall.Errno(32) // ERROR_SHARING_VIOLATION
	errAccessDenied     = syscall.Errno(5)  // ERROR_ACCESS_DENIED
)

// isSharingErr reports whether err is a transient Windows sharing
// violation worth retrying.
func isSharingErr(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	return errno == errSharingViolation || errno == errAccessDenied
}

// retryOnSharing retries op while it fails with a transient sharing
// violation, up to a bounded budget.
func retryOnSharing(op func() error) error {
	var err error
	for attempt := 0; attempt < shareRetryAttempts; attempt++ {
		err = op()
		if err == nil || !isSharingErr(err) {
			return err
		}
		time.Sleep(shareRetryDelay)
	}
	return err
}

// document is the on-disk shape: one JSON object holding every approval.
type document struct {
	Version   int                `json:"version"`
	Approvals []actions.Approval `json:"approvals"`
}

// FileApprover is a JSON-file actions.Approver. The zero value is not
// usable; construct with New.
type FileApprover struct {
	path string
	mu   sync.Mutex
}

// New returns a FileApprover backed by the JSON document at path. The
// document is created lazily on the first Approve; a missing document
// reads as an empty store (which approves nothing).
func New(path string) *FileApprover {
	return &FileApprover{path: path}
}

// Path returns the backing document path.
func (f *FileApprover) Path() string { return f.path }

// Matches returns the approval for def.ID and checks it against the
// resolved action (actions.ApprovalMatches). A missing approval is
// *actions.ErrApprovalRequired; any drift is *actions.ErrApprovalStale
// naming the drifted fields.
func (f *FileApprover) Matches(def actions.Definition, tool actions.ToolIdentity, inputDigests map[string]string) (*actions.Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	for i := range doc.Approvals {
		if doc.Approvals[i].ActionID != def.ID {
			continue
		}
		ap := doc.Approvals[i]
		if stale := actions.ApprovalMatches(&ap, def, tool, inputDigests); stale != nil {
			return nil, stale
		}
		return &ap, nil
	}
	return nil, &actions.ErrApprovalRequired{ActionID: def.ID}
}

// Approve records a local approval for def exactly as resolved (tool
// identity and input digests supplied by the caller), replacing any
// previous approval for the same action ID. It validates def first: an
// invalid definition is never recorded. This is the only trust-creating
// entry point in the package and must only be called from explicit
// approval flows — never from any run path.
func (f *FileApprover) Approve(def actions.Definition, tool actions.ToolIdentity, inputDigests map[string]string, approvedBy string) (*actions.Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	if err := def.Validate(); err != nil {
		return nil, err
	}
	ap := actions.Approval{
		ID:           domain.NewID(),
		ActionID:     def.ID,
		ArgvDigest:   actions.ArgvDigest(def.Argv),
		Tool:         tool,
		WorkingRoot:  def.WorkingRoot,
		Outputs:      actions.CanonicalOutputs(def.Outputs),
		InputDigests: copyDigests(inputDigests),
		EnvAllow:     actions.CanonicalEnvAllow(def.EnvAllow),
		Network:      def.Network,
		ApprovedBy:   approvedBy,
		ApprovedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	replaced := false
	for i := range doc.Approvals {
		if doc.Approvals[i].ActionID == def.ID {
			doc.Approvals[i] = ap
			replaced = true
			break
		}
	}
	if !replaced {
		doc.Approvals = append(doc.Approvals, ap)
	}
	if err := f.save(doc); err != nil {
		return nil, err
	}
	return &ap, nil
}

// List returns a copy of every recorded approval, in document order.
func (f *FileApprover) List() ([]actions.Approval, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	return append([]actions.Approval(nil), doc.Approvals...), nil
}

// load reads and validates the document; a missing file is an empty
// store.
func (f *FileApprover) load() (document, error) {
	var b []byte
	err := retryOnSharing(func() error {
		var e error
		b, e = os.ReadFile(f.path)
		return e
	})
	if errors.Is(err, os.ErrNotExist) {
		return document{Version: docVersion}, nil
	}
	if err != nil {
		return document{}, fmt.Errorf("approvalstore: read %q: %w", f.path, err)
	}
	var doc document
	if err := json.Unmarshal(b, &doc); err != nil {
		return document{}, fmt.Errorf("approvalstore: parse %q: %w", f.path, err)
	}
	if doc.Version != docVersion {
		return document{}, fmt.Errorf("approvalstore: %q: unsupported document version %d (want %d)", f.path, doc.Version, docVersion)
	}
	return doc, nil
}

// save atomically replaces the document: exclusive-create temp file,
// write, sync, rename over the destination.
func (f *FileApprover) save(doc document) error {
	doc.Version = docVersion
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("approvalstore: encode: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(f.path), filepath.Base(f.path)+".tmp-")
	if err != nil {
		return fmt.Errorf("approvalstore: create temp next to %q: %w", f.path, err)
	}
	tmpName := tmp.Name()
	commit := false
	defer func() {
		if !commit {
			// Best-effort cleanup of our own temp artifact only.
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("approvalstore: write %q: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("approvalstore: sync %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("approvalstore: close %q: %w", tmpName, err)
	}
	if err := retryOnSharing(func() error { return os.Rename(tmpName, f.path) }); err != nil {
		return fmt.Errorf("approvalstore: publish %q: %w", f.path, err)
	}
	commit = true
	return nil
}

// copyDigests defensively copies a digest map.
func copyDigests(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
