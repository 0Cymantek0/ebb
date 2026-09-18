package vault

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

	"ebb/internal/domain"
)

// docVersion is the vaults.json schema version.
const docVersion = 1

// defaultVaultName is the explicit default designation. Default()
// prefers a vault with this name over registration order.
const defaultVaultName = "main"

// Windows sharing-violation tolerance, mirroring
// internal/actions/approvalstore: Go's file opens on Windows omit
// FILE_SHARE_DELETE, so a concurrent reader of vaults.json can make a
// rename-over-target fail (and vice versa) with a sharing violation or
// access-denied errno. Both sides are short-lived; a bounded retry
// resolves the race and never masks a real failure.
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

// Vault is one registered vault in vaults.json. It is the
// credential-free half of a vault: the unlock secret lives in the OS
// credential store (or the user's records), NEVER in this record.
// Fields mirror catalog's vaults row; see CatalogArgs for the bridge.
type Vault struct {
	// ID is the vault identity: 32 lowercase hex chars (domain.NewID).
	ID string `json:"id"`
	// Name is a human label and explicit-default designation, not a key.
	Name string `json:"name"`
	// RepoDir is the absolute path of the restic repository directory.
	RepoDir string `json:"repo_dir"`
	// RepoID is the backend repository identity ("" until known).
	RepoID string `json:"repo_id,omitempty"`
	// CreatedAt is RFC3339Nano UTC (Foundation §16.1).
	CreatedAt string `json:"created_at"`
}

// CatalogArgs is the argument bundle for catalog.RegisterVault at the
// higher wiring layer. This package deliberately does not import
// internal/catalog; the cli/lifecycle layer performs the actual
//
//	cat.RegisterVault(catalog.Vault{
//	    ID:           args.ID,
//	    Path:         args.Path,
//	    RepoID:       args.RepoID,
//	    Kind:         args.Kind,
//	    RegisteredAt: args.RegisteredAt,
//	})
//
// so the registry (rebuildable, secret-free) and the catalog row stay in
// sync through one auditable call site.
type CatalogArgs struct {
	ID           domain.VaultID
	Path         string
	RepoID       string
	Kind         string
	RegisteredAt string
}

// CatalogArgs maps this Vault onto the catalog.RegisterVault call.
// Kind is "local" in v1 (the only kind).
func (v Vault) CatalogArgs() CatalogArgs {
	return CatalogArgs{
		ID:           domain.VaultID(v.ID),
		Path:         v.RepoDir,
		RepoID:       v.RepoID,
		Kind:         "local",
		RegisteredAt: v.CreatedAt,
	}
}

// validate checks one record loaded from disk (hostile-input hygiene:
// vaults.json is user-editable; Foundation §13.4 spirit).
func (v Vault) validate() error {
	if _, err := domain.ParseID(v.ID); err != nil {
		return fmt.Errorf("vault: registry entry id %q: %w", v.ID, err)
	}
	if v.Name == "" {
		return fmt.Errorf("vault: registry entry %s: name required", v.ID)
	}
	if v.RepoDir == "" {
		return fmt.Errorf("vault: registry entry %s: repo_dir required", v.ID)
	}
	return nil
}

// Registry is the vaults.json document plus its path. One Registry
// value is safe for concurrent use; saves are crash-atomic (exclusive
// temp file + fsync + rename over the destination, with the Windows
// sharing-retry), so a concurrent reader observes either the old or the
// new document, never a torn one. Read-modify-write races between
// SEPARATE Registry values or processes can still lose a registration;
// cross-process locking is not a v1 property (same contract as
// internal/actions/approvalstore).
type Registry struct {
	Version int     `json:"version"`
	Vaults  []Vault `json:"vaults"`

	path string
	mu   sync.Mutex
}

// New returns a Registry backed by vaults.json at path. The document is
// read lazily and created on first mutation; a missing document reads
// as an empty registry.
func New(path string) *Registry {
	return &Registry{path: path}
}

// Path returns the backing document path.
func (r *Registry) Path() string { return r.path }

// Register appends a new vault and persists atomically. The ID is a
// fresh domain.NewID; CreatedAt is now (UTC RFC3339Nano). Duplicate
// names are rejected: Get resolves by name and ambiguity would make
// lookups guess. The record contains no secret and never the password.
func (r *Registry) Register(name, repoDir, repoID string) (Vault, error) {
	return r.registerWithID(domain.NewID().String(), name, repoDir, repoID)
}

// registerWithID is Register with a caller-minted identity. Enroll is
// the only caller: its credential-store entry already targets the id
// it minted before initializing the repository, so the registered id
// MUST be that same id or the keyring entry would orphan.
func (r *Registry) registerWithID(id, name, repoDir, repoID string) (Vault, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	doc, err := r.load()
	if err != nil {
		return Vault{}, err
	}
	if _, perr := domain.ParseID(id); perr != nil {
		return Vault{}, fmt.Errorf("vault: register: %w", perr)
	}
	if name == "" {
		return Vault{}, errors.New("vault: register: name required")
	}
	if repoDir == "" {
		return Vault{}, errors.New("vault: register: repoDir required")
	}
	for _, v := range doc.Vaults {
		if v.Name == name {
			return Vault{}, fmt.Errorf("vault: register: duplicate vault name %q (existing id %s)", name, v.ID)
		}
		if v.ID == id {
			return Vault{}, fmt.Errorf("vault: register: duplicate vault id %s", id)
		}
	}
	v := Vault{
		ID:        id,
		Name:      name,
		RepoDir:   repoDir,
		RepoID:    repoID,
		CreatedAt: domain.FormatTime(time.Now()),
	}
	doc.Vaults = append(doc.Vaults, v)
	if err := r.save(doc); err != nil {
		return Vault{}, err
	}
	return v, nil
}

// Get returns the vault with exactly idOrName (id match first, then
// name), or a wrapped ErrNotFound.
func (r *Registry) Get(idOrName string) (*Vault, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	doc, err := r.load()
	if err != nil {
		return nil, err
	}
	for i := range doc.Vaults {
		if doc.Vaults[i].ID == idOrName {
			v := doc.Vaults[i]
			return &v, nil
		}
	}
	for i := range doc.Vaults {
		if doc.Vaults[i].Name == idOrName {
			v := doc.Vaults[i]
			return &v, nil
		}
	}
	return nil, fmt.Errorf("%w: vault %q", ErrNotFound, idOrName)
}

// Default returns the default vault: the vault explicitly named "main"
// when one exists, else the first registered vault. An empty registry
// is a wrapped ErrNotFound.
func (r *Registry) Default() (*Vault, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	doc, err := r.load()
	if err != nil {
		return nil, err
	}
	for i := range doc.Vaults {
		if doc.Vaults[i].Name == defaultVaultName {
			v := doc.Vaults[i]
			return &v, nil
		}
	}
	if len(doc.Vaults) > 0 {
		v := doc.Vaults[0]
		return &v, nil
	}
	return nil, fmt.Errorf("%w: no vaults registered", ErrNotFound)
}

// List returns a copy of every registered vault, in document order.
func (r *Registry) List() ([]Vault, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	doc, err := r.load()
	if err != nil {
		return nil, err
	}
	return append([]Vault(nil), doc.Vaults...), nil
}

// load reads and validates the document; a missing file is an empty
// registry. Unknown versions and malformed records are hard errors:
// guessing a vault binding would point restic at the wrong repository.
// It returns a pointer because Registry carries the document mutex.
func (r *Registry) load() (*Registry, error) {
	var b []byte
	err := retryOnSharing(func() error {
		var e error
		b, e = os.ReadFile(r.path)
		return e
	})
	if errors.Is(err, os.ErrNotExist) {
		return &Registry{Version: docVersion}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vault: read registry %q: %w", r.path, err)
	}
	var doc Registry
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("vault: parse registry %q: %w", r.path, err)
	}
	if doc.Version != docVersion {
		return nil, fmt.Errorf("vault: registry %q: unsupported version %d (want %d)", r.path, doc.Version, docVersion)
	}
	for _, v := range doc.Vaults {
		if err := v.validate(); err != nil {
			return nil, fmt.Errorf("vault: registry %q: %w", r.path, err)
		}
	}
	doc.path = r.path
	return &doc, nil
}

// save atomically replaces the document: exclusive-create temp file in
// the same directory, write, fsync, rename over the destination (with
// the Windows sharing-retry). The temp file is this package's only
// filesystem artifact besides the document itself.
func (r *Registry) save(doc *Registry) error {
	doc.Version = docVersion
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: encode registry: %w", err)
	}
	if err := writeAtomic(r.path, b); err != nil {
		return fmt.Errorf("vault: save registry: %w", err)
	}
	return nil
}

// writeAtomic durably replaces path with b via temp+rename. The temp
// file is created in path's directory with exclusive semantics (0600 on
// POSIX; on Windows the mode is advisory and the inherited per-user ACL
// of the parent directory governs), synced, then renamed over the
// destination under the bounded Windows sharing-retry. A failed
// publish removes only this temp file, never anything else.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("create temp next to %q: %w", path, err)
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
		return fmt.Errorf("write %q: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync %q: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %q: %w", tmpName, err)
	}
	if err := retryOnSharing(func() error { return os.Rename(tmpName, path) }); err != nil {
		return fmt.Errorf("publish %q: %w", path, err)
	}
	commit = true
	return nil
}
