// Package config owns Ebb's persistent global configuration document
// (D032/D037 groundwork): one config.json living beside catalog.db in
// the state directory (vault.DefaultConfigDir, so EBB_STATE_DIR
// isolation covers it). Schema v1 holds exactly one list-valued key,
// "projects_dir" — the scan roots Wave 2's `ebb analyse` will consume.
//
// The document contains PATHS ONLY. Secrets (vault/capsule passphrases,
// tokens) must never be stored here (Foundation §13: the config dir is
// plaintext; secrets belong to the OS credential store and ephemeral
// passfiles).
//
// Missing file = zero-value config, never an error (a fresh install has
// no config.json until the first mutation writes it). Writes are atomic
// (temp file in the same directory + rename, mode 0600) so an
// interrupted save can never leave a torn document.
//
// Path spelling rule (host-agnostic, judged identically everywhere):
// stored values are absolute, Cleaned, insertion-ordered, and
// deduplicated. Dedup compares exact bytes FIRST and falls back to a
// strings.ToLower comparison — a deliberate tiebreaker-only use, giving
// Windows path semantics (C:\Foo and c:\foo name one root) on every
// platform while never rewriting the spelling the user typed; the
// first-inserted spelling wins.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// File is the configuration document's name inside the state directory.
const File = "config.json"

// SchemaVersion is the schema this build reads and writes. A document
// stamped with a HIGHER version is refused (fail closed: a newer
// install's keys must not be silently dropped by an older binary).
const SchemaVersion = 1

// KeyProjectsDir is the v1 list-valued scan-roots key.
const KeyProjectsDir = "projects_dir"

// MaxListValues bounds every list-valued key (32 scan roots is far past
// any sane developer-machine layout and keeps the document trivially
// reviewable by a human).
const MaxListValues = 32

// Typed errors. Unknown keys and bad values are usage-class mistakes;
// they are wrapped with the offending key/value via %w so callers can
// both errors.Is the sentinel and show the context.
var (
	// ErrUnknownKey: the key is not defined in schema v1.
	ErrUnknownKey = errors.New("config: unknown configuration key")
	// ErrRelativePath: a value must be an absolute path (nonexistence on
	// disk is ACCEPTED — offline/external drives are valid scan roots).
	ErrRelativePath = errors.New("config: value must be an absolute path")
	// ErrTooManyValues: the key's list is at MaxListValues.
	ErrTooManyValues = errors.New("config: too many values")
	// ErrNotPresent: RemoveProjectsDir named a path that is not stored.
	ErrNotPresent = errors.New("config: value is not configured")
	// ErrUnsupportedSchema: the document's schema_version is newer than
	// this build understands.
	ErrUnsupportedSchema = errors.New("config: unsupported schema version")
)

// wire is the on-disk document shape (the one place untyped JSON is
// tolerated; everything above and below speaks concrete types).
type wire struct {
	SchemaVersion int      `json:"schema_version"`
	ProjectsDir   []string `json:"projects_dir"`
}

// Config is Ebb's global configuration. Construct via Load (or &Config{}
// for a fresh document); mutate through the methods; persist with Save.
type Config struct {
	schemaVersion int
	projectsDir   []string
}

// Load reads dir/config.json. A missing file is the zero-value config
// with no error. A present document must be schema v1 (or the
// empty-file zero shape) with absolute, Clean-able projects_dir values;
// a hand-edited document violating the invariants is refused rather
// than silently repaired.
func Load(dir string) (*Config, error) {
	path := filepath.Join(dir, File)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if w.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("%w: document says %d, this build understands %d",
			ErrUnsupportedSchema, w.SchemaVersion, SchemaVersion)
	}
	for _, p := range w.ProjectsDir {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("%w: projects_dir entry %q", ErrRelativePath, p)
		}
	}
	c := &Config{schemaVersion: w.SchemaVersion, projectsDir: append([]string(nil), w.ProjectsDir...)}
	c.projectsDir = dedupPaths(c.projectsDir)
	if len(c.projectsDir) > MaxListValues {
		return nil, fmt.Errorf("%w: projects_dir holds %d entries (max %d)",
			ErrTooManyValues, len(c.projectsDir), MaxListValues)
	}
	return c, nil
}

// Save atomically writes the document to dir/config.json (creating the
// directory), always stamped with the current SchemaVersion. The temp
// file is removed on any failure, so a failed save never leaves a
// partial document or debris.
func (c *Config) Save(dir string) error {
	w := wire{SchemaVersion: SchemaVersion, ProjectsDir: c.ProjectsDirs()}
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: create state dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, File)
	tmp, err := os.CreateTemp(dir, "."+File+"-*")
	if err != nil {
		return fmt.Errorf("config: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(tmpName) }
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("config: chmod temp %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		cleanup()
		return fmt.Errorf("config: write temp %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("config: sync temp %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("config: close temp %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("config: replace %s: %w", path, err)
	}
	return nil
}

// ProjectsDirs returns a copy of the scan roots, insertion-ordered.
func (c *Config) ProjectsDirs() []string {
	if len(c.projectsDir) == 0 {
		return nil
	}
	return append([]string(nil), c.projectsDir...)
}

// AddProjectsDir appends one scan root: absolutized (filepath.Abs
// against the process working directory), Cleaned, deduplicated
// (exact bytes first, then strings.ToLower — see the package comment).
// The first-inserted spelling wins; a later case-variant spelling is a
// duplicate, not a new entry.
func (c *Config) AddProjectsDir(path string) error {
	abs, err := absolutize(path)
	if err != nil {
		return err
	}
	for _, existing := range c.projectsDir {
		if samePath(existing, abs) {
			return nil
		}
	}
	if len(c.projectsDir) >= MaxListValues {
		return fmt.Errorf("%w: projects_dir is full (%d entries; max %d)",
			ErrTooManyValues, len(c.projectsDir), MaxListValues)
	}
	c.projectsDir = append(c.projectsDir, abs)
	return nil
}

// RemoveProjectsDir removes one scan root (the same Abs+Clean
// normalization and the same case-insensitive tiebreaker as Add, so any
// spelling the user could have added removes it). An absent path is a
// typed ErrNotPresent.
func (c *Config) RemoveProjectsDir(path string) error {
	abs, err := absolutize(path)
	if err != nil {
		return err
	}
	for i, existing := range c.projectsDir {
		if samePath(existing, abs) {
			c.projectsDir = append(c.projectsDir[:i], c.projectsDir[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: %q (configured roots: %s)",
		ErrNotPresent, path, strings.Join(c.projectsDir, ", "))
}

// Get returns a copy of the key's values and whether the key exists in
// schema v1. An existing key with no values returns (nil, true).
func (c *Config) Get(key string) ([]string, bool) {
	if key != KeyProjectsDir {
		return nil, false
	}
	return c.ProjectsDirs(), true
}

// Set replaces the key's whole list. Values must already be absolute
// (typed ErrRelativePath otherwise; Set never absolutizes silently);
// they are Cleaned and deduplicated with the documented rule and
// bounded by MaxListValues. Unknown keys are typed ErrUnknownKey.
func (c *Config) Set(key string, values []string) error {
	if key != KeyProjectsDir {
		return fmt.Errorf("%w: %q (v1 knows only %s)", ErrUnknownKey, key, KeyProjectsDir)
	}
	normalized := make([]string, 0, len(values))
	for _, v := range values {
		if !filepath.IsAbs(v) {
			return fmt.Errorf("%w: %q", ErrRelativePath, v)
		}
		normalized = append(normalized, filepath.Clean(v))
	}
	normalized = dedupPaths(normalized)
	if len(normalized) > MaxListValues {
		return fmt.Errorf("%w: %d values given (max %d)",
			ErrTooManyValues, len(normalized), MaxListValues)
	}
	c.projectsDir = normalized
	return nil
}

// absolutize resolves one user-supplied path to the stored form.
func absolutize(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("config: resolve %q: %w", path, err)
	}
	return filepath.Clean(abs), nil
}

// samePath is the dedup comparator: exact bytes first, then a
// strings.ToLower tiebreaker (Windows path semantics applied
// host-agnostically; see the package comment).
func samePath(a, b string) bool {
	if a == b {
		return true
	}
	return strings.ToLower(a) == strings.ToLower(b)
}

// dedupPaths applies the comparator to a cleaned list, keeping the
// first occurrence of each spelling and preserving insertion order.
func dedupPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		dup := false
		for _, kept := range out {
			if samePath(kept, p) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, p)
		}
	}
	return out
}
