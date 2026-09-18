// Package catalog implements Ebb's local durable catalog (Foundation
// §16.5): the rebuildable index of workspaces, vaults, snapshots,
// approvals and retention intents, plus the crash-recovery operation
// journal of Foundation §12.4.
//
// Storage is SQLite through the pure-Go driver modernc.org/sqlite
// (Decisions.md D002.amendment — no CGO anywhere). Every pooled
// connection is opened with the §16.5 durability pragmas:
// journal_mode=DELETE, synchronous=EXTRA, foreign_keys=ON and
// busy_timeout=5000. Write transactions take SQLite's IMMEDIATE lock
// (via the driver's _txlock DSN parameter) so concurrent writers queue
// on the busy timeout instead of failing a deferred read-to-write lock
// upgrade.
//
// v1 is synchronous: context is deliberately not threaded through the
// API. Every call is one short transaction issued by the serialized CLI;
// adding cancellation is a future, deliberate widening.
package catalog

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	// The driver registers itself under the name "sqlite"; it is imported
	// for its side effect of registration, the standard database/sql
	// mechanism.
	_ "modernc.org/sqlite"

	"ebb/internal/domain"
)

// dsnSuffix carries the per-connection pragmas mandated by Foundation
// §16.5 plus the immediate transaction lock. The driver executes each
// _pragma value verbatim on every new pooled connection, in its fixed
// order (busy_timeout first, the rest lexicographically).
const dsnSuffix = "?_pragma=busy_timeout(5000)" +
	"&_pragma=foreign_keys(1)" +
	"&_pragma=journal_mode(DELETE)" +
	"&_pragma=synchronous(EXTRA)" +
	"&_txlock=immediate"

// Catalog is a handle to the local durable catalog. It is safe for
// concurrent use; all writes run inside transactions.
type Catalog struct {
	db *sql.DB
}

// Open opens (creating if necessary) the catalog database at path and
// brings its schema up to date by applying pending migrations. The
// durability pragmas are applied to every connection the pool ever
// opens. A missing or corrupt file surfaces as an ordinary error from
// the first statement, never a panic.
func Open(path string) (*Catalog, error) {
	if path == "" {
		return nil, errors.New("catalog: open: empty path")
	}
	db, err := sql.Open("sqlite", path+dsnSuffix)
	if err != nil {
		return nil, fmt.Errorf("catalog: open %s: %w", path, err)
	}
	c := &Catalog{db: db}
	if err := c.migrate(); err != nil {
		if cerr := db.Close(); cerr != nil {
			return nil, fmt.Errorf("catalog: %w (additionally closing handle: %v)", err, cerr)
		}
		return nil, err
	}
	return c, nil
}

// Close releases the underlying connection pool. The catalog must not
// be used afterwards.
func (c *Catalog) Close() error {
	return c.db.Close()
}

// QuickCheck runs SQLite's PRAGMA quick_check and reports the first
// problems found. It is the cheap structural verification called after
// an unclean-exit detection, before trusting the journal (§11.5).
func (c *Catalog) QuickCheck() error {
	rows, err := c.db.Query("PRAGMA quick_check")
	if err != nil {
		return fmt.Errorf("catalog: quick_check: %w", err)
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("catalog: quick_check: scan: %w", err)
		}
		if line != "ok" {
			problems = append(problems, line)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("catalog: quick_check: %w", err)
	}
	if len(problems) > 0 {
		return fmt.Errorf("catalog: quick_check reported %d problem(s): %s", len(problems), strings.Join(problems, "; "))
	}
	return nil
}

// migrate applies pending schema migrations. Each migration runs inside
// one transaction together with the insert of its version row, so an
// interrupted migration leaves no partial version behind.
func (c *Catalog) migrate() error {
	err := withTx(c.db, func(tx *sql.Tx) error {
		if _, err := tx.Exec(schemaMigrationsDDL); err != nil {
			return fmt.Errorf("catalog: ensure schema_migrations: %w", err)
		}
		for i, ddl := range migrations {
			version := i + 1
			var applied int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&applied); err != nil {
				return fmt.Errorf("catalog: migration %d: check: %w", version, err)
			}
			if applied > 0 {
				continue
			}
			if _, err := tx.Exec(ddl); err != nil {
				return fmt.Errorf("catalog: migration %d: %w", version, err)
			}
			if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
				version, domain.FormatTime(time.Now())); err != nil {
				return fmt.Errorf("catalog: migration %d: record: %w", version, err)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("catalog: migrate: %w", err)
	}
	return nil
}

// withTx runs fn inside one transaction: BEGIN (IMMEDIATE, via the DSN
// _txlock), body, COMMIT — or ROLLBACK on any error. All Catalog writes
// go through it.
func withTx(db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("catalog: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, sql.ErrTxDone) {
			return fmt.Errorf("catalog: %w (additionally rolling back: %v)", err, rerr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("catalog: commit: %w", err)
	}
	return nil
}

// nullStr maps an empty Go string to SQL NULL for nullable text columns
// (empty is "absent" throughout the catalog schema).
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
