package catalog

import "errors"

// Sentinel errors returned by Catalog methods. Callers must match with
// errors.Is; SQL-layer failures are wrapped with context instead of
// being flattened into these.
var (
	// ErrNotFound reports a lookup by stable identity that matched no
	// row.
	ErrNotFound = errors.New("catalog: record not found")

	// ErrCASConflict reports that a guarded journal write lost its
	// compare-and-swap race: the operation's phase or generation no
	// longer matches the caller's expectation (Foundation §12.4: state
	// transitions use CAS generation checks inside catalog
	// transactions). The catalog never retries internally; the caller
	// re-reads the journal and decides.
	ErrCASConflict = errors.New("catalog: operation state changed concurrently (CAS conflict)")

	// ErrLastPinned reports a refused unpin: the snapshot is the last
	// pinned snapshot of a live workspace, and invariant I07 forbids
	// leaving a live workspace without a recovery obligation. Unpinning
	// anyway requires the force flag plus an explicit recorded reason.
	ErrLastPinned = errors.New("catalog: refusing to unpin the last pinned snapshot of a live workspace (I07)")
)
