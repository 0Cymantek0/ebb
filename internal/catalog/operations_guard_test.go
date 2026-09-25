// operations_guard_test.go: the atomic operation-begin primitive
// (BeginOperationIfNoActive) and the forget operation's phase vocabulary.
// Regression-first specs for the Wave 5 safety fix of the §12.1
// check-then-insert race window (the gap lifecycle.go documents): two
// callers must never both observe "no active operation" — including from
// SEPARATE connection pools on the same database file, the shape a
// cross-process race takes.

package catalog

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// openAt opens an independent connection pool on the SAME catalog file
// (Open's DSN carries the IMMEDIATE transaction lock, so two pools
// reproduce the cross-process writer serialization the primitive relies
// on).
func openAt(t *testing.T, path string) *Catalog {
	t.Helper()
	c, err := Open(path)
	if err != nil {
		t.Fatalf("Open(%s): %v", path, err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return c
}

// TestGoBeginOperationIfNoActiveSerial: two sequential begins on one
// workspace — the second must be refused with the typed
// ErrActiveOperation naming the holder row; another workspace is
// unaffected; a begin after the holder reaches a terminal phase works.
func TestGoBeginOperationIfNoActiveSerial(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "serial")

	op, err := c.BeginOperationIfNoActive(ws, OpKindForget, PhaseForgetPlanned)
	if err != nil {
		t.Fatalf("first begin: %v", err)
	}
	if op.ID == "" || op.Kind != OpKindForget || op.Phase != PhaseForgetPlanned || op.WorkspaceID != ws {
		t.Fatalf("created operation = %+v", op)
	}
	got, err := c.GetOperation(op.ID)
	if err != nil || got.Kind != OpKindForget || got.Phase != PhaseForgetPlanned {
		t.Fatalf("journal row = %+v (%v)", got, err)
	}

	_, err = c.BeginOperationIfNoActive(ws, OpKindForget, PhaseForgetPlanned)
	if !errors.Is(err, ErrActiveOperation) {
		t.Fatalf("second begin err = %v, want ErrActiveOperation", err)
	}
	var active *ActiveOperationError
	if !errors.As(err, &active) {
		t.Fatalf("second begin err = %v, want *ActiveOperationError", err)
	}
	if active.Operation.ID != op.ID || active.Operation.Kind != OpKindForget || active.Operation.Phase != PhaseForgetPlanned {
		t.Fatalf("holder row = %+v, want the first operation", active.Operation)
	}

	// Another workspace is not blocked by this workspace's holder.
	ws2 := liveWorkspace(t, c, "other")
	if _, err := c.BeginOperationIfNoActive(ws2, OpKindForget, PhaseForgetPlanned); err != nil {
		t.Fatalf("begin on a second workspace: %v", err)
	}

	// After the holder reaches a terminal phase the workspace accepts a
	// new operation again.
	if err := c.AdvanceOperation(op.ID, PhaseForgetPlanned, PhaseCanceled); err != nil {
		t.Fatalf("cancel holder: %v", err)
	}
	if _, err := c.BeginOperationIfNoActive(ws, OpKindForget, PhaseForgetPlanned); err != nil {
		t.Fatalf("begin after cancel: %v", err)
	}
}

// TestGoBeginOperationIfNoActiveConcurrent: two independent pools race
// the primitive on the same database file; across repeated rounds
// EXACTLY one caller wins per round and the loser's typed error names
// the winner's row.
func TestGoBeginOperationIfNoActiveConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.db")
	c1 := openAt(t, path)
	c2 := openAt(t, path)
	ws := liveWorkspace(t, c1, "conc")

	for round := 0; round < 6; round++ {
		type result struct {
			op  Operation
			err error
		}
		results := make([]result, 2)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i, c := range []*Catalog{c1, c2} {
			wg.Add(1)
			go func(i int, c *Catalog) {
				defer wg.Done()
				<-start
				op, err := c.BeginOperationIfNoActive(ws, OpKindForget, PhaseForgetPlanned)
				results[i] = result{op: op, err: err}
			}(i, c)
		}
		close(start)
		wg.Wait()

		var winners []result
		for _, r := range results {
			switch {
			case r.err == nil:
				winners = append(winners, r)
			case errors.Is(r.err, ErrActiveOperation):
			default:
				t.Fatalf("round %d: unexpected error %v", round, r.err)
			}
		}
		if len(winners) != 1 {
			t.Fatalf("round %d: %d winners, want exactly 1 (%+v / %+v)", round, len(winners), results[0], results[1])
		}
		active, err := c1.ActiveOperations(ws)
		if err != nil || len(active) != 1 || active[0].ID != winners[0].op.ID {
			t.Fatalf("round %d: active rows = %+v (%v), want exactly the winner %s", round, active, err, winners[0].op.ID)
		}
		// Reset for the next round: the winner is canceled (the same
		// close a pre-destruction forget failure performs).
		if err := c1.AdvanceOperation(winners[0].op.ID, PhaseForgetPlanned, PhaseCanceled); err != nil {
			t.Fatalf("round %d: reset: %v", round, err)
		}
	}
}

// TestForgetPhaseVocabulary: the forget operation's dedicated phases are
// journaled through the CAS machinery, FORGET_DONE is terminal
// (ActiveOperations excludes it), and the rank helper orders the walk
// that crash resumes rely on.
func TestForgetPhaseVocabulary(t *testing.T) {
	c := open(t)
	ws := liveWorkspace(t, c, "vocab")

	if _, err := c.BeginOperationIfNoActive(ws, "nonsense", PhaseForgetPlanned); err == nil {
		t.Fatal("invalid kind accepted")
	}
	if _, err := c.BeginOperationIfNoActive(ws, OpKindForget, "FORGET_NONSENSE"); err == nil {
		t.Fatal("invalid start phase accepted")
	}
	op2, err := c.BeginOperationIfNoActive(ws, OpKindTrim, "")
	if err != nil || op2.Phase != PhasePlanned {
		t.Fatalf("empty start phase: op=%+v err=%v, want the PLANNED default", op2, err)
	}
	if err := c.AdvanceOperation(op2.ID, PhasePlanned, PhaseCanceled); err != nil {
		t.Fatalf("close the default-phase op: %v", err)
	}

	op, err := c.BeginOperationIfNoActive(ws, OpKindForget, PhaseForgetPlanned)
	if err != nil {
		t.Fatalf("begin forget: %v", err)
	}
	walk := []string{PhaseForgetPlanned, PhaseForgetIntentRecorded, PhaseForgetUnpinned, PhaseForgetBackendForgotten}
	for i := 0; i+1 < len(walk); i++ {
		if err := c.AdvanceOperation(op.ID, walk[i], walk[i+1]); err != nil {
			t.Fatalf("advance %s -> %s: %v", walk[i], walk[i+1], err)
		}
	}
	if err := c.AdvanceOperation(op.ID, PhaseForgetBackendForgotten, PhaseForgetDone); err != nil {
		t.Fatalf("advance to FORGET_DONE: %v", err)
	}
	active, err := c.ActiveOperations(ws)
	if err != nil || len(active) != 0 {
		t.Fatalf("active rows after FORGET_DONE = %+v (%v), want none (terminal)", active, err)
	}

	// Rank: strictly increasing along the walk; unknown phases rank last.
	prev := ForgetPhaseRank(PhaseForgetPlanned)
	for _, p := range walk[1:] {
		if r := ForgetPhaseRank(p); r <= prev {
			t.Fatalf("rank(%s)=%d not after rank %d", p, r, prev)
		}
	}
	if ForgetPhaseRank("PLANNED") != -1 || ForgetPhaseRank(PhaseForgetDone) <= ForgetPhaseRank(PhaseForgetBackendForgotten) {
		t.Fatalf("rank helper misplaced: DONE=%d unknown=%d", ForgetPhaseRank(PhaseForgetDone), ForgetPhaseRank("PLANNED"))
	}
}
