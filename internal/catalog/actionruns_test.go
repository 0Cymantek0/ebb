package catalog

// action_runs journal tests: one row per attempt, terminal-status
// enforcement, listing order, and the succeeded-set used by open resume.

import (
	"errors"
	"testing"

	"ebb/internal/domain"
)

func TestActionRunsLifecycle(t *testing.T) {
	c := open(t)
	ws := domain.WorkspaceID(domain.NewID())
	if err := c.UpsertWorkspace(Workspace{ID: ws, Name: "runs", Status: WorkspaceLive}); err != nil {
		t.Fatal(err)
	}
	opID, err := c.BeginOperation(ws, OpKindOpen, `C:\ws`, "", "")
	if err != nil {
		t.Fatal(err)
	}

	// A crashed attempt stays "running"; a failed attempt is terminal.
	crashed, err := c.StartActionRun(opID, "deps")
	if err != nil {
		t.Fatal(err)
	}
	failed, err := c.StartActionRun(opID, "deps")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.FinishActionRun(failed, ActionRunFailed, 7, "stderr boom"); err != nil {
		t.Fatal(err)
	}

	// Finishing twice is rejected (one attempt, one outcome).
	if err := c.FinishActionRun(failed, ActionRunSucceeded, 0, ""); err == nil {
		t.Fatal("double finish must be rejected")
	}
	// "running" is not a terminal status.
	if err := c.FinishActionRun(crashed, ActionRunRunning, 0, ""); err == nil {
		t.Fatal("running is not a finishable status")
	}

	// A second attempt succeeds.
	second, err := c.StartActionRun(opID, "deps")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.FinishActionRun(second, ActionRunSucceeded, 0, ""); err != nil {
		t.Fatal(err)
	}

	runs, err := c.ListActionRuns(opID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 {
		t.Fatalf("runs = %d, want 3 (one row per attempt)", len(runs))
	}
	if runs[0].Status != ActionRunRunning || runs[1].Status != ActionRunFailed ||
		runs[2].Status != ActionRunSucceeded {
		t.Fatalf("run statuses in start order = %+v", runs)
	}
	if runs[1].ExitCode != 7 || runs[1].OutputExcerpt != "stderr boom" || runs[1].EndedAt == "" {
		t.Fatalf("failed row incomplete: %+v", runs[1])
	}

	succeeded, err := c.SucceededActions(opID)
	if err != nil {
		t.Fatal(err)
	}
	if !succeeded["deps"] || len(succeeded) != 1 {
		t.Fatalf("succeeded set = %v, want {deps}", succeeded)
	}

	// Unknown operations list empty; unknown rows refuse finishing.
	if empty, err := c.ListActionRuns(domain.OperationID(domain.NewID())); err != nil || len(empty) != 0 {
		t.Fatalf("unknown op runs = %v (%v)", empty, err)
	}
	if err := c.FinishActionRun(domain.ID(domain.NewID()), ActionRunFailed, 1, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown run err = %v, want ErrNotFound", err)
	}
	// An empty action id is refused.
	if _, err := c.StartActionRun(opID, ""); err == nil {
		t.Fatal("empty action id must be refused")
	}
}
