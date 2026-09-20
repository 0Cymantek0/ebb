package catalog

// Vocabulary test for the restore operation kind and phases (D033):
// the closed vocabularies must accept every restore spelling, and the
// terminal set must exclude RESTORE_DONE's resumable failure twin.

import "testing"

func TestRestoreVocabulary(t *testing.T) {
	if !validOpKinds[OpKindRestore] {
		t.Fatalf("validOpKinds must accept %q", OpKindRestore)
	}
	for _, phase := range []string{
		PhaseRestorePlanning, PhaseRestoreRunning, PhaseRestoreDone, PhaseRestoreFailed,
	} {
		if !validPhases[phase] {
			t.Fatalf("validPhases must accept %q", phase)
		}
	}
	terminal := map[string]bool{}
	for _, p := range terminalPhases {
		terminal[p] = true
	}
	if !terminal[PhaseRestoreDone] {
		t.Fatalf("terminalPhases must include %q so a completed restore never blocks the workspace's future operations", PhaseRestoreDone)
	}
	if terminal[PhaseRestoreFailed] {
		t.Fatalf("terminalPhases must NOT include %q — a failed restore is resumable by rerunning `ebb restore`", PhaseRestoreFailed)
	}
}
