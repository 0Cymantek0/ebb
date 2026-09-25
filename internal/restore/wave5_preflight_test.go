package restore

// wave5_preflight_test.go pins the E14-minimal custody contract (D6):
// before ANY effect, one present-and-non-empty output root of ANY group
// in the selected trim refuses the ENTIRE restore — no recipe runs over
// live data, and the refusal lists every group's presence state. It also
// probes the D5 legacy-manifest refusal (a trim manifest without the
// frozen action definition must not silently replay on the fabricated
// seal approval).

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0Cymantek0/ebb/internal/catalog"
)

// TestRestorePreflightBlocksAnyLiveOutput: group A's output is present
// and non-empty while group B's is missing — the whole restore is
// refused before a single recipe runs (E14: the old driver ran EVERY
// group's recipe, over A's live data).
func TestRestorePreflightBlocksAnyLiveOutput(t *testing.T) {
	recGit, liveGit := noDriftGit()
	f := buildTrimFixture(t, trimFixtureSpec{
		secondGroup: true,
		recordedGit: recGit, liveGit: liveGit,
	})
	// Group A (node-dependencies) has LIVE output content; group B
	// (py-reqs, outputs ["vendor"]) never had its outputs created.
	writeFile(t, filepath.Join(f.wsRoot, "node_modules", "left-pad.js"), []byte("// live work\n"))

	runner := &lrRunner{}
	o := f.newLiveRestorer(runner)
	_, err := o.LiveRestore(context.Background(), f.vault, f.wsRoot, LiveRestoreOptions{})
	if err == nil {
		t.Fatalf("restore with a live output root must be refused entirely (E14)")
	}
	if calls := len(runner.definitions()); calls != 0 {
		t.Fatalf("runner invocations = %d, want 0 (no recipe may run over live data)", calls)
	}
	// The refusal lists every group's presence state.
	msg := err.Error()
	if !strings.Contains(msg, "node-dependencies") || !strings.Contains(msg, "py-reqs") {
		t.Fatalf("refusal must list per-group presence for BOTH groups: %v", err)
	}
	if !strings.Contains(msg, "node_modules") {
		t.Fatalf("refusal must name the live output root: %v", err)
	}
	// No durable restore operation was opened (a preflight refusal).
	ops, lerr := f.cat.ListOperations(f.wsID)
	if lerr != nil {
		t.Fatal(lerr)
	}
	for _, op := range ops {
		if op.Kind == catalog.OpKindRestore {
			t.Fatalf("preflight refusal must not open a restore operation row: %+v", op)
		}
	}
}
