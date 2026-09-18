package lifecycle

// Exact captured action definitions in the manifest (Foundation §16.2
// with the optional `definition` extension object of §16.1): the writer
// freezes CaptureOptions.ActionDefs per matching group, refuses a graph
// that cannot run, refuses orphan definitions, and the frozen wire form
// round-trips through the strict reader.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"ebb/internal/actions"
	"ebb/internal/catalog"
	"ebb/internal/domain"
)

func fixtureActionDef() actions.Definition {
	return actions.Definition{
		ID:          "deps",
		Argv:        []string{"pnpm", "install", "--frozen-lockfile"},
		WorkingRoot: ".",
		Inputs:      []string{"package.json", "pnpm-lock.yaml"},
		Outputs:     []string{"node_modules", "vendor/dist"},
		EnvAllow:    []string{"PNPM_HOME"},
		Network:     actions.NetworkAllowed,
		Timeout:     15 * time.Minute,
	}
}

// dumpedManifest fetches the frozen manifest bytes of a completed
// capture from the fake store.
func dumpedManifest(t *testing.T, h *harness, payloadID string, opID domain.OperationID) []byte {
	t.Helper()
	b, err := h.store.DumpFile(context.Background(), h.vault.RepoDir, h.vault.Passfile,
		payloadID, "/"+opDirName(opID)+"/"+manifestName)
	if err != nil {
		t.Fatalf("dump frozen manifest: %v", err)
	}
	return b
}

func TestManifestFreezesActionDefinitions(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	opts := snapshotOpts(ws)
	opts.Policy = trimPolicy(t)
	opts.ActionDefs = []actions.Definition{fixtureActionDef()}

	res, err := h.coord().Snapshot(context.Background(), h.vault, root, opts)
	if err != nil {
		t.Fatalf("snapshot with action defs: %v", err)
	}
	raw := dumpedManifest(t, h, res.BackendIDs[0], h.opIDOf(t, ws))

	// The strict reader (the same one Recover uses) accepts it, and the
	// wire form round-trips exactly.
	var m manifestDoc
	if err := decodeStrictJSON(raw, &m); err != nil {
		t.Fatalf("strict parse of the frozen manifest: %v", err)
	}
	if len(m.Actions) != 1 {
		t.Fatalf("actions = %+v", m.Actions)
	}
	d := m.Actions[0].Definition
	if d == nil {
		t.Fatalf("the definition extension must be frozen: %+v", m.Actions[0])
	}
	if d.ID != "deps" || strings.Join(d.Argv, " ") != "pnpm install --frozen-lockfile" ||
		d.WorkingRoot != "." || d.TimeoutNS != int64(15*time.Minute) ||
		d.Network != string(actions.NetworkAllowed) ||
		strings.Join(d.Inputs, ",") != "package.json,pnpm-lock.yaml" ||
		strings.Join(d.Outputs, ",") != "node_modules,vendor/dist" ||
		strings.Join(d.EnvAllow, ",") != "PNPM_HOME" {
		t.Fatalf("definition wire form drifted: %+v", d)
	}
	if len(d.DependsOn) != 0 {
		t.Fatalf("unexpected depends_on: %+v", d.DependsOn)
	}
	// schema_version stays 1 (optional extension object, not a schema
	// bump — §16.1).
	if m.SchemaVersion != schemaVersionCurrent {
		t.Fatalf("schema_version = %d", m.SchemaVersion)
	}
}

func TestManifestWithoutActionDefsStaysHintOnly(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	opts := snapshotOpts(ws)
	opts.Policy = trimPolicy(t) // no ActionDefs: legacy shape

	res, err := h.coord().Snapshot(context.Background(), h.vault, root, opts)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	raw := dumpedManifest(t, h, res.BackendIDs[0], h.opIDOf(t, ws))
	if strings.Contains(string(raw), "\"definition\"") {
		t.Fatal("a capture without ActionDefs must not emit definition objects")
	}
	var m manifestDoc
	if err := decodeStrictJSON(raw, &m); err != nil {
		t.Fatalf("strict parse: %v", err)
	}
	if len(m.Actions) != 1 || m.Actions[0].Definition != nil {
		t.Fatalf("legacy action shape drifted: %+v", m.Actions)
	}
}

func TestCaptureRejectsUnrunnableActionGraph(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	opts := snapshotOpts(ws)
	opts.Policy = trimPolicy(t)
	bad := fixtureActionDef()
	bad.Timeout = 0 // invalid definition
	opts.ActionDefs = []actions.Definition{bad}

	_, err := h.coord().Snapshot(context.Background(), h.vault, root, opts)
	var inv *ErrInvalidOptions
	if !errors.As(err, &inv) || !strings.Contains(err.Error(), "action definitions") {
		t.Fatalf("err = %v, want ErrInvalidOptions naming the action definitions", err)
	}
	// Nothing durable began: no operation row exists.
	ops, lerr := h.coord().cat.ListOperations(ws)
	if lerr != nil {
		t.Fatal(lerr)
	}
	if len(ops) != 0 {
		t.Fatalf("no operation may begin on an invalid action graph, got %d", len(ops))
	}
}

func TestCaptureRejectsOrphanActionDefinition(t *testing.T) {
	h := newHarness(t)
	ws := newWSID()
	root := h.workspace("ws")
	opts := snapshotOpts(ws)
	opts.Policy = trimPolicy(t)
	orphan := fixtureActionDef()
	orphan.ID = "not-a-group"
	opts.ActionDefs = []actions.Definition{orphan}

	_, err := h.coord().Snapshot(context.Background(), h.vault, root, opts)
	if err == nil || !strings.Contains(err.Error(), "matches no regenerate group") {
		t.Fatalf("orphan definition must fail the capture: %v", err)
	}
	// The failed capture leaves the operation at CAPTURING with the
	// failure recorded (the standard capture-step failure posture;
	// `ebb recover` cancels it from durable evidence) and the source
	// untouched.
	c := h.coord()
	ops, lerr := c.cat.ListOperations(ws)
	if lerr != nil || len(ops) != 1 {
		t.Fatalf("operations = %d (%v), want the one failed capture", len(ops), lerr)
	}
	if ops[0].Phase != catalog.PhaseCapturing {
		t.Fatalf("failed-capture op phase = %q, want CAPTURING", ops[0].Phase)
	}
	if !strings.Contains(ops[0].LastError, "matches no regenerate group") {
		t.Fatalf("journal last error must name the orphan: %q", ops[0].LastError)
	}
}
