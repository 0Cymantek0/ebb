package lifecycle

import (
	"testing"

	"ebb/internal/domain"
	"ebb/internal/version"
)

// TestProducerVersionSingleSource pins the version lockstep
// structurally: the producer identity frozen into manifests and
// receipts must be built from internal/version.Version — the same
// single build-version authority `ebb version` reports — so a
// link-time-stamped release binary records its real version in its
// recovery records, and nobody can reintroduce a second hard-coded
// version copy (the old ProducerEbbVersion const drifted from the CLI
// version by comment-only lockstep) without failing this test.
func TestProducerVersionSingleSource(t *testing.T) {
	want := "ebb " + version.Version + "; " + ProducerBackend
	if got := producerString(); got != want {
		t.Fatalf("manifest producer = %q, want %q (version.Version = %q)",
			got, want, version.Version)
	}

	r := buildReceipt(
		domain.SnapshotID("snap-1"), domain.WorkspaceID("ws-1"),
		"repo", "payload", "manifest-digest", "inventory-digest",
		domain.OperationID("op-1"), "coverage+documents",
		"2026-01-01T00:00:00Z", nil,
	)
	if got := r.Verification.ToolVersions["ebb"]; got != version.Version {
		t.Fatalf("receipt tool_versions[ebb] = %q, want version.Version = %q",
			got, version.Version)
	}
	if got := r.Verification.ToolVersions["backend"]; got != ProducerBackend {
		t.Fatalf("receipt tool_versions[backend] = %q, want %q", got, ProducerBackend)
	}
}
