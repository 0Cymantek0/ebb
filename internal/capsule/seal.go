package capsule

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// seal.go is the DESTINATION seal of Foundation §16.4/§15.2: the
// receipt written into the capsule's fresh repository AFTER the copied
// payload has been verified there. It is deliberately NOT a verbatim
// copy of the source vault's seal — that receipt names the source
// repository id and the source payload backend id, neither of which
// exists inside the capsule (R38/F43: "destination seal refers to
// destination IDs, not stale source IDs"). Instead it records the
// destination repository/payload ids plus the §16.4 replication block:
// the source LOGICAL identity and the source manifest digest, so a
// future reader can prove content-level identity before accepting the
// link.
//
// The document shape mirrors the lifecycle receipt (schema_version,
// digests, named verification checks, operation id, retention) plus the
// replication block; capsule re-declares the wire form locally as a
// STRICT reader (DisallowUnknownFields) exactly the way internal/restore
// re-declares lifecycle's frozen formats (cross-package contract, not a
// shared struct).

const (
	sealSchemaVersion = 1
	sealKind          = "destination-seal"
	sealDocName       = "receipt.json"
	// sealDirPrefix mirrors lifecycle's seal staging shape so a future
	// `ebb import`/`ebb open <capsule>` can locate the receipt with the
	// same .ebb-seal-<opID> tree-shape rule restore uses today.
	sealDirPrefix = ".ebb-seal-"

	// Named checks recorded on the destination seal (§16.4: a
	// verification result names its checks).
	checkCoverage        = "coverage-complete"
	checkPayloadReadback = "payload-readback-complete"
	checkIndependence    = "independent-encryption-domain"
	checkSealReadback    = "destination-seal-readback-complete"

	sealScope = "capsule-export"
	// ProducerEbb mirrors lifecycle.ProducerEbbVersion (the capsule
	// package cannot import internal/cli for the version constant; the
	// CLI passes its own version via Params.EbbVersion when available).
	ProducerEbb = "ebb capsule v1"
)

// destinationSeal is the §16.4 destination receipt wire form.
type destinationSeal struct {
	SchemaVersion    int              `json:"schema_version"`
	Kind             string           `json:"kind"`
	SnapshotID       string           `json:"snapshot_id"`
	WorkspaceID      string           `json:"workspace_id"`
	Source           sealSourceRef    `json:"source"`
	BackendRepoID    string           `json:"backend_repo_id"`
	PayloadBackendID string           `json:"payload_backend_id"`
	ManifestDigest   string           `json:"manifest_digest"`
	InventoryDigest  string           `json:"inventory_digest"`
	RequiredFeatures []string         `json:"required_features"`
	Verification     sealVerification `json:"verification"`
	OperationID      string           `json:"operation_id"`
	Retention        string           `json:"retention"`
}

// sealSourceRef is the §16.4 replication block: the source logical
// identity and the source digests the reader compares at
// content level before accepting the destination link.
type sealSourceRef struct {
	BackendRepoID     string `json:"backend_repo_id"`
	PayloadBackendID  string `json:"payload_backend_id"`
	LogicalSnapshotID string `json:"logical_snapshot_id"`
	ManifestDigest    string `json:"manifest_digest"`
	InventoryDigest   string `json:"inventory_digest"`
}

type sealVerification struct {
	Checks       []string          `json:"checks"`
	Scope        string            `json:"scope"`
	Time         string            `json:"time"`
	ToolVersions map[string]string `json:"tool_versions"`
}

// buildDestinationSeal assembles the receipt. Checks must be the checks
// ACTUALLY performed before the seal snapshot was written.
func buildDestinationSeal(
	logicalSnapID, wsID, srcRepoID, srcPayloadID string,
	dstRepoID, dstPayloadID string,
	manifestDigest, inventoryDigest string,
	opID string,
	at time.Time,
	checks []string,
	ebbVersion string,
) destinationSeal {
	tools := map[string]string{"ebb-capsule": ProducerEbb}
	if ebbVersion != "" {
		tools["ebb"] = ebbVersion
	}
	return destinationSeal{
		SchemaVersion: sealSchemaVersion,
		Kind:          sealKind,
		SnapshotID:    logicalSnapID,
		WorkspaceID:   wsID,
		Source: sealSourceRef{
			BackendRepoID:     srcRepoID,
			PayloadBackendID:  srcPayloadID,
			LogicalSnapshotID: logicalSnapID,
			ManifestDigest:    manifestDigest,
			InventoryDigest:   inventoryDigest,
		},
		BackendRepoID:    dstRepoID,
		PayloadBackendID: dstPayloadID,
		ManifestDigest:   manifestDigest,
		InventoryDigest:  inventoryDigest,
		RequiredFeatures: []string{},
		Verification: sealVerification{
			Checks: checks, Scope: sealScope,
			Time: at.UTC().Format(time.RFC3339Nano), ToolVersions: tools,
		},
		OperationID: opID,
		Retention:   "pinned", // export never implies forget (§15.2)
	}
}

// marshalSealDoc serializes strictly (the bytes written into the capsule
// repo are the bytes the digest is taken over).
func marshalSealDoc(d destinationSeal) ([]byte, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("capsule: marshal destination seal: %w", err)
	}
	return append(b, '\n'), nil
}

// parseDestinationSeal is the STRICT reader (unknown fields rejected,
// trailing data rejected) used when re-reading the seal from the
// packaged capsule repository.
func parseDestinationSeal(b []byte) (destinationSeal, error) {
	var d destinationSeal
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return destinationSeal{}, fmt.Errorf("capsule: strict destination-seal parse: %w", err)
	}
	if dec.More() {
		return destinationSeal{}, fmt.Errorf("capsule: strict destination-seal parse: trailing data after JSON value")
	}
	if d.SchemaVersion != sealSchemaVersion {
		return destinationSeal{}, fmt.Errorf("capsule: destination seal schema_version %d is unsupported (reader supports %d)", d.SchemaVersion, sealSchemaVersion)
	}
	if d.Kind != sealKind {
		return destinationSeal{}, fmt.Errorf("capsule: destination seal kind %q is not %q", d.Kind, sealKind)
	}
	return d, nil
}
