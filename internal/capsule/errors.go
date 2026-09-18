package capsule

import (
	"errors"
	"fmt"
)

// errors.go — the capsule package's typed failures. The CLI layer maps
// them onto Foundation §17.5 exit codes (internal/cli/errors.go is the
// single classification authority):
//
//	ErrInvalidParams / ErrOutputOccupied / ErrPartialExists → 2/3
//	ErrVerification (any check)                            → 4
//	underlying domain.StoreError keeps its own class        → 4/7/2
type errInvalidParams struct{ Detail string }

func (e *errInvalidParams) Error() string {
	return "capsule: invalid export parameters: " + e.Detail
}

// ErrInvalidParams reports caller-side mistakes made before anything was
// created (bad output path, missing evidence, unwired store seam).
// Exit 2.
func ErrInvalidParams(detail string) error { return &errInvalidParams{Detail: detail} }

// IsInvalidParams reports whether err is the params error.
func IsInvalidParams(err error) bool {
	var e *errInvalidParams
	return errors.As(err, &e)
}

// Stable capsule blocker codes (the §5.5 code half; the CLI picks them
// up through the Code() interface like restore's typed errors).
const (
	CodeOutputOccupied = "EBB_E_OUTPUT_OCCUPIED"
	CodePartialStale   = "EBB_E_EXPORT_PARTIAL_STALE"
	CodeExportVerify   = "EBB_E_EXPORT_VERIFY"
)

// ErrOutputOccupied reports that the final output path already exists;
// a capsule is published by no-clobber rename and never overwrites.
// Exit 3.
type ErrOutputOccupied struct{ Path string }

func (e *ErrOutputOccupied) Error() string {
	return fmt.Sprintf("%s: capsule: output path %s already exists; a capsule is never overwritten (no-clobber publication)", CodeOutputOccupied, e.Path)
}

// Code returns the stable §5.5 blocker code.
func (e *ErrOutputOccupied) Code() string { return CodeOutputOccupied }

// ErrPartialExists reports that the recognizable partial artifact of an
// earlier interrupted export still occupies the output's partial path.
// v1 refuses rather than resuming or appending (documented decision);
// the safe action is to inspect and explicitly delete the stale partial.
// Exit 3.
type ErrPartialExists struct{ Path string }

func (e *ErrPartialExists) Error() string {
	return fmt.Sprintf(
		"%s: capsule: a partial export artifact %s already exists (a previous export was interrupted before it could clean up). v1 refuses to resume or append; the source snapshot is intact. Safe action: inspect the file (it contains an ebb-export.json manifest naming its operation) and delete it explicitly, then rerun the export",
		CodePartialStale, e.Path)
}

// Code returns the stable §5.5 blocker code.
func (e *ErrPartialExists) Code() string { return CodePartialStale }

// ErrVerification reports a failed named check of the export's own
// verification chain (destination coverage, content readback, container
// integrity, extracted-repository readback, encryption independence).
// Checks are named per Foundation §16.4 — never a free-form "safe=false".
// Exit 4; nothing was published.
type ErrVerification struct {
	Check   string
	Details []string
}

func (e *ErrVerification) Error() string {
	return fmt.Sprintf("%s: capsule: verification check %q failed: %s", CodeExportVerify, e.Check, joinDetails(e.Details))
}

// Code returns the stable §5.5 code for a failed export check.
func (e *ErrVerification) Code() string { return CodeExportVerify }

// Checks returns the failed check names (the CLI shows them as
// conditions).
func (e *ErrVerification) Checks() []string { return []string{e.Check} }

func joinDetails(d []string) string {
	out := ""
	for i, s := range d {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

// IsVerification reports whether err is a failed export check.
func IsVerification(err error) bool {
	var e *ErrVerification
	return errors.As(err, &e)
}
