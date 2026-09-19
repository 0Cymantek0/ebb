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
//
// Import (§15.3) adds: ErrCapsuleUnlock (auth — wrong capsule
// passphrase), ErrNotACapsule / ErrCopyIntegrity (integrity —
// structural failure or an unprovable copy), ErrImportSpace /
// ErrTrimCapsule (blocked — headroom or trim-kind, nothing mutated).
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

// Import-side blocker codes (§15.3; the same single-classification
// authority contract — internal/cli/errors.go maps them, this package
// only names them).
const (
	CodeCapsuleUnlock   = "EBB_E_IMPORT_UNLOCK"    // wrong capsule passphrase (auth)
	CodeNotACapsule     = "EBB_E_NOT_A_CAPSULE"    // container/repository structural failure
	CodeImportSpace     = "EBB_E_IMPORT_SPACE"     // destination headroom block (blocked, nothing extracted)
	CodeTrimCapsule     = "EBB_E_TRIM_CAPSULE"     // trim capsules carry no importable payload (blocked)
	CodeImportIntegrity = "EBB_E_IMPORT_INTEGRITY" // silent copy skip / ambiguous destination discovery
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

// ---- import-side typed failures (§15.3) --------------------------------

// ErrCapsuleUnlock reports that the supplied recovery secret did not
// unlock the repository inside the capsule (the store's auth failure
// re-typed to name the capsule file; the underlying store error is
// preserved for the CLI's exit classification). Nothing was extracted
// into the destination vault. Exit class: auth.
type ErrCapsuleUnlock struct {
	Path string
	Err  error
}

func (e *ErrCapsuleUnlock) Error() string {
	return fmt.Sprintf("%s: capsule: the passphrase did not unlock the repository inside %s (%v); nothing was imported",
		CodeCapsuleUnlock, e.Path, e.Err)
}

// Unwrap preserves the store's auth error (a *domain.StoreError with
// Class StoreErrAuth).
func (e *ErrCapsuleUnlock) Unwrap() error { return e.Err }

// Code returns the stable §5.5 blocker code.
func (e *ErrCapsuleUnlock) Code() string { return CodeCapsuleUnlock }

// ErrNotACapsule reports that the file is not a structurally valid
// capsule: the container failed the §15.1/§15.3 hostile-input
// discipline, or the repository extracted from it did not open/list as
// a fresh capsule repository (exactly one payload + one seal). The
// capsule file itself was never modified; nothing was imported. Exit
// class: integrity.
type ErrNotACapsule struct {
	Path    string
	Details []string
}

func (e *ErrNotACapsule) Error() string {
	return fmt.Sprintf("%s: capsule: %s is not a usable capsule: %s",
		CodeNotACapsule, e.Path, joinDetails(e.Details))
}

// Code returns the stable §5.5 blocker code.
func (e *ErrNotACapsule) Code() string { return CodeNotACapsule }

// ErrImportSpace reports the §15.3 headroom block: free space on the
// destination volume is below what extraction plus the copy into the
// vault can be expected to need. Refused BEFORE extraction with BOTH
// numbers named; import to another configured volume or free space.
// Exit class: blocked.
type ErrImportSpace struct {
	Volume    string // the path the probe measured (the destination repo dir)
	FreeBytes int64
	NeedBytes int64 // 2 × the capsule's declared repository bytes
	RepoBytes int64
}

func (e *ErrImportSpace) Error() string {
	return fmt.Sprintf(
		"%s: capsule: insufficient space on the destination volume of %s: %d bytes free, approximately %d needed (the capsule holds %d bytes of repository; v1 budget space for the extraction plus the copy into the vault). Import to another configured volume or free space first; nothing was extracted",
		CodeImportSpace, e.Volume, e.FreeBytes, e.NeedBytes, e.RepoBytes)
}

// Code returns the stable §5.5 blocker code.
func (e *ErrImportSpace) Code() string { return CodeImportSpace }

// ErrTrimCapsule reports the blocked-by-kind refusal: the capsule's
// payload is a trim capture, whose only authoritative material is a
// removal plan — there is no workspace payload to import (Foundation
// §15.3, §11.4 trim scope). Nothing was imported. Exit class: blocked.
type ErrTrimCapsule struct {
	Path        string
	SnapshotID  string
	WorkspaceID string
}

func (e *ErrTrimCapsule) Error() string {
	return fmt.Sprintf(
		"%s: capsule: %s holds a trim capture (snapshot %s of workspace %s): a trim capsule's authoritative material is a removal plan; there is no workspace payload to import. Nothing was imported",
		CodeTrimCapsule, e.Path, e.SnapshotID, e.WorkspaceID)
}

// Code returns the stable §5.5 blocker code.
func (e *ErrTrimCapsule) Code() string { return CodeTrimCapsule }

// ErrCopyIntegrity reports that the payload copy into the destination
// vault could not be proven: restic copy can skip silently (probe C10 —
// copying a missing id exits 0), and a discovery that finds zero or
// more-than-one new snapshot is ambiguous. The destination may hold an
// unattributable snapshot; the detail lines name the ids honestly.
// Exit class: integrity.
type ErrCopyIntegrity struct {
	Details []string
}

func (e *ErrCopyIntegrity) Error() string {
	return fmt.Sprintf("%s: capsule: the payload copy into the destination vault could not be proven: %s",
		CodeImportIntegrity, joinDetails(e.Details))
}

// Code returns the stable §5.5 blocker code.
func (e *ErrCopyIntegrity) Code() string { return CodeImportIntegrity }
