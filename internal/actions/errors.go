package actions

import (
	"fmt"
	"strings"
	"time"
)

// ErrApprovalRequired reports that no local approval exists for the
// action; execution is refused and nothing runs (Foundation §7.3).
type ErrApprovalRequired struct {
	ActionID string
}

func (e *ErrApprovalRequired) Error() string {
	return fmt.Sprintf("actions: no local approval for action %q; execution refused", e.ActionID)
}

// ErrApprovalStale reports that a recorded approval no longer matches the
// resolved action. Diff names every drifted field precisely (Foundation
// §7.3: approval changes when its security-relevant inputs change).
type ErrApprovalStale struct {
	Diff []string
}

func (e *ErrApprovalStale) Error() string {
	return "actions: approval stale, security-relevant inputs changed: " + strings.Join(e.Diff, "; ")
}

// ErrInputChanged reports that a declared input's digest differs from
// the digest pinned by an approval or snapshot (Foundation §7.3: inputs
// are pinned so a restore cannot use today's lockfile with yesterday's
// payload).
type ErrInputChanged struct {
	Path           string
	ApprovedDigest string
	ActualDigest   string
}

func (e *ErrInputChanged) Error() string {
	return fmt.Sprintf("actions: input %q changed since approval (approved %s, actual %s)",
		e.Path, e.ApprovedDigest, e.ActualDigest)
}

// ErrInputMissing reports a declared input that does not exist under the
// workspace root; detected before any process is spawned.
type ErrInputMissing struct {
	Path string
	Err  error
}

func (e *ErrInputMissing) Error() string {
	return fmt.Sprintf("actions: declared input %q is missing: %v", e.Path, e.Err)
}

func (e *ErrInputMissing) Unwrap() error { return e.Err }

// ErrOutputMissing lists declared outputs that do not exist after the
// action ran.
type ErrOutputMissing struct {
	Outputs []string
}

func (e *ErrOutputMissing) Error() string {
	return "actions: declared outputs missing after execution: " + strings.Join(e.Outputs, ", ")
}

// ErrTimeout reports that the action exceeded its declared timeout and
// was killed. Only the direct child process is killed in v1 (documented
// limitation; see Runner.Run).
type ErrTimeout struct {
	ActionID string
	Timeout  time.Duration
}

func (e *ErrTimeout) Error() string {
	return fmt.Sprintf("actions: action %q exceeded its %s timeout and was killed", e.ActionID, e.Timeout)
}

// secretEnvKeys is the documented denylist of Ebb's own secret-bearing
// environment names (Foundation §13.1: secrets never reach command
// arguments, logs, or child process environments). An action whose env
// allowlist asks for any of these keys is definitionally unapprovable:
// no approval may ever be recorded for it, it is never displayed as a
// pending yes/no choice, and Definition.Validate refuses it outright —
// the value would flow from the vault-unlock mechanism straight into an
// approved arbitrary command's environment (Wave G review finding G1c).
var secretEnvKeys = []string{
	"EBB_VAULT_PASSWORD", // the vault unlock secret (vault passfile mechanism)
}

// EnvKeyDenylisted reports whether key matches one of Ebb's own
// secret-bearing environment names (platform env-name matching rules:
// case-insensitive on Windows).
func EnvKeyDenylisted(key string) bool {
	for _, secret := range secretEnvKeys {
		if envKeyMatches(key, secret) {
			return true
		}
	}
	return false
}

// ErrEnvDenylisted reports that an action's env allowlist asks for one
// of Ebb's own secret-bearing environment keys. Such an action is
// definitionally unapprovable: the refusal happens at validation, before
// any prompt, approval record, or execution (never a yes/no question).
type ErrEnvDenylisted struct {
	ActionID string
	Key      string
}

func (e *ErrEnvDenylisted) Error() string {
	return fmt.Sprintf(
		"actions: action %q asks for the secret-bearing environment key %q in its env allowlist; an action requesting Ebb's own secrets is definitionally unapprovable — fix the action definition",
		e.ActionID, e.Key)
}
