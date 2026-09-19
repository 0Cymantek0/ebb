package actions

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"ebb/internal/domain"
)

// Approval records one local authorization (Foundation §7.3): the exact
// command, executable identity, working root, input digests, output
// ownership, environment allowlist and network declaration a specific
// user approved at a specific time. A local approval never transfers:
// imported policy or capsules start untrusted regardless of what they
// contain.
type Approval struct {
	// ID identifies this approval record.
	ID domain.ID `json:"id"`
	// ActionID is the stable action (policy regenerate) id.
	ActionID string `json:"action_id"`
	// ArgvDigest is the SHA-256 of the exact argv (ArgvDigest).
	ArgvDigest string `json:"argv_digest"`
	// Tool pins the resolved executable path and its SHA-256.
	Tool ToolIdentity `json:"tool"`
	// WorkingRoot is the approved root-relative working directory (""
	// means the workspace root; Foundation §7.3 pins the working root as
	// approval-authorized state — Wave G review finding G1).
	WorkingRoot string `json:"working_root"`
	// Outputs is the canonical (sorted) declared output ownership
	// (Foundation §7.3 "output ownership"). Whatever the outputs cover is
	// exempt from the F36 protected-content gate, so drift here widens
	// what an approved action may silently change — it must re-prompt.
	Outputs []string `json:"outputs"`
	// InputDigests maps root-relative input path to content SHA-256.
	InputDigests map[string]string `json:"input_digests"`
	// EnvAllow is the canonical (sorted) env key allowlist.
	EnvAllow []string `json:"env_allow"`
	// Network is the approved network declaration.
	Network Network `json:"network"`
	// ApprovedBy names the approving local principal.
	ApprovedBy string `json:"approved_by"`
	// ApprovedAt is the RFC3339 UTC approval timestamp.
	ApprovedAt string `json:"approved_at"`
}

// Approver decides whether a resolved, digested definition still matches
// a recorded local approval. Implementations must never create approvals
// implicitly: a missing approval is ErrApprovalRequired and any drift is
// ErrApprovalStale; recording trust is a separate, explicit act.
type Approver interface {
	Matches(def Definition, resolvedTool ToolIdentity, inputDigests map[string]string) (*Approval, error)
}

// ArgvDigest returns the SHA-256 of the exact argv. Each argument is
// length-prefixed before hashing so the framing is unambiguous (["a","b"]
// and ["ab"] never collide).
func ArgvDigest(argv []string) string {
	h := sha256.New()
	var lenBuf [8]byte
	for _, a := range argv {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(a)))
		h.Write(lenBuf[:])
		h.Write([]byte(a))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// DigestFile returns the streamed SHA-256 of a file's contents.
func DigestFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("actions: open %q for digest: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("actions: digest %q: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ResolveTool resolves name through PATH and returns its identity: the
// name as written, the absolute resolved path, and the streamed SHA-256
// of the executable file. The runner executes exactly this resolved,
// hashed binary.
func ResolveTool(name string) (ToolIdentity, error) {
	p, err := exec.LookPath(name)
	if err != nil {
		return ToolIdentity{}, fmt.Errorf("actions: resolve tool %q: %w", name, err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return ToolIdentity{}, fmt.Errorf("actions: resolve tool %q: %w", name, err)
	}
	digest, err := DigestFile(abs)
	if err != nil {
		return ToolIdentity{}, err
	}
	return ToolIdentity{Name: name, ResolvedPath: abs, SHA256: digest}, nil
}

// ApprovalMatches reports whether approval exactly covers the resolved
// definition. It returns nil on an exact match over ALL of action id +
// argv digest + tool identity (path AND sha256) + working root + output
// ownership + every input digest + env allowlist + network; otherwise it
// returns an *ErrApprovalStale whose Diff names each drifted field. The
// pure comparison lives here so every Approver implementation shares one
// drift definition.
//
// Migration (Wave G review finding G1): records persisted before the
// working-root/output fields existed carry no output ownership. They are
// STALE — never silently honored — with a drift line saying the recorded
// approval does not cover the working root/outputs; one re-approval
// records them. The store is a rebuildable cache of trust decisions, so
// a single honest re-prompt is the whole migration cost.
func ApprovalMatches(approval *Approval, def Definition, tool ToolIdentity, inputDigests map[string]string) *ErrApprovalStale {
	if approval == nil {
		return &ErrApprovalStale{Diff: []string{"approval missing"}}
	}
	var diff []string
	if approval.ActionID != def.ID {
		diff = append(diff, fmt.Sprintf("action id: approved %q, current %q", approval.ActionID, def.ID))
	}
	if want := ArgvDigest(def.Argv); approval.ArgvDigest != want {
		diff = append(diff, fmt.Sprintf("argv digest: approved %s, current %s (the exact command changed)", approval.ArgvDigest, want))
	}
	if approval.Tool.ResolvedPath != tool.ResolvedPath {
		diff = append(diff, fmt.Sprintf("tool path: approved %q, current %q", approval.Tool.ResolvedPath, tool.ResolvedPath))
	}
	if approval.Tool.SHA256 != tool.SHA256 {
		diff = append(diff, fmt.Sprintf("tool sha256: approved %s, current %s (executable bytes changed)", approval.Tool.SHA256, tool.SHA256))
	}

	if len(approval.Outputs) == 0 {
		// A valid definition always declares at least one output root,
		// so empty recorded outputs mean the record predates output
		// pinning: stale, never silently honored (see the migration note).
		diff = append(diff, "working root/outputs not covered by the recorded approval (recorded before these fields were pinned); one re-approval records them")
	} else {
		if approval.WorkingRoot != def.WorkingRoot {
			diff = append(diff, fmt.Sprintf("working root: approved %q, current %q", approval.WorkingRoot, def.WorkingRoot))
		}
		if want := CanonicalOutputs(def.Outputs); !slices.Equal(approval.Outputs, want) {
			diff = append(diff, fmt.Sprintf("outputs: approved %v, current %v (the approved output ownership changed)", approval.Outputs, want))
		}
	}

	declared := make(map[string]bool, len(def.Inputs))
	for _, rel := range def.Inputs {
		declared[rel] = true
		pinned, ok := approval.InputDigests[rel]
		switch {
		case !ok:
			diff = append(diff, fmt.Sprintf("input %q: present now but not covered by the approval", rel))
		case pinned != inputDigests[rel]:
			diff = append(diff, fmt.Sprintf("input %q: digest changed (approved %s, actual %s)", rel, pinned, inputDigests[rel]))
		}
	}
	for _, rel := range slices.Sorted(maps.Keys(approval.InputDigests)) {
		if !declared[rel] {
			diff = append(diff, fmt.Sprintf("input %q: approved but no longer declared", rel))
		}
	}

	if !envSetEqual(approval.EnvAllow, def.EnvAllow) {
		diff = append(diff, fmt.Sprintf("env allowlist: approved %v, current %v",
			CanonicalEnvAllow(approval.EnvAllow), CanonicalEnvAllow(def.EnvAllow)))
	}
	if approval.Network != def.Network {
		diff = append(diff, fmt.Sprintf("network: approved %q, current %q", approval.Network, def.Network))
	}
	if len(diff) == 0 {
		return nil
	}
	return &ErrApprovalStale{Diff: diff}
}

// VerifyInputDigests checks actual input digests against the digests
// pinned by an approval (or a captured snapshot, Foundation §7.3) and
// returns the first *ErrInputChanged (paths visited in sorted order), or
// nil when every pinned digest still matches. Pinned inputs that are
// absent from actual are reported with the sentinel digest "(absent)".
func VerifyInputDigests(approved, actual map[string]string) error {
	for _, p := range slices.Sorted(maps.Keys(approved)) {
		want := approved[p]
		got, ok := actual[p]
		if !ok {
			got = "(absent)"
		}
		if got != want {
			return &ErrInputChanged{Path: p, ApprovedDigest: want, ActualDigest: got}
		}
	}
	return nil
}
