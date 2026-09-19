package actions_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ebb/internal/actions"
)

// baseAction is the resolved triple (definition, tool, digests) the drift
// matrix starts from.
type baseAction struct {
	def     actions.Definition
	tool    actions.ToolIdentity
	digests map[string]string
}

func newBaseAction() baseAction {
	def := validDef()
	def.Argv = []string{"pnpm", "install", "--frozen-lockfile"}
	tool := actions.ToolIdentity{
		Name:         "pnpm",
		ResolvedPath: "C:/Tools/pnpm.exe",
		SHA256:       strings64("aa"),
	}
	digests := map[string]string{
		"package.json":   strings64("01"),
		"pnpm-lock.yaml": strings64("02"),
	}
	return baseAction{def: def, tool: tool, digests: digests}
}

// approvalFor builds the approval that exactly covers b (including the
// §7.3 working root and output ownership). The digest map is deep-copied
// so later mutations of b cannot alias into the approval.
func approvalFor(b baseAction) *actions.Approval {
	digests := make(map[string]string, len(b.digests))
	for k, v := range b.digests {
		digests[k] = v
	}
	return &actions.Approval{
		ActionID:     b.def.ID,
		ArgvDigest:   actions.ArgvDigest(b.def.Argv),
		Tool:         b.tool,
		WorkingRoot:  b.def.WorkingRoot,
		Outputs:      actions.CanonicalOutputs(b.def.Outputs),
		InputDigests: digests,
		EnvAllow:     actions.CanonicalEnvAllow(b.def.EnvAllow),
		Network:      b.def.Network,
		ApprovedBy:   "test-user",
		ApprovedAt:   time.Now().UTC().Format(time.RFC3339),
	}
}

func TestApprovalMatchesExact(t *testing.T) {
	b := newBaseAction()
	if stale := actions.ApprovalMatches(approvalFor(b), b.def, b.tool, b.digests); stale != nil {
		t.Fatalf("exact match reported stale: %v", stale)
	}
}

// TestApprovalMatchesDriftMatrix proves each security-relevant field
// individually causes a stale approval with that field named in the diff.
func TestApprovalMatchesDriftMatrix(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(b *baseAction)
		wantDiff string
	}{
		{
			name:     "action id",
			mutate:   func(b *baseAction) { b.def.ID = "other-action" },
			wantDiff: `action id: approved "node-deps", current "other-action"`,
		},
		{
			name:     "argv",
			mutate:   func(b *baseAction) { b.def.Argv = []string{"pnpm", "install"} },
			wantDiff: "argv digest:",
		},
		{
			name:     "tool path",
			mutate:   func(b *baseAction) { b.tool.ResolvedPath = "D:/Elsewhere/pnpm.exe" },
			wantDiff: `tool path: approved "C:/Tools/pnpm.exe"`,
		},
		{
			name:     "tool sha",
			mutate:   func(b *baseAction) { b.tool.SHA256 = strings64("ff") },
			wantDiff: "tool sha256:",
		},
		{
			// G1b regression: the working root is approval-authorized
			// state (Foundation §7.3).
			name:     "working root",
			mutate:   func(b *baseAction) { b.def.WorkingRoot = "attacker-shipped-dir" },
			wantDiff: `working root: approved "", current "attacker-shipped-dir"`,
		},
		{
			// G1 regression: drifted Outputs widen the F36 exclusion set;
			// the drift must surface as a stale approval.
			name:     "outputs widened",
			mutate:   func(b *baseAction) { b.def.Outputs = append(b.def.Outputs, "notes") },
			wantDiff: `outputs: approved [node_modules], current [node_modules notes]`,
		},
		{
			name:     "input digest",
			mutate:   func(b *baseAction) { b.digests["package.json"] = strings64("99") },
			wantDiff: `input "package.json": digest changed`,
		},
		{
			name: "input added since approval",
			mutate: func(b *baseAction) {
				b.def.Inputs = append(b.def.Inputs, "extra.lock")
				b.digests["extra.lock"] = strings64("03")
			},
			wantDiff: `input "extra.lock": present now but not covered by the approval`,
		},
		{
			name: "input dropped from definition",
			mutate: func(b *baseAction) {
				b.def.Inputs = b.def.Inputs[:1]
				delete(b.digests, "pnpm-lock.yaml")
			},
			wantDiff: `input "pnpm-lock.yaml": approved but no longer declared`,
		},
		{
			name:     "env allowlist",
			mutate:   func(b *baseAction) { b.def.EnvAllow = []string{"NODE_ENV", "NPM_CONFIG"} },
			wantDiff: "env allowlist:",
		},
		{
			name:     "network",
			mutate:   func(b *baseAction) { b.def.Network = actions.NetworkOfflineArtifacts },
			wantDiff: "network:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := newBaseAction()
			ap := approvalFor(b)
			tc.mutate(&b)
			stale := actions.ApprovalMatches(ap, b.def, b.tool, b.digests)
			if stale == nil {
				t.Fatal("expected stale approval, got match")
			}
			if len(stale.Diff) != 1 {
				t.Fatalf("expected exactly one diff line, got %d: %v", len(stale.Diff), stale.Diff)
			}
			if !strings.Contains(stale.Diff[0], tc.wantDiff) {
				t.Fatalf("diff %q does not contain %q", stale.Diff[0], tc.wantDiff)
			}
			// The typed error must be observable through errors.As.
			var typed *actions.ErrApprovalStale
			if !errors.As(error(stale), &typed) {
				t.Fatal("diff error does not assert as *actions.ErrApprovalStale")
			}
		})
	}
}

func TestApprovalMatchesNilApproval(t *testing.T) {
	b := newBaseAction()
	stale := actions.ApprovalMatches(nil, b.def, b.tool, b.digests)
	if stale == nil || !strings.Contains(stale.Error(), "approval missing") {
		t.Fatalf("nil approval must be stale, got: %v", stale)
	}
}

func TestApprovalMatchesEnvSetOrderInsensitive(t *testing.T) {
	b := newBaseAction()
	ap := approvalFor(b)
	b.def.EnvAllow = []string{"NODE_ENV"} // same set, CanonicalEnvAllow sorted it
	if stale := actions.ApprovalMatches(ap, b.def, b.tool, b.digests); stale != nil {
		t.Fatalf("env set equality must ignore order: %v", stale)
	}
}

func TestVerifyInputDigests(t *testing.T) {
	approved := map[string]string{"a.lock": strings64("a1"), "b.lock": strings64("b1")}
	if err := actions.VerifyInputDigests(approved, map[string]string{"a.lock": strings64("a1"), "b.lock": strings64("b1")}); err != nil {
		t.Fatalf("matching digests must verify, got: %v", err)
	}
	err := actions.VerifyInputDigests(approved, map[string]string{"a.lock": strings64("a1"), "b.lock": strings64("XX")})
	var typed *actions.ErrInputChanged
	if !errors.As(err, &typed) {
		t.Fatalf("expected *actions.ErrInputChanged, got: %v", err)
	}
	if typed.Path != "b.lock" || typed.ActualDigest != strings64("XX") {
		t.Fatalf("wrong drift detail: %+v", typed)
	}
	err = actions.VerifyInputDigests(approved, map[string]string{"a.lock": strings64("a1")})
	if !errors.As(err, &typed) || typed.ActualDigest != "(absent)" {
		t.Fatalf("expected absent-input drift, got: %v", err)
	}
}

func TestArgvDigestFraming(t *testing.T) {
	if actions.ArgvDigest([]string{"a", "b"}) == actions.ArgvDigest([]string{"ab"}) {
		t.Error("length-prefixed framing must distinguish [a b] from [ab]")
	}
	if actions.ArgvDigest([]string{"a", "b"}) == actions.ArgvDigest([]string{"b", "a"}) {
		t.Error("argument order must matter")
	}
	if actions.ArgvDigest([]string{"pnpm", "install"}) != actions.ArgvDigest([]string{"pnpm", "install"}) {
		t.Error("identical argv must digest identically")
	}
	if len(actions.ArgvDigest([]string{"x"})) != 64 {
		t.Errorf("digest must be 64 hex chars, got %d", len(actions.ArgvDigest([]string{"x"})))
	}
}

func TestDigestFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "input.txt")
	content := []byte("ebb test input bytes")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	got, err := actions.DigestFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("DigestFile = %s, want %s", got, hex.EncodeToString(sum[:]))
	}
	if _, err := actions.DigestFile(filepath.Join(dir, "absent.txt")); err == nil {
		t.Error("digesting a missing file must fail")
	}
}

func TestTypedErrorStrings(t *testing.T) {
	checks := []struct {
		err  error
		want string
	}{
		{&actions.ErrApprovalRequired{ActionID: "x"}, `no local approval for action "x"`},
		{&actions.ErrApprovalStale{Diff: []string{"argv digest: changed", "network: changed"}}, "approval stale"},
		{&actions.ErrOutputMissing{Outputs: []string{"a", "b"}}, `missing after execution: a, b`},
		{&actions.ErrTimeout{ActionID: "x", Timeout: time.Second}, `action "x" exceeded its 1s timeout`},
		{&actions.ErrInputMissing{Path: "in.txt", Err: os.ErrNotExist}, `input "in.txt" is missing`},
	}
	for _, c := range checks {
		if !strings.Contains(c.err.Error(), c.want) {
			t.Errorf("error %q does not contain %q", c.err.Error(), c.want)
		}
	}
	// ErrInputMissing must unwrap to its cause.
	var em *actions.ErrInputMissing
	if !errors.As(errors.Join(&actions.ErrInputMissing{Path: "p", Err: os.ErrNotExist}), &em) || !errors.Is(em, os.ErrNotExist) {
		t.Error("ErrInputMissing must wrap and unwrap its cause")
	}
}

// strings64 builds a fake hex digest of n distinct byte values repeated
// to 64 chars, keeping matrix cases readable.
func strings64(seed string) string {
	out := make([]byte, 0, 64)
	for len(out) < 64 {
		out = append(out, seed[0])
	}
	for i := range out {
		out[i] = "0123456789abcdef"[(int(seed[0])+i)%16]
	}
	return string(out)
}
