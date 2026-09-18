//go:build security_poc

package cli

// Wave G adversarial security PoCs (cli package).
//
// G1c The grouped approval prompt — the ONLY surface where a human
//
//	decides what an approved action may do — renders argv, tool,
//	inputs, outputs, network and the shell warning, but NOT the env
//	allowlist and NOT the working root. Foundation §7.3: "the UI must
//	show newly introduced installation scripts or broader access" —
//	an env_allow key (up to and including secret-bearing process env
//	keys like EBB_VAULT_PASSWORD) and a redirected working root are
//	invisible at trust time.
//
// A PoC test that FAILS prints "G1c CONFIRMED".

import (
	"context"
	"strings"
	"testing"

	"ebb/internal/actions"
	"ebb/internal/restore"
)

func TestPoCApprovalPromptOmitsEnvAllowlistAndWorkingRoot(t *testing.T) {
	pending := []restore.PendingApproval{{
		Def: actions.Definition{
			ID:          "deps",
			Argv:        []string{"make", "install"},
			WorkingRoot: "attacker-shipped-subdir",
			Inputs:      []string{"package.json"},
			Outputs:     []string{"build"},
			EnvAllow:    []string{"EBB_VAULT_PASSWORD"},
			Network:     actions.NetworkAllowed,
			Timeout:     0,
		},
		Tool:         actions.ToolIdentity{Name: "make", ResolvedPath: `C:\tools\make.exe`, SHA256: "cafebabe1234"},
		InputDigests: map[string]string{"package.json": "abcd"},
		Cause:        &actions.ErrApprovalRequired{ActionID: "deps"},
	}}
	_ = context.Background()
	text := approvalPromptText(pending)
	if !strings.Contains(text, "EBB_VAULT_PASSWORD") || !strings.Contains(text, "attacker-shipped-subdir") {
		t.Fatalf("G1c CONFIRMED: the approval prompt never shows the env allowlist (here carrying the "+
			"secret-bearing process key EBB_VAULT_PASSWORD) or the working root (%q) — the user approves "+
			"blind on exactly the two fields whose drift the approval identity also fails to pin (G1/G1b). "+
			"Prompt text was:\n%s", "attacker-shipped-subdir", text)
	}
}
