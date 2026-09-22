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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/0Cymantek0/ebb/internal/actions"
	"github.com/0Cymantek0/ebb/internal/restore"
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
	// Fixed build (fix holds): the prompt shows the working root and the
	// env allowlist — but a secret-bearing env key (Ebb's own denylist,
	// Foundation §13.1) is NEVER spelled by name; the placeholder says it
	// is unapprovable instead. And such a definition cannot even reach a
	// prompt: validation refuses it outright (ErrEnvDenylisted), so no
	// approval record can ever exist for it.
	if strings.Contains(text, "EBB_VAULT_PASSWORD") {
		t.Fatalf("G1c REGRESSION: the approval prompt spells the secret-bearing env key by name:\n%s", text)
	}
	if !strings.Contains(text, "attacker-shipped-subdir") {
		t.Fatalf("G1c REGRESSION: the approval prompt still hides the working root:\n%s", text)
	}
	if !strings.Contains(text, "secret-bearing env key suppressed") {
		t.Fatalf("G1c REGRESSION: the prompt lists env keys without the suppression marker for denylisted ones:\n%s", text)
	}
	validDef := pending[0].Def
	validDef.Timeout = time.Minute // isolate the denylist from the timeout rule
	var denied *actions.ErrEnvDenylisted
	if err := validDef.Validate(); !errors.As(err, &denied) {
		t.Fatalf("G1c REGRESSION: a definition asking for EBB_VAULT_PASSWORD must fail Validate with ErrEnvDenylisted (never promptable, never approvable), got %v", err)
	}
}
