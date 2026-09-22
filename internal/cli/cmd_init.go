// cmdInit implements `ebb init` (Foundation §5.1, §17.1): ensure the
// state directory and catalog, enroll a vault when none is registered
// (interactive: repository path + vault.Enroll's credential machinery),
// verify the default vault unlocks when one exists, and print the
// detected ecosystem groups as SUGGESTIONS only — detection is
// existence-only and never writes an Ebbfile.
//
// Exit contract: 0 ok; 2 usage (bad repo dir state, unwired seams); 3
// blocked (state dir/catalog unavailable, detection root missing); 7
// vault (no vault registered non-interactively, unlock rejected).

package cli

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/0Cymantek0/ebb/internal/vault"
)

// initVault is the registered-vault view of the init result.
type initVault struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	RepoDir string `json:"repo_dir"`
	RepoID  string `json:"repo_id,omitempty"`
	// Enrolled is true when this invocation created the vault.
	Enrolled bool `json:"enrolled"`
	// UnlockVerified reports a completed Unlock check.
	UnlockVerified bool `json:"unlock_verified,omitempty"`
}

// initGroup is one detected ecosystem group (a suggestion, never a
// decision).
type initGroup struct {
	ID          string   `json:"id"`
	Adapter     string   `json:"adapter"`
	Outputs     []string `json:"outputs"`
	Inputs      []string `json:"inputs"`
	ApproxBytes int64    `json:"approx_bytes"`
	Present     bool     `json:"present"`
	Confidence  string   `json:"confidence"`
}

// initDetails is the --json payload of init.
type initDetails struct {
	StateDir string      `json:"state_dir"`
	Catalog  string      `json:"catalog"`
	Vault    *initVault  `json:"vault,omitempty"`
	Groups   []initGroup `json:"groups"`
	Notes    []string    `json:"notes"`
}

func cmdInit(args []string, streams Streams, deps Deps) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(streams.Err)
	jsonOut := fs.Bool("json", false, "emit JSON envelope on stdout")
	rebuildCatalog := fs.Bool("rebuild-catalog", false,
		"rebuild a lost/corrupt catalog from vault discovery (Foundation §11.5: workspaces come back UNBOUND, snapshots pinned; nothing is deleted)")
	forceRebuild := fs.Bool("force-rebuild", false,
		"with --rebuild-catalog: merge-discover over an existing non-empty catalog (duplicates reported; rows never dropped)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return ExitUsage
	}
	root := "."
	if fs.NArg() > 1 {
		fmt.Fprintln(streams.Err, "ebb init: takes at most one path")
		return ExitUsage
	}
	if fs.NArg() == 1 {
		root = fs.Arg(0)
	}
	if *forceRebuild && !*rebuildCatalog {
		fmt.Fprintln(streams.Err, "ebb init: --force-rebuild only applies together with --rebuild-catalog")
		return ExitUsage
	}

	env := newEnvelope("init", "error")
	sess, err := openSession(deps)
	if err != nil {
		return emitFailure(env, *jsonOut, streams, classifyExitCode(err), err.Error())
	}
	defer sess.close()

	// Catalog recovery (F39): the rebuild path replaces the enrollment /
	// detection flow entirely — it resolves the registered vault itself
	// and never touches the working directory.
	if *rebuildCatalog {
		if fs.NArg() == 1 {
			fmt.Fprintf(streams.Err, "note: --rebuild-catalog walks the vault; the path argument %q is unused\n", root)
		}
		return runCatalogRebuild(sess, streams, deps, *jsonOut, *forceRebuild)
	}

	ctx, stop := commandContext(deps)
	defer stop()

	details := initDetails{
		StateDir: sess.cfgDir,
		Catalog:  filepath.Join(sess.cfgDir, vault.CatalogFile),
		Groups:   []initGroup{},
		Notes:    []string{},
	}

	// ---- Vault: enroll when absent, verify when present ----------------
	reg := sess.registry()
	existing, regErr := reg.Default()
	switch {
	case regErr == nil:
		ok, uerr := vault.Unlock(ctx, sess.cfgDir, existing.ID, sess.store)
		if uerr != nil || !ok {
			msg := fmt.Sprintf("%s: default vault %s (%s) could not be unlocked: %v. Safe action: fix the credential source (%s env, OS credential store) or re-enroll in a terminal with `ebb init`",
				CodeUnlockRejected, existing.Name, existing.ID, uerr, vault.EnvPassword)
			return emitFailure(env, *jsonOut, streams, ExitVault, msg)
		}
		details.Vault = &initVault{ID: existing.ID, Name: existing.Name,
			RepoDir: existing.RepoDir, RepoID: existing.RepoID, UnlockVerified: true}

	case errors.Is(regErr, vault.ErrNotFound):
		if deps.StdinIsTerminal == nil || !deps.StdinIsTerminal() {
			msg := fmt.Sprintf("%s: no vault is registered in %s and stdin is not a terminal, so interactive enrollment cannot run. Safe action: run `ebb init` in a terminal (or set %s for CI enrollment)",
				CodeNoVault, sess.cfgDir, vault.EnvPassword)
			return emitFailure(env, *jsonOut, streams, ExitVault, msg)
		}
		defaultRepo := filepath.Join(sess.cfgDir, "vault")
		fmt.Fprintf(streams.Err, "no vault registered. vault repository directory (Enter for %s): ", defaultRepo)
		line, rerr := deps.ReadLine()
		if rerr != nil {
			return emitFailure(env, *jsonOut, streams, ExitUsage,
				fmt.Sprintf("reading repository directory: %v", rerr))
		}
		repoDir := strings.TrimSpace(line)
		if repoDir == "" {
			repoDir = defaultRepo
		}
		v, eerr := vault.Enroll(ctx, sess.cfgDir, "main", repoDir, sess.store, streams.Err)
		if eerr != nil {
			return emitFailure(env, *jsonOut, streams, classifyExitCode(eerr),
				fmt.Sprintf("enroll vault at %s: %v", repoDir, eerr))
		}
		details.Vault = &initVault{ID: v.ID, Name: v.Name, RepoDir: v.RepoDir,
			RepoID: v.RepoID, Enrolled: true}

	default:
		return emitFailure(env, *jsonOut, streams, ExitBlocked,
			fmt.Sprintf("vault registry: %v", regErr))
	}

	// ---- Ecosystem suggestions over the path ---------------------------
	absRoot, aerr := filepath.Abs(root)
	if aerr != nil {
		absRoot = filepath.Clean(root)
	}
	if deps.DetectEcosystem == nil {
		return emitFailure(env, *jsonOut, streams, ExitUsage,
			fmt.Sprintf("ecosystem detection %v", ErrNotIntegrated))
	}
	det, derr := deps.DetectEcosystem(absRoot)
	if derr != nil {
		return emitFailure(env, *jsonOut, streams, ExitBlocked,
			fmt.Sprintf("ecosystem detection over %s: %v", root, derr))
	}
	for _, g := range det.Suggestions {
		details.Groups = append(details.Groups, initGroup{
			ID: g.GroupID, Adapter: g.Adapter,
			Outputs: g.Outputs, Inputs: g.Inputs,
			ApproxBytes: g.ApproxBytes, Present: g.Present,
			Confidence: string(g.Confidence),
		})
	}
	details.Notes = append(details.Notes, det.Notes...)

	env.Outcome = "ok"
	env.Details = details
	emit(env, *jsonOut, streams, renderInitHuman(details, absRoot))
	return ExitOK
}

// renderInitHuman renders the init report for the human stream.
func renderInitHuman(d initDetails, root string) string {
	var b strings.Builder
	line := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	line("ebb state directory: %s\n", d.StateDir)
	line("catalog: %s\n", d.Catalog)
	if d.Vault != nil {
		if d.Vault.Enrolled {
			line("vault enrolled: %s (%s) at %s\n", d.Vault.Name, d.Vault.ID, d.Vault.RepoDir)
		} else {
			line("vault: %s (%s) at %s — unlock verified\n", d.Vault.Name, d.Vault.ID, d.Vault.RepoDir)
		}
	}
	if len(d.Groups) == 0 {
		line("detected groups at %s: none\n", root)
	} else {
		line("detected groups at %s (suggestions only; no Ebbfile was written):\n", root)
		for _, g := range d.Groups {
			state := "present"
			if !g.Present {
				state = "absent"
			}
			line("  %s [%s] outputs: %s — %s, %s confidence\n",
				g.ID, g.Adapter, strings.Join(g.Outputs, ", "), state, g.Confidence)
		}
	}
	for _, n := range d.Notes {
		line("note: %s\n", n)
	}
	return b.String()
}
