// session.go is the Wave E state bridge: the one place the CLI opens
// Ebb's per-user state (config dir + catalog + snapshot store + vault
// registry) and hands a resolved vault to the lifecycle/restore
// coordinators through vault.WithPassfile (Foundation §13.1: the vault
// password reaches the backend only via an ephemeral passfile, never
// argv, never a variable this package would hold).

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0Cymantek0/ebb/internal/catalog"
	"github.com/0Cymantek0/ebb/internal/domain"
	"github.com/0Cymantek0/ebb/internal/lifecycle"
	"github.com/0Cymantek0/ebb/internal/policy"
	"github.com/0Cymantek0/ebb/internal/vault"
)

// session is one command's opened durable state.
type session struct {
	deps   Deps
	cfgDir string
	cat    *catalog.Catalog
	store  domain.SnapshotStore
	// closeStore releases the store's private resources (restic cache
	// dir); nil-safe via closeSession.
	closeStore func()
}

// openSession resolves the state dir, opens the catalog and constructs
// the snapshot store. It does NOT require a registered vault — commands
// that need one call session.vault() afterwards (so `ebb status`, a pure
// catalog view, works before any enrollment).
func openSession(deps Deps) (*session, error) {
	if deps.StateDir == nil {
		return nil, usageError(fmt.Errorf("state dir %w", ErrNotIntegrated))
	}
	cfgDir, err := deps.StateDir()
	if err != nil {
		return nil, blockedError(fmt.Errorf("ebb state directory: %v", err))
	}
	if deps.OpenCatalog == nil {
		return nil, usageError(fmt.Errorf("catalog %w", ErrNotIntegrated))
	}
	cat, err := deps.OpenCatalog(filepath.Join(cfgDir, vault.CatalogFile))
	if err != nil {
		return nil, blockedError(fmt.Errorf("open catalog: %v", err))
	}
	if deps.NewStore == nil {
		cat.Close()
		return nil, usageError(fmt.Errorf("snapshot store %w", ErrNotIntegrated))
	}
	store, closeStore, err := deps.NewStore()
	if err != nil {
		cat.Close()
		var ce *cliError
		if errors.As(err, &ce) {
			// The seam already classified (e.g. missing restic binary
			// is provider-unavailable, not a generic block).
			return nil, ce
		}
		return nil, blockedError(fmt.Errorf("snapshot store: %v", err))
	}
	return &session{deps: deps, cfgDir: cfgDir, cat: cat, store: store, closeStore: closeStore}, nil
}

// close releases the catalog handle and the store's private resources.
// Safe to call on a nil session.
func (s *session) close() {
	if s == nil {
		return
	}
	if s.closeStore != nil {
		s.closeStore()
	}
	_ = s.cat.Close()
}

// registry returns the vault registry in the state dir.
func (s *session) registry() *vault.Registry {
	return vault.New(filepath.Join(s.cfgDir, vault.RegistryFile))
}

// catalogPath is the session catalog's file location (report wording).
func (s *session) catalogPath() string {
	return filepath.Join(s.cfgDir, vault.CatalogFile)
}

// approvalsFile is the durable local approval store's document name in
// the state dir (approvalstore backs it; Foundation §7.3 local trust
// never transfers).
const approvalsFile = "approvals.json"

// approvalsPath returns the approval store's location for this session.
func (s *session) approvalsPath() string {
	return filepath.Join(s.cfgDir, approvalsFile)
}

// defaultVault returns the registry's default vault, or a §5.5-worded
// vault blocker (exit 7) when none is registered.
func (s *session) defaultVault() (*vault.Vault, error) {
	v, err := s.registry().Default()
	if err != nil {
		return nil, vaultError(fmt.Errorf("%s: no default vault is registered in %s; capture, park, trim, open and recover all need one. Safe action: run `ebb init` to enroll a vault (source: %v)",
			CodeNoVault, s.cfgDir, err))
	}
	return v, nil
}

// withVaultPassfile resolves the default vault's unlock secret and runs
// fn with the ephemeral passfile path (vault.WithPassfile owns the
// create/remove contract; Foundation §13.1). Password-source failures
// surface with the §5.5 vault wording so commands map them to exit 7.
func (s *session) withVaultPassfile(ctx context.Context, fn func(repoDir, passfile string) error) error {
	v, err := s.defaultVault()
	if err != nil {
		return err
	}
	return s.withVaultPassfileOf(ctx, v, fn)
}

// withVaultPassfileNonInteractive mirrors withVaultPassfile for
// request-handler contexts (the web control center's facets): the same
// default-vault resolution and the same ephemeral passfile contract,
// but the unlock secret is resolved through
// vault.WithPassfileNonInteractive — env or OS keyring ONLY — so a
// handler can never block on the invisible terminal prompt that
// Password's last rung would open on a TTY stdin (wave-4 K3: a lazy
// prompt inside /api/tree froze the first request). When no
// non-interactive source holds the secret, the failure is the §5.5
// vault blocker (exit-7 family) naming the two fixes a background read
// can use: set EBB_VAULT_PASSWORD or store the vault password in the
// OS keyring. It deliberately does NOT replace withVaultPassfile:
// interactive commands keep their prompt.
func (s *session) withVaultPassfileNonInteractive(ctx context.Context, fn func(repoDir, passfile string) error) error {
	v, err := s.defaultVault()
	if err != nil {
		return err
	}
	err = vault.WithPassfileNonInteractive(v.ID, func(passfilePath string) error {
		return fn(v.RepoDir, passfilePath)
	})
	if err != nil {
		var noSource *vault.NoSourceError
		if errors.As(err, &noSource) {
			// %w (not %v) keeps the typed cause reachable through the
			// §5.5 wrap, so callers can distinguish this refusal from
			// store failures without matching message text.
			return vaultError(fmt.Errorf("%s: vault %s (%s) is locked and a background read cannot unlock it: %w. Safe action: set %s or store the vault password in the OS keyring (via `ebb init`) — the web control center never prompts a terminal",
				CodeUnlockRejected, v.Name, v.ID, noSource, vault.EnvPassword))
		}
		return err
	}
	return nil
}

// resolveVault resolves a vault by registry id or name (the same
// resolution `ebb forget`'s session machinery uses for the default; gc
// takes an explicit <vault> argument). An unknown name is a usage-class
// argument mistake (exit 2), mirroring status/open unknown-name wording.
func (s *session) resolveVault(idOrName string) (*vault.Vault, error) {
	v, err := s.registry().Get(idOrName)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return nil, usageError(fmt.Errorf("no vault named %q is registered (%s); run `ebb doctor` to inspect the registry",
				idOrName, gcVaultNamesHint(s.registry())))
		}
		return nil, blockedError(fmt.Errorf("resolve vault %q: %v", idOrName, err))
	}
	return v, nil
}

// withVaultPassfileOf is withVaultPassfile for one explicitly resolved
// vault (gc targets a named vault, not necessarily the default).
func (s *session) withVaultPassfileOf(ctx context.Context, v *vault.Vault, fn func(repoDir, passfile string) error) error {
	err := vault.WithPassfile(v.ID, func(passfilePath string) error {
		return fn(v.RepoDir, passfilePath)
	})
	if err != nil {
		var noSource *vault.NoSourceError
		if errors.As(err, &noSource) {
			return vaultError(fmt.Errorf("%s: vault %s (%s) could not be unlocked: %v. Safe action: set %s, store the password in the OS credential store via `ebb init`, or run in a terminal to be prompted",
				CodeUnlockRejected, v.Name, v.ID, err, vault.EnvPassword))
		}
		return err
	}
	return nil
}

// lifecycleVaultRef adapts withVaultPassfile's strings to the lifecycle
// VaultRef shape.
func lifecycleVaultRef(repoDir, passfile string) lifecycle.VaultRef {
	return lifecycle.VaultRef{RepoDir: repoDir, Passfile: passfile}
}

// newLifecycle builds the lifecycle coordinator over this session. The
// returned error is already a cliError (usage-class when the seam is
// unwired; blocked-class on construction failure).
func (s *session) newLifecycle(probe domain.PlatformProbe) (*lifecycle.Coordinator, error) {
	if s.deps.NewLifecycle == nil {
		return nil, usageError(fmt.Errorf("lifecycle coordinator %w", ErrNotIntegrated))
	}
	c, err := s.deps.NewLifecycle(lifecycle.Dependencies{
		Store: s.store,
		Cat:   s.cat,
		Probe: probe,
	})
	if err != nil {
		return nil, blockedError(err)
	}
	return c, nil
}

// resolveWorkspaceID implements the CLI-owned workspace-name binding
// documented on lifecycle.CaptureOptions: re-capturing the same root
// under the same name rebinds the SAME workspace id (stable identity
// across captures). Match order: exact name AND recorded root path; then
// exact name AND live status — but only while the live row's recorded
// root matches the capture root (see resolveWorkspaceIDRefusing);
// otherwise a fresh workspace is created (empty id).
//
// The signature cannot surface a refusal (every capture command feeds
// the result straight into CaptureOptions), so a refused match degrades
// to "" here: the capture enrolls a NEW workspace row and the old row's
// recorded root is never rewritten. Wave 5 E12's silent identity rebind
// is therefore unreachable through this wrapper. The capture path
// itself (openCaptureCommand) resolves STRICTLY via
// resolveWorkspaceIDRefusing and fails the command with the blocked
// error; only the post-operation receipt lines still use this lenient
// wrapper, where the row always resolves by name+root already.
func (s *session) resolveWorkspaceID(name, rootAbs string) domain.WorkspaceID {
	id, _ := s.resolveWorkspaceIDRefusing(name, rootAbs)
	return id
}

// resolveWorkspaceIDRefusing is resolveWorkspaceID with the Wave 5 E12
// refusal: the name-only fallback NEVER adopts a live workspace whose
// recorded root differs from the capture root. That adoption is what let
// lifecycle.beginOperation silently rewrite the old row's RootPath —
// identity theft: one project's history re-pointed at a different
// directory because both were named the same. Same-root recapture stays
// allowed (the legitimate flow). The refusal is a blocked error naming
// both paths and demanding either a new workspace for the new path or an
// explicit workspace id.
func (s *session) resolveWorkspaceIDRefusing(name, rootAbs string) (domain.WorkspaceID, error) {
	list, err := s.cat.ListWorkspaces()
	if err != nil {
		return "", blockedError(fmt.Errorf("list workspaces: %v", err))
	}
	var byLiveName domain.WorkspaceID
	var liveRow catalog.Workspace
	for _, w := range list {
		if w.Name != name {
			continue
		}
		if w.RootPath != "" && filepath.Clean(w.RootPath) == filepath.Clean(rootAbs) {
			return w.ID, nil
		}
		if w.Status == catalog.WorkspaceLive && byLiveName == "" {
			byLiveName, liveRow = w.ID, w
		}
	}
	if byLiveName != "" && liveRow.RootPath != "" {
		return "", blockedError(fmt.Errorf(
			"%s: workspace %q (%s) is recorded at root %s, but the capture root is %s; adopting the name-only match would rewrite the recorded root and silently re-point the workspace's history. Safe action: enroll the new path as a new workspace (a distinct workspace name), or pass the explicit workspace id only when you truly mean the recorded one",
			CodeWorkspaceIdentityMismatch, name, byLiveName, liveRow.RootPath, rootAbs))
	}
	return byLiveName, nil
}

// ---- writer assertion (Foundation §17.2) --------------------------------
//
// Unattended destructive operation requires --assert-writers-stopped,
// and --yes never supplies it. On a terminal the interactive
// confirmation is the assertion and records source
// "interactive-confirm"; the flag records "flag:--assert-writers-stopped".

const (
	assertionFlagSource        = "flag:--assert-writers-stopped"
	assertionInteractiveSource = "interactive-confirm"
)

// writerAssertion resolves the recorded writer-assertion source for a
// park, or returns a §5.5-worded blocker (exit 3) when neither an
// explicit assertion nor an interactive confirmation is available.
// assertStopped is the parsed --assert-writers-stopped flag value;
// --yes is accepted for ordinary prompts but deliberately NEVER
// supplies this assertion (Foundation §17.2).
func writerAssertion(deps Deps, assertStopped bool, out io.Writer) (string, error) {
	if assertStopped {
		return assertionFlagSource, nil
	}
	if deps.StdinIsTerminal != nil && deps.StdinIsTerminal() {
		prompt := "workspace will be REMOVED after a verified capture; assert all writers are stopped? type 'yes': "
		if confirmYes(deps, out, prompt) {
			return assertionInteractiveSource, nil
		}
		return "", blockedError(fmt.Errorf("%s: the interactive writer assertion was declined; the workspace was NOT removed. Safe action: stop all processes writing to the workspace and run `ebb park` again",
			CodeWritersUnasserted))
	}
	return "", blockedError(fmt.Errorf("%s: park removes the workspace after a verified capture, and no writer assertion is available (stdin is not a terminal and --assert-writers-stopped was not given; --yes never supplies it). Safe action: verify no process is writing to the workspace, then rerun with --assert-writers-stopped, or run in a terminal and confirm interactively",
		CodeWritersUnasserted))
}

// confirmYes prompts on out and reads one line through the ReadLine
// seam, accepting "yes"/"y" (case-insensitive). The prompt text is
// caller-supplied; this helper owns only the reading.
func confirmYes(deps Deps, out io.Writer, prompt string) bool {
	if deps.ReadLine == nil {
		return false
	}
	fmt.Fprint(out, prompt)
	line, err := deps.ReadLine()
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "yes", "y":
		return true
	default:
		return false
	}
}

// reclaimCommandForDisplay mirrors lifecycle's policy-derived recreate
// argv (internal/lifecycle reclaimCommand): a declared command wins,
// ecosystem adapters carry the pinned per-adapter recipe. Duplicated
// deliberately at the presentation layer — the authoritative value in
// results is lifecycle.TrimResult.ReclaimCommands.
func reclaimCommandForDisplay(g policy.Regenerate) []string {
	if len(g.Command) > 0 {
		return g.Command
	}
	switch g.Adapter {
	case policy.AdapterPNPM:
		return []string{"pnpm", "install", "--frozen-lockfile"}
	case policy.AdapterNPM:
		return []string{"npm", "ci"}
	case policy.AdapterUV:
		return []string{"uv", "sync", "--locked"}
	case policy.AdapterPip:
		return []string{"python", "-m", "pip", "install", "-r", firstInputOf(g)}
	}
	return nil
}

func firstInputOf(g policy.Regenerate) string {
	if len(g.Inputs) > 0 {
		return g.Inputs[0]
	}
	return "requirements.txt"
}

// commandContext returns the cancellable command context from the
// signal seam (tests inject their own; production installs
// SIGINT/SIGTERM notification so a Ctrl+C maps to exit 130 with the
// journal keeping the last durable phase).
func commandContext(deps Deps) (ctx context.Context, stop func()) {
	if deps.NewSignalContext == nil {
		return context.Background(), func() {}
	}
	return deps.NewSignalContext()
}

// statModelessTTY reports whether stdin is a character device (a
// terminal) via os.Stdin.Stat — the production StdinIsTerminal seam.
func statModelessTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
