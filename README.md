# Ebb

Safe, low-effort disk-space reclamation for development workspaces — with recovery you can trust.

Ebb frees space from development projects without making you re-audit every ignored file each time. It preserves what is irreplaceable (source, dirty Git state, notes, `.env`, private assets), omits only what you explicitly declared reconstructible, verifies every retained byte before removing anything, and can put the workspace back later.

```
ebb init          # one-time: register a local encrypted vault (restic)
ebb snapshot .    # capture + verify, change nothing
ebb trim . --groups node-dependencies   # remove approved generated output only
ebb park .        # verified capture, then remove the whole workspace
ebb open renderer # restore it later — files verified against an independent oracle
ebb reclaim . --target 15GiB           # trim first; escalate to park only if needed
ebb forget <snapshot-id>               # deliberately release a recovery copy
ebb verify <snapshot-id>               # re-check seal/documents/coverage (--content for full readback)
ebb status        # what Ebb knows
```

## Status

Pre-release (v0.1.0-dev), actively developed. Windows (native NTFS) is the verified platform; Linux builds and its platform layer are implemented but not yet exercised by native test runs. See **Known limitations** below before trusting any destructive operation.

What works, end to end, verified against the real restic 0.19.1 binary (`internal/lifecycle/e2e_reSTORic_test.go`):

- **Capture** (`snapshot`) — full inventory with SHA-256 digests, encrypted restic backend, exact coverage check, and full content readback of every preserved byte. A capture that fails verification is retained (pinned, marked unsealed) — never silently erased.
- **Park** — capture → seal → revalidate the live source against the sealed inventory (any change invalidates removal) → quarantine rename → per-entry re-verified removal. Crash-safe: interrupted parks resume from durable evidence (`ebb recover`).
- **Trim** — remove only explicitly declared reconstructible groups (e.g. `node_modules`), leaving the workspace live; the removal plan + recipe inputs are captured and sealed first.
- **Open** — restore a parked/captured workspace: seal validated, files materialized to a private staging dir (links excluded from the backend stage and recreated natively — junctions work unprivileged on Windows), verified against the retained inventory as an independent oracle, then published. Nothing unrelated is ever overwritten.
- **Reclaim** — the ordinary "I need space" entry point: plans, executes approved trims, and escalates to a full park only with its own explicit terminal confirmation when the target can't be met otherwise. Exit 8 is an honest shortfall report, never an invitation to weaken policy.
- **Forget / verify** — deliberate, confirmed release of a pinned snapshot (with a last-recovery-copy guard for parked workspaces) and on-demand evidence re-checks.
- **Safety architecture** — removal authority lives in one audited file (AST-enforced tripwire); the scanner verifies directory-handle identities during descent (junction-swap attack detected, not followed); recovery-path evidence is validated against the catalog's seal-time digests (a tampered vault cannot steer deletion — independently reviewed, PoC-backed); Git observation runs a hardened, non-executing recipe; no project code ever runs during inspection; vault passwords live in the OS credential store, never in logs or argv.

## Install / build

Requires Go ≥ 1.27 and restic 0.19.x on PATH (scoop: `scoop install go restic`; winget/choco equivalents work).

```sh
go build -o ebb ./cmd/ebb
go test ./...          # full suite (~4-5 min; the restic acceptance suite auto-skips without restic)
```

State lives in `os.UserConfigDir()/ebb` (Windows: `%AppData%\ebb`): `catalog.db` (SQLite operation journal + snapshot index) and `vaults.json`. Vault data goes wherever you point `ebb init` (default `<cfgdir>/vault`, restic-encrypted).

## Usage notes

- `park` requires a stopped-writers assertion: interactive confirm in a terminal, or `--assert-writers-stopped` for automation. `--yes` never supplies it.
- Policies are optional `Ebbfile.toml` files; without one, everything unknown is preserved (conservative default). Generated-output removal requires an explicit `[[regenerate]]` declaration — a lockfile alone never marks a tree disposable.
- Snapshots stay pinned after open; deliberate release via `ebb forget` is future work (see limitations).

## Documentation

- `Foundation.md` — product intent, safety model, contracts, release gates. Read this first for the "why".
- `Decisions.md` — architecture decision ledger (D001…).
- `Modules.md` — current module map (Mermaid) of the implemented system.
- `Learnings.md` — hard-won platform/backend lessons.

## Known limitations (explicit, not hidden)

- Opening a workspace whose preserved set contains **true symlinks** requires the Windows symlink privilege (Developer Mode / elevation) — junctions (the common case, e.g. pnpm-style `node_modules`) recreate unprivileged. A privilege-blocked open fails BEFORE publishing anything, with a precise typed error naming the blocked entries.
- Rebuild actions after open are reported (exact commands), not executed — `open` stops at files-ready in v1.
- `gc`, `export`, `import` are not yet implemented; `verify --content` is subprocess-per-file (slow on large trees).
- Open security-review P2s (lab/security-review/wave-F/FINDINGS.md F4-F7): restore lacks a seal-digest cross-check against the catalog, a crash window between quarantine rename and CAS commit needs manual reconciliation, the vault/root overlap preflight is lexical, and `recover` auto-resumes blocked walks without writer reconfirmation. All require an attacker who can already write the vault or catalog; all are scheduled work.
- Hardlink relationships, NTFS alternate data streams, sparse flags and ACLs are captured as inventory facts but not restored (documented per-snapshot in the manifest's `not_promised` capabilities).
- Linux: builds clean and the platform layer is implemented, but no native Linux test run has certified it; macOS is unsupported.
- Full §11.4 readback spawns one restic dump per file — capture latency scales with file count (batching is a known optimization; no benchmark baseline exists yet).
