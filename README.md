# Ebb

Safe, low-effort disk-space reclamation for development workspaces — with recovery you can trust.

Ebb frees space from development projects without making you re-audit every ignored file each time. It preserves what is irreplaceable (source, dirty Git state, notes, `.env`, private assets), omits only what you explicitly declared reconstructible, verifies every retained byte before removing anything, and can put the workspace back later.

```
ebb init          # one-time: register a local encrypted vault (restic)
ebb snapshot .    # capture + verify, change nothing
ebb trim . --groups node-dependencies   # remove approved generated output only
ebb park .        # verified capture, then remove the whole workspace
ebb open renderer # restore it later — files verified against an independent oracle
ebb status        # what Ebb knows
```

## Status

Pre-release (v0.1.0-dev), actively developed. Windows (native NTFS) is the verified platform; Linux builds and its platform layer are implemented but not yet exercised by native test runs. See **Known limitations** below before trusting any destructive operation.

What works, end to end, verified against the real restic 0.19.1 binary (`internal/lifecycle/e2e_reSTORic_test.go`):

- **Capture** (`snapshot`) — full inventory with SHA-256 digests, encrypted restic backend, exact coverage check, and full content readback of every preserved byte. A capture that fails verification is retained (pinned, marked unsealed) — never silently erased.
- **Park** — capture → seal → revalidate the live source against the sealed inventory (any change invalidates removal) → quarantine rename → per-entry re-verified removal. Crash-safe: interrupted parks resume from durable evidence (`ebb recover`).
- **Trim** — remove only explicitly declared reconstructible groups (e.g. `node_modules`), leaving the workspace live; the removal plan + recipe inputs are captured and sealed first.
- **Open** — restore a parked/captured workspace: seal validated, files materialized to a private staging dir, verified against the retained inventory as an independent oracle, then published. Nothing unrelated is ever overwritten.
- **Safety architecture** — removal authority lives in one audited file (AST-enforced tripwire); the scanner verifies directory-handle identities during descent (junction-swap attack detected, not followed); Git observation runs a hardened, non-executing recipe; no project code ever runs during inspection; vault passwords live in the OS credential store, never in logs or argv.

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

- **Opening a workspace that contains junctions/symlinks fails on unprivileged Windows** — restic needs `SeCreateSymbolicLinkPrivilege` to materialize reparse points. Park/capture are unaffected (links stored as links, never followed); the failed open leaves everything safe (nothing published, snapshot pinned). Fix planned: recreate links from the retained inventory after restore.
- Rebuild actions after open are reported (exact commands), not executed — `open` stops at files-ready in v1.
- `reclaim`, `forget`, `gc`, `verify`, `export`, `import` are not yet implemented.
- Hardlink relationships, NTFS alternate data streams, sparse flags and ACLs are captured as inventory facts but not restored (documented per-snapshot in the manifest's `not_promised` capabilities).
- Linux: builds clean and the platform layer is implemented, but no native Linux test run has certified it; macOS is unsupported.
- Full §11.4 readback spawns one restic dump per file — capture latency scales with file count (batching is a known optimization).
