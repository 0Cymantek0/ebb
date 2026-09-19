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
ebb gc <vault>                          # physically reclaim unreferenced vault storage (after forget)
ebb export <snapshot-id> --output f     # independent encrypted capsule for transfer/archival
ebb import <file.ebb>                   # verified recovery of a capsule into a vault
ebb init --rebuild-catalog              # recover the catalog from a surviving vault (F39)
ebb verify <snapshot-id>               # re-check seal/documents/coverage (--content for full readback)
ebb status        # what Ebb knows
```

## Status

Pre-release (v0.1.0-dev), actively developed. Windows (native NTFS) is the verified platform; Linux builds and its platform layer are implemented but not yet exercised by native test runs. See **Known limitations** below before trusting any destructive operation.

What works, end to end, verified against the real restic 0.19.1 binary (`internal/lifecycle/e2e_reSTORic_test.go`):

- **Capture** (`snapshot`) — full inventory with SHA-256 digests, encrypted restic backend, exact coverage check, and full content readback of every preserved byte. A capture that fails verification is retained (pinned, marked unsealed) — never silently erased.
- **Park** — capture → seal → revalidate the live source against the sealed inventory (any change invalidates removal) → quarantine rename → per-entry re-verified removal. Crash-safe: interrupted parks resume from durable evidence (`ebb recover`).
- **Trim** — remove only explicitly declared reconstructible groups (e.g. `node_modules`), leaving the workspace live; the removal plan + recipe inputs are captured and sealed first.
- **Open** — restore a parked/captured workspace: seal validated (and cross-checked against the catalog's seal-time digests — a tampered vault cannot publish forged content), files materialized to a private staging dir (links excluded from the backend stage and recreated natively — junctions work unprivileged on Windows), verified against the retained inventory as an independent oracle, then published. Nothing unrelated is ever overwritten.
- **Rebuild** — after publishing, `open` runs the retained, locally-approved reconstruction actions (e.g. `pnpm install --frozen-lockfile`) at the final destination: exact command definitions are frozen in the snapshot manifest, approvals are recorded once and reused while they match, every attempt is journaled, and protected files are re-verified afterwards (a rebuild that damages preserved content fails loudly — files are never deleted). `--files-only` skips reconstruction; a failed rebuild exits 6 and is resumable (`ebb open --resume`).
- **Reclaim** — the ordinary "I need space" entry point: plans, executes approved trims, and escalates to a full park only with its own explicit terminal confirmation when the target can't be met otherwise. Exit 8 is an honest shortfall report, never an invitation to weaken policy.
- **Forget / gc / verify** — deliberate, confirmed release of a pinned snapshot (last-recovery-copy guard); gc then asks the backend to physically reclaim unreferenced storage, gated on no active operations and verified to never remove retained snapshots; verify re-checks evidence on demand.
- **Export** — a portable, independently-encrypted capsule (fresh restic repo inside a ZIP64 container): copy-verified, destination-resealed, and proven to open only with the newly generated passphrase. The source snapshot stays pinned.
- **Catalog rebuild** — if `catalog.db` is lost, `ebb init --rebuild-catalog` rebuilds workspaces/snapshots from the vault itself (discovered workspaces come back UNBOUND and pinned — never guessed disposable).
- **Safety architecture** — removal authority lives in one audited file (AST-enforced tripwire); the scanner verifies directory-handle identities during descent (junction-swap attack detected, not followed); recovery-path evidence is validated against the catalog's seal-time digests (a tampered vault cannot steer deletion — independently reviewed, PoC-backed); Git observation runs a hardened, non-executing recipe; no project code ever runs during inspection; vault passwords live in the OS credential store, never in logs or argv. The capsule container is read with a hostile-input discipline (traversal, duplicates, NTFS ADS/trailing-dot/device-name aliases all refused; extraction enforces the verified byte budget) — Waves F, G and H/I each had an adversarial review with PoC-backed fixes (`lab/security-review/`).

## Install / build

Requires Go ≥ 1.27 and restic 0.19.x on PATH (scoop: `scoop install go restic`; winget/choco equivalents work).

From source:

```sh
go build -o ebb ./cmd/ebb
go test ./...          # full suite (~4-5 min; the restic acceptance suite auto-skips without restic)
```

`scripts/verify.sh` is the canonical verification gate (gofmt, `go vet`, the full test suite, and a GOOS=linux cross-compile build/vet — everything the project runs before accepting a change):

```sh
bash scripts/verify.sh
```

Release builds (`scripts/release.sh <version>`) cross-compile CGO-free, stripped, version-stamped binaries for windows/amd64, linux/amd64, darwin/amd64 and darwin/arm64 into `dist/<version>/`, with checksummed zip/tar.gz archives and a `SHA256SUMS.txt`. The script refuses a dirty working tree unless `EBB_RELEASE_DIRTY=1` is set:

```sh
scripts/release.sh v0.1.0
```

There is no official distribution channel yet — Ebb is pre-release, and where binaries are published (and whether the pinned restic backend ships alongside them) is still an open decision. Building from source is the supported path today.

State lives in `os.UserConfigDir()/ebb` (Windows: `%AppData%\ebb`): `catalog.db` (SQLite operation journal + snapshot index) and `vaults.json`. Vault data goes wherever you point `ebb init` (default `<cfgdir>/vault`, restic-encrypted).

## Usage notes

- `park` requires a stopped-writers assertion: interactive confirm in a terminal, or `--assert-writers-stopped` for automation. `--yes` never supplies it.
- Policies are optional `Ebbfile.toml` files; without one, everything unknown is preserved (conservative default). Generated-output removal requires an explicit `[[regenerate]]` declaration — a lockfile alone never marks a tree disposable.
- Snapshots stay pinned after open; deliberate release is `ebb forget` (with a last-recovery-copy guard for parked workspaces).

## Documentation

- `Foundation.md` — product intent, safety model, contracts, release gates. Read this first for the "why".
- `Decisions.md` — architecture decision ledger (D001…).
- `Modules.md` — current module map (Mermaid) of the implemented system.
- `Learnings.md` — hard-won platform/backend lessons.
- `docs/BENCHMARKS.md` — measured performance baseline and the harness command (`lab/bench`).

## Known limitations (explicit, not hidden)

- Opening a workspace whose preserved set contains **true symlinks** requires the Windows symlink privilege (Developer Mode / elevation) — junctions (the common case, e.g. pnpm-style `node_modules`) recreate unprivileged. A privilege-blocked open fails BEFORE publishing anything, with a precise typed error naming the blocked entries.
- `ebb import <file.ebb>` is implemented (extract → verify → copy → readback → reseal; `ebb inspect <file.ebb>` shows public metadata, and with EBB_CAPSULE_PASSWORD set runs full verification without registering), but it needs ~2x the capsule payload free on the destination volume; `ebb open <file.ebb> --to <path>` is NOT implemented — open from a capsule is two steps: `import`, then `open <workspace-name>`; imported snapshots stay pinned and their rebuild approvals start EMPTY by design (the first `open` of an imported snapshot re-prompts).
- Rebuild executes approved actions with your privileges — there is no sandbox (Foundation §9.5); the approval prompt shows the exact command, tool hash, inputs and outputs before anything runs.
- Rebuild approvals pin the full authorization surface (exact command, tool hash, inputs, working root, output ownership, env allowlist, network): any drift — including an Ebbfile edit that widens an action's outputs — re-prompts, and an action asking for Ebb's own vault password is refused outright, never prompted. Recovery paths consult the filesystem rather than trusting journal rows (Wave G audit findings G1–G4 all fixed; see lab/security-review/wave-G/FINDINGS.md).
- Hardlink relationships, NTFS alternate data streams, sparse flags and ACLs are captured as inventory facts but not restored (documented per-snapshot in the manifest's `not_promised` capabilities).
- Linux: builds clean and the platform layer is implemented, but no native Linux test run has certified it; macOS is unsupported.
- Full §11.4 readback uses one streaming `restic dump --archive tar` subprocess per tree (measured ~17x faster than the former per-file transport on a small fixture; see `docs/BENCHMARKS.md` for the baseline). Very large single files still dominate readback time by bytes.
