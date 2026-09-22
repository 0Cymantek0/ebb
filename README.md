# ebb

Disk space for builders.

Ebb reclaims disk space from development workspaces without making you re-audit every ignored file each time. It frees the gigabytes you can reconstruct, keeps what you cannot, and proves the copy is good before anything is removed. Recovery is a first-class operation, not an afterthought.

```
ebb init                              # once: register a local encrypted vault
ebb config add projects_dir ~/dev     # once: tell ebb where your projects live
ebb analyse                           # see every project: size, staleness, what to do
ebb reclaim ~/dev/api                 # free the space (outputs only, source untouched)
```

Windows 11 and Linux. Go + [restic](https://restic.net) underneath. Zero telemetry, zero network calls.

---

## Why ebb

Every developer knows the feeling. Fourteen projects, each with `node_modules`, `target`, `.venv`, `build`. Some untouched for two years. The disk is full and the realistic options are bad:

- Delete `node_modules` by hand. Repeat next week. Hope you never `rm -rf` the wrong window.
- Nuke whole project folders. Lose the uncommitted fix, the `.env`, the note to self.
- Move things to an external drive. Discover the drive three years later, unlabeled.

The fear is justified: `.gitignore` does not mean disposable. Private notes, `.env` files, local datasets, and uncommitted work are routinely ignored by Git and are exactly the things no one can re-download.

Ebb takes the other default. **Preservation is the default.** Nothing is removed unless it is provably reconstructible or provably captured and verified first. Every claim below is enforced in code, not in prose:

- **Preservation-first.** Without explicit declarations, everything unknown is preserved. A lockfile alone never marks a tree disposable. Generated output is only removed when a policy declares the group and how to recreate it.
- **Verified before removed.** A successful backup subprocess exit code is not proof of retained data. Ebb verifies every capture with an exact coverage check plus a full content readback, and `ebb open` verifies restored files against an oracle independent of the encoder.
- **Physical-space accounting.** Ebb reports what the volume actually freed, next to the logical estimate. When the two disagree, you see both.

## The daily loop

Four commands cover almost everything.

### `ebb reclaim`: get space back, in place

```
$ ebb reclaim ~/dev/api --target 12GiB
reclaim for workspace "api"
  requested: 12 GiB
  removed group node-dependencies; recreate with: pnpm install --frozen-lockfile
    (41218 entries; plan retained as snapshot 9f21c...)
  carved 2 preserved file(s)/link(s) to the vault overlay
  achieved (estimated): 2.4 GiB; measured free-space delta: 2.4 GiB
```

Reclaim plans against the measured workspace, removes only declared reconstructible output (`node_modules`, `target`, `.venv`, ...), and leaves the project live. Your `.env`, uncommitted changes, notes, and everything Git-ignored-but-irreplaceable stay exactly where they are. Every removal is preceded by a verified capture of the removal plan, so it can always be undone. If trim alone cannot reach your target, ebb offers escalation to a full park as a separate, explicit confirmation. `--yes` never answers that one. A shortfall is reported as a shortfall (exit 8), never solved by deleting something undeclared.

Use `--dry-run` to see the staged plan with no effects.

### `ebb restore`: put dependencies back, in place

```
$ ebb restore ~/dev/api
restore for workspace "api"
  group node-dependencies: pnpm install --frozen-lockfile
  strategy: merge (1 drifted input reconciled, safety backup at package.json.bak-drift-...)
  protected-file gate: passed
```

The direct inverse of reclaim, on a live workspace. It re-executes the exact recipes sealed at trim time. Restore is gated like a landing gear check: it refuses to run inside an in-flight merge or rebase, never auto-decides a branch mismatch, and reconciles drifted recipe inputs (you edited `package.json` while the deps were trimmed) with an explicit three-way strategy: `merge` (union manifests, live wins, your package manager resolves), `current`, or `baseline`. After the recipes run, a post-flight integrity gate re-verifies everything outside the recreated outputs. Your edits inside `node_modules` come back too: carve-out overlays captured at trim time are re-applied on top of the fresh install.

### `ebb park`: shelve the whole project

```
$ ebb park ~/dev/three-year-old-experiment
Workspace: experiment
Preserve: 1873 entries (214 MiB)
Volume C.: 81 GiB available
workspace will be REMOVED after a verified capture; assert all writers are stopped? type 'yes': yes
parked workspace "experiment"
  snapshot retained: 4ab7e... (pinned)
```

Park captures the entire workspace to the encrypted vault, verifies it (coverage plus full readback), quarantines it, re-validates the live tree against the sealed inventory one last time, and only then removes the folder. The folder goes away; the bytes do not. Park requires a writer assertion (interactive confirmation or `--assert-writers-stopped` for automation) so nothing is removed while a build or editor is mid-write.

### `ebb open`: bring it back

```
$ ebb open experiment
```

Open restores a parked workspace to its recorded root (or `--to <dir>`). Files are staged privately, verified against the retained inventory as an independent oracle, then published. Nothing unrelated is ever overwritten. After the files land, open re-runs the locally-approved reconstruction actions (for example `pnpm install --frozen-lockfile`) so the workspace comes back ready to work in. Bare `ebb open` on a terminal shows an interactive picker of your parked workspaces.

## Autonomous discovery

### `ebb analyse`: one scan across every project

```
$ ebb analyse
Ebb workspace analysis
  scanned 14 project(s) across 1 root(s) (11.2 GiB estimated footprint - shallow stat estimate, not a full walk)
1. Bloated Active (active within 14 days, heavy regenerable output)
  api                          [Node         ] node_modules + dist     2.4 GiB estimated
       -> ebb reclaim C:\dev\api
2. Stale (untouched 30-90 days)
  renderer-ui                  [Node         ] untouched 63d           1.8 GiB estimated
       -> ebb reclaim C:\dev\renderer-ui
  legacy-payments              [plain        ] untouched 71d           6.1 GiB estimated  [UNPUSHED COMMITS]
       (unpushed commits: park preserves them, deletion would not - push or park)
  Subtotal reclaimable (unshielded, estimated): 1.8 GiB
3. Abandoned (untouched >90 days; ready to park)
  poc-wasm                     [Rust         ] untouched 412d         412 MiB estimated
       -> ebb park C:\dev\poc-wasm
4. Merged Worktrees (merged upstream, clean tree)
  feature-auth                 [Go           ] untouched 22d           96 MiB estimated
       -> git worktree remove C:\dev\repo\.worktrees\feature-auth

Total recoverable (estimated): 2.3 GiB

Recommendations (copyable):
  [R] Reclaim stale projects (1 project(s), 1.8 GiB estimated): ebb analyse --reclaim-stale --yes
```

Point ebb at your projects directory once (`ebb config add projects_dir <path>`) and it scans every immediate child: a shallow footprint probe of known output folders, git topology, and staleness classification. Categories: **bloated active** (touched within 14 days, more than 2 GiB of regenerable output), **stale** (untouched 30 to 90 days), **abandoned** (90+ days, park it), and **merged worktrees** (safe to remove natively). Every project gets one category or a plain "quiet"/"unknown".

Projects carry git safety shields, and shields block every batch action: `[UNPUSHED COMMITS]` (advise park or push, never deletion), `[DIRTY]` (uncommitted changes), `[CONFLICT]` (in-flight merge or rebase), `[LOCKED]` (a process holds file handles, reported with the holder). Recommendations are printed as copyable commands; you stay in control:

```
$ ebb analyse --reclaim-stale          # prints ebb reclaim per unshielded stale project
$ ebb analyse --reclaim-stale --yes    # executes them (per-project gates still in charge)
$ ebb analyse --prune-worktrees        # merged + clean + unshielded worktrees only
```

Batch execution re-probes shields immediately before each run. A project that became dirty since the scan is skipped, not reclaimed. The projects' own safety gates (capture, verify, grouped approvals) always stay in charge. Scan mode is 100% read-only: stats, directory listings, one manifest read. Nothing else.

### `ebb analyse --docker`: 7-tier Docker clutter intelligence

Docker disks fill up differently, so ebb classifies Docker clutter into seven tiers, correlated with the workspaces it just scanned. Read-only discovery; each tier ends with the exact native command to copy:

| Tier | What it finds | Copyable command |
|---|---|---|
| 0 | Pure dead clutter: dangling images, orphaned anonymous volumes | `docker image prune -f`, `docker volume prune -f` |
| 1 | Stale BuildKit cache (unused 14+ days) | `docker builder prune --filter "until=336h"` |
| 2 | Zombie containers blocking space (exited, project gone) | `docker rm <ids>` |
| 3 | Cold project images (workspace dormant 60+ days) | `ebb freeze <image-id>` |
| 4 | Dormant upstream base images (re-pullable) | `docker rmi <refs>` |
| 5 | Host VHDX slack (Windows Docker Desktop disk never shrinks) | `wsl --shutdown; ...set-sparse true; fstrim` |
| 6 | Orphaned compose volumes (project directory gone) | `docker volume rm <names>` |

Ebb never executes these for you. Anything correlated to a live workspace, pinned by a stopped container, or of unknown age is shielded and left alone. Unknown images are counted and reported, never guessed deletable.

### `ebb freeze`: cold images to the vault, verified

Tier 3's answer for `registry.local/api:3-gigabytes`. Freeze streams `docker save` directly into the encrypted vault with zero bytes staged on disk, hashes the stream in flight, and proves the capture by reading it back before reporting success. Restoring is one command, digest-verified before a single byte reaches the daemon:

```
ebb freeze 3f2a9c1d4e5f --dry-run     # size estimate only
ebb freeze 3f2a9c1d4e5f               # verified capture into the vault
ebb freeze --restore 3f2a9c1d4e5f     # stream it back into the daemon
ebb freeze 3f2a9c1d4e5f --remove      # after a VERIFIED freeze: separate confirmation to rmi
```

### `ebb doctor`

Diagnostics for the whole toolchain: restic present and matching the conformance target, git, platform probe capabilities, volume usage, writer inspection, streams, config dir, catalog. Every check is pass/warn/fail; nothing is auto-repaired. Only a missing restic binary is a hard failure.

## Developer space economy

### `ebb stats`: the terminal dashboard

```
$ ebb stats
lifetime reclaimed   148.2 GiB across 23 operations
lifetime restored     61.7 GiB across 12 operations
hoarding score        3 parked projects older than 6 months
clean desk streak     9 days since the last stale-project discovery
```

A local dashboard over your own catalog: lifetime reclaimed and restored bytes, a hoarding score for parked projects you have not touched, a clean desk streak, and a few offline comparisons (the classic "that is N Linux kernel tarballs") because reclaimed space should feel like something. `status` is an alias.

### `ebb stats --web`: a control center that cannot mutate

`ebb stats --web` serves a strictly read-only control center on localhost at a fresh unguessable per-run URL: command palette, deep search across workspaces and operations, full history, and a snapshot content explorer that browses exactly what each vault snapshot preserved. Actions in the web UI are **copy-to-terminal**: every button copies the equivalent ebb CLI command instead of executing it.

That is deliberate. The server exposes zero mutation endpoints. There is no endpoint to delete, unpark, forget, or prune anything, so there is nothing for a CSRF attack or a DNS-rebinding page to trigger. A malicious webpage can stare at your local ebb server and find nothing to command it to do, and because every run serves under a random per-run URL, other local processes cannot read your dashboard without the URL `ebb` prints. Mutation stays where the audit trail, the confirmations, and the typed assertions live: your terminal.

### `ebb stats --share`: a PNG card

Exports the dashboard as a PNG card, for the team chat where someone asked how you freed 40 GiB last sprint.

All analytics are computed locally from the catalog. Zero telemetry, zero network calls, in any mode.

## Safety guarantees

The trust core, each claim enforced in code:

- **Preservation is the default.** No policy file, no removals of anything but declared output. An explicit `Ebbfile.toml` must parse strictly; when absent, conservative defaults apply.
- **`.gitignore` is not a disposable signal.** Ignored files are preserved unless there is definitive proof or your explicit instruction otherwise. Generated output is only touched when a `[[regenerate]]` group declares the outputs and the recreate recipe.
- **Verified before removed.** Capture runs an exact coverage check plus a full content readback of every preserved byte before any removal is authorized. Verification failure means nothing is removed and the payload stays retained, pinned and inspectable.
- **Open verifies with an independent oracle.** Restored files are checked against the retained inventory, not against the component that encoded them. A tampered vault cannot publish forged content.
- **Git shields.** Analyse batches and worktree pruning refuse shielded projects (unpushed commits, dirty trees, in-flight conflicts). Restore fails closed on in-flight merges and never auto-decides a branch mismatch.
- **Carve-out overlays.** If you patched a file inside `node_modules` (a hotfix in a dependency, a built artifact), trim notices the preserved entry inside the output, captures it as an overlay patch to the vault with your consent, and restore re-applies it after the recreate recipe. Your edits survive round trips.
- **Last-copy protection.** Deleting the only remaining snapshot of a parked workspace requires an explicit `--last-of-parked` acknowledgement, on top of the typed confirmation.
- **Secrets never on the command line.** Vault passwords live in the OS credential store or `EBB_VAULT_PASSWORD`, and reach restic only through an ephemeral passfile. Capsule passphrases come from `EBB_CAPSULE_PASSWORD` or a terminal prompt, never from argv. Secrets never enter logs or JSON output.
- **Crash-safe by journal.** Every operation writes a durable journal. If ebb is killed mid-operation, nothing is silently lost: `ebb status` shows the operation, and `ebb recover <operation-id>` reconciles it from durable evidence. Interrupted removals resume where they stopped.
- **Untrusted input is treated as hostile.** Inspection never runs project code (no hooks, no filters, no lifecycle scripts). Git observation uses a hardened, non-executing recipe. Capsule files are parsed with traversal, duplicate, and NTFS-alias defenses, and extraction respects a verified byte budget. Docker daemon identifiers are validated before they can appear in any copyable command.
- **Shortfalls are reported, not manufactured.** Ebb reports a shortfall (exit 8) rather than manufacture a saving. Unknown failures are reported as blocked; nothing is removed on a maybe.

## Install

### From GitHub Releases

Each release publishes versioned archives and a checksum manifest:

- `ebb-<version>-windows-amd64.zip`
- `ebb-<version>-linux-amd64.tar.gz`
- `SHA256SUMS.txt`

Download the archive for your platform, verify it against `SHA256SUMS.txt`, and put the `ebb` binary on your PATH. winget and scoop manifests, plus an install script, are the distribution plan for the first tagged releases; until they are published, the archives are the official channel.

### From source

Requires Go 1.27+ and restic 0.19.x on PATH (ebb drives the real `restic` binary; the build is conformance-tested against 0.19.1).

```
go build -o ebb ./cmd/ebb
ebb doctor        # verify the toolchain
go test ./...     # full suite; restic acceptance tests auto-skip without restic
```

## Command reference

| Command | Purpose |
|---|---|
| [`ebb reclaim [path]`](docs/cli.md#ebb-reclaim) | Free space in place: verified trims, park only on explicit escalation |
| [`ebb restore [path]`](docs/cli.md#ebb-restore) | Rebuild trimmed dependencies in place, git-gated and drift-reconciled |
| [`ebb park [path]`](docs/cli.md#ebb-park) | Verified encrypted capture, then the workspace folder is removed |
| [`ebb open [name]`](docs/cli.md#ebb-open) | Recover a parked workspace, verified by an independent oracle |
| [`ebb analyse [path]`](docs/cli.md#ebb-analyse) | Scan project roots: staleness, shields, Docker tiers, batch actions |
| [`ebb stats`](docs/cli.md#ebb-stats) | Local dashboard, `--web` read-only control center, `--share` PNG card |
| [`ebb freeze <image-id>`](docs/cli.md#ebb-freeze) | Stream a Docker image into the vault, verified; `--restore` loads it back |
| [`ebb init`](docs/cli.md#ebb-init) | Enroll a vault, verify unlock, show detected groups (suggestions only) |
| [`ebb delete <target>`](docs/cli.md#ebb-delete) | End recovery obligations and prune freed vault storage in one action |
| [`ebb recover <op-id>`](docs/cli.md#ebb-recover) | Reconcile an interrupted operation from durable evidence |
| [`ebb verify <snapshot-id>`](docs/cli.md#ebb-verify) | Refresh retained-snapshot evidence; `--content` adds full readback |
| [`ebb export / import`](docs/cli.md#ebb-export) | Independent encrypted capsules for transfer and archival |
| [`ebb doctor`](docs/cli.md#ebb-doctor) | Capability and configuration diagnostics |

Full reference with every flag, exit code, and JSON envelope shape: [docs/cli.md](docs/cli.md).

Measured performance, methodology, and raw results: [docs/BENCHMARKS.md](docs/BENCHMARKS.md). Headline: after the streaming-tar readback transport landed, verified full content readback costs a flat 8 restic invocations regardless of file count, and a verified park of the small-file benchmark fixture dropped from 86 seconds to 6.

## Platform support

| Platform | Status |
|---|---|
| Windows 11 (NTFS) | Certified. Primary platform; native junctions, Restart Manager writer inspection, named-stream enumeration. |
| Linux (amd64) | Certified. Full suite runs natively (Debian 13, restic 0.19.1). OS keyring storage and a few NTFS-shaped capabilities are reported as unsupported by `ebb doctor` rather than silently degraded. |
| macOS | Not supported in v1. No builds are published. |

Known sharp edges, stated plainly: opening a workspace whose preserved set contains true symlinks on Windows requires Developer Mode or elevation (junctions, the common pnpm-style case, recreate unprivileged; a privilege failure happens before anything is published). Importing a capsule needs roughly twice the payload in free space on the destination volume. Hardlink relationships, NTFS alternate data streams, sparse flags, and ACLs are recorded as facts but not restored.

## FAQ

**Is my `.env` safe?**
Yes. `.env` files are not reconstructible, so they are preserved by every operation: reclaim and trim never touch them, park captures them, open restores them. Only output directories declared in an `Ebbfile.toml` regenerate group are ever removal candidates.

**What if I edited a file inside `node_modules`?**
Ebb detects the preserved entry inside the removal output and refuses a silent delete. You get a carve-out offer: the file is captured to the vault as an overlay patch, then the bulk is removed. `ebb restore` reapplies your edit after the fresh install.

**Does ebb need the network?**
No. Ebb is fully offline: local vaults, local catalog, local analytics. There are no telemetry, update checks, or phone-home calls anywhere, including the web dashboard. The only network traffic in your day is your own `docker pull` and `git push`.

**Where is my data?**
Local state lives in your user config directory (`%AppData%\ebb` on Windows, `~/.config/ebb` on Linux): `catalog.db` (SQLite catalog and operation journal) and `vaults.json` (vault registry). Vault data is a restic repository wherever you point `ebb init` (default `<config>/vault`), encrypted with keys held in your OS credential store. Nothing is uploaded anywhere.

**What happens if ebb is killed mid-operation?**
Nothing is silently lost. Operations journal their durable phases; a killed park or removal leaves the workspace recoverable, not gutted. `ebb status` lists the interrupted operation and `ebb recover <operation-id>` reconciles it: adopting the quarantine tree, resuming the removal walk, or cancelling cleanly. Ctrl+C exits with code 130 and the same recovery path.

**Can I move a workspace to another machine?**
Yes. `ebb export <snapshot-id> --output project.ebb` writes an independently encrypted capsule (a fresh restic repository in a ZIP64 container); the passphrase is displayed once. On the other side, `ebb import project.ebb` registers the snapshot into a vault, verified, and `ebb open <name>` restores it. Imported snapshots stay pinned and their rebuild approvals start empty: trust is never imported.

## License

Ebb is free to use, study, modify, embed, and redistribute, and it is source-available under the Apache License, Version 2.0 with the Commons Clause v1.0 condition. In plain terms: build anything on top of it, including paid products, and sell those products freely. What the license forbids is selling Ebb itself, or a repackaged or trivially renamed Ebb, as a product whose value comes from Ebb rather than from what you added. Both full texts live in [LICENSE](LICENSE).

---

Every destructive path in ebb is gated, journaled, and independently verified. [Full CLI reference](docs/cli.md) | [Benchmarks](docs/BENCHMARKS.md)
