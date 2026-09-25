# ebb CLI reference

Every user-facing command, flag, exit code, and machine output shape.

Conventions that hold across the whole CLI:

- Human-readable output goes to **stderr**. With `--json`, a single result envelope object goes to **stdout** and human output is suppressed. Every controlled exit emits exactly one terminal result.
- Confirmation prompts are interactive only: a command running without a terminal (CI, scripts) must either pass the corresponding `--yes`-class flag or it is blocked. `--yes` never answers writer assertions or escalation confirmations.
- Deletion-class actions always show what will happen before asking for confirmation, and the confirmation is typed.
- Workspace names are labels, not identities. A capture at a root that differs from the recorded root of a same-named workspace never re-points that workspace's history: the path enrolls as a new workspace instead. Re-capturing the same root under the same name keeps the same workspace.

## Quickstart

```
ebb init                              # once: enroll an encrypted vault (restic)
ebb config add projects_dir /home/you/dev
ebb analyse                           # every project: size, staleness, shields, actions
ebb reclaim /home/you/api --dry-run   # staged plan, no effects
ebb reclaim /home/you/api             # execute
ebb stats                             # what you freed, and what you are hoarding
```

## The daily loop

### `ebb reclaim`

Free space from a live workspace in place. Reclaim plans against the measured workspace, executes the declared reconstructible-output removals under full validation (each preceded by a sealed capture of the removal plan, the recipe inputs, and any approved carve-out overlays), and escalates to a whole-workspace park only when the target cannot be met otherwise. Escalation is a separate typed confirmation plus a writer assertion; `--yes` never answers it. A shortfall is exit 8, never a reason to delete something undeclared. A trim does not copy the removed output bytes: recovery is `ebb restore` re-running the sealed recipes, which needs the toolchain, the network, and the registries to work. The byte-backed capture-before-removal path is `ebb park`.

```
ebb reclaim [path] [flags]
```

| Option | Description |
|---|---|
| `--target <bytes>` | Space goal, e.g. `25GiB` (default: release as much as safely possible) |
| `--dry-run` | Print the staged plan without effects |
| `--yes` | Accept the trim removal confirmations (never answers the park escalation) |
| `--carve-out` | Authorize granular carve-out of preserved entries inside trim outputs: capture to vault, then remove |
| `--assert-writers-stopped` | Writer assertion for the park escalation (does not answer its confirmation) |
| `--json` | Machine envelope on stdout |

Exit codes: 0 completed; 2 usage; 3 blocked; 4 capture verification failure; 5 removal interrupted (reconcile with `ebb recover`); 7 vault; 8 target shortfall or no useful gain; 130 cancelled.

Example:

```
$ ebb reclaim . --target 12GiB --dry-run
reclaim plan for workspace "api" (dry run: nothing will be removed; no captures are made)
  requested: 12 GiB
  stage 1 trim node-dependencies [2.4 GiB]: outputs: node_modules; recreate: pnpm install --frozen-lockfile
  park escalation stage: would REMOVE the workspace after a verified capture and parking;
    staged-plan additional release: 214 MiB; needs its own confirmation and a stopped-writers assertion
```

### `ebb restore`

Recreate trimmed dependencies in place on a live workspace. The recovery path for `reclaim`/`trim`: it re-runs the recipes sealed at trim time rather than restoring captured bytes, behind a git pre-flight gate, three-way drift reconciliation, and a post-flight protected-file integrity gate. Restore never needs `--yes`; its only decisions (branch mismatch, drift strategy) are terminal menus that `--json` mode refuses with a typed error instead of prompting.

The trim seals each group's exact rebuild action: argv, working root (relative to the workspace), inputs, outputs, env allowlist, network, and timeout. Restore replays that definition verbatim and checks it against the local approval store before anything runs: a recipe whose recorded approval still matches its current tool identity and input digests runs silently; a missing or drifted approval is asked again on a terminal and refuses headless. A trim manifest from before this freeze carries no frozen definitions: such a replay is labeled a legacy recovery attempt, is never claimed to be the previously-approved action, and needs a fresh explicit approval (`--legacy-approve` headless, or the terminal prompt).

```
ebb restore [path] [flags]
```

| Option | Description |
|---|---|
| `--strategy merge\|current\|baseline` | Resolve recipe-input drift non-interactively. `merge`: union manifests with a safety backup, live wins, your native tool resolves. `current`: rebuild from the live files. `baseline`: revert inputs to the frozen trim baseline. |
| `--dry-run` | Report the selected trim, commands, drift table, and overlays without effects |
| `--legacy-approve` | Record the fresh explicit approval a legacy trim manifest (one without frozen action definitions) needs, without a prompt |
| `--json` | Machine envelope on stdout |

Restore refuses to run a single recipe while any group's declared output still exists and is non-empty: that is live data a recipe must never run over. When every output is already present the answer is "already restored"; when only some are, the whole restore is refused and both sets are listed. Both refusals are existence-only checks: present means something is there, not that the content is valid or the application healthy. A failed restore's own rerun is the exception: it resumes instead of refusing.

Exit codes: 0 restored (or previewed); 2 usage; 3 blocked (nothing to restore, in-flight git conflict, unresolved branch mismatch, outputs still present, already restored, legacy manifest without approval, approval drift without a terminal, drift without a strategy); 6 recipe execution or protected-gate failure (resumable by rerunning); 7 vault; 130 cancelled.

### `ebb park`

Capture the entire workspace, verify it, then remove the folder. Sequence: capture, coverage plus full content readback, seal, revalidate the live tree against the sealed inventory, quarantine rename, per-entry re-verified removal. Requires a stopped-writers assertion before any capture: interactive confirmation on a terminal, or `--assert-writers-stopped` for automation. `--yes` never supplies it.

```
ebb park [path] [flags]
```

| Option | Description |
|---|---|
| `--assert-writers-stopped` | Unattended writer assertion, recorded in the operation journal |
| `--yes` | Accept ordinary prompts (never supplies the writer assertion) |
| `--json` | Machine envelope on stdout |

Exit codes: 0 parked; 2 usage; 3 blocked (missing or declined assertion, destructive blockers, source changed); 4 verification failure (payload retained unsealed); 5 removal interrupted; 7 vault; 130 cancelled.

### `ebb open`

Recover a parked or captured workspace. Files are staged privately, verified against the retained inventory as an independent oracle, then published to the workspace's recorded root (or `--to`). After publishing, open re-runs the recorded, locally-approved reconstruction actions so the workspace comes back working; `--files-only` skips that. A failed rebuild is exit 6 with the files intact and the snapshot pinned, resumable with `ebb open --resume`. Bare `ebb open` on an interactive terminal opens a picker of parked workspaces.

Target resolution: a 32-hex argument opens that exact snapshot. A name must match exactly one workspace: several matches refuse with `EBB_E_OPEN_AMBIGUOUS_TARGET`, listing every candidate. The matched workspace's newest sealed park snapshot is opened, falling back to its newest sealed plain snapshot when no park exists; an exact creation-timestamp tie inside the winning kind is refused too. In every ambiguous case, pass the snapshot id. The report names the state that came back: snapshot id, kind, and creation timestamp.

```
ebb open <name | snapshot-id | operation-id> [flags]
```

| Option | Description |
|---|---|
| `--to <dir>` | Destination directory (default: the workspace's recorded original root) |
| `--files-only` | Stop after publishing the preserved files; no reconstruction |
| `--yes` | Record approvals for not-yet-approved reconstruction actions without a prompt (never covers approval drift) |
| `--resume` | Resume the rebuild of the workspace's interrupted open operation (positional argument: operation id or workspace; reruns every action that has no recorded success or whose declared outputs are no longer present, an existence-only check) |
| `--cancel` | Cancel a `REBUILD_FAILED`/`REBUILDING` open operation (files stay; snapshot stays pinned) |
| `--json` | Machine envelope on stdout |

Exit codes: 0 done (files-only included); 2 usage; 3 blocked (trim or seal-kind snapshot, ambiguous target, occupied destination, insufficient space); 4 seal or document verification failure; 5 publish blocked (staging kept, reconcile with `ebb recover`); 6 rebuild failed or blocked (files intact, resumable); 7 vault; 130 cancelled.

## Discovery and Docker

### `ebb analyse`

Alias: `analyze`. Autonomous workspace discovery over configured roots (or one explicit directory). Shallow, read-only scanning: stats, directory listings, one manifest read. Classifies each project (bloated active, stale, abandoned, merged worktree, or quiet/active/unknown), applies git safety shields, prints copyable recommendations, and can execute batches behind explicit consent. Destructive action exists only behind the batch flags; shields block every batch; the projects' own safety gates stay in charge during execution.

```
ebb analyse [path] [flags]
```

| Option | Description |
|---|---|
| `--docker` | Append the Docker tier analysis (read-only, workspace-correlated) |
| `--reclaim-stale` | Act on stale unshielded projects via `ebb reclaim` (print-only without `--yes` or a per-item typed confirmation) |
| `--prune-worktrees` | Act on merged+clean unshielded worktrees via native `git worktree remove` (print-only without `--yes` or a per-item typed confirmation) |
| `--yes` | Accept batch execution prompts (never answers writer assertions or park escalations) |
| `--json` | Machine envelope on stdout |

Scan roots come from `ebb config add projects_dir <path>` (or pass a directory directly). Classification thresholds: active means touched within 14 days; stale means 30 to 90 days; abandoned means beyond 90 days; bloated means an output footprint above 2 GiB on an active project.

Exit codes: 0 ok; 2 usage; 3 blocked (no scan roots configured; the message shows how to add one); 130 cancelled.

Docker tiers (`--docker`): tier 0 pure dead clutter (dangling images, orphaned anonymous volumes), tier 1 stale BuildKit cache (14+ days), tier 2 zombie containers blocking space, tier 3 cold project images (freeze-to-vault via `ebb freeze`), tier 4 dormant upstream base images (60+ days, re-pullable), tier 5 host VHDX slack on Windows, tier 6 orphaned compose volumes. Each tier ends with the exact native command to copy. Ebb never executes them. Shielded items (live workspace, unknown age, unparseable daemon identifier) are reported for manual inspection only.

### `ebb freeze`

Stream a Docker image into the vault as cold storage: `docker save` piped directly into `restic backup --stdin` with zero bytes staged on disk, SHA-256 hashed in flight, and proven by an independent readback before anything is reported captured. `--restore` is the inverse (`restic dump` piped to `docker load`), with the digest verified before a single byte reaches the daemon. The daemon-side `docker rmi` runs only behind a second, separate confirmation (`--remove` plus `--yes-removal` or the prompt) and only after a verified freeze. Frozen images are retained in the vault indefinitely: there is no `ebb`-side forget path for freeze entries yet (`ebb delete` and `ebb gc` never touch them), so plan vault capacity accordingly.

```
ebb freeze <image-id> [flags]
ebb freeze --restore <entry-or-image-id> [flags]
```

| Option | Description |
|---|---|
| `--dry-run` | Show the size estimate (`docker image inspect`) without effects; takes no other action flags |
| `--yes` | Accept the freeze confirmation headlessly (never answers the removal confirmation) |
| `--restore <entry-or-image-id>` | Stream a frozen image back into the daemon (takes the id itself, not a positional argument) |
| `--remove` | After a verified freeze, offer the daemon-image removal (separate confirmation) |
| `--yes-removal` | Accept that separate removal confirmation headlessly (requires `--remove`) |
| `--json` | Machine envelope on stdout |

Exit codes: 0 frozen, restored, or estimated; 2 usage; 3 blocked (daemon unreachable, confirmation declined or unavailable); 4 the vault readback did not match the recorded digest (the entry is retained unverified and pinned; nothing was removed from the daemon); 7 vault; 130 cancelled.

### `ebb doctor`

Report supported capabilities and configuration problems. No automatic repair. Checks: restic (the one hard prerequisite; a missing binary is exit 2), git, platform probe, volume usage, writer inspection, named streams, config dir, catalog. Every check is pass, warn, fail, or n/a; platform gaps (for example Restart Manager outside Windows) are reported as unsupported.

```
ebb doctor [--json]
```

## Analytics

### `ebb stats`

Alias: `status`. The local dashboard over your own catalog: lifetime reclaimed and restored bytes, hoarding score (parked projects you are not touching), clean desk streak, and offline size comparisons. Everything is computed locally from `catalog.db`. There is no telemetry and no network access, in any mode.

```
ebb stats [--json] [--web | --share [--out <file>]]
```

| Option | Description |
|---|---|
| `--json` | Machine envelope on stdout (works with `--share`; refused with `--web`) |
| `--web` | Serve the read-only local control center on `127.0.0.1` at a fresh unguessable per-run URL until Ctrl+C; opens the browser only when stdin is a terminal |
| `--share` | Render the dashboard as a shareable PNG card (1600x900, deterministic for the same day's data) |
| `--out <file>` | Destination for `--share` (default: `ebb-stats-YYYYMMDD.png` in the current directory) |

Exit codes: 0 report produced (an empty catalog is a valid report); 2 usage (positional arguments, `--web` combined with `--share` or `--json`, `--out` without `--share`); 3 blocked (catalog read failure, card write failure, server failure); 130 cancelled (Ctrl+C during `--web`).

#### `ebb stats --web`: read-only by construction

`--web` serves a control center bound to localhost: command palette, deep search across workspaces, snapshots, and operations, full operation history, and a snapshot content explorer showing exactly what each vault snapshot preserved.

Every action in the web UI is copy-to-terminal: buttons copy the equivalent ebb CLI command to your clipboard instead of executing anything. That is a security decision, not a limitation. The server exposes zero mutation endpoints, and it serves everything under a random per-run URL segment minted at startup, so other processes on the machine cannot read the dashboard without the URL printed by the serving line. There is no route that deletes, unpins, forgets, prunes, or starts anything, so there is nothing for a cross-site request forgery attempt or a DNS-rebinding page to trigger: a hostile webpage can reach the port and find nothing to command. Mutation stays in the terminal, where the audit trail, the typed confirmations, and the writer assertions live.

`--share` writes a PNG summary card, suitable for pasting into a chat or a PR description.

## Vault and lifecycle

### `ebb init`

One-time setup and recovery entry point: ensure the state directory and catalog, enroll a vault when none is registered (interactive: repository path plus the credential machinery; passwords go to the OS credential store, or `EBB_VAULT_PASSWORD` for CI), verify the default vault unlocks when one exists, and print detected ecosystem regeneration groups as suggestions only. Detection is existence-only and never writes an `Ebbfile.toml`.

`--rebuild-catalog` rebuilds workspaces and snapshots from a surviving vault when `catalog.db` was lost (discovered workspaces come back unbound and pinned, never guessed disposable); `--force-rebuild` overwrites an existing catalog.

```
ebb init [path] [--rebuild-catalog] [--force-rebuild] [--json]
```

Exit codes: 0 ok; 2 usage; 3 blocked; 7 vault (no vault registered non-interactively, unlock rejected).

### `ebb verify`

Refresh retained-snapshot evidence: seal and document checks plus coverage. `--content` adds a full per-file readback of every preserved byte (expensive; the whole payload is re-read and digest-checked).

```
ebb verify <snapshot-id> [--content] [--json]
```

Exit codes: 0 all checks pass; 2 unknown or malformed id; 3 blocked (trim-kind or seal-kind row, unsealed payload: not verifiable in this form); 4 a check failed; 7 vault; 130 cancelled.

### `ebb export`

Produce an independent encrypted capsule from a snapshot: a fresh restic repository holding only the selected payload, packaged as a ZIP64 container, fully verified before a no-clobber publication. Export never implies forget; the source snapshot stays pinned. The generated capsule passphrase is your recovery secret: it prints once, to the terminal, immediately after publication. It never enters argv, logs, or the JSON envelope.

```
ebb export <snapshot-id> --output <file> [--dry-run] [--json]
```

| Option | Description |
|---|---|
| `--output <file>` | Capsule output path (required; never overwritten) |
| `--dry-run` | Check eligibility and print the plan without creating anything |
| `--json` | Machine envelope on stdout |

Exit codes: 0 capsule published; 2 malformed id or bad arguments; 3 refused (trim or seal kind, unsealed payload, occupied output path, stale partial); 4 a verification check failed (nothing published); 7 vault; 130 cancelled.

### `ebb import`

Register a capsule's snapshot into a vault without opening it: extract, verify, copy, readback, reseal. The mirror of export. Import never imports trust: the snapshot registers pinned, and rebuild approvals start empty even if the source manifest claims they were approved elsewhere. The capsule passphrase comes from `EBB_CAPSULE_PASSWORD` or one terminal prompt, never argv. Opening from a capsule is two steps: `ebb import`, then `ebb open <workspace-name>`.

```
ebb import <file> [--vault <name>] [--dry-run] [--json]
```

| Option | Description |
|---|---|
| `--vault <name>` | Destination vault, by name or id (default: the registry's default vault) |
| `--dry-run` | Verify the container and print the plan (declared totals, headroom) without extracting, unlocking, or registering anything |
| `--json` | Machine envelope on stdout |

Note: import needs roughly twice the capsule payload in free space on the destination volume.

Exit codes: 0 registered (or already known: idempotent rerun); 2 bad arguments; 3 blocked before mutation (no passphrase source, content-identity conflict, destination headroom, trim-kind capsule); 4 a verification check failed or the copy could not be proven (the destination is rolled back); 7 wrong passphrase or vault unavailable; 130 cancelled.

### `ebb recover`

Reconcile an interrupted operation from durable evidence. Every operation writes a journal; after a crash, kill, or Ctrl+C, `ebb status` shows the operation and this command adopts the quarantine tree, resumes the removal walk, or cancels cleanly.

```
ebb recover <operation-id> [--resume-removal] [--cancel] [--json]
```

| Option | Description |
|---|---|
| `--resume-removal` | Explicitly resume a blocked removal walk (required for `REMOVAL_BLOCKED` after the blocker is resolved and writers are stopped again) |
| `--cancel` | Abandon an operation whose removal never started, a crashed capsule transport, a dead restore, or a forget still before its unpin; retained snapshots stay pinned. A forget past its unpin is refused: rerun `ebb forget` to finish it |
| `--json` | Machine envelope on stdout |

Exit codes: 0 reconciliation completed; 2 usage (unknown operation id, contradictory flags); 5 journal or evidence mismatch, or a reconciliation that itself got blocked mid-removal; 7 vault; 130 cancelled.

### `ebb config`

Manage global settings stored in the state directory. v1 key: `projects_dir`, the list-valued absolute scan roots for `ebb analyse` (roots need not exist: offline or external drives are valid). `--json` is accepted before or after the subcommand.

```
ebb config list
ebb config get <key>
ebb config set <key> <value>
ebb config add <key> <value>
ebb config remove <key> <value>
```

Exit codes: 0 ok; 2 usage (shape mistakes, unknown key, bad or absent value; values must be absolute paths); 3 state I/O failure.

## Deletion

### `ebb delete`

End recovery obligations and physically prune the freed vault storage in one action. Target resolution: a 32-hex id addresses one snapshot; anything else is a workspace name addressing all of its snapshots. Stage one is the forget stage with all of forget's protections; stage two runs the vault prune immediately when eligible, or skips with a warning naming `ebb gc` as the completion path.

Protections on every path: unsealed payloads and seal-kind rows are refused; an active operation on the target blocks the command; deleting the only remaining snapshot of a parked or unbound workspace requires the explicit `--last-of-parked` acknowledgement; and deletion always carries a typed confirmation (or `--yes` headlessly). Never silent.

```
ebb delete <workspace-name | snapshot-id> [flags]
```

| Option | Description |
|---|---|
| `--yes` | Accept the typed-target confirmation without a prompt (the deletion summary is shown first) |
| `--last-of-parked` | Acknowledge deleting the only snapshot of a parked workspace |
| `--dry-run` | Show what would be unpinned, forgotten, and pruned without mutating anything |
| `--json` | Machine envelope on stdout |

Exit codes: 0 deleted (or clean no-op); 2 unknown target; 3 refused; 4 prune-side integrity failure; 5 partial durable state needing a rerun (every step is idempotent); 7 vault; 130 cancelled.

## Advanced plumbing

These commands remain fully functional. They are the layers the daily loop composes, exposed for scripting and inspection.

- `ebb snapshot [path]`: capture and verify without removing anything; the safest possible first command on a workspace.
- `ebb trim [path] --groups a,b`: remove explicitly approved regenerate groups from a live workspace, under the same validation, capture, and carve-out rules reclaim applies.
- `ebb plan [path] [--target N]`: compute a reclaim plan; preview only, grants no removal authority.
- `ebb inspect [path]`: explain scope, costs, and blockers without running project code. With a capsule file argument, prints its bounded public metadata (and with `EBB_CAPSULE_PASSWORD` set, runs full verification without registering).
- `ebb forget <snapshot-id>`: deliberately end one snapshot's recovery obligation behind a typed confirmation. Retention is forget's explicit job, never a prune-side policy. The last-recovery-copy guard counts only copies a live backend listing still returns: a catalog row is not custody, and replica receipts are informational, never counted. Forget is journaled as a phased operation (`FORGET_PLANNED` → `FORGET_INTENT_RECORDED` → `FORGET_UNPINNED` → `FORGET_BACKEND_FORGOTTEN` → `FORGET_DONE`): an interrupted forget resumes idempotently on rerun, and cancellation is refused once the snapshot is unpinned.
- `ebb gc <vault> [--dry-run]`: reclaim vault storage no snapshot references anymore (backend prune; verified to never remove retained snapshots). Run it after `delete` or `forget`.
- `ebb version`: print the ebb version, the restic conformance target, and the Go version.

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | ok | Requested outcome completed (a shortfall-free report) |
| 2 | usage-error | Invalid arguments, schema, or unsupported command feature |
| 3 | blocked | Blocked before mutation by policy, capability, trust, or stopped-writers |
| 4 | verification-failed | Capture or integrity verification failed (nothing removed) |
| 5 | reconciliation-required | Interrupted or partial destructive operation; run `ebb recover` |
| 6 | rebuild-failed | Preserved files recovered; reconstruction failed or was blocked (files intact, resumable) |
| 7 | vault-unavailable | Vault, unlock, or provider unavailable |
| 8 | shortfall | No useful gain, or reclaim target shortfall |
| 130 | cancelled | Controlled user cancellation (Ctrl+C); the journal keeps the last durable phase |

Every non-zero exit prints a stable blocker code (for example `EBB_E_NO_VAULT`, `EBB_E_LAST_OF_PARKED`, `EBB_E_ESCALATION_UNCONFIRMED`), the affected scope, the reason, and a safe action. Machine mode carries the same facts in the envelope.

## JSON envelopes

With `--json`, exactly one envelope object is written to stdout (indented, newline-terminated). `warnings` and `errors` are always arrays, never null. Optional fields are omitted when the command produced no value for them.

```json
{
  "operation_id": "6c1f...",
  "command": "park",
  "phase": "DONE",
  "workspace_id": "9a42...",
  "snapshot_id": "4ab7...",
  "outcome": "ok",
  "conditions": ["writer-assertion:interactive-confirm", "workspace-parked"],
  "bytes": {
    "preserved": 224395264,
    "freed_observed": 224395264,
    "freed_estimated": 224395264
  },
  "details": { "...": "command-specific payload" },
  "warnings": [],
  "errors": []
}
```

The `outcome` vocabulary mirrors the exit codes: `ok`, `usage-error`, `blocked`, `verification-failed`, `reconciliation-required`, `rebuild-failed`, `vault-unavailable`, `shortfall`, `cancelled` (plus `dry-run` for preview runs). The `bytes` object carries one field per meaning the command actually measured: `preserved`, `omitted`, `restored`, `freed_observed` (the measured free-space delta on the source volume), `freed_estimated` (the logical estimate). `details` is command-specific; the shapes are visible by running any command with `--json --dry-run` where a dry run exists.

## Environment variables

| Variable | Purpose |
|---|---|
| `EBB_STATE_DIR` | Override ebb's state directory (default: the OS user config dir plus `ebb`) |
| `EBB_VAULT_PASSWORD` | Vault password source for CI and scripts (alternative to the OS credential store and the terminal prompt) |
| `EBB_CAPSULE_PASSWORD` | Capsule passphrase for `ebb import` (alternative to the one terminal prompt) |

No secret is ever accepted as a command-line argument, and none ever appears in logs, prompts, or JSON output.

## File locations

State lives in the per-user config directory: `%AppData%\ebb` on Windows, `~/.config/ebb` on Linux (override with `EBB_STATE_DIR`).

| Path | Contents |
|---|---|
| `<state>/catalog.db` | SQLite catalog: workspaces, snapshots, the durable operation journal |
| `<state>/vaults.json` | Vault registry (which restic repositories ebb knows) |
| `<state>/config.json` | Global settings (`projects_dir` scan roots); created on first change |
| `<state>/approvals.json` | Local reconstruction-action approvals (never transferred with exports or imports) |
| `<state>/vault/` | Default vault location (a restic repository), wherever you pointed `ebb init` |

Vault repositories are standard restic repositories, encrypted at rest; the password reaches restic only through an ephemeral passfile, sourced from `EBB_VAULT_PASSWORD`, the OS credential store, or a no-echo terminal prompt, in that priority order.
