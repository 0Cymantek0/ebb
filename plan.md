# Ebb product overhaul plan

Status: research and adversarial validation in progress. This document is being committed incrementally. It is a design proposal, not a statement that the proposed implementation exists or has passed release qualification.

Baseline: `0Cymantek0/ebb`, commit `1d0f7ea64af62afd97816432e4e65166a82920ae`. Research date: 2026-09-25. Planning branch: `research/automatic-workspace-overhaul-2026-09-25`. Production code and the user's workspaces and vaults are outside this run's mutation scope. The spoken name "Abe" is interpreted as Ebb, not a rename request.

## 1. Product intent and non-negotiable constraints

Ebb should reduce the recurring effort of deciding what occupies developer storage, what can safely leave a working machine, and how to resume work later. The product must save decision-making time, not merely abbreviate a few shell commands.

Windows and Linux are the initial supported platforms. macOS is explicitly deferred. Cross-platform support means a tested capability contract on each supported filesystem and operating system, not identical native behavior or a promise that Windows environments become runnable Linux environments.

Users should not need to understand Ebb's internal reconstruction policy to use the ordinary workflow. Discover projects, relationships and reclaim opportunities automatically where evidence permits. Configuration remains an expert override for exceptional cases. A commonplace nested Python manifest is not an acceptable reason to require a hand-written policy file.

A complete command executes directly when all required decisions and authorization are already supplied. An incomplete but valid interactive command enters a guided terminal interface and continues the same operation. Piped, JSON, CI and explicitly non-interactive invocations must never wait for hidden prompts. Invalid or ambiguous destructive arguments must not be guessed.

## 2. Feasibility proposition to test

A broadly useful, language-independent workspace lifecycle with progressively richer automatic understanding is feasible. Perfect semantic inference about every arbitrary working directory is not a defensible product contract. Identical observable files can correspond to different user intent or hidden dependencies. A tool that preserves an unsupported directory safely can be compatible with it without knowing how to regenerate it.

Separate the following claims throughout the design:

- Discovery can identify candidates and explain the evidence without authorizing removal.
- Byte recovery requires retained, verified bytes and a surviving recovery location and key.
- Reconstruction requires a recipe plus its actual dependency and execution requirements; a package name or lockfile is not an independent backup.
- Application readiness is a further claim. A directory existing or an installer exiting zero does not establish it.
- Space released on one volume is not necessarily net space saved across the machine.

No model confidence score, user confirmation, hash of metadata, or successful finite test turns an unproven reconstruction assumption into a universal no-loss guarantee. The design will document explicit supported failure modes and refuse or preserve when its contract cannot be satisfied.

## 3. Work sequence and definition of done

1. Revalidate the earlier Ebb review at the pinned baseline. Trace discovery, policy, planning, capture, removal, recovery, command dispatch and TUI seams. Record source-confirmed defects separately from hypotheses and historical rationale.
2. Research overlapping established systems using primary documentation and source. Compare their ownership models, evidence, failure behavior, user workflow and architectural limits, not just features.
3. Develop at least two structurally different approaches. Choose using safety, actual storage economics, low user effort, implementability and compatibility.
4. Specify the selected data model, operation state machine, trust boundaries, platform capabilities, discovery adapters, recovery contract and CLI/TUI behavior.
5. Execute feasible adversarial experiments in disposable fixtures. Preserve negative results and change the plan only where evidence justifies it. Source inspection and bounded models are not end-to-end product validation.
6. Add staged implementation work, release gates, user-value experiments, residual risks and a final consistency review. Commit each coherent addition or surgical correction on this branch.

Done for this run means a source-linked plan with a reproducible evidence trail, explicit alternatives, failures that changed the design, and named untested boundaries. It does not mean "impossible to break." Production overhaul, native Windows certification, full real-restic lifecycle testing, and user studies are separate implementation and qualification work unless actually exercised and recorded here.

## 4. Evidence and review rules

Use stable identifiers for defects, decisions, claims and experiments. Classify findings as source-confirmed, experimentally reproduced, proposed, or unresolved. Distinguish a reproduced defect from an inferred consequence. Cite baseline file paths and symbols with immutable GitHub links; record external primary sources with retrieval dates.

Maintain a rating rubric for candidate comparison, not an invented probability of safety. Safety failures veto a candidate regardless of its usability or automation score. No previous numeric Ebb-specific rubric was supplied in the available conversation, so any rubric introduced in this document will be explicitly labeled as a proposed one.

Keep the main document self-contained for product decisions. Supporting scripts and raw results may live under `docs/research/ebb-overhaul/`, linked from the relevant experiment. Never silently replace a failed experiment with a weaker passing criterion.

## 5. Misconceptions that must not survive the overhaul

The user observed a working project with `wavebox/requirements.txt`, a root `.venv`, and a buildless frontend. Ebb reported every entry preserved and no reclaim gain. The earlier assistant proposed dummy root manifests and claimed normal trim backed up the removed dependency bytes. The implementation does not support that advice.

A dummy manifest is not evidence of reproducibility. Finding a real manifest is also insufficient by itself. Reading installed package versions does not prove that their implementation files have not been patched. A successful rebuild today does not guarantee that the same downloads will exist tomorrow. User confirmation establishes consent, not semantic truth.

Normal trim retains a removal plan, recipe inputs and selected carve-out overlays, not the ordinary dependency-tree bytes it removes. `open --files-only` is not an emergency exact-byte restore for a trim-only payload. Park and snapshot also honor the resolved policy; when configured outputs are omitted for reconstruction, these operations are not unconditional full-directory images.

The earlier assessment that Ebb had a strong recovery core and merely weak inference was too generous. There are valuable verification and journaling mechanisms, but the cross-module source review below found recovery-selection and retention-accounting defects too. Treat every safety claim as scoped and testable.

## 6. Baseline architecture and defect ledger

### 6.1 Actual request flow

The executable delegates to `internal/cli`. `runDiscovery` resolves the root, obtains filesystem and Git observations, scans an inventory, annotates Git evidence, parses an Ebbfile or conservative defaults, then resolves routes. `planner` proposes routes; `lifecycle` captures and removes; `restore` has separate whole-workspace and live-trim recovery drivers. `catalog` records operations and snapshots. `storage/restic` owns backend invocation. `platform` supplies native file identity and link behavior. `analyse` is a separate shallow project-ranking engine. The CLI currently owns substantial approval and orchestration logic.

This separation is partly sound. Read-only discovery should not acquire deletion authority. The defect is that different paths maintain incompatible definitions of recipes, identity, recoverability and success. A new scanner alone cannot repair those contradictions.

### 6.2 Source-confirmed findings

These are findings from the pinned source. They are not claims that a production Windows binary was executed in this research run. Severity is proposed release priority: P0 is a recovery/safety release blocker; P1 breaks an ordinary promised workflow; P2 is a material usability, diagnostics or coverage problem.

| ID | Priority | Finding and consequence | Required correction |
|---|---|---|---|
| E01 | P1 | Ecosystem discovery checks root markers and supports only pnpm, npm, uv and limited pip suggestions. It does not discover the user's nested manifest. | Recursive, bounded component discovery with explicit evidence and completeness, independent of removal authority. |
| E02 | P1 | `init` prints suggestions but never writes policy; `runDiscovery` uses an empty regenerate set without an Ebbfile. Detected projects can still yield no usable trim plan. | One discovery-to-proposal workflow that requires ordinary users to review an outcome, not author configuration. |
| E03 | P0 | Trim snapshots its operation documents, input copies and carve-out overlays, not normal output bytes. A wrong recipe or unavailable dependency can make removed content unrecoverable. | Default recoverable eviction must retain original content. Recipe-only disposal must be a separately named, explicitly weaker operation. |
| E04 | P1 | Built-in capture action derivation does not propagate `Regenerate.Root`; the ecosystem builder fixes `WorkingRoot` to `.`. Live restore also fixes it to `.` despite the removal manifest carrying `Root`. | One versioned recipe representation and round-trip contract for working directory, inputs, outputs, tool, environment and network requirements. |
| E05 | P1 | UV's action recipe uses `uv sync --locked`, while trim's recorded command uses `uv sync --frozen`. The presentation helper also differs from the trim writer. | Derive display and execution from one recipe object, with version-specific semantics tested. |
| E06 | P0 | Live trim restore synthesizes approval from the tool and inputs resolved at restore time. It does not establish that this is the executable approved earlier. Whole-workspace open uses a different approval store. | Separate consent to remove from consent to execute. Retain approval scope and recheck executable identity and script/input closure before execution. |
| E07 | P1 | Live restore constructs `NetworkAllowed` rather than retaining the group's declaration. The action subsystem explicitly does not enforce network isolation. | Preserve the declaration and distinguish requested capability, actual enforcement and observed use. Never display an annotation as an enforced sandbox. |
| E08 | P0 | Preservation and carve-out routing use known evidence such as policy and Git tracking. There is no general baseline comparison proving that every untracked edit inside a declared output is disposable. | Capture unknown output bytes by default; preserve patches and additions without requiring Git tracking. A directory name is not ownership. |
| E09 | P1 | Reclaim invokes a separate trim for each planned group; `selectTrimRecord` selects only the newest completed trim. Earlier outstanding groups are not aggregated by that selection. | Track outstanding obligations by group generation and operation batch, not only the latest operation. Restore all selected outstanding groups. |
| E10 | P1 | `ListSnapshots` orders by `created_at, id` ascending. Named `open` stores the first eligible park/plain snapshot in variables named `latestPark`/`latestSnap`. It therefore chooses the oldest eligible snapshot of the preferred kind. | Select the newest eligible retained snapshot explicitly, with deterministic tie-breaking and a visible timestamp. |
| E11 | P0 | `forget` checks `len(ListSnapshots)==1` for last-copy acknowledgement. Unpinning and completing a retention intent leave historical snapshot rows present. Those rows can continue to count after their backend copies are gone. | Count verified surviving recovery locations/obligations, not history rows. Give snapshots an explicit availability/tombstone state and centralize the guard across every purge entry point. |
| E12 | P1 | Workspace resolution can fall back from matching name and root to the first live workspace with the same name. Different directories with the same basename can share an identity/history unexpectedly. Live trim selection also falls back to historical source-path equality. | Names are display labels. Bind operations to an explicit workspace ID and root generation, and require disambiguation/rebinding rather than silently merging histories. |
| E13 | P1 | Runner completion checks that output roots exist, not that their contents satisfy a recovery contract. Resume has a similar existence-only shortcut. | Distinguish files recovered, recipe completed and application health checked. Validate exact retained content where exact recovery is promised. |
| E14 | P0 | Live restore refuses when all outputs already exist, but otherwise can rerun recipes for groups with existing output data. Native installers can remove that data. | Stage recovery separately; never overwrite new live work because another output is missing. Require conflict handling and retain the existing generation before replacement. |
| E15 | P0 | Protected-file checks run after arbitrary approved code. Detection is not rollback. Error presentation can still say recovered files are intact after a protected-content mismatch. | Prevent writes outside the execution boundary where an isolation provider exists; otherwise require explicit host-execution trust. Report damaged live files distinctly and recover from a retained checkpoint, never claim they are intact. |
| E16 | P2 | `analyse` measures immediate children of known output roots, so deep dependency trees are severely undercounted. Its deeper marker search is suppressed by a root `.git`, and its language labels exceed the reconstruction adapter set. | Share a project graph and publish lower bounds/incompleteness. Compute useful recursive sizes asynchronously, revalidate before action, and never equate recognized language with reclaim authority. |
| E17 | P0 | The benchmark's explicit `--work` accepts an existing directory and the successful cleanup removes that directory. Checking that a directory lies under itself does not prove it was created by the benchmark or is disposable. | Always create a uniquely owned child scratch directory. Refuse reuse of nonempty work directories; use an ownership marker and independent containment checks. |
| E18 | P2 | Command parsing and interaction are inconsistent. Most commands reorder flags around positional arguments, while `plan` directly uses `flag.Parse`. Guidance often requires restarting a command for missing decisions. | Parse into one typed intent, then resolve missing fields through one interaction layer. Keep explicit invalid arguments distinguishable from absent input. |
| E19 | P0 | Unsupported fidelity is broader than ordinary file bytes. Hardlink relationships, ACLs and sparse behavior are not all restored; ADS and special files can block. A copied venv can depend on an interpreter outside the workspace. | Publish and enforce a per-operation fidelity and runtime-compatibility contract before removal. Unsupported required fidelity means preserve/refuse, not a late warning. |
| E20 | P1 | Recipe inputs can be recorded as missing during trim. A later runner error cannot put back output bytes that were never retained. | Validate recovery availability before removal; missing evidence blocks recipe-only disposal and falls back to byte-preserving eviction. |

E11 does not mean Ebb deletes snapshots without any user instruction. Each `forget` still requires its ordinary confirmation. The problem is that the additional protection for removing the last recoverable copy can be defeated by stale accounting. This distinction matters when communicating severity.

E14 is a source-confirmed hazardous path, with installer behavior documented independently. Its exact full-stack reproduction remains a release test. E17 concerns the benchmark program, not an ordinary `ebb reclaim` invocation, and must not be reported as a production CLI defect.

### 6.3 Evidence anchors

All Ebb links below refer to the fixed baseline, not a moving branch.

- E01: [ecosystem detector](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/adapters/ecosystem/ecosystem.go), especially `Detect` and its root-only contract.
- E02, E18: [CLI composition and discovery](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/app.go), [init](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_init.go), [plan parser](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/commands.go), [default policy](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/policy/policy.go).
- E03, E20: [trim](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/lifecycle/trim.go), `writeTrimOpDir` and `copyRecipeInputs`.
- E04, E05: [action derivation](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/actiondefs.go), [ecosystem recipes](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/adapters/ecosystem/recipe.go), [manifest recipes](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/lifecycle/manifest.go).
- E06, E07, E09, E12, E14: [live restore](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/restore/liverestore.go), especially `selectTrimRecord`, `outputsAllPresent`, `sealedManifestApprover`, `groupDefinition` and `runRecipe`; [reclaim](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_reclaim.go), `runReclaimTrimStep`.
- E08: [route resolver](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/policy/resolve.go), `routeEntry` and group cancellation evidence; [carve-out logic](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/lifecycle/trim_carveout.go).
- E10, E11: [snapshot catalog](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/catalog/snapshot.go), `ListSnapshots` and `Unpin`; [retention intents](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/catalog/retention.go), `CompleteRetentionIntent`; [forget](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_forget.go), last-copy guard and `runForget`; [open target selection](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_open.go), `resolveOpenTarget`.
- E12: [session identity resolution](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/session.go), `resolveWorkspaceID`.
- E07, E13, E15: [action contracts](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/actions/defs.go), [runner](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/actions/run.go), [rebuild verification](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/restore/rebuild.go), and `emitOpenRebuildFailure` in the open CLI.
- E16: [shallow analyzer](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/analyse/shallow.go), [classification](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/analyse/classify.go).
- E17: [benchmark scratch ownership and cleanup](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/lab/bench/main.go), `resolveScratch`, `assertUnder` and the deferred cleanup in `run`.
- E19: [documented platform limitations](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/README.md), [inventory classification](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/inventory/scanner.go), and native adapters under `internal/platform`.

### 6.4 Testing and history limits

The repository contains many unit, adversarial and real-backend tests, but test count is not a correctness argument. The [verification script](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/scripts/verify.sh) runs formatting, vet, tests and Linux build/vet checks, and explicitly omits the race detector on the original development machine. The inspected baseline tree has no committed GitHub Actions workflow. An empty combined-status result is not proof that no external CI exists.

The [benchmark document](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/docs/BENCHMARKS.md) distinguishes synthetic marker-tree recreation from real dependency reinstalls. Some historical lab and design references are not in the current tree. Do not treat their cited pass counts as independently reproduced here, or repeat comments about old transport performance as current measurements.

Historical comments explicitly record root-only detection, suggestion-only enrollment, and differing action approval designs. These establish intended limitations. They do not justify calling a lost working directory or reversed recency selection intentional. The overhaul should preserve useful safety mechanisms while replacing duplicated contracts, rather than rewriting the storage engine for cosmetic consistency.
