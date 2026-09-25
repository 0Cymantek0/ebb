# Ebb product overhaul plan

Status: design selected provisionally; adversarial experiments and release-gate definition in progress. This document is committed incrementally. Proposed mechanisms are not existing production features.

Baseline: `0Cymantek0/ebb`, commit `1d0f7ea64af62afd97816432e4e65166a82920ae`. Research date: 2026-09-25. Branch: `research/automatic-workspace-overhaul-2026-09-25`. Production code, user workspaces and user vaults are outside this run's mutation scope. The spoken name "Abe" is interpreted as Ebb, not a rename request.

## 1. Product intent and non-negotiable constraints

Ebb should reduce the recurring effort of deciding what occupies developer storage, what can safely leave a working machine, and how to resume work later. The product must save decision-making time, not merely abbreviate shell commands.

Windows and Linux are the initial platforms. macOS is deferred. Cross-platform support means a tested capability contract on each supported operating system and filesystem, not identical native behavior or a promise that Windows environments become runnable Linux environments.

Ordinary users should not need to understand reconstruction policy to use the product. Discover projects, relationships and useful opportunities automatically where evidence permits. Configuration is an expert override, not the ordinary onboarding path. A nested Python manifest is not an extreme edge case.

A complete command executes directly when its decisions and authorization are supplied. An incomplete but valid interactive command enters a guided terminal interface and continues the same operation. Piped, JSON, CI and explicitly non-interactive invocations must never wait for hidden prompts. Invalid or ambiguous destructive arguments must not be guessed.

## 2. Feasibility and the guarantee boundary

A broadly useful, language-independent workspace lifecycle with progressively richer automatic understanding is feasible. Perfect semantic inference about every arbitrary working directory is not a defensible contract. Identical observable files can correspond to different user intent or hidden dependencies. Supporting a directory safely does not require knowing how to regenerate every file inside it.

Keep five claims separate:

1. Discovery identifies candidates and explains evidence. It does not authorize removal.
2. Exact content recovery requires retained, verified bytes and a surviving recovery location and key.
3. Reconstruction needs a recipe and its actual dependency and execution requirements. A lockfile is not an independent backup.
4. Application readiness requires additional evidence. A directory existing or an installer exiting zero is insufficient.
5. Space released on one volume is not necessarily space saved across the machine.

No confidence score, confirmation, metadata hash or finite test creates a universal no-loss guarantee. The supported failure model must be explicit. Loss of every recovery device/key, a compromised source host, unsupported fidelity and uncontrolled concurrent writers cannot be hidden behind marketing language.

A snapshot captures a point in time; it does not stop newer writes to the live tree that is later removed. A second-round counterexample already invalidated the provisional idea that a verified capture alone made subsequent eviction safe. Strict unattended removal requires an immutable managed object or a provider that enforces a stable capture/removal epoch. Cooperative user quiescence is a stated assumption, not an equivalent technical guarantee.

## 3. Work sequence and definition of done

The sequence is baseline archaeology, primary-source comparison, structurally different candidate designs, bounded adversarial experiments, surgical revisions, then implementation/release gates and final consistency review. The evidence trail must distinguish source findings, executed mechanism tests, proposed fixes and untested integration boundaries.

Done for this planning run means a source-linked plan, reproducible experiments, explicit rejected alternatives, failures that changed the design and named residual risks. It does not mean impossible to break. Production changes, real-restic lifecycle qualification, native Windows testing and user studies are separate work unless actually exercised and recorded.

Supporting research lives at [research.md](docs/research/ebb-overhaul/research.md). It includes the sources, transfer decisions and limitations of the comparison. This root document remains the product and implementation contract.

## 4. Evidence and review rules

Use stable identifiers for defects, decisions and experiments. Classify findings as source-confirmed, experimentally observed, proposed or unresolved. A source-shaped reduction is not execution of the Go application. A sequential fixture is not concurrency verification. A simulated crash between atomic model transitions is not power-loss testing.

No previous numeric Ebb-specific rating rubric was available. The proposed rubric uses veto gates first and ordinal judgments second. Do not invent a percentage probability of safety. Preserve negative results and failed assumptions instead of changing a test until the preferred architecture passes.

Review dimensions are recovery correctness, fidelity, project coverage, active user effort, actual storage economics, operational complexity and testability. A safety veto cannot be averaged away by attractive UX. A design may be selected while important release evidence remains unresolved.

## 5. Misconceptions that must not survive

The user's working project has `wavebox/requirements.txt`, a root `.venv`, and a buildless frontend. Ebb preserved everything and reported no gain. Advising a dummy root manifest was wrong. A dummy declaration is not evidence of reproducibility, and detecting a real manifest does not itself establish ownership of an environment.

Matching installed package versions does not prove that implementation files are unmodified. A successful rebuild today does not guarantee future downloads. Confirmation establishes consent, not truth.

Normal trim retains its removal plan, input copies and selected carve-out overlays, not the ordinary dependency-tree bytes it removes. `open --files-only` is not exact-byte recovery for a trim-only payload. Park and snapshot also honor resolved output omissions, so configured reconstruction groups prevent these from being unconditional directory images.

The earlier claim that Ebb had a strong recovery core and only weak inference was too generous. Useful verification and journaling coexist with recovery-selection and retention-accounting defects. Git is a reference for explicit state and recoverability, not evidence that any system never fails. Its own GC documentation warns about concurrent immediate pruning.

## 6. Baseline architecture and defect ledger

### 6.1 Actual request flow

The executable delegates to `internal/cli`. `runDiscovery` resolves the root, obtains filesystem/Git observations, scans inventory, annotates Git evidence, parses an Ebbfile or conservative defaults, and resolves routes. `planner` proposes routes; `lifecycle` captures/removes; `restore` has distinct whole-workspace and live-trim drivers. `catalog` records operations/snapshots. `storage/restic` owns backend invocation. `platform` supplies native identities and links. `analyse` separately ranks projects using shallow probes.

Read-only discovery should remain separate from removal authority. The defect is that different paths carry incompatible definitions of recipes, identity, recoverability and success. Improving the scanner alone cannot repair this.

### 6.2 Source-confirmed findings

Severity below is proposed release priority. P0 blocks a recovery/safety release, P1 breaks an ordinary promised workflow, P2 is a material usability or coverage problem. These are pinned-source findings, not claims that a Windows Ebb binary ran in this research session.

| ID | Priority | Finding and consequence | Required correction |
|---|---|---|---|
| E01 | P1 | Detection checks root markers and supports pnpm/npm/uv/limited pip suggestions. It misses the nested manifest. | Bounded recursive component discovery with provenance and completeness. |
| E02 | P1 | `init` suggests groups but writes no policy. Discovery uses no regenerate groups without an Ebbfile. | One discover/propose/review flow; do not require ordinary users to write policy. |
| E03 | P0 | Trim captures documents, inputs and overlays, not normal output bytes. A wrong recipe can make deletion irreversible. | Byte-backed eviction by default; explicitly weaker recipe-only disposal. |
| E04 | P1 | Built-in capture actions and live restore hardcode `WorkingRoot` to `.` despite `Regenerate.Root`. | One versioned recipe contract preserving cwd, paths, tools and environment. |
| E05 | P1 | UV uses `--locked` in one recipe and `--frozen` in trim; display also differs. | Derive execution and display from the same recipe. |
| E06 | P0 | Live restore synthesizes approval from the currently resolved tool/inputs instead of comparing previously approved identity. | Separate removal consent from execution consent; retain and recheck exact scope. |
| E07 | P1 | Live restore replaces network declaration with `NetworkAllowed`. Existing network fields do not enforce isolation. | Preserve declaration and report actual enforcement separately. |
| E08 | P0 | Carve-outs protect known preserved/Git-tracked evidence, not every arbitrary patch inside outputs. | Retain unknown output bytes; names and package versions are insufficient. |
| E09 | P1 | Reclaim trims groups separately; restore selects only the latest completed trim. | Per-group outstanding recovery obligations and parent batches. |
| E10 | P1 | Snapshot rows are ascending by date; named open chooses the first eligible row and calls it latest. | Explicit newest eligible selection with deterministic tie-break and visible time. |
| E11 | P0 | Last-copy `forget` guard counts historical rows that remain after backend deletion. | Count surviving eligible custody, not history rows; unify purge guards. |
| E12 | P1 | Identity resolution can fall back to the first live workspace with the same name; restore also uses historical paths. | Names are labels. Use workspace IDs/root generations and explicit rebinding. |
| E13 | P1 | Runner/resume output-exists checks do not establish content validity or application readiness. | Evidence-specific outcomes and contract validation. |
| E14 | P0 | When only some outputs exist, live restore can rerun recipes over existing new data. | Stage separately and resolve conflicts per generation; never silently clobber. |
| E15 | P0 | Protected-file checks occur after arbitrary code; detection is not rollback. Error wording can still claim files intact. | Isolation where available, explicit host-execution trust otherwise, truthful damage reporting. |
| E16 | P2 | Shallow sizes undercount deep trees; `.git` suppresses deeper marker search; labels exceed recipe support. | Shared graph, useful recursive accounting, explicit unknown/completeness states. |
| E17 | P0 | Benchmark `--work` accepts existing directories and cleanup removes that root; containment under itself proves no ownership. | Fresh exclusively owned child scratch dirs; reject unsafe reuse. |
| E18 | P2 | Flag parsing is inconsistent and missing inputs often require restarting. | Typed intents with guided resolution and one shared interaction protocol. |
| E19 | P0 | Fidelity gaps include hardlink/ACL/sparse semantics; ADS/special files may block. Venvs can need external interpreters. | Enforced per-operation fidelity and compatibility contract. |
| E20 | P1 | Trim can record recipe inputs as missing and defer failure until restore. | Recovery availability gate before removal; default to retained bytes. |

E11 still requires ordinary explicit `forget` confirmation. The defect concerns the additional last-recoverable-copy protection, not spontaneous deletion. E14's end-to-end installer reproduction remains a release test. E17 concerns the benchmark, not an ordinary reclaim invocation.

### 6.3 Immutable evidence anchors

Every Ebb link here is pinned to the baseline.

- E01: [ecosystem detector](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/adapters/ecosystem/ecosystem.go).
- E02/E18: [discovery](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/app.go), [init](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_init.go), [plan parser](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/commands.go), [policy](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/policy/policy.go).
- E03/E20: [trim](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/lifecycle/trim.go), `writeTrimOpDir` and `copyRecipeInputs`.
- E04/E05: [action derivation](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/actiondefs.go), [ecosystem recipes](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/adapters/ecosystem/recipe.go), [manifest](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/lifecycle/manifest.go).
- E06/E07/E09/E12/E14: [live restore](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/restore/liverestore.go), especially `selectTrimRecord`, `outputsAllPresent`, `sealedManifestApprover`, `groupDefinition`; [reclaim](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_reclaim.go), `runReclaimTrimStep`.
- E08: [resolver](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/policy/resolve.go), [carve-outs](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/lifecycle/trim_carveout.go).
- E10/E11: [snapshot catalog](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/catalog/snapshot.go), `ListSnapshots`/`Unpin`; [retention](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/catalog/retention.go), `CompleteRetentionIntent`; [forget](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_forget.go); [open selection](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/cmd_open.go), `resolveOpenTarget`.
- E12: [session](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/cli/session.go), `resolveWorkspaceID`.
- E07/E13/E15: [action contracts](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/actions/defs.go), [runner](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/actions/run.go), [rebuild](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/restore/rebuild.go), `emitOpenRebuildFailure` in the open CLI.
- E16: [shallow analysis](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/analyse/shallow.go), [classification](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/analyse/classify.go).
- E17: [benchmark](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/lab/bench/main.go), `resolveScratch`, `assertUnder`, cleanup in `run`.
- E19: [documented limitations](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/README.md), [inventory](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/internal/inventory/scanner.go), native platform adapters.

### 6.4 Test and history limits

The [verification script](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/scripts/verify.sh) runs formatting, vet, tests and Linux build/vet checks, but explicitly omits the race detector on the original development machine. No GitHub Actions workflow is committed in the inspected baseline. Empty combined-status results do not prove that no external CI exists.

The [benchmark document](https://github.com/0Cymantek0/ebb/blob/1d0f7ea64af62afd97816432e4e65166a82920ae/docs/BENCHMARKS.md) distinguishes synthetic marker-tree reconstruction from real dependency installs. Some referenced labs/design documents are absent from the current tree. Their historical pass counts were not independently reproduced here.

Comments explicitly identify root-only detection and suggestion-only enrollment as intended limitations. They do not justify dropped working-directory fields or reversed recency selection. Preserve useful mechanisms while replacing duplicated contracts, rather than rewriting the storage engine for cosmetic consistency.

## 7. What established systems contribute

The detailed [source survey](docs/research/ebb-overhaul/research.md) covers Git, git-annex, DVC, restic, Borg, Kopia, Nix, Bazel, BuildKit, native package/build tools, ReproZip, direnv, Watchman, terminal libraries and adjacent disk-cleanup tools. It is a representative architectural survey, not an exhaustive catalog.

| Precedent | Transfer into Ebb | Boundary not to copy or overclaim |
|---|---|---|
| Git/git-annex | Stable content identity, explicit history, liveness roots, verified copy policy. | Names and historical location records do not prove custody; Git is not infallible. |
| DVC | Separate workspace materialization, content cache and declared run inputs. | A live hardlink is not an independent backup; users should not have to author pipelines. |
| restic/Borg/Kopia | Retained immutable evidence, bounded content I/O, verified storage, rebuildable indexes. | Encryption does not prevent deletion of every copy; do not invent another backup engine. |
| Nix | Retain complete required closures through explicit roots. | Migrating every project into a managed build system is not acceptable onboarding. |
| Bazel/BuildKit | Normalize operations into a graph and distinguish action results from stored objects. | Sandboxes and caches only cover their declared/enforced contract. |
| uv/npm/Cargo/CMake/Gradle | Consume native structured facts and honor versioned owner semantics. | Queries can execute configuration; conventional names do not establish ownership. |
| ReproZip | Optional observation of an actual user-invoked successful command. | One trace covers one execution; Linux tracing is not a universal Windows solution. |
| Watchman | Incremental indexing with rescan on lost synchronization. | Notifications are invalidation hints, not removal evidence. |
| Bubble Tea/Huh/tview | Organized guided interaction, reducer-style state and accessible fallback. | A UI framework must not own deletion logic or hide required approvals. |
| gdu/npkill | Useful fast scanning/selection baselines for usability comparisons. | A new picker plus a remove command is not meaningful differentiation. |
| SQLite testing | Systematic fault injection and recovery checks. | Database transactions do not atomically include filesystem and vault operations. |

## 8. Candidate architectures and decision

### A. Universal inference followed by recipe-only deletion

Recursively read manifests, scripts and installed metadata; perhaps use an LLM to connect outputs to recipes; delete apparently regenerable content. This gives a compelling demo and potentially small retained storage.

Rejected as the default. Locally patched dependencies, unobserved runtime branches, disappearing registries and ambiguous ownership defeat the evidence model. Adding a confidence threshold changes how often errors occur, not whether removed bytes can be recovered. A human yes does not fix missing bytes.

### B. Require a fully managed hermetic environment

Capture toolchain and input closure in a Nix/Bazel/container-style model and require builds to run through it. This provides stronger provenance for participating projects.

Rejected as mandatory onboarding. Converting legacy repositories, proprietary tools, native Windows software and arbitrary data workflows would cost more effort than Ebb saves. Retain this as an optional high-assurance provider and future learning mode, not a gate for basic use.

### C. Recovery-first lifecycle with an evidence graph

Generic file identity, inventory, custody and restoration work without a language adapter. Semantic adapters improve suggestions, cost estimation and optional reconstruction. Default eviction retains original content. A recipe never becomes the only recovery mechanism unless the user explicitly chooses a weaker disposal contract.

Selected, subject to native qualification and product-value testing. This avoids making recognition accuracy the sole defense against permanent loss. It does not remove disruption risk, writer consistency requirements, fidelity limits or storage costs.

### Proposed assessment

| Dimension | A: infer/delete | B: managed-only | C: recovery-first |
|---|---|---|---|
| Ordinary legacy adoption | Low setup, hidden risk | High migration cost | Low setup for supported file types |
| Unknown language | Guesses or stops | Requires integration | Can inventory and retain bytes |
| Wrong ownership guess | Potential permanent loss | Constrained inside managed scope | Bytes retained, but interruption still possible |
| Storage reduction | Often high because bytes discarded | Depends on managed caches/closure | Must measure compression, dedup or offload |
| Safety gate | Fails as universal default | Plausible within narrower system | Plausible within explicit custody/quiescence contract |
| Product fit | Attractive but unsafe promise | Too much onboarding | Best match, value still unmeasured |

These are engineering judgments, not empirical ratings or success probabilities. Any surviving data-loss counterexample blocks release of the affected path even if every other dimension looks good.

## 9. User-facing operation contract

Keep a small vocabulary. `reclaim` removes selected local material under a stated recovery mode while leaving the project usable after restoration. `restore` returns outstanding groups. `park` shelves a whole workspace. `open` reopens it. `purge` deliberately ends recovery obligations. Existing advanced verbs may remain compatibility aliases, but must use the same engine.

Internally distinguish:

- **Recoverable eviction:** original bytes and required supported metadata are verified in Ebb-controlled custody before local removal. Default choice.
- **Native cache cleanup:** delegate to the cache owner using a versioned provider. Report that this is cache disposal, not exact Ebb-backed undo. Never count an independently prunable package cache as Ebb's only recovery copy.
- **Recipe-only disposal:** intentionally weaker expert mode. Requires explicit acceptance of losing exact output bytes. Generic `--yes`, age, a lockfile and an LLM score must not enable it accidentally.
- **Preserve/refuse:** unsupported fidelity, unsafe writers, ambiguous scope or inadequate recovery/headroom. Explain a useful alternative in the same interaction.

No automatic escalation from dependency eviction to whole-project park, from byte-backed recovery to recipe-only disposal, or from cold storage to permanent purge.

### The user's actual project

Discover `wavebox/requirements.txt` anywhere within the selected boundary. Read `.venv/pyvenv.cfg` and installed metadata as observations, not proof. Treat the install line in `OPEN_ME.bat` as a candidate relationship without executing it. A buildless `frontend/` needs no invented Node manifest.

The ordinary proposal can say: retain and evict the 447.9 MiB environment, return it from original bytes later, and separately report the recorded interpreter requirement. Leave `frontend`, source, `.env`, data, logs and scratch unchanged by default. Larger opaque data may be offered as a separate offload/park choice, never inferred disposable from names.

If multiple environments or requirement files compete, retain multiple hypotheses and offer one understandable choice only when it materially changes the operation. Do not ask the user to transcribe TOML. Where ownership remains ambiguous, byte-backed whole-scope shelving can still be offered if its boundaries and writer/fidelity gates are satisfied.

Restoring at a different path or on another OS changes the runtime claim. Recover portable content where supported; flag environment repair separately. Do not say that copying a venv makes it portable.

## 10. Provisional invariants and red-team revisions

D01: Discovery and AI assistance can propose, never authorize removal.

D02: A recovery obligation names an exact workspace/group generation, retained content and fidelity contract, eligible locations, verification evidence and key requirements. It is not synonymous with a snapshot row.

D03: Byte-backed eviction never silently becomes recipe-only. Unknown content in selected output trees is retained, including private patches, added files and empty directories.

D04: Capture, verification and removal must refer to the same stable epoch. Immutable managed objects or enforceable exclusion support strict unattended operation. Cooperative quiescence must be explicit. A snapshot or quarantine rename alone is insufficient.

D05: Names are labels. Authorization binds to workspace ID, native root identity, generation and plan digest. Rebinding a path or name requires a new review.

D06: History is append-only evidence, while liveness is current custody plus active obligations/leases. GC must consult the latter under the same coordination contract as eviction and recovery.

D07: Existing live data is a conflict, not permission to overwrite. Restoration publishes staged validated content through no-replace semantics or a separately authorized, journaled replacement that retains the previous generation.

D08: Same-volume savings and cross-volume offload are reported separately. Retaining incompressible unique content locally may save nothing.

D09: Files recovered, metadata recovered, recipe executed and application health checked are distinct outcomes. Failed protected-content checks cannot emit `files-intact`.

D10: Direct CLI, TUI, JSON and batch commands consume the same typed intent and operation events. They do not reimplement recovery semantics.

D11: Two logical copies on the same disk are not independent protection from disk loss. Unknown failure domains remain unknown.

D12: Multi-component operations record partial completion per component. They promise resumability, not impossible atomicity across unrelated filesystem objects and volumes.

D13: After losing the catalog, mutually consistent vault records alone do not prove continuity of authenticity against an adversary capable of replacing both. Use an independent trusted checkpoint where that threat matters, or explicitly re-establish trust.

### Executed counterexamples so far

Local experiments have observed unchanged package metadata with changed implementation bytes, unchanged inode/size/mtime with different bytes, a hardlink backup changing with the live file, lexical containment escaping through an ancestor symlink, an open descriptor writing after quarantine rename, and empty output directories passing existence checks.

A reduced SQL/decision model reproduces oldest-first snapshot selection, latest-trim omission and historical-row/custody divergence. These are not Go CLI integration runs.

A finite single-object model explored 20 states and 42 transitions without violating its custody/read-lease invariant. Removing durability, obligation protection or read leases produced counterexamples. This is evidence for the model only. It excludes torn writes, arbitrary external writers, multiple objects and native filesystem behavior.

The second review then broke four stronger assumptions: a verified backup can precede a newer live generation; two copies can share one failure domain; a batch can finish only one component before interruption; and forged manifest/seal pairs can be mutually consistent after an independent witness is lost. D04 and D11-D13 record the resulting corrections. No “unbreakable” claim follows from the passing finite model.

The next document revision will bind the detailed data model, state transitions, terminal workflow, implementation phases and acceptance tests to these invariants and publish the executable evidence.
