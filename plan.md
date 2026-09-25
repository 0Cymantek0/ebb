# Ebb product overhaul plan

Status: research-backed design proposal for implementation review. Production overhaul has not been implemented or release-qualified. This document was developed through incremental commits and three rounds of bounded adversarial experiments.

Baseline: `0Cymantek0/ebb`, commit `1d0f7ea64af62afd97816432e4e65166a82920ae`. Research date: 2026-09-25. Branch: `research/automatic-workspace-overhaul-2026-09-25`. Production code, user workspaces and user vaults are outside this run's mutation scope. The spoken name "Abe" is interpreted as Ebb, not a rename request.

Reading order: sections 1-5 define the product; section 6 records existing defects; sections 7-10 explain the architectural choice; sections 11-17 specify implementation and interaction; sections 18-22 cover delivery, tests, product value, evidence and remaining risks.

Supporting artifacts: [primary-source research](docs/research/ebb-overhaul/research.md), [experiment source](docs/research/ebb-overhaul/redteam.py), [second round](docs/research/ebb-overhaul/round2.py), [third round](docs/research/ebb-overhaul/round3.py), [recorded evidence](docs/research/ebb-overhaul/evidence.json), [third-round result](docs/research/ebb-overhaul/round3.json), [claim ledger](docs/research/ebb-overhaul/ledger.tsv).

## 1. Product intent and non-negotiable constraints

Ebb should reduce the recurring effort of deciding what occupies developer storage, what can safely leave a working machine, and how to resume work later. The product must save decision-making time, not merely abbreviate shell commands.

Windows and Linux are the initial platforms. macOS is deferred. Cross-platform support means a tested capability contract on each supported operating system and filesystem, not identical native behavior or a promise that Windows environments become runnable Linux environments.

Ordinary users should not need to understand reconstruction policy to use the product. Discover projects, relationships and useful opportunities automatically where evidence permits. Configuration is an expert override, not the ordinary onboarding path. A nested Python manifest is not an extreme edge case.

A complete command executes directly when its decisions and authorization are supplied. An incomplete but valid interactive command enters a guided terminal interface and continues the same operation. Piped, JSON, CI and explicitly non-interactive invocations must never wait for hidden prompts. Invalid or ambiguous destructive arguments must not be guessed.

The desired outcome is concrete: a developer can see useful storage options across existing projects, choose a small number of understandable actions, recover the selected material later without reconstructing its history, and know what is still available. Ebb must not force that developer to become a build-system, backup or filesystem expert.

## 2. Feasibility and the guarantee boundary

A broadly useful, language-independent workspace lifecycle with progressively richer automatic understanding is feasible. Perfect semantic inference about every arbitrary working directory is not a defensible contract. Identical observable files can correspond to different user intent or hidden dependencies. Supporting a directory safely does not require knowing how to regenerate every file inside it.

Keep five claims separate:

1. Discovery identifies candidates and explains evidence. It does not authorize removal.
2. Exact content recovery requires retained, verified bytes and a surviving recovery location and key.
3. Reconstruction needs a recipe and its actual dependency and execution requirements. A lockfile is not an independent backup.
4. Application readiness requires additional evidence. A directory existing or an installer exiting zero is insufficient.
5. Space released on one volume is not necessarily space saved across the machine.

No confidence score, confirmation, metadata hash or finite test creates a universal no-loss guarantee. The supported failure model must be explicit. Loss of every recovery device/key, a compromised source host, unsupported fidelity and uncontrolled concurrent writers cannot be hidden behind marketing language.

A snapshot captures a point in time; it does not stop newer writes to the live tree that is later removed. A second-round counterexample invalidated the provisional idea that a verified capture alone made subsequent eviction safe. Strict unattended removal requires an immutable managed object or a provider that enforces a stable capture/removal epoch. Cooperative user quiescence is a stated assumption, not an equivalent technical guarantee.

The product promise should be: automate discovery and recoverable storage decisions within an explicit, tested contract, while preserving or refusing anything outside that contract. It should not be: understand all human intent or make any arbitrary application portable.

## 3. Work sequence and definition of done

The sequence is baseline archaeology, primary-source comparison, structurally different candidate designs, bounded adversarial experiments, surgical revisions, then implementation/release gates and a final consistency review. The evidence trail distinguishes source findings, executed mechanism tests, proposed fixes and untested integration boundaries.

Done for this planning run means a source-linked plan, reproducible experiments, explicit rejected alternatives, failures that changed the design and named residual risks. It does not mean impossible to break. Production changes, real-restic lifecycle qualification, native Windows testing and user studies are separate work unless actually exercised and recorded.

Supporting research lives at [research.md](docs/research/ebb-overhaul/research.md). It contains source-specific observations and transfer decisions. This root document remains the product and implementation contract.

## 4. Evidence and review rules

Use stable identifiers for defects, decisions and experiments. Classify findings as source-confirmed, experimentally observed, proposed or unresolved. A source-shaped reduction is not execution of the Go application. A sequential fixture is not concurrency verification. A simulated crash between atomic model transitions is not power-loss testing.

No previous numeric Ebb-specific rating rubric was available. The proposed rubric uses veto gates first and ordinal judgments second. Do not invent a percentage probability of safety. Preserve negative results and failed assumptions instead of changing a test until the preferred architecture passes.

Review dimensions are recovery correctness, fidelity, project coverage, active user effort, actual storage economics, operational complexity and testability. A safety veto cannot be averaged away by attractive UX. A design may be selected while important release evidence remains unresolved.

Evidence maturity uses a separate 0-4 scale: 0 means absent; 1 means specified; 2 means supported by relevant source/contract evidence; 3 means exercised by a bounded mechanism experiment; 4 means qualified through the required native product integration. This is not a product-quality score. A model reaching level 3 does not advance the whole product to level 3 or 4.

## 5. Misconceptions that must not survive

The user's working project has `wavebox/requirements.txt`, a root `.venv`, and a buildless frontend. Ebb preserved everything and reported no gain. Advising a dummy root manifest was wrong. A dummy declaration is not evidence of reproducibility, and detecting a real manifest does not itself establish ownership of an environment.

Matching installed package versions does not prove that implementation files are unmodified. A successful rebuild today does not guarantee future downloads. Confirmation establishes consent, not truth.

Normal trim retains its removal plan, input copies and selected carve-out overlays, not the ordinary dependency-tree bytes it removes. `open --files-only` is not exact-byte recovery for a trim-only payload. Park and snapshot also honor resolved output omissions, so configured reconstruction groups prevent these from being unconditional directory images.

The earlier claim that Ebb had a strong recovery core and only weak inference was too generous. Useful verification and journaling coexist with recovery-selection and retention-accounting defects. Git is a reference for explicit state and recoverability, not evidence that any system never fails. Its [GC documentation](https://git-scm.com/docs/git-gc) warns about concurrent immediate pruning.

The claim that a few commands cannot constitute a valuable product is also too absolute. Command count is not a useful measure either way. The real test is whether Ebb removes recurring decisions, mistakes and recovery effort enough to justify its setup, storage and maintenance costs.

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
| Git/git-annex | Stable content identity, explicit history, liveness roots, verified copy policy. | Names and historical location records do not prove custody. |
| DVC | Separate workspace materialization, content cache and declared run inputs. | A live hardlink is not an independent backup; users should not need pipelines. |
| restic/Borg/Kopia | Retained immutable evidence, bounded content I/O, verified storage, rebuildable indexes. | Encryption does not prevent deletion of every copy; do not invent another backup engine. |
| Nix | Retain required closures through explicit roots. | Migrating every project into a managed build system is not acceptable onboarding. |
| Bazel/BuildKit | Normalize operations into a graph and distinguish action results from stored objects. | Sandboxes and caches cover only their declared/enforced contract. |
| Native tools | Consume structured facts and honor versioned owner semantics. | Queries can execute configuration; conventional names do not establish ownership. |
| ReproZip | Observe an actual user-invoked successful command when requested. | One trace covers one execution; Linux tracing is not a Windows implementation. |
| Watchman | Incremental indexing with rescan on lost synchronization. | Notifications are invalidation hints, not removal evidence. |
| Bubble Tea/Huh/tview | Organized interaction, reducer-style state and accessible fallback. | A UI framework must not own deletion logic or hide approvals. |
| gdu/npkill | Fast scanning/selection baselines for usability comparisons. | A new picker plus removal is not meaningful differentiation. |
| SQLite testing | Systematic fault injection and recovery checks. | Database transactions do not atomically include filesystem/vault operations. |

## 8. Candidate architectures and decision

### A. Universal inference followed by recipe-only deletion

Recursively read manifests, scripts and installed metadata; perhaps use an LLM to connect outputs to recipes; delete apparently regenerable content. This gives a compelling demo and potentially small retained storage.

Rejected as the default. Locally patched dependencies, unobserved runtime branches, disappearing registries and ambiguous ownership defeat the evidence model. Adding a confidence threshold changes how often errors occur, not whether removed bytes can be recovered. A human yes does not fix missing bytes.

### B. Require a fully managed hermetic environment

Capture toolchain and input closure in a Nix/Bazel/container-style model and require builds to run through it. This provides stronger provenance for participating projects.

Rejected as mandatory onboarding. Converting legacy repositories, proprietary tools, native Windows software and arbitrary data workflows would cost more effort than Ebb saves. Retain this as an optional high-assurance provider and future learning mode, not a gate for basic use.

### C. Recovery-first lifecycle with an evidence graph

Generic identity, inventory, custody and restoration work without a language adapter. Semantic adapters improve suggestions, cost estimation and optional reconstruction. Default eviction retains original content. A recipe never becomes the only recovery mechanism unless the user explicitly chooses a weaker disposal contract.

Selected, subject to native qualification and product-value testing. This avoids making recognition accuracy the sole defense against permanent loss. It does not remove disruption risk, writer consistency requirements, fidelity limits or storage costs.

### Proposed assessment

| Dimension | A: infer/delete | B: managed-only | C: recovery-first |
|---|---|---|---|
| Ordinary legacy adoption | Low setup, hidden risk | High migration cost | Low setup for supported file types |
| Unknown language | Guesses or stops | Requires integration | Can inventory and retain bytes |
| Wrong ownership guess | Potential permanent loss | Constrained inside managed scope | Bytes retained, interruption still possible |
| Storage reduction | Often high because bytes discarded | Depends on managed caches/closure | Must measure compression, dedup or offload |
| Safety gate | Fails as universal default | Plausible within narrower system | Plausible within explicit custody/quiescence contract |
| Product fit | Attractive but unsafe promise | Too much onboarding | Best match, value still unmeasured |

These are engineering judgments, not empirical success probabilities. A surviving data-loss counterexample blocks the affected path even when every other dimension looks good.

## 9. User-facing operation contract

Keep a small vocabulary. `reclaim` removes selected local material under a stated recovery mode while leaving the project available for resumption. `restore` returns outstanding groups. `park` shelves a workspace. `open` reopens it. `purge` deliberately ends recovery obligations. Existing advanced verbs can remain compatibility aliases but must use the same engine.

Distinguish four modes internally and explain them in ordinary language:

- **Recoverable eviction:** original bytes and required supported metadata are verified in Ebb-controlled custody before local removal. Default choice.
- **Native cache cleanup:** delegate to the cache owner through a versioned provider. This is cache disposal, not exact Ebb-backed undo. An independently prunable package cache is never Ebb's only recovery copy.
- **Recipe-only disposal:** intentionally weaker expert mode. Requires explicit acceptance of losing exact output bytes. Generic `--yes`, age, a lockfile and an LLM score must not enable it accidentally.
- **Preserve/refuse:** unsupported fidelity, unsafe writers, ambiguous scope or inadequate custody/headroom. Explain an alternative in the same interaction.

No automatic escalation from dependency eviction to whole-project park, from byte-backed recovery to recipe-only disposal, or from cold storage to permanent purge.

### The user's actual project

Discover `wavebox/requirements.txt` anywhere within the selected boundary. Read `.venv/pyvenv.cfg` and installed metadata as observations, not proof. Treat the install line in `OPEN_ME.bat` as a candidate relationship without executing it. A buildless `frontend/` needs no invented Node manifest.

The ordinary proposal can offer to retain and evict the environment, return it from original bytes later, and separately report its interpreter requirement. The supplied inspection showed 447.9 MiB for `.venv`; that is an input observation, not a newly measured net saving. Leave frontend, source, `.env`, data, logs and scratch unchanged by default. Larger opaque data can be offered as a separate offload/park choice, never inferred disposable from names.

If several environments or requirement files compete, retain the competing hypotheses. Ask one understandable question only when the answer changes the operation. Do not ask the user to transcribe TOML. Ambiguous ownership can still permit byte-backed whole-scope shelving when its boundaries and writer/fidelity gates are satisfied.

Restoration at a different path or on another OS changes the runtime claim. Recover compatible content and flag environment repair separately. Copying a venv is not a portability solution.

## 10. Invariants and revisions

D01: Discovery and optional AI assistance can propose, never authorize removal.

D02: A recovery obligation names an exact workspace/group generation, retained content and fidelity contract, eligible locations, verification evidence and key requirements. It is not synonymous with a snapshot row.

D03: Byte-backed eviction never silently becomes recipe-only. Unknown content in selected output trees is retained, including private patches, added files and empty directories.

D04: Capture, verification and removal refer to the same stable epoch. Immutable managed objects or enforceable exclusion support strict unattended operation. Cooperative quiescence is explicit. A snapshot or quarantine rename alone is insufficient.

D05: Names are labels. Authorization binds to workspace ID, native root identity, generation and plan digest. Rebinding a path or name requires new review.

D06: History is evidence; liveness is current custody plus obligations and read leases. GC consults the latter under the same coordination contract as eviction/recovery.

D07: Existing live data is a conflict, not permission to overwrite. Materialization publishes staged validated bytes using no-replace semantics or a separately authorized, journaled replacement retaining the previous generation.

D08: Same-volume savings and cross-volume offload are reported separately. Retaining incompressible unique content locally may save nothing.

D09: Files recovered, metadata recovered, recipe executed and health checked are distinct outcomes. Failed protected-content checks cannot emit `files-intact`.

D10: Direct CLI, TUI, JSON and batch commands consume the same typed intent and operation events. They do not reimplement recovery semantics.

D11: Two logical copies on one disk are not independent protection from disk loss. Unknown failure domains remain unknown.

D12: Multi-component operations record partial completion by component. They promise resumability, not atomicity across unrelated objects and volumes.

D13: After losing an independent witness, mutually consistent replacement descriptions do not prove continuity of authenticity. The R19 logical counterexample assumes an adversary able to replace trusted descriptions or a compromised provider/key; it does not break restic encryption. Preserve an independent trusted checkpoint where this threat matters, or explicitly re-establish trust.

D14: Byte materialization and reconstruction are different operations. Staging followed by rename is not universally valid for rebuilt outputs containing absolute paths. Use the intended logical path inside a qualified execution provider, a proven relocatable recipe, or explicitly trusted host repair with checkpoints. Never claim that a generic temporary directory is sufficient.

## 11. Core data model and module boundaries

### 11.1 Types before implementation

| Type | Required information | Why it exists |
|---|---|---|
| Workspace | Stable ID, display names, registered scopes, root generations, local bindings. | Prevent same-name/path history confusion. |
| Scope | Root handle identity, volume, allowed descendants, excluded boundaries, fidelity requirements. | Define what the user authorized, independent of labels. |
| Component | Stable ID within a workspace, kind, roots, linked components, observations. | Represent nested/polyglot projects without assuming one root manifest. |
| Artifact group | Exact root-relative outputs, physical identities, ownership evidence, shared references, generation. | Separate a proposed logical group from files that may change. |
| Observation | Source/provider version, fact, scope, time, digest where applicable, completeness, trust class. | Preserve the difference between observed, inferred and unknown. |
| Relation | Input/output/runtime/contains/shared-reference edge, evidence IDs, competing alternatives. | Model relationships without collapsing a guess into truth. |
| Recipe | Schema version, argv, cwd, input closure, outputs, toolchain identity, environment contract, network requirements, execution provider, path sensitivity. | One representation across capture, display, restore and approval. |
| Recovery contract | Generation, mode, content tree reference, metadata fidelity, runtime assumptions, custody requirements. | State precisely what can be recovered. |
| Custody location | Store ID, content references, verification scope/time, availability, key reference, failure-domain evidence. | Avoid counting deleted rows or shared mutable links as copies. |
| Obligation | Recovery contract ID, active/released state, explicit release reason and event. | Keep needed recovery content live. |
| Operation | ID, idempotency key, reviewed plan digest, resource reservations, durable phase, per-component outcomes. | Reconcile interruptions without guessing. |
| Consent | Principal, operation/mode/scope, accepted assumptions, plan digest, generation, expiry/review policy. | Prevent broad or stale approval from authorizing a different action. |
| Lease | Operation, content/store/resource, fencing generation, renewal/release state. | Coordinate Ebb actors and protect readers against Ebb GC. |
| Outcome | Files/fidelity/reconstruction/health evidence, released bytes by volume, warnings, next available actions. | Prevent success wording from exceeding evidence. |

The component graph may contain legitimate cycles. Do not reject a workspace because two components reference one another. A particular execution plan must either order an acyclic action graph, consolidate an atomic owner-defined operation, or explain why that action cannot be automated.

Paths must be represented losslessly for the source platform. Linux byte filenames and Windows case/name rules cannot be reduced to one lossy lowercase string. Use escaped display names separately from raw identity. Reject incompatible destination names before publication; never silently sanitize two names into one.

### 11.2 Application service contract

The following are design signatures, not new implemented APIs:

```text
Observe(scope, budget) -> observations + completeness
Prepare(intent, observations, answers) -> Plan | Questions | Blocked
Accept(plan_digest, explicit_consent) -> reviewed operation token
Execute(operation_token) -> durable events + outcome
Resume(operation_id) -> Questions | events + outcome
Restore(obligation_selection, destination) -> Plan | Questions | Blocked
Release(obligation_selection, consent) -> release operation
```

Only the application service can issue a removal-capable operation token after deterministic validation. Plugin findings, UI events and serialized config are data, never authority. A token is scoped and revalidated; it is not a bearer token that bypasses generation checks indefinitely.

Use a modular Go application, not microservices. Keep observation/adapters, pure planning, lifecycle coordination, storage, native filesystem capabilities and presentation as distinct responsibilities. Existing packages can evolve toward these boundaries without a simultaneous wholesale rename.

The CLI/TUI layer owns parsing, display and answering typed questions. It must not instantiate a second recipe engine or recursively invoke interactive command handlers. The storage adapter never decides human intent. The observation adapter never calls remove. The coordinator owns cross-resource ordering and recovery.

### 11.3 Durable schema

Add explicit schema versions to new manifests and operation documents. Persist recipes and recovery contracts once, then refer to their digest. Unknown required fields/features fail before mutation. Optional observations can be ignored only when they cannot alter safety meaning.

Do not use one `pinned` boolean as the entire retention model. Maintain obligations, custody availability/tombstones and active leases separately. Index by workspace ID, group ID and generation so `restore` finds all outstanding groups, not just the last operation. Use a monotonically ordered local event/sequence identifier rather than wall time alone for operation ordering; timestamps remain display/evidence fields.

Store changes use compare-and-swap/fencing and explicit transactions. A reader or writer that loses its lease cannot continue using an old authorization. The protocol must detect catalog rollback or generation mismatch rather than blindly treating an older row as current truth.

## 12. Automatic discovery without mandatory configuration

### 12.1 Observation pipeline

Start from an explicit path, current working directory or previously enrolled project roots. Do not scan every mounted drive or upload source automatically. First render the selected scope, then progressively enrich it.

1. Establish native boundaries: volume, real directory versus reparse/link, nested mounts, vault overlap and linked worktree administration. Ambiguous aliases are shown and bound explicitly.
2. Inventory entries without following external links or hydrating cloud placeholders. A budget cutoff produces an incomplete observation, not absence.
3. Find component markers recursively at arbitrary supported depths. Separate cheap metadata discovery from the full inventory required for mutation. Skip dependency interiors for marker inference when justified, but still inventory selected bytes before removal.
4. Parse supported manifests and existing generated metadata without executing project code. Record malformed content as a warning and retain the files.
5. Gather environment and output observations, including `pyvenv.cfg`, installed package metadata, lockfiles, out-of-tree build references, local dependency paths and known native cache ownership.
6. Construct candidate relations with source-specific provenance. Prefer explicit structured relationships, then previously observed execution evidence, then static script references, then name/location hints. Hints remain hypotheses.
7. Plan useful actions from recovery capability, fidelity, storage cost and approved scope. Do not require a proven rebuild recipe for byte-backed eviction.

A root `.git` must not stop discovery of nested components. Conversely, finding a manifest in test fixtures or vendored examples must not promote it to the workspace's build owner. Multiple nested repositories remain explicit boundaries with shared references represented, not silently flattened.

### 12.2 Coverage strategy

The generic file lifecycle must work independently of the following semantic adapter rollout. These rows are planned capabilities, not claims they already exist.

| Family | Evidence to consume | Conservative boundary |
|---|---|---|
| Python/pip/uv/Poetry/Conda | Nested manifests, lockfiles, environment metadata, interpreter references, local/editable installs. | No environment inferred disposable from name/version matching. |
| JavaScript/TypeScript | Workspace manifests, package-manager lockfiles/config, output directories and local links. | Respect hoisting/shared stores; buildless sites remain source. |
| Rust | Cargo manifests/workspace metadata and actual target-directory configuration. | `target` may be redirected/shared or contain custom data. |
| Go | `go.mod`, `go.work`, local replacements and separately owned caches. | Do not hand-delete shared global caches. |
| C/C++ | Existing CMake file-API replies, build trees, compile database as evidence. | Reading metadata is distinct from running configuration. |
| JVM/Android | Gradle/Maven structure and existing generated metadata. | Evaluating Gradle scripts is execution, not passive inspection. |
| .NET | Project/solution references and known generated output observations. | Evaluated build properties/tasks need an explicit execution boundary. |
| Ruby/PHP/Dart and other tools | Manifests/lockfiles through small versioned adapters. | Unknown semantics fall back to byte retention. |
| ML/data/game/research workspaces | Datasets, models, checkpoints, native assets, opaque directories. | Large size or the word cache never implies reproducibility. |
| No manifest/unknown language | Inventory, relationships, custody, user scope. | Offer file-backed shelving/offload, not fabricated recipes. |

The public capability report has separate columns for recognized, relationship evidence available, exact-byte eviction supported, and recipe reconstruction supported. Avoid a single misleading supported-language checkbox.

### 12.3 Native metadata and optional learning

Use owner APIs only through versioned observation capabilities. Reading an existing CMake reply is different from invoking CMake. Cargo metadata options need explicit side-effect/offline review. Gradle initialization/configuration can execute code. Sources and detailed boundaries are in the research document.

An optional future learning command may observe a user-selected build/run and retain the command, cwd, environment requirements and observed file/tool dependencies. It never executes `OPEN_ME.bat` simply because the file exists. Trace results carry run/input coverage and do not authorize deletion of unseen files or certify all future execution branches.

An optional local model may rank hypotheses or explain unknown layouts. Model output is untrusted data with no filesystem authority. Sending paths, source, environment values or secrets to a remote model requires explicit user approval and is unnecessary for the core product.

### 12.4 Configuration policy

Store ordinary discovered facts and approved choices in Ebb's local catalog, keyed by workspace identity and generation. Do not require an Ebbfile in every repository. A user-visible policy file is useful for expert overrides, team conventions and unusual relationships, but imported/repository-provided execution settings begin untrusted.

Preserve rules can make a plan more conservative. No configuration file, auto-generated declaration or tool suggestion can silently weaken custody, expand outside the selected root or enable host code execution. Conflicting declarations are explained in the TUI with the files they affect.

## 13. Capture, eviction, recovery and retention protocol

### 13.1 Stable scope and resource ownership

Before mutation, resolve the full resource set: workspace/group generations, native file identities, output ancestors, selected vault and its volume, shared artifacts and active operations. Reserve overlapping resources in a deterministic order. Separate catalog serialization from native exclusion; an Ebb lock does not stop an unrelated editor or build process.

Strict unattended mode is allowed only when the owner/provider can guarantee the required stable epoch. A fresh scan with no observed open handles is not proof. If ordinary files require cooperative quiescence, show that assumption once for the scope and retain it in the receipt. Known writers block; the UI can wait/recheck, skip the group or guide a user-approved application-native stop. Do not kill unrelated processes to make a reclaim operation succeed.

### 13.2 Durable phase model

| Phase | Required evidence/action | Interruption behavior |
|---|---|---|
| Observed | Scope and observation completeness recorded. | No removal authority. |
| Prepared | Exact candidates, contract, budgets, capabilities and plan digest. | Safe to discard the proposal. |
| Authorized | Explicit scoped consent, required assumptions and reservations. | Revalidate before continuing. |
| Capturing | Stream original selected content and metadata into owned staging/backend. | Source remains; incomplete content is not a recovery copy. |
| Custody committed | Backend reports durable committed content; manifest and binding recorded. | Keep content even if later steps fail. |
| Verified | Independent coverage/content/fidelity checks satisfy the contract. | Failure keeps source; never promote a partial verification. |
| Obligation recorded | Durable recovery obligation names the verified generation/custody. | A crash cannot leave removed bytes without a discoverable obligation. |
| Source revalidated | Same stable epoch, scope, identities and content evidence. | Drift invalidates authorization; capture a new generation or stop. |
| Quarantining/removing | Journal intent and native identity before each destructive step; update outcomes after it. | Recover from both filesystem reality and durable intent, never path text alone. |
| Evicted | Selected generation absent locally, custody still live, actual deltas recorded. | Restore remains available; partial batches remain explicit. |
| Restoring | Read lease plus verified materialization into owned destination staging. | Preserve staging and new user data on failure. |
| Published | No-replace publication or separately authorized retained replacement. | Reconcile publication-before-journal crash by identity and content. |
| Recovered | Requested content/fidelity restored; health remains separate. | Obligation remains until policy permits explicit release. |
| Released/purged | Explicit obligation release, last-copy checks, backend deletion and verification. | Idempotent continuation from recorded intent. |

This is a recoverable multi-step protocol, not a claim that SQLite, restic and the filesystem share one atomic transaction. Native flush and directory-durability behavior must be qualified by platform. A sealed document alone does not establish that its content is physically durable.

Byte capture should stream with bounded memory. Restic remains the initial storage implementation. Add exact group-scoped content payloads and supported metadata representation rather than redesigning its chunk store. Expected coverage comes from a source observation independent of the writer's encoding, with all selected entries accounted for, not a sample.

### 13.3 Recovery selection and conflicts

A default restore selects all outstanding obligations requested for the workspace and shows their generations. A default open selects the newest eligible available whole-workspace generation, with an explicit timestamp and kind. Missing/forgotten/corrupt custody is excluded or shown as unavailable, never silently substituted with an older state without disclosure.

Existing destination entries are classified per group/path. Default behavior preserves them. Offer restore elsewhere, compare, merge through an explicitly defined owner operation, or replace after retaining the existing generation. Never infer that an existing empty-looking directory is Ebb's old output. Do not let one missing group authorize replay over every present group.

Recipes do not run during exact-byte recovery. Optional repair/rebuild is a subsequent operation with its own trust, compatibility and conflict gates. A failed rebuild cannot invalidate the original retained generation.

### 13.4 Retention and garbage collection

GC computes liveness from active obligations, temporary capture pins, exports/imports, readers and explicit user-retention choices. It verifies eligible surviving custody when releasing the last required copy. Rows representing history, offline/unverified locations, or replicas in the same failure domain must not manufacture an independent surviving copy.

Keep logical release, physical backend forget and compaction distinct. All public purge/forget/delete aliases call one guard. The existing bug cannot be fixed in only one command while another continues counting stale rows.

Automatic TTLs may clean unreferenced owned staging or expendable indexes under an ownership-safe policy. They must not expire the sole byte-backed obligation merely because a rebuild once succeeded. Successful open does not implicitly authorize deleting all recovery history.

Ebb coordination protects against other Ebb actors. Direct external mutation of Ebb's private vault is outside that coordination and must be documented, detected where possible and never treated as a healthy supported workflow. Use backend locking in addition to, not instead of, Ebb's logical leases.

## 14. Honest storage economics and scheduling

For every affected volume v, use the planning identity:

```text
net_gain(v) = exclusive_allocation_released(v)
              - new_retained_allocation(v)
              - retained_operation_overhead(v)
```

Transient peak allocation is a separate time-dependent budget. It includes staging, backup packs, journal growth, metadata, restore output and required reserve. Do not assume future freed bytes are available before capture/verification completes.

A hardlink name contributes no independent released allocation while another alias keeps the inode alive. Reflinks, filesystem deduplication, compression and sparse files require provider-specific measurement or explicitly unknown attribution. Logical file sizes are not a substitute. Source-volume delta, vault growth and machine-wide total remain separate in both JSON and the TUI.

The user's vault was on C: and the workspace on D:. Offloading that workspace can free D: while consuming C:. It does not automatically create the same amount of machine-wide free space. If both are partitions on one physical device, this also does not add protection from that device failing.

R11 demonstrated the basic same-volume limit: 1,048,576 high-entropy fixture bytes became 1,048,902 bytes under zlib, while repetitive content compressed strongly. This is not a restic forecast. It rejects the assumption that local exact retention always saves space. Compression/dedup estimates should be ranges or unknown until measured against the real backend.

Order options by meaningful net benefit and recovery cost, not raw directory size. An explainable initial policy can prefer already retained exact generations, highly redundant cold outputs, then explicit cross-volume offload. Opaque user data and whole-project park stay separate choices. Age, build-output appearance and Git commit time are ranking evidence only, never deletion authority.

When capture shows insufficient benefit or the available reserve changes, stop before removal. Report source unchanged and retained temporary material accurately. Reclaim only newly unreferenced owned artifacts through the normal release protocol; do not run a broad emergency prune to hide a shortfall.

A nearly full drive may have no safe same-volume solution. Offer another enrolled volume, a smaller selection or preservation. Do not lower recovery guarantees to meet a target number. Report “no authorized positive net gain” with the reason, rather than a bare `no-gain` that leaves the user to reverse-engineer policy.

## 15. Windows and Linux capability contract

Initial qualification targets should be explicitly named Windows/NTFS and Linux/ext4 environments. Additional filesystems enter after tests. Network filesystems, FUSE/cloud placeholders, exFAT, unusual mount arrangements and security metadata need separate capability results. Operating-system name alone is not a qualification.

| Capability | Required behavior |
|---|---|
| Ordinary files/directories | Recover content, names, empty directories and required basic metadata. Preserve executable permission where relevant. |
| Symlinks/junctions/reparse | Retain link kind and target without traversing outside scope. Prove destination creation capability before removal. Do not silently replace a symlink with a different semantic object. |
| Hardlinks | Record group relationships and external aliases. Preserve required relationships or refuse/obtain explicit fidelity-loss acceptance. Never call a mutable link an independent backup. |
| ADS/xattrs/ACLs | Capture and restore required metadata with a qualified representation. If unsupported, preserve the affected scope. ADS is common enough on Windows that broad-support marketing must wait for an acceptable user experience here. |
| Sparse/compressed files | Preserve required semantics or state the precise weaker contract before action. Budget physical expansion during restore. |
| Cloud placeholders | Never hydrate merely to inspect. Require an explicit supported provider/scope decision. |
| Databases/VM disks | Require application-consistent handling where needed. A readable file and a point-in-time volume image are not automatically a usable application state. |
| Mounts/shared caches | Treat as separate owners/scopes. No recursive parent cleanup across the boundary. |
| Publication | Native no-clobber/verified-identity operation with a tested fallback; a pre-check followed by ordinary rename is not enough. |
| Writer control | Distinguish enforced exclusion, cooperative quiescence and unsupported control. Never label them equivalent. |

On Linux, use directory-handle-relative operations and suitable resolution/no-replace capabilities where available. On Windows, use native handles, sharing modes and reparse-point semantics. Capability detection and negative tests are necessary; string normalization cannot replace native guarantees. Relevant primary contracts are [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html), [rename](https://man7.org/linux/man-pages/man2/rename.2.html), [VSS](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service) and [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

Keep elevation optional. When a requested fidelity or isolation level requires unavailable privileges, explain that before removing anything. Do not auto-enable Developer Mode, shut down WSL, detach a mount or stop Docker because a space target was requested.

## 16. Execution trust and path-sensitive reconstruction

Default inventory, proposal and exact-byte recovery do not run repository code. Build files, README instructions, package scripts, shell launchers and imported configuration are untrusted until an explicit execution decision.

A recipe records argv, cwd, input identity, output ownership, interpreter/toolchain requirements, environment keys, network requirements and the chosen execution provider. Approval is bound to the workspace and those fields. A hash of `cmd.exe` alone does not authenticate the script it launches or its transitive inputs. An executable hash alone also does not capture all shared libraries or tool configuration.

Providers report what they actually enforce: filesystem write confinement, readable scope, network egress, process-tree control, resource budgets and logical execution paths. A timeout killing a direct child is not process-tree isolation. A Job Object is not an egress sandbox. An environment allowlist does not prevent a same-user process reading secrets from the filesystem.

For untrusted execution, use a qualified isolation provider or refuse. For user-trusted host execution, display that broader trust explicitly and retain a checkpoint of the scoped data. That checkpoint does not promise rollback of arbitrary host effects. Do not advertise “protected files cannot change” when the mechanism only notices changes afterward.

R20 demonstrated a specific design correction. A fixture console script worked inside a newly created Python environment, retained identical bytes after the environment was renamed, and then failed with ENOENT because its shebang still named the staging path. Therefore reconstruction cannot universally use an arbitrary temporary path and then rename.

Three supported strategies are possible: an isolation provider presents the intended final logical path while storing changes privately; an owner-specific recipe produces demonstrably relocatable outputs; or an explicitly host-trusted repair runs at the final path after checkpoint/conflict checks. The selected strategy is part of the contract. No generic search-and-replace of embedded paths is allowed.

Success receipts separate content recovery from compatibility, reconstruction and health checks. A health check is user-approved code too. A failing check leaves the recovered bytes and original custody intact, with a clear “files recovered; application check failed” outcome.

Secrets use platform credential mechanisms or appropriately protected ephemeral input. Never put passwords in argv, serialized plans, crash logs or share cards. Discovery indexes can reveal filenames and project identities, so protect them as user data. Remote storage/model use is opt-in; local operation must not require telemetry or an external service.

## 17. CLI and TUI design

### 17.1 Interaction contract

This is the proposed interface behavior, not a claim that new flags already exist.

| Invocation state | Behavior |
|---|---|
| Bare `ebb`, usable terminal | Open a project/storage overview with actions. |
| Valid verb, missing required target/choice, usable terminal | Guide only the missing decisions, then continue the same intent. |
| Complete intent with valid authorization | Execute directly; concise progress and receipt, no full-screen detour. |
| `--json`, explicit non-interactive mode, redirected input or unusable display | Never prompt; return structured missing-field/blocker data and nonzero status. |
| Typo or unsupported flag | Explain the exact invalid input; an interactive correction can be offered but never silently reinterpret it. |
| Scope/generation changes after review | Invalidate the reviewed plan and show the delta before new consent. |
| Interrupted operation | Offer resume, inspect retained state or safely cancel the pending action. Never hide partial completion. |

Completeness and authorization are separate. Supplying a path is not consent to permanent purge. `--yes` can answer an ordinary already-scoped confirmation, not change modes, waive unsupported fidelity, assert stopped writers or trust arbitrary code. Preserve existing safety distinctions while removing unnecessary reruns.

Use one typed question protocol with stable IDs and allowed answers. A TUI screen, a plain terminal prompt and a machine caller all resolve the same questions. Batch execution must not invoke nested interactive readers. Once an operation token is consumed, a second Enter cannot start a duplicate operation.

### 17.2 Library decision

Recommend Bubble Tea v2 for state/update/view organization, Bubbles for reusable controls and Lip Gloss for restrained layout. Huh can provide small forms/accessibility where its integration fits. tview remains a viable widget-based alternative, not a rejected inferior product.

The inspected [Huh module](https://raw.githubusercontent.com/charmbracelet/huh/main/go.mod) and [Bubbles module](https://raw.githubusercontent.com/charmbracelet/bubbles/main/go.mod) both reference Bubble Tea v2 and Lip Gloss v2. This establishes major-version alignment in those source snapshots, not a compiled compatibility result. Pin a mutually compatible released set after the native terminal spike. Do not follow moving main branches in production.

The choice is justified by the proposed reducer/event protocol, not by benchmark claims. Keep views pure. Run scanning, hashing and subprocess work outside the render loop; deliver progress as immutable events.

### 17.3 Screen flow

The ordinary reclaim flow is scope, proposed groups, review, progress and receipt. Small missing decisions use inline forms. Full-screen navigation is reserved for bare invocation or multi-project work. Avoid modal stacks and repeated confirmations of identical scope.

Illustrative review layout; figures other than the user-supplied environment size are intentionally not forecasts:

```text
Ebb / ebb_test                                      D:\dev\ebb_test

Selected                                          Recovery
[x] Python environment       447.9 MiB on source   Original files retained
[ ] Data                      Not selected         Leave in place
[ ] Entire workspace          Separate action      Park, not dependency trim

Source-volume release         Calculating exclusive allocation
Vault growth                  Estimate pending
Machine-wide net gain         Not yet established
Writers                       Check required
Rebuild scripts               None will run

[ Review and continue ]  [ Back ]
Details: inputs, links, fidelity, interpreter and storage location
```

The screen should explain that a nested requirements file was discovered, and whether its relationship to the environment is observed or inferred. It need not force the user to decide that relationship when exact-byte eviction makes the inference unnecessary.

Progress displays phase, completed bytes/entries where meaningful, source/vault volumes and an activity heartbeat. Never fabricate a percentage for an unbounded phase. Verbose backend output goes into an expandable, sanitized log, not a scrolling wall that destroys the summary.

A completion receipt names what left the source, where its exact generation is retained, source-volume delta, vault growth, net estimate/measurement status, recovery mode and available next action. `status` should show pending operations and outstanding recovery first; dashboard statistics must not replace operational status.

### 17.4 Failure handling

A blocked writer offers recheck, skip and process details in place. A missing vault offers an enrolled alternative or safe cancellation, never automatic remote upload. Insufficient headroom offers a smaller selection or another volume. Ambiguous same-name workspaces show full paths and identities. Destination conflicts preserve new data and offer restore elsewhere before replacement.

Known actionable blockers remain within the current flow. Fatal invalid state produces a stable error code and a retained operation ID. Do not claim the user must rerun a different command when the current application service can continue safely after a decision.

### 17.5 Visual and accessibility requirements

Use aligned columns, bounded line widths and progressive detail. Avoid rainbow logs, giant ASCII branding, ornamental borders around every field and color-only status. Every action is keyboard-accessible. Support narrow terminals, resizing, high contrast, no-color mode, screen-reader/plain prompts and clean redirected output.

Measure display cells, not UTF-8 byte length. Escape control sequences in filenames and subprocess output, including OSC/CSI sequences that can forge rows or alter a terminal. Copyable commands use platform-correct quoting; a display-truncated path must never become the executed path.

Restore terminal mode/cursor on completion, cancellation and failure. Ctrl+C requests safe cancellation and preserves a truthful receipt. A second interruption may terminate immediately, but recovery must still find the durable state. Losing the terminal must not leave an invisible authorization prompt or a child process consuming future input.

`--json` retains a single structured result contract. If streaming events are added, expose a separately versioned JSON-lines mode rather than mixing progress into existing stdout JSON. Human progress belongs on the designated terminal stream; errors retain stable machine fields.

## 18. Staged implementation and migration

### Phase 0: repair known recovery hazards and establish native gates

Add failing production regressions for E04-E15 and E20 before fixing them. Prioritize last-copy custody, newest-snapshot selection, multiple outstanding trims, identity collisions, partial-output conflicts and truthful failure outcomes. Fix benchmark scratch ownership separately. Publish the corrected trim guarantee immediately rather than waiting for a new UI.

Add native Windows and Linux CI, real-restic acceptance jobs and an available race-detector job. Fail qualification when a required integration silently skips because a binary or privilege is absent. Keep explicit unsupported-capability tests distinct from skipped required tests.

Exit gate: the affected old behavior fails the new regressions, the fixes pass them, and no current production flow claims a stronger recovery contract than it implements.

### Phase 1: unify contracts and catalog semantics

Introduce the shared recipe, intent, outcome, group-generation and obligation types. Adapt existing command handlers to one application service. Repair recipe cwd/network/tool identity round trips. Implement explicit availability/tombstones and newest eligible selection. Preserve old history rather than rewriting it as verified new-format custody.

Exit gate: equivalent direct, batch and recovery requests select the same groups and definitions; unknown versions refuse before mutation; identity and retention races have production tests.

### Phase 2: byte-backed group eviction and recovery

Add exact selected-group payloads through the existing restic backend. Retain unknown patches and additions. Implement stable-epoch capability checks, per-volume reserve budgets, read leases, no-clobber publication and per-group recovery. Reconcile every interruption point through durable facts and native identity.

Exit gate: real backend round trips restore the promised content/fidelity offline after all recipe download sources are made unavailable. No selected unknown file disappears without retained bytes. Peak headroom and net gain are measured, not inferred from logical size.

### Phase 3: shared automatic discovery

Replace the root-only and shallow-only parallel understanding paths with one observation graph. Start with the user's nested Python/buildless case and mixed Node/Python workspaces. Add other semantic providers incrementally. Generic byte-backed support remains available without those providers.

Exit gate: ordinary held-out projects need no handwritten Ebbfile; fixture manifests, nested Git repositories and shared caches do not gain deletion authority from recognition alone. Incomplete scans never report complete absence.

### Phase 4: TUI and direct-command parity

Build the reducer/question protocol and terminal spike, then the overview, selection, review, progress, conflict and receipt views. Reuse the same engine rather than translating TUI clicks into shell commands. Keep accessible/plain and machine modes first-class.

Exit gate: the same test intents produce identical authorized plans in TUI/direct/JSON modes; no headless path waits for input; terminal resize/cancel/restore scenarios pass native PTY/ConPTY tests. Run end-user usability sessions, not just screenshot approval.

### Phase 5: optional reconstruction and native integrations

Add path-aware execution providers, explicit host-trusted repair, optional observed-build learning and native cache operations. Each provider has a declared contract, a version range, negative fixtures and isolated tests. Never let provider convenience weaken generic custody invariants.

Exit gate: missing tools, changed tool identity, registry disappearance, private dependencies and path-sensitive outputs are handled without losing the original retained generation.

### Phase 6: pilot, hardening and release decision

Run the product-value and large-workspace gates below. Publish exact platform/filesystem/fidelity support. Commission an independent review of destructive paths once the production implementation exists. Keep macOS, a new storage backend, transparent filesystem virtualization and remote-AI automation out of the critical path.

### Migration rules

Legacy trim records remain explicitly recipe-only. A migration cannot invent their missing original bytes. Legacy retained snapshots are reclassified only from actual evidence. Back up the catalog before schema migration and fault-test interrupted upgrade/restart. New writers and old readers must fail safely on unsupported formats.

Do not silently change an existing command from cheap recipe disposal to multi-gigabyte exact backup without showing its storage consequence. Version the behavior and make the default safe for new use, with clear deprecation of weaker legacy semantics.

Old CLI aliases delegate to the same application service. Keep stable exit-code families and versioned envelopes. `stats` and web/share-card features can remain available, but expanding gamified metrics is lower priority than custody, recovery and the primary terminal workflow.

## 19. Validation matrix and release gates

### 19.1 Representative workspace corpus

Keep deterministic fixtures plus a consented held-out set of real projects. Do not author every fixture to match the detector's assumptions. Every case records the exact protected set, allowed changed set, expected recovery contract and platform capabilities.

| Scenario | Required behavior |
|---|---|
| User's nested Python + buildless frontend | Detect nested facts, no dummy files, preserve source/data, offer byte-backed environment eviction. |
| Two environments and three requirements files | Preserve competing relations; no arbitrary owner selection. |
| Editable install outside the root | Record external dependency; never capture/delete external source implicitly. |
| Untracked patch/addition inside dependency output | Original bytes survive exact eviction/recovery. |
| Manifest under tests/fixtures | No automatic authority over the real environment. |
| Out-of-tree build and shared target directory | Explicit shared ownership and scope, correct net accounting. |
| pnpm/uv linked managed store | Do not traverse/delete the owner's cache by name. |
| Same project basename on two drives | Distinct identities, no mixed snapshot history. |
| Git worktrees/submodules/stashes/conflict state | Preserve relevant supported bytes and disclose external administration/runtime dependencies. |
| No manifest or unfamiliar language | Useful inventory and byte-backed shelving without fabricated reconstruction. |
| Live SQLite/database/VM files | Application-consistency gate, no false ready claim. |
| Writer after capture/quarantine | Drift detected or execution refused under strict mode; no assertion that rename stops writers. |
| File replaced at same path/native-ID reuse | Generation/evidence revalidation; stale authorization rejected. |
| Symlink/junction cycle or ancestor substitution | Bounded no-follow behavior, no escape. |
| Linux byte names/Windows aliases/reserved names | Lossless source identity; incompatible destination refused before publication. |
| ADS/ACL/xattr/executable/sparse metadata | Exact promised fidelity or explicit refusal before removal. |
| Vault inside source or source inside vault through alias | Reject unsafe overlap. |
| Nearly full source/vault, quota changes mid-operation | Reserve gate and source-preserving shortfall. |
| Disk disconnected or key unavailable | No removal based on an unavailable supposed copy. |
| Two trim groups; crash after the first | Accurate partial batch and both outstanding obligations discoverable. |
| Old snapshot forgotten, last real copy remains | Additional last-copy acknowledgement still enforced. |
| Existing destination with new user work | No silent overwrite or installer cleanup. |
| Capture/restore/GC concurrent in separate processes | Native coordination/fencing protects obligations and active readers. |
| Malformed/tampered manifest, archive bomb, unknown version | Bounded parsing and fail-closed behavior before publication/removal. |
| Tool/script/input drift or disappearing registry | Refuse/review execution; exact retained bytes remain recoverable. |
| Path-sensitive venv/native build outputs | No generic stage-rename readiness claim. |
| Hostile terminal filename/output and lost TTY | Escaped display, no command injection/hidden prompt, terminal restoration. |
| Notification overflow or interrupted scan | Invalidate/rebuild affected observations, never interpret as no changes. |

### 19.2 Fault injection and independent verification

Inject failure before and after each catalog commit, backend commit, seal readback, rename, unlink, publication and pin/release transition. Include partial writes, fsync errors, process termination, disk-full errors, unavailable credentials, sharing violations and readback corruption. Reopen with a new process and inspect actual state.

A separate verifier compares original and recovered selected content, names, metadata and link relationships to the declared contract. Do not let the same encoding routine define both expected and actual truth. Test corrupted-but-self-consistent descriptions against the threat model and independent witness. Cryptographic failures and missing copies must not be reduced to generic success-with-warning.

Run real concurrent actors, not only sequential mock races. Test both operation orderings and lease loss. Fuzz path parsers, archive/manifest readers, version gates and terminal rendering inputs. Seed every failure into the permanent corpus.

### 19.3 Performance and ergonomics budgets

Proposed targets, not measured achievements: initial terminal feedback within 250 ms on the reference machine; cached overview within 2 seconds; heartbeat during long phases; bounded resident memory while hashing/streaming; full attribution of peak scratch/vault growth; and correct cancellation without orphaned untracked work. Benchmark on small-file dependency trees and large already-compressed assets separately.

A cold full scan can exceed a fast cached-view budget. Show progressive completeness instead of hiding a recursive scan behind an unresponsive UI. Watchers and cached stats accelerate discovery only; mutation revalidation still follows the stable-epoch contract.

Use the same recovery/fidelity guarantees for competitor or manual-baseline comparisons. It is misleading to compare a verified backup against unverified deletion and call the latter's speed an Ebb failure or Ebb's richer outcome a free benefit.

## 20. Product value and end-user effort

The potentially useful product is a recoverable workspace storage manager that remembers decisions, understands enough structure to suggest good scopes, and returns users to their work. The novelty is not a new content hash, backup algorithm or terminal widget. The researched systems already cover much of that machinery.

A valid value proposition combines cross-project visibility, useful automatic grouping, trustworthy custody, per-volume planning and predictable resumption. This remains a hypothesis until tested. If most users still need to inspect scripts, write policy, manage backups and repair environments manually, the overhaul has failed even if every command is technically correct.

### Proposed pilot

Recruit a small initial sample, for example 12 consenting developers across Windows/Linux and multiple project families. Use a crossover comparison against their usual tools, including a manual workflow with equivalent recovery guarantees. Give each participant a repeated reclaim-and-resume task, a nested-project task, a low-headroom task and a conflict/recovery task. Repeat after a delay so remembered setup is not confused with recurring effort.

Measure active decision time separately from elapsed I/O. Count questions, policy edits, incorrect selections, assistance, unexpected rebuild/network needs, usable bytes released on the pressured volume, net machine saving and time to resume actual work. Record cases where preservation/no-gain was correct but the explanation failed.

Initial go/no-go targets are hypotheses: substantial median active-time reduction, such as at least half against an equivalent baseline; ordinary held-out tasks usually completed without hand-edited configuration; no unrecovered protected content or silent fidelity downgrade; and repeated voluntary use. Do not advertise these targets as results or infer universal rates from a small pilot.

Stop or narrow the product if byte-backed same-volume savings are usually negligible, restore latency dominates the saved effort, setup is worse than the manual workflow, or the planner repeatedly recommends operations that cannot safely execute. In that case specialize in cross-volume shelving or a well-supported managed-artifact use case rather than weakening safety to preserve the original marketing claim.

## 21. Executed experiments, changes earned and reproduction

The first round ran in Linux 6.18.44 with Python 3.13.5 and SQLite 3.46.1. The container had no restic binary, native Windows host or independent agent runner. Repository cloning from the container failed because its network could not resolve GitHub; the authorized GitHub connector supplied source inspection and commits. None of the following is a claimed Ebb end-to-end run.

| IDs | Evidence boundary | Result and resulting change |
|---|---|---|
| R01-R03 | SQL/source-shaped decision reductions | Oldest snapshot selected, earlier trim omitted, history rows exceeded surviving copies. Reinforces E09-E11 regressions. |
| R04-R06 | Real local files | Metadata did not prove content; same inode/size/mtime hid changes; live writes changed hardlink backup. Require original-byte custody and stronger epoch evidence. |
| R07-R08 | Real Linux filesystem | Ancestor symlink escaped lexical scope; open FD wrote after rename. Native scope/exclusion cannot be replaced with string checks or quarantine. |
| R09-R10 | Real fixtures plus decision reductions | Empty directory passed existence; partial absence coexisted with new data elsewhere. Require content contracts and per-group conflicts. |
| R11 | Real zlib experiment | High-entropy retention grew 326 bytes for a 1 MiB fixture. This is a counterexample, not a restic benchmark. |
| R12 | Logical execution-coverage counterexample | Another run required an unobserved file. Tracing remains bounded evidence. |
| R13 | Exhaustive single-object finite model | 20 states/42 transitions satisfied its invariant; weakened durability, obligation or read-lease variants failed. Not native/power-loss proof. |
| R14-R15 | Interaction/outcome reducers | 16 mode combinations, stale/duplicate acceptance and evidence-level separation met their local gates. No actual terminal renderer tested. |
| R16-R19 | Second-round fixture/logical models | Verified old generation, shared failure domain, partial batch and lost trust anchor broke stronger assumptions. D04/D11-D13 revised. |
| R20 | Real Linux venv/subprocess | Console script ran before relocation and failed after it with unchanged bytes. D14 separates path-aware rebuilding from byte publication. |

The 20 numbered experiments include 17 counterexamples to unsafe or overbroad assumptions and three bounded positive mechanism checks. “Observed” in the raw first-round report means the specified observation occurred, not that Ebb passed a release test. Negative controls in R13 deliberately remove guards and must continue to fail.

Reproduce in a disposable Linux environment with Python 3.10 or newer, without optimization that disables assertions. The scripts need no external Python packages or network:

```sh
python3 docs/research/ebb-overhaul/redteam.py --out /tmp/ebb-overhaul-results
python3 docs/research/ebb-overhaul/round2.py
python3 docs/research/ebb-overhaul/round3.py
```

Use a dedicated output directory; the first script writes results/report/ledger files there. All test workspaces are fresh temporary directories. Its Linux-specific flags are intentional; it is not the planned cross-platform production suite.

The first two scripts' SHA-256 values are recorded in `evidence.json`; the third script's Git blob identity is recorded in `round3.json`. The committed first-round script blob was checked against the executed local file. The evidence ledger preserves unresolved native qualification, user-value and real-backend economics gates.

The finite model's small state space is a deliberate limitation, not proof of a large system. R16 and R20 show why passing a narrower model must not end review. Further decisive testing needs the actual implementation, native hosts, a real backend and real users, not more repetitions of the same toy model.

## 22. Final review and unresolved decisions

The final consistency pass checks that byte retention is not called runtime portability, snapshots are not called writer exclusion, ordinary package caches are not called independent custody, directories existing are not called readiness, and source-volume release is not called machine-wide saving. It also checks that every UI path reaches the same authorization and retention rules.

Current evidence maturity: existing defects have source evidence at level 2, with selected mechanisms corroborated at level 3; the proposed single-object custody and UI decision models reach level 3 within their stated boundaries; native Ebb recovery, actual TUI rendering, cross-platform fidelity, backend economics and user-value targets have not reached level 4. No aggregate safety score is assigned.

Highest-risk implementation unknowns are a practical stable-epoch contract for ordinary Linux workspaces, faithful metadata restoration on both platforms, coordination across real Ebb processes and backend operations, useful net savings with original bytes retained, and low-friction path-sensitive environment repair. These are explicit implementation spikes and release gates, not details to postpone until after a polished demo.

Keep the initial scope narrow enough to qualify but broad enough to test the product idea: existing Windows/Linux projects, no mandatory manifest relocation, no required Ebbfile, exact supported content recovery, explicit recovery limitations and a shared direct/TUI workflow. Expand semantic recognition without granting adapters more destructive authority.

Do not prioritize macOS, a new storage engine, global always-on privileged scanning, transparent filesystem virtualization, remote-AI interpretation, additional share cards or gamified statistics ahead of these gates. Do not delete working optional features merely to make the architecture diagram cleaner.

Decision: proceed with the recovery-first design and staged repairs. Do not ship expanded automatic destructive behavior until the required native tests pass. The next implementation task is the regression/custody phase, not a more aggressive heuristic and not a cosmetic terminal rewrite.
