# Primary-source research for the Ebb overhaul

Research date: 2026-09-25. This is a deliberately selected comparison of overlapping systems, not a claim to have inspected every established product or audited their entire source trees. Sources below were read as architecture documentation, command contracts, or selected source. No performance comparison between these products was executed. External project versions and APIs must be pinned again when implementation starts.

## Findings by architectural family

### Git, git-annex and DVC: names, content, custody and liveness

**Git.** Its garbage collector works from reachability, including references, index and reflog retention. Its documentation explicitly warns that immediate pruning during concurrent writes can corrupt a repository. Ebb should borrow explicit identity and retained history, not the claim that Git is infallible. A committed file is also not a backup of every ignored file in a workspace. [Git garbage collection](https://git-scm.com/docs/git-gc).

**git-annex.** It separates content identity from location knowledge, and removal is constrained by copy policy. Trusting a location changes whether its reported copy counts. Its trust documentation warns that stale trusted-location information can lead to insufficient surviving copies. The useful model for Ebb is a recovery obligation attached to content and verified custody, not a count of historical database rows. Ebb's own policy must additionally state which failure domains a copy protects against. [Architecture](https://git-annex.branchable.com/how_it_works/), [drop](https://git-annex.branchable.com/git-annex-drop/), [trust](https://git-annex.branchable.com/trust/).

**DVC.** Workspace materialization and content storage are separate concerns. Its data-management documentation distinguishes reflinks/copies from mutable hardlinks and symlinks; careless writes through shared links can corrupt cached content. Its run cache uses declared stage signatures rather than inferring an arbitrary program's whole behavior. A shared cache also makes garbage collection a cross-project concern. Ebb can reuse these concepts without making users adopt a DVC pipeline. An unrelated package manager's cache is never Ebb's sole backup merely because its files happen to exist today. [Internal files](https://doc.dvc.org/user-guide/project-structure/internal-files), [large datasets and links](https://origin-doc.dvc.org/user-guide/data-management/large-dataset-optimization), [shared caches](https://origin-doc.dvc.org/user-guide/how-to/share-a-dvc-cache), [run cache](https://origin-doc.dvc.org/user-guide/pipelines/run-cache).

### restic, Borg and Kopia: byte custody rather than semantic guessing

**restic.** The current Ebb backend already supplies encrypted, content-addressed backup storage. Its threat model assumes a trusted source host and authentic client; cryptography does not prevent all copies being deleted by an attacker. Keep restic as the initial backend and repair Ebb's selection, retention, fidelity and orchestration contracts before contemplating a storage rewrite. Ebb must verify the exact retained scope, distinguish cached observations from current availability, and document which key and storage failures remain outside its guarantee. [restic design and threat model](https://restic.readthedocs.io/en/stable/100_references.html).

**Borg.** Repository internals separate append-style transaction records and commits from compaction. Incomplete transactions and rebuildable indexes receive explicit treatment. The lesson is durable recovery state and idempotent reconciliation, not copying Borg's internals into Ebb. A database transaction still cannot atomically include arbitrary filesystem changes. [Borg data structures](https://borgbackup.readthedocs.io/en/stable/internals/data-structures.html).

**Kopia.** Its architecture separates blob packs, content-addressable blocks, larger objects and label-addressed manifests. This supports Ebb's proposed distinction between immutable evidence/content and human-friendly workspace names. Labels must not be the identity used to authorize removal. [Kopia architecture](https://kopia.io/docs/advanced/architecture/).

### Nix, Bazel and BuildKit: reproducibility comes from a managed contract

**Nix.** Garbage-collection roots and transitive references define live store paths. Recovery depends on retaining the required closure, not just the top-level dependency declaration. Ebb should introduce explicit obligation roots covering content, manifests, metadata and key requirements. Requiring every existing project to become a Nix project would defeat Ebb's low-effort adoption goal. [Nix GC](https://nix.dev/manual/nix/2.34/command-ref/nix-store/gc).

**Bazel.** The remote action cache and content-addressed output storage are distinct. Correct reuse requires the relevant inputs to be represented. Sandboxing has provider-specific limits; Bazel explicitly describes cases where host files remain readable. Ebb must not claim a universal sandbox from a working-directory setting. A successful rebuild is evidence for that execution, not proof of every future run or unobserved dependency. [Remote caching](https://bazel.build/remote/caching), [sandboxing](https://bazel.build/docs/sandboxing).

**BuildKit.** Frontends translate high-level descriptions into a lower-level graph consumed by a solver and workers. Content-addressed graph operations are useful for cache keys and reuse, but a graph digest does not make a mutable external reference immutable. Ebb should similarly normalize adapters into one recipe representation and one execution protocol; adapters must not implement their own deletion logic. [BuildKit overview](https://docs.docker.com/build/buildkit/), [developer definitions](https://github.com/moby/buildkit/blob/master/docs/dev/README.md), [solver](https://github.com/moby/buildkit/blob/master/docs/dev/solver.md).

### Native tools: ecosystem facts need versioned, owner-specific interpretation

**uv.** Its cache is explicitly managed by uv; concurrent use is supported through uv's own discipline, while direct modification is discouraged. Current documentation also describes layouts that can place environments centrally and represent `.venv` using a link or fallback file. The conventional folder name is therefore not a universal ownership rule. Preserve `--locked` versus `--frozen` semantics and query capability/version before relying on an adapter. [Cache](https://docs.astral.sh/uv/concepts/cache/), [project layout](https://docs.astral.sh/uv/concepts/projects/layout/), [sync semantics](https://docs.astral.sh/uv/concepts/projects/sync/).

**npm.** The documented `ci` contract removes existing `node_modules`; tree-shaping options and project configuration matter. It is unsafe to run it over new live work merely because another output is absent. Script execution is governed by versioned package-manager policy; Ebb must report and control the execution mode rather than assuming an install command is inert. [npm ci](https://docs.npmjs.com/cli/v11/commands/npm-ci/).

**Python venv.** Virtual environments can carry absolute interpreter paths and depend on the base interpreter. The Python documentation calls them generally nonportable. Ebb should recover bytes at their recorded location where possible, then report host compatibility separately. A cross-platform content transport is not a cross-platform runnable-environment guarantee. [venv](https://docs.python.org/3/library/venv.html).

**Cargo.** Its metadata command exposes structured workspace, package and target information. This is richer than guessing from directory names, but Ebb must choose a documented offline/no-dependency mode, restrict executable identity, and account for configuration and possible side effects. Pure manifest parsing remains the default on untrusted projects. [Cargo metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html).

**CMake.** The file API publishes indexed, versioned replies containing source/build relationships. Clients follow the reply index and retry on generation changes. Reading existing replies can avoid running project configuration. Stale or absent replies cannot establish that a build directory is disposable. [CMake file API](https://cmake.org/cmake/help/latest/manual/cmake-file-api.7.html).

**Gradle.** Initialization and configuration evaluate scripts before selected tasks execute. Therefore "query project metadata" is not automatically a read-only operation. Ebb may read known static markers or previously generated metadata by default; evaluating Gradle requires explicit execution trust and isolation appropriate to the requested claim. [Gradle lifecycle](https://docs.gradle.org/current/userguide/build_lifecycle.html).

### ReproZip, direnv and Watchman: observation is useful, but bounded

**ReproZip.** It traces a user-invoked command's system calls and records files, binaries and environment dependencies for packing. Its packing component is Linux-specific. This supports an optional Ebb learning workflow that observes an actual successful build rather than executing a guessed script. Inference: tracing one run cannot establish dependencies used only by unexecuted branches, different inputs or future network responses. An observed closure is not a universal closure. [ReproZip packing](https://docs.reprozip.org/en/latest/packing.html).

**direnv.** Explicit authorization for local environment configuration is the relevant precedent. Ebb must not execute `.envrc`, launch scripts or build files merely because discovery found them. Trust decisions need content and context binding rather than a global blanket acceptance of a filename. [direnv manual](https://direnv.net/man/direnv.1.html).

**Watchman.** It explicitly recrawls after losing synchronization, including notification overflow. Watchers should make Ebb's index faster to refresh; they must not be the source of deletion authority. A missing event is not proof that a file stayed unchanged. [Watchman troubleshooting](https://facebook.github.io/watchman/docs/troubleshooting).

### Terminal interfaces and adjacent storage products

**Bubble Tea.** The current main documentation describes the v2 Go model/update/view approach. This is a good fit for a terminal view over Ebb's typed intents and operation events. Effects belong in the application engine; rendering cannot acquire filesystem authority. Pin a compatible Bubble Tea/Bubbles/Lip Gloss set after a small Windows/Linux terminal spike. Do not mix major versions because their package names look similar. [Bubble Tea](https://github.com/charmbracelet/bubbletea).

**Huh.** Its accessible mode falls back to conventional prompts for screen readers. That pattern should be available whether or not Ebb uses Huh directly. Compatibility with the selected Bubble Tea release must be verified before adoption. [Huh accessibility](https://github.com/charmbracelet/huh#accessibility).

**tview.** This is a credible widget-oriented Go alternative. Choose between it and Bubble Tea on a tested interaction prototype, event ownership and accessibility, not screenshots alone. The recommendation is Bubble Tea because the reducer model matches the proposed command/decision protocol; this is a design preference, not a performance result. [tview](https://github.com/rivo/tview).

**gdu and npkill.** These already address disk visibility and fast interactive selection of large directories. Ebb has little differentiation if it only adds a similar picker and wraps removal. The additional value must be recoverable storage decisions, coherent project/group state, cross-project ownership checks and dependable resumption. Their existence disproves a claim that interactive cleanup itself is novel. [gdu](https://github.com/dundee/gdu), [npkill](https://github.com/voidcosmos/npkill).

### Platform and reliability contracts

**Linux path operations.** `openat2` provides resolution restrictions such as staying beneath a directory and rejecting links. `renameat2` offers no-replace publication on supported filesystems. Ordinary rename does not invalidate open descriptors. These mechanisms must be wrapped by a native capability interface and tested on the actual filesystem; lexical prefix checks alone are insufficient. [openat2](https://man7.org/linux/man-pages/man2/openat2.2.html), [rename](https://man7.org/linux/man-pages/man2/rename.2.html).

**Windows.** VSS coordinates requesters, writers and providers for consistent captures; using a snapshot without the relevant application's cooperation does not automatically establish application consistency. Job Objects manage process groups, but breakaway behavior and creation paths require testing. A job object is not a filesystem/network sandbox. Keep privileged snapshot/isolation facilities optional and explicitly capability-gated. [VSS](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service), [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

**SQLite.** Its reliability work includes systematic I/O failures and simulated crashes with subsequent integrity checks. Ebb should inject failures at every durable transition and filesystem/backend boundary, including incomplete writes, rather than testing only process cancellation between successful stages. Reusing SQLite does not make a filesystem-plus-vault operation atomic. [SQLite testing](https://sqlite.org/testing.html), [atomic commit](https://www2.sqlite.org/atomiccommit.html).

## What this comparison changes

1. Use a content-custody and recovery-obligation model as the foundation. Discovery describes possible relationships; it never proves recoverability by itself.
2. Retain the existing restic integration initially. Repair Ebb's contracts instead of inventing another backup format, package manager or build system.
3. Make byte-preserving eviction useful on unknown languages. Add semantic adapters progressively, with their observation and execution capabilities separated.
4. Treat package-manager caches as externally owned resources. Delegation to a native prune command is a distinct, accurately described operation, not a byte-backed Ebb eviction.
5. Store one versioned recipe and one typed operation protocol across direct CLI, TUI, JSON, recovery and batch execution.
6. Keep “files recovered,” “recipe completed” and “application health checked” distinct. No current comparison justifies collapsing them.
7. Treat source-volume release, machine-wide savings, transient headroom and restore headroom as separate quantities.
8. Reject the promise of universal automatic reconstruction. Pursue universal safe classification and scoped content recovery, with useful automation where evidence supports it.

## Research limits

This is architectural and contract research, not an exhaustive competitor inventory or a security certification of the referenced products. No claims of market novelty, user adoption, measured time savings or comparative throughput are established here. Existing Ebb code was read through the authorized GitHub connector. The working container cannot clone the repository over its network, has no restic binary and provides no native Windows host. Executable tests in this run must therefore clearly distinguish local filesystem observations and reduced decision models from Ebb integration tests. No independent background-agent review was available.
