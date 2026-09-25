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

## 5. Initial misconception register

The user observed a working project with `wavebox/requirements.txt`, a root `.venv`, and a buildless frontend. Ebb reported every entry preserved and no reclaim gain. The earlier assistant then proposed dummy root manifests and claimed normal trim backed up the removed dependency bytes. Those claims require correction against code before offering further operational advice.

The prior review also reported dropped reconstruction working directories, inconsistent UV arguments and differing approval paths. These are investigation leads until independently rechecked in this run. Git is an engineering reference for explicit state, recoverability and narrow guarantees, not evidence that any tool never fails.
