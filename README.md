# Ebb foundation package

Read `Foundation.md` first. It is the product and implementation baseline, including problem definition, decisions, contracts, sequencing and release gates.

`CONTEXT.md` is the domain glossary. `research/evidence-ledger.md` distinguishes documented facts, observed counterexamples, design choices and untested claims. `research/iteration-log.md` records the significant corrections. `research/source-register.json` is the machine-readable primary-source register.

The original working draft is retained at `research/Foundation.baseline.md`. The short draft originally written on the assigned PC is also preserved during delivery as `research/Foundation.remote-initial.md`.

## Contained experiments

`lab/run_probes.py` uses only Python's standard library and the Git executable. It creates and removes its own temporary generated fixtures. It does not accept a user project path. These probes are Linux/POSIX mechanism tests; running them on Windows is not a Windows conformance suite.

On Linux, from the package directory:

```sh
python lab/run_probes.py --output lab/results-new.json
```

Read `lab/PLAN.md` before running. The checked-in first and repeated results are kept separately. A successful result means the stated narrow observation was reproduced; it does not mean Ark has been implemented or that every release gate passes.

The assigned PC receives documentation and reproducible evidence only. No application installation or destructive project experiment is part of this delivery.
