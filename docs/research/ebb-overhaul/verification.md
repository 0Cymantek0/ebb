# Planning-run verification

Date: 2026-09-25. This verifies the research artifacts and bounded experiments, not the production implementation.

## Requirement coverage

| Requirement | Recorded location / result |
|---|---|
| Windows/Linux first, macOS deferred | plan.md sections 1, 15, 18 and 22. |
| Broad language/layout compatibility without normal Ebbfile authoring | Sections 2, 9 and 12; generic content lifecycle separated from semantic adapter coverage. |
| Deeper existing-code investigation | Section 6, E01-E20 with pinned source links. Source inspection is not described as a native runtime audit. |
| Established-system research | research.md and section 7; selected primary-source survey, explicitly not every product in existence. |
| Structurally different alternatives | Section 8; infer/delete, managed-only and recovery-first designs compared. |
| Repeated adversarial revision | Sections 10 and 21; three rounds, R01-R20, original failures retained. |
| Guided TUI and complete-command direct mode | Section 17, including machine-mode refusal, accessibility and shared intent/authorization. |
| Product value rather than command count | Sections 1, 5 and 20, with prospective user study and narrowing/stop criteria. |
| Incremental plan commits | Root plan developed through intent, baseline defects, candidate choice and detailed contract revisions on the research branch. |
| Migration and implementation order | Section 18; safety regressions and custody before broader destructive automation. |
| Final review and limits | Sections 19, 21 and 22; native integration, real storage economics and user-value gates remain unresolved. |

## Fresh executable verification

All three Python files were syntax-compiled and rerun in the local Linux container after the final plan revision. The first script produced 15 expected observations, the second four expected counterexamples, and the third the path-sensitive environment failure. There were zero experiment-run failures.

Interpretation: 17 assumptions were falsified; three small mechanism/decision models met their stated gates. This is not “20 Ebb integration tests passed.” The finite custody model explored 20 states and 42 transitions and rejected three deliberately weakened variants. It excludes torn writes, native filesystem coordination, multiple content objects and arbitrary external writers.

The committed script blob identities were read back through GitHub and matched the files executed locally:

| File | Git blob SHA |
|---|---|
| redteam.py | b71ce90d33fe827ec07fbbac8be7489821d6445f |
| round2.py | b7eccc206784a928e7c223d1da4d388f4b5dea77 |
| round3.py | 452c1714467516c9cabe79aa9df07060974608c1 |

The first-round evidence retains its original run timestamp; the final rerun checked the same observations without replacing the original negative evidence.

## Scope checks

The branch comparison against baseline showed additions limited to root plan.md and docs/research/ebb-overhaul. No production Go file, user workspace, vault, dependency or release configuration was modified. Supporting Python programs are design experiments under docs, not changes to Ebb's runtime.

The final review corrected the experiment ledger to include R20, and distinguished the R19 trust-anchor model from a cryptographic attack on restic. The main plan separates source-volume release from machine-wide saving, files from application readiness, snapshot capture from writer exclusion, and staged byte publication from path-sensitive reconstruction.

## Not verified in this run

No native Windows host, real restic binary, full Ebb build/test execution, package-registry end-to-end scenario, power-loss simulation, real concurrent Ebb-process suite, rendered terminal/ConPTY implementation, independent second-agent audit or user study was completed. These remain explicit release or product-value gates. No “unbreakable” or universal no-loss certification is asserted.
