# Ebb benchmarks — baseline 2026-09-18

This is the project's first measured performance baseline (Foundation §14.4:
"performance gates, not invented benchmark results"; D013: numbers come from
the real binary or there are no numbers). Every number below was produced by
the harness at `lab/bench/` driving the REAL production packages —
`internal/inventory`, `internal/lifecycle`, `internal/restore`,
`internal/storage/restic`, `internal/platform`, `internal/catalog` — against
the REAL restic 0.19.1 binary, on generated disposable fixtures, with no
production code modified. Raw evidence for this run (machine-readable
`results.json` + rendered `report.md`) is committed at
`lab/bench/results/20260918T213610Z/`.

## Reproduce

```
go run ./lab/bench
```

That is the exact command that produced the baseline (all defaults). Useful
flags: `--restic <path>` (default PATH lookup; the run skips with a message
when absent), `--work <dir>` (scratch root; default a fresh temp dir, removed
afterwards), `--scale <float>` (fixture multiplier, default 1.0),
`--out <dir>` (default `lab/bench/results/<UTC-timestamp>/`), `--filter
smallfiles,node` (subset), `--device "..."` (device class label). The harness
creates/destroys only inside `--work` and `--out`, asserts every fixture root
resolves inside the scratch root before any destructive call, and pins
`APPDATA`/`XDG_CONFIG_HOME`/`TEMP` into the scratch root so no user state can
be touched. No network is used.

## Environment

| Item | Value |
|---|---|
| Date (UTC) | 2026-09-18T21:36Z (run) / 2026-09-18T21:49Z (report) |
| OS | Windows 11 (10.0.26200), NTFS system volume, Git Bash shell |
| CPU | Intel64 Family 6 Model 151 Stepping 2 (12 logical CPUs) |
| Device class | SSD (assumed; no autodetection in v1) |
| ebb | 0.1.0-dev (build-version var, now `internal/version.Version`) |
| Backend | restic 0.19.1 (windows/amd64, go1.26.4), local repository in scratch |
| Go | go1.27.1 windows/amd64 |
| Total harness runtime | 804.3 s (13 m 24 s) at default scale 1.0 |
| Peak harness RSS | 590.2 MiB (runtime.MemStats; restic subprocess memory excluded) |
| Volume free-space noise | drift 84.0 KiB over 8 pre-run samples (see honesty notes) |

## Corpus

Generated from fixed seeds (seeded PRNG, not crypto). Default (scale 1.0)
counts are deliberately TIME-BOUNDED, not the Foundation §14.4 reference
counts — see "Why the default corpus is small" below.

| fixture | shape | scale 1.0 |
|---|---|---|
| smallfiles | small files (64 B–4 KiB), deep dirs, unicode/space names (Latin, accented, CJK, emoji), empty dirs | 113 entries (96 files, 17 dirs), 179.8 KiB |
| node | package.json + package-lock.json + `node_modules/@bench/pkg-*` (12 pkgs × 4 files) + private src | 88 entries (60 files), 29.0 KiB |
| python | pyproject.toml + uv.lock + `.venv`-shaped tree (8 pkgs × 3 files + bin) + src | 51 entries (37 files), 13.9 KiB |
| media | incompressible seeded-PRNG data | 4 files × 64 MiB = 256 MiB |
| shared | 4 unique 1 MiB blobs × 6 copies each (dedup) + 4-name hardlink group (`os.Link`) | 31 entries (28 files), 28.0 MiB |

### Why the default corpus is small (and how to reach the reference counts)

The task's corpus target (~5,000-entry small-file tree; ~2,000 node files;
~1,500 python files) and its runtime budget (~10 minutes for the default full
run) are mutually exclusive on this hardware: one restic subprocess invocation
costs ~0.8–1.0 s here (measured below), and every §11.4 verification pass is
one `restic dump` PER FILE. Three readback-shaped passes per fixture
(snapshot, explicit readback, park) × 5,000 files ≈ 3.5–4 h for the smallfiles
fixture alone. The default counts were therefore sized to keep the full run
near ten minutes; the reference counts are one flag away:

| target | flag | projected runtime (measured per-file constant × count) |
|---|---|---|
| smallfiles ≈ 5,000 entries | `--scale 44` | ≈ 3.3 h (readback pass alone ≈ 63 min) |
| node ≈ 2,000 files | `--scale 40` | ≈ 33 min per readback pass |
| python ≈ 1,500 files | `--scale 40` | ≈ 23 min per readback pass |
| media 256 MiB | default | as measured |

Projections are arithmetic on the measured constants, not measurements.
Foundation §14.4's original 100,000-entry corpus projects to ≈ 21 h per park
with the current per-file transport.

## Measured operations (wall clock, seconds, default scale 1.0)

Per fixture the harness ran: metadata scan (`ebb inspect`-shaped), hashed
scan (the capture pass), `Coordinator.Snapshot` (capture + §11.4 coverage +
full readback + seal), an explicit full readback (every file node of the
payload dumped through `Store.DumpFile` and SHA-256-compared against the
independent scan digests), `Coordinator.Park` (capture + seal + revalidation
+ quarantine + removal), and `Opener.Open` to a fresh destination.

| fixture | scan meta | scan hash | snapshot | readback | park | open |
|---|---:|---:|---:|---:|---:|---:|
| smallfiles | 0.02 | 0.02 | 96.6 | 79.4 | 86.2 | 4.3 |
| node | 0.03 | 0.02 | 69.3 | 61.7 | 103.3 | 7.3 |
| python | 0.03 | 0.03 | 46.4 | 37.3 | 40.6 | 3.9 |
| media | 0.00 | 0.22 | 13.8 | 11.2 | 24.5 | 7.1 |
| shared | 0.01 | 0.04 | 49.1 | 26.4 | 30.3 | 3.7 |

Restic subprocess attribution (calls / cumulative subprocess seconds; the
harness counts through a decorator around the real store):

| fixture | snapshot | readback | park | open |
|---|---|---|---|---|
| smallfiles | 106 / 96.5 | 100 / 79.3 | 106 / 86.0 | 5 / 4.2 |
| node | 70 / 69.2 | 64 / 61.7 | 70 / 103.0 | 5 / 7.2 |
| python | 47 / 46.2 | 41 / 37.3 | 47 / 40.5 | 5 / 3.8 |
| media | 14 / 13.3 | 8 / 11.1 | 14 / 23.1 | 5 / 6.7 |
| shared | 38 / 48.1 | 32 / 26.4 | 38 / 30.1 | 5 / 3.7 |

Call-count shapes: snapshot/park = files + 10 (init id, repo id, backup P,
ls P, one dump per file incl. the three frozen op-dir documents, backup S,
ls S, dump S); readback = files + 4; open = 5 (seal + document dumps + one
`restore`). Subprocess time is 99.7–99.9 % of wall time in every op — the
pipeline is invocation-bound, not data-bound, for small files.

## Bytes

| fixture | logical | allocated (probe) | vault Δ snapshot | vault Δ park | park free Δ (observed) | park est. (logical) |
|---|---:|---:|---:|---:|---:|---:|
| smallfiles | 179.8 KiB | 179.8 KiB | 219.4 KiB | 6.2 KiB | −7.5 MiB | 179.8 KiB |
| node | 29.0 KiB | 29.0 KiB | 65.9 KiB | 6.1 KiB | −51.9 MiB | 29.0 KiB |
| python | 13.9 KiB | 13.9 KiB | 36.3 KiB | 6.1 KiB | −4.0 MiB | 13.9 KiB |
| media | 256.0 MiB | 256.0 MiB | 256.1 MiB | 6.1 KiB | +274.9 MiB | 256.0 MiB |
| shared | 28.0 MiB | 28.0 MiB | 5.0 MiB | 6.1 KiB | +14.7 MiB | 28.0 MiB |

(vault Δ snapshot = repository growth during the snapshot op; vault Δ park =
growth during the park op, i.e. the SECOND capture of the same content.)

## Per-entry readback overhead

`readback_seconds / readback_files` (per file) and `readback_seconds /
entries` (per entry, the §14.4 metric):

| fixture | readback files | readback s | ms/file | ms/entry |
|---|---:|---:|---:|---:|
| smallfiles | 99 | 79.4 | 802 | 703 |
| node | 63 | 61.7 | 980 | 701 |
| python | 40 | 37.3 | 932 | 731 |
| media | 7 | 11.2 | 1607 | 2800 |
| shared | 31 | 26.4 | 851 | 851 |

## Interpretation (honest)

1. **Readback dominates everything, and it is per-FILE, not per-byte.**
   For the small-file fixtures, readback is 60–92 % of park wall time, and
   per-file readback overhead is 0.80–0.98 s regardless of file size — the
   cost is the `restic dump` subprocess (startup, password KDF, repo open,
   index load), ~0.9 s per invocation on this machine. Scans are four orders
   of magnitude cheaper (0.02 s for 96 files); removal is invisible next to
   readback. Storage is not the problem: the park's SECOND capture of
   unchanged content grew the repository by only ~6 KiB per fixture
   (parent-snapshot dedup), while still paying the full per-file readback
   again. Verification is the cost.

2. **The per-file DumpFile transport cannot scale to the mandated corpus.**
   At the measured ~0.89 s/file average, the §14.4 5,000-entry small-file
   tree costs ≈ 63 min per readback pass (≈ 3.3 h for the harness's three
   passes), and a 100,000-entry tree projects to ≈ 21 h per park.
   IMPORTANT: these readback numbers reflect the per-file transport measured
   on this baseline date. A streaming-tar readback transport is being built
   in parallel (Foundation §11.4 allows consuming a directory dump as one
   streaming tar); when it lands, RE-MEASURE with this same harness — the
   comparison is the point.

3. **Open is cheap and scales with bytes, not file count.** 3.7–7.3 s per
   fixture regardless of entry count (one `restic restore` invocation plus
   five document dumps). media's 256 MiB open took 7.1 s (~36 MiB/s end to
   end including the independent-oracle verification scan). The park/open
   asymmetry is entirely the readback gate.

4. **Data-bound costs appear only at media scale.** The 64 MiB dumps add a
   visible data component: 1607 ms/file vs ~900 ms for tiny files, i.e.
   ~30 MiB/s per-dump throughput on top of the invocation constant. media's
   park (24.5 s) is the only park where backup+restore I/O, not invocation
   count, shapes the number.

5. **Dedup works and is visible in the vault deltas.** shared's 28 MiB of
   6×-duplicated content grew the repository 5.0 MiB (5.6× reduction; the
   4 hardlink names are stored as independent copies — known restic
   behavior on Windows, Learnings). media's 256 MiB of incompressible data
   grew it 256.1 MiB (1.00×, pure encryption/index overhead).

6. **Cluster-rounding gap between logical and allocated: NOT observed on
   this volume.** The production probe (FileCompressionInfo route) reported
   allocated == logical for every fixture and in a direct size sweep
   (100 B, 1 KiB, …, 1 MiB, 5000 B, 100 kB odd sizes all reported
   allocated == logical). This diverges from the Learnings entry that
   FileCompressionInfo reports ≥4 KiB per small file — worth re-checking
   the original lab observation against volume/machine differences before
   relying on either claim. Allocated sums are per-NAME and double-count
   the shared fixture's hardlink group (§14.1 caveat).

7. **Volume free-space deltas are only meaningful well above ~100 MiB on a
   live system.** The pre-run drift sample was 84 KiB (quiet moment), but
   during the run background system writes swamped the small fixtures:
   their park free-deltas came out NEGATIVE (−3.9 to −51.9 MiB) while
   freeing 14–180 KiB. media's +274.9 MiB (freed 256 MiB allocated, net of
   ~6 KiB vault growth, plus system noise) and shared's +14.7 MiB are the
   only deltas above the live-system noise floor. Single-run free-space
   numbers on an OS volume are observations, not attribution (Foundation
   §14.1 says exactly this).

8. **Per-invocation cost grows with repository state.** node's park made
   the same 70 restic calls as its snapshot but spent 103.0 s vs 69.2 s
   (1.47 s vs 0.99 s per call) after three more snapshots existed in the
   repository. One data point; if confirmed, per-file dump cost degrades
   further as vaults accumulate snapshots.

9. **Harness process memory is modest but readback of large files is
   whole-file in memory.** Peak harness RSS 590 MiB, driven by the 64 MiB
   media dumps (`DumpFile` returns whole files as byte slices — the current
   production readback path). A streaming transport would also fix this.

## Honesty notes

- Single wall-clock runs, not medians; the machine is a live laptop.
- The default run took 13 m 24 s, slightly over the ~10-minute target: the
  sizing arithmetic used ~0.8 s/invocation, the realized constant was
  ~0.9–1.0 s (and item 8 above pushed node's park further).
- The explicit-readback cell verifies workspace files against independent
  scan digests; the three frozen op-dir documents are read for cost but
  have no independent digest outside the snapshot.
- Peak RSS excludes restic subprocess memory (runtime.MemStats covers the
  harness process only).

---

# Post-D019 re-measure (streaming tar readback) — 2026-09-19

Same harness, same default scale, same machine, same reproduce command
(`go run ./lab/bench`); the only change in the measured code path is that
the harness now exercises the D019 streaming tar readback transport
(wave G W2) instead of silently falling back to the per-file one — see
the surprise below. Raw evidence for this run: `lab/bench/results/
20260918T231442Z/` (the run's own UTC clock label; written 2026-09-19).

## Surprise first: the harness was measuring the wrong transport

The first rerun reproduced the baseline's per-file numbers almost
exactly. Cause: the harness's counting decorator embedded only
`domain.SnapshotStore`, and `DumpTreeTar` lives in the separate,
interface-segregated `domain.TreeTarDumper` seam (D019 deliberately left
`SnapshotStore`'s method set unchanged so all fakes keep compiling). A
decorator that embeds only the base interface HIDES the optional seam
from lifecycle's `store.(domain.TreeTarDumper)` assertion — the exact
wrapper-hides-optional-interface lesson Learnings already records for
verified-dir-descent probe wrappers. Fixed by embedding and explicitly
delegating `TreeTarDumper` in the counting store (tar dumps are counted
on stream Close, the producer-exit/full-consumption gate). Lesson
recorded; any future decorator around the store must do the same.

## Headline numbers (default scale 1.0)

| fixture | snapshot before → after | park before → after | snapshot restic calls before → after |
|---|---|---|---|
| smallfiles | 96.6 s → 5.9 s | 86.2 s → 6.0 s | 106 → 8 |
| node | 69.3 s → 5.8 s | 103.3 s → 5.9 s | 70 → 8 |
| python | 46.4 s → 5.7 s | 40.6 s → 5.8 s | 47 → 8 |
| media | 13.8 s → 7.0 s | 24.5 s → 6.9 s | 14 → 8 |
| shared | 49.1 s → 5.9 s | 30.3 s → 5.9 s | 38 → 8 |

The §11.4 full readback inside capture (snapshot) and park now costs a
FLAT 8 restic invocations per fixture regardless of file count. Total
harness runtime: 13 m 24 s → 4 m 45 s; peak harness RSS 590.2 →
461.4 MiB.

## Readback transport comparison (new measurement, same file set + same independent digests)

The harness's explicit-readback operation remains, by design, a raw
per-file `Store.DumpFile` walk — it is the D019 FALLBACK transport's
cost curve, kept as the yardstick (that column did not "collapse" and
should not: it is no longer the production path). The new comparison
column drives the exact same file set and the same independent scan
digests through `lifecycle.VerifyReadback` — the exported §11.4 executor
`ebb verify --content` rides, which selects the tar transport when the
store implements `TreeTarDumper`:

| fixture | files | per-file DumpFile s | tar transport s | speedup |
|---|---:|---:|---:|---:|
| smallfiles | 96 | 80.0 | 0.8 | 99.2x |
| node | 60 | 51.5 | 0.8 | 64.0x |
| python | 37 | 33.1 | 0.8 | 40.7x |
| media | 4 | 6.9 | 1.1 | 6.4x |
| shared | 28 | 25.9 | 0.8 | 31.4x |

Per-file overhead on the fallback transport is unchanged (~0.81–0.99
s/file — invocation-bound, as the baseline established); the tar
transport is a constant ~0.8 s subprocess per TREE plus byte-bound
streaming (media, 4 × 64 MiB, is the honest byte-bound case at 6.4x).

## What this does to the reference-scale projections

The baseline's projection table (smallfiles `--scale 44` ≈ 3.3 h with a
≈ 63 min readback pass) collapses on the transport that production
actually uses: the tar readback pass for ~5,000 small files projects to
roughly one minute (one subprocess streaming ~10 MiB at these file
sizes), and a snapshot or park of that tree to minutes, not hours.
D021's "reconsider when reference-scale runs become cheap enough" gate
is now met — the default corpus can grow on the next baseline refresh.

## Honesty notes for this run

- Single wall-clock run, live laptop, same caveats as the baseline.
- The per-file readback column and the new tar column run back to back
  over the same snapshot, so the speedup column shares fixture state;
  the tar pass runs second (repo/index warm) — the per-file pass had the
  same warmup advantage over the baseline's cold numbers, and 30–99x is
  far outside that noise.
- park free-deltas for the small fixtures remain inside the measured
  noise floor (0 B drift over 8 pre-run samples; small negative deltas
  are live-system writes, as the baseline's note 7 already explains).
- `media`'s tar speedup (6.4x) is byte-bound, not invocation-bound: with
  4 × 64 MiB files the per-file transport pays only 4 invocations. The
  tar win is a SMALL-FILE win — exactly the corpus shape the reference
  targets care about.

---

## The Messy Codebase Gauntlet (5+1) — 2026-09-21

The gauntlet (lab/gauntlet) is the release benchmark for Ebb's *messy
codebase* contract: six synthetic developer workspaces (~5.2 GiB, 16,680
files, byte-deterministic for seed 20260921) that the REAL ebb binary
runs `reclaim / restore / park / open` against, each flow a separate
process with an isolated state dir under a disposable scratch. It is
both a benchmark and a SAFETY gate: the runner itself sha256-digests
every workspace's Preserve set before the first flow and compares it
after EVERY flow and at the end, walks the whole tree asserting nothing
outside declared Ebbfile outputs vanished, verifies the neglected
veteran's merge conflict round-trips park/open unresolved (via
`git ls-files -u` as an independent oracle), and requires the torture
bar to degrade without panics or data loss.

Methodology note: the first scale-1.0 run
(lab/gauntlet/results/20260921T195832Z) caught a fixture
inconsistency — the polyglot Preserve set listed
`services/api/.venv/pyvenv.cfg`, a file inside the same archetype's
declared `.venv` regenerable output, which ebb (correctly) trimmed with
the whole group — after which the corpus dropped the entry and gained a
regression test (`TestPreserveDisjointFromDeclaredOutputs`,
lab/gauntlet/corpus_test.go) asserting no Preserve path ever lies inside
a declared output; the tables below are the post-fix green run.

Reproduce: `go run ./lab/gauntlet` (defaults; see lab/gauntlet/README.md
for flags). Raw evidence for this section:
`lab/gauntlet/results/20260921T201637Z/` (results.json, report.md,
plus every flow's verbatim --json envelope under flows/). The earlier
runs stay committed as history (20260921T194516Z first run, also the
park-cwd evidence; 20260921T195832Z the fixture-inconsistency run).

### Environment

| Item | Value |
|---|---|
| OS | Windows 11 (10.0.26200), NTFS system volume |
| CPU | 12th Gen Intel Core i5-12450HX (12 logical CPUs) |
| ebb | 0.1.0-dev (built by the runner from this tree, `go build ./cmd/ebb`) |
| Backend | restic 0.19.1 (windows/amd64, go1.26.4), local repo in the scratch |
| Go | go1.27.1 windows/amd64 |
| Corpus | 6 archetypes, scale 1.0, seed 20260921: 16,680 files / 5.2 GiB |
| Total harness runtime | 336.3 s (~5 min 36 s), single run |
| Volume free-space noise | drift 1.2 MiB over 8 pre-run samples (deltas within this are noise) |
| Peak memory method | Windows Job Object `PeakJobMemoryUsed` — the commit peak of the WHOLE flow tree (ebb + restic + cmd.exe recipes), not ebb alone |

Flows run headless with `--json`; argv is pinned by test
(`reclaim --dry-run --yes`, `reclaim --yes`, `restore --json` — restore
takes no `--yes` by its own contract — `park <root> --yes
--assert-writers-stopped`, `open <name> --yes` from outside the
workspace; see the open finding below).

### Results: all six archetypes pass

Every archetype met its expectation contract (flows exited as designed)
with every Preserve byte identical after every flow and at the end —
6/6 PASS, runner verdict "ALL EXPECTATIONS PASSED".

### clean-starter — pass (600 MiB, 2,456 files)

| flow | exit | wall | peak RSS | free Δ (vs 1.2 MiB noise) | ebb bytes | expectation | preserve intact |
|---|---:|---:|---:|---|---|---|---|
| reclaim-dry | 0 | 2.3 s | 90.5 MiB | +1.1 MiB (noise) | — | pass | YES |
| reclaim | 0 | 17.1 s | 231.4 MiB | +602.3 MiB | freed-est 600.0 MiB, freed-obs 605.6 MiB | pass | YES |
| restore | 0 | 2.6 s | 160.8 MiB | −5.7 MiB | — | pass | YES |

### real-world-dev — pass (600 MiB, 2,067 files)

| flow | exit | wall | peak RSS | free Δ | ebb bytes | expectation | preserve intact |
|---|---:|---:|---:|---|---|---|---|
| reclaim | 0 | 16.0 s | 211.9 MiB | +504.2 MiB | freed-est 500.0 MiB, freed-obs 504.1 MiB | pass | YES |
| restore | 0 | 4.0 s | 159.9 MiB | +3.4 MiB | — | pass | YES |

The dirty git state (unmerged spike branch, staged+unstaged edits,
untracked .env/notes/recordings) survived both flows byte-for-byte.

### polyglot-monorepo — pass (1.5 GiB, 4,641 files)

| flow | exit | wall | peak RSS | free Δ | ebb bytes | expectation | preserve intact |
|---|---:|---:|---:|---|---|---|---|
| reclaim | 0 | 45.2 s | 229.3 MiB | +1.5 GiB | freed-est 1.5 GiB, freed-obs 1.5 GiB | pass | YES |
| restore | 0 | 2.0 s | 161.2 MiB | −5.9 MiB | — | pass | YES |

All three ecosystem groups (npm web, uv api, cargo engine) were
trimmed whole as their Ebbfiles declare, all three offline recipes ran
on restore, and all 36 Preserve files (manifests, locks, sources — all
outside declared outputs) were byte-identical after both flows.

### heavy-asset — pass (1.7 GiB, 4,818 files)

| flow | exit | wall | peak RSS | free Δ | ebb bytes | expectation | preserve intact |
|---|---:|---:|---:|---|---|---|---|
| reclaim | 0 | 22.9 s | 225.4 MiB | +159.6 MiB | freed-est 144.0 MiB, freed-obs 159.5 MiB | pass | YES |
| park | 0 | 41.3 s | 577.1 MiB | +9.3 MiB | preserved 1.6 GiB, freed-est 1.6 GiB, freed-obs 9.5 MiB | pass | YES |
| open | 0 | 23.2 s | 285.9 MiB | −1.68 GiB | restored 1.6 GiB | pass | YES |

park's freed-obs stays far below the estimate because the park
SNAPSHOT grows the vault on the same volume by roughly what the removal
frees — the honest attribution number is the estimate (1.6 GiB), with
the runner-observed open delta writing it all back. Peak park RSS
577 MiB is the flow tree's commit peak while streaming 2 × 700 MiB
safetensors through restic.

### neglected-veteran — pass (600 MiB, 2,460 files)

| flow | exit | wall | peak RSS | free Δ | ebb bytes | expectation | preserve intact |
|---|---:|---:|---:|---|---|---|---|
| reclaim | 0 | 13.3 s | 214.2 MiB | +601.8 MiB | freed-est 600.0 MiB, freed-obs 601.7 MiB | pass | YES |
| park | 0 | 7.0 s | 257.8 MiB | +15.1 MiB | preserved 53.0 KiB, freed-est 53.0 KiB, freed-obs 16.1 MiB | pass | YES |
| open | 0 | 4.2 s | 156.5 MiB | +2.9 MiB | restored 53.0 KiB | pass | YES |

The unresolved merge conflict round-tripped park/open UNRESOLVED, as
Foundation §9.2 demands: after open, `.git/MERGE_HEAD` exists and
`git ls-files -u` still lists unmerged entries (verified with plain git
as an independent oracle). The registry-impossible lockfile and the
8-month-stale mtimes changed nothing.

### torture-bar — pass, fail-closed expectation met by graceful success

| flow | exit | wall | peak RSS | free Δ | ebb bytes | expectation | preserve intact |
|---|---:|---:|---:|---|---|---|---|
| reclaim-dry | 0 | 0.6 s | 89.2 MiB | 0 B (noise) | — | pass (0 with warnings) | YES |
| reclaim | 0 | 24.4 s | 194.2 MiB | +332.5 MiB | freed-est 330.0 MiB, freed-obs 332.7 MiB | pass (0 with warnings) | YES |

The designed-to-fail zoo did not make ebb fail: the junction cycle
(absolute-target junctions a→b→a), the 412-char deep path, the corrupt
manifests and the held-open hold.txt all survived, ebb trimmed all four
declared node_modules groups, and exited 0 both times with only planner
notes in warnings — no refusal was ever needed. The junction cycle is
still a junction cycle, the deep bottom file is byte-identical, and
keep/ (notes, .env, credentials) never moved a byte. The held-open file
did not block anything because it lives OUTSIDE every declared output —
the scenario pins that ebb's removal authority stays inside declared
outputs rather than sweeping parents.

### Open finding (ebb bug; does not gate these tables): park from inside the workspace

`ebb park` run with its cwd INSIDE the workspace — the CLI's own
default shape, `ebb park [path]` with path "." — fails on Windows at
the quarantine rename with errno 32 every time: the invoking process's
own cwd handle blocks renaming the root directory. Exit 5
(`reconciliation-required`):

```text
lifecycle: removal blocked at C:\ebb-gauntlet\run-...\corpus\heavy-asset
(EBB_E_SHARING_VIOLATION): rename to quarantine blocked by an open handle
(errno 32); close writers and retry: rename ...\heavy-asset ...\.ebb-quarantine-...:
The process cannot access the file because it is being used by another process.
```

An identical fixture parked from OUTSIDE with an explicit path succeeds
(exit 0, DONE). Reproduced minimally both ways (evidence:
lab/gauntlet/results/20260921T194516Z); the tables above therefore run
park/open from outside — a documented deviation, not a massage. Two
follow-on inconsistencies in the same path: the park error tells the
user to run `ebb recover <op> --resume-removal`, but recover REFUSES
for a SEALED park operation ("ResumeRemoval applies to
QUARANTINED/REMOVING/REMOVAL_BLOCKED"), and plain `ebb recover <op>`
then exits 0 "ok" WITHOUT removing the workspace. Likely fix direction:
before the quarantine rename, if the target root is the process cwd,
`os.Chdir` to the parent first. Until the fix lands and the gauntlet is
re-run, the park/open numbers here describe the from-outside shape.

### Limitations (honest)

- Restore recipes recreate 5 MiB marker trees, NOT full dependency
  reinstalls (offline by design; full reinstalls are covered by
  ecosystem e2e tests). Reclaim/park sides are real full-tree
  operations.
- Peak RSS is the Job Object commit peak of the whole flow tree (ebb +
  restic + cmd.exe recipes) — ebb-alone RSS is strictly lower; no
  per-process split is claimed.
- Volume free-space deltas are observations on a live OS volume against
  a 1.2 MiB measured noise floor; park's freed-obs is further confounded
  by vault growth on the same volume (noted above).
- Single wall-clock runs, not medians; the machine is a live laptop.
- park/open are measured via the from-outside shape because of the open
  park-cwd finding above; re-run the gauntlet after that fix to cover
  the CLI's default from-inside shape too.
