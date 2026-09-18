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
| ebb | 0.1.0-dev (`lifecycle.ProducerEbbVersion`) |
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
