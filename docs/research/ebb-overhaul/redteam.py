#!/usr/bin/env python3
"""Bounded adversarial experiments for Ebb's proposed overhaul.

NOT Ebb integration tests. No restic, package installation, or user data is used.
Every filesystem fixture is a fresh TemporaryDirectory owned by this script.
Hypotheses and negative controls are defined below before execution. Output is
JSON, a Markdown report, and a TSV evidence ledger in an explicitly chosen dir.

Acceptance: every unsafe baseline must produce its specified counterexample;
every revised mechanism must meet the stated local gate. A passing observation
does not prove native Windows behavior, power-loss durability, or application
readiness. Test failures exit nonzero and are preserved in the report.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import random
import shutil
import sqlite3
import sys
import tempfile
import zlib
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone

RESULTS: list[dict] = []


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record(ident: str, boundary: str, hypothesis: str, falsifier: str, fn) -> None:
    try:
        observations = fn()
        RESULTS.append(dict(id=ident, boundary=boundary, hypothesis=hypothesis,
                            falsifier=falsifier, status="OBSERVED", observations=observations))
    except Exception as exc:
        RESULTS.append(dict(id=ident, boundary=boundary, hypothesis=hypothesis,
                            falsifier=falsifier, status="TEST_FAILED",
                            error=f"{type(exc).__name__}: {exc}"))


def recency() -> dict:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE snapshots(id TEXT, created_at TEXT, kind TEXT)")
    db.executemany("INSERT INTO snapshots VALUES(?,?,?)", [
        ("old", "2026-09-01", "park"), ("new", "2026-09-24", "park")])
    rows = db.execute("SELECT id,created_at,kind FROM snapshots ORDER BY created_at,id").fetchall()
    selected = next(r[0] for r in rows if r[2] == "park")
    fixed = max(rows, key=lambda r: (r[1], r[0]))[0]
    assert selected == "old" and fixed == "new"
    return dict(ascending_first=selected, explicit_latest=fixed,
                scope="Original SQL ordering plus reduced selection; not the Go CLI")


def outstanding() -> dict:
    operations = [(1, "python"), (2, "node")]
    latest_only = [max(operations)[1]]
    obligations = {group: generation for generation, group in operations}
    assert latest_only == ["node"] and set(obligations) == {"python", "node"}
    return dict(latest_only=latest_only, outstanding_groups=sorted(obligations))


def historical_counts() -> dict:
    db = sqlite3.connect(":memory:")
    db.executescript("CREATE TABLE snapshots(id TEXT,pinned INTEGER);"
                     "CREATE TABLE retention_intents(snapshot_id TEXT,completed_at TEXT);")
    db.executemany("INSERT INTO snapshots VALUES(?,1)", [("a",), ("b",)])
    db.execute("UPDATE snapshots SET pinned=0 WHERE id='a'")
    db.execute("INSERT INTO retention_intents VALUES('a','completed')")
    backend = {"b"}
    count = db.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0]
    assert count == 2 and len(backend) == 1 and not (count == 1)
    return dict(history_rows=count, surviving_copies=len(backend),
                old_additional_last_copy_guard=False, custody_based_guard=True)


def metadata_patch(root: Path) -> dict:
    info = root / "sample-1.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Name: sample\nVersion: 1.0\n")
    impl = root / "sample.py"
    impl.write_text("answer = 1\n")
    before = digest(impl.read_bytes())
    meta = digest((info / "METADATA").read_bytes())
    impl.write_text("answer = 2\n")
    assert digest((info / "METADATA").read_bytes()) == meta
    assert digest(impl.read_bytes()) != before
    return dict(package_metadata_unchanged=True, implementation_changed=True,
                implication="Matching installed versions do not prove exact reconstructibility")


def stale_stat(root: Path) -> dict:
    p = root / "same-stat"
    p.write_bytes(b"AAAA")
    a = p.stat()
    before = digest(p.read_bytes())
    p.write_bytes(b"BBBB")
    os.utime(p, ns=(a.st_atime_ns, a.st_mtime_ns))
    b = p.stat()
    assert (a.st_ino, a.st_size, a.st_mtime_ns) == (b.st_ino, b.st_size, b.st_mtime_ns)
    assert before != digest(p.read_bytes())
    return dict(inode_size_mtime_equal=True, bytes_equal=False,
                limitation="Does not defeat every richer stat fingerprint; rejects this specific shortcut")


def hardlinks(root: Path) -> dict:
    live, shared, independent = (root / x for x in ("live", "shared", "independent"))
    live.write_bytes(b"original")
    os.link(live, shared)
    shutil.copy2(live, independent)
    live.write_bytes(b"modified")
    assert shared.read_bytes() == b"modified" and independent.read_bytes() == b"original"
    return dict(hardlink_backup_changed=True, independent_copy_changed=False,
                same_inode=live.stat().st_ino == shared.stat().st_ino)


def ancestor_link(root: Path) -> dict:
    workspace, outside = root / "workspace", root / "outside"
    workspace.mkdir(); outside.mkdir()
    (outside / "sentinel").write_text("outside")
    (workspace / "cache").symlink_to(outside, target_is_directory=True)
    lexical = workspace / "cache" / "sentinel"
    assert lexical.is_relative_to(workspace) and lexical.read_text() == "outside"
    assert not lexical.resolve().is_relative_to(workspace.resolve())
    blocked = False
    try:
        fd = os.open(workspace / "cache", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        blocked = True
    else:
        os.close(fd)
    assert blocked
    return dict(lexically_inside=True, actual_target_outside=True,
                nofollow_directory_open_refused=True,
                limitation="Single-component check only, not a full race-resistant path provider")


def rename_writer(root: Path) -> dict:
    live, quarantine = root / "live-dir", root / "quarantine"
    live.mkdir()
    p = live / "state"
    p.write_bytes(b"before")
    fd = os.open(p, os.O_RDWR)
    try:
        live.rename(quarantine)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, b"AFTER!")
        os.fsync(fd)
    finally:
        os.close(fd)
    assert (quarantine / "state").read_bytes() == b"AFTER!"
    return dict(write_after_rename_succeeded=True,
                implication="Quarantine and writer quiescence are separate requirements")


def empty_output(root: Path) -> dict:
    out = root / "node_modules"
    out.mkdir()
    existence_pass = out.exists()
    required_present = (out / "critical-package" / "index.js").exists()
    assert existence_pass and not required_present
    return dict(existence_gate_passed=True, expected_content_present=False)


def partial_restore(root: Path) -> dict:
    a, b = root / "a", root / "b"
    a.mkdir(); (a / "new-user-work").write_text("new")
    all_present = all(p.exists() for p in (a, b))
    assert not all_present
    conflict_groups = [p.name for p in (a, b) if p.exists()]
    assert conflict_groups == ["a"] and (a / "new-user-work").read_text() == "new"
    return dict(global_gate_would_allow_replay=True, groups_requiring_conflict_handling=conflict_groups,
                limitation="Does not invoke npm; models the caller's gating, preserves the sentinel")


def allocation() -> dict:
    random_data = random.Random(20260925).randbytes(1024 * 1024)
    repetitive = b"x" * (1024 * 1024)
    measurements = {}
    for name, data in [("high_entropy", random_data), ("repetitive", repetitive)]:
        packed = zlib.compress(data)
        net = len(data) - len(packed)
        measurements[name] = dict(source_bytes=len(data), retained_bytes=len(packed), net_bytes=net)
    assert measurements["high_entropy"]["net_bytes"] < 0
    assert measurements["repetitive"]["net_bytes"] > 0
    return dict(codec="zlib, NOT a restic benchmark", measurements=measurements,
                implication="Same-volume exact retention does not guarantee positive net gain")


def future_dependency() -> dict:
    observed = {"base.dat"}
    later_run = {"base.dat", "feature-enabled.dat"}
    assert later_run - observed == {"feature-enabled.dat"}
    return dict(trace_covered_observed_run=True, unobserved_dependency=sorted(later_run-observed),
                scope="Logical counterexample to trace completeness, not a tracer experiment")


@dataclass(frozen=True)
class State:
    live: bool = True
    buffered: bool = False
    durable: bool = False
    verified: bool = False
    obligation: bool = False
    lease: bool = False
    restored: bool = False


def transitions(s: State, mutant: str = ""):
    if s.live and not s.buffered and not s.durable:
        yield "copy_to_buffer", replace(s, buffered=True)
    if s.buffered and not s.durable:
        yield "durably_commit", replace(s, durable=True, buffered=False)
    if (s.durable or (mutant == "verify_volatile" and s.buffered)) and not s.verified:
        yield "verify", replace(s, verified=True)
    if s.verified and not s.obligation:
        yield "pin_obligation", replace(s, obligation=True)
    if s.live and s.verified and s.obligation and (s.durable or mutant == "verify_volatile"):
        yield "remove_live", replace(s, live=False)
    if s.buffered:
        yield "crash_loses_buffer", replace(s, buffered=False)
    if s.durable and not s.lease:
        yield "begin_read_lease", replace(s, lease=True)
    if s.lease and s.durable and not s.live:
        yield "restore_publish", replace(s, live=True, restored=True)
    if s.lease:
        yield "end_read_lease", replace(s, lease=False)
    if s.live and s.restored and s.obligation:
        yield "release_obligation", replace(s, obligation=False)
    gc_allowed = not s.obligation and not s.lease
    if mutant == "ignore_obligations":
        gc_allowed = not s.lease
    if mutant == "ignore_leases":
        gc_allowed = not s.obligation
    if s.durable and gc_allowed:
        yield "gc", replace(s, durable=False, verified=False)


def invariant(s: State) -> bool:
    return (s.live or s.durable) and (not s.lease or s.durable)


def explore(mutant: str = "") -> dict:
    initial = State()
    pending = deque([(initial, [])])
    seen = {initial}
    edges = 0
    while pending:
        state, path = pending.popleft()
        for event, nxt in transitions(state, mutant):
            edges += 1
            if not invariant(nxt):
                return dict(states=len(seen), edges=edges, counterexample=path+[event])
            if nxt not in seen:
                seen.add(nxt); pending.append((nxt, path+[event]))
    return dict(states=len(seen), edges=edges, counterexample=None)


def crash_gc_model() -> dict:
    result = {name or "revised": explore(name) for name in
              ("", "verify_volatile", "ignore_obligations", "ignore_leases")}
    assert result["revised"]["counterexample"] is None
    assert all(result[name]["counterexample"] for name in
               ("verify_volatile", "ignore_obligations", "ignore_leases"))
    return dict(results=result, invariant="live or durable; an active reader always has durable content",
                exclusions="Single content object. Atomic abstract transitions. No torn I/O, filesystem, cryptography, arbitrary writers or multi-host coordination.")


def intent_dispatch() -> dict:
    cases = 0
    for tty, json_mode, noninteractive, missing in itertools.product([False, True], repeat=4):
        guided = tty and not json_mode and not noninteractive and missing
        mode = "guided" if guided else ("structured-error" if missing else "direct")
        assert mode != "guided" or (tty and not json_mode and not noninteractive)
        cases += 1
    shown_generation, actual_generation = 7, 8
    can_execute = shown_generation == actual_generation
    assert not can_execute
    executed_tokens = set()
    token = ("workspace-1", 7, "reviewed-plan")
    dispatches = 0
    for _ in range(2):
        if token not in executed_tokens:
            executed_tokens.add(token); dispatches += 1
    assert dispatches == 1
    return dict(dispatch_cases=cases, stale_plan_execution_allowed=can_execute,
                duplicate_accept_dispatches=dispatches,
                exclusions="Reducer model, not terminal rendering or a crash-durable idempotency implementation")


def output_claims() -> dict:
    evidence = {"files_verified": True, "recipe_exit_zero": True, "health_checked": False}
    readiness = "application-checked" if evidence["health_checked"] else "files-recovered"
    assert readiness == "files-recovered"
    return dict(evidence=evidence, reported=readiness,
                implication="A successful installer must not manufacture application-readiness evidence")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    specs = [
        ("R01", "SQL + source-shaped reduction", "Ascending-first means latest", "Two dates select the older date", recency),
        ("R02", "decision reduction", "Latest trim represents all outstanding groups", "An earlier group is omitted", outstanding),
        ("R03", "SQL + custody reduction", "Historical row count equals surviving copies", "Two rows but one surviving copy", historical_counts),
        ("R04", "real local filesystem", "Matching package metadata proves identical content", "Implementation changes without metadata changes", metadata_patch),
        ("R05", "real local filesystem", "Inode/size/mtime is sufficient content evidence", "Same tuple has different digest", stale_stat),
        ("R06", "real local filesystem", "A live hardlink is an independent backup", "Writing live modifies backup", hardlinks),
        ("R07", "real Linux filesystem", "Lexical containment confines actual access", "Ancestor symlink reaches sibling sentinel", ancestor_link),
        ("R08", "real Linux filesystem", "Rename-to-quarantine stops existing writers", "An open descriptor writes after rename", rename_writer),
        ("R09", "real local filesystem", "Existing output means successful reconstruction", "Empty output passes existence but lacks required content", empty_output),
        ("R10", "real fixture + decision reduction", "Any missing output makes whole replay safe", "Another output contains new live work", partial_restore),
        ("R11", "real codec, not product benchmark", "Exact same-volume retention always saves space", "Incompressible fixture grows after compression", allocation),
        ("R12", "logical counterexample", "One observed run includes all future dependencies", "Another input activates another dependency", future_dependency),
        ("R13", "exhaustive finite-state model", "Durability, obligations and leases suffice within the model", "Reachable state violates custody; mutants must fail", crash_gc_model),
        ("R14", "UI decision model", "Machine modes never guide; stale/duplicate acceptance cannot execute", "Bad mode or repeated dispatch", intent_dispatch),
        ("R15", "outcome decision model", "Evidence levels remain separate", "Files-only evidence becomes application-ready", output_claims),
    ]
    with tempfile.TemporaryDirectory(prefix="ebb-design-redteam-") as scratch:
        for ident, boundary, hypothesis, falsifier, fn in specs:
            if fn in {metadata_patch, stale_stat, hardlinks, ancestor_link, rename_writer, empty_output, partial_restore}:
                root = Path(scratch) / ident
                root.mkdir()
                record(ident, boundary, hypothesis, falsifier, lambda fn=fn, root=root: fn(root))
            else:
                record(ident, boundary, hypothesis, falsifier, fn)
    output = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
                  environment=dict(system=platform.system(), release=platform.release(),
                                   python=sys.version.split()[0], sqlite=sqlite3.sqlite_version,
                                   restic=shutil.which("restic"), agy=shutil.which("agy")),
                  boundary="Design experiments, NOT Ebb product or Windows certification", results=RESULTS)
    (args.out / "results.json").write_text(json.dumps(output, indent=2) + "\n")
    lines = ["# Executed adversarial experiments", "", output["boundary"], "",
             "| ID | Boundary | Status | Hypothesis or gate |", "|---|---|---|---|"]
    lines.extend(f"| {r['id']} | {r['boundary']} | {r['status']} | {r['hypothesis']} |" for r in RESULTS)
    for r in RESULTS:
        lines.extend(["", "## " + r["id"], "", "Falsifier: " + r["falsifier"], "",
                      "```json", json.dumps(r.get("observations", {"error": r.get("error")}), indent=2), "```"])
    (args.out / "report.md").write_text("\n".join(lines) + "\n")
    tsv = ["id\tboundary\tstatus\tclaim\tevidence"]
    tsv.extend("\t".join((r["id"], r["boundary"], r["status"], r["hypothesis"],
                           "results.json#" + r["id"])) for r in RESULTS)
    (args.out / "ledger.tsv").write_text("\n".join(tsv) + "\n")
    print(json.dumps(output, indent=2))
    return int(any(r["status"] != "OBSERVED" for r in RESULTS))


if __name__ == "__main__":
    raise SystemExit(main())
