#!/usr/bin/env python3
"""Second-round counterexamples against the recovery-first proposal.
These are reduced models, not Ebb integration tests. Each finding tightens a
previously plausible contract. Nothing outside a new tempfile is modified.
"""
import json
from pathlib import Path
import tempfile

results = []
with tempfile.TemporaryDirectory(prefix='ebb-redteam-round2-') as root:
    root = Path(root)
    live = root / 'live'
    backup = root / 'backup'
    live.write_bytes(b'generation-one')
    backup.write_bytes(live.read_bytes())
    captured = backup.read_bytes()
    live.write_bytes(b'generation-two')
    assert captured != live.read_bytes()
    results.append({'id': 'R16', 'boundary': 'real fixture + decision reduction',
                    'hypothesis': 'Verified backup alone permits later removal of live data',
                    'verdict': 'FALSIFIED', 'observed': 'Backup is valid but contains an older generation.',
                    'revision': 'Require a stable capture/removal epoch. Snapshots and hash rechecks alone do not stop subsequent writers. Strict unattended eviction needs enforceable exclusion or an immutable owner; cooperative quiescence is an explicit assumption.'})

    model = {'source_present': True, 'copy_1': {'device': 'disk-a', 'present': True},
             'copy_2': {'device': 'disk-a', 'present': True}}
    copies = [model['copy_1'], model['copy_2']]
    assert len(copies) == 2 and len({c['device'] for c in copies}) == 1
    results.append({'id': 'R17', 'boundary': 'custody/failure-domain model',
                    'hypothesis': 'Two copy locations protect against a disk failure',
                    'verdict': 'FALSIFIED', 'observed': 'Both copy locations share disk-a.',
                    'revision': 'Count independent failure domains separately from logical copies; unknown domain must remain unknown, not be guessed independent.'})

    pending = {'A': 'evicted', 'B': 'live'}
    assert len(set(pending.values())) == 2
    results.append({'id': 'R18', 'boundary': 'multi-component interruption model',
                    'hypothesis': 'A batch can be described with one done/not-done flag',
                    'verdict': 'FALSIFIED', 'observed': 'Crash after component A leaves B live.',
                    'revision': 'Parent batch records per-component generations and outcomes. Promise resumable partial completion, not filesystem-wide atomicity.'})

    vault_only = {'payload': 'forged', 'manifest_digest': 'forged-hash', 'seal_digest': 'forged-hash'}
    internally_consistent = vault_only['manifest_digest'] == vault_only['seal_digest']
    assert internally_consistent
    results.append({'id': 'R19', 'boundary': 'trust-anchor counterexample',
                    'hypothesis': 'After losing the catalog, self-consistent vault documents prove original authenticity',
                    'verdict': 'FALSIFIED', 'observed': 'A replacement manifest and seal can agree with one another.',
                    'revision': 'Distinguish recoverable consistency from continuity of authenticity. Retain an independent trusted checkpoint or explicitly re-establish trust; a key or witness stored only beside the data does not add an independent anchor.'})

print(json.dumps({'boundary': 'Round-two design tests; no native product qualification', 'results': results}, indent=2))
