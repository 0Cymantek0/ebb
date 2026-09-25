#!/usr/bin/env python3
"""Real local counterexample: staged Python environment publication.
No pip or network. Only a fresh TemporaryDirectory is created and removed.
The console script is a fixture using Python's documented absolute shebang form.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import venv

with tempfile.TemporaryDirectory(prefix='ebb-path-sensitive-') as scratch:
    root = Path(scratch)
    stage, final = root / 'staged-env', root / 'final-env'
    venv.EnvBuilder(with_pip=False, symlinks=True).create(stage)
    script = stage / 'bin' / 'fixture-tool'
    script.write_text('#!' + str(stage / 'bin' / 'python') + '\nprint("ready")\n')
    script.chmod(0o755)
    before = hashlib.sha256(script.read_bytes()).hexdigest()
    initial = subprocess.run([str(script)], check=True, capture_output=True, text=True)
    assert initial.stdout.strip() == 'ready'
    stage.rename(final)
    moved = final / 'bin' / 'fixture-tool'
    assert hashlib.sha256(moved.read_bytes()).hexdigest() == before
    try:
        subprocess.run([str(moved)], check=True, capture_output=True, text=True)
    except FileNotFoundError as exc:
        observed_errno = exc.errno
    else:
        raise AssertionError('Expected absolute-shebang command to fail after relocation')
    assert observed_errno == 2
    result = {
        'id': 'R20', 'boundary': 'real Linux venv and subprocess, no package installation',
        'hypothesis': 'A successfully rebuilt environment can always be staged then renamed',
        'verdict': 'FALSIFIED', 'before_stdout': 'ready', 'after_errno': observed_errno,
        'script_bytes_unchanged': True,
        'revision': 'Separate byte materialization from reconstruction. Rebuild path-sensitive outputs at their intended logical path inside a qualified isolation provider, use a proven relocatable recipe, or require explicit host-trusted repair with retained checkpoints. Do not claim generic stage-and-rename makes all rebuilt environments runnable.',
        'limits': 'A generated fixture console script exercises the documented shebang rule; it is not a test of all Python packages or Windows venvs.'
    }
    print(json.dumps(result, indent=2))
