"""Cached retired agent callbacks must never block ongoing development."""

import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


ENTRY = Path(__file__).resolve().parents[1] / "scripts/eval_hook.py"


@pytest.mark.parametrize(
    "module",
    [None, "this is not valid Python !!!\n", "raise RuntimeError('broken adapter')\n"],
)
def test_retired_callback_never_imports_adapter_or_blocks_work(tmp_path, module):
    root = tmp_path / "checkout"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    shutil.copy2(ENTRY, scripts / "eval_hook.py")
    package = root / "skylos/benchmarks"
    package.mkdir(parents=True)
    (root / "skylos/__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    if module is not None:
        (package / "eval_hooks.py").write_text(module)
    result = subprocess.run(
        [sys.executable, "-B", str(scripts / "eval_hook.py"), "--client", "codex"],
        input=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "cwd": str(root),
                "session_id": "bootstrap",
            }
        ),
        cwd=root,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout) == {}
    assert not result.stderr
