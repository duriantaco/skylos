"""Done must reject removed auth even when existing tests stay green."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, run_check
from skylos.done.config import DEFAULT_MODES, DoneConfig
from skylos.done.engine import run


IMPORTS = (
    "from django.contrib.auth.decorators import login_required\n"
    "from django.http import HttpResponseForbidden\n"
)
PROTECTED = IMPORTS + "@login_required\ndef export_customer(request):\n    return 42\n"
OPEN = PROTECTED.replace("@login_required\n", "")


def _git(root, *args):
    return subprocess.run(
        [
            "git",
            "-c",
            "user.name=Done test",
            "-c",
            "user.email=test@example.invalid",
            *args,
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()


def _write(root, relative, source):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)


def _repo(tmp_path, before=PROTECTED, after=OPEN):
    root = tmp_path / "repo"
    root.mkdir()
    _write(root, "views.py", before)
    _write(root, "pyproject.toml", "[tool.skylos.done]\n")
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "views.py", "pyproject.toml")
    _git(root, "commit", "-qm", "protected base")
    if after is None:
        (root / "views.py").unlink()
    else:
        _write(root, "views.py", after)
    return root


def _check(root):
    return run_check(
        "security_controls", CheckContext(open_comparison(root, "main"), DoneConfig())
    )


def test_removed_decorator_is_a_default_blocking_done_failure(tmp_path):
    root = _repo(tmp_path)
    result = _check(root)
    assert DEFAULT_MODES["security_controls"] == "block"
    assert result.status == "fail"
    assert result.findings[0].rule == "SKY-L021"
    assert result.findings[0].file == "views.py"
    assert result.findings[0].line >= 1
    assert "Auth decorator" in result.findings[0].message


@pytest.mark.parametrize(
    "after",
    [
        PROTECTED.replace("return 42", "return 43"),
        OPEN.replace(
            "    return 42",
            "    if not request.user.is_authenticated:\n"
            "        return HttpResponseForbidden()\n    return 42",
        ),
        IMPORTS,
        None,
    ],
)
def test_intact_boundary_or_removed_implementation_does_not_fail(tmp_path, after):
    result = _check(_repo(tmp_path, after=after))
    assert result.status == "pass"
    assert not result.findings


def test_a_guard_in_another_handler_cannot_preserve_removed_auth(tmp_path):
    after = OPEN + "\n@login_required\ndef other(request):\n    return 0\n"
    assert _check(_repo(tmp_path, after=after)).status == "fail"


def test_same_sensitive_handler_renamed_without_auth_still_fails(tmp_path):
    after = OPEN.replace("def export_customer", "def export_orders")
    assert _check(_repo(tmp_path, after=after)).status == "fail"


@pytest.mark.parametrize("missing", ["base", "head", "diff"])
def test_partial_security_comparison_is_unfinished(tmp_path, monkeypatch, missing):
    comparison = open_comparison(_repo(tmp_path), "main")
    attribute = {"base": "base_text", "head": "head_text", "diff": "file_diff"}[missing]
    monkeypatch.setattr(
        comparison, attribute, lambda *args: "" if missing == "diff" else None
    )
    result = run_check("security_controls", CheckContext(comparison, DoneConfig()))
    assert result.status == "incomplete"
    assert result.findings == []


def test_invalid_python_context_is_unfinished(tmp_path):
    assert _check(_repo(tmp_path, after="def broken(:\n")).status == "incomplete"


def test_nonempty_diff_without_source_hunks_is_unfinished(tmp_path, monkeypatch):
    comparison = open_comparison(_repo(tmp_path), "main")
    monkeypatch.setattr(comparison, "file_diff", lambda *args: "Binary files differ\n")
    result = run_check("security_controls", CheckContext(comparison, DoneConfig()))
    assert result.status == "incomplete"


def test_head_cannot_turn_off_done_auth_check(tmp_path):
    root = _repo(tmp_path)
    _write(
        root, "pyproject.toml", '[tool.skylos.done.checks]\nsecurity_controls="off"\n'
    )
    result = run(root, base_ref="main", run_tests=False)
    by_id = {outcome.result.id: outcome for outcome in result.checks}
    assert by_id["security_controls"].mode == "block"
    assert by_id["security_controls"].result.status == "fail"
    assert by_id["gate_tampering"].result.status == "fail"
    assert result.verdict == "fail"


def test_done_check_does_not_follow_scanner_ignore_settings(tmp_path):
    root = _repo(tmp_path)
    _write(
        root, "pyproject.toml", '[tool.skylos]\nignore=["SKY-L021"]\nexclude=["."]\n'
    )
    assert _check(root).status == "fail"


def test_actual_done_cli_keeps_passing_tests_from_hiding_auth_removal(tmp_path):
    # This new, trusted fixture is deliberately executed. The ordinary happy
    # path test cannot prove that unauthenticated requests are rejected.
    protected = (
        "def login_required(view):\n"
        "    def protected(request):\n"
        "        if not request.authenticated:\n"
        "            raise PermissionError('Sign in')\n"
        "        return view(request)\n"
        "    return protected\n"
        "@login_required\n"
        "def export_customer(request):\n"
        "    return request.customer\n"
    )
    root = _repo(tmp_path, before=protected, after=protected)
    _write(
        root,
        "pyproject.toml",
        "[tool.skylos.done]\ntest_command = "
        + json.dumps([sys.executable, "-m", "pytest", "-q"])
        + "\n",
    )
    _write(root, ".gitignore", "__pycache__/\n.pytest_cache/\n.skylos/\n")
    _write(
        root,
        "test_views.py",
        "from types import SimpleNamespace\nfrom views import export_customer\n"
        "def test_export_customer():\n"
        "    request = SimpleNamespace(authenticated=True, customer=42)\n"
        "    assert export_customer(request) == 42\n",
    )
    _git(root, "add", ".gitignore", "test_views.py", "pyproject.toml")
    _git(root, "commit", "-qm", "trusted happy path test")
    source = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ, PYTHONPATH=source, SKYLOS_NO_TELEMETRY="1", SKYLOS_JOBS="1")
    cli = str(Path(sys.executable).with_name("skylos"))

    def done():
        return subprocess.run(
            [cli, "done", ".", "--base", "main", "--format", "json"],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
        )

    intact = done()
    assert intact.returncode == 0, intact.stdout + intact.stderr
    intact_receipt = json.loads(intact.stdout)
    assert intact_receipt["verdict"] == "pass"
    _write(root, "views.py", protected.replace("@login_required\n", ""))
    happy_test = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "test_views.py"],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
    )
    assert happy_test.returncode == 0, happy_test.stdout + happy_test.stderr
    removed = done()
    assert removed.returncode == 1, removed.stdout + removed.stderr
    receipt = json.loads(removed.stdout)
    assert receipt["verdict"] == "fail"
    auth = next(item for item in receipt["checks"] if item["id"] == "security_controls")
    assert auth["mode"] == "block"
    assert auth["status"] == "fail"
    assert any(item["rule"] == "SKY-L021" for item in auth["findings"])
