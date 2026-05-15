import json
import io
import sys
from types import SimpleNamespace
from unittest.mock import patch

from rich.console import Console

import skylos.cli as cli
from skylos.core.result_cache import (
    TRACE_CACHE_DIR,
    build_trace_cache_key,
    save_trace_cache,
)
from skylos.commands.cache_cmd import run_cache_command


def _args(root, **overrides):
    data = {
        "path": [str(root)],
        "coverage": False,
        "trace": True,
        "pytest_fixtures": False,
        "cache": True,
        "refresh_cache": False,
        "no_cache": False,
        "json": True,
        "llm": False,
        "github": False,
        "concise": False,
        "verbose": False,
        "diff_base": None,
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def _console():
    return Console(file=io.StringIO())


def _write_minimal_project(root):
    (root / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")


def _trace_payload(root):
    return {
        "version": 1,
        "calls": [
            {
                "file": str(root / "app.py"),
                "function": "f",
                "line": 1,
                "count": 1,
            }
        ],
    }


def test_trace_cache_miss_runs_trace_subprocess(tmp_path):
    _write_minimal_project(tmp_path)

    def fake_run(*_args, **_kwargs):
        (tmp_path / ".skylos_trace").write_text(
            json.dumps(_trace_payload(tmp_path)),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    with (
        patch("skylos.core.result_cache._git_visible_files", return_value=None),
        patch("skylos.cli.subprocess.run", side_effect=fake_run) as mock_run,
    ):
        result = cli._run_pre_analysis_steps(_args(tmp_path), tmp_path, _console())

    assert mock_run.called
    assert result.trace_file == tmp_path / ".skylos_trace"


def test_trace_cache_hit_skips_trace_subprocess_and_writes_trace(tmp_path):
    _write_minimal_project(tmp_path)
    key, fingerprint = build_trace_cache_key(
        tmp_path,
        [tmp_path],
        return_fingerprint=True,
    )
    payload = _trace_payload(tmp_path)
    save_trace_cache(
        tmp_path,
        key,
        payload,
        pytest_returncode=0,
        fingerprint_summary=fingerprint,
    )

    with (
        patch("skylos.core.result_cache._git_visible_files", return_value=None),
        patch("skylos.cli.subprocess.run") as mock_run,
    ):
        result = cli._run_pre_analysis_steps(_args(tmp_path), tmp_path, _console())

    assert not mock_run.called
    assert result.trace_file == tmp_path / ".skylos_trace"
    assert (
        json.loads((tmp_path / ".skylos_trace").read_text(encoding="utf-8")) == payload
    )


def test_refresh_cache_runs_subprocess_despite_hit(tmp_path):
    _write_minimal_project(tmp_path)
    key, fingerprint = build_trace_cache_key(
        tmp_path,
        [tmp_path],
        return_fingerprint=True,
    )
    save_trace_cache(
        tmp_path,
        key,
        _trace_payload(tmp_path),
        pytest_returncode=0,
        fingerprint_summary=fingerprint,
    )

    def fake_run(*_args, **_kwargs):
        (tmp_path / ".skylos_trace").write_text(
            json.dumps(_trace_payload(tmp_path)),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    with (
        patch("skylos.core.result_cache._git_visible_files", return_value=None),
        patch("skylos.cli.subprocess.run", side_effect=fake_run) as mock_run,
    ):
        cli._run_pre_analysis_steps(
            _args(tmp_path, refresh_cache=True),
            tmp_path,
            _console(),
        )

    assert mock_run.called


def test_no_cache_disables_trace_cache_even_with_cache_flag(tmp_path):
    _write_minimal_project(tmp_path)
    key, fingerprint = build_trace_cache_key(
        tmp_path,
        [tmp_path],
        return_fingerprint=True,
    )
    save_trace_cache(
        tmp_path,
        key,
        _trace_payload(tmp_path),
        pytest_returncode=0,
        fingerprint_summary=fingerprint,
    )

    def fake_run(*_args, **_kwargs):
        (tmp_path / ".skylos_trace").write_text(
            json.dumps(_trace_payload(tmp_path)),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    with patch("skylos.cli.subprocess.run", side_effect=fake_run) as mock_run:
        cli._run_pre_analysis_steps(
            _args(tmp_path, no_cache=True),
            tmp_path,
            _console(),
        )

    assert mock_run.called


def test_trace_cache_bypassed_with_pytest_fixtures(tmp_path):
    _write_minimal_project(tmp_path)

    def fake_run(*_args, **_kwargs):
        (tmp_path / ".skylos_trace").write_text(
            json.dumps(_trace_payload(tmp_path)),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    with patch("skylos.cli.subprocess.run", side_effect=fake_run) as mock_run:
        cli._run_pre_analysis_steps(
            _args(tmp_path, pytest_fixtures=True),
            tmp_path,
            _console(),
        )

    assert mock_run.called
    assert not (tmp_path / TRACE_CACHE_DIR).exists()


def test_trace_failure_without_payload_disables_stale_trace_for_analysis(
    tmp_path,
    monkeypatch,
):
    _write_minimal_project(tmp_path)
    stale_trace = tmp_path / ".skylos_trace"
    stale_trace.write_text(json.dumps(_trace_payload(tmp_path)), encoding="utf-8")
    observed = {}

    def fake_analyze(*_args, **kwargs):
        observed["trace_file"] = kwargs.get("trace_file")
        return json.dumps(
            {
                "unused_functions": [],
                "unused_imports": [],
                "unused_classes": [],
                "unused_variables": [],
                "unused_parameters": [],
                "analysis_summary": {"total_files": 1},
            }
        )

    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", str(tmp_path), "--trace", "--json", "--no-provenance"],
    )

    with (
        patch(
            "skylos.cli.subprocess.run",
            return_value=SimpleNamespace(returncode=1, stderr="boom"),
        ),
        patch("skylos.cli.run_analyze", side_effect=fake_analyze),
    ):
        cli.main()

    assert observed["trace_file"] is False
    assert not stale_trace.exists()


def test_cache_clear_command_removes_run_cache(tmp_path):
    run_cache = tmp_path / ".skylos" / "cache" / "runs" / "v1"
    run_cache.mkdir(parents=True)
    (run_cache / "entry.json").write_text("{}", encoding="utf-8")

    code = run_cache_command(
        ["clear", str(tmp_path)],
        console_factory=lambda: _console(),
    )

    assert code == 0
    assert not (tmp_path / ".skylos" / "cache" / "runs").exists()
