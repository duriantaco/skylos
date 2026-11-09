"""CLI verification reuses project facts without changing its verdicts."""

import json
from contextlib import nullcontext

import pytest

from skylos.rules.ai_defect import module_facts_index as mfi
from skylos.verify_change import verify_change_path


def _project(root):
    (root / "pyproject.toml").write_text('[project]\nname = "cache-probe"\n')
    (root / "pkg").mkdir()
    target = root / "pkg" / "app.py"
    target.write_text("import helper\nhelper.absent()\n")
    provider = root / "helper.py"
    provider.write_text("def present():\n    return 1\n")
    return target, provider


def _verify(target):
    return verify_change_path(
        target,
        behavior_comparison=False,
        include_dependency_hallucinations=False,
        include_security_findings=False,
    )


def _stats(stderr):
    return [
        json.loads(line.split("=", 1)[1])
        for line in stderr.splitlines()
        if line.startswith("SKYLOS_VERIFY_STATS=")
    ]


def test_positional_verify_warms_project_facts_and_invalidates_provider(
    tmp_path, monkeypatch, capsys
):
    target, provider = _project(tmp_path)
    monkeypatch.setenv("SKYLOS_VERIFY_STATS", "1")
    with monkeypatch.context() as uncached:
        uncached.setattr(
            "skylos.verify_change._facts_session", lambda *a, **kw: nullcontext(None)
        )
        expected = _verify(target)
    assert not (tmp_path / mfi.CACHE_PATH).exists()
    capsys.readouterr()
    cold = _verify(target)
    cold_stats = _stats(capsys.readouterr().err)[0]["module_facts"]
    warm = _verify(target)
    warm_stats = _stats(capsys.readouterr().err)[0]["module_facts"]

    assert cold == warm == expected
    assert any("absent" in f["message"] for f in cold["findings"])
    assert (tmp_path / mfi.CACHE_PATH).is_file()
    assert cold_stats["enabled"] and warm_stats["enabled"]
    assert cold_stats["rebuilt"] > 0
    assert warm_stats["loaded_entries"] > 0
    assert warm_stats["hits"] > 0
    assert warm_stats["rebuilt"] == 0
    assert warm_stats["reference_targets"] == 1

    provider.write_text("def present():\n    return 1\n\ndef absent():\n    return 2\n")
    changed = _verify(target)
    changed_stats = _stats(capsys.readouterr().err)[0]["module_facts"]
    assert not any("absent" in f["message"] for f in changed["findings"])
    assert changed_stats["rebuilt"] == 1


def test_verify_uses_callers_index_and_does_not_add_stats_to_payload(
    tmp_path, monkeypatch, capsys
):
    target, _ = _project(tmp_path)
    monkeypatch.delenv("SKYLOS_VERIFY_STATS", raising=False)
    with mfi.module_facts_index_session(tmp_path) as index:
        result = _verify(target)
        assert index.entries
        assert mfi.active_module_facts_index() is index
    assert not _stats(capsys.readouterr().err)
    assert "module_facts" not in result


def test_injected_analyzer_stays_uncached(tmp_path, monkeypatch, capsys):
    target, _ = _project(tmp_path)
    monkeypatch.setenv("SKYLOS_VERIFY_STATS", "1")

    def analyzer(*args, **kwargs):
        assert mfi.active_module_facts_index() is None
        return {}

    verify_change_path(target, analyze_func=analyzer, behavior_comparison=False)
    assert not (tmp_path / mfi.CACHE_PATH).exists()
    assert _stats(capsys.readouterr().err)[0]["module_facts"] == {"enabled": False}


@pytest.mark.parametrize("missing", [True, False], ids=["missing", "closed"])
def test_diagnostics_do_not_use_stdout_without_writable_stderr(
    monkeypatch, capsys, missing
):
    import io

    from skylos.verify_change import _emit_verification_stats

    stream = io.StringIO()
    stream.close()
    monkeypatch.setenv("SKYLOS_VERIFY_STATS", "1")
    with monkeypatch.context() as patched:
        patched.setattr("sys.stderr", None if missing else stream)
        _emit_verification_stats(None)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_real_hook_cli_keeps_cache_stats_on_stderr(tmp_path):
    import os
    import subprocess
    import sys
    from pathlib import Path

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    target, _ = _project(tmp_path)
    target.write_text("value = 1\n")
    proc = subprocess.run(
        [str(Path(sys.executable).with_name("skylos")), "hook", "recheck", str(target)],
        cwd=tmp_path,
        env={
            **os.environ,
            "SKYLOS_VERIFY_STATS": "1",
            "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        },
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "SKYLOS_VERIFY_STATS=" not in proc.stdout
    records = _stats(proc.stderr)
    assert len(records) == 1
    assert records[0]["module_facts"]["enabled"]
    assert records[0]["module_facts"]["reference_targets"] == 1
