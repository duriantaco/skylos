import importlib
import json
import os
import sys
from pathlib import Path

import pytest

from skylos.analysis.errors import analysis_result_incomplete
from skylos.analyzer import analyze
from skylos.cli import main


analyzer_module = importlib.import_module("skylos.analyzer")


def _write(root, name, source):
    root = root.resolve(strict=True)
    path = root / name
    path.resolve().relative_to(root)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as handle:
        handle.write(source)
    return path


def _raise_scan_error(_ctx):
    raise RuntimeError("controlled secret scanner failure")


def _run_cli(path, monkeypatch, capsys):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            str(path),
            "--secrets",
            "--gate",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            "--no-clipboard",
        ],
    )
    with pytest.raises(SystemExit) as stopped:
        main()
    return stopped.value.code, json.loads(capsys.readouterr().out)


@pytest.mark.parametrize(
    "name,source", [("app.py", "print(1)\n"), ("uv.lock", "version = 1\n")]
)
@pytest.mark.parametrize("failure", ["raises", "unavailable"])
def test_secret_scanner_failure_cannot_pass_the_actual_cli(
    tmp_path, monkeypatch, capsys, name, source, failure
):
    path = _write(tmp_path, name, source)
    monkeypatch.setattr(
        analyzer_module,
        "_secrets_scan_ctx",
        _raise_scan_error if failure == "raises" else None,
    )
    exit_code, report = _run_cli(path, monkeypatch, capsys)
    assert exit_code == 2
    assert analysis_result_incomplete(report)
    assert report.get("grade") is None
    assert (
        report["analysis_summary"]["grade_unavailable_reason"] == "analysis_incomplete"
    )
    assert len(report["analysis_errors"]) == 1
    error = report["analysis_errors"][0]
    assert error["rule_id"] == "SKY-ANALYSIS-INCOMPLETE"
    assert error["kind"] == (
        "secret_scan_error" if failure == "raises" else "secret_scanner_unavailable"
    )
    assert "secret scanner" in error["message"].lower()


def test_healthy_secret_scanner_still_blocks_real_pattern_via_cli(
    tmp_path, monkeypatch, capsys
):
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    path = _write(tmp_path, "app.py", f'key = "{key}"\nprint(key)\n')
    exit_code, report = _run_cli(path, monkeypatch, capsys)
    assert exit_code == 1
    assert not analysis_result_incomplete(report)
    assert any(finding["rule_id"] == "SKY-S101" for finding in report["secrets"])


@pytest.mark.parametrize("failure", ["raises", "unavailable"])
def test_source_secret_failure_preserves_other_analysis_findings(
    tmp_path, monkeypatch, failure
):
    broken = _write(tmp_path, "broken.py", "eval(input())\n")
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    _write(tmp_path, "healthy.py", f'key = "{key}"\nprint(key)\n')
    original_scan = analyzer_module._secrets_scan_ctx
    calls = []

    def selective_scan(ctx):
        calls.append(ctx["relpath"])
        if ctx["relpath"] == broken.name:
            _raise_scan_error(ctx)
        return original_scan(ctx)

    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setattr(
        analyzer_module,
        "_secrets_scan_ctx",
        selective_scan if failure == "raises" else None,
    )
    report = json.loads(
        analyze(
            str(tmp_path), enable_secrets=True, enable_danger=True, grep_verify=False
        )
    )
    assert analysis_result_incomplete(report)
    assert any(finding["rule_id"] == "SKY-D201" for finding in report["danger"])
    assert "broken" in {Path(item["file"]).stem for item in report.get("danger", [])}
    if failure == "raises":
        assert len(report["analysis_errors"]) == 1
        assert Path(report["analysis_errors"][0]["file"]) == broken
        assert any(finding["file"] == "healthy.py" for finding in report["secrets"])
        assert set(calls) == {"broken.py", "healthy.py"}
    else:
        assert not calls
        assert not report.get("secrets")


@pytest.mark.parametrize("with_source", [False, True])
def test_config_secret_failure_is_explicit_without_discarding_healthy_config(
    tmp_path, monkeypatch, with_source
):
    broken = _write(tmp_path, "uv.lock", "version = 1\n")
    key = "AKIA" + "ABCDEFGHIJKLMNOP"
    _write(tmp_path, "settings.toml", f'access_key = "{key}"\n')
    if with_source:
        _write(tmp_path, "app.py", "print(1)\n")
    original_scan = analyzer_module._secrets_scan_ctx

    def selective_scan(ctx):
        if ctx["relpath"] == broken.name:
            _raise_scan_error(ctx)
        return original_scan(ctx)

    monkeypatch.setattr(analyzer_module, "_secrets_scan_ctx", selective_scan)
    report = json.loads(analyze(str(tmp_path), enable_secrets=True, grep_verify=False))
    assert analysis_result_incomplete(report)
    assert len(report["analysis_errors"]) == 1
    assert Path(report["analysis_errors"][0]["file"]) == broken
    assert report["analysis_errors"][0]["kind"] == "secret_scan_error"
    assert any(finding["file"] == "settings.toml" for finding in report["secrets"])


@pytest.mark.parametrize("failure", ["raises", "unavailable"])
def test_disabled_secrets_does_not_run_or_report_scanner_failure(
    tmp_path, monkeypatch, failure
):
    _write(tmp_path, "app.py", "eval(input())\n")
    _write(tmp_path, "uv.lock", "version = 1\n")
    calls = []

    def broken_scan(ctx):
        calls.append(ctx)
        _raise_scan_error(ctx)

    monkeypatch.setattr(
        analyzer_module,
        "_secrets_scan_ctx",
        broken_scan if failure == "raises" else None,
    )
    report = json.loads(
        analyze(
            str(tmp_path), enable_secrets=False, enable_danger=True, grep_verify=False
        )
    )
    assert not calls
    assert not analysis_result_incomplete(report)
    assert not report.get("analysis_errors")
    assert not report.get("secrets")
    assert report.get("danger")


def test_unchanged_config_secret_exclusion_does_not_create_a_failure(
    tmp_path, monkeypatch
):
    source = _write(tmp_path, "app.py", "print(1)\n")
    _write(tmp_path, "uv.lock", "version = 1\n")
    calls = []

    def selective_scan(ctx):
        calls.append(ctx["relpath"])
        if ctx["relpath"] == "uv.lock":
            _raise_scan_error(ctx)
        return []

    monkeypatch.setattr(analyzer_module, "_secrets_scan_ctx", selective_scan)
    report = json.loads(
        analyze(
            str(tmp_path),
            enable_secrets=True,
            changed_files={str(source)},
            grep_verify=False,
        )
    )
    assert calls == ["app.py"]
    assert not analysis_result_incomplete(report)
    assert not report.get("analysis_errors")
