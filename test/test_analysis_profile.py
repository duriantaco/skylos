"""Profiling measures the scanner without changing its report or verdict."""

import io
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from skylos.core import analysis_profile as profiling
from skylos.core.python_requirements import normalize_distribution_name


def test_disabled_profile_does_not_start_profiler(monkeypatch):
    def unexpected(**kwargs):
        pytest.fail("disabled profiling must not allocate a profiler")

    monkeypatch.setattr(profiling, "AnalysisProfile", unexpected)
    previous = sys.getprofile()
    with profiling.profile_scan(False) as profile:
        assert profile is None
        assert normalize_distribution_name("Example_Pkg") == "example-pkg"
    assert sys.getprofile() is previous


def test_profile_records_phases_and_forwards_progress(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(profiling, "perf_counter", lambda: clock[0])
    updates = []
    with profiling.profile_scan(True) as profile:
        callback = profile.progress_callback(lambda *args: updates.append(args))
        clock[0] = 11.0
        callback(0, 1, Path("PHASE: imports"))
        callback(1, 1, Path("PHASE: imports"))
        clock[0] = 13.0
        callback(0, 1, Path("PHASE: security"))
        clock[0] = 15.0

    result = profile.summary()
    assert result["completed"] is True
    assert result["wall_seconds"] == 5.0
    assert result["phases"] == [
        {"name": "analysis setup", "seconds": 1.0, "visits": 1},
        {"name": "imports", "seconds": 2.0, "visits": 1},
        {"name": "security", "seconds": 2.0, "visits": 1},
    ]
    assert len(updates) == 3


def test_profile_lists_scanner_function_calls():
    with profiling.profile_scan(True, limit=100) as profile:
        for _ in range(20):
            normalize_distribution_name("Example_Pkg")

    result = profile.summary()
    rows = result["functions"]["by_cumulative"]
    matching = [row for row in rows if row["function"] == "normalize_distribution_name"]
    assert len(matching) == 1
    assert matching[0]["calls"] == 20
    assert matching[0]["cumulative_seconds"] >= matching[0]["self_seconds"] >= 0
    assert all(row["file"].startswith("skylos/") for row in rows)
    assert not any("test_analysis_profile" in row["file"] for row in rows)
    assert sys.getprofile() is None


def test_scanner_exception_is_preserved_and_profile_is_partial():
    with pytest.raises(ValueError, match="scanner failed"):
        with profiling.profile_scan(True) as profile:
            normalize_distribution_name("Example_Pkg")
            raise ValueError("scanner failed")

    assert profile.summary()["completed"] is False
    assert sys.getprofile() is None


def test_existing_profile_hook_is_restored():
    seen = []

    def previous(frame, event, arg):
        seen.append(event)

    sys.setprofile(previous)
    try:
        with profiling.profile_scan(True):
            normalize_distribution_name("Example_Pkg")
        assert sys.getprofile() is previous
        assert seen
    finally:
        sys.setprofile(None)


def test_profile_file_and_human_output(tmp_path):
    with profiling.profile_scan(True) as profile:
        normalize_distribution_name("Example_Pkg")
    result = profile.summary()
    output = tmp_path / "profile.json"
    profiling.write_profile_output(result, output)
    assert json.loads(output.read_text()) == result
    stream = io.StringIO()
    profiling.render_profile(result, stream=stream)
    assert "Skylos analysis profile" in stream.getvalue()
    assert "profiling overhead" in stream.getvalue()


def test_profile_output_refuses_symlink(tmp_path):
    victim = tmp_path / "keep.json"
    victim.write_text("keep")
    link = tmp_path / "profile.json"
    link.symlink_to(victim)
    with pytest.raises(OSError, match="profile output"):
        profiling.write_profile_output({}, link)
    assert victim.read_text() == "keep"


def test_profile_and_report_must_not_overwrite_each_other(tmp_path):
    report = tmp_path / "report.json"
    with pytest.raises(ValueError, match="must differ"):
        profiling.validate_profile_output(report, tmp_path / "." / "report.json")
    profiling.validate_profile_output(report, tmp_path / "profile.json")


@pytest.mark.parametrize("command", [[], ["verify"]], ids=["scan", "verify"])
def test_cli_rejects_overlapping_profile_and_report_before_analysis(
    tmp_path, monkeypatch, command
):
    import skylos.cli as cli

    output = tmp_path / "report.json"
    output.write_text("KEEP")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            *command,
            str(tmp_path),
            "--output",
            str(output),
            "--profile-output",
            str(output),
        ],
    )
    with (
        patch.object(cli, "run_analyze", side_effect=AssertionError("unexpected scan")),
        pytest.raises(SystemExit) as outcome,
    ):
        cli.main()
    assert outcome.value.code == 2
    assert output.read_text() == "KEEP"


def _scan(monkeypatch, tmp_path, capsys, flags, *, finding=False):
    import skylos.cli as cli

    result = {
        "unused_functions": [],
        "unused_imports": [],
        "unused_classes": [],
        "unused_variables": [],
        "unused_parameters": [],
        "danger": [],
        "quality": [],
        "secrets": [],
        "analysis_summary": {"total_files": 1},
    }
    if finding:
        result["danger"] = [
            {
                "rule_id": "SKY-D201",
                "file": str(tmp_path / "app.py"),
                "line": 1,
                "severity": "HIGH",
                "message": "eval with untrusted input",
            }
        ]

    def analyze(*args, **kwargs):
        progress = kwargs.get("progress_callback")
        if progress is not None:
            progress(0, 1, Path("PHASE: security"))
        normalize_distribution_name("Example_Pkg")
        return json.dumps(result)

    monkeypatch.setattr(
        sys, "argv", ["skylos", str(tmp_path), "--json", "--no-provenance", *flags]
    )
    with (
        patch.object(cli, "run_analyze", side_effect=analyze),
        patch.object(cli, "load_config", return_value={}),
    ):
        try:
            cli.main()
            code = 0
        except SystemExit as exc:
            code = exc.code
    captured = capsys.readouterr()
    return code, json.loads(captured.out), captured.err


@pytest.mark.parametrize("finding", [False, True])
def test_profile_preserves_json_findings_and_strict_exit(
    tmp_path, monkeypatch, capsys, finding
):
    before_code, before, _ = _scan(
        monkeypatch, tmp_path, capsys, ["--strict"], finding=finding
    )
    code, result, stderr = _scan(
        monkeypatch, tmp_path, capsys, ["--strict", "--profile"], finding=finding
    )

    profile = result.pop("profiling")
    assert result == before
    assert code == before_code == int(finding)
    assert "Skylos analysis profile" in stderr
    assert profile["completed"] is True
    assert any(row["name"] == "security" for row in profile["phases"])


def test_profile_output_alone_enables_profile(tmp_path, monkeypatch, capsys):
    output = tmp_path / "profile.json"
    code, result, _ = _scan(
        monkeypatch, tmp_path, capsys, ["--profile-output", str(output)]
    )
    assert code == 0
    assert json.loads(output.read_text()) == result["profiling"]


@pytest.mark.parametrize("empty_path", [False, True])
def test_profile_output_failure_exits_two_after_json_even_when_forced(
    tmp_path, monkeypatch, capsys, empty_path
):
    output = "" if empty_path else str(tmp_path / "missing" / "profile.json")
    code, result, stderr = _scan(
        monkeypatch,
        tmp_path,
        capsys,
        ["--force", "--profile-output", output],
        finding=True,
    )
    assert code == 2
    assert result["danger"][0]["rule_id"] == "SKY-D201"
    assert result["profiling"]["completed"] is True
    assert "profile output unavailable" in stderr


def test_main_profile_defaults_are_disabled():
    from skylos.cli_core.main_parser import build_main_parser

    args = build_main_parser(version="probe").parse_args(["."])
    assert args.profile is False and args.profile_output is None


def test_repository_addopts_cannot_enable_profiling_or_choose_an_output():
    from skylos.core.cli_shared import sanitize_addopts

    assert sanitize_addopts(["--profile", "--profile-output", "victim.json"]) == []


def test_profile_output_error_does_not_replace_scanner_error(
    tmp_path, monkeypatch, capsys
):
    import skylos.cli as cli

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "--json",
            "--no-provenance",
            "--profile-output",
            str(tmp_path / "missing" / "profile.json"),
        ],
    )
    with (
        patch.object(
            cli, "run_analyze", side_effect=ValueError("scanner probe failed")
        ),
        patch.object(cli, "load_config", return_value={}),
        pytest.raises(SystemExit) as outcome,
    ):
        cli.main()

    assert outcome.value.code == 1
    assert "profile output unavailable" in capsys.readouterr().err


@pytest.mark.parametrize(
    "status,expected_code", [("pass", 0), ("fail", 1), ("incomplete", 2)]
)
def test_verify_profile_preserves_injected_function_and_exit(
    tmp_path, capsys, status, expected_code
):
    from skylos.commands.verify_cmd import run_verify_command

    received = []

    def verify(path, **kwargs):
        received.append((path, kwargs))
        normalize_distribution_name("Example_Pkg")
        return {"status": status, "summary": "probe", "findings": []}

    code = run_verify_command(
        [str(tmp_path), "--format", "json", "--profile"],
        verify_change_path_func=verify,
        parse_exclude_folders_func=lambda **kwargs: [],
    )
    captured = capsys.readouterr()
    result = json.loads(captured.out)
    profile = result.pop("profiling")
    assert result == {"status": status, "summary": "probe", "findings": []}
    assert code == expected_code
    assert received == [
        (
            str(tmp_path),
            {
                "file": None,
                "line_range": None,
                "confidence": 60,
                "exclude_folders": [],
                "project_context": False,
            },
        )
    ]
    assert profile["completed"] is True
    assert "Skylos analysis profile" in captured.err


def test_verify_profile_artifact_failure_is_operational_with_no_fail(tmp_path, capsys):
    from skylos.commands.verify_cmd import run_verify_command

    code = run_verify_command(
        [
            str(tmp_path),
            "--format",
            "json",
            "--profile-output",
            str(tmp_path / "missing" / "profile.json"),
            "--no-fail",
        ],
        verify_change_path_func=lambda *args, **kwargs: {
            "status": "fail",
            "summary": "probe",
            "findings": [],
        },
        parse_exclude_folders_func=lambda **kwargs: [],
    )
    captured = capsys.readouterr()
    assert code == 2
    assert json.loads(captured.out)["status"] == "fail"
    assert "profile output unavailable" in captured.err
