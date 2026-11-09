from __future__ import annotations

import copy
import io
import json
import sys

import pytest

from skylos.commands import cleanup_cmd


def _raw_report():
    return {
        "analysis_errors": [],
        "analysis_summary": {"total_files": 1},
        "quality": [],
    }


def _plan(status="ready"):
    task = {
        "id": "cleanup-1",
        "rule_id": "SKY-L033",
        "category": "quality",
        "file": "app.py",
        "line": 2,
        "name": "unused expression",
        "severity": "MEDIUM",
        "message": "Expression has no effect",
        "action": "Remove the expression after checking its intent.",
        "finding_type": "defect",
    }
    return {
        "schema_version": 1,
        "tool": "cleanup",
        "status": status,
        "tasks": [task] if status == "ready" else [],
        "advisories": [],
        "counts": {"tasks": 1 if status == "ready" else 0},
        "limitations": [],
    }


@pytest.fixture
def planner(monkeypatch):
    import skylos.cleanup

    calls = []

    def build(result, **kwargs):
        calls.append((result, kwargs))
        return _plan()

    monkeypatch.setattr(skylos.cleanup, "build_cleanup_plan", build)
    return calls


def _run(argv, *, analyze_func=None):
    output = io.StringIO()
    code = cleanup_cmd.run_cleanup_command(
        argv, stdout=output, analyze_func=analyze_func
    )
    return code, output.getvalue()


def test_live_scan_enables_only_static_cleanup_checks_and_preserves_file_scope(
    tmp_path, planner
):
    source = tmp_path / "app.py"
    source.write_text("answer = 42\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos]\nexclude = ["project_generated"]\n', encoding="utf-8"
    )
    calls = []

    def analyze(path, **kwargs):
        print("scanner progress must not contaminate JSON")
        print("scanner diagnostic", file=sys.stderr)
        calls.append((path, kwargs))
        return json.dumps(_raw_report())

    code, output = _run(
        [str(source), "--format", "json", "--top", "3", "--all-advice"],
        analyze_func=analyze,
    )

    assert code == 0
    report = json.loads(output)
    assert report["status"] == "ready"
    assert report["source"] == "live_scan"
    assert calls[0][0] == str(source)
    options = calls[0][1]
    assert options["enable_quality"] is True
    assert options["enable_ai_defects"] is True
    assert options["enable_dead_code"] is True
    for key in (
        "enable_danger",
        "enable_secrets",
        "enable_dependency_hallucinations",
        "enable_sca",
        "grep_verify",
        "trace_file",
        "all_advice",
    ):
        assert options[key] is False
    assert "project_generated" in options["exclude_folders"]
    assert planner == [
        (
            _raw_report(),
            {"project_root": tmp_path, "top": None, "all_advice": True},
        )
    ]
    assert source.read_text(encoding="utf-8") == "answer = 42\n"


def test_saved_report_is_offline_and_identified_as_saved(tmp_path, planner):
    saved = tmp_path / "scan.json"
    original = json.dumps(_raw_report())
    saved.write_text(original, encoding="utf-8")

    def forbidden_scan(*args, **kwargs):
        pytest.fail("--from-report must not run the analyzer")

    code, output = _run(
        [str(tmp_path), "--from-report", str(saved), "--format", "json"],
        analyze_func=forbidden_scan,
    )

    assert code == 0
    assert json.loads(output)["source"] == "saved_report"
    assert planner[0][0] == _raw_report()
    assert saved.read_text(encoding="utf-8") == original


@pytest.mark.parametrize(
    "report_status, expected", [("ready", 0), ("clear", 0), ("incomplete", 2)]
)
def test_queue_exit_codes_are_not_quality_gate_verdicts(
    tmp_path, monkeypatch, report_status, expected
):
    import skylos.cleanup

    monkeypatch.setattr(
        skylos.cleanup, "build_cleanup_plan", lambda *_a, **_kw: _plan(report_status)
    )
    code, output = _run(
        [str(tmp_path), "--format", "json"],
        analyze_func=lambda *_a, **_kw: _raw_report(),
    )
    assert code == expected
    assert json.loads(output)["status"] == report_status


@pytest.mark.parametrize("content", ["{", "[]", '{"quality": "invalid"}'])
def test_invalid_saved_input_returns_machine_readable_error(tmp_path, content):
    saved = tmp_path / "scan.json"
    saved.write_text(content, encoding="utf-8")
    code, output = _run(
        [str(tmp_path), "--from-report", str(saved), "--format", "json"]
    )
    report = json.loads(output)
    assert code == 2
    assert report["status"] == "incomplete"
    assert report["tasks"] == []
    assert report["limitations"]
    assert report["source"] == "saved_report"


def test_scan_exception_and_missing_path_return_json(tmp_path):
    def fail(*_args, **_kwargs):
        raise RuntimeError("scanner unavailable")

    code, output = _run([str(tmp_path), "--format", "json"], analyze_func=fail)
    assert code == 2
    assert "scanner unavailable" in json.loads(output)["limitations"][0]

    code, output = _run([str(tmp_path / "missing"), "--format", "json"])
    assert code == 2
    assert json.loads(output)["status"] == "incomplete"


@pytest.mark.parametrize("top", ["0", "-1", "words"])
def test_invalid_top_is_rejected_before_scanning(top, monkeypatch):
    monkeypatch.setattr(cleanup_cmd, "_scan", lambda *_a: pytest.fail("must not scan"))
    with pytest.raises(SystemExit) as exc:
        cleanup_cmd.run_cleanup_command(["--top", top])
    assert exc.value.code == 2


def test_human_output_separates_advice_and_preserves_terminal_safety(
    tmp_path, monkeypatch
):
    import skylos.cleanup

    plan = _plan()
    advisory = copy.deepcopy(plan["tasks"][0])
    advisory["rule_id"] = "SKY-L038"
    advisory["message"] = "Use a conversion\x1b[2J\nfield"
    plan["advisories"] = [advisory]
    plan["counts"] = {"tasks": 4, "advisories": 1, "optional_advice": 2}
    plan["limitations"] = ["Some APIs unverified"]
    monkeypatch.setattr(skylos.cleanup, "build_cleanup_plan", lambda *_a, **_kw: plan)

    code, output = _run([str(tmp_path)], analyze_func=lambda *_a, **_kw: _raw_report())

    assert code == 0
    assert "Next cleanup tasks (1 of 4)" in output
    assert "Remove the expression" in output
    assert "Review advice (1 of 1)" in output
    assert "add --all-advice" in output
    assert "Some APIs unverified" in output
    assert "run your checks" in output
    assert "\x1b" not in output


def test_native_cli_help_exits_before_scan(monkeypatch, capsys):
    import skylos.cli as cli

    monkeypatch.setattr(cleanup_cmd, "_scan", lambda *_a: pytest.fail("must not scan"))
    monkeypatch.setattr(sys, "argv", ["skylos", "cleanup", "--help"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    help_output = capsys.readouterr().out
    assert "skylos cleanup" in help_output
    assert "--from-report" in help_output
    assert "--all-advice" in help_output


def test_cli_dispatch_produces_json(tmp_path, planner, monkeypatch, capsys):
    import skylos.cli as cli

    saved = tmp_path / "scan.json"
    saved.write_text(json.dumps(_raw_report()), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            "cleanup",
            str(tmp_path),
            "--from-report",
            str(saved),
            "--format",
            "json",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert json.loads(capsys.readouterr().out)["source"] == "saved_report"


def test_live_analyzer_never_executes_target_source(tmp_path, monkeypatch):
    import skylos.cleanup

    marker = tmp_path / "EXECUTED"
    source = tmp_path / "app.py"
    source.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "def compute():\n    return 42\n",
        encoding="utf-8",
    )
    received = []

    def build(result, **kwargs):
        received.append(result)
        return _plan("clear")

    monkeypatch.setattr(skylos.cleanup, "build_cleanup_plan", build)
    code, output = _run([str(tmp_path), "--format", "json"])

    assert code == 0
    assert json.loads(output)["status"] == "clear"
    assert received[0]["analysis_summary"]["total_files"] == 1
    assert not marker.exists()


def test_native_analyzer_without_dead_code_option_keeps_static_defaults(tmp_path):
    received = {}

    def legacy_analyze(
        path,
        *,
        exclude_folders,
        enable_quality,
        enable_ai_defects,
        enable_danger,
        enable_secrets,
        enable_dependency_hallucinations,
        enable_sca,
        grep_verify,
        trace_file,
        config_file,
        all_advice,
    ):
        received.update(locals())
        return _raw_report()

    report = cleanup_cmd._scan(tmp_path, tmp_path, legacy_analyze)

    assert report["analysis_summary"]["total_files"] == 1
    assert received["enable_quality"] is True
    assert received["enable_ai_defects"] is True
    for flag in (
        "enable_danger",
        "enable_secrets",
        "enable_dependency_hallucinations",
        "enable_sca",
        "grep_verify",
        "trace_file",
        "all_advice",
    ):
        assert received[flag] is False
