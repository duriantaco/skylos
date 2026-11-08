import copy
import json
import sys
from unittest.mock import patch

import pytest

import skylos.typecheck
from skylos.commands.verify_cmd import run_verify_command


def report(status):
    return {
        "status": status,
        "complete": status in {"pass", "fail"},
        "checker": "tsc",
        "summary": "Type checker test result",
        "comparison": {"status": "not_requested", "reason": "No baseline requested"},
        "diagnostics": []
        if status == "pass"
        else [
            {
                "file": "app.ts",
                "line": 2,
                "column": 7,
                "code": "TS2322",
                "message": "Type string is not assignable to type number",
                "severity": "error",
                "origin": "unclassified",
            }
        ],
    }


@pytest.mark.parametrize(
    "type_status,static_status,expected",
    [
        ("pass", "pass", 0),
        ("fail", "pass", 1),
        ("incomplete", "pass", 2),
        ("not_configured", "pass", 2),
        ("pass", "fail", 1),
        ("pass", "incomplete", 2),
        ("fail", "incomplete", 1),
    ],
)
def test_verify_type_verdict_json(
    tmp_path, monkeypatch, capsys, type_status, static_status, expected
):
    result = report(type_status)
    monkeypatch.setattr(
        skylos.typecheck, "run_type_check", lambda *a, **kw: copy.deepcopy(result)
    )
    code = run_verify_command(
        [str(tmp_path), "--type-check", "--format", "json"],
        verify_change_path_func=lambda *a, **kw: {
            "status": static_status,
            "summary": "Static result",
            "findings": [],
        },
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == expected
    assert payload["type_check"] == result
    assert payload["findings"] == []


@pytest.mark.parametrize("positional", [True, False])
def test_verify_passes_canonical_file_scope_to_checker(
    tmp_path, monkeypatch, capsys, positional
):
    target = tmp_path / "app.ts"
    target.write_text("export const answer = 42;\n")
    calls = []

    def check(path, **kwargs):
        calls.append((path, kwargs))
        return report("pass")

    monkeypatch.setattr(skylos.typecheck, "run_type_check", check)
    flags = [str(target)] if positional else [str(tmp_path), "--file", "app.ts"]
    code = run_verify_command(
        [*flags, "--type-check", "--format", "json"],
        verify_change_path_func=lambda *a, **kw: {
            "status": "pass",
            "summary": "Static result",
            "findings": [],
        },
    )
    assert code == 0
    assert calls[0][1]["target_files"] == [str(target.resolve())]
    assert calls[0][1]["base_ref"] is None
    capsys.readouterr()


def test_verify_type_short_and_no_fail(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        skylos.typecheck, "run_type_check", lambda *a, **kw: report("fail")
    )
    code = run_verify_command(
        [str(tmp_path), "--type-check", "--format", "short", "--no-fail"],
        verify_change_path_func=lambda *a, **kw: {
            "status": "pass",
            "summary": "Static result",
            "findings": [],
        },
    )
    output = capsys.readouterr().out
    assert code == 0
    assert "app.ts:2:7" in output and "TS2322 (unclassified)" in output
    assert "FAIL:" in output


def test_verify_default_does_not_run_checker(tmp_path, monkeypatch, capsys):
    def unexpected(*args, **kwargs):
        raise AssertionError("Static verification must not execute a type checker")

    monkeypatch.setattr(skylos.typecheck, "run_type_check", unexpected)
    static = {"status": "pass", "summary": "Static result", "findings": []}
    assert (
        run_verify_command(
            [str(tmp_path), "--format", "json"],
            verify_change_path_func=lambda *a, **kw: dict(static),
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == static


@pytest.mark.parametrize(
    "status,flags,expected",
    [
        ("fail", [], 1),
        ("incomplete", [], 2),
        ("not_configured", ["--force"], 2),
        ("fail", ["--force"], 0),
        ("pass", [], 0),
        ("fail", ["--profile"], 1),
        ("fail", ["--strict"], 1),
    ],
)
def test_normal_scan_type_check_keeps_machine_output_and_exit(
    tmp_path, monkeypatch, capsys, status, flags, expected
):
    import skylos.cli as cli

    (tmp_path / "app.ts").write_text("export const answer = 42;\n")
    monkeypatch.setattr(
        skylos.typecheck, "run_type_check", lambda *a, **kw: report(status)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["skylos", str(tmp_path), "--json", "--no-provenance", "--type-check", *flags],
    )
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
    with (
        patch.object(cli, "run_analyze", return_value=json.dumps(result)),
        patch.object(cli, "load_config", return_value={}),
    ):
        try:
            cli.main()
            code = 0
        except SystemExit as exc:
            code = exc.code
    output = capsys.readouterr()
    payload = json.loads(output.out)
    assert code == expected
    assert payload["type_check"]["status"] == status
    assert "Type check (tsc)" in output.err
    if "--profile" in flags:
        assert payload["profiling"]["completed"] is True


def test_type_flags_fail_before_static_execution(tmp_path, monkeypatch, capsys):
    import skylos.cli as cli

    monkeypatch.setattr(sys, "argv", ["skylos", str(tmp_path), "--type-checker", "tsc"])
    with (
        patch.object(
            cli, "run_analyze", side_effect=AssertionError("Should not analyze")
        ),
        pytest.raises(SystemExit) as exc,
    ):
        cli.main()
    assert exc.value.code == 2
    assert "require --type-check" in capsys.readouterr().err


def test_repository_addopts_cannot_enable_compiler_execution():
    from skylos.core.cli_shared import sanitize_addopts

    assert (
        sanitize_addopts(
            [
                "--type-check",
                "--type-checker",
                "mypy",
                "--type-check-timeout=3600",
            ]
        )
        == []
    )
