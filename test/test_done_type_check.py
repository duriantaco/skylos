"""Optional Done type checking uses trusted policy and preserves diagnostic origins."""

import copy
import json
import subprocess
import sys
import types

import pytest

from skylos.commands.done_cmd import run_done_command
from skylos.done import checks, engine
from skylos.done.base import DoneError, open_comparison
from skylos.done.config import CHECK_IDS, DoneConfig, parse_done_config
from skylos.done.receipt import (
    build_receipt,
    render_markdown,
    render_text,
    validate_receipt,
)


def _git(root, *args):
    return subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _config(*, mode="off", checker="auto", timeout=120, gate="off"):
    modes = {key: "off" for key in CHECK_IDS}
    modes.update(type_check=mode, gate_tampering=gate)
    return (
        '[project]\nname = "typed-demo"\nversion = "0.1"\n'
        "[tool.skylos.done]\n"
        f'type_checker = "{checker}"\ntype_check_timeout_seconds = {timeout}\n'
        "[tool.skylos.done.checks]\n"
        + "".join(f'{key} = "{value}"\n' for key, value in modes.items())
    )


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "pyproject.toml").write_text(_config())
    (tmp_path / "app.py").write_text("answer = 42\n")
    _git(tmp_path, "add", "pyproject.toml", "app.py")
    _git(tmp_path, "commit", "-qm", "base")
    return tmp_path


def _set_base_policy(repo, **options):
    (repo / "pyproject.toml").write_text(_config(**options))
    _git(repo, "add", "pyproject.toml")
    _git(repo, "commit", "-qm", "trusted policy")


def _report(*diagnostics, status="pass", complete=True, comparison="complete"):
    return {
        "status": status,
        "complete": complete,
        "checker": "mypy",
        "summary": "Type check completed",
        "diagnostics": list(diagnostics),
        "comparison": {"status": comparison},
    }


def _diagnostic(origin="introduced", severity="error"):
    return {
        "origin": origin,
        "file": "app.py",
        "line": 1,
        "col": 4,
        "code": "assignment",
        "message": "Incompatible assignment",
        "severity": severity,
    }


@pytest.fixture
def checker(monkeypatch):
    calls = []
    api = types.ModuleType("skylos.typecheck")
    api.report = _report()

    def run_type_check(path, **kwargs):
        calls.append((path, kwargs))
        return api.report

    api.run_type_check = run_type_check
    monkeypatch.setitem(sys.modules, "skylos.typecheck", api)
    return api, calls


def test_type_check_defaults_off_without_running_a_checker(repo, checker):
    _, calls = checker
    result = engine.run(repo, run_tests=False)

    outcome = next(c for c in result.checks if c.result.id == "type_check")
    assert outcome.mode == "off"
    assert outcome.result.status == "skipped"
    assert outcome.result.rule is None
    assert calls == []
    assert "type_check" not in build_receipt(result)


def test_type_check_config_validates_checker_and_budget():
    default = DoneConfig()
    configured = parse_done_config(
        _config(mode="advise", checker="pyright", timeout=45)
    )
    invalid = parse_done_config(
        '[tool.skylos.done]\ntype_checker = "sh -c arbitrary"\n'
        "type_check_timeout_seconds = 999999\n"
    )

    assert default.mode("type_check") == "off"
    assert default.type_checker == "auto"
    assert default.type_check_timeout_seconds == 120
    assert configured.mode("type_check") == "advise"
    assert configured.type_checker == "pyright"
    assert configured.type_check_timeout_seconds == 45
    assert invalid.type_checker == "auto"
    assert invalid.type_check_timeout_seconds == 1800
    assert any("type_checker" in p for p in invalid.problems)
    assert any("type_check_timeout_seconds" in p for p in invalid.problems)
    assert default.digest() != configured.digest()


@pytest.mark.parametrize("name", ["auto", "mypy", "pyright", "pyrefly", "tsc"])
def test_type_check_accepts_only_supported_checker_names(name):
    config = parse_done_config(_config(checker=name))
    assert config.type_checker == name
    assert config.problems == ()


@pytest.mark.parametrize(
    "report,wanted,blocking",
    [
        (_report(_diagnostic(), status="fail"), "fail", True),
        (_report(_diagnostic("preexisting")), "pass", False),
        (_report(_diagnostic("unclassified")), "incomplete", True),
        (_report(_diagnostic(severity="warning")), "pass", False),
        (_report(_diagnostic(severity="warn")), "pass", False),
        (_report(_diagnostic(severity="hint")), "pass", False),
        (_report(complete=False), "incomplete", None),
        (_report(comparison="incomplete"), "incomplete", None),
        (_report(comparison="not_requested"), "incomplete", None),
        (_report(status="not_configured", complete=False), "incomplete", None),
    ],
    ids=[
        "introduced",
        "preexisting",
        "unknown",
        "warning",
        "warning-alias",
        "hint",
        "partial",
        "base-failed",
        "no-base",
        "no-checker",
    ],
)
def test_type_check_results_preserve_origins_and_fail_closed(
    repo, checker, report, wanted, blocking
):
    api, calls = checker
    api.report = report
    comparison = open_comparison(repo, None)
    context = checks.CheckContext(comparison, DoneConfig(), run_tests=False)

    result = checks.run_check("type_check", context)

    assert result.status == wanted
    assert result.rule is None
    assert calls[0][1]["comparison"] is comparison
    if blocking is not None:
        assert result.findings[0].blocking is blocking
        assert report["diagnostics"][0]["origin"] in result.findings[0].message


def test_explicit_type_check_runs_independently_of_tests_and_blocks(repo, checker):
    api, calls = checker
    api.report = _report(_diagnostic(), status="fail")

    result = engine.run(repo, run_tests=False, type_check=True, checker="mypy")

    assert result.verdict == "fail"
    outcome = next(c for c in result.checks if c.result.id == "type_check")
    assert outcome.mode == "block"
    assert outcome.result.status == "fail"
    assert calls[0][1]["checker"] == "mypy"
    assert calls[0][1]["timeout_seconds"] == 120


def test_head_cannot_disable_trusted_type_check_policy(repo, checker):
    api, calls = checker
    _set_base_policy(repo, mode="block", checker="pyright", timeout=45)
    (repo / "pyproject.toml").write_text(_config(mode="off", checker="mypy"))
    api.report = _report(_diagnostic(), status="fail")

    result = engine.run(repo, run_tests=False, type_check=False)

    assert result.verdict == "fail"
    assert calls[0][1]["checker"] == "pyright"
    assert calls[0][1]["timeout_seconds"] == 45


@pytest.mark.parametrize("explicit", [False, True])
def test_trusted_advisory_type_check_only_blocks_after_explicit_opt_in(
    repo, checker, explicit
):
    _set_base_policy(repo, mode="advise")
    checker[0].report = _report(_diagnostic(), status="fail")

    result = engine.run(repo, run_tests=False, type_check=explicit)

    assert result.verdict == ("fail" if explicit else "pass")
    assert len(checker[1]) == 1


def test_cli_cannot_replace_checker_required_by_trusted_policy(repo, checker):
    _set_base_policy(repo, mode="block", checker="pyright")

    with pytest.raises(DoneError, match="trusted.*policy"):
        engine.run(repo, run_tests=False, type_check=True, checker="mypy")

    assert checker[1] == []


def test_type_check_waits_for_earlier_blocking_tampering_checks(
    repo, checker, monkeypatch
):
    _set_base_policy(repo, mode="block", gate="block")
    visited = []

    def earlier(check_id, context):
        visited.append(check_id)
        return checks.CheckResult(check_id, None, "fail", "Tampering found")

    monkeypatch.setattr(engine, "run_check", earlier)
    result = engine.run(repo, run_tests=False)

    assert "type_check" not in visited
    assert checker[1] == []
    outcome = next(c for c in result.checks if c.result.id == "type_check")
    assert outcome.result.status == "incomplete"
    assert outcome.blocking


def test_preexisting_type_errors_are_visible_without_blocking_receipts(repo, checker):
    api, _ = checker
    api.report = _report(_diagnostic("preexisting"))
    result = engine.run(repo, run_tests=False, type_check=True)

    receipt = build_receipt(result)

    assert result.verdict == "pass"
    assert receipt["type_check"]["diagnostics"][0]["origin"] == "preexisting"
    assert receipt["type_check"]["diagnostics"][0]["code"] == "assignment"
    assert receipt["type_check"]["diagnostics"][0]["col"] == 4
    assert "preexisting" in render_text(receipt)
    assert "preexisting" in render_markdown(receipt)
    assert validate_receipt(receipt) == []


def test_type_check_receipt_keeps_the_adapters_column(repo, checker):
    diagnostic = _diagnostic("preexisting")
    diagnostic["column"] = diagnostic.pop("col")
    checker[0].report = _report(diagnostic)

    receipt = build_receipt(engine.run(repo, run_tests=False, type_check=True))

    assert receipt["type_check"]["diagnostics"][0]["column"] == 4
    assert receipt["type_check"]["diagnostics"][0]["col"] == 4
    assert validate_receipt(receipt) == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", []),
        ("counts", {"introduced": 0, "preexisting": 0, "unclassified": 0}),
        ("comparison", {"status": [], "reason": ""}),
        ("diagnostics", [{**_diagnostic("preexisting"), "file": "../outside.py"}]),
        ("diagnostics", [{**_diagnostic("preexisting"), "origin": "forged"}]),
    ],
)
def test_type_check_receipt_rejects_malformed_optional_reports(
    repo, checker, field, value
):
    checker[0].report = _report(_diagnostic("preexisting"))
    receipt = build_receipt(engine.run(repo, run_tests=False, type_check=True))
    broken = copy.deepcopy(receipt)
    broken["type_check"][field] = value

    assert validate_receipt(broken)


def test_done_cli_type_check_flags_write_a_valid_receipt(repo, checker, capsys):
    code = run_done_command(
        [
            str(repo),
            "--no-tests",
            "--type-check",
            "--type-checker",
            "mypy",
            "--format",
            "json",
        ]
    )

    receipt = json.loads(capsys.readouterr().out)
    assert code == 0
    assert receipt["type_check"]["status"] == "pass"
    assert validate_receipt(receipt) == []
    assert checker[1][0][1]["checker"] == "mypy"


def test_done_cli_rejects_a_checker_without_opt_in(repo, checker):
    with pytest.raises(SystemExit) as exc:
        run_done_command([str(repo), "--type-checker", "mypy"])

    assert exc.value.code == 2
    assert checker[1] == []
