"""The closing count, the upload count and the gate lines name the same records."""

from copy import deepcopy
from io import StringIO
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

import skylos.api as api
import skylos.cli as cli
from skylos.cloud.gate_status import clean_new_issue_baseline, new_issues_text
from skylos.commands.scan_cmd import (
    _closing_summary,
    _print_failed_gate_exit_note,
    _public_upload_receipt,
)
from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.assessment_display import (
    assessment_coverage_text,
    assessment_rows,
    closing_summary,
    hidden_advice_text,
    listed_issue_counts,
)
from test.test_cli_report_serialization import _configure, _report


def _row(rule, source, line=1, **changes):
    row = {
        "rule_id": rule,
        "file": str(source),
        "line": line,
        "severity": "HIGH",
        "name": "build",
        "value": 30,
        "threshold": 10,
        "message": f"{rule} finding",
    }
    row.update(changes)
    return row


@pytest.fixture
def scan(tmp_path):
    source = tmp_path / "service.py"
    source.write_text("def build():\n    return 1\n" * 20, encoding="utf-8")
    raw = {
        "danger": [_row("SKY-D211", source, severity="CRITICAL")],
        "secrets": [
            _row("SKY-S101", source, severity="CRITICAL", message="github"),
            _row("SKY-S101", source, severity="CRITICAL", message="entropy"),
        ],
        "quality": [
            _row("SKY-L014", source),
            _row("SKY-L027", source, line=4, severity="MEDIUM"),
            _row("SKY-Q301", source, line=10, value=11),
            _row("SKY-Q306", source, line=10, value=22, threshold=15),
            _row("SKY-C304", source, line=10, value=219, threshold=50),
        ],
        "unused_functions": [
            {
                "name": "old",
                "full_name": "service.old",
                "file": str(source),
                "line": 7,
                "confidence": 100,
                "type": "function",
            }
        ],
        "analysis_summary": {"grade_categories": ["security", "quality", "dead_code"]},
        "provenance": {},
    }
    return apply_advice_policy(raw, project_root=tmp_path), tmp_path


def _upload_summary(result, root):
    with (
        patch.object(api, "get_git_info", return_value=("c", "main", "actor", {})),
        patch.object(api, "get_git_root", return_value=str(root)),
        patch.object(api, "detect_ai_code", return_value={"detected": False}),
        patch.object(api, "_annotate_findings_with_blame"),
        patch.object(api, "_load_repo_link", return_value={}),
    ):
        prepared = api._prepare_report_upload(result, analyzer_owned=True)
    return prepared.core_payload["runs"][0]["properties"]["summary"]


def test_closing_count_is_the_listed_count_the_upload_sends(scan):
    result, root = scan
    before = deepcopy(result)

    counts = listed_issue_counts(result)
    summary = _upload_summary(result, root)

    assert result == before
    assert sum(counts.values()) == summary["listed_finding_count"] == 6
    assert summary["finding_count"] == 9
    assert closing_summary(result) == (
        "Found 6 issues: security 1, secrets 2, quality 2, dead code 1. "
        "1 more advice finding is hidden by default; --all-advice lists and counts it."
    )


def test_hidden_advice_hint_is_singular_or_plural_and_names_the_count():
    result = {"advice_visibility": {"omitted_checks": 8}}
    assert hidden_advice_text(result) == (
        "8 more advice findings are hidden by default; "
        "--all-advice lists and counts them."
    )
    single = {"advice_visibility": {"omitted_checks": 1}}
    assert hidden_advice_text(single) == (
        "1 more advice finding is hidden by default; --all-advice lists and counts it."
    )
    for value in (0, -1, True, "8", None):
        assert (
            hidden_advice_text({"advice_visibility": {"omitted_checks": value}}) == ""
        )
    assert hidden_advice_text({}) == ""


def test_all_advice_lists_and_counts_the_optional_records(tmp_path):
    raw = {"quality": [_row("SKY-L027", tmp_path / "a.py", severity="MEDIUM")]}
    hidden = apply_advice_policy(raw, project_root=tmp_path)
    shown = apply_advice_policy(raw, project_root=tmp_path, all_advice=True)
    assert closing_summary(hidden) == (
        "Found 0 issues. 1 more advice finding is hidden by default; "
        "--all-advice lists and counts it."
    )
    assert closing_summary(shown) == "Found 1 issue: quality 1."


def test_scan_without_listed_issues_still_names_hidden_advice_and_uncertainty():
    result = {"quality": [], "advice_visibility": {"omitted_checks": 8}}
    assert closing_summary(result, uncertainty_count=1) == (
        "Found 0 issues. Usage remains uncertain for 1 symbol. "
        "8 more advice findings are hidden by default; "
        "--all-advice lists and counts them."
    )
    assert closing_summary({}) == "Found 0 issues."


def test_listed_records_of_unknown_categories_are_counted_not_dropped():
    with patch(
        "skylos.reporting.finding_types.iter_result_findings",
        return_value=iter([("security", {}), ("future", {})]),
    ):
        assert closing_summary({}) == "Found 2 issues: security 1, other 1."


def test_scans_with_more_than_dead_code_get_the_issue_count():
    result = {
        "analysis_summary": {"grade_categories": ["dead_code", "quality"]},
        "advice_visibility": {"omitted_checks": 2},
    }
    assert _closing_summary(result, 0) == closing_summary(result)


@pytest.mark.parametrize("checks", [["dead_code"], [], None, "quality"])
def test_dead_code_only_scans_keep_the_dead_code_headline(checks):
    result = {"analysis_summary": {"grade_categories": checks}}
    assert _closing_summary(result, 0) is None


def test_print_badge_prints_the_summary_in_place_of_the_raw_counts():
    logger = Mock(console=Mock())
    cli.print_badge(
        0,
        logger,
        danger_enabled=True,
        danger_count=1,
        quality_enabled=True,
        quality_count=5,
        show_badge=False,
        summary="Found 4 issues: security 1, secrets 2, quality 1.",
    )
    printed = [call.args[0] for call in logger.console.print.call_args_list]
    assert "Found 4 issues: security 1, secrets 2, quality 1." in printed
    assert not any("5 quality issues" in str(item) for item in printed)


def test_maintainability_and_coverage_rows_say_what_they_count():
    assessment = {
        "maintainability": {
            "status": "measured",
            "advice_count": 0,
            "rule_count": 5,
            "affected_files": 0,
        },
        "coverage": {"status": "incomplete", "incomplete_checks": ["dependencies"]},
    }
    rows = dict(assessment_rows(assessment))
    assert (
        rows["Maintainability"]
        == "0 advice findings · 5 rules checked · 0 affected files"
    )
    assert assessment_coverage_text(assessment) == (
        "Coverage: incomplete; not fully checked: dependencies; "
        "some issues may not be reported"
    )
    complete = {"coverage": {"status": "complete"}}
    assert assessment_coverage_text(complete) == "Coverage: complete"


@pytest.mark.parametrize(
    "explain,expected",
    [
        (
            {"baseline": {"branch": "main"}, "detection_mode": "baseline"},
            "5 new issues (not in the last passing scan of main)",
        ),
        (
            {"baseline": {"branch": None}, "detection_mode": "baseline"},
            "5 new issues (not in the last passing scan)",
        ),
        (
            {"baseline": {"branch": "main"}, "detection_mode": "pr-diff"},
            "5 new issues (on lines this pull request changed)",
        ),
        ({"baseline": None, "detection_mode": "first-scan-baseline"}, "5 new issues"),
        ({"detection_mode": "something-else"}, "5 new issues"),
        ({"detection_mode": ["baseline"]}, "5 new issues"),
        ("not-a-dict", "5 new issues"),
        (None, "5 new issues"),
        (
            {"baseline": {"branch": "ma\x1b]0;x\x07in"}, "detection_mode": "baseline"},
            "5 new issues (not in the last passing scan of ma]0;xin)",
        ),
    ],
)
def test_new_issue_count_names_what_it_was_compared_with(explain, expected):
    assert new_issues_text(5, clean_new_issue_baseline(explain)) == expected


def test_one_new_issue_is_singular():
    assert new_issues_text(1, None) == "1 new issue"


def test_upload_result_keeps_a_clean_baseline_but_the_public_receipt_does_not():
    data = {
        "quality_gate": {"passed": False, "new_violations": 5},
        "explain": {
            "baseline": {"scan_id": "scan-0", "branch": "main", "selection_rule": "x"},
            "detection_mode": "baseline",
        },
    }
    result = api._report_upload_success_result(data, "scan-1", False, "pro")
    assert result["new_issue_baseline"] == {"mode": "baseline", "branch": "main"}
    assert "new_issue_baseline" not in _public_upload_receipt(result)
    old = api._report_upload_success_result(
        {"quality_gate": {"passed": False}}, "scan-1", False, "pro"
    )
    assert "new_issue_baseline" not in old


def _gate_note(capsys, *, strict, is_forced, note=True):
    token = api._FAILED_GATE_NOTE.set(note)
    try:
        api._enforce_report_quality_gate(
            False, strict=strict, is_forced=is_forced, quiet=False
        )
    finally:
        api._FAILED_GATE_NOTE.reset(token)
    return capsys.readouterr().out


def test_failed_gate_note_says_whether_the_command_fails(capsys):
    assert _gate_note(capsys, strict=False, is_forced=False) == (
        "\n⚠️ Quality gate failed, but this command does not fail because of it.\n"
    )
    assert _gate_note(capsys, strict=True, is_forced=True) == (
        "\n⚠️ Quality gate failed; --force stops it from failing this command.\n"
    )
    assert _gate_note(capsys, strict=False, is_forced=False, note=False) == ""
    with pytest.raises(SystemExit) as exc:
        _gate_note(capsys, strict=True, is_forced=False, note=False)
    assert exc.value.code == 1
    assert "not enforcing" not in capsys.readouterr().out


def test_upload_report_restores_the_note_setting(monkeypatch):
    seen = []
    monkeypatch.setattr(api, "get_project_token", lambda: "local-test-key")
    monkeypatch.setattr(api, "get_project_info", lambda _token: None)
    monkeypatch.setattr(api, "_print_pending_upload_reminder", lambda: None)
    monkeypatch.setattr(api, "_prepare_report_upload", lambda *_a, **_k: object())
    monkeypatch.setattr(api, "_print_preflight_notice", lambda *_a, **_k: None)

    def send(*_args, **_kwargs):
        seen.append(api._FAILED_GATE_NOTE.get())
        raise RuntimeError("stop")

    monkeypatch.setattr(api, "_send_prepared_upload", send)
    with pytest.raises(RuntimeError):
        api.upload_report({}, failed_gate_note=False)
    assert seen == [False]
    assert api._FAILED_GATE_NOTE.get() is True


def _exit_note(**flags):
    output = StringIO()
    console = Console(
        file=output, width=400, color_system=None, theme=cli._skylos_console_theme()
    )
    args = SimpleNamespace(**{"strict": False, "gate": False, "force": False, **flags})
    _print_failed_gate_exit_note(console, args, False)
    return " ".join(output.getvalue().split())


def test_scan_exit_note_matches_the_exit_code():
    assert _exit_note() == (
        "⚠️ The failed quality gate does not change this command's exit code; "
        "add --gate to make it fail."
    )
    assert _exit_note(strict=True) == (
        "Exiting with code 1 because the Skylos Cloud quality gate failed (--strict)."
    )
    assert _exit_note(gate=True) == (
        "Exiting with code 1 because the Skylos Cloud quality gate failed (--gate)."
    )
    assert _exit_note(strict=True, force=True) == (
        "⚠️ --force: the failed quality gate does not change this command's exit code."
    )
    output = StringIO()
    console = Console(file=output, color_system=None, theme=cli._skylos_console_theme())
    for passed in (True, None):
        _print_failed_gate_exit_note(console, SimpleNamespace(), passed)
    assert output.getvalue() == ""


def _rich_upload(monkeypatch, tmp_path, response, *extra):
    _configure(monkeypatch, tmp_path, "rich", upload=True)
    monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, *extra])
    monkeypatch.setattr(cli, "_print_upload_destination", lambda *_a: (True, False))
    result = {**_report(), "unused_functions": []}
    monkeypatch.setattr(cli, "run_analyze", lambda *_a, **_k: json.dumps(result))
    upload = Mock(return_value=response)
    monkeypatch.setattr(cli, "upload_report", upload)
    try:
        cli.main()
        code = 0
    except SystemExit as exc:
        code = exc.code
    return upload, code


FAILED_RESPONSE = {
    "success": True,
    "scan_id": "scan-1",
    "quality_gate_passed": False,
    "quality_gate": {"passed": False, "new_violations": 5},
    "new_issue_baseline": {"mode": "baseline", "branch": "main"},
}


def test_rich_upload_labels_new_issues_and_the_exit(monkeypatch, capsys, tmp_path):
    upload, code = _rich_upload(monkeypatch, tmp_path, FAILED_RESPONSE)
    out = " ".join(capsys.readouterr().out.split())

    assert code in (0, None)
    assert upload.call_args.kwargs["failed_gate_note"] is False
    assert upload.call_args.kwargs["strict"] is False
    assert "5 new issues (not in the last passing scan of main)" in out
    assert (
        "does not change this command's exit code; add --gate to make it fail." in out
    )
    assert out.index("5 new issues") < out.index("does not change")
    assert "new violation" not in out and "not enforcing" not in out


def test_rich_strict_upload_still_exits_one_and_says_why(monkeypatch, capsys, tmp_path):
    upload, code = _rich_upload(monkeypatch, tmp_path, FAILED_RESPONSE, "--strict")
    out = " ".join(capsys.readouterr().out.split())

    assert code == 1
    assert upload.call_args.kwargs["failed_gate_note"] is False
    assert (
        "Exiting with code 1 because the Skylos Cloud quality gate failed (--strict)."
        in out
    )
    assert "does not change this command's exit code" not in out


@pytest.mark.parametrize("force", [False, True])
def test_gate_upload_lets_the_api_note_only_a_forced_run(
    monkeypatch, capsys, tmp_path, force
):
    extra = ["--gate"]
    if force:
        extra.append("--force")
    upload, _code = _rich_upload(monkeypatch, tmp_path, FAILED_RESPONSE, *extra)
    capsys.readouterr()

    assert upload.call_args.kwargs["failed_gate_note"] is force
