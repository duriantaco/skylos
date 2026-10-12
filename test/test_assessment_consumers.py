"""Assessments communicate urgency and coverage without numeric reassurance."""

from copy import deepcopy
from io import StringIO
from unittest.mock import Mock

import pytest
from rich.console import Console

import skylos.api as api
from skylos.cli import _skylos_console_theme
from skylos.cicd.review import _format_assessment_markdown
from skylos.reporting.assessment import compute_assessment
from skylos.reporting.assessment_display import assessment_rows, maintainability_rows
from skylos.reporting.github_annotations import _emit_github_annotations
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results
from skylos_mcp.server import (
    _architecture_payload,
    _health_score_payload,
    _make_summary,
)


def assessment():
    return {
        "version": 1,
        "scope": "all_analyzed_findings",
        "scanned_checks": ["security", "quality", "dead_code"],
        "coverage": {
            "status": "partial",
            "not_assessed": ["secrets"],
            "incomplete_checks": [],
            "reasons": [],
        },
        "risk": {
            "status": "critical",
            "highest_severity": "CRITICAL",
            "finding_count": 1,
        },
        "maintainability": {
            "status": "measured",
            "advice_count": 30,
            "rule_count": 1,
            "affected_files": 5,
            "checks": [
                {
                    "rule_id": "SKY-C303",
                    "count": 30,
                    "affected_units": 30,
                    "unit": "function",
                    "analyzed_units": 200,
                    "affected_percent": 15,
                    "max_value": 45,
                    "max_threshold": 10,
                    "max_excess_ratio": 4.5,
                }
            ],
        },
        "dead_code": {
            "status": "review",
            "candidate_count": 2,
            "confidence_range": [60, 95],
        },
        "finding_counts": {"defect": 0, "review": 3, "advice": 30, "advice_groups": 1},
    }


def result():
    return {
        "assessment": assessment(),
        "analysis_summary": {"total_files": 5},
        "danger": [
            {
                "rule_id": "SKY-D211",
                "file": "a.py",
                "line": 1,
                "message": "Critical review evidence",
                "severity": "CRITICAL",
            }
        ],
        "quality": [],
    }


@pytest.mark.parametrize("renderer", [render_results, render_pretty_results])
@pytest.mark.parametrize("width", [80, 120])
def test_assessment_keeps_critical_review_and_measurements_without_score(
    renderer, width
):
    scan = result()
    scan["analysis_summary"]["assessment_includes_filtered_findings"] = True
    original = deepcopy(scan)
    output = StringIO()
    console = Console(
        file=output, width=width, theme=_skylos_console_theme(), color_system=None
    )
    renderer(console, scan)
    text = " ".join(output.getvalue().split())
    assert "CRITICAL" in text and "1 unresolved finding" in text
    assert "30/200 functions (15%)" in text
    assert "max 45" in text and "limit 10" in text and "4.5× limit" in text
    assert "Coverage: partial" in text and "not assessed: secrets" in text
    assert "Assessment includes all analyzed findings" in text
    assert "Gate" in text and "Not evaluated" in text
    assert "A+" not in text and "/100" not in text and "Badge" not in text
    assert scan == original


@pytest.mark.parametrize("status", ["unknown", "not_assessed"])
def test_unknown_or_disabled_risk_does_not_claim_clean(status):
    payload = assessment()
    payload["risk"] = {"status": status}
    risk = dict(assessment_rows(payload))["Risk"]
    assert "No risk findings" not in risk


def test_zero_candidates_does_not_claim_everything_dead_code_free():
    payload = assessment()
    payload["dead_code"] = {"status": "none", "candidate_count": 0}
    assert (
        dict(assessment_rows(payload))["Dead code"] == "No candidates in assessed code"
    )


def test_zero_denominator_describes_the_empty_inventory():
    payload = assessment()
    check = payload["maintainability"]["checks"][0]
    check.update(affected_units=0, analyzed_units=0, affected_percent=None)
    assert maintainability_rows(payload)[0][1] == "No eligible functions checked"


def test_known_urgency_does_not_hide_findings_with_unknown_severity():
    payload = assessment()
    payload["risk"]["severity_counts"] = {"CRITICAL": 1, "UNKNOWN": 1}
    payload["risk"]["finding_count"] = 2
    assert assessment_rows(payload)[0][1] == (
        "CRITICAL · 2 unresolved findings · 1 with unknown severity"
    )


def test_missing_denominator_is_explicit_without_percentage():
    payload = assessment()
    check = payload["maintainability"]["checks"][0]
    check.update(analyzed_units=None, affected_percent=None)
    rows = maintainability_rows(payload)
    assert rows[0][1] == "30 functions · denominator unavailable"


def test_measurements_distinguish_languages_for_the_same_rule():
    payload = assessment()
    python_check = payload["maintainability"]["checks"][0]
    python_check.update(language="Python", name="Complexity")
    typescript_check = {**python_check, "language": "TypeScript"}
    payload["maintainability"]["checks"].append(typescript_check)
    labels = [row[0] for row in maintainability_rows(payload)]
    assert labels == [
        "SKY-C303 · Python · Complexity",
        "SKY-C303 · TypeScript · Complexity",
    ]


def test_incomplete_empty_checks_render_unknown_instead_of_clean():
    scan = {
        "analysis_summary": {"grade_categories": ["security", "dead_code"]},
        "analysis_errors": [{"message": "Engine unavailable"}],
    }
    payload = compute_assessment(scan)
    rows = dict(assessment_rows(payload))
    assert rows["Risk"].startswith("Unknown")
    assert rows["Dead code"].startswith("Unknown")
    assert "No risk findings" not in rows["Risk"]
    assert "No candidates" not in rows["Dead code"]


def test_gate_result_is_separate_from_risk():
    payload = assessment()
    assert dict(assessment_rows(payload, gate={"passed": True}))["Gate"].startswith(
        "PASS"
    )
    assert dict(assessment_rows(payload, gate={"passed": False}))["Gate"].startswith(
        "FAIL"
    )
    assert dict(assessment_rows(payload))["Risk"].startswith("CRITICAL")


def test_github_assessment_notice_escapes_workflow_commands(capsys):
    payload = result()
    payload["assessment"]["coverage"]["not_assessed"] = ["secrets\n::error injected%"]
    _emit_github_annotations(payload)
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("::notice title=Skylos Assessment::Risk: CRITICAL")
    assert "secrets%0A::error injected%25" in lines[0]
    assert lines[1].startswith("::error")


def test_ci_summary_has_no_blended_score():
    lines = "\n".join(_format_assessment_markdown(assessment()))
    assert "| Risk | CRITICAL" in lines
    assert "30/200 functions (15%)" in lines
    assert "Coverage: partial" in lines
    assert "Legacy" not in lines and "/100" not in lines and "Grade" not in lines


@pytest.mark.parametrize(
    "consumer", [_make_summary, _health_score_payload, _architecture_payload]
)
def test_mcp_consumers_preserve_assessment(consumer):
    scan = result()
    reply = consumer(scan)
    assert reply["assessment"] == scan["assessment"]
    assert "grade" not in reply and "category_scores" not in reply


def test_upload_metadata_carries_assessment_without_grade():
    payload = assessment()
    metadata = api._build_report_metadata(
        commit_hash="abc", branch="main", actor="dev", assessment_data=payload
    )
    assert metadata["assessment"] == payload
    assert "grade" not in metadata


def test_upload_retains_canonical_families_without_changing_review_sections():
    from skylos.api._findings import UPLOAD_FINDING_SPECS, VERIFY_FINDING_SPECS
    from skylos.core.review_decisions import FINDING_SECTIONS

    shared = {"rule_id": "SKY-Q301", "file": "absent.py", "line": 2, "message": "Same evidence", "severity": "WARN"}
    signal = {"rule_id": "SKY-ARCH01", "file": "absent.py", "line": 3, "message": "Architecture advice", "severity": "WARN", "evidence": ["preserved"]}
    scan = {
        "quality": [shared],
        "publisher_change_findings": [{"rule_id": "SKY-AI001", "message": "Publisher change", "severity": "HIGH"}],
        "code_health": [dict(shared), {"rule_id": "SKY-Q302", "message": "Code health", "severity": "WARN"}],
        "architecture_metrics": {"advisories": [{"signals": [signal, dict(signal)]}]},
    }
    before = deepcopy(scan)
    rows = api._normalize_result_sections(scan, UPLOAD_FINDING_SPECS, None)
    assert [row["rule_id"] for row in rows] == ["SKY-Q301", "SKY-AI001", "SKY-Q302", "SKY-ARCH01", "SKY-ARCH01"]
    assert [row["category"] for row in rows] == ["QUALITY", "AI_DEFECT", "QUALITY", "QUALITY", "QUALITY"]
    assert rows[-1]["evidence"] == ["preserved"]
    assert scan == before
    assert UPLOAD_FINDING_SPECS is FINDING_SECTIONS
    assert api._normalize_result_sections(scan, VERIFY_FINDING_SPECS, None) == []


def test_all_upload_protocol_payloads_preserve_assessment(monkeypatch):
    monkeypatch.setattr(api, "get_git_info", lambda: ("abc", "main", "dev", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_detect_report_provenance_data", lambda *_: None)
    prepared = api._prepare_report_upload(result())
    for payload in (
        prepared.metadata,
        prepared.core_payload,
        prepared.legacy_payload,
        prepared.compatibility_payload,
    ):
        assert payload["assessment"] == result()["assessment"]
        assert "grade" not in payload


def test_upload_success_prints_assessment_and_actual_gate_separately(capsys):
    api._print_report_upload_success(
        grade_data=None,
        assessment_data=assessment(),
        passed=False,
        new_violations=1,
        plan="workspace",
        scan_id=None,
        credits_left=None,
    )
    text = capsys.readouterr().out
    assert (
        "Risk: CRITICAL" in text and "Maintainability:" in text and "Dead code:" in text
    )
    assert "FAIL" in text.upper()
    assert "Grade:" not in text and "/100" not in text


def test_saved_upload_context_preserves_assessment_for_resend(monkeypatch):
    from types import SimpleNamespace

    payload = assessment()
    prepared = SimpleNamespace(metadata={"assessment": payload}, scan_summary={})
    session = SimpleNamespace(mode="inline", idempotency_key="same-key")
    captured = {}
    monkeypatch.setattr(api, "_pending_request_parts", lambda *_: (b"{}", {}))
    monkeypatch.setattr(
        api, "_save_pending_upload", lambda *_, **kwargs: captured.update(kwargs)
    )
    api._save_pending_for_session(session, prepared, "report", None, {})
    assert captured["context"]["assessment_data"] == payload


def test_legacy_grade_renderer_never_copies_numeric_badge(monkeypatch):
    copy = Mock()
    monkeypatch.setattr("skylos.ui.clipboard.copy_to_clipboard", copy)
    scan = result()
    scan.pop("assessment")
    scan["grade"] = {"overall": {"score": 97, "letter": "A+"}, "categories": {}}
    output = StringIO()
    console = Console(file=output, width=120, theme=_skylos_console_theme())
    render_results(console, scan)
    assert "Legacy score" in output.getvalue()
    assert "not a current risk assessment" in output.getvalue()
    assert "Badge" not in output.getvalue()
    copy.assert_not_called()
