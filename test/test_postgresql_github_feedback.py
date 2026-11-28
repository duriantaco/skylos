from copy import deepcopy

import pytest

from skylos.cicd import review
from skylos.reporting.assessment import compute_assessment
from skylos.reporting.github_annotations import _emit_github_annotations
from skylos.reporting.listing import github_feedback_result
from test.test_cicd_review_sticky import BOT, FakeGitHub


def _row(rule, line, **extra):
    return {
        "rule_id": rule,
        "file": "db.sql",
        "line": line,
        "severity": "MEDIUM",
        "message": rule,
        **extra,
    }


def _review(result, gh, monkeypatch, tmp_path, summary_only=False):
    monkeypatch.setattr(review, "_gh_available", lambda: True)
    monkeypatch.setattr(review, "_review_root_for_results", lambda _: tmp_path)
    monkeypatch.setattr(
        review,
        "get_changed_line_ranges",
        lambda *a, **kw: [{"file": "db.sql", "start": 1, "end": 10}],
    )
    monkeypatch.setattr(review, "_detect_regressions_from_diff", lambda *a, **kw: [])
    monkeypatch.setattr(review, "_resolve_review_provenance", lambda *a, **kw: None)
    monkeypatch.setattr(review.subprocess, "run", gh)
    review.run_pr_review(
        result,
        repo="acme/app",
        pr_number=7,
        diff_base="",
        summary_only=summary_only,
    )
    return gh.issue_comments[0]["body"]


@pytest.mark.parametrize("summary_only", [False, True])
def test_report_only_quality_never_posts_or_contributes_to_risk(
    capsys, tmp_path, monkeypatch, summary_only
):
    result = {
        "quality": [_row(f"SKY-Q{number}", number - 502) for number in range(503, 511)],
        "analysis_summary": {"grade_categories": ["quality"], "total_files": 1},
    }
    result["assessment"] = compute_assessment(result)
    before = deepcopy(result)
    _emit_github_annotations(result)
    output = capsys.readouterr().out
    assert "Skylos Assessment" in output
    assert "8 risk findings" not in output
    assert " file=" not in output

    gh = FakeGitHub()
    body = _review(result, gh, monkeypatch, tmp_path, summary_only)
    assert gh.review_comments == []
    assert "**0** issue(s) on changed lines | **0** total" in body
    assert "changed=0 max=0" in body
    assert "SKY-Q" not in body
    assert "| quality |" not in body
    assert "8 risk findings" not in body
    assert result == before


def test_security_groups_stay_on_changed_lines_with_other_rules_visible(
    capsys, tmp_path, monkeypatch
):
    grant = {"kind": "postgresql_public_grant", "blocking": False}
    result = {
        "quality": [_row("SKY-Q504", 1), _row("SKY-Q301", 2)],
        "custom_rules": [_row("SKY-Q504", 3, message="Custom quality check")],
        "danger": [_row("SKY-D418", n, review_item=grant) for n in (4, 5, 11)],
    }
    _emit_github_annotations(result)
    output = capsys.readouterr().out
    assert output.count("SKY-D418 (review only)") == 1
    assert "3 locations for review" in output
    assert "full JSON report" in output
    assert output.count("Skylos SKY-Q504") == 1
    assert "Custom quality check" in output
    gh = FakeGitHub()
    body = _review(result, gh, monkeypatch, tmp_path)
    assert [c["line"] for c in gh.review_comments] == [2, 3]
    assert "**2** issues and **1** review-only group (2 findings)" in body
    assert "`SKY-D418` · 2 findings" in body
    assert "db.sql:11" not in body
    assert "full JSON report" in body
    assert "| quality | 1 |" in body
    assert "| custom_rules | 1 |" in body


def test_custom_markers_and_filtered_scan_assessment_survive():
    danger = _row("SKY-D211", 9, severity="HIGH")
    report = {
        "quality": [_row("SKY-Q504", 1), _row("SKY-Q504", 2, source="custom")],
        "danger": [danger],
    }
    assessment = compute_assessment(report, scanned_checks=["quality", "security"])
    filtered = {
        **report,
        "danger": [],
        "assessment": assessment,
        "analysis_summary": {"assessment_includes_filtered_findings": True},
    }
    projected = github_feedback_result(filtered)
    assert projected["quality"] == [report["quality"][1]]
    assert projected["assessment"]["risk"]["highest_severity"] == "HIGH"


def test_previously_counted_advisory_does_not_claim_the_change_fixed_it(
    tmp_path, monkeypatch
):
    gh = FakeGitHub()
    gh.issue_comments.append(
        {
            "id": 321,
            "user": BOT,
            "body": f"{review.SUMMARY_MARKER}\n<!-- skylos-review-state: changed=1 max=1 -->",
        }
    )
    body = _review({"quality": [_row("SKY-Q510", 4)]}, gh, monkeypatch, tmp_path)
    assert len(gh.issue_comments) == 1
    assert "are fixed" not in body
    assert "changed=0 max=1" in body


def test_legacy_grade_annotation_uses_the_visible_findings(capsys):
    from skylos.reporting.grader import compute_grade

    report = {"quality": [_row("SKY-Q504", 1)]}
    report["grade"] = compute_grade(report, 1)
    assert report["grade"]["overall"]["score"] < 100
    _emit_github_annotations(report)
    assert "Legacy Score::A+ (100/100)" in capsys.readouterr().out
