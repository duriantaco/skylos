"""PR review shows code the change left unused, even off the changed lines."""

from __future__ import annotations

from unittest.mock import patch

from skylos.cicd.review import (
    _flatten_findings,
    _left_unused_rows,
    _post_summary_comment,
    filter_findings_to_diff,
    run_pr_review,
)
from test.test_cicd_review_sticky import FakeGitHub


def _dead(name, line, *, introduced=True, file="/repo/app.py"):
    item = {"name": name, "file": file, "line": line, "confidence": 100}
    if introduced:
        item.update(change_status="introduced", report_scope="dependency_impact")
    return item


def _results(*items):
    return {"unused_functions": list(items)}


def test_flatten_keeps_the_impact_marker_only_for_introduced_dead_code():
    findings = _flatten_findings(
        _results(
            _dead("legacy", 3),
            _dead("old_dead", 9, introduced=False),
            {**_dead("forged", 12), "change_status": "existing"},
        )
    )
    scopes = {f["message"]: f.get("report_scope") for f in findings}
    assert scopes == {
        "Unused function: legacy": "dependency_impact",
        "Unused function: old_dead": None,
        "Unused function: forged": None,
    }


def test_rows_list_introduced_findings_no_inline_comment_shows():
    findings = _flatten_findings(
        _results(
            _dead("on_changed_line", 3),  # R1: inline comment instead
            _dead("off_changed_lines", 40),  # R2: summary row
            _dead("pre_existing", 50, introduced=False),  # R3: not shown
        )
    )
    ranges = [{"file": "app.py", "start": 1, "end": 5}]
    inline = filter_findings_to_diff(findings, ranges, project_root="/repo")

    assert [f["message"] for f in inline] == ["Unused function: on_changed_line"]
    assert _left_unused_rows(findings, inline, "/repo") == [
        ("Unused function: off_changed_lines", "app.py:40")
    ]
    # A summary-only review posts no inline comments, so every one is listed.
    assert [what for what, _ in _left_unused_rows(findings, [], "/repo")] == [
        "Unused function: on_changed_line",
        "Unused function: off_changed_lines",
    ]


def _summary_body(left_unused):
    gh = FakeGitHub()
    with patch("skylos.cicd.review.subprocess.run", side_effect=gh):
        _post_summary_comment([], [], 7, "acme/app", left_unused=left_unused)
    return gh.issue_comments[-1]["body"]


def test_summary_lists_what_the_change_left_unused():
    body = _summary_body([("Unused function: legacy", "src/app.py:40")])

    assert "| **1** left unused by this change" in body
    assert "### Left unused by this change" in body
    assert "| Unused function: legacy | src/app.py:40 |" in body


def test_summary_has_no_section_when_nothing_was_left_unused():  # R4
    body = _summary_body([])

    assert "left unused" not in body.lower()


def test_summary_rows_are_sanitized_and_capped():
    rows = [("Unused function: x | @owner `pwn`", "app.py:1")] + [
        (f"Unused function: f{i}", f"app.py:{i}") for i in range(2, 30)
    ]
    body = _summary_body(rows)

    section = body.split("### Left unused by this change", 1)[1]
    assert "@owner" not in section
    assert section.count("\n| Unused function:") == 20
    assert "…and 9 more." in section


class _ReviewPostFails(FakeGitHub):
    def __call__(self, cmd, **kwargs):
        if "--method" in cmd and any(str(a).endswith("/reviews") for a in cmd):
            self._fail(cmd, "gh: Validation Failed (HTTP 422)")
        return super().__call__(cmd, **kwargs)


def _review(gh, *items, max_comments=25):
    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._review_root_for_results", return_value="/repo"),
        patch(
            "skylos.cicd.review._to_relative_path",
            side_effect=lambda file: file.removeprefix("/repo/"),
        ),
        patch(
            "skylos.cicd.review.get_changed_line_ranges",
            return_value=[{"file": "app.py", "start": 1, "end": 40}],
        ),
        patch("skylos.cicd.review._detect_regressions_from_diff", return_value=[]),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch("skylos.cicd.review.subprocess.run", side_effect=gh),
    ):
        run_pr_review(
            _results(*items),
            pr_number=7,
            repo="acme/app",
            diff_base="",
            max_comments=max_comments,
        )
    return gh.issue_comments[-1]["body"].partition("### Left unused by this change")[2]


def test_finding_past_the_inline_cap_is_named_in_the_summary():
    gh = FakeGitHub()
    section = _review(
        gh, *[_dead(f"f{i}", i, introduced=False) for i in range(1, 26)], _dead("legacy", 26)
    )

    assert len(gh.review_comments) == 25
    assert "| Unused function: legacy | app.py:26 |" in section


def test_failed_inline_review_leaves_every_finding_in_the_summary():
    section = _review(_ReviewPostFails(), _dead("legacy", 3))

    assert "| Unused function: legacy | app.py:3 |" in section


def test_inline_comment_from_an_earlier_push_is_not_repeated():
    gh = FakeGitHub()
    _review(gh, _dead("legacy", 3))
    section = _review(gh, _dead("legacy", 3))

    assert len(gh.review_comments) == 1
    assert section == ""

    # A legacy comment naming one symbol is not evidence for another name.
    # With no inline slots available, the new name must reach the summary.
    gh = FakeGitHub()
    gh.review_comments = [
        {
            "id": 55,
            "path": "app.py",
            "line": 3,
            "body": "🔵 **LOW** `SKY-U001`\n\nUnused function: old_name\n\n---\n"
            "_🤖 Analyzed by [Skylos](https://x)_",
            "user": {"login": "github-actions[bot]", "type": "Bot"},
        }
    ]
    section = _review(
        gh, _dead("old_name", 3, introduced=False), _dead("new_name", 3), max_comments=0
    )
    assert "| Unused function: new_name | app.py:3 |" in section
    assert len(gh.review_comments) == 1
