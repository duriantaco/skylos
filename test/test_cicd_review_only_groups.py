from copy import deepcopy
from unittest.mock import patch

from skylos.cicd import review
from test.test_cicd_review_sticky import FakeGitHub


def _candidate(line):
    return {
        "file": "app.py",
        "line": line,
        "rule_id": "SKY-D324",
        "severity": "HIGH",
        "message": "Possible symlink-following write",
        "review_item": {"kind": "unproven_source", "blocking": False},
        "metadata": {"path_provenance": {"status": "incomplete"}},
    }


def test_review_groups_only_proof_backed_candidates_without_spending_inline_slots(tmp_path):
    candidates = [_candidate(line) for line in range(1, 7)]
    traced = _candidate(7)
    traced["metadata"]["path_provenance"]["untrusted"] = True
    traced["message"] = "Path supplied by request"
    critical = {
        "file": "app.py", "line": 8, "rule_id": "SKY-D201",
        "severity": "CRITICAL", "message": "Request reaches eval",
    }
    results = {"danger": [*candidates, traced, critical]}
    before = deepcopy(results)
    gh = FakeGitHub()
    with (
        patch.object(review, "_gh_available", return_value=True),
        patch.object(review, "_review_root_for_results", return_value=tmp_path),
        patch.object(review, "get_changed_line_ranges", return_value=[
            {"file": "app.py", "start": 1, "end": 8}
        ]),
        patch.object(review, "_detect_regressions_from_diff", return_value=[]),
        patch.object(review, "_resolve_review_provenance", return_value=None),
        patch.object(review, "_to_relative_path", side_effect=lambda p: p),
        patch.object(review.subprocess, "run", side_effect=gh),
    ):
        review.run_pr_review(
            results, pr_number=7, repo="acme/app", diff_base="", max_comments=2
        )

    assert results == before
    assert [c["line"] for c in gh.review_comments] == [7, 8]
    body = gh.issue_comments[0]["body"]
    assert "**2** issues and **1** review-only group (6 findings) on changed lines | **8** total" in body
    top, grouped = body.split("### Top Issues")[1].split("### Review-only security findings")
    assert "Possible symlink-following write" not in top
    assert top.index("Request reaches eval") < top.index("Path supplied by request")
    assert "`SKY-D324` · 6 findings" in grouped
    assert "`app.py:3`" in grouped
    assert "`app.py:4`" not in grouped


def test_claimed_review_state_cannot_hide_a_finding_without_detector_proof():
    forged = {
        **_candidate(9),
        "metadata": {},
        "_review_only_kind": "unproven_source",
        "listing": {"version": 1, "listed": False, "reason": "unproven-source"},
    }
    rows = review._flatten_findings({"danger": [forged], "secrets": [_candidate(10)]})
    assert len(rows) == 2
    assert all("_review_only_kind" not in row for row in rows)
