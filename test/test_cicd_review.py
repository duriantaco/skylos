from unittest.mock import Mock, patch

import pytest

from skylos.cicd.review import (
    _parse_unified_diff,
    filter_findings_to_diff,
    get_changed_line_ranges,
    _flatten_findings,
    _merge_llm_findings,
    _format_review_comment,
    _format_evidence_card_comment,
    _post_summary_comment,
    _review_comment_location,
    _detect_pr_number,
    run_pr_review,
)
from skylos.cicd.evidence import build_evidence_card


SAMPLE_DIFF = """\
diff --git a/app.py b/app.py
index abc1234..def5678 100644
--- a/app.py
+++ b/app.py
@@ -10,0 +11,3 @@ def handler():
+    query = request.args.get("q")
+    cursor.execute("SELECT * FROM users WHERE name = " + query)
+    return cursor.fetchall()
diff --git a/utils.py b/utils.py
index 111..222 100644
--- a/utils.py
+++ b/utils.py
@@ -5 +5 @@ def helper():
-    return old_value
+    return new_value
"""


def _stripe_like_token() -> str:
    return "sk" + "_live_" + "abcdefghijklmnopqrstuvwxyz1234567890"


@pytest.fixture
def sample_results():
    return {
        "danger": [
            {
                "rule_id": "SKY-D201",
                "file": "app.py",
                "line": 12,
                "severity": "CRITICAL",
                "message": "SQL injection",
            },
            {
                "rule_id": "SKY-D202",
                "file": "other.py",
                "line": 50,
                "severity": "HIGH",
                "message": "Not on changed lines",
            },
        ],
        "quality": [
            {
                "rule_id": "SKY-Q301",
                "file": "utils.py",
                "line": 5,
                "severity": "MEDIUM",
                "message": "Complexity",
            },
        ],
        "secrets": [],
    }


def test_parse_unified_diff():
    ranges = _parse_unified_diff(SAMPLE_DIFF)
    assert len(ranges) == 2

    assert ranges[0]["file"] == "app.py"
    assert ranges[0]["start"] == 11
    assert ranges[0]["end"] == 13

    assert ranges[1]["file"] == "utils.py"
    assert ranges[1]["start"] == 5
    assert ranges[1]["end"] == 5


def test_parse_unified_diff_keeps_deletion_only_hunk_anchor():
    diff = """diff --git a/app/main.py b/app/main.py
--- a/app/main.py
+++ b/app/main.py
@@ -7 +6,0 @@
-def require_admin(): ...
"""

    assert _parse_unified_diff(diff) == [{"file": "app/main.py", "start": 6, "end": 6}]
    assert _parse_unified_diff(diff, include_deletion_anchors=False) == []


def test_filter_findings_to_diff(sample_results):
    ranges = _parse_unified_diff(SAMPLE_DIFF)
    findings = _flatten_findings(sample_results)
    filtered = filter_findings_to_diff(findings, ranges)

    assert len(filtered) == 2
    files = {f["file"] for f in filtered}
    assert "app.py" in files
    assert "utils.py" in files
    assert "other.py" not in files


def test_filter_findings_empty_ranges():
    findings = [{"file": "a.py", "line": 1, "message": "test"}]
    assert filter_findings_to_diff(findings, []) == []


def test_pr_review_ignores_old_finding_after_deletion_only_hunk():
    diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +0,0 @@\n-# note\n"
    results = {
        "quality": [
            {"file": "a.py", "line": 1, "rule_id": "SKY-Q301", "message": "Old issue"}
        ]
    }

    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._detect_regressions_from_diff", return_value=[]),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch(
            "skylos.cicd.review.subprocess.run",
            return_value=Mock(returncode=0, stdout=diff),
        ),
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        run_pr_review(results, pr_number=1, repo="owner/repo", diff_base="main")

    post_review.assert_not_called()
    assert len(post_summary.call_args.args[0]) == 1
    assert post_summary.call_args.args[1] == []


def test_pr_review_keeps_deletion_anchor_for_security_regression():
    diff = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +0,0 @@\n-# guard\n"
    regression = {
        "file": "a.py",
        "line": 1,
        "rule_id": "SKY-L021",
        "message": "Guard removed",
        "kind": "security_regression",
        "category": "security_regression",
    }

    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch(
            "skylos.cicd.review._detect_regressions_from_diff",
            return_value=[regression],
        ),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch(
            "skylos.cicd.review.subprocess.run",
            return_value=Mock(returncode=0, stdout=diff),
        ),
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment"),
    ):
        run_pr_review({}, pr_number=1, repo="owner/repo", diff_base="main")

    assert post_review.call_args.args[0] == [regression]
    assert post_review.call_args.kwargs["changed_ranges"] == [
        {"file": "a.py", "start": 1, "end": 1}
    ]


def test_pr_review_reports_new_unused_function_once():
    diff = (
        "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -0,0 +1,2 @@\n+def unused():\n+    return 1\n"
    )
    unused = {"file": "a.py", "line": 1, "name": "unused", "confidence": 100}
    results = {
        "unused_functions": [unused],
        "forgotten": [{**unused, "status": "EXPIRED"}],
    }

    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._detect_regressions_from_diff", return_value=[]),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch(
            "skylos.cicd.review.subprocess.run",
            return_value=Mock(returncode=0, stdout=diff),
        ),
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        run_pr_review(results, pr_number=1, repo="owner/repo", diff_base="main")

    comments = post_review.call_args.args[0]
    assert len(comments) == 1
    assert comments[0]["rule_id"] == "SKY-U001"
    assert comments[0]["message"] == "Unused function: unused"
    assert comments[0]["category"] == "dead_code"
    assert len(post_summary.call_args.args[0]) == 1
    assert len(post_summary.call_args.args[1]) == 1


def test_pr_review_does_not_match_old_same_named_file(tmp_path):
    diff = (
        "diff --git a/foo.py b/foo.py\n--- a/foo.py\n+++ b/foo.py\n"
        "@@ -0,0 +1 @@\n+# changed\n"
    )
    results = {
        "unused_functions": [
            {"file": str(tmp_path / "src" / "foo.py"), "line": 1, "name": "old"}
        ]
    }

    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review.find_git_root", return_value=tmp_path),
        patch("skylos.cicd.review._detect_regressions_from_diff", return_value=[]),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch(
            "skylos.cicd.review.subprocess.run",
            return_value=Mock(returncode=0, stdout=diff),
        ),
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        run_pr_review(results, pr_number=1, repo="owner/repo", diff_base="main")

    post_review.assert_not_called()
    assert post_summary.call_args.args[1] == []


def test_pr_review_uses_report_repository_instead_of_current_directory(
    tmp_path, monkeypatch
):
    current_repo = tmp_path / "current"
    report_repo = tmp_path / "report"
    for repo_dir in (current_repo, report_repo):
        (repo_dir / ".git").mkdir(parents=True)
    monkeypatch.chdir(current_repo)

    report_diff = (
        "diff --git a/report.py b/report.py\n"
        "--- a/report.py\n+++ b/report.py\n"
        "@@ -0,0 +1 @@\n+changed\n"
    )
    current_diff = (
        "diff --git a/current.py b/current.py\n"
        "--- a/current.py\n+++ b/current.py\n"
        "@@ -0,0 +1 @@\n+changed\n"
    )

    def git_diff(*args, **kwargs):
        return Mock(
            returncode=0,
            stdout=report_diff if kwargs.get("cwd") == report_repo else current_diff,
        )

    results = {
        "project_root": str(report_repo),
        "quality": [
            {
                "file": str(report_repo / "report.py"),
                "line": 1,
                "rule_id": "SKY-Q301",
                "message": "Issue in report repository",
            }
        ],
    }
    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch("skylos.cicd.review.subprocess.run", side_effect=git_diff) as git_run,
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment"),
    ):
        run_pr_review(results, pr_number=1, repo="owner/repo", diff_base="main")

    assert [finding["file"] for finding in post_review.call_args.args[0]] == [
        str(report_repo / "report.py")
    ]
    assert all(call.kwargs.get("cwd") == report_repo for call in git_run.call_args_list)


def test_pr_review_prefers_scanned_repository_over_upload_project_root(
    tmp_path, monkeypatch
):
    report_repo = tmp_path / "report"
    (report_repo / ".git").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    results = {
        "project_root": ".",
        "analysis_summary": {"comparison_scope": {"repository_root": str(report_repo)}},
    }
    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch(
            "skylos.cicd.review.subprocess.run",
            return_value=Mock(returncode=0, stdout=""),
        ) as git_run,
        patch("skylos.cicd.review._post_pr_review"),
        patch("skylos.cicd.review._post_summary_comment"),
    ):
        run_pr_review(results, pr_number=1, repo="owner/repo", diff_base="main")

    assert all(call.kwargs.get("cwd") == report_repo for call in git_run.call_args_list)


def test_pr_review_invalid_report_root_does_not_post_comments(tmp_path):
    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._detect_regressions_from_diff") as regressions,
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        with pytest.raises(SystemExit) as exit_info:
            run_pr_review(
                {"project_root": str(tmp_path / "missing")},
                pr_number=1,
                repo="owner/repo",
                diff_base="main",
            )

    assert exit_info.value.code == 2
    regressions.assert_not_called()
    post_review.assert_not_called()
    post_summary.assert_not_called()


def test_pr_review_rejects_relative_report_root_in_another_repository(
    tmp_path, monkeypatch
):
    current_repo = tmp_path / "current"
    (current_repo / ".git").mkdir(parents=True)
    (current_repo / "package").mkdir()
    monkeypatch.chdir(current_repo)

    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._resolve_review_provenance", return_value=None),
        patch("skylos.cicd.review.build_risk_passport", return_value={}),
        patch("skylos.cicd.review.subprocess.run") as git_diff,
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        git_diff.return_value = Mock(returncode=0, stdout="")
        with pytest.raises(SystemExit) as exit_info:
            run_pr_review(
                {"project_root": "package"},
                pr_number=1,
                repo="owner/repo",
                diff_base="main",
            )

    assert exit_info.value.code == 2
    git_diff.assert_not_called()
    post_review.assert_not_called()
    post_summary.assert_not_called()


def test_pr_review_invalid_base_does_not_post_comments():
    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review._detect_regressions_from_diff", return_value=[]),
        patch("skylos.cicd.review.subprocess.run") as git_diff,
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        git_diff.return_value = Mock(returncode=128, stdout="", stderr="bad ref")
        with pytest.raises(SystemExit) as exit_info:
            run_pr_review({}, pr_number=1, repo="owner/repo", diff_base="missing")

    assert exit_info.value.code == 2
    post_review.assert_not_called()
    post_summary.assert_not_called()


def test_pr_review_summary_only_invalid_base_does_not_post_comments():
    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review.subprocess.run") as git_diff,
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        git_diff.return_value = Mock(returncode=128, stdout="", stderr="bad ref")
        with pytest.raises(SystemExit) as exit_info:
            run_pr_review(
                {},
                pr_number=1,
                repo="owner/repo",
                diff_base="missing",
                summary_only=True,
            )

    assert exit_info.value.code == 2
    post_review.assert_not_called()
    post_summary.assert_not_called()


def test_pr_review_failed_regression_diff_does_not_post_comments():
    def git_diff(command, **kwargs):
        return Mock(
            returncode=128 if "--unified=3" in command else 0,
            stdout="",
            stderr="bad ref",
        )

    with (
        patch("skylos.cicd.review._gh_available", return_value=True),
        patch("skylos.cicd.review.subprocess.run", side_effect=git_diff),
        patch("skylos.cicd.review._post_pr_review") as post_review,
        patch("skylos.cicd.review._post_summary_comment") as post_summary,
    ):
        with pytest.raises(SystemExit) as exit_info:
            run_pr_review({}, pr_number=1, repo="owner/repo", diff_base="missing")

    assert exit_info.value.code == 2
    post_review.assert_not_called()
    post_summary.assert_not_called()


def test_pr_review_carries_dead_code_reason_into_comment():
    finding = _flatten_findings(
        {
            "unused_functions": [
                {
                    "file": "a.py",
                    "line": 3,
                    "name": "old",
                    "confidence": 95,
                    "dead_code_reason": "No static references were found.",
                }
            ]
        }
    )[0]

    assert "No static references were found." in _format_review_comment(finding)
    card = _format_evidence_card_comment(finding)
    assert "No static references were found." in card
    assert "Confidence:** 95%" in card


def test_diff_range_lookup_uses_selected_project(tmp_path):
    with patch("skylos.cicd.review.subprocess.run") as git_diff:
        git_diff.return_value.returncode = 0
        git_diff.return_value.stdout = ""
        assert get_changed_line_ranges("HEAD", cwd=tmp_path, raise_on_error=True) == []

    assert git_diff.call_args.kwargs["cwd"] == tmp_path


def test_diff_range_lookup_rejects_invalid_base(tmp_path):
    with patch("skylos.cicd.review.subprocess.run") as git_diff:
        git_diff.return_value.returncode = 128
        git_diff.return_value.stderr = "fatal: unknown revision"
        with pytest.raises(ValueError, match="Cannot compare"):
            get_changed_line_ranges("missing", cwd=tmp_path, raise_on_error=True)


def test_diff_filter_does_not_confuse_same_basename_in_different_directories(
    tmp_path,
):
    finding = {"file": str(tmp_path / "src" / "foo.py"), "line": 1}
    root_file_change = [{"file": "foo.py", "start": 1, "end": 1}]
    nested_file_change = [{"file": "src/foo.py", "start": 1, "end": 1}]

    assert (
        filter_findings_to_diff([finding], root_file_change, project_root=tmp_path)
        == []
    )
    assert filter_findings_to_diff(
        [finding], nested_file_change, project_root=tmp_path
    ) == [finding]


def test_filter_findings_to_diff_matches_related_location_span():
    finding = {
        "file": "src/app.py",
        "line": 40,
        "message": "Cross-layer exposure",
        "related_locations": [
            {
                "file": "deploy/kubernetes.yaml",
                "start_line": 10,
                "end_line": 24,
            }
        ],
    }
    changed_ranges = [{"file": "deploy/kubernetes.yaml", "start": 18, "end": 18}]

    assert filter_findings_to_diff([finding], changed_ranges) == [finding]


def test_filter_findings_to_diff_matches_related_location_path_suffix():
    finding = {
        "file": "/workspace/src/app.py",
        "line": 40,
        "message": "Cross-layer exposure",
        "related_locations": [
            {
                "file": "/workspace/deploy/kubernetes.yaml",
                "start_line": 10,
                "end_line": 24,
            }
        ],
    }
    changed_ranges = [{"file": "deploy/kubernetes.yaml", "start": 24, "end": 30}]

    assert filter_findings_to_diff([finding], changed_ranges) == [finding]


def test_pr_comment_reanchors_to_changed_related_location():
    finding = {
        "file": "/workspace/deploy/rendered.yaml",
        "line": 8,
        "related_locations": [
            {
                "file": "/workspace/deploy/rendered.yaml",
                "start_line": 40,
                "end_line": 65,
            }
        ],
    }
    changed_ranges = [{"file": "deploy/rendered.yaml", "start": 57, "end": 58}]

    assert _review_comment_location(finding, changed_ranges) == (
        "/workspace/deploy/rendered.yaml",
        57,
    )


def test_filter_findings_to_diff_ignores_nonoverlapping_related_locations():
    finding = {
        "file": "src/app.py",
        "line": 40,
        "message": "Cross-layer exposure",
        "related_locations": [
            {
                "file": "deploy/kubernetes.yaml",
                "start_line": 10,
                "end_line": 24,
            },
            "not-a-location",
            {"file": "deploy/other.yaml", "start_line": 1, "end_line": 4},
        ],
    }
    changed_ranges = [{"file": "deploy/kubernetes.yaml", "start": 25, "end": 30}]

    assert filter_findings_to_diff([finding], changed_ranges) == []


def test_flatten_findings(sample_results):
    findings = _flatten_findings(sample_results)
    assert len(findings) == 3
    assert findings[0]["category"] == "danger"
    assert findings[2]["category"] == "quality"


def test_flatten_findings_preserves_related_locations():
    related_locations = [
        {"file": "deploy/kubernetes.yaml", "start_line": 10, "end_line": 24}
    ]
    findings = _flatten_findings(
        {
            "danger": [
                {
                    "file": "src/app.py",
                    "line": 40,
                    "message": "Cross-layer exposure",
                    "related_locations": related_locations,
                }
            ]
        }
    )

    assert findings[0]["related_locations"] == related_locations


def test_flatten_findings_preserves_safe_evidence_metadata():
    token = _stripe_like_token()
    findings = _flatten_findings(
        {
            "danger": [
                {
                    "rule_id": "SKY-L001",
                    "file": "app.py",
                    "line": 3,
                    "message": "Potential issue",
                    "metadata": {
                        "security_evidence": "hypothesis",
                        "review_reason": "needs runtime proof",
                        "raw_secret": token,
                    },
                    "verification": {
                        "verdict": "VERIFIED",
                        "raw_context": "not copied",
                    },
                }
            ]
        }
    )

    finding = findings[0]
    assert finding["_security_evidence"] == "hypothesis"
    assert finding["_review_reason"] == "needs runtime proof"
    assert finding["verification"] == {"verdict": "VERIFIED"}
    assert "raw_secret" not in finding["metadata"]
    assert "raw_context" not in finding["verification"]


@pytest.mark.parametrize(
    ("rule_id", "evidence_kind"),
    (
        ("SKY-D252", "cookie_security_options"),
        ("SKY-D280", "authorization_guard"),
        ("SKY-D281", "server_action_sql_taint"),
        ("SKY-D282", "webhook_signature_guard"),
    ),
)
def test_flatten_findings_keeps_incomplete_security_flow_out_of_proven(
    rule_id, evidence_kind
):
    findings = _flatten_findings(
        {
            "danger": [
                {
                    "rule_id": rule_id,
                    "file": "app/api/route.ts",
                    "line": 7,
                    "severity": "HIGH",
                    "message": "Security proof could not be completed",
                    "metadata": {
                        "security_evidence": {
                            "evidence_kind": evidence_kind,
                            "guards_seen": ["candidate guard"],
                            "guards_missing": ["route-local proof"],
                            "analysis_complete": False,
                            "analysis_diagnostics": ["work budget exhausted"],
                        }
                    },
                }
            ]
        }
    )

    packet = findings[0]["metadata"]["security_evidence"]
    card = build_evidence_card(findings[0])

    assert packet["analysis_complete"] is False
    assert findings[0]["_security_evidence"] == packet
    assert card.label == "likely"
    assert "analysis was incomplete" in "\n".join(card.evidence).lower()


def test_flatten_findings_bounds_and_sanitizes_security_evidence_packet():
    token = _stripe_like_token()
    findings = _flatten_findings(
        {
            "danger": [
                {
                    "rule_id": "SKY-D252",
                    "file": "src/session.ts",
                    "line": 4,
                    "metadata": {
                        "security_evidence": {
                            "evidence_kind": "cookie_security_options",
                            "source": f"cookie write {token}" + ("x" * 1_000),
                            "guards_seen": [
                                f"guard-{index}-{token}" for index in range(100)
                            ],
                            "guards_missing": ["httpOnly=true"],
                            "analysis_complete": False,
                            "analysis_diagnostics": ["work budget exhausted"],
                            "options": {
                                "httpOnly": {"state": "unknown"},
                                "secure": "true",
                                "attacker-controlled": token,
                            },
                            "untrusted_extension": {"raw_secret": token},
                        }
                    },
                }
            ]
        }
    )

    packet = findings[0]["metadata"]["security_evidence"]

    assert "untrusted_extension" not in packet
    assert "attacker-controlled" not in packet["options"]
    assert "httpOnly" not in packet["options"]
    assert len(packet["guards_seen"]) <= 12
    assert len(packet["source"]) <= 500
    assert token not in repr(packet)


def test_evidence_comment_redacts_provider_tokens_and_neutralizes_markdown():
    token = "glpat-" + "AbCdEfGhIjKlMnOpQrStUvWx"
    forged = "**forged proof** @maintainer [click](https://evil.invalid)"
    finding = _flatten_findings(
        {
            "danger": [
                {
                    "rule_id": "SKY-D281",
                    "severity": "CRITICAL",
                    "file": "app/actions.ts",
                    "line": 9,
                    "message": f"SQL proof {token}",
                    "metadata": {
                        "security_evidence": {
                            "evidence_kind": "server_action_sql_taint",
                            "source": f"proof {token}",
                            "sink": "interpolated SQL",
                            "path": ["dynamic value", "interpolated SQL"],
                            "guards_seen": [forged],
                            "guards_missing": ["parameterized SQL binding"],
                            "analysis_complete": False,
                        }
                    },
                }
            ]
        }
    )[0]

    comment = _format_evidence_card_comment(finding)

    assert token not in repr(finding)
    assert token not in comment
    assert "**forged proof**" not in comment
    assert "@maintainer" not in comment
    assert "[click](https://evil.invalid)" not in comment
    assert "forged proof" in comment
    assert "maintainer" in comment
    assert "click" in comment


def test_flatten_findings_preserves_ai_provenance_flags():
    findings = _flatten_findings(
        {
            "danger": [
                {
                    "rule_id": "SKY-D201",
                    "file": "app.py",
                    "line": 3,
                    "message": "eval",
                    "ai_authored": True,
                    "ai_agent": "codex",
                }
            ]
        }
    )

    assert findings[0]["ai_authored"] is True
    assert findings[0]["ai_agent"] == "codex"


def test_merge_llm_hypothesis_does_not_downgrade_static_finding_source():
    static_findings = [
        {
            "category": "danger",
            "rule_id": "SKY-D201",
            "severity": "HIGH",
            "message": "eval() usage",
            "file": "app.py",
            "line": 3,
        }
    ]
    llm_findings = [
        {
            "rule_id": "SKY-D201",
            "file": "app.py",
            "line": 3,
            "_source": "llm",
            "_security_evidence": "hypothesis",
            "explanation": "possible issue",
        }
    ]

    merged = _merge_llm_findings(static_findings, llm_findings)
    card = build_evidence_card(merged[0])

    assert merged[0].get("_source") != "llm"
    assert card.label == "proven"


def test_llm_match_cannot_overwrite_analyzer_owned_incomplete_security_evidence():
    static_finding = _flatten_findings(
        {
            "danger": [
                {
                    "rule_id": "SKY-D280",
                    "severity": "HIGH",
                    "file": "app/api/route.ts",
                    "line": 7,
                    "message": "Security proof could not be completed",
                    "metadata": {
                        "security_evidence": {
                            "evidence_kind": "authorization_guard",
                            "guards_seen": ["candidate authentication call"],
                            "guards_missing": ["route-local proof"],
                            "analysis_complete": False,
                            "analysis_diagnostics": ["work budget exhausted"],
                        }
                    },
                }
            ]
        }
    )[0]
    llm_finding = {
        "rule_id": "SKY-D280",
        "file": "app/api/route.ts",
        "line": 7,
        "metadata": {
            "security_evidence": {
                "evidence_kind": "authorization_guard",
                "source": "route entry",
                "sink": "database mutation",
                "path": ["route entry", "database mutation"],
                "guards_missing": [
                    "route-local rejecting authentication guard before mutation"
                ],
                "analysis_complete": True,
            }
        },
    }

    merged = _merge_llm_findings([static_finding], [llm_finding])[0]
    packet = merged["metadata"]["security_evidence"]
    card = build_evidence_card(merged)

    assert packet["analysis_complete"] is False
    assert packet["analysis_diagnostics"] == ["work budget exhausted"]
    assert card.label == "likely"


def test_llm_merge_requires_full_path_line_and_rule_identity():
    static_finding = {
        "category": "danger",
        "rule_id": "SKY-D201",
        "severity": "HIGH",
        "message": "eval() usage",
        "file": "src/app.py",
        "line": 4,
    }
    unrelated_llm_finding = {
        "rule_id": "SKY-D201",
        "file": "other/app.py",
        "line": 4,
        "explanation": "This belongs to a different file.",
    }

    merged = _merge_llm_findings([static_finding], [unrelated_llm_finding])

    assert len(merged) == 2
    assert "explanation" not in merged[0]
    assert merged[1]["_source"] == "llm"


def test_llm_merge_cannot_overwrite_analyzer_or_verifier_owned_fields():
    static_finding = {
        "category": "danger",
        "rule_id": "SKY-L999",
        "severity": "HIGH",
        "message": "Candidate finding",
        "file": "src/app.py",
        "line": 4,
        "verification": {"verdict": "REFUTED", "reason": "trusted verifier"},
        "_review_verdict": "REFUTED",
        "_review_reason": "trusted review",
        "_security_evidence": "hypothesis",
        "metadata": {
            "review_verdict": "REFUTED",
            "review_reason": "trusted review",
            "security_evidence": "hypothesis",
        },
    }
    llm_finding = {
        "rule_id": "SKY-L999",
        "file": "src/app.py",
        "line": 4,
        "explanation": "Useful non-authoritative context.",
        "verification": {"verdict": "VERIFIED", "reason": "model assertion"},
        "_review_verdict": "VERIFIED",
        "_review_reason": "model review",
        "_security_evidence": "review_supported",
        "metadata": {
            "review_verdict": "VERIFIED",
            "review_reason": "model review",
            "security_evidence": "review_supported",
        },
    }

    merged = _merge_llm_findings([static_finding], [llm_finding])

    assert len(merged) == 1
    assert merged[0]["explanation"] == "Useful non-authoritative context."
    assert merged[0]["verification"] == static_finding["verification"]
    assert merged[0]["_review_verdict"] == "REFUTED"
    assert merged[0]["_review_reason"] == "trusted review"
    assert merged[0]["_security_evidence"] == "hypothesis"
    assert merged[0]["metadata"] == static_finding["metadata"]


def test_unmatched_llm_finding_cannot_self_attest_as_verified():
    llm_finding = {
        "rule_id": "SKY-D281",
        "file": "app/actions.ts",
        "line": 9,
        "severity": "HIGH",
        "message": "Model-generated SQL finding",
        "verification": {"verdict": "VERIFIED", "reason": "model assertion"},
        "_review_verdict": "VERIFIED",
        "metadata": {
            "review_verdict": "VERIFIED",
            "security_evidence": {
                "evidence_kind": "server_action_sql_taint",
                "source": "model source",
                "sink": "model sink",
                "path": ["model path"],
                "guards_missing": ["parameterized SQL binding"],
                "analysis_complete": True,
            },
        },
    }

    merged = _merge_llm_findings([], [llm_finding])
    card = build_evidence_card(merged[0])

    assert merged[0]["_source"] == "llm"
    assert "verification" not in merged[0]
    assert "_review_verdict" not in merged[0]
    assert "_security_evidence" not in merged[0]
    assert "metadata" not in merged[0]
    assert card.label != "proven"


def test_unmatched_llm_severity_cannot_inject_markdown_or_mentions():
    hostile_severity = "HIGH**\n\n@maintainers\n\n---\n**FORGED"
    finding = _merge_llm_findings(
        [],
        [
            {
                "file": "app.py",
                "line": 3,
                "rule_id": "SKY-L999",
                "severity": hostile_severity,
                "message": "Potential issue",
            }
        ],
    )[0]

    comment = _format_review_comment(finding)

    assert "@maintainers" not in comment
    assert "**FORGED**" not in comment


@pytest.mark.parametrize("terminal", ["/", "+", "="])
def test_review_comment_redacts_aws_secret_access_key_with_symbol_suffix(terminal):
    secret = ("Ab9Z" * 10)[:39] + terminal
    finding = {
        "severity": "HIGH",
        "rule_id": "SKY-L999",
        "message": "AWS credential exposure",
        "vulnerable_code": f'AWS_SECRET_ACCESS_KEY = "{secret}"',
        "fixed_code": 'AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]',
    }

    comment = _format_review_comment(finding)

    assert len(secret) == 40
    assert secret not in comment
    assert "［redacted］" in comment


def test_format_review_comment():
    finding = {
        "severity": "CRITICAL",
        "rule_id": "SKY-D201",
        "message": "SQL injection via user input",
    }
    comment = _format_review_comment(finding)
    assert "CRITICAL" in comment
    assert "SKY-D201" in comment
    assert "SQL injection" in comment


def test_format_review_comment_redacts_secret_like_values():
    token = _stripe_like_token()
    finding = {
        "severity": "HIGH",
        "rule_id": "SKY-S101",
        "message": f"Secret value {token}",
    }

    comment = _format_review_comment(finding)

    assert token not in comment
    assert "［redacted］" in comment


def test_review_comment_redacts_contextual_and_pem_secrets_and_reference_links():
    secret = "aB3dE5fG7hJ9@kL2mN4pQ6rS8!tU0v"
    pem_body = "MIIEvQsensitivebase64materialmustnotescape1234567890"
    finding = {
        "severity": "HIGH",
        "rule_id": "SKY-S101",
        "message": (
            f"API_SECRET={secret} [click][ref]\n    [ref]: https://evil.invalid"
        ),
        "vulnerable_code": (
            "API_SECRET=aB3dE5fG7hJ9\n"
            "kL2mN4pQ6rS8!tU0v\n"
            "WEBHOOK_SECRET: |\n"
            "  zC4fH6jK8mP1\n"
            "  qR3tV5xY7!bN9@dF2\n"
            "-----BEGIN PRIVATE KEY-----\n"
            f"{pem_body}\n"
            "-----END PRIVATE KEY-----"
        ),
        "fixed_code": "API_SECRET = os.environ['API_SECRET']",
    }

    comment = _format_review_comment(finding)

    assert secret not in comment
    assert "aB3dE5fG7hJ9" not in comment
    assert "kL2mN4pQ6rS8!tU0v" not in comment
    assert "zC4fH6jK8mP1" not in comment
    assert "qR3tV5xY7!bN9@dF2" not in comment
    assert pem_body not in comment
    assert "END PRIVATE KEY" not in comment
    assert "][ref]" not in comment
    assert "[ref]:" not in comment
    assert "https://evil.invalid" not in comment


def test_format_evidence_card_comment():
    finding = {
        "category": "danger",
        "severity": "HIGH",
        "rule_id": "SKY-D211",
        "message": "SQL built from user input",
        "file": "app.py",
        "line": 9,
    }

    comment = _format_evidence_card_comment(finding)

    assert "Risk: Proven security finding" in comment
    assert "SKY-D211" in comment
    assert "Evidence:" in comment
    assert "Impact:" in comment
    assert "Suggested fix:" in comment
    assert "Confidence:" in comment


def test_format_evidence_card_comment_includes_fallback_suggested_fix():
    finding = {
        "category": "quality",
        "severity": "MEDIUM",
        "rule_id": "SKY-Q999",
        "message": "Generic maintainability issue",
        "file": "app.py",
        "line": 5,
    }

    comment = _format_evidence_card_comment(finding)

    assert "Risk: Likely quality issue" in comment
    assert "Suggested fix:" in comment
    assert "Refactor the affected code" in comment


def test_format_evidence_card_comment_supports_reliability():
    finding = {
        "category": "reliability",
        "severity": "MEDIUM",
        "rule_id": "SKY-DEP003",
        "message": "External Ingress reaches reload mode.",
        "file": "deploy.yaml",
        "line": 4,
    }

    comment = _format_evidence_card_comment(finding)

    assert "Risk: Likely reliability issue" in comment
    assert "SKY-DEP003" in comment


def test_summary_comment_omits_evidence_counts_by_default():
    captured = {}

    def mock_run(cmd, **kwargs):
        if "pr" in cmd and "comment" in cmd:
            captured["body"] = cmd[cmd.index("--body") + 1]

        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeResult()

    finding = {
        "category": "danger",
        "severity": "HIGH",
        "rule_id": "SKY-D201",
        "message": "eval() usage",
        "file": "app.py",
        "line": 4,
    }

    with patch("skylos.cicd.review.subprocess.run", side_effect=mock_run):
        _post_summary_comment([finding], [finding], 42, "owner/repo")

    assert "### Evidence" not in captured["body"]


def test_summary_comment_lists_reliability_category():
    captured = {}

    def mock_run(cmd, **kwargs):
        if "pr" in cmd and "comment" in cmd:
            captured["body"] = cmd[cmd.index("--body") + 1]

        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeResult()

    finding = {
        "category": "reliability",
        "severity": "MEDIUM",
        "rule_id": "SKY-DEP003",
        "message": "External Ingress reaches reload mode.",
        "file": "deploy.yaml",
        "line": 4,
    }

    with patch("skylos.cicd.review.subprocess.run", side_effect=mock_run):
        _post_summary_comment([finding], [finding], 42, "owner/repo")

    assert "| reliability | 1 |" in captured["body"]


def test_summary_comment_counts_changed_dead_code_once():
    finding = {
        "category": "dead_code",
        "severity": "LOW",
        "rule_id": "SKY-U001",
        "message": "Unused function: unused",
        "file": "a.py",
        "line": 1,
    }

    with patch("skylos.cicd.review.subprocess.run") as gh:
        _post_summary_comment([finding], [finding], 42, "owner/repo")

    command = gh.call_args.args[0]
    body = command[command.index("--body") + 1]
    assert "**1** issue(s) on changed lines | **1** total" in body
    assert "| dead_code | 1 |" in body


def test_summary_comment_includes_evidence_counts_when_enabled():
    captured = {}

    def mock_run(cmd, **kwargs):
        if "pr" in cmd and "comment" in cmd:
            captured["body"] = cmd[cmd.index("--body") + 1]

        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeResult()

    findings = [
        {
            "category": "danger",
            "severity": "HIGH",
            "rule_id": "SKY-D201",
            "message": "eval() usage",
            "file": "app.py",
            "line": 4,
        },
        {
            "category": "security",
            "severity": "HIGH",
            "_source": "llm",
            "_security_evidence": "hypothesis",
            "message": "Possible auth issue",
            "file": "views.py",
            "line": 8,
        },
    ]

    with patch("skylos.cicd.review.subprocess.run", side_effect=mock_run):
        _post_summary_comment(
            findings,
            findings,
            42,
            "owner/repo",
            evidence_cards=True,
        )

    body = captured["body"]
    assert "### Evidence" in body
    assert "| Proven | 1 |" in body
    assert "| Speculative | 1 |" in body


def test_summary_comment_includes_risk_passport_when_supplied():
    captured = {}

    def mock_run(cmd, **kwargs):
        if "pr" in cmd and "comment" in cmd:
            captured["body"] = cmd[cmd.index("--body") + 1]

        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeResult()

    risk_passport = {
        "recommendation": "BLOCK",
        "ai_authored_files": 2,
        "ai_agents": ["codex"],
        "provenance_confidence": "high",
        "changed_line_evidence": {"proven": 1, "likely": 0, "speculative": 0},
        "high_risk_ai_files": ["app.py"],
        "security_controls_weakened": ["auth"],
        "missing_llm_guardrails": [],
        "reasons": ["Changed-line security regression: auth"],
        "warnings": [],
    }

    with patch("skylos.cicd.review.subprocess.run", side_effect=mock_run):
        _post_summary_comment(
            [],
            [],
            42,
            "owner/repo",
            risk_passport=risk_passport,
        )

    body = captured["body"]
    assert "### AI PR Risk Passport" in body
    assert "**Merge recommendation: BLOCK**" in body
    assert "| Security controls weakened | auth |" in body


def test_summary_risk_passport_neutralizes_hostile_reference_images():
    captured = {}

    def mock_run(cmd, **kwargs):
        if "pr" in cmd and "comment" in cmd:
            captured["body"] = cmd[cmd.index("--body") + 1]

        class FakeResult:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeResult()

    long_label = "tracking-" + ("x" * 160)
    hostile_reason = (
        "![escaped\\] label][pixel]\n"
        "- ![tracking][pixel]\n"
        "    [pixel]: https://evil.invalid/pixel.png\n"
        f"![long][{long_label}]\n"
        f"[{long_label}]: https://evil.invalid/long.png"
    )
    risk_passport = {
        "recommendation": "BLOCK",
        "changed_line_evidence": {},
        "reasons": [hostile_reason],
    }

    with patch("skylos.cicd.review.subprocess.run", side_effect=mock_run):
        _post_summary_comment(
            [],
            [],
            42,
            "owner/repo",
            risk_passport=risk_passport,
        )

    body = captured["body"]
    assert "![escaped" not in body
    assert "![tracking]" not in body
    assert f"[{long_label}]" not in body
    assert "https://evil.invalid" not in body


def test_detect_pr_number(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")
    assert _detect_pr_number() == 42


def test_detect_pr_number_not_pr(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    assert _detect_pr_number() is None


def test_detect_pr_number_no_env(monkeypatch):
    monkeypatch.delenv("GITHUB_REF", raising=False)
    assert _detect_pr_number() is None
