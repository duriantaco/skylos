from unittest.mock import patch

import pytest

from skylos.cicd.review import (
    _parse_unified_diff,
    filter_findings_to_diff,
    _flatten_findings,
    _merge_llm_findings,
    _format_review_comment,
    _format_evidence_card_comment,
    _post_summary_comment,
    _detect_pr_number,
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


def test_flatten_findings(sample_results):
    findings = _flatten_findings(sample_results)
    assert len(findings) == 3
    assert findings[0]["category"] == "danger"
    assert findings[2]["category"] == "quality"


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
    assert "[redacted]" in comment


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


def test_detect_pr_number(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")
    assert _detect_pr_number() == 42


def test_detect_pr_number_not_pr(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    assert _detect_pr_number() is None


def test_detect_pr_number_no_env(monkeypatch):
    monkeypatch.delenv("GITHUB_REF", raising=False)
    assert _detect_pr_number() is None
