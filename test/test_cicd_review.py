import pytest

from skylos.cicd.review import (
    _parse_unified_diff,
    filter_findings_to_diff,
    _flatten_findings,
    _format_review_comment,
    _detect_pr_number,
)


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

    # app.py: +11,3 means lines 11-13
    assert ranges[0]["file"] == "app.py"
    assert ranges[0]["start"] == 11
    assert ranges[0]["end"] == 13

    # utils.py: +5 (single line change)
    assert ranges[1]["file"] == "utils.py"
    assert ranges[1]["start"] == 5
    assert ranges[1]["end"] == 5


def test_filter_findings_to_diff(sample_results):
    ranges = _parse_unified_diff(SAMPLE_DIFF)
    findings = _flatten_findings(sample_results)
    filtered = filter_findings_to_diff(findings, ranges)

    # app.py line 12 is in range 11-13, utils.py line 5 is in range 5-5
    assert len(filtered) == 2
    files = {f["file"] for f in filtered}
    assert "app.py" in files
    assert "utils.py" in files
    # other.py line 50 is NOT in any changed range
    assert "other.py" not in files


def test_filter_findings_empty_ranges():
    findings = [{"file": "a.py", "line": 1, "message": "test"}]
    assert filter_findings_to_diff(findings, []) == []


def test_flatten_findings(sample_results):
    findings = _flatten_findings(sample_results)
    assert len(findings) == 3
    assert findings[0]["category"] == "danger"
    assert findings[2]["category"] == "quality"


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


def test_detect_pr_number(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/pull/42/merge")
    assert _detect_pr_number() == 42


def test_detect_pr_number_not_pr(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    assert _detect_pr_number() is None


def test_detect_pr_number_no_env(monkeypatch):
    monkeypatch.delenv("GITHUB_REF", raising=False)
    assert _detect_pr_number() is None
