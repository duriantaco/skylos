import pytest

from skylos.llm.merger import (
    normalize_message,
    similar,
    findings_match,
    deduplicate_input_findings,
    merge_findings,
    deduplicate_merged_findings,
    classify_confidence,
)


def _f(file, line, message, rule_id="SKY-L001", cat="security", extra=None):
    d = {
        "file": str(file),
        "line": line,
        "message": message,
        "rule_id": rule_id,
        "_category": cat,
    }
    if extra:
        d.update(extra)
    return d


def test_normalize_message_removes_line_numbers_and_colons():
    msg = "Use of eval() at Line 123: dangerous at app.py:55"
    out = normalize_message(msg)
    assert "line" not in out
    assert ":55" not in out
    assert "use of eval()" in out


def test_similar_threshold_basic():
    a = normalize_message("Possible SQL injection: tainted input")
    b = normalize_message("Possible SQL injection tainted input")
    assert similar(a, b, threshold=0.5) is True


def test_findings_match_requires_same_file(tmp_path):
    f1 = _f(tmp_path / "a.py", 10, "Issue A")
    f2 = _f(tmp_path / "b.py", 10, "Issue A")
    assert findings_match(f1, f2) is False


def test_findings_match_line_tolerance(tmp_path):
    f1 = _f(tmp_path / "a.py", 10, "SQL injection risk")
    f2 = _f(tmp_path / "a.py", 14, "SQL injection risk")
    assert findings_match(f1, f2, line_tolerance=5) is True
    assert findings_match(f1, f2, line_tolerance=2) is False


def test_findings_match_category_exact_match(tmp_path):
    f1 = _f(tmp_path / "a.py", 10, "msg one", cat="security")
    f2 = _f(tmp_path / "a.py", 12, "msg two totally different", cat="security")
    assert findings_match(f1, f2) is True


def test_findings_match_message_similarity_match(tmp_path):
    f1 = _f(
        tmp_path / "a.py",
        20,
        "Possible SQL injection: tainted or string-built query",
        cat="security",
    )
    f2 = _f(
        tmp_path / "a.py",
        22,
        "Possible SQL injection tainted string built query",
        cat="bug",
    )
    assert findings_match(f1, f2) is True


def test_findings_match_rule_prefix_match(tmp_path):
    f1 = _f(tmp_path / "a.py", 30, "Something", rule_id="SKY-L001", cat="security")
    f2 = _f(
        tmp_path / "a.py", 31, "Completely different", rule_id="SKY-L009", cat="quality"
    )
    assert findings_match(f1, f2) is True


def test_deduplicate_input_findings_removes_nearby_duplicates(tmp_path):
    file = tmp_path / "a.py"

    findings = [
        _f(file, 10, "Unused import: pickle"),
        _f(file, 11, "Unused import: pickle"),
        _f(file, 20, "Unused import: pickle"),
    ]

    out = deduplicate_input_findings(findings)
    assert len(out) == 2
    assert sorted([f["line"] for f in out]) == [10, 20]


def test_merge_findings_static_llm_match_becomes_high(tmp_path):
    file = tmp_path / "a.py"

    static_findings = [
        _f(
            file,
            50,
            "Possible SQL injection: tainted input",
            rule_id="SKY-L001",
            cat="security",
        ),
    ]
    llm_findings = [
        _f(
            file,
            52,
            "SQL injection vulnerability due to string formatting",
            rule_id="SKY-L003",
            cat="security",
            extra={"suggestion": "Use parameterized queries"},
        ),
    ]

    merged = merge_findings(static_findings, llm_findings)
    assert len(merged) == 1
    m = merged[0]

    assert m["_source"] == "static+llm"
    assert m["_confidence"] == "high"
    assert "suggestion" not in m
    assert m["_llm_suggestion"] == "Use parameterized queries"


def test_merge_findings_static_only_medium(tmp_path):
    file = tmp_path / "a.py"

    static_findings = [
        _f(file, 10, "Unused import: pickle", rule_id="SKY-L010", cat="dead_code")
    ]
    llm_findings = []

    merged = merge_findings(static_findings, llm_findings)
    assert len(merged) == 1
    assert merged[0]["_source"] == "static"
    assert merged[0]["_confidence"] == "medium"


def test_merge_findings_llm_only_flagged_needs_review(tmp_path):
    file = tmp_path / "a.py"

    static_findings = []
    llm_findings = [
        _f(file, 99, "Insecure use of eval()", rule_id="SKY-L001", cat="security")
    ]

    merged = merge_findings(static_findings, llm_findings)
    assert len(merged) == 1
    assert merged[0]["_source"] == "llm"
    assert merged[0]["_confidence"] == "medium"
    assert merged[0].get("_needs_review") is True


def test_deduplicate_merged_findings_prefers_high_and_static_plus_llm(tmp_path):
    file = tmp_path / "a.py"

    findings = [
        {
            **_f(file, 10, "Unused import: pickle"),
            "_source": "static",
            "_confidence": "medium",
        },
        {
            **_f(file, 11, "Unused import: pickle"),
            "_source": "llm",
            "_confidence": "medium",
        },
        {
            **_f(file, 12, "Unused import: pickle"),
            "_source": "static+llm",
            "_confidence": "high",
        },
    ]

    out = deduplicate_merged_findings(findings)
    assert len(out) == 1
    assert out[0]["_confidence"] == "high"
    assert out[0]["_source"] == "static+llm"


@pytest.mark.parametrize(
    "finding, expected",
    [
        ({"_confidence": "high", "_source": "static+llm"}, "HIGH (both)"),
        ({"_confidence": "medium", "_source": "static"}, "MED (static)"),
        ({"_confidence": "medium", "_source": "llm"}, "MED (LLM)"),
        ({}, "MED"),
    ],
)
def test_classify_confidence_outputs_expected_label(finding, expected):
    assert classify_confidence(finding) == expected
