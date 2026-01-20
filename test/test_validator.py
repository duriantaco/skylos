import pytest

from skylos.llm.validator import (
    CodeValidator,
    ResultValidator,
    deduplicate_findings,
    merge_findings,
    _infer_issue_type,
    _parse_severity,
)

from skylos.llm.schemas import Finding, Severity, Confidence, IssueType, CodeLocation


def mk_finding(
    file="file.py",
    line=1,
    msg="Issue detected",
    rule="SKY-L001",
    issue_type=IssueType.SECURITY,
    severity=Severity.MEDIUM,
    confidence=Confidence.MEDIUM,
    explanation=None,
    suggestion=None,
):
    return Finding(
        rule_id=rule,
        issue_type=issue_type,
        severity=severity,
        confidence=confidence,
        message=msg,
        location=CodeLocation(file=file, line=line),
        explanation=explanation,
        suggestion=suggestion,
    )


def test_validator_adjusts_out_of_range_line_non_strict():
    src = "a = 1\nb = 2\nc = 3\n"
    v = CodeValidator(strict=False)

    f = mk_finding(line=999, issue_type=IssueType.QUALITY, msg="Some quality issue")
    result = v.validate(f, src, "file.py")

    assert result.valid is True
    assert result.adjusted_finding is not None
    assert result.adjusted_finding.location.line == 3
    assert result.adjusted_finding.confidence == Confidence.LOW
    assert "line_adjusted" in (result.adjusted_finding.explanation or "")


def test_validator_rejects_out_of_range_line_strict():
    src = "a = 1\nb = 2\n"
    v = CodeValidator(strict=True)

    f = mk_finding(line=999, issue_type=IssueType.QUALITY, msg="Some quality issue")
    result = v.validate(f, src, "file.py")

    assert result.valid is False
    assert result.adjusted_finding is None
    assert "out of range" in result.reason.lower()


def test_validator_dead_code_low_relevance_non_strict():
    src = "print('hi')\nprint('bye')\n"
    v = CodeValidator(strict=False)

    f = mk_finding(line=1, issue_type=IssueType.DEAD_CODE, msg="Unused function: foo")
    result = v.validate(f, src, "file.py")

    assert result.valid is True
    assert result.adjusted_finding is not None

    assert result.adjusted_finding.confidence == Confidence.UNCERTAIN

    expl = result.adjusted_finding.explanation or ""
    assert "low_relevance" in expl
    assert "symbol_not_found:foo" in expl


def test_validator_dead_code_low_relevance_strict_rejects():
    src = "print('hi')\n"
    v = CodeValidator(strict=True)

    f = mk_finding(line=1, issue_type=IssueType.DEAD_CODE, msg="Unused function: foo")
    result = v.validate(f, src, "file.py")

    assert result.valid is False
    assert result.adjusted_finding is None
    assert "not relevant" in result.reason.lower()


def test_validator_symbol_not_found_sets_uncertain_non_strict():
    src = "import json\nprint('hello')\n"
    v = CodeValidator(strict=False)

    f = mk_finding(
        line=1,
        issue_type=IssueType.DEAD_CODE,
        msg="Unused import: pickle",
        confidence=Confidence.MEDIUM,
    )
    result = v.validate(f, src, "file.py")

    assert result.valid is True
    assert result.adjusted_finding is not None
    assert result.adjusted_finding.confidence == Confidence.UNCERTAIN
    assert "symbol_not_found:pickle" in (result.adjusted_finding.explanation or "")


def test_validator_symbol_not_found_strict_rejects():
    src = "import json\n"
    v = CodeValidator(strict=True)

    f = mk_finding(
        line=1,
        issue_type=IssueType.DEAD_CODE,
        msg="Unused import: pickle",
    )
    result = v.validate(f, src, "file.py")

    assert result.valid is False
    assert result.adjusted_finding is None
    assert "symbol" in result.reason.lower()


def test_validator_security_pattern_unverified_lowers_confidence():
    src = "print('safe')\nprint('safe2')\nprint('safe3')\n"
    v = CodeValidator(strict=False)

    f = mk_finding(
        line=2,
        issue_type=IssueType.SECURITY,
        msg="Possible SQL injection via string formatting",
        confidence=Confidence.MEDIUM,
    )
    result = v.validate(f, src, "file.py")

    assert result.valid is True
    assert result.adjusted_finding is not None
    assert result.adjusted_finding.confidence == Confidence.LOW
    assert "pattern_not_verified" in (result.adjusted_finding.explanation or "")


def test_result_validator_filters_by_min_confidence():
    src = "import json\nprint('hello')\n"
    rv = ResultValidator(strict=False, min_confidence=Confidence.MEDIUM)

    bad = mk_finding(
        line=1,
        issue_type=IssueType.DEAD_CODE,
        msg="Unused import: pickle",
        confidence=Confidence.MEDIUM,
    )

    ok = mk_finding(
        line=1,
        issue_type=IssueType.SECURITY,
        msg="Use of eval() is dangerous",
        confidence=Confidence.MEDIUM,
    )

    validated, stats = rv.validate([bad, ok], src, "file.py")

    assert len(validated) == 1
    assert validated[0].message == ok.message

    assert stats["original"] == 2
    assert stats["accepted"] == 1
    assert stats["rejected"] == 1


def test_deduplicate_findings_removes_nearby_duplicates():
    f1 = mk_finding(file="a.py", line=10, msg="Same issue")
    f2 = mk_finding(file="a.py", line=11, msg="Same issue")
    f3 = mk_finding(file="a.py", line=20, msg="Same issue")

    out = deduplicate_findings([f1, f2, f3])
    assert len(out) == 2
    assert [x.location.line for x in out] == [10, 20]


def test_merge_findings_corroborates_llm_with_static_upgrades_confidence():
    llm = [
        mk_finding(
            file="file.py",
            line=50,
            msg="Possible SQL injection",
            issue_type=IssueType.SECURITY,
            confidence=Confidence.MEDIUM,
            explanation="LLM spotted risky SQL.",
        )
    ]
    static = [
        {
            "file": "file.py",
            "line": 52,
            "message": "Possible SQL injection: tainted query",
            "rule_id": "SKY-D211",
        }
    ]

    merged = merge_findings(llm, static, "file.py")

    assert len(merged) == 1
    assert merged[0].confidence == Confidence.HIGH
    assert "Corroborated by static analysis" in (merged[0].explanation or "")


def test_merge_findings_adds_static_only_when_not_near_any_llm():
    llm = [
        mk_finding(
            file="file.py", line=10, msg="Use of eval()", issue_type=IssueType.SECURITY
        )
    ]
    static = [
        {
            "file": "file.py",
            "line": 100,
            "message": "Unused import: pickle",
            "rule_id": "SKY-L010",
            "severity": "medium",
        }
    ]

    merged = merge_findings(llm, static, "file.py")

    assert len(merged) == 2

    added = [x for x in merged if x.location.line == 100][0]
    assert added.explanation == "[From static analysis only]"
    assert added.confidence == Confidence.MEDIUM
    assert added.issue_type in (
        IssueType.DEAD_CODE,
        IssueType.QUALITY,
        IssueType.SECURITY,
    )


@pytest.mark.parametrize(
    "static_dict, expected",
    [
        (
            {"message": "Possible SQL injection", "rule_id": "SKY-D211"},
            IssueType.SECURITY,
        ),
        ({"message": "Unused import: pickle"}, IssueType.DEAD_CODE),
        ({"message": "Function is complex (McCabe=12)"}, IssueType.QUALITY),
    ],
)
def test_infer_issue_type(static_dict, expected):
    assert _infer_issue_type(static_dict) == expected


@pytest.mark.parametrize(
    "sev, expected",
    [
        ("critical", Severity.CRITICAL),
        ("blocker", Severity.CRITICAL),
        ("high", Severity.HIGH),
        ("error", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("warning", Severity.MEDIUM),
        ("low", Severity.LOW),
        ("whatever", Severity.LOW),
    ],
)
def test_parse_severity(sev, expected):
    assert _parse_severity(sev) == expected
