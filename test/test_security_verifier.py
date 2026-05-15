import logging
from unittest.mock import patch

import skylos.api as api
from skylos.cli import review_security_scan_result
from skylos.llm.security_verifier import ID_KEY, REVIEW_MODE, SecurityVerifier
from skylos.llm.schemas import (
    AnalysisResult,
    CodeLocation,
    Confidence,
    Finding,
    IssueType,
    Severity,
)


def _security_finding(*, line=3, severity=Severity.HIGH):
    return Finding(
        rule_id="SKY-L001",
        issue_type=IssueType.SECURITY,
        severity=severity,
        message="Possible SQL injection",
        location=CodeLocation(file="app.py", line=line),
        confidence=Confidence.HIGH,
    )


def _security_verifier():
    return SecurityVerifier.__new__(SecurityVerifier)


def _let_caplog_capture_skylos_logs(monkeypatch):
    monkeypatch.setattr(logging.getLogger("skylos"), "propagate", True)


def test_parse_reviews_logs_invalid_json(caplog, monkeypatch):
    _let_caplog_capture_skylos_logs(monkeypatch)
    verifier = _security_verifier()

    with caplog.at_level(logging.WARNING, logger="skylos.llm.security_verifier"):
        reviews = verifier._parse_reviews("not json")

    assert reviews is None
    assert "invalid JSON" in caplog.text


def test_parse_reviews_logs_missing_reviews_list(caplog, monkeypatch):
    _let_caplog_capture_skylos_logs(monkeypatch)
    verifier = _security_verifier()

    with caplog.at_level(logging.WARNING, logger="skylos.llm.security_verifier"):
        reviews = verifier._parse_reviews('{"reviews": {"id": 1}}')

    assert reviews is None
    assert "missing 'reviews' list" in caplog.text


def test_parse_reviews_accepts_reviews_list():
    verifier = _security_verifier()

    reviews = verifier._parse_reviews(
        '{"reviews": [{"id": 1, "verdict": "SUPPORTED", "reason": "ok"}]}'
    )

    assert reviews == [{ID_KEY: 1, "verdict": "SUPPORTED", "reason": "ok"}]


def test_request_review_logs_adapter_failure(caplog, monkeypatch):
    _let_caplog_capture_skylos_logs(monkeypatch)

    class BrokenVerifier(SecurityVerifier):
        def get_adapter(self):
            raise RuntimeError("provider down")

    verifier = BrokenVerifier(
        model="gpt-4.1",
        api_key="k",
    )

    with caplog.at_level(logging.WARNING, logger="skylos.llm.security_verifier"):
        response = verifier._request_review("review this", mode=REVIEW_MODE)

    assert response is None
    assert "request failed" in caplog.text


def test_review_security_scan_result_marks_findings_review_only():
    finding = _security_finding()
    result = AnalysisResult(findings=[finding], files_analyzed=1)

    with patch(
        "skylos.llm.security_verifier.SecurityVerifier.review_findings",
        return_value={
            "supported": 0,
            "refuted": 0,
            "undecided": 1,
            "refuted_findings": [],
        },
    ):
        out = review_security_scan_result(
            model="gpt-4.1",
            api_key="k",
            provider=None,
            base_url=None,
            result=result,
        )

    metadata = out.findings[0].metadata
    assert metadata["security_evidence"] == "hypothesis"
    assert metadata["needs_review"] is True
    assert metadata["ci_blocking"] is False
    assert out.has_blockers() is False


def test_review_security_scan_result_filters_refuted_findings():
    finding = _security_finding()
    result = AnalysisResult(findings=[finding], files_analyzed=1)

    with patch(
        "skylos.llm.security_verifier.SecurityVerifier.review_findings",
        return_value={
            "supported": 0,
            "refuted": 1,
            "undecided": 0,
            "refuted_findings": [finding],
        },
    ):
        out = review_security_scan_result(
            model="gpt-4.1",
            api_key="k",
            provider=None,
            base_url=None,
            result=result,
        )

    assert out.findings == []


def test_supported_review_only_findings_stay_non_blocking():
    finding = _security_finding()
    result = AnalysisResult(findings=[finding], files_analyzed=1)

    def _supported(_findings):
        _findings[0].metadata["security_evidence"] = "review_supported"
        _findings[0].metadata["review_verdict"] = "SUPPORTED"
        return {
            "supported": 1,
            "refuted": 0,
            "undecided": 0,
            "refuted_findings": [],
        }

    with patch(
        "skylos.llm.security_verifier.SecurityVerifier.review_findings",
        side_effect=_supported,
    ):
        out = review_security_scan_result(
            model="gpt-4.1",
            api_key="k",
            provider=None,
            base_url=None,
            result=result,
        )

    metadata = out.findings[0].metadata
    assert metadata["security_evidence"] == "review_supported"
    assert metadata["review_verdict"] == "SUPPORTED"
    assert out.has_blockers() is False


def test_normalize_findings_preserves_security_review_metadata():
    normalized = api._normalize_findings(
        [
            {
                "file": "app.py",
                "line": 8,
                "message": "Possible SQL injection",
                "rule_id": "SKY-L001",
                "severity": "HIGH",
                "_source": "llm",
                "_confidence": "medium",
                "_needs_review": True,
                "_ci_blocking": False,
                "_security_evidence": "review_supported",
                "_review_verdict": "SUPPORTED",
                "_review_reason": "query is built from request data",
            }
        ],
        "SECURITY",
        "/repo",
        extract_metadata=True,
    )

    metadata = normalized[0]["metadata"]
    assert metadata["source"] == "llm"
    assert metadata["needs_review"] is True
    assert metadata["ci_blocking"] is False
    assert metadata["security_evidence"] == "review_supported"
    assert metadata["review_verdict"] == "SUPPORTED"


def test_normalize_findings_preserves_existing_security_evidence_packet():
    packet = {
        "evidence_kind": "source_to_sink",
        "entrypoint": "fetch_url",
        "source": "tainted variable `url`",
        "sink": "requests.get",
        "path": ["tainted variable `url`", "HTTP sink `requests.get`"],
        "guards_missing": ["URL host or scheme allowlist"],
    }

    normalized = api._normalize_findings(
        [
            {
                "file": "app.py",
                "line": 8,
                "message": "Possible SSRF",
                "rule_id": "SKY-D216",
                "severity": "CRITICAL",
                "metadata": {"security_evidence": packet},
                "_source": "static",
                "_confidence": "high",
            }
        ],
        "SECURITY",
        "/repo",
        extract_metadata=True,
    )

    metadata = normalized[0]["metadata"]
    assert metadata["source"] == "static"
    assert metadata["confidence"] == "high"
    assert metadata["security_evidence"] == packet
