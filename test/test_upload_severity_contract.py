from __future__ import annotations

import copy

import pytest

from skylos import api
from skylos.api._payloads import _compact_upload_finding, _upload_severity


def _result_with_dependency(severity: str) -> dict:
    return {
        "analysis_summary": {
            "comparison_scope": {
                "kind": "repository_root",
                "complete_repository": True,
                "changed_files_only": False,
                "excluded_folders": [],
            },
            "grade_categories": ["quality"],
            "analysis_error_count": 0,
            "resolution_scope_limited": False,
        },
        "analysis_errors": [],
        "suppressed": [],
        "grade": {"overall": "A"},
        "quality": [],
        "dependency_vulnerabilities": [
            {
                "rule_id": "SKY-SCA-PYSEC-2026-4320",
                "file": "uv.lock",
                "line": 139,
                "message": "Vulnerable dependency: example@1.0.0",
                "severity": severity,
                "category": "DEPENDENCY",
            }
        ],
        "architecture_metrics": {
            "iad_enforced": False,
            "advisories": [],
            "advisory_count": 0,
            "advisory_signal_count": 0,
        },
    }


@pytest.mark.parametrize(
    ("raw", "sent"),
    [
        ("CRITICAL", "CRITICAL"),
        ("HIGH", "HIGH"),
        ("MEDIUM", "MEDIUM"),
        ("LOW", "LOW"),
        ("INFO", "INFO"),
        ("high", "HIGH"),
        (" low ", "LOW"),
        ("UNKNOWN", "MEDIUM"),
        ("unknown", "MEDIUM"),
        ("moderate", "MEDIUM"),
        ("", "MEDIUM"),
        (None, "MEDIUM"),
    ],
)
def test_upload_severity_is_always_a_contract_value(raw, sent):
    assert _upload_severity(raw) == sent
    finding = {"rule_id": "SKY-D211", "file": "app.py", "line": 3, "message": "m"}
    if raw is not None:
        finding["severity"] = raw
    assert _compact_upload_finding(finding, include_snippet=False)["severity"] == sent


def test_unrated_dependency_advisory_uploads_as_medium_and_keeps_its_raw_severity(
    monkeypatch,
):
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_load_repo_link", lambda *_: {})
    result = _result_with_dependency("UNKNOWN")
    prepared = api._prepare_report_upload(copy.deepcopy(result), analyzer_owned=True)

    compact = prepared.compatibility_payload["findings"]
    sarif = prepared.core_payload["runs"][0]["results"]
    assert len(compact) == len(sarif) == 1
    assert compact[0]["rule_id"] == "SKY-SCA-PYSEC-2026-4320"
    assert compact[0]["severity"] == "MEDIUM"
    assert sarif[0]["ruleId"] == compact[0]["rule_id"]
    assert result["dependency_vulnerabilities"][0]["severity"] == "UNKNOWN"


def test_rated_dependency_advisory_keeps_its_severity_in_the_upload(monkeypatch):
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "actor", {}))
    monkeypatch.setattr(api, "get_git_root", lambda: None)
    monkeypatch.setattr(api, "detect_ai_code", lambda *_: {"detected": False})
    monkeypatch.setattr(api, "_load_repo_link", lambda *_: {})
    prepared = api._prepare_report_upload(
        copy.deepcopy(_result_with_dependency("CRITICAL")), analyzer_owned=True
    )
    assert prepared.compatibility_payload["findings"][0]["severity"] == "CRITICAL"
