"""Advisories folded under their package's lead row are not filtered findings."""

from copy import deepcopy

from skylos.api._scan_coverage import scan_coverage_receipt
from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.assessment import compute_assessment
from skylos.reporting.listing import is_combined, listed_result

LOCK = "uv.lock"


def _advisory(rule_id, severity, aliases):
    return {
        "rule_id": rule_id,
        "category": "DEPENDENCY",
        "severity": severity,
        "message": "certifi@2026.7.22: compromised intermediate CA keys. Upgrade to 2026.10.19.",
        "file": LOCK,
        "line": 139,
        "symbol": "certifi@2026.7.22",
        "metadata": {
            "vuln_id": rule_id.removeprefix("SKY-SCA-"),
            "aliases": aliases,
            "ecosystem": "PyPI",
            "package_name": "certifi",
            "package_version": "2026.7.22",
        },
    }


def _raw_report():
    return {
        "analysis_summary": {
            "comparison_scope": {
                "kind": "repository_root",
                "complete_repository": True,
                "changed_files_only": False,
                "excluded_folders": [],
            },
            "grade_categories": ["dependencies"],
            "analysis_error_count": 0,
            "resolution_scope_limited": False,
        },
        "analysis_errors": [],
        "suppressed": [],
        "dependency_vulnerabilities": [
            _advisory("SKY-SCA-GHSA-6q48-6c7w-9gw2", "CRITICAL", ["PYSEC-2026-4320"]),
            _advisory("SKY-SCA-PYSEC-2026-4320", "UNKNOWN", ["GHSA-6q48-6c7w-9gw2"]),
        ],
        "architecture_metrics": {"iad_enforced": False, "advisories": []},
        "provenance": {},
    }


def _listed_report(tmp_path):
    result = _raw_report()
    result["assessment"] = compute_assessment(result)
    return apply_advice_policy(result, project_root=tmp_path)


def _coverage(result):
    return scan_coverage_receipt(result, analyzer_owned=True, analysis_mode="static")


def test_listing_folds_the_alias_under_its_lead(tmp_path):
    result = _listed_report(tmp_path)
    rows = result["dependency_vulnerabilities"]
    assert [is_combined(row) for row in rows].count(True) == 1
    assert len(listed_result(result)["dependency_vulnerabilities"]) == 1
    assert len(rows) == 2


def test_folded_advisory_keeps_complete_coverage(tmp_path):
    result = _listed_report(tmp_path)
    receipt = _coverage(deepcopy(result))
    assert "filtered_findings" not in receipt["reasons"]
    assert receipt["complete"] is True
    assert receipt["scope"] == "full_repository"


def test_folded_advisory_without_a_listed_lead_is_still_filtering(tmp_path):
    result = _listed_report(tmp_path)
    combined = next(
        row for row in result["dependency_vulnerabilities"] if is_combined(row)
    )
    combined["listing"]["lead"] = {
        "rule_id": "SKY-SCA-GHSA-0000-0000-0000",
        "file": LOCK,
        "line": 139,
    }
    assert "filtered_findings" in _coverage(result)["reasons"]


def test_dropping_the_folded_row_is_still_filtering(tmp_path):
    result = _listed_report(tmp_path)
    result["dependency_vulnerabilities"] = [
        row for row in result["dependency_vulnerabilities"] if not is_combined(row)
    ]
    assert "filtered_findings" in _coverage(result)["reasons"]


def test_a_forged_combined_mark_on_a_security_finding_cannot_hide_it(tmp_path):
    result = _listed_report(tmp_path)
    result["danger"] = [
        {
            "rule_id": "SKY-D211",
            "file": "app.py",
            "line": 3,
            "severity": "CRITICAL",
            "message": "SQL built from request input",
            "listing": {
                "version": 1,
                "listed": False,
                "reason": "combined",
                "lead": {
                    "rule_id": "SKY-SCA-GHSA-6Q48-6C7W-9GW2",
                    "file": LOCK,
                    "line": 139,
                },
            },
        }
    ]
    assert len(listed_result(result)["danger"]) == 1
    receipt = _coverage(result)
    assert "filtered_findings" in receipt["reasons"]
