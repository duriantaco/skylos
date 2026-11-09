"""Frozen PHP/C# review cases reach the shared corpus and native output."""

from pathlib import Path

import pytest

from skylos.benchmarks import security
from skylos.core.gatekeeper import check_gate


MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/security/manifest.json"
CASES = {
    "review-php-strict-page-allowlist": ("PHP", []),
    "review-php-loose-boolean-allowlist": ("PHP", [("SKY-D255", 4, "CRITICAL")]),
    "review-php-tainted-allowlist": ("PHP", [("SKY-D255", 5, "CRITICAL")]),
    "review-csharp-json-data-only": ("C#", []),
    "review-csharp-formatter-named-lookalike": ("C#", []),
    "review-csharp-newtonsoft-unsafe": ("C#", [("SKY-D233", 4, "HIGH")]),
    "review-csharp-settings-named-lookalike": ("C#", []),
}


@pytest.mark.parametrize("case_id", CASES)
def test_review_case_native_output_identity_coverage_and_gate(case_id, monkeypatch):
    language, expected = CASES[case_id]
    case = next(
        c for c in security.load_manifest(MANIFEST)["cases"] if c["id"] == case_id
    )
    reports = []
    scan = security._scan_case

    def capture(*args, **kwargs):
        report = scan(*args, **kwargs)
        reports.append(report)
        return report

    monkeypatch.setattr(security, "_scan_case", capture)
    result = security.run_case(case, MANIFEST)
    report = reports[0]
    assert result["scored"] is True
    assert result["failures"] == []
    assert report["analysis_summary"]["languages"] == {language: 1}
    assert report["analysis_summary"]["total_files"] == 1
    assert not report.get("analysis_errors")
    findings = report.get("danger", [])
    assert [
        (row["rule_id"], row["line"], row["severity"]) for row in findings
    ] == expected
    assert all(row["listing"]["listed"] for row in findings)
    passed, _ = check_gate(report, {"gate": {"max_security": 0, "max_high": 0}})
    assert passed is (not expected)
