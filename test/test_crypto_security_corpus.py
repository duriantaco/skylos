"""Shared cryptographic source controls, labelled before native analysis.

Only source is scanned. A quiet weak-hash rule does not assert that the program
is a complete password-storage scheme or that every security family is covered.
"""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import security
from skylos.reporting.listing import is_listed

MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/security/manifest.json"

# Required rule identity and source location; safe controls remain rule-specific.
CONTRACTS = {
    "crypto-corpus-md5-password": (("SKY-D207",), 4),
    "crypto-corpus-md5-nonsecurity": (("SKY-D207",), None),
    "crypto-corpus-sha1-token-factory": (("SKY-D208",), 4),
    "crypto-corpus-sha1-nonsecurity": (("SKY-D208",), None),
    "crypto-corpus-sha256-password": (("SKY-D207", "SKY-D208"), None),
    "crypto-corpus-hash-named-lookalike": (("SKY-D207", "SKY-D208"), None),
    "crypto-corpus-misleading-cache-name": (("SKY-D207",), 4),
    "crypto-corpus-weak-random-cookie": (("SKY-D250",), 4),
    "crypto-corpus-secrets-cookie": (("SKY-D250",), None),
    "crypto-corpus-system-random-cookie": (("SKY-D250",), None),
    "crypto-corpus-retry-jitter": (("SKY-D250",), None),
    "crypto-corpus-reassigned-strong": (("SKY-D250",), None),
    "crypto-corpus-branch-weak-cookie": (("SKY-D250",), 7),
    "crypto-corpus-random-named-lookalike": (("SKY-D250",), None),
    "crypto-corpus-alias-rebound-strong": (("SKY-D250",), None),
    "crypto-corpus-alias-rebound-weak": (("SKY-D250",), 7),
}


def _case(case_id):
    return deepcopy(
        next(
            case
            for case in security.load_manifest(MANIFEST)["cases"]
            if case["id"] == case_id
        )
    )


@pytest.mark.parametrize("case_id", CONTRACTS)
def test_crypto_source_truth_is_present_in_default_manifest(case_id):
    rules, line = CONTRACTS[case_id]
    case = _case(case_id)
    assert case["languages"] == ["python"]
    assert case["expect"] == {
        "present": {"danger": list(rules)} if line is not None else {},
        "absent": {} if line is not None else {"danger": list(rules)},
    }


@pytest.mark.parametrize("case_id", CONTRACTS)
def test_crypto_control_native_identity_location_and_coverage(case_id, monkeypatch):
    reports = []
    original = security.analyze

    def capture(*args, **kwargs):
        raw = original(*args, **kwargs)
        reports.append(json.loads(raw))
        return raw

    monkeypatch.setattr(security, "analyze", capture)
    result = security.run_case(_case(case_id), MANIFEST)
    report = reports[0]
    assert report["analysis_summary"]["total_files"] == 1
    assert report["analysis_summary"]["languages"] == {"Python": 1}
    assert not report.get("analysis_errors")
    rules, line = CONTRACTS[case_id]
    rows = report.get("danger", [])
    assert [(row["rule_id"], Path(row["file"]).name, row["line"]) for row in rows] == (
        [(rule, "app.py", line) for rule in rules] if line is not None else []
    )
    assert all(is_listed(row, "danger") for row in rows)
    assert result["scored"] is True
    assert result["true_positives"] == (len(rules) if line is not None else 0)
    assert result["true_negatives"] == (len(rules) if line is None else 0)
    assert result["false_positives"] == result["false_negatives"] == 0
    assert result["failures"] == []


@pytest.mark.parametrize(
    "case_id", ["crypto-corpus-md5-password", "crypto-corpus-md5-nonsecurity"]
)
def test_crypto_control_incomplete_source_does_not_earn_credit(case_id, monkeypatch):
    monkeypatch.setattr(
        security,
        "_scan_case_with_scanner",
        lambda *args, **kwargs: {
            "analysis_summary": {"total_files": 0},
            "danger": [],
        },
    )
    result = security.run_case(_case(case_id), MANIFEST)
    assert result["scored"] is False
    assert result["true_positives"] == result["true_negatives"] == 0
    assert result["false_positives"] == result["false_negatives"] == 0
    assert result["scores"]["overall_score"] == 0
