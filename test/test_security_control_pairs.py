"""Opposite controls for the shared Rust/Dart security families."""

import copy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import security


MANIFEST = Path(__file__).resolve().parents[1] / "benchmarks/security/manifest.json"
CONTRACTS = {
    "rust-shell-literal-command": ("rust", "SKY-D212", False),
    "rust-path-argument": ("rust", "SKY-D215", True),
    "dart-process-command-argument": ("dart", "SKY-D212", True),
    "dart-process-literal-command": ("dart", "SKY-D212", False),
    "dart-file-path-argument": ("dart", "SKY-D215", True),
    "dart-file-basename-guard": ("dart", "SKY-D215", False),
}


def _case(case_id):
    return copy.deepcopy(
        next(
            case
            for case in security.load_manifest(MANIFEST)["cases"]
            if case["id"] == case_id
        )
    )


@pytest.mark.parametrize("case_id", CONTRACTS)
def test_security_pair_labels_keep_frozen_source_truth(case_id):
    language, rule, unsafe = CONTRACTS[case_id]
    case = _case(case_id)
    assert case["languages"] == [language]
    assert case["expect"] == {
        "present": {"danger": [rule]} if unsafe else {},
        "absent": {} if unsafe else {"danger": [rule]},
    }


@pytest.mark.parametrize("case_id", CONTRACTS)
def test_security_pair_native_reports_match_required_polarity(monkeypatch, case_id):
    language, rule, unsafe = CONTRACTS[case_id]
    if language == "dart":
        pytest.importorskip(
            "tree_sitter_dart_orchard", reason="needs optional skylos[dart] extra"
        )
    original = security.analyze
    reports = []

    def capture(*args, **kwargs):
        raw = original(*args, **kwargs)
        reports.append(json.loads(raw))
        return raw

    monkeypatch.setattr(security, "analyze", capture)
    result = security.run_case(_case(case_id), MANIFEST)
    assert reports[0]["analysis_summary"]["total_files"] == 1
    assert reports[0]["analysis_summary"]["languages"] == {language.title(): 1}
    assert not reports[0].get("analysis_errors")
    assert {finding["rule_id"] for finding in reports[0].get("danger", [])} == (
        {rule} if unsafe else set()
    )
    assert result["true_positives"] == int(unsafe)
    assert result["true_negatives"] == int(not unsafe)
    assert result["false_positives"] == result["false_negatives"] == 0
    assert result["failures"] == []

    # A real finding disappearing, or a safe case gaining its forbidden rule,
    # must fail without rewriting the fixture's source truth.
    mutant = {
        "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
        "analysis_errors": [],
    }
    mutant["danger"] = [] if unsafe else [{"rule_id": rule}]
    monkeypatch.setattr(
        security, "_scan_case_with_scanner", lambda *args, **kwargs: mutant
    )
    changed = security.run_case(_case(case_id), MANIFEST)
    assert changed["false_negatives"] == int(unsafe)
    assert changed["false_positives"] == int(not unsafe)
    assert len(changed["failures"]) == 1


@pytest.mark.parametrize("case_id", CONTRACTS)
def test_security_pairs_do_not_score_absence_when_analysis_is_missing(
    monkeypatch, case_id
):
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


@pytest.mark.parametrize(
    "case_id", ["dart-file-path-argument", "dart-file-basename-guard"]
)
def test_missing_dart_engine_cannot_pass_either_polarity(monkeypatch, case_id):
    from skylos.visitors.languages.dart import core

    reports = []
    original = security.analyze

    def capture(*args, **kwargs):
        raw = original(*args, **kwargs)
        reports.append(json.loads(raw))
        return raw

    monkeypatch.setattr(core, "DART_LANG", None)
    monkeypatch.setattr(security, "analyze", capture)
    result = security.run_case(_case(case_id), MANIFEST)
    assert any(
        error["kind"] == "language_engine_unavailable" and error["language"] == "dart"
        for error in reports[0]["analysis_errors"]
    )
    assert result["scored"] is False
    assert result["true_positives"] == result["true_negatives"] == 0
    assert result["false_positives"] == result["false_negatives"] == 0
    assert result["scores"]["overall_score"] == 0


def test_security_pairs_skip_bandit_without_executing(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Bandit must not run for Rust or Dart")

    monkeypatch.setattr(security, "_scan_case_with_scanner", forbidden)
    result = security.run_manifest(
        MANIFEST, selected_cases=set(CONTRACTS), scanner="bandit"
    )
    assert result["case_count"] == 0
    assert result["skipped_case_count"] == 6
    assert result["scores"]["overall_score"] == 0
