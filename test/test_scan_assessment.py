"""Risk cannot be averaged away; maintainability requires real measurements."""

import copy
import math

import pytest

from skylos.cli import _apply_display_filters, _apply_rule_selection
from skylos.core.gatekeeper import check_gate
from skylos.reporting.assessment import compute_assessment
from skylos.reporting.result_builder import _attach_grade


def _result(**sections):
    return {
        "analysis_summary": {
            "grade_categories": ["security", "quality", "dead_code", "secrets"],
            "comparison_scope": {
                "kind": "repository_root",
                "changed_files_only": False,
            },
        },
        "analysis_errors": [],
        **sections,
    }


def _advice(file="app.py", *, rule="SKY-Q301", line=1, value=45, threshold=10):
    return {
        "rule_id": rule,
        "severity": "HIGH",
        "file": file,
        "line": line,
        "name": "function",
        "value": value,
        "threshold": threshold,
    }


def _measure(result, file="app.py", language="Python", count=20, rule="SKY-Q301"):
    result["analysis_summary"].setdefault("maintainability_inventory", []).append(
        {
            "file": file,
            "language": language,
            "function_lines": list(range(1, count + 1)),
            "rule_units": {rule: count},
        }
    )


@pytest.mark.parametrize(
    "section,rule",
    [
        ("secrets", "SKY-S101"),
        ("danger", "SKY-D211"),
        ("quality", "SKY-L001"),
        ("dependency_vulnerabilities", "SKY-SCA001"),
    ],
)
def test_critical_observation_cannot_be_diluted(section, rule):
    result = _result(**{section: [{"rule_id": rule, "severity": "CRITICAL"}]})
    original = compute_assessment(result)
    result["quality"] = result.get("quality", []) + [
        _advice(line=i) for i in range(1000)
    ]
    result["analysis_summary"]["total_loc"] = 10_000_000
    assert original["risk"]["status"] == "critical"
    assert compute_assessment(result)["risk"] == original["risk"]
    assert "overall" not in original


def test_pending_review_preserves_urgency_and_catalog_ignores_downgrade():
    result = _result(
        danger=[
            {"rule_id": "SKY-D211", "severity": "CRITICAL", "finding_type": "advice"}
        ]
    )
    assessed = compute_assessment(result)
    assert assessed["risk"]["status"] == "critical"
    assert assessed["finding_counts"]["review"] == 1
    assert assessed["maintainability"]["advice_count"] == 0


def test_dead_code_remains_review_burden_not_proven_risk():
    result = _result(
        unused_functions=[{"name": "unused", "confidence": 95, "severity": "HIGH"}]
    )
    assessed = compute_assessment(result)
    assert assessed["risk"]["status"] == "none"
    assert assessed["dead_code"] == {
        "status": "review",
        "candidate_count": 1,
        "confidence_range": [95, 95],
    }


@pytest.mark.parametrize(
    "severity,status",
    [
        ("CRITICAL", "critical"),
        ("HIGH", "high"),
        ("MEDIUM", "medium"),
        ("WARN", "medium"),
        ("LOW", "low"),
        (None, "unknown"),
        ("made-up", "unknown"),
    ],
)
def test_risk_is_explicit_about_unknown_severity(severity, status):
    assessed = compute_assessment(_result(danger=[{"severity": severity}]))
    assert assessed["risk"]["status"] == status
    assert assessed["risk"]["finding_count"] == 1


def test_incomplete_scan_keeps_known_critical_and_does_not_claim_absence():
    result = _result(
        secrets=[{"severity": "CRITICAL"}], analysis_errors=[{"kind": "syntax_error"}]
    )
    assessed = compute_assessment(result)
    assert assessed["risk"]["status"] == "critical"
    assert assessed["risk"]["categories"]["security"]["status"] == "unknown"
    assert assessed["dead_code"]["status"] == "unknown"
    assert assessed["coverage"]["status"] == "incomplete"


def test_checks_not_run_cannot_be_scored_clean():
    result = _result()
    result["analysis_summary"]["grade_categories"] = ["dead_code"]
    assessed = compute_assessment(result)
    assert assessed["risk"]["status"] == "not_assessed"
    assert assessed["maintainability"]["status"] == "not_assessed"
    assert "security" in assessed["coverage"]["not_assessed"]


def test_incomplete_dependency_provider_does_not_hide_other_coverage():
    result = _result()
    result["analysis_summary"]["grade_categories"].append("dependencies")
    assessed = compute_assessment(result)
    assert assessed["risk"]["categories"]["dependencies"]["status"] == "unknown"
    assert assessed["risk"]["categories"]["security"]["status"] == "none"
    assert assessed["coverage"]["incomplete_checks"] == ["dependencies"]


def test_prevalence_and_limit_exceedance_are_measured_separately():
    result = _result(
        quality=[_advice(line=1), _advice(line=2, value=11), _advice(line=3, value=20)]
    )
    _measure(result)
    check = compute_assessment(result)["maintainability"]["checks"][0]
    assert (
        check["affected_units"],
        check["analyzed_units"],
        check["affected_percent"],
    ) == (3, 20, 15)
    assert (check["max_value"], check["max_threshold"], check["max_excess_ratio"]) == (
        45,
        10,
        4.5,
    )


def test_mirrored_findings_and_overlapping_rules_do_not_multiply_affected_functions():
    first = _advice()
    result = _result(
        quality=[first, _advice(rule="SKY-Q302", value=8, threshold=3)],
        code_health=[copy.deepcopy(first)],
    )
    _measure(result)
    _measure(result, rule="SKY-Q302")
    # Each file has a single receipt in actual scans.
    result["analysis_summary"]["maintainability_inventory"] = [
        {
            "file": "app.py",
            "language": "Python",
            "function_lines": list(range(1, 21)),
            "rule_units": {"SKY-Q301": 20, "SKY-Q302": 20},
        }
    ]
    assessed = compute_assessment(result)
    assert assessed["maintainability"]["advice_count"] == 2
    assert assessed["maintainability"]["affected_functions"] == 1


def test_typescript_files_do_not_dilute_python_advice():
    result = _result(quality=[_advice(), _advice("app.ts")])
    _measure(result)
    before = compute_assessment(result)["maintainability"]["checks"]
    _measure(result, "app.ts", "TypeScript", count=1000)
    after = compute_assessment(result)["maintainability"]["checks"]
    assert next(check for check in after if check["language"] == "Python") == next(
        check for check in before if check["language"] == "Python"
    )
    assert (
        next(check for check in after if check["language"] == "TypeScript")[
            "affected_percent"
        ]
        == 0.1
    )


@pytest.mark.parametrize(
    "value,threshold",
    [
        (math.nan, 10),
        (math.inf, 10),
        (10, 0),
        (10, -1),
        (True, 10),
        (10**1000, 10),
        (1e308, 1e-308),
    ],
)
def test_invalid_metric_values_do_not_create_fake_precision(value, threshold):
    result = _result(quality=[_advice(value=value, threshold=threshold)])
    check = compute_assessment(result)["maintainability"]["checks"][0]
    assert check["max_excess_ratio"] is None
    assert check["affected_percent"] is None


def test_missing_or_ambiguous_inventory_does_not_invent_denominator():
    result = _result(quality=[_advice("unknown.ts")])
    assert (
        compute_assessment(result)["maintainability"]["checks"][0]["analyzed_units"]
        is None
    )
    _measure(result, "unknown.ts", "TypeScript", count=2)
    result["analysis_summary"]["maintainability_inventory"][0]["function_lines"] = [
        1,
        1,
    ]
    assert (
        compute_assessment(result)["maintainability"]["checks"][0]["affected_percent"]
        is None
    )


def test_advice_without_a_location_does_not_invent_an_affected_file():
    finding = _advice()
    finding.pop("file")
    maintenance = compute_assessment(_result(quality=[finding]))["maintainability"]
    assert maintenance["advice_count"] == 1
    assert maintenance["affected_files"] == 0
    assert maintenance["checks"][0]["analyzed_units"] is None


def test_assessment_cannot_change_records_or_gate_outcome():
    result = _result(quality=[_advice(line=i) for i in range(18)])
    before = copy.deepcopy(result)
    gate_before = check_gate(result, {"gate": {"max_quality": 10}})
    result["assessment"] = compute_assessment(result)
    assert gate_before == check_gate(result, {"gate": {"max_quality": 10}})
    result.pop("assessment")
    assert result == before


def test_display_filter_keeps_assessment_and_true_selection_omits_it():
    result = _result(
        quality=[_advice()], danger=[{"severity": "CRITICAL", "rule_id": "SKY-D211"}]
    )
    result["assessment"] = compute_assessment(result)
    filtered = _apply_display_filters(result, category="quality")
    assert filtered["assessment"] == result["assessment"]
    assert filtered["analysis_summary"]["assessment_includes_filtered_findings"] is True
    assert "assessment" not in _apply_rule_selection(result, ["SKY-Q301"])


def test_new_scan_attachment_emits_assessment_without_legacy_grade():
    result = _result(secrets=[{"severity": "CRITICAL"}])
    _attach_grade(result, [], False, False, False, False, True)
    assert result["assessment"]["risk"]["status"] == "critical"
    assert "grade" not in result


def test_missing_expected_ai_check_prevents_clean_correctness_assessment():
    from pathlib import Path
    from skylos.core.verification_coverage import build_ai_verification_coverage
    from skylos.core.verification_registry import expected_ai_verification_checks

    result = _result()
    result["analysis_summary"]["grade_categories"] = ["ai_defects"]
    result["analysis_summary"]["ai_verification"] = build_ai_verification_coverage(
        [], expected_checks=expected_ai_verification_checks([Path("main.go")])
    )
    assessed = compute_assessment(result)
    assert assessed["coverage"]["incomplete_checks"] == ["ai_defects"]
    assert assessed["risk"]["categories"]["correctness"]["status"] == "unknown"
    assert assessed["risk"]["status"] == "unknown"


def test_metric_unit_requires_actual_measured_function_location():
    result = _result(quality=[_advice(line=99)])
    _measure(result, count=2)
    assessed = compute_assessment(result)["maintainability"]
    assert assessed["checks"][0]["analyzed_units"] is None
    assert assessed["checks"][0]["affected_percent"] is None
    assert assessed["affected_functions"] is None


def test_alternate_names_at_same_measured_function_do_not_multiply_prevalence():
    first = _advice(line=1)
    second = dict(first, name="module.function", message="Different evidence")
    result = _result(quality=[first, second])
    _measure(result, count=2)
    assessed = compute_assessment(result)["maintainability"]
    assert assessed["advice_count"] == 2
    assert assessed["checks"][0]["affected_units"] == 1
    assert assessed["checks"][0]["affected_percent"] == 50
