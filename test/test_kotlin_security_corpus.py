"""Static Kotlin security corpus, source coverage and scoring contracts."""

import copy
import json
from pathlib import Path

import pytest

from skylos.benchmarks import security


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks/security/manifest.json"
CHALLENGES = ROOT / "benchmarks/security/adversarial_manifest.json"
SPECS = {
    "kotlin-sql-interpolation": ("SKY-D211", "present", 10),
    "kotlin-sql-binding": ("SKY-D211", "absent", 10),
    "kotlin-sql-other-scalar": ("SKY-D211", "present", 11),
    "kotlin-command-shell": ("SKY-D212", "present", 6),
    "kotlin-command-text": ("SKY-D212", "absent", 7),
    "kotlin-command-numeric-argv": ("SKY-D212", "absent", 5),
    "kotlin-ssrf-destination": ("SKY-D216", "present", 11),
    "kotlin-ssrf-fixed-origin": ("SKY-D216", "absent", 11),
    "kotlin-ssrf-unrelated-allowlist": ("SKY-D216", "present", 12),
    "kotlin-path-segment": ("SKY-D215", "present", 9),
    "kotlin-path-basename": ("SKY-D215", "absent", 9),
    "kotlin-path-prefix": ("SKY-D215", "present", 10),
}


def _case(case_id, manifest=MANIFEST):
    cases = security.load_manifest(manifest)["cases"]
    return copy.deepcopy(next(case for case in cases if case["id"] == case_id))


def test_kotlin_cases_are_registered_with_frozen_rule_polarities():
    cases = security.validate_manifest(security.load_manifest(MANIFEST), MANIFEST)
    by_id = {case["id"]: case for case in cases}
    assert set(SPECS) <= set(by_id)
    for case_id, (rule, mode, _) in SPECS.items():
        case = by_id[case_id]
        assert case["languages"] == ["kotlin"]
        assert "kotlin" in case["taxonomy"]
        assert case["expect"][mode]["danger"] == [rule]
        assert not case["expect"]["absent" if mode == "present" else "present"]


def test_kotlin_language_does_not_require_language_taxonomy():
    case = _case("kotlin-sql-interpolation")
    case["taxonomy"] = ["sql_injection"]
    assert security.validate_manifest({"version": 1, "cases": [case]}, MANIFEST) == [
        case
    ]


def test_kotlin_taxonomy_is_accepted():
    case = _case("kotlin-sql-interpolation")
    case["taxonomy"] = ["kotlin"]
    assert security.validate_manifest({"version": 1, "cases": [case]}, MANIFEST) == [
        case
    ]


@pytest.mark.parametrize("case_id", SPECS)
def test_native_kotlin_scan_and_mutated_findings_enforce_both_polarities(
    monkeypatch, case_id
):
    case = _case(case_id)
    rule, mode, line = SPECS[case_id]
    captures = []
    original = security.analyze

    def capture(*args, **kwargs):
        kwargs.update(
            grep_cache=False,
            trace_file=False,
            enable_ai_defects=False,
            enable_dependency_hallucinations=False,
            enable_sca=False,
        )
        raw = original(*args, **kwargs)
        captures.append(json.loads(raw))
        return raw

    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setenv("SKYLOS_NO_UPLOAD", "1")
    monkeypatch.setenv("SKYLOS_NO_TELEMETRY", "1")
    monkeypatch.setattr(security, "analyze", capture)
    result = security.run_case(case, MANIFEST)
    assert len(captures) == 1
    report = captures[0]
    assert report["analysis_summary"]["total_files"] == 1
    assert report["analysis_summary"]["languages"] == {"Kotlin": 1}
    assert not report.get("analysis_errors")
    assert result["scored"] is True
    assert result["failures"] == [], result
    findings = report.get("danger", [])
    if mode == "present":
        assert any(
            finding.get("rule_id") == rule
            and finding.get("line") == line
            and Path(finding["file"]).name == "App.kt"
            for finding in findings
        )
    else:
        assert not any(finding.get("rule_id") == rule for finding in findings)

    # Accounting controls only: keep real source coverage but remove the real
    # finding, or add a spurious one to a source-proven safe case.
    altered = copy.deepcopy(report)
    if mode == "present":
        altered["danger"] = [
            finding
            for finding in altered.get("danger", [])
            if finding.get("rule_id") != rule
        ]
    else:
        altered.setdefault("danger", []).append(
            {
                "rule_id": rule,
                "message": "Injected benchmark accounting control",
                "file": str(MANIFEST.parent / case["path"] / "App.kt"),
                "line": line,
                "severity": "HIGH",
            }
        )
    monkeypatch.setattr(
        security, "_scan_case_with_scanner", lambda *args, **kwargs: altered
    )
    broken = security.run_case(case, MANIFEST)
    assert broken["scored"] is True
    assert len(broken["failures"]) == 1
    assert broken["failures"][0]["failure_type"] == "expectation"
    assert broken["failures"][0]["mode"] == mode
    assert broken["false_negatives"] == (1 if mode == "present" else 0)
    assert broken["false_positives"] == (1 if mode == "absent" else 0)
    assert broken["true_positives"] == broken["true_negatives"] == 0


def test_bandit_skips_kotlin_without_running_a_python_scanner(monkeypatch):
    cases = [_case(case_id) for case_id in SPECS]
    monkeypatch.setattr(
        security, "load_manifest", lambda path: {"version": 1, "cases": cases}
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("Bandit must not scan Kotlin source")

    monkeypatch.setattr(security, "_scan_case_with_scanner", forbidden)
    summary = security.run_manifest(MANIFEST, scanner="bandit")
    assert summary["case_count"] == 0
    assert summary["skipped_case_count"] == len(SPECS)
    assert {case["id"] for case in summary["skipped_cases"]} == set(SPECS)
    assert all(case["languages"] == ["kotlin"] for case in summary["skipped_cases"])
    assert all(value == 0 for value in summary["counts"].values())


@pytest.mark.parametrize("case_id", ["kotlin-sql-interpolation", "kotlin-sql-binding"])
@pytest.mark.parametrize("unavailable", ["zero_sources", "engine_incomplete"])
def test_kotlin_contracts_do_not_score_unavailable_analysis(
    monkeypatch, case_id, unavailable
):
    report = {
        "analysis_summary": {"total_files": 1, "analysis_error_count": 0},
        "analysis_errors": [],
    }
    if unavailable == "zero_sources":
        report["analysis_summary"]["total_files"] = 0
    else:
        report["analysis_summary"]["language_engines"] = {
            "kotlin": {"status": "unavailable", "complete": False}
        }
    monkeypatch.setattr(
        security, "_scan_case_with_scanner", lambda *args, **kwargs: report
    )
    result = security.run_case(_case(case_id), MANIFEST)
    assert result["scored"] is False
    assert result["failures"]
    for field in (
        "true_positives",
        "false_positives",
        "false_negatives",
        "true_negatives",
    ):
        assert result[field] == 0


def test_fixed_format_string_argv_case_keeps_its_safe_truth_in_challenge_manifest():
    case = _case("kotlin-command-argv", CHALLENGES)
    assert case["languages"] == ["kotlin"]
    assert case["expect"] == {"present": {}, "absent": {"danger": ["SKY-D212"]}}
    assert case["id"] not in {
        entry["id"] for entry in security.load_manifest(MANIFEST)["cases"]
    }
