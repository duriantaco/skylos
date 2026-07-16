from pathlib import Path

from skylos.core.verification_coverage import (
    build_ai_verification_coverage,
    reconcile_check_findings,
)
from skylos.core.verification_registry import expected_ai_verification_checks


def test_expected_checks_deduplicate_typescript_and_javascript():
    expectations = expected_ai_verification_checks(
        [Path("app.ts"), Path("legacy.cjs"), Path("other.txt")]
    )

    assert [item.check_id for item in expectations] == ["typescript_local_api_surface"]
    assert expectations[0].languages == ("typescript", "javascript")
    assert expectations[0].applicable_files == 2


def test_coverage_marks_supported_missing_check_incomplete():
    expectations = expected_ai_verification_checks([Path("main.go")])

    coverage = build_ai_verification_coverage([], expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert coverage["missing_checks"] == ["go_workspace_api_surface"]
    assert coverage["checks"][0]["reasons"] == [
        {"code": "expected_check_missing", "count": 1}
    ]


def test_coverage_marks_unsupported_language_explicitly():
    expectations = expected_ai_verification_checks([Path("main.php")])

    coverage = build_ai_verification_coverage([], expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert coverage["missing_checks"] == []
    assert coverage["language_support"] == [
        {
            "language": "php",
            "capability": "local_workspace_api_surface",
            "status": "unsupported",
            "check_id": "php_workspace_api_surface",
            "reason": "local_api_verification_not_implemented",
        }
    ]
    assert coverage["checks"][0]["reasons"] == [
        {"code": "unsupported_capability", "count": 1}
    ]


def test_expected_checks_cover_every_discovered_source_language():
    expectations = expected_ai_verification_checks(
        [
            Path("app.py"),
            Path("app.ts"),
            Path("legacy.js"),
            Path("main.go"),
            Path("App.java"),
            Path("main.php"),
            Path("main.rs"),
            Path("main.dart"),
            Path("Program.cs"),
            Path("Main.kt"),
            Path("build.kts"),
            Path("entrypoint.sh"),
        ]
    )

    assert {language for item in expectations for language in item.languages} == {
        "python",
        "typescript",
        "javascript",
        "go",
        "java",
        "php",
        "rust",
        "dart",
        "csharp",
        "kotlin",
        "shell",
    }
    assert {item.check_id for item in expectations if not item.supported} == {
        "php_workspace_api_surface",
        "rust_workspace_api_surface",
        "dart_workspace_api_surface",
        "csharp_workspace_api_surface",
        "kotlin_workspace_api_surface",
        "shell_workspace_api_surface",
    }


def test_coverage_marks_expected_file_count_mismatch_incomplete():
    expectations = expected_ai_verification_checks([Path("app.ts"), Path("app.js")])
    check = {
        "id": "typescript_local_api_surface",
        "status": "completed",
        "outcome": "pass",
        "languages": ["typescript"],
        "applicable_files": 1,
        "skipped_references": 0,
        "finding_count": 0,
    }

    coverage = build_ai_verification_coverage([check], expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert coverage["checks"][0]["languages"] == ["javascript", "typescript"]
    assert coverage["checks"][0]["applicable_files"] == 1
    assert coverage["checks"][0]["expected_applicable_files"] == 2
    assert coverage["checks"][0]["reasons"] == [
        {"code": "expected_file_coverage_mismatch", "count": 1}
    ]


def test_coverage_preserves_incomplete_proof_when_check_also_has_findings():
    expectations = expected_ai_verification_checks([Path("app.java")])
    check = {
        "id": "java_workspace_api_surface",
        "status": "completed",
        "outcome": "fail",
        "languages": ["java"],
        "applicable_files": 1,
        "skipped_references": 1,
        "finding_count": 1,
    }

    coverage = build_ai_verification_coverage([check], expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert coverage["checks"][0]["outcome"] == "fail"


def test_coverage_treats_skipped_expected_check_as_incomplete():
    expectations = expected_ai_verification_checks([Path("app.ts")])
    check = {
        "id": "typescript_local_api_surface",
        "status": "skipped",
        "outcome": "pass",
        "languages": [],
        "applicable_files": 0,
        "skipped_references": 0,
        "finding_count": 0,
        "reasons": [{"code": "rule_ignored", "count": 1}],
    }

    coverage = build_ai_verification_coverage([check], expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert coverage["checks"][0]["outcome"] == "incomplete"


def test_coverage_without_source_expectations_remains_complete():
    coverage = build_ai_verification_coverage([], expected_checks=[])

    assert coverage["state"] == "complete"
    assert coverage["detected_languages"] == []
    assert coverage["expected_checks"] == []
    assert coverage["checks"] == []


def test_coverage_marks_malformed_expected_check_incomplete():
    expectations = expected_ai_verification_checks([Path("app.java")])
    check = {
        "id": "java_workspace_api_surface",
        "languages": ["java"],
        "applicable_files": 1,
        "finding_count": 0,
    }

    coverage = build_ai_verification_coverage([check], expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert coverage["checks"][0]["outcome"] == "incomplete"
    assert coverage["checks"][0]["reasons"] == [
        {"code": "malformed_check_record", "count": 1}
    ]


def test_coverage_merges_duplicate_checks_conservatively():
    expectations = expected_ai_verification_checks([Path("app.go")])
    checks = [
        {
            "id": "go_workspace_api_surface",
            "status": "completed",
            "outcome": "incomplete",
            "languages": ["go"],
            "applicable_files": 1,
            "skipped_references": 1,
            "finding_count": 0,
            "reasons": [{"code": "surface_parse_error", "count": 1}],
        },
        {
            "id": "go_workspace_api_surface",
            "status": "completed",
            "outcome": "pass",
            "languages": ["go"],
            "applicable_files": 1,
            "skipped_references": 0,
            "finding_count": 0,
            "reasons": [],
        },
    ]

    coverage = build_ai_verification_coverage(checks, expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert len(coverage["checks"]) == 1
    assert coverage["checks"][0]["outcome"] == "incomplete"
    assert {reason["code"] for reason in coverage["checks"][0]["reasons"]} == {
        "duplicate_check_record",
        "surface_parse_error",
    }


def test_coverage_preserves_duplicate_failure_and_marks_proof_incomplete():
    expectations = expected_ai_verification_checks([Path("app.java")])
    checks = [
        {
            "id": "java_workspace_api_surface",
            "status": "completed",
            "outcome": "fail",
            "languages": ["java"],
            "applicable_files": 1,
            "skipped_references": 0,
            "finding_count": 1,
        },
        {
            "id": "java_workspace_api_surface",
            "status": "completed",
            "outcome": "pass",
            "languages": ["java"],
            "applicable_files": 1,
            "skipped_references": 0,
            "finding_count": 0,
        },
    ]

    coverage = build_ai_verification_coverage(checks, expected_checks=expectations)

    assert coverage["state"] == "incomplete"
    assert coverage["checks"][0]["outcome"] == "fail"
    assert coverage["checks"][0]["finding_count"] == 1


def test_reconcile_check_findings_clears_suppressed_detector_failure():
    check = {
        "id": "go_workspace_api_surface",
        "status": "completed",
        "outcome": "fail",
        "finding_count": 2,
        "skipped_references": 0,
    }

    reconciled = reconcile_check_findings(check, 0)

    assert reconciled["finding_count"] == 0
    assert reconciled["outcome"] == "pass"


def test_reconcile_check_findings_preserves_uncertainty_after_suppression():
    check = {
        "id": "java_workspace_api_surface",
        "status": "completed",
        "outcome": "fail",
        "finding_count": 1,
        "skipped_references": 1,
    }

    reconciled = reconcile_check_findings(check, 0)

    assert reconciled["finding_count"] == 0
    assert reconciled["outcome"] == "incomplete"


def test_reconcile_check_findings_records_suppressed_waiver():
    check = {
        "id": "python_local_api_reference",
        "status": "completed",
        "outcome": "fail",
        "finding_count": 1,
        "skipped_references": 0,
        "reasons": [],
    }

    reconciled = reconcile_check_findings(check, 0, suppressed_count=1)

    assert reconciled["finding_count"] == 0
    assert reconciled["suppressed_findings"] == 1
    assert reconciled["outcome"] == "pass"
    assert reconciled["reasons"] == [{"code": "finding_suppressed", "count": 1}]
