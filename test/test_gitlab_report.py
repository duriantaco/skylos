from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from skylos.reporting import gitlab
from skylos.reporting.gitlab import build_gitlab_report


def _finding(**changes):
    return {
        "file": "src/app.py",
        "line": 12,
        "rule_id": "SKY-D211",
        "severity": "HIGH",
        "message": "Unsafe command construction",
        "name": "app.handler",
        **changes,
    }


def _report(result, root="/checkout/project"):
    return build_gitlab_report(result, project_root=Path(root))


def _dependency(**metadata):
    return _finding(
        file="pnpm-lock.yaml",
        rule_id="SKY-SCA-GHSA-example-1234",
        metadata={
            "ecosystem": "npm",
            "package_name": "example",
            "package_version": "1.0.0",
            "vuln_id": "GHSA-example-1234",
            "advisory_status": "complete",
            "package_path": "example@1.0.0(peer@2.0.0)",
            "dependency_roots": ["packages/app"],
            "dependency_dev": True,
            **metadata,
        },
    )


def test_empty_result_is_a_complete_empty_array():
    report = _report({})
    assert report.complete
    assert report.diagnostics == []
    assert json.dumps(report.findings) == "[]"


def test_emits_only_gitlab_required_schema_fields():
    report = _report({"danger": [_finding()]})
    assert report.complete
    row = report.findings[0]
    assert set(row) == {
        "description",
        "check_name",
        "fingerprint",
        "severity",
        "location",
    }
    assert row["description"] == "Unsafe command construction"
    assert row["check_name"] == "SKY-D211"
    assert row["severity"] == "critical"
    assert row["location"] == {"path": "src/app.py", "lines": {"begin": 12}}
    assert len(row["fingerprint"]) == 64
    assert all(char in "0123456789abcdef" for char in row["fingerprint"])
    assert json.loads(json.dumps(report.findings)) == report.findings


@pytest.mark.parametrize(
    "section,rule",
    [
        ("danger", "SKY-D000"),
        ("reliability", "SKY-R000"),
        ("ai_defects", "SKY-AI000"),
        ("quality", "SKY-Q000"),
        ("secrets", "SKY-S000"),
        ("custom_rules", "CUSTOM"),
        ("unused_functions", "SKY-U001"),
        ("unused_imports", "SKY-U002"),
        ("unused_variables", "SKY-U003"),
        ("unused_classes", "SKY-U004"),
        ("unused_parameters", "SKY-U006"),
        ("unused_files", "SKY-E002"),
        ("unused_fixtures", "SKY-U000"),
        ("unused_exports", "SKY-U000"),
        ("forgotten", "SKY-U001"),
        ("circular_dependencies", "SKY-CIRC"),
        ("dependency_vulnerabilities", "SKY-SCA-000"),
    ],
)
def test_all_current_result_sections_have_default_rules(section, rule):
    report = _report({section: [{"file": "src/app.py", "line": 1, "name": "symbol"}]})
    assert report.complete
    assert len(report.findings) == 1
    assert report.findings[0]["check_name"] == rule
    assert report.findings[0]["location"]["lines"]["begin"] == 1


@pytest.mark.parametrize(
    "severity,expected",
    [
        ("CRITICAL", "blocker"),
        ("HIGH", "critical"),
        ("MEDIUM", "major"),
        ("LOW", "minor"),
        ("INFO", "info"),
        ("INFORMATIONAL", "info"),
        ("UNKNOWN", "major"),
        (" high ", "critical"),
    ],
)
def test_severity_mapping(severity, expected):
    report = _report({"danger": [_finding(severity=severity)]})
    assert report.complete
    assert report.findings[0]["severity"] == expected
    if severity == "UNKNOWN":
        assert "severity unknown" in report.findings[0]["description"]


def test_relative_and_absolute_paths_share_fingerprint():
    relative = _report({"danger": [_finding(file="./src/app.py")]})
    absolute = _report({"danger": [_finding(file="/checkout/project/src/app.py")]})
    assert relative.complete and absolute.complete
    assert relative.findings == absolute.findings


def test_fingerprint_survives_checkout_and_line_movement():
    before = _report(
        {
            "danger": [
                _finding(
                    file="/old/project/src/app.py",
                    line=12,
                    message="Unsafe call in /old/project/src/app.py",
                )
            ]
        },
        root="/old/project",
    )
    after = _report(
        {
            "danger": [
                _finding(
                    file="/new/project/src/app.py",
                    line=30,
                    message="Unsafe call in /new/project/src/app.py",
                )
            ]
        },
        root="/new/project",
    )
    assert before.complete and after.complete
    assert before.findings[0]["fingerprint"] == after.findings[0]["fingerprint"]


def test_same_rule_different_symbols_and_messages_stay_distinct():
    report = _report(
        {
            "danger": [
                _finding(name="app.first"),
                _finding(name="app.second"),
                _finding(name="app.first", message="Different unsafe call"),
            ]
        }
    )
    assert report.complete
    assert len({row["fingerprint"] for row in report.findings}) == 3


def test_repeated_semantic_findings_retain_multiple_locations():
    source = [_finding(line=12), _finding(line=24), _finding(line=24, col=9)]
    before = _report({"danger": source})
    after = _report(
        {"danger": [{**item, "line": item["line"] + 10} for item in source]}
    )
    assert before.complete and after.complete
    assert len(before.findings) == 3
    assert {row["fingerprint"] for row in before.findings} == {
        row["fingerprint"] for row in after.findings
    }


def test_deduplication_and_order_do_not_depend_on_input_order():
    findings = [
        _finding(line=22),
        _finding(line=4),
        _finding(line=4),
        _finding(file="a.py"),
        _finding(line=4, severity="CRITICAL"),
    ]
    report = _report({"danger": findings})
    reversed_report = _report({"danger": list(reversed(findings))})
    assert report.complete
    assert report == reversed_report
    assert len(report.findings) == 3
    assert report.findings[0]["location"]["path"] == "a.py"
    assert report.findings[1]["severity"] == "blocker"


@pytest.mark.parametrize(
    "field,value",
    [
        ("package_name", "another"),
        ("package_version", "1.0.1"),
        ("vuln_id", "GHSA-other-5678"),
        ("ecosystem", "PyPI"),
        ("package_path", "example@1.0.0(peer@3.0.0)"),
        ("dependency_roots", ["packages/other"]),
        ("dependency_dev", False),
        ("dependency_optional", True),
        ("dependency_markers", {"pnpm_usage": ["packages/app|dev"]}),
    ],
)
def test_dependency_identity_keeps_package_advisory_snapshot_and_usage(field, value):
    before = _report({"dependency_vulnerabilities": [_dependency()]})
    after = _report({"dependency_vulnerabilities": [_dependency(**{field: value})]})
    assert before.complete and after.complete
    assert before.findings[0]["fingerprint"] != after.findings[0]["fingerprint"]


def test_dependency_unknown_advisory_is_still_represented():
    finding = _dependency(advisory_status="unavailable", advisory_error="timeout")
    finding["severity"] = "UNKNOWN"
    report = _report({"dependency_vulnerabilities": [finding]})
    assert report.complete
    assert report.findings[0]["severity"] == "major"
    assert "example＠1.0.0" in report.findings[0]["description"]
    assert "severity unknown" in report.findings[0]["description"]


def test_dependency_occurrence_order_and_checkout_do_not_change_identity():
    before = _dependency(
        dependency_occurrences=[
            {
                "file": "/first/project/pnpm-lock.yaml",
                "line": 20,
                "package_path": "example@1.0.0(peer@2.0.0)",
                "dependency_roots": ["b", "a"],
            },
            {
                "file": "/first/project/other/pnpm-lock.yaml",
                "line": 22,
                "package_path": "example@1.0.0(peer@3.0.0)",
            },
        ]
    )
    before["file"] = "/first/project/pnpm-lock.yaml"
    after = deepcopy(before)
    after["file"] = "/second/project/pnpm-lock.yaml"
    after["line"] = 90
    for occurrence in after["metadata"]["dependency_occurrences"]:
        occurrence["file"] = occurrence["file"].replace("/first/", "/second/")
        occurrence["line"] += 50
        if "dependency_roots" in occurrence:
            occurrence["dependency_roots"].reverse()
    after["metadata"]["dependency_occurrences"].reverse()
    old = _report({"dependency_vulnerabilities": [before]}, root="/first/project")
    new = _report({"dependency_vulnerabilities": [after]}, root="/second/project")
    assert old.complete and new.complete
    assert old.findings[0]["fingerprint"] == new.findings[0]["fingerprint"]


def test_uv_array_index_is_not_dependency_identity():
    before = _dependency(ecosystem="PyPI", package_name="example_pkg", package_path="0")
    after = _dependency(ecosystem="PyPI", package_name="example-pkg", package_path="9")
    old = _report({"dependency_vulnerabilities": [before]})
    new = _report({"dependency_vulnerabilities": [after]})
    assert old.complete and new.complete
    assert old.findings[0]["fingerprint"] == new.findings[0]["fingerprint"]


@pytest.mark.parametrize(
    "path",
    [
        "../outside.py",
        "src/../../outside.py",
        "/elsewhere/app.py",
        "/checkout/project-other/app.py",
        "https://example.com/app.py",
        "./https://example.com/app.py",
        "file:///checkout/project/app.py",
        "//server/share/app.py",
        "C:\\outside\\app.py",
        "src\\..\\outside.py",
        "",
        ".",
        "src/",
        " src/app.py",
        "src/app.py ",
        "src/\napp.py",
        "src/\x00app.py",
        "src/\u202eapp.py",
        "/checkout/project/../outside.py",
    ],
)
def test_invalid_locations_are_visible_failures_without_leaking_path(path):
    report = _report({"danger": [_finding(file=path), _finding(file="valid.py")]})
    assert not report.complete
    assert len(report.findings) == 1
    assert report.findings[0]["location"]["path"] == "valid.py"
    assert report.diagnostics == ["Unrepresentable finding in danger."]


@pytest.mark.parametrize(
    "line", [0, -1, True, False, 1.2, "", "0", "1.0", "12x", None, 2**31]
)
def test_explicit_invalid_line_is_not_moved_to_line_one(line):
    report = _report({"danger": [_finding(line=line)]})
    assert not report.complete
    assert not report.findings


def test_numeric_string_line_and_alternative_location_keys():
    report = _report(
        {
            "quality": [
                {
                    "file_path": "src/app.py",
                    "line_number": "14",
                    "code": "CUSTOM-CHECK",
                    "description": "A quality issue",
                }
            ]
        }
    )
    assert report.complete
    assert report.findings[0]["check_name"] == "CUSTOM-CHECK"
    assert report.findings[0]["location"]["lines"]["begin"] == 14


def test_missing_line_is_only_accepted_for_file_level_findings():
    item = _finding()
    del item["line"]
    report = _report({"danger": [item], "unused_files": [{"file": "unused.py"}]})
    assert not report.complete
    assert len(report.findings) == 1
    assert report.findings[0]["location"] == {
        "path": "unused.py",
        "lines": {"begin": 1},
    }


def test_secret_details_and_snippets_are_never_exported():
    secret = "unrecognized-opaque-value-12345"
    item = _finding(
        message=secret,
        name=secret,
        preview=secret,
        snippet=secret,
        source_line=secret,
        line_text=secret,
        metadata={"secret": secret},
    )
    report = _report({"secrets": [item]})
    assert report.complete
    assert secret not in json.dumps(report.findings)
    assert (
        report.findings[0]["description"] == "Potential secret detected (value omitted)"
    )


def test_secret_providers_at_one_location_are_not_collapsed():
    report = _report(
        {
            "secrets": [
                _finding(provider="provider-a"),
                _finding(provider="provider-b"),
            ]
        }
    )
    assert report.complete
    assert len({row["fingerprint"] for row in report.findings}) == 2


def test_non_secret_messages_use_shared_ci_redaction_and_neutralization():
    token = "ghp_" + "A" * 36
    item = _finding(
        message=f"Found {token} at https://user:private@example.com/ @all <script>\x1b[31m"
    )
    report = _report({"danger": [item]})
    assert report.complete
    text = report.findings[0]["description"]
    assert token not in text
    assert "private" not in text
    assert "@all" not in text
    assert "<script>" not in text
    assert "\x1b" not in text


def test_formatter_never_reads_sources_or_resolves_symlinks(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("formatter attempted filesystem access")

    monkeypatch.setattr(Path, "read_text", forbidden)
    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(Path, "resolve", forbidden)
    monkeypatch.setattr("builtins.open", forbidden)
    report = _report({"danger": [_finding(snippet="not exported")]})
    assert report.complete


@pytest.mark.parametrize("value", ["malformed", 42, {}, [None], ["secret-value"]])
def test_malformed_finding_collection_or_item_is_incomplete(value):
    report = _report({"quality": value, "danger": [_finding()]})
    assert not report.complete
    assert len(report.findings) == 1
    assert "secret-value" not in str(report.diagnostics)


@pytest.mark.parametrize("result", [None, [], "bad", 42])
def test_non_object_results_are_incomplete(result):
    report = _report(result)
    assert report == gitlab.GitLabReport([], ["Invalid scan result."], False)


def test_baselined_dependency_findings_are_not_reintroduced():
    report = _report(
        {
            "dependency_vulnerabilities": [_dependency()],
            "baseline_dependency_vulnerabilities": [
                _dependency(package_name="accepted")
            ],
        }
    )
    assert report.complete
    assert len(report.findings) == 1
    assert "accepted" not in json.dumps(report.findings)


@pytest.mark.parametrize(
    "extra",
    [
        {
            "analysis_errors": [
                {"message": "private-value", "file": "/external/private"}
            ]
        },
        {"analysis_summary": {"incomplete_languages": ["private-value"]}},
        {"analysis_summary": {"sca_coverage": {"status": "incomplete"}}},
        {"analysis_summary": {"sca_coverage": {"status": "unavailable"}}},
        {"analysis_summary": {"sca_coverage": {"status": "unknown"}}},
    ],
)
def test_scan_incompleteness_keeps_valid_findings_and_safe_diagnostics(extra):
    report = _report({"danger": [_finding()], **extra})
    assert not report.complete
    assert len(report.findings) == 1
    assert report.diagnostics
    assert "private-value" not in str(report.diagnostics)


@pytest.mark.parametrize(
    "status",
    ["complete", "complete_with_unresolved_versions", "no_supported_manifests"],
)
def test_documented_coverage_limitations_are_not_export_failures(status):
    report = _report(
        {
            "analysis_summary": {
                "sca_coverage": {
                    "status": status,
                    "complete": status != "no_supported_manifests",
                    "category_complete": False,
                }
            }
        }
    )
    assert report.complete


def _nuget_unresolved_coverage():
    return {
        "status": "complete_with_unresolved_versions",
        "complete": False,
        "category_complete": False,
        "unresolved_dependency_count": 1,
        "nuget_unresolved_count": 1,
        "parse_error_count": 0,
        "unresolved_lockfile_dependency_count": 0,
        "query": {"status": "complete", "complete": True},
    }


def test_nuget_coverage_gap_is_not_gitlab_report_failure():
    report = _report(
        {
            "analysis_summary": {"sca_coverage": _nuget_unresolved_coverage()},
            "danger": [_finding()],
        }
    )

    assert report.complete
    assert len(report.findings) == 1
    assert report.diagnostics == []


@pytest.mark.parametrize(
    "change",
    [
        {"unresolved_dependency_count": 0},
        {"nuget_unresolved_count": 0},
        {"parse_error_count": 1},
        {"query": {"status": "incomplete", "complete": False}},
        {"limit_reasons": ["manifest_count_limit_exceeded"]},
    ],
)
def test_spoofed_nuget_coverage_gap_is_not_clean_report(change):
    coverage = {**_nuget_unresolved_coverage(), **change}
    report = _report({"analysis_summary": {"sca_coverage": coverage}})

    assert not report.complete
    assert "Invalid dependency analysis completion receipt." in report.diagnostics


def test_output_limit_retains_bounded_findings_and_reports_incomplete(monkeypatch):
    monkeypatch.setattr(gitlab, "MAX_FINDINGS", 2)
    report = _report({"danger": [_finding(line=line) for line in (1, 2, 3)]})
    assert not report.complete
    assert len(report.findings) == 2
    assert any("Report finding limit" in message for message in report.diagnostics)


def test_input_limit_also_applies_across_categories(monkeypatch):
    monkeypatch.setattr(gitlab, "MAX_INPUT_FINDINGS", 2)
    report = _report(
        {"danger": [_finding()], "quality": [_finding(line=2), _finding(line=3)]}
    )
    assert not report.complete
    assert len(report.findings) == 2
    assert any("Finding input limit" in message for message in report.diagnostics)


def test_long_description_is_bounded_and_truncation_visible():
    report = _report({"danger": [_finding(message="x" * 2500)]})
    assert not report.complete
    assert len(report.findings) == 1
    assert len(report.findings[0]["description"]) <= gitlab.MAX_DESCRIPTION_LENGTH
    assert any("Description limit" in message for message in report.diagnostics)


def test_report_byte_limit_is_visible(monkeypatch):
    monkeypatch.setattr(gitlab, "MAX_REPORT_BYTES", 5)
    report = _report({"danger": [_finding()]})
    assert not report.complete
    assert not report.findings
    assert any("Report byte limit" in message for message in report.diagnostics)


def test_empty_sanitized_rule_or_message_cannot_produce_invalid_rows():
    report = _report(
        {
            "danger": [
                _finding(rule_id="\x00"),
                _finding(message="\x00"),
            ]
        }
    )
    assert not report.complete
    assert not report.findings


def test_untrusted_status_type_does_not_crash_conversion():
    report = _report({"analysis_summary": {"sca_coverage": {"status": []}}})
    assert report.findings == []
    assert not report.complete


@pytest.mark.parametrize(
    "summary",
    [
        [],
        "invalid",
        {"sca_coverage": []},
        {"sca_coverage": {"status": "complete", "complete": False}},
        {"sca_coverage": {"status": "complete", "complete": 1}},
    ],
)
def test_malformed_completion_receipts_are_not_clean(summary):
    report = _report({"analysis_summary": summary, "danger": [_finding()]})
    assert not report.complete
    assert len(report.findings) == 1


@pytest.mark.parametrize(
    "coverage",
    [
        {"complete": False},
        {"complete": False, "status": "failed"},
        {"status": "unexpected"},
        {"complete": True},
        {"status": "complete"},
        {"status": "complete_with_unresolved_versions"},
        {"status": "no_supported_manifests"},
        {"complete": True, "status": "no_supported_manifests"},
        {"complete": True, "status": "incomplete"},
        {"complete": True, "status": "unavailable"},
        {"complete": True, "status": "unknown"},
        {"complete": False, "status": "complete_with_unresolved_versions"},
        {},
        None,
    ],
)
def test_unknown_missing_or_inconsistent_sca_completion_fields_fail_closed(coverage):
    report = _report(
        {
            "analysis_summary": {"sca_coverage": coverage},
            "danger": [_finding()],
        }
    )
    assert not report.complete
    assert len(report.findings) == 1
    assert "Invalid dependency analysis completion receipt." in report.diagnostics


@pytest.mark.parametrize("status", ["incomplete", "unavailable", "unknown"])
def test_native_operational_failure_receipts_are_incomplete(status):
    report = _report(
        {
            "analysis_summary": {"sca_coverage": {"status": status, "complete": False}},
            "dependency_vulnerabilities": [_dependency()],
        }
    )
    assert not report.complete
    assert len(report.findings) == 1
    assert report.diagnostics == ["Dependency vulnerability analysis is incomplete."]


def test_invalid_project_root_is_incomplete():
    report = _report({}, root="/root/\x00bad")
    assert not report.complete
    assert report.diagnostics == ["Invalid project root."]


def test_cyclic_or_oversized_dependency_context_is_bounded():
    cycle = {}
    cycle["cycle"] = cycle
    report = _report(
        {
            "dependency_vulnerabilities": [
                _dependency(dependency_markers=cycle),
                _dependency(dependency_roots=["root"] * 257),
            ]
        }
    )
    assert not report.complete
    assert not report.findings


def test_external_dependency_occurrence_is_not_silently_hashed():
    report = _report(
        {
            "dependency_vulnerabilities": [
                _dependency(
                    dependency_occurrences=[
                        {"file": "../outside/pnpm-lock.yaml"},
                    ]
                )
            ]
        }
    )
    assert not report.complete
    assert not report.findings


def test_input_is_not_modified():
    result = {"dependency_vulnerabilities": [_dependency()], "danger": [_finding()]}
    original = deepcopy(result)
    _report(result)
    assert result == original
