"""Coverage disclosures do not certify skipped dependencies or erase failures."""

from copy import deepcopy
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from skylos import cli
from skylos.api._scan_coverage import _dependency_coverage_complete
from skylos.cloud.gitlab import scan_receipt
from skylos.core.gatekeeper import check_gate, run_gate_interaction
from skylos.core.sca_baseline import dependency_scan_complete, dependency_snapshot
from skylos.core.sca_coverage import (
    NON_REGISTRY_COVERAGE_STATUS,
    valid_non_registry_sca_receipt,
)
from skylos.reporting.assessment import compute_assessment
from skylos.reporting.github_annotations import _emit_github_annotations
from skylos.reporting.gitlab import build_gitlab_report
from skylos.reporting.llm_report import _generate_llm_report
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results


def _coverage():
    return {
        "status": NON_REGISTRY_COVERAGE_STATUS,
        "complete": False,
        "category_complete": False,
        "supported_lockfile_count": 1,
        "queried_dependency_count": 1,
        "not_checked_lockfile_dependency_count": 1,
        "non_registry_lockfile_dependency_count": 1,
        "parse_error_count": 0,
        "unresolved_dependency_count": 0,
        "unresolved_lockfile_dependency_count": 0,
        "lockfile_issues": [],
        "lockfile_not_checked": [
            {
                "file": "/checkout/project/uv.lock",
                "line": 3,
                "name": "git-package",
                "package": "git-package",
                "reason": "non_registry_source",
                "source_type": "git",
            }
        ],
        "query": {
            "status": "complete",
            "complete": True,
            "requested_batches": 1,
            "successful_batches": 1,
            "failed_batches": 0,
            "advisory_context_error_count": 0,
            "advisory_details": {
                "status": "complete",
                "complete": True,
                "unique_id_count": 0,
                "requested_count": 0,
                "successful_count": 0,
                "failed_count": 0,
                "skipped_count": 0,
                "deadline_exceeded": False,
                "total_size_exceeded": False,
            },
        },
    }


def _result(coverage=None):
    return {
        "analysis_errors": [],
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["dependencies"],
            "analysis_error_count": 0,
            "sca_coverage": _coverage() if coverage is None else coverage,
        },
    }


def test_completed_public_queries_allow_gate_but_never_dependency_resolution(tmp_path):
    result = _result()
    before = deepcopy(result)
    assert valid_non_registry_sca_receipt(result["analysis_summary"]["sca_coverage"])
    assert check_gate(result, {}) == (True, [])
    assert check_gate(result, {}, strict=True) == (True, [])
    assert run_gate_interaction(result=result, config={}) == 0
    assert build_gitlab_report(result, project_root=tmp_path).complete
    assert scan_receipt(result, analyzer_owned=True, full_scan=True) == {
        "complete": True,
        "full_scan": False,
    }
    assert not dependency_scan_complete(result)
    assert dependency_snapshot(result, tmp_path) is None
    assert not _dependency_coverage_complete(result["analysis_summary"])
    assert compute_assessment(result)["risk"]["status"] == "unknown"
    assert result == before


@pytest.mark.parametrize("kind", ["git", "path", "url", "registry"])
def test_known_source_kinds_remain_coverage_limits(kind):
    coverage = _coverage()
    entry = coverage["lockfile_not_checked"][0]
    entry["source_type"] = kind
    if kind == "registry":
        entry["reason"] = "non_public_registry"
    assert valid_non_registry_sca_receipt(coverage)


def test_no_public_packages_is_operationally_complete_without_fabricated_batches():
    coverage = _coverage()
    coverage["queried_dependency_count"] = 0
    coverage["query"] = {
        "status": "complete",
        "complete": True,
        "requested_batches": 0,
        "failed_batches": 0,
    }
    assert check_gate(_result(coverage), {}) == (True, [])


_CONTRADICTIONS = [
    ((), "complete", True),
    ((), "category_complete", True),
    ((), "non_registry_lockfile_dependency_count", 0),
    ((), "non_registry_lockfile_dependency_count", True),
    ((), "non_registry_lockfile_dependency_count", 2),
    ((), "not_checked_lockfile_dependency_count", -1),
    ((), "parse_error_count", 1),
    ((), "unresolved_lockfile_dependency_count", 1),
    ((), "limit_reasons", ["max_files"]),
    ((), "lockfile_not_checked", []),
    ((), "lockfile_issues", [{"reason": "unsupported_package_source"}]),
    (("lockfile_not_checked", 0), "reason", "unsupported_package_source"),
    (("lockfile_not_checked", 0), "source_type", "unknown"),
    (("lockfile_not_checked", 0), "source_type", []),
    (("lockfile_not_checked", 0), "file", "poetry.lock"),
    (("query",), "status", "incomplete"),
    (("query",), "complete", False),
    (("query",), "requested_batches", True),
    (("query",), "successful_batches", 0),
    (("query",), "failed_batches", 1),
    (("query",), "advisory_context_error_count", 1),
    (("query",), "limit_reasons", ["response_size"]),
    (("query", "advisory_details"), "complete", False),
    (("query", "advisory_details"), "failed_count", 1),
    (("query", "advisory_details"), "skipped_count", 1),
    (("query", "advisory_details"), "requested_count", 1),
    (("query", "advisory_details"), "unique_id_count", 1),
    (("query", "advisory_details"), "deadline_exceeded", True),
    (("query", "advisory_details"), "total_size_exceeded", True),
]


@pytest.mark.parametrize("path,key,value", _CONTRADICTIONS)
def test_forged_source_or_failed_query_receipts_fail_closed(path, key, value, tmp_path):
    coverage = _coverage()
    target = coverage
    for part in path:
        target = target[part]
    target[key] = value
    result = _result(coverage)
    assert not valid_non_registry_sca_receipt(coverage)
    assert check_gate(result, {})[0] is False
    assert (
        run_gate_interaction(result=result, config={}, force=True, advisory=True) == 2
    )
    assert (
        cli._concise_scan_exit_code(result, {}, SimpleNamespace(gate=False, force=True))
        == 2
    )
    assert not build_gitlab_report(result, project_root=tmp_path).complete
    assert scan_receipt(result, analyzer_owned=True, full_scan=True) == {
        "complete": False,
        "full_scan": False,
    }


def test_missing_operational_query_counts_are_not_a_completion_proof():
    coverage = _coverage()
    coverage["query"] = {"status": "complete", "complete": True}
    assert not valid_non_registry_sca_receipt(coverage)
    assert check_gate(_result(coverage), {})[0] is False


def _render(result, renderer):
    buffer = StringIO()
    console = Console(
        file=buffer,
        width=160,
        force_terminal=False,
        theme=cli._skylos_console_theme(),
    )
    if renderer is render_results:
        renderer(console, result, copy_badge=False)
    else:
        renderer(console, result)
    return " ".join(buffer.getvalue().replace("│", " ").split())


@pytest.mark.parametrize("renderer", [render_results, render_pretty_results])
@pytest.mark.parametrize("with_assessment", [False, True])
def test_human_no_finding_output_discloses_sources_with_or_without_assessment(
    renderer,
    with_assessment,
):
    result = _result()
    if with_assessment:
        result["assessment"] = compute_assessment(result)
    before = deepcopy(result)
    output = _render(result, renderer)
    assert "1 packages queried" in output
    assert "1 lockfile entries not checked" in output
    assert "git-package (Git)" in output
    assert "vulnerability status is unknown" in output
    assert "runtime reachability are not verified" in output
    assert output.count("Dependency coverage limitation:") == 1
    assert "A+" not in output
    assert result == before


def test_llm_concise_and_github_disclose_limits_without_fabricating_findings(capsys):
    result = _result()
    before = deepcopy(result)
    markdown = _generate_llm_report(result, Path("/checkout/project"))
    concise = cli._format_concise_results(result, limit=0)
    _emit_github_annotations(result, max_annotations=0, severity_filter="CRITICAL")
    annotations = capsys.readouterr().out
    for output in (markdown, concise, annotations):
        assert "not checked" in output
        assert "git-package (Git)" in output
        assert "vulnerability status is unknown" in output
    assert markdown.endswith("No findings.\n")
    assert annotations.count("::notice title=Skylos Dependency Coverage::") == 1
    assert "::error" not in annotations
    assert not cli._has_concise_findings(result)
    assert (
        cli._concise_scan_exit_code(
            result, {}, SimpleNamespace(gate=False, force=False)
        )
        == 0
    )
    assert result == before


def test_source_samples_are_bounded_and_do_not_echo_origins_or_command_data(capsys):
    coverage = _coverage()
    coverage["non_registry_lockfile_dependency_count"] = 40
    coverage["not_checked_lockfile_dependency_count"] = 40
    origin = "https://user:example-token@private.example/repo"
    coverage["lockfile_not_checked"] = [
        {"name": origin, "source_type": "git", "reason": "non_registry_source"},
        {
            "name": "bad%0A::error",
            "source_type": "git",
            "reason": "non_registry_source",
        },
        {"name": "safe", "source_type": [], "reason": "non_registry_source"},
        {"name": "safe", "source_type": "git", "reason": []},
        *[
            {
                "name": f"package-{i}",
                "reason": "non_registry_source",
                "source_type": "git",
                "source_url": origin,
            }
            for i in range(40)
        ],
    ]
    result = _result(coverage)
    _emit_github_annotations(result)
    output = capsys.readouterr().out
    assert origin not in output
    assert "example-token" not in output
    assert "::error" not in output
    assert "package-0 (Git)" in output
    assert "package-4 (Git)" in output
    assert "package-5 (Git)" not in output
    assert "35 more entries" in output
    assert len(output.splitlines()) == 1


def test_github_coverage_notice_escapes_percent(monkeypatch, capsys):
    monkeypatch.setattr(
        "skylos.reporting.assessment_display.dependency_coverage_lines",
        lambda _summary: ["not checked 100%\r\n::error::forged"],
    )
    _emit_github_annotations(_result())
    assert capsys.readouterr().out == (
        "::notice title=Skylos Dependency Coverage::not checked 100%25%0D%0A::error::forged\n"
    )


def test_detected_public_dependency_cve_still_blocks_and_exports(tmp_path):
    result = _result()
    result["dependency_vulnerabilities"] = [
        {
            "rule_id": "SKY-SCA-CVE-example",
            "severity": "HIGH",
            "file": str(tmp_path / "uv.lock"),
            "line": 7,
            "message": "Known dependency advisory",
            "metadata": {
                "package_name": "public-package",
                "package_version": "1.0.0",
                "ecosystem": "PyPI",
                "vuln_id": "CVE-example",
            },
        }
    ]
    assert check_gate(result, {}, strict=True)[0] is False
    assert run_gate_interaction(result=result, config={}, strict=True) == 1
    report = build_gitlab_report(result, project_root=tmp_path)
    assert report.complete
    assert len(report.findings) == 1
    assert report.findings[0]["severity"] == "critical"
    assert report.findings[0]["location"]["lines"]["begin"] == 7
