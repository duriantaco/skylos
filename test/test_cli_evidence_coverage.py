import copy
from io import StringIO

import pytest
from rich.console import Console

from skylos import cli
from skylos.core.gatekeeper import check_gate
from skylos.reporting.assessment import compute_assessment
from skylos.reporting.assessment_display import dependency_coverage_lines
from skylos.ui.quality_advice import pytest_signature_advice
from skylos.ui.rich_report import render_results
from skylos.ui.security_evidence import security_evidence_details
from skylos.ui.terminal_report import render_pretty_results


def _render(result, renderer, width=120):
    buffer = StringIO()
    console = Console(
        file=buffer,
        width=width,
        force_terminal=False,
        theme=cli._skylos_console_theme(),
    )
    kwargs = {"expand_advice": True}
    if renderer is render_results:
        kwargs["copy_badge"] = False
    renderer(console, result, **kwargs)
    return " ".join(buffer.getvalue().replace("│", " ").split())


def _finding():
    return {
        "rule_id": "SKY-D211",
        "severity": "CRITICAL",
        "file": "app.py",
        "line": 11,
        "message": "Possible SQL injection",
        "metadata": {
            "security_evidence": {
                "evidence_kind": "python_sql_taint",
                "source": "request data `request.args.get`",
                "sources": ["request data `request.args.get`", "request JSON"],
                "sink": "SQL text passed to .execute()",
                "path": ["customer", "query", "execute"],
                "guards_seen": [],
                "guards_missing": ["parameterized SQL binding"],
                "analysis_complete": False,
            }
        },
    }


@pytest.mark.parametrize("renderer", [render_results, render_pretty_results])
@pytest.mark.parametrize("width", [80, 120])
def test_human_security_output_keeps_real_sources_and_partial_scope(renderer, width):
    result = {"danger": [_finding()], "analysis_summary": {"total_files": 1}}
    before = copy.deepcopy(result)
    gate_before = check_gate(result, {"gate": {"max_critical": 0}})
    output = _render(result, renderer, width)
    for fact in (
        "Static source:",
        "request.args.get",
        "request JSON",
        "Static sink:",
        ".execute()",
        "Recorded path:",
        "parameterized SQL binding",
        "partial static analysis",
    ):
        assert fact in output
    assert "HIGH confidence" not in output
    assert result == before
    assert gate_before == check_gate(result, {"gate": {"max_critical": 0}})
    assert gate_before[0] is False


@pytest.mark.parametrize("complete", [True, None])
def test_static_evidence_does_not_claim_runtime_verification(complete):
    finding = _finding()
    evidence = finding["metadata"]["security_evidence"]
    if complete is None:
        evidence.pop("analysis_complete")
    else:
        evidence["analysis_complete"] = complete
    assert (
        security_evidence_details(finding)[-1]
        == "Evidence scope: static observations; runtime exploitability is not verified"
    )


def test_missing_or_malformed_evidence_does_not_invent_a_flow():
    for finding in (
        {},
        {"metadata": {"security_evidence": {"evidence_kind": "unknown"}}},
        {"security_evidence": "bad"},
    ):
        assert security_evidence_details(finding) == []


def test_evidence_display_is_bounded_and_redacts_controls_and_secrets():
    # Synthetic redaction input, never a credential issued by a provider.
    sample_key = "sk_" + "live_" + "123456" * 4
    finding = _finding()
    evidence = finding["metadata"]["security_evidence"]
    evidence["source"] = "ignored source"
    evidence["sources"] = [
        "\x1b[31m api_key=" + sample_key,
        "b",
        "c",
        "d",
        "e",
        "f",
    ]
    evidence["path"] = ["step" * 1000]
    output = "\n".join(security_evidence_details(finding))
    assert "\x1b" not in output
    assert sample_key not in output
    assert "ignored source" in output
    assert "+3 more in JSON" in output
    assert len(output) < 1600


def test_evidence_preserves_a_distinct_primary_source_and_deduplicates_sources():
    finding = _finding()
    finding["metadata"]["security_evidence"]["sources"] = [
        "request JSON",
        "request JSON",
        "cookie data",
    ]
    source_line = security_evidence_details(finding)[0]
    assert source_line == (
        "Static source: request data `request.args.get`; request JSON; cookie data"
    )


def _sca_summary():
    return {
        "total_files": 1,
        "grade_categories": ["dependencies"],
        "sca_coverage": {
            "complete": True,
            "status": "complete_with_unresolved_versions",
            "category_complete": False,
            "queried_dependency_count": 0,
            "supported_lockfile_count": 0,
            "unresolved_dependency_count": 4,
            "parse_error_count": 0,
            "unresolved_lockfile_dependency_count": 0,
            "unsupported_lockfile_count": 0,
        },
    }


@pytest.mark.parametrize("renderer", [render_results, render_pretty_results])
def test_manifest_only_sca_output_explains_the_unknown_result_and_next_step(renderer):
    result = {"analysis_summary": _sca_summary()}
    result["assessment"] = compute_assessment(result)
    before = copy.deepcopy(result)
    output = _render(result, renderer)
    for fact in (
        "0 packages queried",
        "0 supported lockfiles read",
        "4 manifest versions unresolved",
        "provide a supported lockfile",
        "version ranges are not resolved",
        "runtime reachability are not verified",
    ):
        assert fact in output
    assert result["assessment"]["risk"]["status"] == "unknown"
    assert result == before
    assert "SBOM import" not in output


def test_sca_failures_get_distinct_parse_and_retry_instructions_without_fake_counts():
    lines = dependency_coverage_lines(
        {"sca_coverage": {"parse_error_count": 1, "query": {"complete": False}}}
    )
    output = " ".join(lines)
    assert "1 parse errors" in output
    assert "inspect sca_coverage" in output
    assert "retry failed requests after advisory-service access is restored" in output
    assert "0 packages" not in output
    assert dependency_coverage_lines({}) == []


@pytest.mark.parametrize("renderer", [render_results, render_pretty_results])
@pytest.mark.parametrize(
    "rule,value,name",
    [
        ("SKY-C303", 8, "test_mod.test_refund"),
        ("SKY-L029", "expected", "test_mod.test_retry.expected"),
    ],
)
def test_signature_advice_explains_injection_without_dropping_test_findings(
    renderer, rule, value, name
):
    row = {
        "rule_id": rule,
        "severity": "LOW",
        "file": "tests/test_billing.py",
        "line": 20,
        "name": name,
        "value": value,
        "threshold": 5,
        "simple_name": "expected",
        "message": "Use keyword-only arguments instead.",
    }
    result = {"quality": [row], "analysis_summary": {"total_files": 1}}
    before = copy.deepcopy(result)
    output = _render(result, renderer)
    assert "If pytest supplies these inputs" in output
    assert "review test setup and case clarity" in output
    assert "Use keyword-only arguments instead." not in output
    assert rule in output
    assert result == before
    assert check_gate(result, {"gate": {"max_quality": 0}})[0] is False
    row["name"] = "helpers.process.expected"
    assert "Use keyword-only arguments instead." in _render(result, renderer)


@pytest.mark.parametrize(
    "rule,name",
    [
        ("SKY-C303", "test_billing.helpers.process"),
        ("SKY-L029", "test_billing.helpers.process.expected"),
    ],
)
def test_python_test_module_name_does_not_relabel_an_ordinary_helper(rule, name):
    assert (
        pytest_signature_advice(
            {
                "rule_id": rule,
                "file": "tests/test_billing.py",
                "name": name,
            }
        )
        == ""
    )


@pytest.mark.parametrize("file", ["tests/test_billing.ts", "tests/test_billing.js"])
def test_non_python_test_functions_do_not_receive_pytest_advice(file):
    assert (
        pytest_signature_advice(
            {
                "rule_id": "SKY-C303",
                "file": file,
                "name": "test_refund",
            }
        )
        == ""
    )
