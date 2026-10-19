"""Annotation advice requires policy or requested, proven API coverage."""

import ast
import io
import json
import textwrap

import pytest

from test.fixture_paths import write_fixture
from rich.console import Console

from skylos.analysis.file_processing import scan_python_quality
from skylos.config import load_config
from skylos.rules.quality.practices import TypeAnnotationPracticeRule
from skylos.reporting.typing_coverage import typing_coverage_text


def run_rule(tmp_path, source, *, policy="", coverage=False, filename="api.py"):
    if policy:
        write_fixture(tmp_path, "pyproject.toml", textwrap.dedent(policy), overwrite=True)
    source = textwrap.dedent(source)
    context = {
        "filename": str(tmp_path / filename),
        "project_root": tmp_path,
        "source": source,
    }
    findings = TypeAnnotationPracticeRule(coverage_advice=coverage).visit_node(
        ast.parse(source), context
    ) or []
    return findings, context.get("annotation_coverage", {})


@pytest.mark.parametrize("checker", ["", "[tool.mypy]\ncheck_untyped_defs = true\n"])
def test_partial_annotations_are_statistics_without_an_enforcement_policy(tmp_path, checker):
    findings, coverage = run_rule(
        tmp_path,
        "def resolve(value: str, context): return value\n",
        policy=checker,
    )
    assert findings == []
    assert coverage["definition_count"] == 1
    assert coverage["missing_parameter_annotations"] == 1
    assert coverage["missing_return_annotations"] == 1
    assert coverage["unreported_missing_definitions"] == 1


@pytest.mark.parametrize("setting", ["strict = true", "disallow_untyped_defs = true"])
def test_declared_requirements_preserve_both_low_priority_findings(tmp_path, setting):
    findings, coverage = run_rule(
        tmp_path,
        "def public(value): return value\n",
        policy=f'[tool.mypy]\nfiles = ["api.py"]\n{setting}\n',
    )
    assert [row["rule_id"] for row in findings] == ["SKY-T101", "SKY-T102"]
    assert all(row["severity"] == "LOW" for row in findings)
    assert coverage["unreported_missing_definitions"] == 0


def test_partial_only_policy_does_not_require_wholly_untyped_definitions(tmp_path):
    findings, _ = run_rule(
        tmp_path,
        """
        def partial(value: str, context): return value
        def dynamic(value, context): return value
        """,
        policy='[tool.mypy]\nfiles = ["api.py"]\ndisallow_incomplete_defs = true\n',
    )
    assert [(row["rule_id"], row["name"]) for row in findings] == [
        ("SKY-T101", "partial"), ("SKY-T102", "partial")
    ]


def test_requirement_outside_selected_path_cannot_trigger_advice(tmp_path):
    findings, coverage = run_rule(
        tmp_path,
        "def public(value: str, context): return value\n",
        policy='[tool.mypy]\nfiles = ["other.py"]\nstrict = true\n',
    )
    assert findings == []
    assert coverage["unreported_missing_definitions"] == 1


@pytest.mark.parametrize(
    "settings, source",
    [
        (
            'include = ["api.py", "tests/pipeline.py"]\n'
            'strict = ["tests/pipeline.py"]\n',
            "def resolve(value: int): return value\n",
        ),
        (
            'typeCheckingMode = "strict"\n',
            "def resolve(value: int): return value\n",
        ),
        (
            'reportMissingParameterType = "error"\n',
            "def resolve(value: int): return value\n",
        ),
        (
            'reportUnknownParameterType = "error"\n',
            "def resolve(value=0): return value\n",
        ),
    ],
)
def test_inferred_types_do_not_establish_missing_annotation_requirements(
    tmp_path, settings, source
):
    # Pyright can infer these returns. Its strict/missing-parameter settings
    # cannot establish T102; Unknown-only diagnostics also accept known defaults.
    findings, coverage = run_rule(
        tmp_path, source, policy="[tool.pyright]\n" + settings
    )
    assert findings == []
    assert coverage["missing_return_annotations"] == 1
    assert coverage["definitions_missing_annotations"] == 1


def test_requested_coverage_requires_a_real_export_boundary(tmp_path):
    findings, coverage = run_rule(
        tmp_path,
        """
        __all__ = ["published"]
        def published(value): return value
        def looks_public(value: str): return value
        """,
        coverage=True,
    )
    assert {(row["rule_id"], row["name"]) for row in findings} == {
        ("SKY-T101", "published"), ("SKY-T102", "published")
    }
    assert coverage["definition_count"] == 1


def test_public_spelling_and_unknown_exports_do_not_establish_an_api(tmp_path):
    findings, coverage = run_rule(
        tmp_path,
        "__all__ = discover_exports()\ndef looks_public(value: str): return value\n",
        coverage=True,
    )
    assert findings == []
    assert coverage["definitions_missing_annotations"] == 1


def test_opt_in_cannot_override_explicit_acceptance_of_partial_signatures(tmp_path):
    findings, _ = run_rule(
        tmp_path,
        '__all__ = ["published"]\ndef published(value: str, context): return value\n',
        policy='[tool.mypy]\nfiles = ["api.py"]\nallow_incomplete_defs = true\n',
        coverage=True,
    )
    assert findings == []


OVERLOAD_SOURCE = """
    from typing import overload
    __all__ = ["convert"]
    @overload
    def convert(value: str) -> str: ...
    @overload
    def convert(value: int) -> int: ...
    def convert(value): return value
"""


def test_supplied_overload_contract_avoids_duplicate_optional_coverage(tmp_path):
    findings, coverage = run_rule(tmp_path, OVERLOAD_SOURCE, coverage=True)
    assert findings == []
    assert coverage["definitions_with_supplied_contract"] == 3
    assert coverage["definitions_missing_annotations"] == 1


def test_explicit_requirement_still_applies_to_overload_implementation(tmp_path):
    findings, _ = run_rule(
        tmp_path,
        OVERLOAD_SOURCE,
        coverage=True,
        policy='[tool.mypy]\nfiles = ["api.py"]\nstrict = true\n',
    )
    assert [row["rule_id"] for row in findings] == ["SKY-T101", "SKY-T102"]
    assert all(row["line"] == 8 for row in findings)


def test_configuration_opt_in_reaches_the_real_quality_builder(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[tool.skylos]\ntyping_coverage_advice = true\n"
    )
    source = '__all__ = ["published"]\ndef published(value): return value\n'
    stats = {}
    findings = scan_python_quality(
        ast.parse(source), source, tmp_path / "api.py", load_config(tmp_path),
        project_root=tmp_path, annotation_coverage=stats,
    )
    assert {row["rule_id"] for row in findings if row["rule_id"].startswith("SKY-T10")} == {
        "SKY-T101", "SKY-T102"
    }
    assert stats["definition_count"] == 1


def test_coverage_opt_in_configuration_requires_a_boolean(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos]\ntyping_coverage_advice = "yes"\n'
    )
    assert load_config(tmp_path)["typing_coverage_advice"] is False


def test_end_to_end_default_has_coverage_without_annotation_findings(tmp_path):
    from skylos.analyzer import analyze

    (tmp_path / "api.py").write_text("def public(value: str, context): return value\n")
    report = json.loads(analyze(
        str(tmp_path), enable_quality=True, enable_danger=False, enable_secrets=False,
        grep_verify=False, grep_cache=False, trace_file=False,
    ))
    assert not [row for row in report.get("quality", []) if row["rule_id"] in {"SKY-T101", "SKY-T102"}]
    coverage = report["analysis_summary"]["typing_coverage"]
    assert coverage["definition_count"] == 1
    assert coverage["definitions_missing_annotations"] == 1
    assert coverage["unreported_missing_definitions"] == 1


@pytest.mark.parametrize("renderer", ["pretty", "rich"])
def test_statistics_are_visible_even_without_findings(renderer):
    from skylos.ui.rich_report import render_results
    from skylos.ui.terminal_report import render_pretty_results
    from skylos.cli import _skylos_console_theme

    output = io.StringIO()
    console = Console(file=output, width=180, color_system=None, theme=_skylos_console_theme())
    summary = {"total_files": 1, "typing_coverage": {
        "definition_count": 1, "definitions_with_complete_annotations": 0,
        "definitions_missing_annotations": 1,
    }}
    report = {"analysis_summary": summary, "quality": []}
    if renderer == "pretty":
        render_pretty_results(console, report)
    else:
        render_results(console, report)
    assert "Public signature annotations: 0/1 complete, 1 incomplete" in output.getvalue()
    assert "coverage statistics; not type errors" in output.getvalue()


def test_malformed_statistics_do_not_create_a_summary():
    assert typing_coverage_text({"typing_coverage": {
        "definition_count": True, "definitions_with_complete_annotations": 0,
        "definitions_missing_annotations": 1,
    }}) == ""


def test_parameter_and_return_advice_share_one_entry_without_losing_raw_records(tmp_path):
    import copy
    from skylos.reporting.advice_display import advice_display, combine_advice
    from skylos.reporting.finding_types import iter_result_findings

    rows, _ = run_rule(
        tmp_path, '__all__ = ["published"]\ndef published(value): return value\n',
        coverage=True,
    )
    report = {"quality": rows, "gate": {"quality_count": 2}}
    original = copy.deepcopy(report)
    combined = combine_advice(iter_result_findings(report))
    assert len(combined) == 1
    metadata = advice_display(combined[0][1])
    assert metadata.name == "Function annotations"
    assert list(metadata.findings) == rows
    assert all(row["message"] in metadata.message for row in rows)
    assert report == original


@pytest.mark.parametrize("required", [False, True])
def test_coverage_statistics_cannot_fail_a_gate_but_required_annotations_can(tmp_path, required):
    from skylos.core.gatekeeper import check_gate

    policy = (
        '[tool.mypy]\nfiles = ["api.py"]\ndisallow_untyped_defs = true\n'
        if required else "[tool.mypy]\ncheck_untyped_defs = true\n"
    )
    rows, stats = run_rule(tmp_path, "def public(value: str, context): return value\n", policy=policy)
    report = {"quality": rows, "analysis_summary": {"typing_coverage": stats}}
    passed, _ = check_gate(report, {"gate": {"max_quality": 0}})
    assert passed is not required
    assert stats["definitions_missing_annotations"] == 1


def test_coverage_inventory_is_not_counted_as_an_individual_finding(tmp_path):
    from skylos.reporting.finding_types import iter_result_findings

    rows, stats = run_rule(tmp_path, "def public(value: str, context): return value\n")
    assert list(iter_result_findings({"quality": rows, "analysis_summary": {"typing_coverage": stats}})) == []
