"""Human complexity summaries retain both independent detector results."""

import copy
import ast
import re
from pathlib import Path

import pytest
from rich.console import Console

from skylos.cli import _skylos_console_theme
from skylos.reporting.finding_types import (
    annotate_finding_types,
    summarize_finding_types,
)
from skylos.reporting.llm_report import _generate_llm_report
from skylos.rules.quality.complexity import CognitiveComplexityRule, ComplexityRule
from skylos.rules.quality.nesting import NestingRule
from skylos.rules.quality.structure import FunctionLengthRule
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import collect_pretty_findings, render_pretty_results


def _finding(rule, *, name="branchy_handler", line=8):
    cognitive = rule == "SKY-Q306"
    return {
        "rule_id": rule,
        "kind": "complexity",
        "type": "function",
        "severity": "HIGH",
        "name": name,
        "simple_name": name,
        "file": "/example/app.py",
        "line": line,
        "value": 23 if cognitive else 12,
        "threshold": 15 if cognitive else 10,
        "message": "Cognitive complexity is 23 (threshold: 15)."
        if cognitive
        else "Cyclomatic complexity is 12 (threshold: 10).",
        "evidence": [{"metric_source": "cognitive" if cognitive else "branches"}],
        "standard_refs": [
            "SonarQube S3776" if cognitive else "McCabe Cyclomatic Complexity"
        ],
        "ai_authored": None,
        "ai_declared": False,
        "attribution_level": "unknown",
    }


def _result(*rows):
    result = {
        "analysis_summary": {"total_files": 1, "total_loc": 30},
        "quality": list(rows),
        "analysis_errors": [],
        "grade": {
            "overall": {"score": 80, "letter": "B"},
            "categories": {},
            "scanned_categories": ["quality"],
        },
        "gate": {
            "passed": False,
            "verdict": "failed",
            "exit_code": 1,
            "reasons": ["2 quality issues exceeds 0"],
        },
    }
    # Real CLI scan results are classified before a renderer receives them.
    return annotate_finding_types(result)


def _render(kind, result, *, expand=False, limit=None, all_advice=False):
    if kind == "llm":
        return _generate_llm_report(
            result, Path("/example"), expand_advice=expand, all_advice=all_advice
        )
    console = Console(
        record=True, width=400, color_system=None, theme=_skylos_console_theme()
    )
    if kind == "pretty":
        render_pretty_results(
            console,
            result,
            root_path=Path("/example"),
            expand_advice=expand,
            limit=limit,
            all_advice=all_advice,
        )
    else:
        render_results(
            console,
            result,
            root_path=Path("/example"),
            expand_advice=expand,
            tree=kind == "tree",
            limit=limit,
            copy_badge=False,
            all_advice=all_advice,
        )
    return console.export_text()


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree", "llm"])
@pytest.mark.parametrize("expand", [False, True])
def test_paired_metrics_display_once_and_leave_full_report_unchanged(kind, expand):
    result = _result(_finding("SKY-Q301"), _finding("SKY-Q306"))
    before = copy.deepcopy(result)

    text = _render(kind, result, expand=expand)

    assert result == before
    assert summarize_finding_types(result)["advice"] == 2
    assert "1 advice entry (2 findings) in 1 group" in text
    assert "SKY-Q301" in text and "SKY-Q306" in text
    if expand:
        assert re.search(r"cyclomatic[^\n]*12", text, re.IGNORECASE)
        assert re.search(r"cognitive[^\n]*23", text, re.IGNORECASE)
        assert "10" in text and "15" in text
        if kind == "llm":
            assert len(re.findall(r"^## \d+\.", text, re.MULTILINE)) == 1
            assert '"metric_source": "branches"' in text
            assert '"metric_source": "cognitive"' in text
        else:
            assert text.count("branchy_handler") == 1


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree"])
def test_limit_one_keeps_both_metrics_in_combined_entry(kind):
    result = _result(_finding("SKY-Q301"), _finding("SKY-Q306"))

    text = _render(kind, result, expand=True, limit=1)

    assert "SKY-Q301" in text and "SKY-Q306" in text
    assert re.search(r"cyclomatic[^\n]*12", text, re.IGNORECASE)
    assert re.search(r"cognitive[^\n]*23", text, re.IGNORECASE)
    assert text.count("branchy_handler") == 1


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree", "llm"])
@pytest.mark.parametrize("rule", ["SKY-Q301", "SKY-Q306"])
def test_single_trigger_keeps_its_metric_and_rule(kind, rule):
    row = _finding(rule)
    result = _result(row)
    before = copy.deepcopy(result)

    # One metric alone is measured, not listed, by default.
    assert rule not in _render(kind, result, expand=True)
    text = _render(kind, result, expand=True, all_advice=True)

    assert rule in text
    assert ("SKY-Q306" if rule == "SKY-Q301" else "SKY-Q301") not in text
    assert str(row["value"]) in text
    assert str(row["threshold"]) in text
    assert result == before


def test_pretty_collector_limits_function_entries_after_combining_metrics():
    result = _result(_finding("SKY-Q301"), _finding("SKY-Q306"))
    before = copy.deepcopy(result)

    displayed = collect_pretty_findings(result, root_path=Path("/example"), limit=1)

    assert len(displayed) == 1
    assert "SKY-Q301" in displayed[0].rule and "SKY-Q306" in displayed[0].rule
    assert any("23" in detail and "15" in detail for detail in displayed[0].details)
    assert result == before


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree", "llm"])
def test_custom_rule_collision_stays_separate_from_builtin_complexity(kind):
    builtin = _finding("SKY-Q301")
    custom = dict(
        _finding("SKY-Q306"), source="custom", message="Custom route policy failed"
    )
    result = _result(builtin)
    result["custom_rules"] = [custom]
    annotate_finding_types(result)
    before = copy.deepcopy(result)

    # A custom rule cannot corroborate a built-in metric: the lone Q301 is
    # measured by default and listed with --all-advice.
    assert "Custom route policy failed" in _render(kind, result, expand=True)
    text = _render(kind, result, expand=True, all_advice=True)

    assert "Custom route policy failed" in text
    assert "SKY-Q301" in text and "SKY-Q306" in text
    assert summarize_finding_types(result) == {
        "defect": 0,
        "review": 1,
        "advice": 1,
        "advice_groups": 1,
    }
    assert result == before


@pytest.mark.parametrize(
    "kind,limit",
    [(kind, limit) for kind in ("rich", "pretty", "tree") for limit in (None, 1)]
    + [("llm", None)],
)
def test_nested_scope_components_render_all_child_metrics_and_locations(kind, limit):
    source = """def factory():
    marker = 0
    def inner(value):
        if value.a:
            if value.b:
                if value.c:
                    if value.d:
                        if value.e:
                            if value.f:
                                return value
    return inner
"""
    tree = ast.parse(source)
    rules = [
        CognitiveComplexityRule(),
        ComplexityRule(threshold=5),
        NestingRule(),
        FunctionLengthRule(max_lines=5),
    ]
    context = {"filename": "/example/app.py", "source": source}
    rows = [
        row
        for node in ast.walk(tree)
        for rule in rules
        for row in rule.visit_node(node, context) or []
    ]
    cognitive = {
        r["simple_name"]: r["value"] for r in rows if r["rule_id"] == "SKY-Q306"
    }
    assert cognitive == {"factory": 27, "inner": 21}
    result = _result(*rows)
    before = copy.deepcopy(result)

    # factory's own cognitive score is mostly inner's, and nothing else agrees,
    # so by default only inner (cyclomatic, cognitive and nesting) is listed.
    focused = " ".join(_render(kind, result, expand=True, limit=limit).split())
    assert "1 advice entry (4 findings) in 1 group" in focused
    assert "Cognitive complexity: 27" not in focused

    text = _render(kind, result, expand=True, limit=limit, all_advice=True)
    normalized = " ".join(text.split())

    assert "1 advice entry (6 findings) in 1 group" in normalized
    assert "Nested inner at line 3" in normalized
    assert "factory" in text
    assert "app.py:1" in text or (kind == "llm" and "app.py" in text)
    for row in rows:
        assert row["rule_id"] in text
        assert row["message"] in normalized
        assert str(row["value"]) in text
    assert "Cognitive complexity: 27" in normalized
    assert "Cognitive complexity: 21" in normalized
    assert "Cyclomatic complexity: 7" in normalized
    assert "Maximum nesting: 6" in normalized
    assert "Code lines: 8" in normalized
    assert "Code lines: 11" in normalized
    if kind == "llm":
        assert len(re.findall(r"^## \d+\.", text, re.MULTILINE)) == 1
    assert result == before
