"""Inclusive cognitive scores expose ownership without losing nested findings."""

import ast

import pytest

from skylos.analysis.file_processing import scan_python_quality
from skylos.rules.quality.complexity import (
    CognitiveComplexityRule,
    ComplexityRule,
    _cognitive_complexity,
    _func_complexity,
)
from skylos.rules.quality.nesting import _max_depth


def _nested_source():
    return """def factory():
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


def _findings(source, threshold=0):
    rule = CognitiveComplexityRule(threshold=threshold)
    tree = ast.parse(source)
    context = {"filename": "app.py", "source": source}
    rule.visit_node(tree, context)
    return [
        row for node in ast.walk(tree) for row in rule.visit_node(node, context) or []
    ]


def test_inclusive_parent_and_nested_positive_keep_distinct_scope_evidence():
    rows = _findings(_nested_source(), threshold=15)
    by_name = {row["simple_name"]: row for row in rows}
    assert by_name["factory"]["value"] == 27
    assert by_name["inner"]["value"] == 21
    assert by_name["factory"]["cognitive_scope"] == {
        "version": 1,
        "end_line": 11,
        "own_score": 0,
        "nested_contributions": [
            {
                "line": 3,
                "end_line": 10,
                "name": "inner",
                "kind": "FunctionDef",
                "score": 27,
            }
        ],
    }
    assert by_name["inner"]["cognitive_scope"] == {
        "version": 1,
        "end_line": 10,
        "own_score": 21,
        "nested_contributions": [],
        "containing_function": {"line": 1, "name": "factory"},
    }


def test_actual_quality_pipeline_initializes_lexical_parent_evidence(tmp_path):
    source = _nested_source()
    rows = scan_python_quality(
        ast.parse(source),
        source,
        tmp_path / "app.py",
        {"ignore": [], "complexity": 10, "nesting": 3, "max_args": 5, "max_lines": 50},
        project_root=tmp_path,
    )
    cognitive = {
        row["simple_name"]: row for row in rows if row["rule_id"] == "SKY-Q306"
    }
    assert cognitive["factory"]["value"] == 27
    assert cognitive["inner"]["value"] == 21
    assert cognitive["inner"]["cognitive_scope"]["containing_function"] == {
        "line": 1,
        "name": "factory",
    }


def test_defaults_belong_to_parent_while_nested_body_belongs_to_child():
    rows = _findings("""def factory():
    marker = 0
    def inner(flag=(a if ready else b)):
        if flag:
            return flag
    return inner
""")
    parent = next(row for row in rows if row["simple_name"] == "factory")
    assert parent["value"] == 3
    assert parent["cognitive_scope"]["own_score"] == 1
    assert parent["cognitive_scope"]["nested_contributions"][0]["score"] == 2


def test_local_class_methods_reset_nesting_but_keep_lexical_ancestor():
    source = """def factory():
    class Worker:
        def run(self):
            if self.ready:
                if self.enabled:
                    return self.value
    return Worker
"""
    rows = _findings(source)
    by_name = {row["simple_name"]: row for row in rows}
    assert by_name["factory"]["value"] == by_name["run"]["value"] == 3
    assert by_name["factory"]["cognitive_scope"]["own_score"] == 0
    assert by_name["run"]["cognitive_scope"]["containing_function"]["name"] == "factory"


def test_lambda_body_ownership_is_separate_from_its_creation_expression():
    (row,) = _findings("def factory():\n    return lambda x: 1 if x else 0\n")
    assert row["value"] == 2
    assert row["cognitive_scope"]["own_score"] == 0
    assert row["cognitive_scope"]["nested_contributions"] == [
        {"line": 2, "end_line": 2, "name": "<lambda>", "kind": "Lambda", "score": 2}
    ]


def test_parent_state_resets_between_files_and_direct_function_calls():
    rule = CognitiveComplexityRule(threshold=0)
    first = ast.parse(_nested_source())
    rule.visit_node(first, {})
    second = ast.parse("def independent():\n    if flag:\n        return flag\n")
    rule.visit_node(second, {})
    (row,) = rule.visit_node(second.body[0], {"filename": "other.py"})
    assert "containing_function" not in row["cognitive_scope"]
    assert row["cognitive_scope"]["own_score"] == row["value"] == 1


def test_measurement_ownership_differs_without_changing_existing_contracts():
    outer = ast.parse(_nested_source()).body[0]
    inner = outer.body[1]
    assert _func_complexity(outer) == 1
    assert _func_complexity(inner) == 7
    assert _max_depth(outer.body, is_function_body=True) == 0
    assert _max_depth(inner.body, is_function_body=True) == 6
    contributions = {}
    assert _cognitive_complexity(outer, contributions=contributions) == 27
    assert sum(contributions.values()) == 27


@pytest.mark.parametrize(
    "cases,expected",
    [
        ("case 1: return 1", 2),
        ("case 1: return 1\n        case 2: return 2", 3),
        ("case 1: return 1\n        case _: return 0", 2),
        ("case 1: return 1\n        case captured: return captured", 2),
        ("case 1 if ready: return 1", 3),
        ("case _ if ready: return 1", 2),
        ("case captured if ready: return captured", 2),
        (
            "case _ if first: return 1\n        case _ if second: return 2\n        case _: return 0",
            3,
        ),
        ("case a if first: return a\n        case b if second: return b", 3),
        ("case 1 if ready: return 1\n        case _: return 0", 3),
        ("case 1 | 2: return 1\n        case _: return 0", 2),
        ("case 1 | _: return 1", 1),
        ("case (1 | _) as captured: return captured", 1),
        ("case [value]: return value", 2),
    ],
)
def test_match_counts_only_patterns_that_can_fail_and_each_guard(cases, expected):
    source = f"def choose(value):\n    match value:\n        {cases}\n    return 0\n"
    assert _func_complexity(ast.parse(source).body[0]) == expected


def test_nonexhaustive_match_and_equivalent_if_have_the_same_paths():
    match = ast.parse(
        "def choose(x):\n    match x:\n        case 1: return 1\n    return 0\n"
    ).body[0]
    branch = ast.parse("def choose(x):\n    if x == 1: return 1\n    return 0\n").body[
        0
    ]
    assert _func_complexity(match) == _func_complexity(branch) == 2


def test_match_correction_preserves_nested_callable_ownership():
    source = """def outer():
    def choose(x):
        match x:
            case 1: return 1
        return 0
    return choose
"""
    outer = ast.parse(source).body[0]
    assert _func_complexity(outer) == 1
    assert _func_complexity(outer.body[0]) == 2


def test_guarded_captures_keep_real_decisions_without_inventing_pattern_branches():
    guards = ast.parse("""def choose(value):
    match value:
        case _ if first: return 1
        case _ if second: return 2
        case _: return 0
""").body[0]
    cases = ast.parse("""def choose(value):
    match value:
        case 1: return 1
        case 2: return 2
        case 3: return 3
        case _: return 0
""").body[0]
    rule = ComplexityRule(threshold=3)
    assert _func_complexity(guards) == 3
    assert rule.visit_node(guards, {"filename": "app.py"}) is None
    (row,) = rule.visit_node(cases, {"filename": "app.py"})
    assert row["value"] == 4
    assert row["threshold"] == 3
