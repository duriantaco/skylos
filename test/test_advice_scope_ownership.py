"""Nested cognitive measurements share source, while independent scopes do not."""

import ast
from copy import deepcopy

import pytest

from scripts.check_advice_output import check_report
from skylos.analysis.file_processing import scan_python_quality
from skylos.reporting.advice_display import advice_display, combine_advice
from skylos.rules.quality.complexity import CognitiveComplexityRule


SOURCE = """def factory() -> object:
    marker = 0
    def inner(value: object) -> object:
        if value.a:
            if value.b:
                if value.c:
                    if value.d:
                        if value.e:
                            if value.f:
                                return value
    return inner
"""


def _cognitive_rows(source=SOURCE, file="app.py"):
    tree = ast.parse(source)
    rule = CognitiveComplexityRule()
    context = {"filename": file, "source": source}
    rule.visit_node(tree, context)
    return [
        ("quality", row)
        for node in ast.walk(tree)
        for row in rule.visit_node(node, context) or []
    ]


def _recover(rows):
    return [
        original
        for _category, finding in rows
        for original in (
            advice_display(finding).findings if advice_display(finding) else (finding,)
        )
    ]


def test_inclusive_score_and_child_are_one_component_with_both_locations():
    rows = _cognitive_rows()
    before = deepcopy(rows)
    assert [row["value"] for _, row in rows] == [27, 21]
    result = combine_advice(rows)
    assert len(result) == 1
    display = advice_display(result[0][1])
    assert display.primary_line == 1
    assert display.findings == tuple(row for _, row in rows)
    assert "nested scopes" in display.name
    assert "Nested inner at line 3" in display.message
    assert "27" in display.message and "21" in display.message
    assert all(row["message"] in display.message for _, row in rows)
    assert rows == before
    assert combine_advice(result) == result


def test_real_pipeline_keeps_independent_child_depth_and_all_raw_checks(tmp_path):
    path = tmp_path / "app.py"
    path.write_text(SOURCE)
    findings = scan_python_quality(
        ast.parse(SOURCE), SOURCE, path,
        {"ignore": [], "complexity": 10, "nesting": 3, "max_args": 5, "max_lines": 50},
        project_root=tmp_path,
    )
    metric_rows = [
        ("quality", row) for row in findings
        if row["rule_id"] in {"SKY-Q306", "SKY-Q302"}
    ]
    assert len(metric_rows) == 3
    result = combine_advice(metric_rows)
    assert len(result) == 1
    display = advice_display(result[0][1])
    assert len(display.findings) == 3
    assert display.rule_ids == ("SKY-Q306", "SKY-Q302")
    assert "Nested inner at line 3: SKY-Q302: Maximum nesting: 6" in display.message
    report = {"quality": findings}
    before = deepcopy(report)
    check_report(report, project_root=tmp_path)
    assert report == before


def test_child_keeps_its_own_entry_when_parent_is_suppressed_or_absent():
    rows = _cognitive_rows()
    child = rows[1]
    assert combine_advice([child]) == [child]


@pytest.mark.parametrize("category", ["custom_rules", "danger"])
def test_an_advice_shaped_custom_or_risk_record_does_not_join(category):
    rows = _cognitive_rows()
    rows[0] = (category, rows[0][1])
    assert combine_advice(rows) == rows


@pytest.mark.parametrize("rule_id", ["SKY-P404", "SKY-L001"])
def test_a_catalogued_risk_finding_is_not_consolidated(rule_id):
    rows = _cognitive_rows()
    rows[0][1]["rule_id"] = rule_id
    assert combine_advice(rows) == rows


@pytest.mark.parametrize("flag,value", [
    ("source", "custom"), ("category", "custom"), ("custom_rule", True),
])
def test_custom_checks_claiming_a_builtin_rule_id_stay_independent(flag, value):
    rows = _cognitive_rows()
    rows[0][1][flag] = value
    assert combine_advice(rows) == rows


def test_conflicting_known_languages_do_not_establish_shared_ownership():
    rows = _cognitive_rows()
    rows[0][1]["language"] = "Python"
    rows[1][1]["language"] = "JavaScript"
    assert combine_advice(rows) == rows


@pytest.mark.parametrize("change", [
    "missing_parent_scope", "missing_child_scope", "wrong_version", "boolean_version",
    "wrong_sum", "wrong_owner_name", "wrong_owner_span", "different_parent_name",
    "different_parent_line", "unknown_kind", "list_kind", "dict_kind", "different_file", "different_file_alias",
    "missing_owner", "reduced_included_score", "duplicate_owner",
])
def test_unknown_conflicting_or_incomplete_ownership_keeps_both_entries(change):
    rows = _cognitive_rows()
    parent, child = (row for _, row in rows)
    scope = parent["cognitive_scope"]
    if change == "missing_parent_scope":
        parent.pop("cognitive_scope")
    elif change == "missing_child_scope":
        child.pop("cognitive_scope")
    elif change == "wrong_version":
        scope["version"] = 2
    elif change == "boolean_version":
        scope["version"] = True
    elif change == "wrong_sum":
        scope["own_score"] += 1
    elif change == "wrong_owner_name":
        scope["nested_contributions"][0]["name"] = "other"
    elif change == "wrong_owner_span":
        scope["nested_contributions"][0]["end_line"] -= 1
    elif change == "different_parent_name":
        child["cognitive_scope"]["containing_function"]["name"] = "other"
    elif change == "different_parent_line":
        child["cognitive_scope"]["containing_function"]["line"] = 2
    elif change == "unknown_kind":
        scope["nested_contributions"][0]["kind"] = "Unverified"
    elif change == "list_kind":
        scope["nested_contributions"][0]["kind"] = []
    elif change == "dict_kind":
        scope["nested_contributions"][0]["kind"] = {}
    elif change == "different_file":
        child["file"] = "other.py"
    elif change == "different_file_alias":
        child["file_path"] = "other.py"
    elif change == "missing_owner":
        scope["own_score"] = parent["value"]
        scope["nested_contributions"] = []
    elif change == "reduced_included_score":
        scope["nested_contributions"][0]["score"] = 20
        scope["own_score"] = 7
    elif change == "duplicate_owner":
        scope["nested_contributions"].append(dict(scope["nested_contributions"][0]))
        parent["value"] *= 2
    assert combine_advice(rows) == rows


def test_duplicate_variants_of_a_parent_do_not_establish_unique_ownership():
    parent, child = _cognitive_rows()
    duplicate = (parent[0], deepcopy(parent[1]))
    duplicate[1]["message"] = "Different evidence variant"
    rows = [parent, duplicate, child]
    assert combine_advice(rows) == rows


@pytest.mark.parametrize("member_index", [0, 1])
def test_conflicting_identity_variants_block_scope_ownership(member_index):
    rows = _cognitive_rows()
    variant = deepcopy(rows[member_index][1])
    variant["simple_name"] = "different_function"
    rows.append(("quality", variant))
    assert combine_advice(rows) == rows


def test_zero_own_score_wrappers_keep_grandchild_evidence_at_every_level():
    source = """def outer():
    marker = 0
    def middle():
        marker2 = 0
        def inner(value):
            if value.a:
                if value.b:
                    if value.c:
                        if value.d:
                            if value.e:
                                if value.f:
                                    return value
        return inner
    return middle
"""
    rows = _cognitive_rows(source)
    assert [row["value"] for _, row in rows] == [33, 27, 21]
    result = combine_advice(rows)
    assert len(result) == 1
    assert len(_recover(result)) == 3
    assert "Nested middle at line 3" in advice_display(result[0][1]).message
    assert "Nested inner at line 5" in advice_display(result[0][1]).message
    assert combine_advice(result) == result


def test_unrelated_functions_and_same_names_in_other_files_remain_independent():
    first = _cognitive_rows(file="one.py")
    second = _cognitive_rows(file="two.py")
    result = combine_advice(first + second)
    assert len(result) == 2
    assert len(_recover(result)) == 4
    assert {row["file"] for _, row in result} == {"one.py", "two.py"}


def test_repeated_same_function_metrics_without_ownership_are_not_hidden():
    rows = _cognitive_rows()
    for _, row in rows:
        row.pop("cognitive_scope")
    assert combine_advice(rows) == rows
