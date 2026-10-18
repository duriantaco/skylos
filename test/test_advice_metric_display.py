"""Human advice groups preserve signals without widening detection policy."""

from copy import deepcopy
from itertools import combinations

import pytest

from skylos.reporting.advice_display import (
    AdviceDisplay,
    ComplexityDisplay,
    advice_display,
    advice_display_counts,
    combine_advice,
    combine_complexity_advice,
    complexity_display,
    group_advice_for_display,
)
from skylos.reporting.finding_types import (
    group_advice,
    iter_result_findings,
    summarize_finding_types,
)


_FUNCTION_RULES = ("SKY-Q301", "SKY-Q306", "SKY-C304", "SKY-Q302", "SKY-L028")


def _finding(rule, **changes):
    result = {
        "rule_id": rule,
        "type": "function",
        "name": "app.process",
        "simple_name": "process",
        "file": "app.py",
        "line": 12,
        "col": 4,
        "value": 20,
        "threshold": 10,
        "severity": "LOW",
        "message": f"Original recommendation for {rule}",
        "metric": f"original-{rule}",
        "evidence": {"steps": [rule]},
    }
    result.update(changes)
    return result


def _architecture(rule, **changes):
    result = _finding(
        rule,
        type="module",
        name="app.services",
        simple_name="services",
        file="app/services.py",
        line=1,
        col=None,
        value=0.8 if rule == "SKY-Q802" else "zone_of_pain",
        threshold=0.5 if rule == "SKY-Q802" else None,
        instability=0.1,
        abstractness=0.1,
        distance=0.8,
        remediations=[{"title": rule, "hint": "Original remediation"}],
    )
    result.update(changes)
    return result


def test_all_function_metrics_form_one_lossless_entry_in_stable_rule_order():
    originals = [_finding(rule) for rule in _FUNCTION_RULES]
    originals[1]["severity"] = "HIGH"
    originals[3].pop("col")  # Native nesting findings do not carry a column.
    originals[4]["name"] = "process"  # Native return findings use a bare name.
    rows = [("quality", row) for row in reversed(originals)]
    before = deepcopy(rows)

    [(category, item)] = combine_advice(rows)
    display = advice_display(item)

    assert category == "quality"
    assert display.name == "Function maintainability"
    assert display.rule_ids == _FUNCTION_RULES
    assert display.findings == tuple(originals)
    assert all(
        actual is original for actual, original in zip(display.findings, originals)
    )
    assert display.metric_lines == (
        "SKY-Q301: Cyclomatic complexity: 20 (threshold: 10)",
        "SKY-Q306: Cognitive complexity: 20 (threshold: 10)",
        "SKY-C304: Code lines: 20 (threshold: 10)",
        "SKY-Q302: Maximum nesting: 20 (threshold: 10)",
        "SKY-L028: Return statements: 20 (threshold: 10)",
    )
    assert item["severity"] == "HIGH"
    assert all(row["message"] in item["message"] for row in originals)
    assert rows == before
    assert combine_advice([(category, item)]) == [(category, item)]


@pytest.mark.parametrize("rules", list(combinations(_FUNCTION_RULES, 2)))
def test_any_two_distinct_function_metrics_can_share_an_entry(rules):
    rows = [("quality", _finding(rule)) for rule in rules]
    [(category, finding)] = combine_advice(rows)
    display = advice_display(finding)
    assert category == "quality"
    assert display.rule_ids == rules
    assert display.name == (
        "Function complexity"
        if rules == _FUNCTION_RULES[:2]
        else "Function maintainability"
    )


def test_generic_spellings_retain_historical_compatibility():
    assert AdviceDisplay is ComplexityDisplay
    assert advice_display is complexity_display
    assert combine_advice is combine_complexity_advice


@pytest.mark.parametrize(
    "changes",
    [
        {"file_path": "different.py"},
        {"symbol": "other.process"},
        {"simple_name": "other"},
        {"column": 5},
        {"type": "module"},
    ],
)
def test_inconsistent_aliases_never_join_a_function_group(changes):
    rows = [
        ("quality", _finding("SKY-Q301")),
        ("quality", _finding("SKY-L028", **changes)),
    ]
    assert combine_advice(rows) == rows


@pytest.mark.parametrize(
    "field, values", [("col", [0, 4]), ("language", ["Python", "TS"])]
)
def test_missing_optional_identity_cannot_bridge_conflicting_known_values(
    field, values
):
    rows = [
        ("quality", _finding("SKY-Q301", **{field: values[0]})),
        ("quality", _finding("SKY-Q306", **{field: None})),
        ("quality", _finding("SKY-C304", **{field: values[1]})),
    ]
    assert combine_advice(rows) == rows


def test_conflicting_qualifications_at_one_location_never_merge():
    rows = [
        ("quality", _finding("SKY-Q301", name="app.First.process")),
        ("quality", _finding("SKY-Q306", name="app.Second.process")),
        ("quality", _finding("SKY-L028", name="process")),
    ]
    assert combine_advice(rows) == rows


@pytest.mark.parametrize(
    "variant", [{}, {"evidence": {"different": True}}, {"severity": "HIGH"}]
)
def test_a_duplicate_rule_leaves_the_entire_candidate_group_uncombined(variant):
    rows = [("quality", _finding(rule)) for rule in _FUNCTION_RULES]
    rows.append(("quality", _finding("SKY-L028", **variant)))
    assert combine_advice(rows) == rows


@pytest.mark.parametrize(
    "category, changes",
    [
        ("custom_rules", {}),
        ("danger", {}),
        ("quality", {"source": "custom"}),
        ("quality", {"custom_rule": True}),
        ("quality", {"category": "custom_rules"}),
    ],
)
def test_custom_or_other_category_collision_remains_an_independent_record(
    category, changes
):
    first, second = _finding("SKY-Q301"), _finding("SKY-L028")
    collision = _finding("SKY-Q302", **changes)
    rows = [("quality", first), (category, collision), ("quality", second)]
    result = combine_advice(rows)
    assert len(result) == 2
    assert advice_display(result[0][1]).findings == (first, second)
    assert result[1] == (category, collision)
    assert result[1][1] is collision


def test_non_advice_risk_checks_at_same_location_remain_unmodified():
    defect = _finding("SKY-L001", severity="CRITICAL")
    review = _finding("UNKNOWN-RULE", severity="HIGH")
    first, second = _finding("SKY-Q301"), _finding("SKY-Q302")
    rows = [("quality", row) for row in (defect, first, review, second)]
    result = combine_advice(rows)
    assert len(result) == 3
    assert result[0][1] is defect
    assert result[2][1] is review
    assert advice_display(result[1][1]).findings == (first, second)


@pytest.mark.parametrize("reverse", [False, True])
def test_architecture_pair_retains_both_signal_objects_and_all_evidence(reverse):
    originals = [_architecture("SKY-Q802"), _architecture("SKY-Q803", severity="HIGH")]
    rows = [("quality", row) for row in originals]
    if reverse:
        rows.reverse()
    before = deepcopy(rows)

    [(category, item)] = combine_advice(rows)
    display = advice_display(item)

    assert category == "quality"
    assert display.name == "Module architecture"
    assert display.rule_ids == ("SKY-Q802", "SKY-Q803")
    assert display.metric_lines == (
        "SKY-Q802: Distance from main sequence: 0.8 (threshold: 0.5)",
        "SKY-Q803: Architecture zone: zone_of_pain",
    )
    assert display.findings == tuple(originals)
    assert all(
        actual is original for actual, original in zip(display.findings, originals)
    )
    assert all(row["message"] in item["message"] for row in originals)
    assert item["severity"] == "HIGH"
    assert rows == before


@pytest.mark.parametrize(
    "changes",
    [
        {"file": "app/other.py"},
        {"name": "app.other", "simple_name": "other"},
        {"line": 2},
        {"type": "function"},
        {"source": "custom"},
        {"name": "<module>", "simple_name": ""},
    ],
)
def test_architecture_signals_with_conflicting_or_missing_module_identity_stay_separate(
    changes,
):
    rows = [
        ("quality", _architecture("SKY-Q802")),
        ("quality", _architecture("SKY-Q803", **changes)),
    ]
    assert combine_advice(rows) == rows


def test_duplicate_architecture_evidence_variants_are_not_merged():
    rows = [
        ("quality", _architecture("SKY-Q802")),
        ("quality", _architecture("SKY-Q803")),
        ("quality", _architecture("SKY-Q803", evidence={"different": True})),
    ]
    assert combine_advice(rows) == rows


def test_expanded_display_counts_and_groups_leave_canonical_rows_and_raw_counts_unchanged():
    functions = [_finding(rule) for rule in _FUNCTION_RULES]
    signals = [_architecture("SKY-Q802"), _architecture("SKY-Q803")]
    result = {
        "quality": [*functions, *signals, _finding("SKY-L001")],
        "custom_rules": [_finding("SKY-Q301")],
        "architecture_metrics": {"advisories": [{"signals": deepcopy(signals)}]},
    }
    before = deepcopy(result)
    raw_rows = list(iter_result_findings(result))
    raw_counts = summarize_finding_types(result)
    raw_groups = group_advice(result)

    assert advice_display_counts(result) == {
        "defect": 1,
        "review": 1,
        "advice": 2,
        "raw_advice": 7,
        "advice_groups": 2,
    }
    groups = group_advice_for_display(result)
    assert [(group["name"], group["count"]) for group in groups] == [
        ("Function maintainability", 1),
        ("Module architecture", 1),
    ]
    assert groups[0]["rule_id"] == " + ".join(_FUNCTION_RULES)
    assert groups[1]["rule_id"] == "SKY-Q802 + SKY-Q803"
    assert result == before
    assert list(iter_result_findings(result)) == raw_rows
    assert summarize_finding_types(result) == raw_counts
    assert group_advice(result) == raw_groups
