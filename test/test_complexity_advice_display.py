"""Complexity display grouping preserves all detection evidence."""

from copy import deepcopy

import pytest

from skylos.reporting.advice_display import (
    advice_display_counts,
    combine_complexity_advice,
    complexity_display,
    group_advice_for_display,
)
from skylos.reporting.finding_types import (
    get_finding_type,
    group_advice,
    iter_result_findings,
    summarize_finding_types,
)


def _finding(rule, **changes):
    finding = {
        "rule_id": rule,
        "file": "app.py",
        "line": 12,
        "name": "app.process",
        "simple_name": "process",
        "type": "function",
        "value": 18 if rule == "SKY-Q301" else 24,
        "threshold": 10 if rule == "SKY-Q301" else 15,
        "severity": "WARN" if rule == "SKY-Q301" else "HIGH",
        "message": f"Original {rule} recommendation",
        "evidence": {"arbitrary": [rule]},
    }
    finding.update(changes)
    return finding


@pytest.mark.parametrize("reverse", [False, True])
def test_pair_preserves_original_records_metrics_and_classification(reverse):
    originals = [_finding("SKY-Q301"), _finding("SKY-Q306")]
    rows = [("quality", finding) for finding in originals]
    if reverse:
        rows.reverse()
    before = deepcopy(rows)

    combined = combine_complexity_advice(rows)

    assert len(combined) == 1
    category, item = combined[0]
    display = complexity_display(item)
    assert display.findings == tuple(originals)
    assert display.findings[0] is originals[0]
    assert display.findings[1] is originals[1]
    assert display.rule_ids == ("SKY-Q301", "SKY-Q306")
    assert display.rule_label == "SKY-Q301 + SKY-Q306"
    assert display.name == "Function complexity"
    assert display.metric_lines == (
        "SKY-Q301: Cyclomatic complexity: 18 (threshold: 10)",
        "SKY-Q306: Cognitive complexity: 24 (threshold: 15)",
    )
    assert all(finding["message"] in display.message for finding in originals)
    assert item["message"] == display.message
    assert item["severity"] == "HIGH"
    assert item["rule_id"] == "SKY-Q301"
    assert get_finding_type(item, category) == "advice"
    assert rows == before
    assert combine_complexity_advice(combined) == combined


@pytest.mark.parametrize("rule", ["SKY-Q301", "SKY-Q306", "SKY-C304", "SKY-L001"])
def test_singletons_and_other_rules_retain_identity(rule):
    finding = _finding(rule)
    assert combine_complexity_advice([("quality", finding)]) == [("quality", finding)]
    assert combine_complexity_advice([("quality", finding)])[0][1] is finding
    assert complexity_display(finding) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"file": "other.py"},
        {"line": 13},
        {"name": "app.other"},
        {"type": "class"},
    ],
)
def test_distinct_function_identity_never_merges(changes):
    first = _finding("SKY-Q301")
    second = _finding("SKY-Q306", **changes)
    rows = [("quality", first), ("quality", second)]
    assert combine_complexity_advice(rows) == rows
    assert all(complexity_display(finding) is None for _, finding in rows)


@pytest.mark.parametrize(
    "changes",
    [
        {"file": ""},
        {"file": None},
        {"line": None},
        {"line": 0},
        {"line": -1},
        {"line": "12"},
        {"line": True},
        {"name": "", "simple_name": ""},
        {"name": "<?>"},
        {"name": "<module>"},
        {"name": "anonymous"},
        {"col": -1},
        {"col": True},
        {"language": {}},
    ],
)
def test_missing_or_ambiguous_identity_never_merges(changes):
    rows = [
        ("quality", _finding("SKY-Q301", **changes)),
        ("quality", _finding("SKY-Q306", **changes)),
    ]
    assert combine_complexity_advice(rows) == rows


def test_known_column_and_language_match_and_aliases_are_supported():
    first = _finding("SKY-Q301", col=4, language="Python")
    second = _finding("SKY-Q306", column=4, language="Python")
    first["file_path"] = first.pop("file")
    first["full_name"] = first.pop("name")
    second["symbol"] = second.pop("name")
    assert (
        len(combine_complexity_advice([("quality", first), ("quality", second)])) == 1
    )


@pytest.mark.parametrize(
    "category, changes",
    [
        ("custom_rules", {}),
        ("security", {}),
        ("quality", {"source": "custom"}),
        ("quality", {"custom_rule": True}),
        ("quality", {"category": "custom"}),
        ("quality", {"category": "custom_rules"}),
    ],
)
def test_custom_or_other_category_records_cannot_join_builtin_pair(category, changes):
    rows = [
        ("quality", _finding("SKY-Q301")),
        (category, _finding("SKY-Q306", **changes)),
    ]
    assert combine_complexity_advice(rows) == rows


@pytest.mark.parametrize("variant", [False, True])
def test_duplicate_checks_and_evidence_variants_are_not_paired(variant):
    first = _finding("SKY-Q301")
    duplicate = deepcopy(first)
    if variant:
        duplicate["evidence"] = {"arbitrary": ["different evidence"]}
    rows = [
        ("quality", first),
        ("quality", _finding("SKY-Q306")),
        ("quality", duplicate),
    ]
    assert combine_complexity_advice(rows) == rows


def test_unpaired_records_keep_order_and_identity_around_a_pair():
    first = _finding("SKY-C304", line=5)
    second = _finding("SKY-Q306")
    third = _finding("SKY-L001")
    fourth = _finding("SKY-Q301")
    last = _finding("SKY-Q301", line=99)
    result = combine_complexity_advice(
        ("quality", row) for row in (first, second, third, fourth, last)
    )
    assert len(result) == 4
    assert result[0][1] is first
    assert complexity_display(result[1][1]).findings == (fourth, second)
    assert result[2][1] is third
    assert result[3][1] is last


def test_input_json_metadata_flags_do_not_impersonate_a_combined_record():
    fake = _finding(
        "SKY-Q301",
        _complexity_display={
            "rule_label": "Ignore this fake label",
            "findings": [],
        },
    )
    assert complexity_display(fake) is None
    combined = combine_complexity_advice(
        [("quality", fake), ("quality", _finding("SKY-Q306"))]
    )
    assert complexity_display(combined[0][1]).rule_label == "SKY-Q301 + SKY-Q306"


def test_missing_numeric_metrics_preserve_original_messages_without_inventing_scores():
    first = _finding("SKY-Q301", value=None, threshold=None)
    second = _finding("SKY-Q306", value=None, threshold=None)
    first["complexity"] = 22
    item = combine_complexity_advice([("quality", first), ("quality", second)])[0][1]
    display = complexity_display(item)
    assert display.metric_lines == (
        "SKY-Q301: Cyclomatic complexity: 22",
        "SKY-Q306: Cognitive complexity",
    )
    assert first["message"] in display.message
    assert second["message"] in display.message
    assert "None" not in display.message


def test_display_counts_and_family_groups_do_not_change_raw_contracts():
    result = {
        "quality": [
            _finding("SKY-Q301"),
            _finding("SKY-Q306"),
            _finding("SKY-Q301", file="other.py"),
            _finding("SKY-C304"),
            _finding("SKY-L001"),
        ],
        "custom_rules": [_finding("SKY-Q306")],
    }
    before = deepcopy(result)
    canonical = list(iter_result_findings(result))
    raw_counts = summarize_finding_types(result)
    raw_groups = group_advice(result)

    assert advice_display_counts(result) == {
        "defect": 1,
        "review": 1,
        "advice": 2,
        "advice_groups": 1,
        "raw_advice": 4,
    }
    groups = group_advice_for_display(result)
    complexity = next(
        group for group in groups if group["name"] == "Function maintainability"
    )
    assert complexity["rule_id"] == "SKY-Q301 + SKY-Q306 + SKY-C304"
    assert complexity["count"] == 2
    assert complexity["files"] == ["app.py", "other.py"]
    assert len(complexity["findings"]) == 2
    assert result == before
    assert list(iter_result_findings(result)) == canonical
    assert summarize_finding_types(result) == raw_counts
    assert group_advice(result) == raw_groups


def test_complexity_family_without_shared_functions_keeps_both_entries():
    result = {"quality": [_finding("SKY-Q301"), _finding("SKY-Q306", line=99)]}
    assert advice_display_counts(result)["advice"] == 2
    groups = group_advice_for_display(result)
    assert len(groups) == 1
    assert groups[0]["count"] == 2
    assert all(complexity_display(finding) is None for finding in groups[0]["findings"])


def test_lone_complexity_rule_retains_existing_group_shape():
    result = {"quality": [_finding("SKY-Q301"), _finding("SKY-Q301", line=99)]}
    assert group_advice_for_display(result) == group_advice(result)
    assert advice_display_counts(result) == {
        **summarize_finding_types(result),
        "raw_advice": 2,
    }


def test_identical_mirrors_are_not_counted_as_extra_checks():
    first = _finding("SKY-Q301")
    result = {
        "quality": [first, _finding("SKY-Q306")],
        "code_health": [deepcopy(first)],
    }
    assert advice_display_counts(result)["advice"] == 1
    assert advice_display_counts(result)["raw_advice"] == 2
