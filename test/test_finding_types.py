"""Finding purpose and full evidence retention, independent of severity."""

import ast
import copy
from pathlib import Path

import pytest

from skylos.reporting.finding_types import (
    annotate_finding_types,
    get_finding_type,
    group_advice,
    iter_result_findings,
    summarize_finding_types,
)
from skylos.rules import catalog


def _finding(rule_id, **overrides):
    return {"rule_id": rule_id, "file": "/repo/app.py", "line": 1, **overrides}


def test_every_builtin_catalog_entry_declares_required_valid_type():
    entries = catalog.get_rule_catalog()
    assert len(entries) > 200
    assert {e["finding_type"] for e in entries} == {"defect", "review", "advice"}
    tree = ast.parse(Path(catalog.__file__).read_text())
    calls = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "RuleCatalogEntry"
    ]
    assert len(calls) == len(entries)
    assert all(any(k.arg == "finding_type" for k in c.keywords) for c in calls)
    with pytest.raises(TypeError):
        catalog.RuleCatalogEntry("CUSTOM", "Custom", "quality")


@pytest.mark.parametrize(
    "rule", ["SKY-L003", "SKY-L016", "SKY-P404", "SKY-Q402", "SKY-T103", "SKY-T106"]
)
def test_context_dependent_risks_are_review_not_advice(rule):
    assert get_finding_type(_finding(rule)) == "review"
    assert not catalog.is_advisory_quality_rule(rule)


@pytest.mark.parametrize(
    "rule", ["SKY-U001", "SKY-D211", "SKY-D324", "SKY-S101", "SKY-F102"]
)
def test_candidates_and_possible_security_incidents_require_review(rule):
    assert get_finding_type(_finding(rule)) == "review"


@pytest.mark.parametrize(
    "rule", ["SKY-L001", "SKY-Q401", "SKY-Q405", "SKY-Q406", "SKY-Q407", "SKY-UC001"]
)
def test_concrete_correctness_patterns_are_defects(rule):
    assert get_finding_type(_finding(rule)) == "defect"


def test_unknown_custom_and_unidentified_dead_code_default_to_review():
    assert get_finding_type({"rule_id": "CUSTOM", "finding_type": "advice"}) == "review"
    assert get_finding_type({"full_name": "app.old_fn"}, "dead_code") == "review"
    assert get_finding_type(_finding("SKY-Q301"), "custom_rules") == "review"
    assert (
        get_finding_type(_finding("SKY-Q301", category="custom"), "quality") == "review"
    )
    assert get_finding_type(_finding("SKY-Q301", source="custom")) == "review"


def test_advisory_compatibility_helper_derives_catalog_advice():
    expected = {
        e["id"]
        for e in catalog.get_rule_catalog()
        if e["category"] == "quality" and e["finding_type"] == "advice"
    }
    assert catalog.ADVISORY_QUALITY_RULES == expected
    assert {e["id"] for e in catalog.get_rule_catalog("advice")} == expected


def test_summary_counts_canonical_findings_and_excludes_report_metadata():
    defect = _finding("SKY-L001")
    review = _finding("SKY-D211")
    advice = _finding("SKY-Q301", message="Complex", name="app.f")
    extra = _finding("SKY-Q802", line=2)
    result = {
        "quality": [defect, advice],
        "danger": [review],
        "code_health": [copy.deepcopy(advice)],
        "architecture_metrics": {"advisories": [{"signals": [extra]}]},
        "unused_exports": [{"file": "/repo/view.ts", "name": "unused"}],
        "unused_fixtures": [{"file": "/repo/conftest.py", "name": "old_fixture"}],
        "circular_dependencies": [_finding("SKY-CIRC", line=3)],
        "publisher_change_findings": [_finding("SKY-D337", line=4)],
        "custom_rules": [_finding("CUSTOM", line=5)],
        "definitions": {"f": copy.deepcopy(defect)},
        "whitelisted": [copy.deepcopy(review)],
        "suppressed": [copy.deepcopy(review)],
        "dead_code_evidence": [copy.deepcopy(review)],
        "analysis_errors": [copy.deepcopy(review)],
        "analysis_summary": {"by_directory": [{"findings": [copy.deepcopy(review)]}]},
    }
    before = copy.deepcopy(result)
    assert summarize_finding_types(result) == {
        "defect": 1,
        "review": 6,
        "advice": 2,
        "advice_groups": 2,
    }
    assert result == before
    assert annotate_finding_types(result) is result
    assert all(
        f["finding_type"] in {"defect", "review", "advice"}
        for _, f in iter_result_findings(result)
    )
    assert result["code_health"][0]["finding_type"] == "advice"
    assert "finding_type" not in result["analysis_errors"][0]
    assert "finding_type" not in result["definitions"]["f"]
    assert "finding_type" not in result["whitelisted"][0]


@pytest.mark.parametrize(
    "variant",
    [
        {"severity": "HIGH"},
        {"evidence": [{"source": "other"}]},
        {"trace": ["other"]},
        {"confirmed": True},
    ],
)
def test_distinct_review_evidence_is_not_collapsed_across_arrays(variant):
    first = _finding(
        "SKY-P404", message="Review", severity="MEDIUM", evidence=[{"source": "first"}]
    )
    second = dict(first, **variant)
    result = {"quality": [first], "code_health": [second]}
    assert summarize_finding_types(result)["review"] == 2
    assert [f for _, f in iter_result_findings(result)] == [first, second]


def test_every_row_within_canonical_array_is_preserved():
    row = _finding("SKY-D211", evidence=[{"input": "request"}])
    result = {"danger": [row, row, copy.deepcopy(row)]}
    assert summarize_finding_types(result)["review"] == 3


def test_advice_group_keeps_all_files_messages_and_original_records():
    first = _finding("SKY-Q301", file="/repo/a.py", message="First", name="a")
    second = _finding("SKY-Q301", file="/repo/b.py", message="Second", name="b")
    result = {"quality": [first, second, _finding("SKY-T103")]}
    groups = group_advice(result)
    assert len(groups) == 1
    assert groups[0]["count"] == 2
    assert groups[0]["files"] == ["/repo/a.py", "/repo/b.py"]
    assert groups[0]["findings"] == [first, second]
    assert groups[0]["findings"][0] is first
    assert result["quality"] == [first, second, _finding("SKY-T103")]
