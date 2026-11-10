"""Unordered native call metadata cannot change cleanup observations."""

from copy import deepcopy

import pytest

from skylos.cleanup import build_cleanup_plan


def _report(**sections):
    return {
        "analysis_summary": {
            "total_files": 1,
            "grade_categories": ["quality", "ai_defects", "dead_code"],
            "ai_verification": {"state": "complete"},
        },
        "analysis_errors": [],
        **sections,
    }


def _finding(**changes):
    return {
        "rule_id": "SKY-L012",
        "file": "app.ts",
        "line": 1,
        "name": "process",
        "severity": "MEDIUM",
        "message": "Review this call",
        "calls": ["twMerge", "clsx"],
        **changes,
    }


def test_native_unused_function_id_survives_call_serialization_order(tmp_path):
    (tmp_path / "app.ts").write_text(
        "export function process() { return twMerge(clsx()); }\n", encoding="utf-8"
    )
    first = _finding(rule_id="SKY-U001", type="function", confidence=80)
    second = {**first, "calls": list(reversed(first["calls"]))}
    reports = [_report(unused_functions=[row]) for row in (first, second)]
    original_reports = deepcopy(reports)
    plans = [build_cleanup_plan(raw, project_root=tmp_path) for raw in reports]

    assert plans[0]["tasks"][0]["source_anchor"] is None
    assert plans[0]["tasks"][0]["id"] == plans[1]["tasks"][0]["id"]
    assert plans[0]["_inventory"] == plans[1]["_inventory"]
    assert [plan["tasks"][0]["finding"]["calls"] for plan in plans] == [
        first["calls"],
        second["calls"],
    ]
    assert reports == original_reports


def test_mirrored_findings_differing_only_in_call_order_count_once(tmp_path):
    first = _finding()
    mirror = {**first, "calls": list(reversed(first["calls"]))}
    raw = _report(quality=[first], ai_defects=[mirror])
    original = deepcopy(raw)

    plan = build_cleanup_plan(raw, project_root=tmp_path)

    assert plan["counts"]["tasks"] == len(plan["_inventory"]) == 1
    assert plan["tasks"][0]["finding"] in (first, mirror)
    assert raw == original


def test_repeated_rows_within_one_bucket_are_preserved(tmp_path):
    first = _finding()
    second = {**first, "calls": list(reversed(first["calls"]))}
    plan = build_cleanup_plan(
        _report(ai_defects=[first, second]), project_root=tmp_path
    )

    assert plan["counts"]["tasks"] == len(plan["_inventory"]) == 2
    assert len({task["id"] for task in plan["tasks"]}) == 2
    assert sorted(task["finding"]["calls"] for task in plan["tasks"]) == sorted(
        [first["calls"], second["calls"]]
    )


def test_architecture_signal_mirror_preserves_original_call_order(tmp_path):
    first = _finding(rule_id="SKY-Q802")
    mirror = {**first, "calls": list(reversed(first["calls"]))}
    raw = _report(
        quality=[first],
        architecture_metrics={"advisories": [{"signals": [mirror]}]},
    )
    original = deepcopy(raw)

    plan = build_cleanup_plan(raw, project_root=tmp_path, all_advice=True)

    assert plan["counts"]["tasks"] == 0
    assert plan["counts"]["advisories"] == len(plan["_inventory"]) == 1
    assert plan["advisories"][0]["finding"]["calls"] == first["calls"]
    assert raw == original


@pytest.mark.parametrize(
    "changes",
    [
        {"calls": ["twMerge", "other"]},
        {"calls": ["twMerge", "clsx", "clsx"]},
        {"severity": "HIGH"},
        {"evidence": [{"step": "second"}, {"step": "first"}]},
        {"trace": [{"step": "second"}, {"step": "first"}]},
        {"evidence": {"calls": ["second", "first"]}},
        {"listing": {"version": 1, "listed": False, "reason": "measurement"}},
    ],
)
def test_call_order_normalization_retains_real_observation_variants(tmp_path, changes):
    first = _finding(
        evidence=[{"step": "first"}, {"step": "second"}],
        trace=[{"step": "first"}, {"step": "second"}],
        listing={"version": 1, "listed": True, "reason": "finding"},
    )
    if isinstance(changes.get("evidence"), dict):
        first["evidence"] = {"calls": ["first", "second"]}
    second = {
        **deepcopy(first),
        "calls": list(reversed(first["calls"])),
        **deepcopy(changes),
    }
    raw = _report(ai_defects=[first], quality=[second], listing_policy_version=1)
    original = deepcopy(raw)

    plan = build_cleanup_plan(raw, project_root=tmp_path, all_advice=True)

    assert plan["counts"]["tasks"] == len(plan["_inventory"]) == 2
    assert len({task["id"] for task in plan["tasks"]}) == 2
    assert all(task["finding"] in (first, second) for task in plan["tasks"])
    assert raw == original


@pytest.mark.parametrize("calls", [[{"step": "first"}, {"step": "second"}], [1, 2]])
def test_non_string_call_metadata_is_not_reinterpreted_as_a_set(tmp_path, calls):
    first = _finding(calls=calls)
    second = {**first, "calls": list(reversed(calls))}
    plan = build_cleanup_plan(
        _report(ai_defects=[first], quality=[second]), project_root=tmp_path
    )

    assert plan["counts"]["tasks"] == 2
    assert len({task["id"] for task in plan["tasks"]}) == 2
