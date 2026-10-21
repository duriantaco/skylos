"""One listing decision; complete records survive every report transport."""

from copy import deepcopy
import json
from unittest.mock import patch

import pytest

from skylos.api._payloads import _compact_upload_finding
from skylos.core.gatekeeper import check_gate
from skylos.reporting.advice_policy import apply_advice_policy, prepare_advice_view
from skylos.reporting.listing import explicit_rule_ids, is_listed
from skylos.reporting.sarif import SarifExporter


def _row(rule="SKY-L027"):
    return {
        "rule_id": rule,
        "file": "/app/service.py",
        "line": 4,
        "severity": "MEDIUM",
        "name": "validate",
        "value": 3,
        "message": "A measured recommendation",
        "evidence": {"source": "retained"},
    }


def test_policy_marks_and_preserves_complete_records(tmp_path):
    raw = {"quality": [_row()], "analysis_summary": {}}
    before = deepcopy(raw)
    result = apply_advice_policy(raw, project_root=tmp_path)
    assert raw == before
    assert len(result["quality"]) == 1
    finding = result["quality"][0]
    assert {k: v for k, v in finding.items() if k != "listing"} == before["quality"][0]
    assert finding["listing"] == {
        "version": 1,
        "listed": False,
        "reason": "measurement",
    }
    assert json.loads(json.dumps(result)) == result
    view, visibility = prepare_advice_view(result)
    assert view["quality"] == [] and visibility.omitted_checks == 1
    expanded, visibility = prepare_advice_view(result, all_advice=True)
    assert expanded["quality"] == result["quality"] and visibility.omitted_checks == 0
    assert result["analysis_summary"]["quality_count"] == 1
    assert result["analysis_summary"]["listed_quality_count"] == 0


@pytest.mark.parametrize("unrelated_optional", [False, True])
def test_equivalent_cross_category_mirrors_share_canonical_listing(
    tmp_path, unrelated_optional
):
    from skylos.reporting.finding_types import iter_result_findings

    metric = _row()
    raw = {"danger": [deepcopy(metric)], "quality": [metric]}
    if unrelated_optional:
        raw["quality"].append({**_row("SKY-C303"), "file": "/app/other.py"})
    before = deepcopy(raw)
    result = apply_advice_policy(raw, project_root=tmp_path)

    assert raw == before
    assert len(list(iter_result_findings(result))) == len(
        list(iter_result_findings(raw))
    )
    assert result["danger"][0]["listing"] == result["quality"][0]["listing"]
    assert result["quality"][0]["listing"]["listed"] is True
    for section in ("danger", "quality"):
        assert [
            {key: value for key, value in row.items() if key != "listing"}
            for row in result[section]
        ] == before[section]
    if unrelated_optional:
        assert result["quality"][1]["listing"]["listed"] is False


@pytest.mark.parametrize(
    "variant", [{"evidence": {"source": "different"}}, {"severity": "HIGH"}]
)
def test_cross_category_evidence_and_severity_variants_keep_own_listing(
    tmp_path, variant
):
    from skylos.reporting.finding_types import iter_result_findings

    metric = _row()
    distinct = {**deepcopy(metric), **variant}
    raw = {"danger": [metric], "quality": [distinct]}
    result = apply_advice_policy(raw, project_root=tmp_path)

    assert len(list(iter_result_findings(raw))) == 2
    assert len(list(iter_result_findings(result))) == 2
    assert result["danger"][0]["listing"]["listed"] is True
    assert result["quality"][0]["listing"]["listed"] is False
    assert {
        key: value for key, value in result["quality"][0].items() if key != "listing"
    } == distinct


def test_listing_keeps_equivalent_repeated_rows_in_one_physical_array(tmp_path):
    from skylos.reporting.finding_types import iter_result_findings

    metric = _row()
    raw = {"quality": [metric, deepcopy(metric)]}
    result = apply_advice_policy(raw, project_root=tmp_path)

    assert len(result["quality"]) == len(list(iter_result_findings(result))) == 2
    assert result["advice_visibility"]["omitted_checks"] == 2
    assert all(not row["listing"]["listed"] for row in result["quality"])


def test_custom_category_is_not_a_builtin_mirror_and_still_blocks_gate(tmp_path):
    from skylos.reporting.finding_types import iter_result_findings

    metric = {**_row("SKY-Q802"), "advisory": True, "scope": "file"}
    raw = {"quality": [metric], "custom_rules": [deepcopy(metric)]}
    result = apply_advice_policy(raw, project_root=tmp_path)

    assert len(list(iter_result_findings(result))) == 2
    assert result["quality"][0]["listing"]["listed"] is False
    assert result["custom_rules"][0]["listing"]["listed"] is True
    assert not check_gate(result, {"gate": {"max_quality": 0}})[0]


@pytest.mark.parametrize("rule", ["SKY-L027", "SKY-L038"])
def test_all_advice_and_explicit_rules_keep_same_raw_records(tmp_path, rule):
    raw = {"quality": [_row(rule), _row("SKY-C303")]}
    focused = apply_advice_policy(raw, project_root=tmp_path)
    selected = apply_advice_policy(
        raw, project_root=tmp_path, explicit_rules=[rule]
    )
    expanded = apply_advice_policy(raw, project_root=tmp_path, all_advice=True)
    for result in (focused, selected, expanded):
        assert len(result["quality"]) == 2
    assert [is_listed(row, "quality") for row in selected["quality"]] == [True, False]
    assert selected["quality"][0]["listing"]["reason"] == "explicit_rule"
    assert all(is_listed(row, "quality") for row in expanded["quality"])


@pytest.mark.parametrize("rule", ["SKY-L027", "SKY-L038"])
def test_gate_uses_mark_and_explicit_config_override(tmp_path, rule):
    result = apply_advice_policy({"quality": [_row(rule)]}, project_root=tmp_path)
    assert check_gate(result, {"gate": {"max_quality": 0}})[0] is True
    configured = {"gate": {"max_quality": 0, "rules": [rule]}}
    passed, reasons = check_gate(result, configured)
    assert not passed and any("1 quality issue" in str(reason) for reason in reasons)
    assert explicit_rule_ids(configured) == {rule}
    assert result["quality"][0]["listing"]["listed"] is False


@pytest.mark.parametrize("section", ["quality", "architecture_metrics"])
def test_named_gate_rule_uses_supported_id_alias(tmp_path, section):
    row = _row("SKY-Q802")
    row["id"] = row.pop("rule_id")
    row.update(advisory=True, scope="file")
    raw = (
        {"quality": [row]}
        if section == "quality"
        else {"architecture_metrics": {"advisories": [{"signals": [row]}]}}
    )
    result = apply_advice_policy(raw, project_root=tmp_path)
    assert check_gate(result, {"gate": {"max_quality": 0}})[0] is True
    passed, reasons = check_gate(
        result, {"gate": {"max_quality": 0, "rules": ["SKY-Q802"]}}
    )
    assert not passed and any("1 quality issue" in str(reason) for reason in reasons)


def test_repeated_assessment_uses_same_listing_decision_as_gate(tmp_path):
    from skylos.reporting.assessment import compute_assessment
    from skylos.reporting.listing import listed_result

    result = apply_advice_policy({"quality": [_row()]}, project_root=tmp_path)
    expected = compute_assessment(listed_result(result), scanned_checks=["quality"])
    assert compute_assessment(result, scanned_checks=["quality"]) == expected
    assert len(result["quality"]) == 1


def test_explicit_architecture_signal_counts_once_in_gate(tmp_path):
    signal = {**_row("SKY-Q802"), "advisory": True, "scope": "file"}
    raw = {
        "quality": [],
        "architecture_metrics": {"advisories": [{"signals": [signal]}]},
    }
    result = apply_advice_policy(
        raw, project_root=tmp_path, explicit_rules=["SKY-Q802"]
    )
    assert result["architecture_metrics"]["advisories"][0]["signals"][0]["listing"][
        "listed"
    ]
    assert (
        check_gate(result, {"gate": {"max_quality": 0, "rules": ["SKY-Q802"]}})[0]
        is False
    )
    result["quality"] = [result["architecture_metrics"]["advisories"][0]["signals"][0]]
    assert check_gate(result, {"gate": {"max_quality": 1}})[0] is True


def test_listing_marks_preserve_separate_circular_dependency_gate_policy(tmp_path):
    cycle = {**_row("SKY-CIRC"), "message": "Module import cycle"}
    result = apply_advice_policy(
        {"quality": [], "circular_dependencies": [cycle]}, project_root=tmp_path
    )
    assert result["circular_dependencies"][0]["listing"]["listed"] is True
    assert check_gate(result, {"gate": {"max_quality": 0}})[0] is True
    assert (
        check_gate(result, {"gate": {"max_quality": 0, "rules": ["SKY-CIRC"]}})[0]
        is False
    )


def test_rule_and_display_filters_refresh_listing_counts(tmp_path):
    from skylos.cli import _apply_display_filters, _apply_rule_selection

    raw = {
        "quality": [
            {**_row(), "file": "/app/a.py"},
            {**_row("SKY-C303"), "file": "/app/b.py"},
        ]
    }
    expanded = apply_advice_policy(raw, project_root=tmp_path, all_advice=True)
    selected = _apply_rule_selection(expanded, ["SKY-L027"])
    assert selected["analysis_summary"]["listed_quality_count"] == 1
    assert selected["advice_visibility"]["total_checks"] == 1
    focused = apply_advice_policy(raw, project_root=tmp_path)
    filtered = _apply_display_filters(focused, file_filter="a.py")
    assert filtered["advice_visibility"]["total_checks"] == 1
    assert filtered["advice_visibility"]["omitted_checks"] == 1
    assert filtered["analysis_summary"]["listed_quality_count"] == 0


@pytest.mark.parametrize("rule", ["SKY-L001", "SKY-D216", "CUSTOM-X"])
def test_listing_cannot_hide_defect_review_or_custom(rule):
    row = {
        **_row(rule),
        "listing": {"version": 1, "listed": False, "reason": "measurement"},
    }
    assert is_listed(row, "quality")
    assert not check_gate({"quality": [row]}, {"gate": {"max_quality": 0}})[0]


@pytest.mark.parametrize(
    "mark",
    [
        None,
        {},
        {"version": 1, "listed": 0, "reason": "measurement"},
        {"version": 2, "listed": False, "reason": "measurement"},
    ],
)
def test_unknown_listing_metadata_keeps_findings_visible(mark):
    assert is_listed({**_row(), "listing": mark}, "quality")


@pytest.mark.parametrize(
    "mark",
    [
        None,
        {},
        {"version": 1, "listed": 0, "reason": "architecture"},
        {"version": 2, "listed": False, "reason": "architecture"},
    ],
)
@pytest.mark.parametrize(
    "classification",
    [{}, {"category": "CUSTOM"}, {"custom_rule": True}, {"source": "custom"}],
)
def test_versioned_gate_keeps_advisories_with_missing_or_invalid_marks(
    mark, classification
):
    row = {
        **_row("SKY-Q802"),
        **classification,
        "advisory": True,
        "scope": "file",
        "listing": mark,
    }
    result = {"listing_policy_version": 1, "quality": [row]}
    before = deepcopy(result)
    assert is_listed(row, "quality")
    view, _ = prepare_advice_view(result)
    assert view["quality"] == [row]
    passed, reasons = check_gate(result, {"gate": {"max_quality": 0}})
    assert not passed and any("1 quality issue" in str(reason) for reason in reasons)
    assert result == before


def test_unknown_listing_reason_has_safe_visibility_message():
    from skylos.reporting.advice_policy import refresh_listing_summary

    row = {
        **_row(),
        "listing": {"version": 1, "listed": False, "reason": "future_optional_reason"},
    }
    result = refresh_listing_summary({"listing_policy_version": 1, "quality": [row]})
    view, visibility = prepare_advice_view(result)
    assert view["quality"] == []
    assert visibility.omitted_checks == 1
    assert "other optional advice" in visibility.message
    recovered, _ = prepare_advice_view(result, all_advice=True)
    assert recovered["quality"] == [row]


def test_sarif_and_compact_upload_retain_listing_and_all_records(tmp_path):
    result = apply_advice_policy({"quality": [_row()]}, project_root=tmp_path)
    row = result["quality"][0]
    upload = {**row, "category": "QUALITY"}
    compact = _compact_upload_finding(upload, include_snippet=False)
    assert compact["listing"] == row["listing"]
    sarif = SarifExporter([upload]).generate()
    records = sarif["runs"][0]["results"]
    assert len(records) == 1
    assert records[0]["properties"]["listing"] == row["listing"]


def test_complete_upload_preparation_preserves_marks_in_every_transport(tmp_path):
    import skylos.api as api

    source = tmp_path / "service.py"
    source.write_text("def validate():\n    return 1\n", encoding="utf-8")
    raw = {
        "quality": [{**_row(), "file": str(source), "line": 1}],
        "danger": [{**_row("SKY-D215"), "file": str(source), "line": 1}],
        "provenance": {},
    }
    result = apply_advice_policy(raw, project_root=tmp_path)
    before = deepcopy(result)
    with (
        patch.object(api, "get_git_info", return_value=("c", "main", "actor", {})),
        patch.object(api, "get_git_root", return_value=str(tmp_path)),
        patch.object(api, "detect_ai_code", return_value={"detected": False}),
        patch.object(api, "_annotate_findings_with_blame"),
        patch.object(api, "_load_repo_link", return_value={}),
    ):
        prepared = api._prepare_report_upload(result, analyzer_owned=True)
    assert result == before
    for payload in (prepared.core_payload, prepared.legacy_payload):
        run = payload["runs"][0]
        rows = {row["ruleId"]: row for row in run["results"]}
        assert set(rows) == {"SKY-L027", "SKY-D215"}
        assert rows["SKY-L027"]["properties"]["listing"]["listed"] is False
        assert rows["SKY-D215"]["properties"]["listing"]["listed"] is True
        assert run["properties"]["listing_policy_version"] == 1
        assert run["properties"]["summary"]["listed_finding_count"] == 1
    rows = {row["rule_id"]: row for row in prepared.compatibility_payload["findings"]}
    assert set(rows) == {"SKY-L027", "SKY-D215"}
    assert rows["SKY-L027"]["listing"]["listed"] is False
    assert rows["SKY-L027"]["metadata"]["listing"] == rows["SKY-L027"]["listing"]
    assert prepared.scan_summary["finding_count"] == 2
    assert prepared.scan_summary["unlisted_finding_count"] == 1
