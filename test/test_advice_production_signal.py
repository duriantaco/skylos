"""Focus weak advice without changing detector records, raw severity or gates."""

from copy import deepcopy
from io import StringIO
import json

import pytest
from rich.console import Console

from skylos.cli import _skylos_console_theme
from skylos.core.gatekeeper import check_gate
from skylos.reporting.advice_display import advice_priority
from skylos.reporting.advice_policy import optional_advice_reason, prepare_advice_view
from skylos.reporting.llm_report import _generate_llm_report
from skylos.ui.rich_report import render_results
from skylos.ui.terminal_report import render_pretty_results


def _finding(rule, **changes):
    return {
        "rule_id": rule,
        "file": "/missing/app.py",
        "name": "app.process",
        "type": "function",
        "line": 10,
        "col": 0,
        "severity": "HIGH",
        "value": 12,
        "threshold": 10,
        "message": f"Original {rule} finding",
        **changes,
    }


@pytest.mark.parametrize("rule", ["SKY-C304", "SKY-Q302", "SKY-L028"])
def test_standalone_size_metrics_are_optional_but_raw_gate_stays_enforced(rule):
    row = _finding(rule)
    report = {"quality": [row]}
    before = deepcopy(report)
    gate_config = {"gate": {"max_quality": 0}}
    gate = check_gate(report, gate_config)

    focused, visibility = prepare_advice_view(report)

    assert focused["quality"] == []
    assert dict(visibility.reasons) == {"single_function_metric": 1}
    assert "standalone" in visibility.message
    complete, _ = prepare_advice_view(report, all_advice=True)
    assert complete is report and complete["quality"][0] is row
    assert report == before and check_gate(report, gate_config) == gate
    assert gate[0] is False


@pytest.mark.parametrize(
    "rules",
    [
        ["SKY-Q301"],
        ["SKY-Q306"],
        ["SKY-C304", "SKY-Q302"],
        ["SKY-C304", "SKY-Q301"],
        ["SKY-Q302", "SKY-Q306", "SKY-L028"],
    ],
)
def test_complexity_signals_and_existing_combined_groups_stay_visible(rules):
    report = {"quality": [_finding(rule) for rule in rules]}
    focused, visibility = prepare_advice_view(report)
    assert focused is report and visibility.omitted_checks == 0


@pytest.mark.parametrize(
    "changes",
    [{"name": ""}, {"name": "<?>"}, {"line": None}, {"file_path": "other.py"}],
)
def test_uncertain_function_identity_keeps_standalone_advice_visible(changes):
    report = {"quality": [_finding("SKY-C304", **changes)]}
    assert prepare_advice_view(report)[0] is report


def test_duplicate_or_conflicting_metric_records_are_not_mistaken_for_singles():
    rows = [_finding("SKY-C304"), _finding("SKY-C304", value=14)]
    report = {"quality": rows}
    assert prepare_advice_view(report)[0] is report


def test_an_uncertain_companion_metric_cannot_establish_a_standalone_measurement():
    report = {"quality": [_finding("SKY-C304"), _finding("SKY-Q301", name="")]}
    assert prepare_advice_view(report)[0] is report


def _literal_context(**changes):
    return {
        "version": 1,
        "scope_complete": True,
        "occurrence_count": 3,
        "distinct_function_count": 1,
        "non_function_occurrences": 0,
        "identifier_like": True,
        "all_occurrences_contract_tokens": True,
        "role_counts": {"call_argument": 3},
        **changes,
    }


def test_repetition_confined_to_one_function_is_recoverable_optional_advice():
    row = _finding("SKY-L027", value=3, literal_context=_literal_context())
    assert optional_advice_reason(row, "quality") == "identifier_literal"
    row["literal_context"]["identifier_like"] = False
    assert optional_advice_reason(row, "quality") == "local_literal"
    report = {"quality": [row]}
    assert prepare_advice_view(report)[0]["quality"] == []
    assert prepare_advice_view(report, all_advice=True)[0] is report


@pytest.mark.parametrize(
    "changes",
    [
        {"distinct_function_count": 2},
        {"distinct_function_count": 1, "non_function_occurrences": 1},
        {"distinct_function_count": 0, "non_function_occurrences": 3},
        {"version": 2},
        {"scope_complete": False},
        {"occurrence_count": 4},
        {"distinct_function_count": True},
        {"distinct_function_count": -1},
    ],
)
def test_shared_and_unknown_literals_keep_their_existing_visibility(changes):
    row = _finding("SKY-L027", value=3, literal_context=_literal_context(**changes))
    assert optional_advice_reason(row, "quality") is None


def test_missing_new_evidence_never_hides_saved_literal_or_argument_findings():
    for rule in ["SKY-L027", "SKY-C303"]:
        assert optional_advice_reason(_finding(rule), "quality") is None


def _argument_evidence(**changes):
    return {
        "version": 1,
        "complete": True,
        "metric": "total_parameters",
        "receiver_binding": "function",
        "required_positional": 2,
        "total_parameters": 12,
        "limits": {"required_positional": 5, "total_parameters": 10},
        **changes,
    }


def test_wide_optional_signatures_retain_the_raw_violation():
    row = _finding("SKY-C303", argument_evidence=_argument_evidence())
    assert optional_advice_reason(row, "quality") == "optional_signature"
    report = {"quality": [row]}
    encoded = json.dumps(report)
    assert prepare_advice_view(report)[0]["quality"] == []
    assert json.dumps(report) == encoded


@pytest.mark.parametrize(
    "changes",
    [
        {"required_positional": 6},
        {"metric": "required_positional"},
        {"receiver_binding": "unknown"},
        {"complete": False},
        {"required_positional_range": [4, 6]},
        {"version": 2},
    ],
)
def test_real_or_uncertain_required_parameter_excess_stays_visible(changes):
    row = _finding("SKY-C303", argument_evidence=_argument_evidence(**changes))
    assert optional_advice_reason(row, "quality") is None


@pytest.mark.parametrize("binding", [None, "unknown", "wrapped", []])
def test_unknown_binding_cannot_supply_an_inherited_signature_contract(binding):
    row = _finding(
        "SKY-C303",
        argument_evidence=_argument_evidence(
            receiver_binding=binding,
            override_contract={"kind": "project_base_signature"},
        ),
    )
    assert optional_advice_reason(row, "quality") is None


def test_complete_inherited_signature_contract_is_optional_but_unknown_shape_is_visible():
    contract = {
        "kind": "project_base_signature",
        "parameter_shape": "identical",
        "receiver_binding": "instance",
        "required_positional": 6,
        "total_parameters": 12,
        "base_class": "Base",
        "base_file": "base.py",
        "base_line": 1,
        "method_line": 2,
    }
    evidence = _argument_evidence(
        receiver_binding="instance",
        metric="required_positional",
        required_positional=6,
        override_contract=contract,
    )
    row = _finding("SKY-C303", argument_evidence=evidence)
    assert optional_advice_reason(row, "quality") == "inherited_signature"
    for field in contract:
        unknown = deepcopy(evidence)
        unknown["override_contract"].pop(field)
        assert (
            optional_advice_reason({**row, "argument_evidence": unknown}, "quality")
            is None
        )


@pytest.mark.parametrize(
    "category", ["custom_rules", "security", "secrets", "dead_code"]
)
def test_nonquality_buckets_cannot_be_filtered_by_new_advice_metadata(category):
    for row in [
        _finding("SKY-C304"),
        _finding("SKY-L027", value=3, literal_context=_literal_context()),
        _finding("SKY-C303", argument_evidence=_argument_evidence()),
    ]:
        assert optional_advice_reason(row, category) is None
        report = {"danger" if category == "security" else category: [row]}
        assert prepare_advice_view(report)[0] is report


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_advice_priority_cap_does_not_change_risk_or_raw_severity(severity):
    row = _finding("SKY-Q501", severity=severity)
    assert advice_priority(row, "quality") == "MEDIUM"
    assert row["severity"] == severity
    assert advice_priority({**row, "source": "custom"}, "quality") == severity
    assert advice_priority(row, "security") == severity
    assert (
        advice_priority(_finding("SKY-D211", severity=severity), "security") == severity
    )


@pytest.mark.parametrize("severity", ["MEDIUM", "WARN", "LOW", "INFO"])
def test_lower_advice_priorities_are_preserved(severity):
    assert (
        advice_priority(_finding("SKY-Q501", severity=severity), "quality") == severity
    )


@pytest.mark.parametrize("kind", ["rich", "pretty", "tree", "llm"])
@pytest.mark.parametrize("expanded", [False, True])
def test_every_human_view_caps_advice_priority_and_keeps_complete_records(
    kind, expanded, tmp_path
):
    row = _finding("SKY-Q501", type="class")
    report = {"quality": [row], "analysis_summary": {"total_files": 1}}
    before = deepcopy(report)
    if kind == "llm":
        output = _generate_llm_report(report, tmp_path, expand_advice=expanded)
        if expanded:
            assert "SKY-Q501 | MEDIUM | Quality" in output
            assert '"severity": "HIGH"' in output
    else:
        stream = StringIO()
        console = Console(
            file=stream, width=400, color_system=None, theme=_skylos_console_theme()
        )
        if kind == "pretty":
            render_pretty_results(
                console, report, root_path=tmp_path, expand_advice=expanded
            )
        else:
            render_results(
                console,
                report,
                root_path=tmp_path,
                tree=kind == "tree",
                expand_advice=expanded,
                copy_badge=False,
            )
        output = stream.getvalue()
    assert "MEDIUM" in output and "Advice priority" in output
    assert "original severities remain in JSON and gates" in output
    assert report == before
