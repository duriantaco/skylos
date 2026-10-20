"""Focused advice never changes detector evidence or configured gate inputs."""

import copy
import json

import pytest

from skylos.core.gatekeeper import check_gate
from skylos.reporting.advice_policy import optional_advice_reason, prepare_advice_view
from skylos.reporting.finding_types import summarize_finding_types


def _signature(**changes):
    return {
        "rule_id": "SKY-L029",
        "type": "function",
        "file": "/project/api.py",
        "name": "render.verbose",
        "value": "verbose",
        "line": 3,
        "col": 12,
        "severity": "LOW",
        "message": "Boolean parameter 'verbose' permits positional calls, which can obscure their meaning. Prefer named calls; consider keyword-only arguments when the public or callback contract permits it.",
        **changes,
    }


def _architecture(**changes):
    return {
        "rule_id": "SKY-Q802",
        "file": "/project/api.py",
        "name": "api",
        "line": 1,
        "severity": "HIGH",
        "advisory": True,
        "scope": "file",
        "value": 0.8,
        "message": "Architecture distance is 0.8",
        **changes,
    }


def test_optional_boolean_contract_and_unknown_or_observed_evidence():
    signature = _signature()
    assert optional_advice_reason(signature, "quality") == "boolean_signature"
    observed = _signature(
        message="Boolean parameter 'verbose' is called positionally with True at line 8; the bare literal does not say what it controls. Pass it by keyword, or make the parameter keyword-only."
    )
    unknown = _signature(message="New evidence contract requiring review")
    report = {"quality": [signature, observed, unknown]}
    view, visibility = prepare_advice_view(report)
    # Boolean traps are measured by default; only the signature-only contract
    # earns the specific reason. --all-advice lists all three.
    assert view["quality"] == []
    assert dict(visibility.reasons) == {"boolean_signature": 1, "measurement": 2}
    assert "--all-advice lists them" in visibility.message
    assert prepare_advice_view(report, all_advice=True)[0] is report


@pytest.mark.parametrize(
    "changes,category",
    [
        ({"source": "custom"}, "quality"),
        ({"custom_rule": True}, "quality"),
        ({"category": "custom"}, "quality"),
        ({}, "custom_rules"),
        ({}, "security"),
        ({}, "secrets"),
        ({}, "dead_code"),
        ({}, "dependency_vulnerabilities"),
        ({"rule_id": "SKY-D211", "finding_type": "advice"}, "security"),
        ({"rule_id": "SKY-L001", "finding_type": "advice"}, "quality"),
    ],
)
def test_custom_and_risk_findings_cannot_be_hidden_by_advice_metadata(
    changes, category
):
    assert optional_advice_reason(_signature(**changes), category) is None


def test_all_advice_restores_original_objects_evidence_and_severity():
    row = _signature(evidence=[{"source": "annotation"}])
    result = {"quality": [row, _architecture()]}
    before = copy.deepcopy(result)
    view, visibility = prepare_advice_view(result, all_advice=True)
    assert view is result and view["quality"][0] is row
    assert view == before
    assert visibility.total_checks == 2
    assert visibility.omitted_checks == 0
    assert visibility.message == ""


def test_canonical_mirrors_count_once_and_raw_gate_outcome_stays_identical():
    row = _signature()
    result = {
        "quality": [row],
        "code_health": [copy.deepcopy(row)],
        "analysis_summary": {},
    }
    encoded = json.dumps(result, sort_keys=True)
    gate_before = check_gate(result, {"gate": {"max_quality": 0}})
    view, visibility = prepare_advice_view(result)
    assert view["quality"] == view["code_health"] == []
    assert visibility.total_checks == visibility.omitted_checks == 1
    assert summarize_finding_types(result)["advice"] == 1
    assert json.dumps(result, sort_keys=True) == encoded
    assert check_gate(result, {"gate": {"max_quality": 0}}) == gate_before
    assert gate_before[0] is False


def test_architecture_views_and_assessments_keep_original_scope():
    optional = _architecture()
    enforced = _architecture(
        advisory=False, name="required", file="/project/required.py"
    )
    result = {
        "quality": [enforced],
        "architecture_metrics": {
            "advisories": [{"signals": [optional], "rule_ids": ["SKY-Q802"]}],
            "advisory_count": 1,
            "advisory_signal_count": 1,
            "module_count": 3,
        },
        "assessment": {"risk": {"counts": {"HIGH": 1}}},
        "gate": {"passed": False, "reasons": ["Required policy failed"]},
        "analysis_summary": {"architecture_advisory_count": 1},
    }
    before = copy.deepcopy(result)
    view, visibility = prepare_advice_view(result)
    assert visibility.omitted_checks == 1
    assert view["quality"] == [enforced]
    assert view["architecture_metrics"]["advisories"] == []
    assert view["analysis_summary"]["architecture_advisory_count"] == 0
    assert view["analysis_summary"]["assessment_includes_filtered_findings"] is True
    assert view["assessment"] == before["assessment"]
    assert view["gate"] == before["gate"]
    assert result == before


def test_nonproduction_scope_never_removes_security_correctness_or_custom(tmp_path):
    directory = tmp_path / "tests"
    directory.mkdir()
    path = directory / "test_app.py"
    path.write_text("def test_render():\n    assert True\n")
    advice = {"rule_id": "SKY-Q301", "file": str(path), "line": 1, "severity": "HIGH"}
    defect = {**advice, "rule_id": "SKY-L001"}
    security = {**advice, "rule_id": "SKY-D324"}
    custom = {**advice, "source": "custom"}
    enforced = _architecture(file=str(path), advisory=False)
    result = {
        "quality": [advice, defect, enforced],
        "danger": [security],
        "custom_rules": [custom],
    }
    before = copy.deepcopy(result)
    view, visibility = prepare_advice_view(result, project_root=tmp_path)
    assert view["quality"] == [defect, enforced]
    assert view["danger"] == [security]
    assert view["custom_rules"] == [custom]
    assert dict(visibility.reasons) == {"test": 1}
    assert result == before


def test_unknown_scope_and_malformed_extension_records_stay_visible():
    row = {"rule_id": "SKY-Q301", "file": "/missing/tests/test_app.py", "line": 1}
    optional = _architecture()
    result = {
        "quality": [row, "extension diagnostic"],
        "architecture_metrics": {
            "advisories": [{"signals": [optional, "unknown signal"]}]
        },
    }
    before = copy.deepcopy(result)
    view, visibility = prepare_advice_view(result, project_root="/missing")
    assert view["quality"] == [row, "extension diagnostic"]
    assert view["architecture_metrics"]["advisories"][0]["signals"] == [
        "unknown signal"
    ]
    assert visibility.omitted_checks == 1
    assert result == before


def test_risk_bucket_keeps_builtin_advice_id_even_when_quality_mirror_is_optional():
    row = _signature()
    result = {"danger": [row], "quality": [copy.deepcopy(row), _architecture()]}
    before = copy.deepcopy(result)
    view, visibility = prepare_advice_view(result)
    assert view["danger"] == [row]
    assert visibility.omitted_checks == 1
    assert summarize_finding_types(view)["advice"] == 1
    assert result == before
