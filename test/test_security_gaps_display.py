from copy import deepcopy

from skylos.core.gatekeeper import check_gate
from skylos.ui.terminal_report import collect_pretty_findings


def _row(rule, **changes):
    return dict(
        rule_id=rule,
        file="app.py",
        line=8,
        col=4,
        symbol="load",
        severity="HIGH",
        message=f"{rule} path check",
        **changes,
    )


def test_one_path_operation_displays_once_and_keeps_all_raw_checks():
    result = {"danger": [_row("SKY-D215"), _row("SKY-D325")]}
    before = deepcopy(result)
    findings = collect_pretty_findings(result)
    assert len(findings) == 1
    assert all(rule in findings[0].rule for rule in ("SKY-D215", "SKY-D325"))
    assert any("SKY-D325 path check" in detail for detail in findings[0].details)
    assert result == before
    assert check_gate(result, {"gate": {"max_security": 0}})[0] is False


def test_separate_operations_and_distinct_evidence_are_not_combined():
    rows = [
        _row("SKY-D215"),
        {**_row("SKY-D325"), "col": 30},
        {**_row("SKY-D215"), "line": 9},
        {**_row("SKY-D325"), "line": 9},
        {**_row("SKY-D325"), "line": 9, "metadata": {"source": "other"}},
    ]
    assert len(collect_pretty_findings({"danger": rows})) == 5
