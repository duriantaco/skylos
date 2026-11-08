"""An explicitly requested type check participates in the common gate verdict."""

from dataclasses import asdict

import pytest

from skylos.core.gate_outcome import (
    FAILED,
    INCOMPLETE,
    PASSED,
    evaluate_gate,
    gate_record,
)
from skylos.core.gatekeeper import run_gate_interaction


@pytest.mark.parametrize(
    "status,complete,wanted",
    [
        ("fail", True, FAILED),
        ("incomplete", False, INCOMPLETE),
        ("not_configured", False, INCOMPLETE),
        ("pass", False, INCOMPLETE),
        ("fail", False, INCOMPLETE),
        ("pass", True, PASSED),
        ("unknown", True, INCOMPLETE),
    ],
)
@pytest.mark.parametrize("strict", [False, True])
def test_gate_includes_explicit_type_check_status(status, complete, wanted, strict):
    report = {"status": status, "complete": complete, "summary": "mypy: project check"}

    outcome = evaluate_gate({"type_check": report}, {}, strict=strict)

    assert outcome.verdict == wanted
    if wanted != PASSED:
        assert any("mypy: project check" in str(reason) for reason in outcome.reasons)
    assert gate_record(outcome, scope="project")["verdict"] == wanted
    if wanted == INCOMPLETE:
        assert outcome.exit_code(force=True) == 2
    elif wanted == FAILED:
        assert outcome.exit_code() == 1
        assert outcome.exit_code(force=True) == 0


def test_explicit_type_errors_do_not_hide_other_gate_failures():
    results = {
        "danger": [{"rule_id": "SKY-D201", "severity": "HIGH"}],
        "type_check": {
            "status": "fail",
            "complete": True,
            "summary": "tsc: 1 introduced error",
        },
    }

    outcome = evaluate_gate(results, {"gate": {"max_security": 0}})

    assert outcome.verdict == FAILED
    assert any("tsc: 1 introduced error" in str(reason) for reason in outcome.reasons)
    assert len(outcome.reasons) >= 2


def test_gate_without_type_check_retains_ordinary_outcome():
    ordinary = evaluate_gate({}, {})
    disabled = evaluate_gate({"type_check": None}, {})

    assert asdict(ordinary) == asdict(disabled)
    assert ordinary.verdict == PASSED


def test_malformed_requested_type_check_is_incomplete():
    assert evaluate_gate({"type_check": {}}, {}).verdict == INCOMPLETE


@pytest.mark.parametrize(
    "status,complete,code,headline",
    [
        ("fail", True, 1, "Quality Gate: FAILED"),
        ("incomplete", False, 2, "INCOMPLETE"),
        ("not_configured", False, 2, "INCOMPLETE"),
        ("pass", True, 0, "Quality Gate: PASSED"),
    ],
)
def test_human_gate_uses_the_same_type_checker_verdict(
    capsys, status, complete, code, headline
):
    report = {"status": status, "complete": complete, "summary": "mypy: type report"}

    actual = run_gate_interaction(
        results={"type_check": report}, config={}, strict=True
    )

    text = capsys.readouterr().out
    assert actual == code
    assert headline in text
    if code:
        assert "Quality Gate: PASSED" not in text
        assert "mypy: type report" in text
