"""Plain-language evidence tests; fixture programs are parsed, never run."""

from copy import deepcopy
import json

import pytest

from skylos.verification.behavior import compare_python_behavior
from skylos.verification.explanations import explain_difference


def _difference(before, after):
    comparison = compare_python_behavior(
        {"app.py": before}, {"app.py": after}, file="app.py", symbol="run"
    )
    assert comparison["status"] == "different", comparison
    assert len(comparison["differences"]) == 1
    difference = comparison["differences"][0]
    assert difference["runtime_witness"] is False
    explanation = difference["explanation"]
    for field in ("title", "before", "after", "impact", "review"):
        assert isinstance(explanation[field], str) and explanation[field]
    return difference


def test_discarded_callback_result_explains_caller_visible_change():
    difference = _difference(
        "def run(callback, value):\n    return callback(value)\n",
        "def run(callback, value):\n    callback(value)\n    return None\n",
    )
    explanation = difference["explanation"]
    assert explanation["title"] == "Callback result discarded"
    assert "callback(value)" in explanation["before"]
    assert "None" in explanation["after"]
    assert "caller" in explanation["impact"].lower()
    assert any(
        word in explanation["review"].lower()
        for word in ("intentional", "intended")
    )
    assert difference["before"]["value"] == ("result", 0)
    assert difference["after"]["value"] == ("constant", "NoneType", "None")


def test_changed_constant_return_is_not_described_as_discarded_callback():
    explanation = _difference(
        "def run(callback):\n    callback()\n    return 1\n",
        "def run(callback):\n    callback()\n    return 2\n",
    )["explanation"]
    assert explanation["title"] == "Return value changed"
    assert "1" in explanation["before"]
    assert "2" in explanation["after"]


def test_swallowed_exception_explains_propagation_for_matching_call_history():
    difference = _difference(
        "def run(callback):\n    return callback()\n",
        "def run(callback):\n"
        "    try:\n"
        "        return callback()\n"
        "    except BaseException:\n"
        "        return None\n",
    )
    assert difference["before"]["calls"] == difference["after"]["calls"]
    explanation = difference["explanation"]
    assert explanation["title"] == "Exception no longer propagated"
    assert "callback()" in explanation["before"]
    assert "None" in explanation["after"]
    assert any(
        word in explanation["impact"].lower()
        for word in ("caller", "failure", "error", "exception")
    )


def test_parameter_kind_change_has_signature_explanation():
    explanation = _difference(
        "def run(value):\n    return value\n",
        "def run(*, value):\n    return value\n",
    )["explanation"]
    assert explanation["title"] == "Function signature changed"
    assert "value" in explanation["before"]
    assert "value" in explanation["after"]
    assert explanation["before"] != explanation["after"]


def test_nested_call_result_is_readable_without_symbolic_tuple_jargon():
    explanation = _difference(
        "def run(callback, prepare, value):\n"
        "    return callback(prepare(value))\n",
        "def run(callback, prepare, value):\n"
        "    callback(prepare(value))\n"
        "    return None\n",
    )["explanation"]
    assert "callback(prepare(value))" in explanation["before"]
    assert "('result'," not in explanation["before"]
    assert "('parameter'," not in explanation["before"]


def test_unmatched_call_histories_do_not_claim_a_same_call_return_change():
    difference = _difference(
        "def run(left, right):\n    return left()\n",
        "def run(left, right):\n    return right()\n",
    )
    explanation = difference["explanation"]
    assert explanation["title"] in {
        "Call sequence changed",
        "Behavior changed on compared paths",
    }
    assert "left()" in explanation["before"]
    assert "right()" in explanation["after"]


def test_different_call_histories_prevent_exception_swallowing_claim():
    before_call = {
        "target": ("parameter", "left"),
        "args": (),
        "kwargs": (),
        "outcome": "raise",
        "active_exception": None,
    }
    after_call = {
        "target": ("parameter", "right"),
        "args": (),
        "kwargs": (),
        "outcome": "return",
        "active_exception": None,
    }
    explanation = explain_difference(
        {
            "kind": "behavior_trace",
            "before": {
                "calls": [before_call],
                "outcome": "raise",
                "value": ("exception", 0, None),
            },
            "after": {
                "calls": [after_call],
                "outcome": "return",
                "value": ("constant", "NoneType", "None"),
            },
        }
    )
    assert explanation["title"] in {
        "Call sequence changed",
        "Behavior changed on compared paths",
    }


@pytest.mark.parametrize(
    "difference",
    [
        {"kind": "behavior_trace", "before": None, "after": None},
        {"kind": "behavior_trace"},
        {
            "kind": "behavior_trace",
            "before": None,
            "after": {
                "calls": [],
                "outcome": "return",
                "value": ("constant", "NoneType", "None"),
            },
        },
    ],
)
def test_missing_trace_evidence_is_handled_without_inventing_a_change(difference):
    explanation = explain_difference(difference)
    assert explanation["title"] == "Behavior changed on compared paths"
    for field in ("title", "before", "after", "impact", "review"):
        assert isinstance(explanation[field], str) and explanation[field]


def test_serialized_json_trace_has_the_same_explanation_and_keeps_evidence():
    difference = _difference(
        "def run(callback, prepare, value):\n"
        "    return callback(prepare(value), flag=True)\n",
        "def run(callback, prepare, value):\n"
        "    callback(prepare(value), flag=True)\n"
        "    return None\n",
    )
    before = deepcopy(difference)
    serialized = json.loads(json.dumps(difference))
    assert explain_difference(serialized) == explain_difference(difference)
    assert difference == before
    assert "flag=True" in difference["explanation"]["before"]
    assert difference["before"]["calls"][1]["kwargs"] == (
        ("flag", ("constant", "bool", "True")),
    )


def test_explanation_does_not_claim_an_executed_or_proven_regression():
    difference = _difference(
        "def run(value):\n    return value\n",
        "def run(value):\n    return None\n",
    )
    prose = " ".join(difference["explanation"].values()).lower()
    assert "proven regression" not in prose
    assert "verified by execution" not in prose
    assert "execution proved" not in prose
    assert "will break" not in prose
    assert difference["runtime_witness"] is False
