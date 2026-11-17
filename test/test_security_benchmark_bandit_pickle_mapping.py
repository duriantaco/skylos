"""Bandit findings must match the exact native sink, never merely an import."""

import pytest
from skylos.benchmarks.security import _bandit_rule_id


@pytest.mark.parametrize(
    ("call", "expected"),
    [
        ("pickle.loads(payload)", "SKY-D205"),
        ("p.loads(payload)", "SKY-D205"),
        ("pickle.load(stream)", "SKY-D204"),
        ("pandas.read_pickle(path)", "SKY-D204"),
        ("pickle.Unpickler(stream)", "B301"),
        ("shelve.open(path)", "B301"),
        ("jsonpickle.decode(payload)", "B301"),
        ("read(payload)", "B301"),
    ],
)
def test_b301_distinguishes_sink_at_exact_position(call, expected):
    assert (
        _bandit_rule_id(
            {
                "test_id": "B301",
                "line_number": 6,
                "col_offset": 11,
                "code": f"6     return {call}\n",
            }
        )
        == expected
    )


@pytest.mark.parametrize("test_id", ["B302", "B403", "B404"])
def test_imports_and_other_serializers_cannot_satisfy_pickle_sink(test_id):
    assert (
        _bandit_rule_id(
            {
                "test_id": test_id,
                "line_number": 6,
                "col_offset": 0,
                "code": "6 pickle.loads(payload)\n",
            }
        )
        == test_id
    )


@pytest.mark.parametrize(
    "record",
    [
        {},
        {"code": "pickle.loads(payload)", "line_number": 6, "col_offset": 0},
        {"code": "6 pickle.loads(payload)", "line_number": 7, "col_offset": 0},
        {"code": "6 pickle.loads(payload)", "line_number": 6, "col_offset": 7},
        {"code": "6 pickle.loads(payload)", "line_number": 6},
        {"code": "6 pickle.loads(\n", "line_number": 6, "col_offset": 0},
        {
            "code": "6 pickle.loads(payload)\n8 other()",
            "line_number": 6,
            "col_offset": 0,
        },
        {"code": '6 "pickle.loads(payload)"', "line_number": 6, "col_offset": 0},
        {"code": "6 # pickle.loads(payload)", "line_number": 6, "col_offset": 0},
    ],
)
def test_missing_ambiguous_or_malformed_source_retains_original_identity(record):
    assert _bandit_rule_id({"test_id": "B301", **record}) == "B301"


def test_an_unrelated_nested_call_cannot_impersonate_the_reported_sink():
    finding = {
        "test_id": "B301",
        "line_number": 6,
        "col_offset": 0,
        "code": "6 jsonpickle.decode(unrelated.loads(payload))\n",
    }
    assert _bandit_rule_id(finding) == "B301"
    finding["code"] = "6 pickle.load(unrelated.loads(payload))\n"
    assert _bandit_rule_id(finding) == "SKY-D204"


def test_builtin_eval_blacklist_has_the_native_eval_identity():
    assert _bandit_rule_id({"test_id": "B307"}) == "SKY-D201"
