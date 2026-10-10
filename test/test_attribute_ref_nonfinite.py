"""Keep nonfinite arithmetic on the independent original scoring path."""

import copy
from functools import partial
from itertools import product
import math
import struct

import pytest

import skylos.analysis.attribute_refs as attribute_module
from skylos.analysis.attribute_refs import AttributeContextIndex
from skylos.visitors.base import Definition
from test.attribute_ref_oracle import _definition as _make_definition
from test.attribute_ref_oracle import _original, _scores


_definition = partial(_make_definition, Definition)
_MARKERS = ["same_file_attr", "same_pkg_attr", "global_attr"]


def _warm_paths(index, contexts, warming):
    for iteration in range(32):
        weights = dict.fromkeys(_MARKERS, iteration / 33)
        if warming in ("oracle", "both"):
            _original(_definition("alpha.work"), contexts, weights)
        if warming in ("index", "both"):
            index.mark(_definition("alpha.work"), weights)


def _assert_original_bits(index, contexts, initial, weight):
    expected = _definition("alpha.work", dict.fromkeys(_MARKERS, initial))
    actual = copy.deepcopy(expected)
    weights = dict.fromkeys(_MARKERS, weight)
    cached = list(index.addition.results.items())
    _original(expected, contexts, weights)
    index.mark(actual, weights)
    assert _scores(actual) == _scores(expected)
    assert list(index.addition.results.items()) == cached


@pytest.mark.parametrize("warming", ["cold", "oracle", "index", "both"])
@pytest.mark.parametrize(
    "modules",
    [["alpha"], ["alpha"] * 33, ["beta", "alpha", "alpha.deep"] * 11],
    ids=["single", "repeated", "mixed"],
)
def test_nonfinite_operands_match_original_bits_without_using_cache(
    monkeypatch, modules, warming
):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 0)
    contexts = [("work", module, None, line) for line, module in enumerate(modules)]
    index = AttributeContextIndex(contexts)
    index.seen_attributes.add("work")
    _warm_paths(index, contexts, warming)
    nonfinite = [
        struct.unpack("!d", bytes.fromhex("7ff8000000000001"))[0],
        struct.unpack("!d", bytes.fromhex("7ff8000000000002"))[0],
        math.inf,
        -math.inf,
    ]
    pairs = [*product(nonfinite, [0, 0.0, -0.0, *nonfinite])]
    pairs += [*product([0, 0.0, -0.0], nonfinite)]
    for initial, weight in pairs * 3:
        _assert_original_bits(index, contexts, initial, weight)


def test_unused_nonfinite_categories_do_not_disable_finite_cache(monkeypatch):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 0)
    contexts = [("work", "alpha", None, line) for line in range(33)]
    initial = {"same_pkg_attr": math.nan, "global_attr": math.inf}
    weights = {"same_pkg_attr": math.inf, "global_attr": -math.inf}
    expected, actual = _definition("alpha.work", initial), _definition("alpha.work", initial)
    index = AttributeContextIndex(contexts)
    index.seen_attributes.add("work")
    _original(expected, contexts, weights)
    index.mark(actual, weights)
    assert _scores(actual) == _scores(expected)
    assert index.addition.results


@pytest.mark.parametrize("marker", ["same_pkg_attr", "global_attr"])
@pytest.mark.parametrize("operand", ["initial", "weight"])
@pytest.mark.parametrize("nonfinite", [math.inf, math.nan])
def test_later_nonfinite_category_replays_all_updates_before_cache_writes(
    monkeypatch, marker, operand, nonfinite
):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 0)
    contexts = [
        ("work", module, None, line)
        for line, module in enumerate(["alpha", "alpha.deep", "beta"] * 11)
    ]
    index = AttributeContextIndex(contexts)
    index.seen_attributes.add("work")
    _warm_paths(index, contexts, "both")
    initial = {"prior": 0.125, marker: nonfinite if operand == "initial" else 0.0}
    weights = {marker: nonfinite} if operand == "weight" else {}
    expected = _definition("alpha.work", initial)
    actual = copy.deepcopy(expected)
    cached = list(index.addition.results.items())
    _original(expected, contexts, weights)
    index.mark(actual, weights)
    assert _scores(actual) == _scores(expected)
    assert list(index.addition.results.items()) == cached
