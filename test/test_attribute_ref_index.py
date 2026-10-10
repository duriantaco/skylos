"""Independent parity checks for the original attribute-context scoring loop."""

import copy
from decimal import Decimal
from fractions import Fraction
import math
from pathlib import Path
import random
import struct

import pytest

import skylos.analysis.attribute_refs as attribute_module
from skylos.analysis.attribute_refs import AttributeContextIndex
from skylos.analysis.penalties import _check_heuristic_refs
from skylos.analyzer import Skylos, _reference_language_family
from skylos.deadcode.evidence import build_dead_code_evidence
from skylos.visitors.base import Definition


@pytest.fixture(autouse=True)
def _exercise_index_with_readable_context_lists(monkeypatch):
    # Small controls exercise the index; separate tests cover its adaptive path.
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 0)


def _ready_index(contexts):
    index = AttributeContextIndex(contexts)
    index.seen_attributes.update(index.by_attribute)
    return index


def _original(definition, contexts, weights):
    # Freeze the prior loop as an oracle, independent of the optimized helpers.
    matching = [row for row in contexts if row[0] == definition.simple_name]
    if not matching:
        return
    module = definition.name.rsplit(".")[0] if "." in definition.name else ""
    package = module.split(".")[0] if module else ""
    for _attribute, context_module, _class, _line in matching:
        context_package = context_module.split(".")[0] if context_module else ""
        if context_module == module:
            definition.heuristic_refs["same_file_attr"] = definition.heuristic_refs.get(
                "same_file_attr", 0.0
            ) + weights.get("same_file_attr", 1.0)
        elif context_package and package and context_package == package:
            definition.heuristic_refs["same_pkg_attr"] = definition.heuristic_refs.get(
                "same_pkg_attr", 0.0
            ) + weights.get("same_pkg_attr", 0.3)
        else:
            definition.heuristic_refs["global_attr"] = definition.heuristic_refs.get(
                "global_attr", 0.0
            ) + weights.get("global_attr", 0.1)


class _OracleIndex:
    def __init__(self, contexts, *, definitions=None, compatible_family=None):
        self.contexts = list(contexts)

    def mark(self, definition, weights):
        _original(definition, self.contexts, weights)


def _number(value):
    if type(value) is float:
        return float, struct.pack("!d", value)
    return type(value), value


def _scores(definition):
    return [(name, _number(value)) for name, value in definition.heuristic_refs.items()]


def _definition(name, initial=None):
    definition = Definition(name, "function", Path("module.py"), 3)
    definition.heuristic_refs = dict(initial or {})
    definition.calls = {"source.helper"}
    definition.called_by = {"source.entry"}
    definition.decorators = ["source.decorator"]
    definition.why_unused = ["prior reason"]
    return definition


@pytest.mark.parametrize("seed", range(40))
def test_randomized_scores_and_insertion_order_match_original(seed):
    rng = random.Random(seed)
    modules = ["", "alpha", "alpha.deep", "alpha.other", "beta", ".hidden"]
    contexts = [
        (
            rng.choice(["work", "other"]),
            rng.choice(modules),
            rng.choice([None, "First", "Second"]),
            rng.randrange(1, 30),
        )
        for _ in range(100)
    ]
    # Lists can contain repeated contexts even though normal scanner input is a set.
    contexts += contexts[:10]
    weights = {
        marker: rng.choice([0, 1, 0.0, -0.0, 0.1, 0.3, -0.2, 1.0])
        for marker in ["same_file_attr", "same_pkg_attr", "global_attr"]
    }
    index = _ready_index(contexts)
    for name in [
        "work",
        "alpha.work",
        "alpha.deep.work",
        "beta.work",
        ".work",
        "other",
    ]:
        initial = {"prior": 0.25}
        for marker in ["global_attr", "same_pkg_attr", "same_file_attr"]:
            if rng.randrange(2):
                initial[marker] = rng.choice([0, 0.0, -0.0, 0.099, 0.2946, 0.999])
        expected = _definition(name, initial)
        actual = copy.deepcopy(expected)
        _original(expected, contexts, weights)
        index.mark(actual, weights)
        assert _scores(actual) == _scores(expected)
        assert actual.to_dict() == expected.to_dict()


@pytest.mark.parametrize("container", [list, set, tuple])
def test_duplicate_context_and_line_semantics_are_preserved(container):
    rows = [("work", "alpha", "First", 1)] * 4 + [
        ("work", "alpha", "Second", 1),
        ("work", "alpha", "First", 2),
        ("work", "alpha.deep", None, 3),
        ("work", "beta", None, 4),
    ]
    contexts = container(rows)
    expected = _definition("alpha.deep.work")
    actual = copy.deepcopy(expected)
    _original(expected, contexts, {})
    _ready_index(contexts).mark(actual, {})
    assert _scores(actual) == _scores(expected)


def test_repeated_float_addition_preserves_a_real_confidence_boundary():
    contexts = [("work", "alpha", None, line) for line in range(10)]
    actual = _definition("alpha.work")
    actual.references = actual._attr_name_ref_count = 1
    _ready_index(contexts).mark(actual, {"same_file_attr": 0.1})
    assert _number(actual.heuristic_refs["same_file_attr"]) == _number(
        0.9999999999999999
    )
    assert _check_heuristic_refs(actual, Skylos(), 100) == 75
    # Multiplying count * weight would incorrectly cross this threshold.
    assert 10 * 0.1 == 1.0


@pytest.mark.parametrize(
    "initial",
    [0.0, math.nextafter(0.3, -math.inf), math.nextafter(1.0, -math.inf), -0.0],
)
@pytest.mark.parametrize("weight", [0.1, 0.3, math.nextafter(0.1, -math.inf), -0.0])
def test_near_threshold_scores_match_bit_for_bit(initial, weight):
    contexts = [("work", "alpha", None, line) for line in range(31)]
    expected = _definition("alpha.work", {"same_file_attr": initial})
    actual = copy.deepcopy(expected)
    weights = {"same_file_attr": weight}
    _original(expected, contexts, weights)
    _ready_index(contexts).mark(actual, weights)
    assert _scores(actual) == _scores(expected)


def test_cache_keeps_numeric_types_signed_zero_and_nan_payloads_distinct():
    def quiet_nan(bits):
        return struct.unpack("!d", bytes.fromhex(bits))[0]

    values = [
        0,
        0.0,
        -0.0,
        quiet_nan("7ff8000000000001"),
        quiet_nan("7ff8000000000002"),
        math.inf,
        -math.inf,
    ]
    contexts = [("work", "alpha", None, 1)]
    index = _ready_index(contexts)
    for weight in [0, -0.0, math.inf, -math.inf, *values[3:5]]:
        for initial in values:
            expected = _definition("alpha.work", {"same_file_attr": initial})
            actual = copy.deepcopy(expected)
            weights = {"same_file_attr": weight}
            _original(expected, contexts, weights)
            index.mark(actual, weights)
            assert _scores(actual) == _scores(expected)


@pytest.mark.parametrize("number", [Decimal("0.1"), Fraction(1, 10), True])
def test_non_builtin_numeric_types_use_original_arithmetic(number):
    contexts = [("work", "beta", None, 1), ("work", "alpha", None, 2)] * 3
    initial = dict.fromkeys(["same_file_attr", "same_pkg_attr", "global_attr"], number)
    expected = _definition("alpha.work", initial)
    actual = copy.deepcopy(expected)
    weights = dict.fromkeys(initial, number)
    _original(expected, contexts, weights)
    _ready_index(contexts).mark(actual, weights)
    assert _scores(actual) == _scores(expected)


class _CountingWeights(dict):
    def __init__(self):
        super().__init__()
        self.calls = []

    def get(self, key, default=None):
        self.calls.append(key)
        return len(self.calls) / 10


class _ObservedScores(dict):
    def __init__(self):
        super().__init__()
        self.events = []

    def get(self, key, default=None):
        self.events.append(("get", key))
        return super().get(key, default)

    def __setitem__(self, key, value):
        self.events.append(("set", key))
        return super().__setitem__(key, value)


def test_mapping_subclasses_preserve_interleaved_reads_and_writes():
    contexts = [
        ("work", module, None, 1)
        for module in ["beta", "alpha", "alpha.deep", "beta", "alpha", "alpha.deep"]
    ]
    expected = _definition("alpha.work")
    actual = copy.deepcopy(expected)
    expected.heuristic_refs = _ObservedScores()
    actual.heuristic_refs = _ObservedScores()
    expected_weights, actual_weights = _CountingWeights(), _CountingWeights()
    _original(expected, contexts, expected_weights)
    _ready_index(contexts).mark(actual, actual_weights)
    assert _scores(actual) == _scores(expected)
    assert actual_weights.calls == expected_weights.calls
    assert actual.heuristic_refs.events == expected.heuristic_refs.events


@pytest.mark.parametrize("weight", [None, 10**1000])
def test_failed_arithmetic_preserves_original_partial_mutation(weight):
    contexts = [("work", module, None, 1) for module in ["beta", "alpha", "beta"]]
    expected = _definition("alpha.work")
    actual = copy.deepcopy(expected)
    weights = {"same_file_attr": weight}
    with pytest.raises((TypeError, OverflowError)) as original_error:
        _original(expected, contexts, weights)
    with pytest.raises(type(original_error.value)):
        _ready_index(contexts).mark(actual, weights)
    assert _scores(actual) == _scores(expected)


def test_non_string_context_module_retains_legacy_behavior():
    contexts = [("work", None, None, 1), ("work", "alpha", None, 2)]
    expected = _definition("alpha.work")
    actual = copy.deepcopy(expected)
    _original(expected, contexts, {})
    _ready_index(contexts).mark(actual, {})
    assert _scores(actual) == _scores(expected)


def test_invalid_context_module_preserves_exception_and_prior_scores():
    contexts = [("work", "beta", None, 1), ("work", 1, None, 2)]
    expected = _definition("alpha.work")
    actual = copy.deepcopy(expected)
    with pytest.raises(AttributeError):
        _original(expected, contexts, {})
    with pytest.raises(AttributeError):
        _ready_index(contexts).mark(actual, {})
    assert _scores(actual) == _scores(expected)


def test_string_subclass_context_keeps_overridden_split_behavior():
    class ContextModule(str):
        def split(self, separator):
            return ["alpha"]

    contexts = [("work", ContextModule("beta"), None, 1)]
    expected = _definition("alpha.work")
    actual = copy.deepcopy(expected)
    _original(expected, contexts, {})
    _ready_index(contexts).mark(actual, {})
    assert _scores(actual) == _scores(expected)


def test_first_category_order_survives_many_modules_in_one_package():
    contexts = [
        ("work", module, None, line)
        for line, module in enumerate(
            ["alpha.one", "alpha.two", "alpha.three", "beta.one", "alpha"], 1
        )
    ]
    expected = _definition("alpha.work")
    actual = copy.deepcopy(expected)
    _original(expected, contexts, {})
    _ready_index(contexts).mark(actual, {})
    assert _scores(actual) == _scores(expected)


@pytest.mark.parametrize("context_count", [5, 33, 129])
def test_complete_mark_refs_and_evidence_match_for_mixed_languages(
    monkeypatch, context_count
):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)
    suffixes = [
        "py",
        "pyw",
        "pyi",
        "ts",
        "js",
        "tsx",
        "php",
        "go",
        "rs",
        "dart",
        "java",
        "kt",
        "cs",
        "cpp",
        "txt",
    ]
    kinds = ["function", "method", "variable", "class", "import", "parameter"]
    definitions = {}
    for index, (suffix, kind) in enumerate(
        (suffix, kind) for suffix in suffixes for kind in kinds
    ):
        name = f"alpha.scope{index}.work"
        definition = Definition(name, kind, Path(f"source{index}.{suffix}"), index + 1)
        definition.heuristic_refs = {"prior": 0.123}
        definitions[name] = definition
    modules = ["beta", "", "alpha.deep", "alpha", "beta"]
    contexts = [
        ("work", modules[line % len(modules)], "Class", line + 1)
        for line in range(context_count)
    ]
    expected, actual = Skylos(), Skylos()
    expected.defs, actual.defs = copy.deepcopy(definitions), copy.deepcopy(definitions)
    for analyzer in (expected, actual):
        analyzer._all_used_attr_context = contexts
        analyzer._all_used_attr_names = {"work"}
    actual._mark_refs()
    with monkeypatch.context() as patch:
        patch.setattr(attribute_module, "AttributeContextIndex", _OracleIndex)
        expected._mark_refs()
    for name, definition in actual.defs.items():
        assert _scores(definition) == _scores(expected.defs[name])
        assert definition.to_dict() == expected.defs[name].to_dict()
        assert (
            definition._attr_name_ref_count == expected.defs[name]._attr_name_ref_count
        )
    assert build_dead_code_evidence(actual.defs).to_dict(definitions=actual.defs) == (
        build_dead_code_evidence(expected.defs).to_dict(definitions=expected.defs)
    )


def test_exact_addition_is_reused_without_replaying_contexts():
    contexts = [("work", "beta", None, line) for line in range(200)]
    index = _ready_index(contexts)
    first = _definition("alpha.work")
    second = _definition("alpha.other.work")
    index.mark(first, {})
    results = dict(index.addition.results)
    index.mark(second, {})
    assert index.addition.results == results
    assert _scores(first) == _scores(second)


def test_addition_cache_eviction_preserves_bit_exact_scores(monkeypatch):
    monkeypatch.setattr(attribute_module, "_ADDITION_CACHE_LIMIT", 4)
    contexts = [("work", "beta", None, line) for line in range(13)]
    index = _ready_index(contexts)
    for initial in [0.0, -0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 0.0, -0.0]:
        expected = _definition("alpha.work", {"global_attr": initial})
        actual = copy.deepcopy(expected)
        _original(expected, contexts, {})
        index.mark(actual, {})
        assert _scores(actual) == _scores(expected)
        assert len(index.addition.results) <= 4


@pytest.mark.parametrize("context_count", [1, 3, 32, 33])
def test_short_and_single_use_attributes_do_not_build_count_maps(
    monkeypatch, context_count
):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)
    contexts = [
        (f"work{attribute}", "alpha", None, line)
        for attribute in range(20)
        for line in range(context_count)
    ]
    index = AttributeContextIndex(contexts)
    for attribute in range(20):
        expected = _definition(f"alpha.work{attribute}")
        actual = copy.deepcopy(expected)
        _original(expected, contexts, {})
        index.mark(actual, {})
        assert _scores(actual) == _scores(expected)
    assert not index.indexed_attributes
    assert not index.addition.results
    assert not index.seen_attributes if context_count <= 32 else index.seen_attributes


def test_large_repeated_attribute_builds_index_only_on_second_use(monkeypatch):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)
    contexts = [("work", "alpha", None, line) for line in range(33)]
    index = AttributeContextIndex(contexts)
    for use in range(3):
        expected = _definition("alpha.work")
        actual = copy.deepcopy(expected)
        _original(expected, contexts, {})
        index.mark(actual, {})
        assert _scores(actual) == _scores(expected)
        assert bool(index.indexed_attributes) == (use > 0)


def test_definition_attribute_name_is_read_once():
    class ObservedDefinition(Definition):
        @property
        def simple_name(self):
            self.name_reads = getattr(self, "name_reads", 0) + 1
            return self._observed_simple_name

        @simple_name.setter
        def simple_name(self, value):
            self._observed_simple_name = value

    actual = ObservedDefinition("alpha.work", "function", Path("module.py"), 3)
    actual.name_reads = 0
    contexts = [("work", "alpha", None, line) for line in range(33)]
    expected = _definition("alpha.work")
    _original(expected, contexts, {})
    _ready_index(contexts).mark(actual, {})
    assert _scores(actual) == _scores(expected)
    assert actual.name_reads == 1


def _python_compatible(definition, family):
    return _reference_language_family(definition.filename) in (None, family)


@pytest.mark.parametrize(
    "context_count, uses, indexed",
    [
        (32, 20, False),
        (33, 2, False),
        (33, 3, False),
        (33, 5, False),
        (33, 6, True),
        (128, 5, False),
        (128, 6, True),
        (129, 2, False),
        (129, 3, False),
        (129, 4, True),
        (10000, 2, False),
        (10000, 3, False),
        (10000, 4, True),
    ],
)
def test_census_selects_only_amortized_attributes_with_exact_score_parity(
    monkeypatch, context_count, uses, indexed
):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)
    contexts = [
        ("work", ["beta", "alpha.deep", "alpha"][line % 3], None, line)
        for line in range(context_count)
    ]
    definitions = {
        index: _definition(f"alpha.Scope{index}.work") for index in range(uses)
    }
    index = AttributeContextIndex(
        contexts, definitions=definitions, compatible_family=_python_compatible
    )
    for actual in definitions.values():
        expected = copy.deepcopy(actual)
        _original(expected, contexts, {})
        index.mark(actual, {})
        assert _scores(actual) == _scores(expected)
        assert actual.to_dict() == expected.to_dict()
    assert bool(index.indexed_attributes) is indexed
    if not indexed:
        assert not index.seen_attributes
        assert not index.addition.results


@pytest.mark.parametrize(
    "last_kind,last_filename,indexed",
    [
        ("function", "last.txt", True),  # Unknown families remain compatible.
        ("method", "last.PY", True),
        ("variable", "last.py", True),
        ("class", "last.py", False),
        ("import", "last.py", False),
        ("parameter", "last.py", False),
        ("function", "last.ts", False),
        ("method", "last.go", False),
    ],
)
def test_census_reuses_language_and_kind_eligibility(
    monkeypatch, last_kind, last_filename, indexed
):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)
    contexts = [("work", "alpha", None, line) for line in range(129)]
    definitions = {index: _definition(f"alpha.Scope{index}.work") for index in range(3)}
    last = Definition("alpha.Last.work", last_kind, last_filename, 4)
    definitions[3] = last
    # Global variables and non-Python symbols do not help pay the index cost.
    definitions[4] = Definition("work", "variable", "module.py", 5)
    for suffix in ["ts", "js", "go", "java", "rs", "php", "dart", "cs", "cpp"]:
        definitions[suffix] = Definition(
            f"alpha.{suffix}.work", "method", Path(f"module.{suffix}"), 6
        )
    index = AttributeContextIndex(
        contexts, definitions=definitions, compatible_family=_python_compatible
    )
    assert ("work" in index.indexing_candidates) is indexed


def test_census_reads_no_custom_definition_getters_and_preserves_single_read(
    monkeypatch,
):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)

    class ObservedDefinition(Definition):
        @property
        def simple_name(self):
            self.name_reads = getattr(self, "name_reads", 0) + 1
            return self._observed_simple_name

        @simple_name.setter
        def simple_name(self, value):
            self._observed_simple_name = value

    actual = ObservedDefinition("alpha.work", "function", Path("module.py"), 3)
    actual.name_reads = 0
    contexts = [("work", "alpha", None, line) for line in range(129)]
    index = AttributeContextIndex(
        contexts,
        definitions={"custom": actual},
        compatible_family=lambda *_args: pytest.fail("custom census"),
    )
    assert index.indexing_candidates is None
    assert actual.name_reads == 0
    index.mark(actual, {})
    assert actual.name_reads == 1


def test_census_does_not_iterate_custom_definition_mapping(monkeypatch):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)

    class ObservedDict(dict):
        def values(self):
            pytest.fail("custom mapping must not be enumerated")

    index = AttributeContextIndex(
        [("work", "alpha", None, line) for line in range(129)],
        definitions=ObservedDict(work=_definition("alpha.work")),
    )
    assert index.indexing_candidates is None


@pytest.mark.parametrize(
    "field", ["filename", "name", "simple_name", "type", "missing_filename"]
)
def test_census_skips_non_plain_fields_without_conversion(monkeypatch, field):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)

    class ConversionTrap:
        def __str__(self):
            pytest.fail("custom conversion during census")

        def __fspath__(self):
            pytest.fail("custom filename conversion during census")

    definition = _definition("alpha.work")
    if field == "missing_filename":
        del definition.filename
    else:
        setattr(definition, field, ConversionTrap())
    index = AttributeContextIndex(
        [("work", "alpha", None, line) for line in range(129)],
        definitions={"work": definition},
        compatible_family=lambda *_args: pytest.fail("non-plain census"),
    )
    assert index.indexing_candidates is None


def test_census_rejects_custom_path_subclasses_without_string_conversion(monkeypatch):
    monkeypatch.setattr(attribute_module, "_MIN_CONTEXTS_TO_INDEX", 32)

    class ObservedPath(type(Path())):
        def __str__(self):
            pytest.fail("custom Path conversion during census")

    definition = _definition("alpha.work")
    definition.filename = ObservedPath("module.py")
    index = AttributeContextIndex(
        [("work", "alpha", None, line) for line in range(129)],
        definitions={"work": definition},
        compatible_family=lambda *_args: pytest.fail("non-plain filename census"),
    )
    assert index.indexing_candidates is None
