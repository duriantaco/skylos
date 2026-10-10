"""Adaptive attribute-index selection checks against the frozen scoring oracle."""

import copy
from functools import partial
from pathlib import Path

import pytest

import skylos.analysis.attribute_refs as attribute_module
from skylos.analysis.attribute_refs import AttributeContextIndex
from skylos.analyzer import _reference_language_family
from skylos.visitors.base import Definition
from test.attribute_ref_oracle import _definition as _make_definition
from test.attribute_ref_oracle import _original, _scores


_definition = partial(_make_definition, Definition)


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
