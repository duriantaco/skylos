"""Performance and catch-scope advice follows the work performed at that site."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.quality.logic_foundation import TryBlockPatternsRule, UnusedExceptVarRule
from skylos.rules.quality.performance import PerformanceRule


def _scan(rule, source, *, with_source=True):
    visitor = LinterVisitor([rule], "app.py")
    if with_source:
        visitor.context["source"] = source
    visitor.visit(ast.parse(source))
    return visitor.findings


@pytest.mark.parametrize("prefix, call", [
    ("import pandas as pd", "pd.read_csv"),
    ("from pandas import read_csv", "read_csv"),
    ("from pandas import read_csv as csv_reader", "csv_reader"),
])
def test_pandas_explicit_iterator_creates_a_lazy_reader(prefix, call):
    source = f"{prefix}\nreader = {call}(path, iterator=True)\n"
    assert _scan(PerformanceRule(), source) == []


@pytest.mark.parametrize("option", ["", ", iterator=False", ", iterator=None", ", iterator=flag"])
def test_eager_or_unproved_pandas_mode_retains_memory_advice(option):
    rows = _scan(PerformanceRule(), f"import pandas as pd\nframe = pd.read_csv(path{option})\n")
    assert [row["rule_id"] for row in rows] == ["SKY-P402"]


def test_iterator_keyword_does_not_exempt_an_unrelated_stream_read():
    rows = _scan(PerformanceRule(), "def load(stream):\n    return stream.read(iterator=True)\n")
    assert [row["rule_id"] for row in rows] == ["SKY-P401"]


def _deferred_body_source(kind):
    if kind == "lambda":
        deferred = "    later = lambda: (\n" + "".join(
            f"        deferred_{i}(),\n" for i in range(20)
        ) + "    )\n"
    else:
        deferred = f"    {kind}def later():\n" + "".join(
            f"        deferred_{i}()\n" for i in range(20)
        )
    compact_work = "    " + "; ".join(f"work_{i}()" for i in range(16)) + "\n"
    return "try:\n" + deferred + compact_work + "except ValueError:\n    recover()\n"


@pytest.mark.parametrize("kind", ["", "async ", "lambda"])
@pytest.mark.parametrize("with_source", [True, False])
def test_deferred_callable_bodies_do_not_inflate_the_enclosing_try(kind, with_source):
    # The compact outer work occupies one code line. Its helper's later work
    # is not executed within this try and cannot make it a 20+ line scope.
    assert _scan(
        TryBlockPatternsRule(), _deferred_body_source(kind), with_source=with_source
    ) == []


def test_real_outer_operations_remain_broad_with_a_nested_helper():
    source = (
        "try:\n"
        "    def later():\n"
        + "".join(f"        deferred_{i}()\n" for i in range(20))
        + "".join(f"    operation_{i}()\n" for i in range(16))
        + "except ValueError:\n    recover()\n"
    )
    rows = _scan(TryBlockPatternsRule(), source)
    assert [row["value"] for row in rows] == [17]


def test_class_body_work_executes_inside_the_try():
    source = (
        "try:\n    class Created:\n"
        + "".join(f"        operation_{i}()\n" for i in range(16))
        + "except ValueError:\n    recover()\n"
    )
    rows = _scan(TryBlockPatternsRule(), source)
    assert [row["value"] for row in rows] == [17]


def test_nested_function_defaults_are_evaluated_inside_the_try():
    source = (
        "try:\n    def later(value=(\n"
        + "".join(f"        operation_{i}(),\n" for i in range(16))
        + "    )):\n        return value\n"
        + "except ValueError:\n    recover()\n"
    )
    rows = _scan(TryBlockPatternsRule(), source)
    assert len(rows) == 1
    assert rows[0]["value"] > 15


def test_class_control_flow_is_not_a_deferred_function_body():
    source = (
        "try:\n    class Created:\n"
        + "".join(f"        if condition_{i}: operation_{i}()\n" for i in range(4))
        + "except ValueError:\n    recover()\n"
    )
    rows = _scan(TryBlockPatternsRule(), source)
    assert [row["value"] for row in rows] == [4]


@pytest.mark.parametrize("template", ["Failure: {error!r}", "{error.args[0]}"])
@pytest.mark.parametrize("namespace", ["locals", "vars"])
def test_exception_capture_read_by_literal_format_mapping(template, namespace):
    source = (
        "try:\n    operation()\nexcept ValueError as error:\n"
        f"    emit({template!r}.format_map({namespace}()))\n"
    )
    assert _scan(UnusedExceptVarRule(), source) == []


@pytest.mark.parametrize("expression", [
    "'Escaped: {{error}}'.format_map(locals())",
    "'Different: {other}'.format_map(locals())",
    "template.format_map(locals())",
    "unknown.format_map(locals())",
    "'Invalid: {error'.format_map(locals())",
])
def test_format_lookalikes_do_not_prove_an_exception_field_read(expression):
    source = f"try:\n    operation()\nexcept ValueError as error:\n    emit({expression})\n"
    assert [row["rule_id"] for row in _scan(UnusedExceptVarRule(), source)] == ["SKY-L005"]


def test_shadowed_namespace_function_cannot_prove_a_mapping_read():
    source = (
        "def run(locals):\n    try:\n        operation()\n"
        "    except ValueError as error:\n        emit('{error}'.format_map(locals()))\n"
    )
    assert [row["rule_id"] for row in _scan(UnusedExceptVarRule(), source)] == ["SKY-L005"]


def test_format_mapping_of_a_new_binding_does_not_read_the_caught_exception():
    source = (
        "try:\n    operation()\nexcept ValueError as error:\n"
        "    error = None\n    emit('{error}'.format_map(locals()))\n"
    )
    assert [row["rule_id"] for row in _scan(UnusedExceptVarRule(), source)] == ["SKY-L005"]


@pytest.mark.parametrize("replacement", ["error = None", "error: object = None", "del error"])
def test_replacing_or_deleting_capture_is_not_reading_the_exception(replacement):
    source = f"try:\n    operation()\nexcept ValueError as error:\n    {replacement}\n"
    assert [row["rule_id"] for row in _scan(UnusedExceptVarRule(), source)] == ["SKY-L005"]


@pytest.mark.parametrize("use", ["emit(error)", "error += context", "error.value = context"])
def test_real_exception_load_and_augmented_assignment_remain_uses(use):
    source = f"try:\n    operation()\nexcept ValueError as error:\n    {use}\n"
    assert _scan(UnusedExceptVarRule(), source) == []
