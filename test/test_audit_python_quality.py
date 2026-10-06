import ast
import inspect
from types import CodeType

import pytest

from skylos.analysis.control_flow import (
    evaluate_static_condition,
    evaluate_static_truth,
)
from skylos.rules.quality.unreachable import UnreachableCodeRule
from skylos.visitors.base import Visitor


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("1 or 0", 1),
        ("0 and 1", 0),
        ("'' or 'ready'", "ready"),
        ("'ready' and ''", ""),
        ("(False or 7) == 7", True),
        ("(True and 7) == 7", True),
        ("(None or 7) == 7", True),
        ("not None", True),
        ("None is None", True),
        ("0 is not None", True),
        ("False and unknown()", False),
        ("True or unknown()", True),
    ],
)
def test_static_expression_preserves_python_operand_values(expression, expected):
    result = evaluate_static_condition(ast.parse(expression, mode="eval").body)
    assert result == expected
    assert type(result) is type(expected)


@pytest.mark.parametrize(
    "expression",
    [
        "unknown or 1",
        "unknown and 0",
        "(unknown or True) == True",
        "(unknown and False) == False",
        "unknown == None",
        "bool(1)",
        "1000 is 1000",
        "'same' is 'same'",
    ],
)
def test_unknown_operands_do_not_prove_a_comparison(expression):
    assert evaluate_static_condition(ast.parse(expression, mode="eval").body) is None


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("None", False),
        ("0", False),
        ("''", False),
        ("1", True),
        ("'ready'", True),
        ("True and None", False),
        ("unknown or 1", True),
        ("unknown and 0", False),
        ("not (unknown or 1)", False),
        ("(unknown or True) == True", None),
    ],
)
def test_branch_truth_is_distinct_from_operand_values(expression, expected):
    assert evaluate_static_truth(ast.parse(expression, mode="eval").body) is expected


@pytest.mark.parametrize("condition,chosen", [("1 or 0", "live"), ("0 and 1", "other")])
def test_branch_visitor_keeps_the_actual_called_function(condition, chosen):
    tree = ast.parse(
        f"def live():\n    pass\ndef other():\n    pass\n"
        f"if {condition}:\n    live()\nelse:\n    other()\n"
    )
    visitor = Visitor("sample", "sample.py")
    visitor.visit(tree)
    references = {name for name, _ in visitor.refs}
    assert f"sample.{chosen}" in references
    assert f"sample.{'other' if chosen == 'live' else 'live'}" not in references


def _quality(source):
    tree = ast.parse(source)
    rule = UnreachableCodeRule()
    return [
        finding
        for node in ast.walk(tree)
        for finding in (rule.visit_node(node, {"filename": "sample.py"}) or [])
    ]


@pytest.mark.parametrize(
    "prefix,flag", [("", inspect.CO_GENERATOR), ("async ", inspect.CO_ASYNC_GENERATOR)]
)
def test_httpx_style_unreachable_yield_is_required_generator_metadata(prefix, flag):
    source = f"{prefix}def read():\n    raise RuntimeError()\n    yield b''\n"
    compiled = compile(source, "sample.py", "exec")
    function = next(code for code in compiled.co_consts if isinstance(code, CodeType))
    assert function.co_flags & flag
    ordinary = compile(source.replace("    yield b''\n", ""), "sample.py", "exec")
    ordinary_function = next(
        code for code in ordinary.co_consts if isinstance(code, CodeType)
    )
    assert not ordinary_function.co_flags & flag
    assert _quality(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "def read():\n    raise RuntimeError()\n    yield calculate()\n",
        "def read():\n    yield b'first'\n    raise RuntimeError()\n    yield b'second'\n",
        "def read():\n    raise RuntimeError()\n    yield b''\n    calculate()\n",
        "def read():\n    raise RuntimeError()\n    calculate()\n",
    ],
)
def test_real_unreachable_work_remains_reported(source):
    assert any(finding["rule_id"] == "SKY-UC001" for finding in _quality(source))
