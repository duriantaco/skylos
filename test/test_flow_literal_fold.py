"""Literal-only folding in ``flow_env``: a test built only from literals and
pure operators keeps only its live branch; any name, including a module
constant, keeps both. ``SKYLOS_DISABLE_LITERAL_FOLD=1`` turns it off."""

import ast
import os
import subprocess
import sys
import textwrap

import pytest

from skylos.rules.danger import flow_env

TAINT = frozenset({"tainted"})


def _evaluate(node, value):
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "source"
    ):
        return TAINT
    labels = frozenset()
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.expr):
            labels |= value(child)
    return labels


def _sink_labels(code):
    tree = ast.parse(textwrap.dedent(code))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
    sinks = [
        node.args[0]
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "sink"
    ]
    flow = flow_env.ValueFlow(
        function,
        _evaluate,
        outer=lambda name: frozenset(),
        top=frozenset({"unknown"}),
    )
    results = flow.run(sinks)
    return [results.get(id(node)) for node in sinks]


DEAD_BRANCHES = """
def f():
    if 7 * 42 > 200:
        x = 'a'
    else:
        x = source()
    sink(x)
    y = 'a' if 1 < 2 else source()
    sink(y)
    z = 'a'
    w = 'b' if True else (z := source())
    sink(z)
    match 'b':
        case 'a':
            v = source()
        case 'b':
            v = 'c'
        case _:
            v = source()
    sink(v)
"""


def test_literal_tests_keep_only_the_live_branch():
    assert _sink_labels(DEAD_BRANCHES) == [frozenset()] * 4


def test_turning_folding_off_keeps_every_branch(monkeypatch):
    monkeypatch.setattr(flow_env, "LITERAL_FOLD_ENABLED", False)
    assert _sink_labels(DEAD_BRANCHES) == [TAINT] * 4


@pytest.mark.parametrize(
    "test",
    [
        "7 * 42 - num > 200",
        "FLAG",
        "True and c",
        "c > 200",
        "10 ** 10 ** 10",
        "'a' * 10 ** 9",
        "len('abc') > 2",
    ],
)
def test_tests_with_names_calls_or_unbounded_values_keep_both_branches(test):
    code = (
        "FLAG = False\n"
        "def f(c):\n"
        "    num = 86\n"
        f"    if {test}:\n"
        "        x = 'a'\n"
        "    else:\n"
        "        x = source()\n"
        "    sink(x)\n"
    )
    assert _sink_labels(code) == [TAINT]


def test_environment_switch_disables_folding_for_the_process():
    env = {**os.environ, "SKYLOS_DISABLE_LITERAL_FOLD": "1"}
    output = subprocess.run(
        [
            sys.executable,
            "-c",
            "from skylos.rules.danger import flow_env;"
            "print(flow_env.LITERAL_FOLD_ENABLED)",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert output.stdout.strip() == "False"
