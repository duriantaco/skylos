"""Locate a SQL operation inside a chain without guessing between SQL calls."""

import ast
import copy
from types import SimpleNamespace

import pytest

from skylos.security.static_trace import _sink_call, attach_security_traces
from test.fixture_paths import write_fixture


@pytest.mark.parametrize("rule", ["SKY-D211", "SKY-D217"])
@pytest.mark.parametrize("result_method", ["fetchall", "fetchone", "scalar"])
def test_unique_sql_operation_inside_result_chain_is_located(rule, result_method):
    tree = ast.parse(
        'sqlite3.connect("app.db").execute(query).' + result_method + "()\n"
    )
    calls = []
    selected = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append(node)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                selected = node
    assert selected is not None
    unit = SimpleNamespace(calls_by_line={1: calls})
    finding = {"rule_id": rule, "line": 1, "col": 0}
    assert _sink_call(unit, finding) is selected


@pytest.mark.parametrize("rule", ["SKY-D211", "SKY-D217"])
def test_two_sql_operations_at_the_same_location_remain_ambiguous(rule):
    tree = ast.parse("cursor.execute(first).execute(second).fetchall()\n")
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append(node)
    unit = SimpleNamespace(calls_by_line={1: calls})
    assert _sink_call(unit, {"rule_id": rule, "line": 1, "col": 0}) is None


def test_chained_sql_trace_keeps_input_source_and_original_finding(tmp_path):
    source = (
        "import sqlite3\n"
        "value = input()\n"
        'query = "SELECT * FROM items WHERE key = " + value\n'
        'sqlite3.connect("app.db").execute(query).fetchall()\n'
    )
    path = write_fixture(tmp_path, "app.py", source)
    finding = {
        "rule_id": "SKY-D211",
        "file": str(path),
        "line": 4,
        "col": 0,
        "severity": "HIGH",
        "metadata": {"security_evidence": {"preserved": True}},
    }
    original = copy.deepcopy(finding)
    attach_security_traces([finding], project_root=tmp_path, files=[path])
    trace = finding["metadata"].pop("security_trace")
    assert finding == original
    source_lines = []
    for step in trace["steps"]:
        if step["kind"] == "source":
            source_lines.append(step["line"])
    assert source_lines == [2]
