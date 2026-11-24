"""Identify failures at an assert in the selected pytest test file."""

import ast
import json
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--replay-evidence")


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    report = yield
    if (
        report.when != "call"
        or not report.failed
        or call.excinfo is None
        or not call.excinfo.errisinstance(AssertionError)
    ):
        return report

    frame = call.excinfo.traceback[-1]
    if Path(str(frame.path)).resolve() != item.path.resolve():
        return report

    line = frame.lineno + 1
    tree = ast.parse(item.path.read_bytes())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert) and node.lineno <= line <= node.end_lineno:
            evidence = {"node_id": item.nodeid, "line": node.lineno}
            Path(item.config.getoption("--replay-evidence")).write_text(
                json.dumps(evidence), encoding="utf-8"
            )
            break
    return report
