"""Completed dynamic target lookups must not consume every caller's budget."""

import ast

import pytest

from skylos.rules.danger.danger_fs import path_provenance as graph


def _project(tmp_path, source):
    project = graph._Project(tmp_path, complete=True)
    project._add_python(tmp_path / "app.py", source)
    project._index()
    return project


def _finding(path, source, symbol):
    function = next(
        node for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name == symbol
    )
    operand = next(node for node in ast.walk(function) if isinstance(node, ast.BinOp))
    return {
        "rule_id": "SKY-D215",
        "file": str(path),
        "line": operand.lineno,
        "symbol": symbol,
        "metadata": {
            "path_source": "helper_parameter",
            "path_operand": {
                "line": operand.lineno,
                "col": operand.col_offset,
                "end_line": operand.end_lineno,
                "end_col": operand.end_col_offset,
            },
        },
    }


def test_dynamic_call_sites_are_indexed_once(tmp_path):
    project = _project(
        tmp_path,
        "def factory():\n    return print\n"
        "factory()('message')\n"
        "handlers = [print]\nhandlers[0]('message')\n",
    )

    assert len(project.dynamic_calls) == 2
    assert len({id(call) for _, call, _ in project.dynamic_calls}) == 2


def test_unrelated_dynamic_targets_do_not_exhaust_the_shared_budget(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(graph, "_MAX_RESOLUTION_WORK", 1000)
    source = (
        "def external_factory():\n    return print\n"
        + "".join("external_factory()('message')\n" for _ in range(80))
        + "".join(
            f"def reader{index}(name):\n    return name\n"
            f"reader{index}('notes.txt')\n"
            for index in range(48)
        )
    )
    project = _project(tmp_path, source)

    for unit, _, scope, _ in project.function_info.values():
        if not scope.node.name.startswith("reader"):
            continue
        sites = project.call_sites(unit, scope.node)
        assert len(sites.resolved) == 1
        assert not sites.possible
        assert not sites.escapes

    assert project._resolution_work <= 1000


@pytest.mark.parametrize(
    ("definition", "factory", "symbol"),
    [
        (
            "def read_bad(name):\n    return (Path('/srv') / name).read_text()\n",
            "def pick():\n    return read_bad\n",
            "read_bad",
        ),
        (
            "def read_bad(name):\n    return (Path('/srv') / name).read_text()\n",
            "from functools import partial\n"
            "def pick():\n    return partial(read_bad)\n",
            "read_bad",
        ),
        (
            "class Reader:\n"
            "    def __init__(self, name):\n"
            "        (Path('/srv') / name).read_text()\n"
            "class Child(Reader):\n    pass\n",
            "def pick():\n    return Child\n",
            "__init__",
        ),
        (
            "def read_bad(name):\n    return (Path('/srv') / name).read_text()\n",
            "def pick():\n    return read_bad if flag else print\n",
            "read_bad",
        ),
    ],
    ids=["function", "partial", "inherited_constructor", "mixed_targets"],
)
def test_cached_targets_keep_the_unsafe_caller_after_a_safe_finding(
    tmp_path, definition, factory, symbol
):
    source = (
        "from pathlib import Path\nfrom flask import request\n"
        "def read_safe(name):\n    return (Path('/srv') / name).read_text()\n"
        "read_safe('notes.txt')\n"
        + definition
        + factory
        + "pick()(request.args['name'])\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source)
    findings = [_finding(path, source, name) for name in ("read_safe", symbol)]
    suppressed = []

    kept = graph.resolve_helper_parameter_findings(
        findings, scan_path=str(tmp_path), project_root=tmp_path, suppressed=suppressed
    )

    assert [row["symbol"] for row in kept] == [symbol]
    assert kept[0]["metadata"]["path_provenance"]["status"] == "untrusted"
    assert kept[0]["metadata"]["path_source"] == "resolved_caller"
    assert [row["symbol"] for row in suppressed] == ["read_safe"]
    assert suppressed[0]["metadata"]["path_provenance"]["status"] == "safe"
