"""Caller discovery limits keep findings visible without depending on timing."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.danger.danger_fs import path_provenance
from test.fixture_paths import write_fixture


def _scan(tmp_path, source):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname = "proj"\n')
    write_fixture(tmp_path, "app.py", source)
    return json.loads(analyze(str(tmp_path), enable_danger=True))


def _path_rows(report, symbol, category="danger"):
    return [
        row
        for row in report.get(category, [])
        if row["rule_id"] == "SKY-D215" and row.get("symbol") == symbol
    ]


def _operand_findings(path, source, symbols):
    findings = []
    for function in ast.parse(source).body:
        if not isinstance(function, ast.FunctionDef) or function.name not in symbols:
            continue
        operand = next(
            node for node in ast.walk(function) if isinstance(node, ast.BinOp)
        )
        findings.append(
            {
                "rule_id": "SKY-D215",
                "file": str(path),
                "line": operand.lineno,
                "symbol": function.name,
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
        )
    return findings


def test_acyclic_parameter_name_collisions_bound_caller_discovery(
    tmp_path, monkeypatch
):
    # Each reference makes values() ask for another function's callers with
    # depth=0. An expression-depth check alone cannot stop this acyclic chain.
    project = path_provenance._Project(tmp_path, complete=True)
    source = "def f0():\n    pass\n\n" + "".join(
        f"def f{index}(f{index - 1}):\n    return f{index - 1}\n\n"
        for index in range(1, 96)
    )
    project._add_python(tmp_path / "app.py", source)
    project._index()
    unit, _, scope, _ = next(iter(project.function_info.values()))
    entered = []
    original = project._call_sites

    def counting(unit, fn):
        entered.append(fn.name)
        return original(unit, fn)

    monkeypatch.setattr(project, "_call_sites", counting)

    with pytest.raises(path_provenance._ResolutionLimit, match="depth limit"):
        project.call_sites(unit, scope.node)

    assert len(entered) <= path_provenance._MAX_RESOLUTION_DEPTH
    assert not project._sites_active
    assert not project._value_active
    assert not project._param_value_active


@pytest.mark.parametrize("limit", ["depth", "work"])
def test_exhausted_caller_resolution_keeps_original_findings(
    tmp_path, monkeypatch, limit
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    if limit == "depth":
        monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_DEPTH", 4)
    else:
        monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_WORK", 24)
    source = (
        "from pathlib import Path\n\n"
        "def f0(name):\n    return (Path('/srv') / name).read_text()\n\n"
        + "".join(
            f"def f{index}(f{index - 1}):\n    return f{index - 1}\n\n"
            for index in range(1, 20)
        )
    )

    report = _scan(tmp_path, source)

    rows = _path_rows(report, "f0")
    assert rows
    assert not _path_rows(report, "f0", "suppressed")
    for row in rows:
        record = row["metadata"]["path_provenance"]
        assert record["status"] == "incomplete"
        assert any(
            f"caller resolution {limit}" in step
            for chain in record["incomplete"]
            for step in chain
        )


def test_work_budget_is_shared_by_findings_and_interrupted_facts_are_not_reused(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(path_provenance, "_MAX_RESOLUTION_WORK", 24)
    source = (
        "from pathlib import Path\n\n"
        "def f0(name):\n    return (Path('/srv') / name).read_text()\n\n"
        + "".join(
            f"def f{index}(f{index - 1}):\n    return f{index - 1}\n\n"
            for index in range(1, 20)
        )
        + "def second(name):\n    return (Path('/srv') / name).read_text()\n\n"
        "second('notes.txt')\n"
    )
    path = write_fixture(tmp_path, "app.py", source)
    findings = _operand_findings(path, source, {"f0", "second"})
    projects = []
    original = path_provenance._Project.load

    def loading(*args, **kwargs):
        project = original(*args, **kwargs)
        projects.append(project)
        return project

    monkeypatch.setattr(path_provenance._Project, "load", loading)
    suppressed = []

    kept = path_provenance.resolve_helper_parameter_findings(
        findings, scan_path=str(tmp_path), project_root=tmp_path, suppressed=suppressed
    )

    assert [row["symbol"] for row in kept] == ["f0", "second"]
    assert not suppressed
    assert all(
        row["metadata"]["path_provenance"]["status"] == "incomplete"
        for row in kept
    )
    assert len(projects) == 1
    assert projects[0]._resolution_work == 25


def test_partial_subclass_cache_is_not_reused_after_a_limit(tmp_path, monkeypatch):
    source = (
        "from pathlib import Path\n"
        "class Base:\n"
        "    def __init__(self, name):\n        self.name = name\n"
        "class Child(Base):\n    pass\n"
        "base = Base('notes.txt')\n"
        "def before(name):\n    return (Path('/srv') / name).read_text()\n"
        "before('safe.txt')\n"
        "def first():\n    return (Path('/srv') / base.name).read_text()\n"
        "def second():\n    return (Path('/srv') / base.name).read_text()\n"
    )
    path = write_fixture(tmp_path, "app.py", source)
    findings = _operand_findings(path, source, {"before", "first", "second"})
    projects = []
    original_subclasses = path_provenance._Project.subclasses

    def interrupted_subclasses(project, node):
        if project._subclasses is None:
            # The real index seeds an empty dictionary before resolving bases.
            # Exhaust work on the next base lookup, leaving that cache partial.
            monkeypatch.setattr(
                path_provenance, "_MAX_RESOLUTION_WORK", project._resolution_work
            )
            projects.append(project)
        return original_subclasses(project, node)

    monkeypatch.setattr(
        path_provenance._Project, "subclasses", interrupted_subclasses
    )
    classified = []
    original_classify = path_provenance._classify

    def counting(project, tracers, finding):
        classified.append(finding["symbol"])
        return original_classify(project, tracers, finding)

    monkeypatch.setattr(path_provenance, "_classify", counting)
    suppressed = []

    kept = path_provenance.resolve_helper_parameter_findings(
        findings, scan_path=str(tmp_path), project_root=tmp_path, suppressed=suppressed
    )

    assert classified == ["before", "first"]
    assert len(projects) == 1
    assert projects[0]._subclasses == {}
    assert [row["symbol"] for row in kept] == ["first", "second"]
    assert all(
        row["metadata"]["path_provenance"]["status"] == "incomplete"
        for row in kept
    )
    assert [row["symbol"] for row in suppressed] == ["before"]
    assert suppressed[0]["metadata"]["path_provenance"]["status"] == "safe"


@pytest.mark.parametrize("untrusted", [False, True])
def test_short_caller_chains_still_resolve_safe_and_untrusted_values(
    tmp_path, monkeypatch, untrusted
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = (
        "from pathlib import Path\n\n"
        "def read_file(name):\n    return (Path('/srv') / name).read_text()\n\n"
    )
    if untrusted:
        source += (
            "from flask import Flask, request\napp = Flask(__name__)\n"
            "@app.route('/read')\ndef view():\n"
            "    return read_file(request.args['name'])\n"
        )
    else:
        source += "read_file('notes.txt')\n"

    report = _scan(tmp_path, source)

    category = "danger" if untrusted else "suppressed"
    rows = _path_rows(report, "read_file", category)
    assert rows
    assert all(
        row["metadata"]["path_provenance"]["status"]
        == ("untrusted" if untrusted else "safe")
        for row in rows
    )
