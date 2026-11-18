"""A reviewed code operand still participates in raw security gates."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule

LOADER = """import ast
from pathlib import Path

SOURCE = Path(__file__).with_name("definitions.py")

def load():
    tree = ast.parse(SOURCE.read_text())
    selected = ast.Module(body=[tree.body[0]], type_ignores=[])
    value = {}
    exec(compile(selected, str(SOURCE), "exec"), value)

def session_finished(callback):
    callback()
"""


def project(tmp_path, source=LOADER, extra=None, runner="loader.py"):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "loader"\n')
    (tmp_path / "definitions.py").write_text("def one():\n    return 1\n")
    path = tmp_path / runner
    path.write_text(source)
    for name, body in (extra or {}).items():
        (tmp_path / name).write_text(body)
    return path


def rows(path):
    tree = ast.parse(path.read_text())
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = str(path.parent)
    linter.visit(tree)
    return [finding for finding in linter.findings if finding["rule_id"] == "SKY-D202"]


def test_review_carries_positive_source_proof_and_keeps_strict_gate(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    project(tmp_path)
    report = json.loads(
        analyze(str(tmp_path), enable_danger=True, grep_verify=False, trace_file=False)
    )
    assert not report.get("analysis_errors")
    (row,) = [r for r in report["danger"] if r["rule_id"] == "SKY-D202"]
    evidence = row["low_risk_context"]
    assert evidence["reason"] == "compiled-project-source"
    assert evidence["source_files"] == ["definitions.py"]
    assert evidence["scope"] == "loader-and-imports"
    assert evidence["runtime_integrity"] == "unverified"
    assert check_gate(report, {"gate": {"max_high": 0, "max_security": 0}})[0] is False


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("SOURCE.read_text()", "input()"),
        ("SOURCE.read_text()", 'request.args["code"]'),
        ("SOURCE.read_text()", "SOURCE.read_text() if flag else input()"),
        ("SOURCE.read_text()", "Path(input()).read_text()"),
        ("SOURCE.read_text()", "SOURCE.read_text() + extra_code"),
        (
            "selected = ast.Module",
            "tree.body.extend(ast.parse(input()).body)\n    selected = ast.Module",
        ),
        ("value = {}", 'value = {"__builtins__": unknown}'),
        ("value = {}", "value = {**unknown}"),
        ("value = {}", "value = dict(unknown)"),
        ("value = {}", "value = {}\n    value.update(unknown)"),
        ("value = {}", 'value = {}\n    value["__builtins__"] = unknown'),
        (
            "value = {}",
            'value = {}\n    alias = value\n    alias["__builtins__"] = unknown',
        ),
        ('"exec"), value)', '"exec"), value, extra_locals)'),
        ('"exec"), value)', '"exec"), value, closure=extra_cells)'),
        ("value = {}", "value = {}\n    SOURCE.write_text(input())"),
        ("def load():", "def load():\n    compile = converter"),
        ("def load():", "def load():\n    exec = replacement"),
        ("def load():", "def load():\n    ast.parse = replacement"),
        ("def load():", "def load():\n    Path.read_text = replacement"),
        (
            'SOURCE = Path(__file__).with_name("definitions.py")',
            "SOURCE = trusted_source",
        ),
    ],
)
def test_external_content_or_substitution_stays_primary_in_test_files(
    tmp_path, old, new
):
    source = LOADER.replace(old, new)
    findings = rows(project(tmp_path, source, runner="test_reader.py"))
    assert findings
    assert all(row.get("low_risk_context") is None for row in findings)


def test_uncontrolled_runner_in_same_module_keeps_every_call_primary(tmp_path):
    source = LOADER + "\ndef execute_other(command):\n    exec(command, {})\n"
    findings = rows(project(tmp_path, source, runner="test_reader.py"))
    assert len(findings) == 2
    assert all(row.get("low_risk_context") is None for row in findings)


@pytest.mark.parametrize(
    ("source", "external"),
    [
        (LOADER, "from pathlib import Path\nPath.read_text = replacement\n"),
        (
            LOADER,
            'from pathlib import Path\nfrom unittest.mock import patch\npatch.object(Path, "read_text", replacement).start()\n',
        ),
        (
            LOADER,
            'from pathlib import Path\nSOURCE = Path(__file__).with_name("definitions.py")\nSOURCE.write_text(input())\n',
        ),
        (
            LOADER,
            'from pathlib import Path\nPath("definitions.py").write_text(input())\n',
        ),
        (LOADER, 'from pathlib import Path\nPath("definitions.py").open("wb")\n'),
        (LOADER, 'open("definitions.py", "w")\n'),
        ("import external\n" + LOADER, "import ast\nast.parse = replacement\n"),
        ("import external\n" + LOADER, "import plugin\nplugin.install()\n"),
    ],
)
def test_observed_project_mutation_or_unknown_imported_effect_stays_primary(
    tmp_path, source, external
):
    (row,) = rows(project(tmp_path, source, {"external.py": external}))
    assert row.get("low_risk_context") is None
