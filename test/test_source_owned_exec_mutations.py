"""Project source location alone cannot establish trusted executable bytes."""

import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule


HEADER = (
    "import ast\nimport os\nimport shutil\nfrom pathlib import Path\n"
    "from flask import request\n"
    'SOURCE = Path(__file__).with_name("core.py")\n'
)
READ_EXEC = (
    "    tree = ast.parse(SOURCE.read_text())\n"
    '    exec(compile(tree, "core.py", "exec"), {})\n'
)
WRITER = (
    "from pathlib import Path\nfrom flask import request\n"
    'TARGET = Path(__file__).with_name("core.py")\n'
    "def upload():\n    TARGET.write_text(request.data.decode())\n"
)


def _project(tmp_path, body, extra=None):
    root = tmp_path / "project"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname="fixture"\n')
    (root / "core.py").write_text("def calculate(value):\n    return value + 1\n")
    (root / "loader.py").write_text(HEADER + body)
    for relative, source in (extra or {}).items():
        (root / relative).write_text(source.replace("__SOURCE_DIRECTORY__", str(root)))
    return root


WRITES = [
    "    SOURCE.write_text(request.data.decode())\n",
    "    SOURCE.write_bytes(request.data)\n",
    '    with open(SOURCE, "w") as handle:\n        handle.write(request.data.decode())\n',
    "    writer = SOURCE.write_text\n    writer(request.data.decode())\n",
    '    pending = SOURCE.with_name("pending.py")\n'
    "    pending.write_text(request.data.decode())\n    os.replace(pending, SOURCE)\n",
    '    pending = SOURCE.with_name("pending.py")\n'
    "    pending.write_text(request.data.decode())\n    pending.replace(SOURCE)\n",
    "    shutil.copyfile(request.args['file'], SOURCE)\n",
    "    persist(SOURCE, request.data)\n",
    "    from functools import partial\n"
    "    persist = partial(SOURCE.write_text)\n    persist(request.data.decode())\n",
    "    from builtins import open as writer\n"
    '    with writer(SOURCE, "w") as handle:\n        handle.write(request.data.decode())\n',
    "    from os import rename as move\n    move(request.args['file'], SOURCE)\n",
]


@pytest.mark.parametrize("write", WRITES)
def test_mutable_source_file_keeps_raw_listing_and_gate(tmp_path, write):
    root = _project(tmp_path, "def run():\n" + write + READ_EXEC)
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )
    assert result.get("analysis_errors", []) == []
    rows = [
        row
        for row in result.get("danger", [])
        if row["rule_id"] == "SKY-D202" and row["file"].endswith("loader.py")
    ]
    assert len(rows) == 1
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["listing"]["listed"] is True
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})
    assert passed is False
    assert any("security issue" in reason for reason in reasons)


EXTERNAL = {
    "independent_writer": WRITER,
    "imported_writer": WRITER.replace("def upload():", "def upload(code):").replace(
        "request.data.decode()", "code"
    ),
    "reader_override": "from pathlib import Path\nPath.read_text = lambda self, **kw: input()\n",
    "parser_override": "import ast\nast.parse = lambda text, **kw: ast.Module(body=[], type_ignores=[])\n",
    "dynamic_code": "exec(input(), {})\n",
    "dynamic_loader": "import importlib\nimportlib.import_module(input())\n",
    "reflective_reader": 'from pathlib import Path\ngetattr(Path, "__dict__")[input()] = input()\n',
    "directory_replace": "import shutil\nfrom pathlib import Path\n"
    "def upload(path):\n    shutil.copytree(path, Path(__file__).parent, dirs_exist_ok=True)\n",
    "opaque_literal_writer": "from opaque_runtime import publish\n"
    'def upload():\n    publish(input(), "__SOURCE_DIRECTORY__")\n',
    "opaque_path_alias": "from opaque_runtime import publish\n"
    'DESTINATION = "__SOURCE_DIRECTORY__"\n'
    "def upload():\n    destination = DESTINATION\n    publish(input(), destination)\n",
    "opaque_noarg_effect": "import opaque_runtime\nopaque_runtime.install()\n",
}


@pytest.mark.parametrize("kind", EXTERNAL)
def test_project_writer_or_reader_override_keeps_exec(tmp_path, kind):
    body = "def run():\n"
    if kind == "imported_writer":
        body = (
            "import external\ndef run():\n    external.upload(request.data.decode())\n"
        )
    root = _project(tmp_path, body + READ_EXEC, {"external.py": EXTERNAL[kind]})
    path = root / "loader.py"
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = str(root)
    linter.visit(ast.parse(path.read_text()))
    assert any(row["rule_id"] == "SKY-D202" for row in linter.findings)


@pytest.mark.parametrize(
    "body",
    [
        "def run():\n" + READ_EXEC,
        "def run():\n    tree = ast.parse(SOURCE.read_text())\n"
        "    alias = tree\n    alias.body = ast.parse(request.data.decode()).body\n"
        '    exec(compile(tree, "core.py", "exec"), {})\n',
    ],
    ids=["safe_project_source", "unsafe_ast_alias"],
)
def test_existing_source_and_ast_mutation_distinction(tmp_path, body):
    root = _project(tmp_path, body)
    path = root / "loader.py"
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = str(root)
    linter.visit(ast.parse(path.read_text()))
    detected = any(row["rule_id"] == "SKY-D202" for row in linter.findings)
    assert detected is ("alias.body" in body)


def test_unrelated_literal_output_does_not_invalidate_source(tmp_path):
    body = (
        "def run():\n"
        '    output = SOURCE.with_name("result.txt")\n'
        '    output.write_text("complete")\n' + READ_EXEC
    )
    root = _project(tmp_path, body)
    path = root / "loader.py"
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = str(root)
    linter.visit(ast.parse(path.read_text()))
    assert not any(row["rule_id"] == "SKY-D202" for row in linter.findings)


def test_immutable_project_source_keeps_zero_limit_gate_passing(tmp_path):
    root = _project(tmp_path, "def run():\n" + READ_EXEC)
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )
    assert result.get("analysis_errors", []) == []
    assert not any(
        row["rule_id"] in {"SKY-D201", "SKY-D202"} for row in result.get("danger", [])
    )
    assert check_gate(result, {"gate": {"max_high": 0, "max_security": 0}}) == (
        True,
        [],
    )


@pytest.mark.parametrize(
    "body",
    [
        "def run(callback):\n    callback()\n" + READ_EXEC,
        "import external\ndef run():\n    external.callback()\n" + READ_EXEC,
        "def run(callbacks):\n    callbacks.before()\n" + READ_EXEC,
        "def run(callback):\n    bool(callback)\n" + READ_EXEC,
        "def run(callback):\n    list(callback)\n" + READ_EXEC,
        'def run(callback):\n    getattr(callback, "before")\n' + READ_EXEC,
    ],
    ids=[
        "parameter_callback",
        "external_callback",
        "receiver_callback",
        "implicit_bool",
        "implicit_iterator",
        "implicit_attribute",
    ],
)
def test_unknown_callback_effects_cannot_prove_source(tmp_path, body):
    root = _project(tmp_path, body)
    path = root / "loader.py"
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = str(root)
    linter.visit(ast.parse(path.read_text()))
    assert any(row["rule_id"] == "SKY-D202" for row in linter.findings)


@pytest.mark.parametrize(
    "module,constructor", [("zipfile", "ZipFile"), ("tarfile", "open")]
)
def test_archive_overwrite_in_another_endpoint_keeps_exec(
    tmp_path, module, constructor
):
    external = (
        f"import {module}\n"
        f"def upload(path):\n    with {module}.{constructor}(path) as archive:\n"
        '        archive.extractall("__SOURCE_DIRECTORY__")\n'
    )
    root = _project(tmp_path, "def run():\n" + READ_EXEC, {"upload.py": external})
    result = json.loads(
        analyze(
            str(root),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )
    assert result.get("analysis_errors", []) == []
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D202"]
    assert len(rows) == 1
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["listing"]["listed"] is True
    passed, reasons = check_gate(result, {"gate": {"max_high": 0, "max_security": 0}})
    assert passed is False
    assert any("security issue" in reason for reason in reasons)
