"""Both Python scanner entry points consume the same owned-source proof."""

import ast

import pytest

from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


@pytest.mark.parametrize("unsafe", [False, True])
def test_source_bytes_and_mutation_have_consistent_results(tmp_path, unsafe):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="proof-parity"\n')
    write_fixture(tmp_path, "core.py", "def value():\n    return 1\n")
    mutation = "    SOURCE.write_text(request.data.decode())\n" if unsafe else ""
    source = (
        "import ast\nfrom pathlib import Path\nfrom flask import request\n"
        'SOURCE=Path(__file__).with_name("core.py")\n'
        "def load():\n"
        + mutation
        + "    tree=ast.parse(SOURCE.read_text())\n"
        + '    exec(compile(tree, "core.py", "exec"), {})\n'
    )
    write_fixture(tmp_path, "loader.py", source)
    path = tmp_path / "loader.py"
    visitor = LinterVisitor([DangerousCallsRule()], str(path))
    visitor.context["project_root"] = str(tmp_path)
    visitor.visit(ast.parse(source))
    for rows in (scan_ctx(tmp_path, [path]), visitor.findings):
        assert any(row["rule_id"] == "SKY-D202" for row in rows) is unsafe


@pytest.mark.parametrize("mutated", [False, True])
def test_native_descriptor_export_keeps_code_identity(tmp_path, mutated):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="descriptor-export"\n')
    write_fixture(tmp_path, "core.py", "def value():\n    return 1\n")
    source = (
        "import ast\nfrom pathlib import Path\n"
        'SOURCE=Path(__file__).with_name("core.py")\n'
        "class Harness:\n    @classmethod\n    def setup(cls):\n"
        "        tree=ast.parse(SOURCE.read_text())\n"
        "        namespace={}\n"
        '        exec(compile(tree, "core.py", "exec"), namespace)\n'
        '        cls.value=staticmethod(namespace["value"])\n'
    )
    if mutated:
        write_fixture(
            tmp_path,
            "patcher.py",
            "import builtins\nbuiltins.staticmethod = opaque_wrapper\n",
        )
    write_fixture(tmp_path, "loader.py", source)
    path = tmp_path / "loader.py"
    visitor = LinterVisitor([DangerousCallsRule()], str(path))
    visitor.context["project_root"] = str(tmp_path)
    visitor.visit(ast.parse(source))
    assert any(row["rule_id"] == "SKY-D202" for row in visitor.findings) is mutated
