"""exec()/eval() of the project's own parsed source is not reported; anything
that lets other code or data reach the executed tree still is."""

import ast
import json
import os

import pytest

from skylos.analyzer import analyze
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule

CORE = "def add(a, b):\n    return a + b\n\n\ndef helper():\n    return 1\n"

HEADER = (
    "import ast\n"
    "import copy\n"
    "import os\n"
    "import sys\n"
    "from pathlib import Path\n"
    "from unittest import mock\n"
    "\n"
    'SOURCE = Path(__file__).resolve().parents[1] / "app" / "core.py"\n'
    "\n"
)

LOAD = (
    "def load(name):\n"
    '    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))\n'
    "    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)\n"
    "    module = ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[]))\n"
    "    namespace = {}\n"
    '    exec(compile(module, str(SOURCE), "exec"), namespace)\n'
    "    return namespace[name]\n"
)

HARNESS = (
    "def method(name):\n"
    '    tree = ast.parse(SOURCE.read_text(encoding="utf-8"))\n'
    "    for node in tree.body:\n"
    "        if isinstance(node, ast.FunctionDef) and node.name == name:\n"
    "            found = copy.deepcopy(node)\n"
    "            found.decorator_list = []\n"
    "            return found\n"
    '    raise AssertionError(name + " missing")\n'
    "\n"
    "\n"
    "def harness(*names):\n"
    "    definitions = []\n"
    "    for name in names:\n"
    "        definitions.append(method(name))\n"
    "    shell = ast.ClassDef(\n"
    '        name="Harness", bases=[], keywords=[], body=definitions, decorator_list=[]\n'
    "    )\n"
    "    module = ast.fix_missing_locations(ast.Module(body=[shell], type_ignores=[]))\n"
    "    namespace = dict(log=lambda message: None)\n"
    '    exec(compile(module, str(SOURCE), "exec", dont_inherit=True), namespace)\n'
    '    return namespace["Harness"]\n'
)

EVAL_EXPRESSION = (
    "def value():\n"
    '    tree = ast.parse(SOURCE.read_text(), mode="exec")\n'
    "    fn = tree.body[0]\n"
    "    expression = ast.Expression(body=fn.body[0].value)\n"
    '    return eval(compile(expression, "core", "eval"), {"a": 1, "b": 2})\n'
)


def _project(tmp_path, extra=None):
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    (root / "app" / "core.py").write_text(CORE)
    for relative, text in (extra or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _findings(tmp_path, code, *, relative="tests/test_core.py", extra=None):
    root = _project(tmp_path, extra)
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(code)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = str(root)
    linter.visit(ast.parse(code))
    return [
        (finding["rule_id"], finding["line"])
        for finding in linter.findings
        if finding["rule_id"] in {"SKY-D201", "SKY-D202"}
    ]


def _runner_lines(code):
    return [
        node.lineno
        for node in ast.walk(ast.parse(code))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"exec", "eval"}
    ]


@pytest.mark.parametrize(
    ("relative", "body"),
    [
        ("tests/test_core.py", LOAD),
        ("tests/test_core.py", HARNESS),
        ("tests/test_core.py", EVAL_EXPRESSION),
        ("tools/loader.py", LOAD),
    ],
    ids=["function", "class_shell_helpers", "eval_expression", "non_test_module"],
)
def test_executing_parsed_project_source_is_not_reported(tmp_path, relative, body):
    assert _findings(tmp_path, HEADER + body, relative=relative) == []


def test_analyze_does_not_report_source_owned_exec(tmp_path):
    root = _project(tmp_path, {"tests/test_core.py": HEADER + LOAD})
    result = json.loads(analyze(str(root), enable_danger=True, grep_verify=False))
    rules = {finding["rule_id"] for finding in result.get("danger", [])}
    assert "SKY-D202" not in rules


def test_analyze_still_reports_exec_of_argv_source(tmp_path):
    code = HEADER + (
        "def load():\n"
        "    tree = ast.parse(open(sys.argv[1]).read())\n"
        '    exec(compile(tree, "x", "exec"), {})\n'
    )
    root = _project(tmp_path, {"tests/test_core.py": code})
    result = json.loads(analyze(str(root), enable_danger=True, grep_verify=False))
    lines = [
        finding["line"]
        for finding in result.get("danger", [])
        if finding["rule_id"] == "SKY-D202"
    ]
    assert lines == [_runner_lines(code)[0]]


UNTRUSTED_PARSE = [
    'ast.parse(request.args["code"])',
    "ast.parse(sys.argv[1])",
    'ast.parse(os.environ["CODE"])',
    "ast.parse(input())",
    "ast.parse(open(sys.argv[1]).read())",
    "ast.parse(Path(sys.argv[1]).read_text())",
    "ast.parse(path.read_text())",
    "ast.parse(Path(path).read_text())",
    'ast.parse(Path(CONFIG["module"]).read_text())',
    'ast.parse(Path("/tmp/x.py").read_text())',
    'ast.parse((Path(__file__).parents[9] / "tmp" / "x.py").read_text())',
    'ast.parse((Path(__file__).parent / ".." / ".." / "x.py").read_text())',
    'ast.parse((Path(__file__).parent / "/tmp/x.py").read_text())',
    'ast.parse(SOURCE.read_text() + "\\nimport os")',
    "ast.parse(FAKE.read_text())",
]


def _untrusted_parse_module(parse):
    return HEADER + (
        "from flask import request\n"
        'CONFIG = {"module": os.environ.get("MODULE", "app/core.py")}\n'
        "\n"
        "\n"
        "class Fake:\n"
        "    def read_text(self):\n"
        "        return input()\n"
        "\n"
        "\n"
        "FAKE = Fake()\n"
        "\n"
        "\n"
        "def load(path):\n"
        f"    tree = {parse}\n"
        '    exec(compile(tree, "x", "exec"), {})\n'
    )


def test_untrusted_parse_harness_is_quiet_for_owned_source(tmp_path):
    assert (
        _findings(tmp_path, _untrusted_parse_module("ast.parse(SOURCE.read_text())"))
        == []
    )


@pytest.mark.parametrize("parse", UNTRUSTED_PARSE)
def test_tree_from_untrusted_or_unowned_source_is_reported(tmp_path, parse):
    code = _untrusted_parse_module(parse)
    assert _findings(tmp_path, code) == [("SKY-D202", _runner_lines(code)[0])]


TAMPERED = [
    "    code = 'print(1)'\n    exec(compile(code, 'x', 'exec'), {})\n",
    "    exec(compile(user, 'x', 'exec'), {})\n",
    "    exec(user, {})\n",
    "    exec(compile(SOURCE.read_text(), 'x', 'exec'))\n",
    "    exec(compile(SOURCE.read_text(), 'x', 'exec'), namespace)\n",
    "    exec(compile(SOURCE.read_text(), 'x', 'exec'), globals())\n",
    "    fn.body.append(ast.Expr(ast.Constant(input())))\n" + "    run(fn)\n",
    "    fn.body[0].value = ast.Constant(sys.argv[1])\n" + "    run(fn)\n",
    "    module = ast.Module(body=[fn, ast.Expr(ast.Constant(user))], type_ignores=[])\n"
    "    exec(compile(module, 'x', 'exec'), {})\n",
    "    module = ast.Module(body=[ast.Expr(ast.Call(ast.Name('print'), [], []))], type_ignores=[])\n"
    "    exec(compile(module, 'x', 'exec'), {})\n",
    "    rewrite(fn)\n" + "    run(fn)\n",
    "    items = [fn]\n    items.append(user)\n"
    "    exec(compile(ast.Module(body=items, type_ignores=[]), 'x', 'exec'), {})\n",
    "    hook = lambda: rewrite(fn)\n" + "    run(fn)\n",
    "    if user:\n        fn = ast.parse(user).body[0]\n" + "    run(fn)\n",
]

TAMPER_HEADER = HEADER + (
    "def rewrite(node):\n"
    "    node.body = ast.parse(input()).body\n"
    "\n"
    "\n"
    "def tampered(user, namespace):\n"
    "    tree = ast.parse(SOURCE.read_text())\n"
    "    fn = tree.body[0]\n"
)

RUN = "    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'x', 'exec'), {})\n"


def test_tamper_harness_is_quiet_without_tampering(tmp_path):
    assert _findings(tmp_path, TAMPER_HEADER + RUN) == []


@pytest.mark.parametrize("body", TAMPERED)
def test_strings_synthesized_or_reachable_trees_are_reported(tmp_path, body):
    code = TAMPER_HEADER + body.replace("    run(fn)\n", RUN)
    assert _findings(tmp_path, code) == [("SKY-D202", _runner_lines(code)[0])]


REBOUND = {
    "module_rebound": "SOURCE = Path(os.environ['MODULE'])\n",
    "global_rebound": "def swap():\n    global SOURCE\n    SOURCE = Path(sys.argv[1])\n",
    "mock_patched": "@mock.patch('tests.test_core.SOURCE', Path('/tmp/x.py'))\ndef test_x():\n    pass\n",
    "read_text_patched": "mock.patch.object(Path, 'read_text', lambda self: input()).start()\n",
    "read_text_assigned": "Path.read_text = lambda self, **kw: input()\n",
    "monkeypatched": "def test_x(monkeypatch):\n    monkeypatch.setattr('pathlib.Path.read_text', input)\n",
    "parse_patched": "ast.parse = lambda text, **kw: ast.Module(body=[], type_ignores=[])\n",
    "namespace_written": "globals()['SOURCE'] = Path('/tmp/x.py')\n",
}


@pytest.mark.parametrize("extra", REBOUND.values(), ids=REBOUND.keys())
def test_rebound_or_patched_names_keep_the_finding(tmp_path, extra):
    code = HEADER + LOAD + "\n\n" + extra
    assert _findings(tmp_path, code) == [("SKY-D202", _runner_lines(code)[0])]


def test_rebound_helper_keeps_the_finding(tmp_path):
    code = HEADER + HARNESS + "\n\nmethod = lambda name: ast.parse(input()).body[0]\n"
    assert _findings(tmp_path, code) == [("SKY-D202", _runner_lines(code)[0])]


def test_conditionally_changed_path_is_reported(tmp_path):
    code = HEADER + (
        "def load(flag):\n"
        "    path = SOURCE\n"
        "    if flag:\n"
        "        path = Path(sys.argv[1])\n"
        "    tree = ast.parse(path.read_text())\n"
        '    exec(compile(tree, "x", "exec"), {})\n'
    )
    assert _findings(tmp_path, code) == [("SKY-D202", _runner_lines(code)[0])]


@pytest.mark.parametrize(
    ("target", "extra"),
    [
        ("vendor", {".venv/lib/core.py": CORE}),
        ("shadowed_ast", {"tests/ast.py": "def parse(text):\n    return None\n"}),
        ("missing", {}),
    ],
)
def test_unowned_or_shadowed_source_files_are_reported(tmp_path, target, extra):
    paths = {
        "vendor": '".venv" / "lib" / "core.py"',
        "shadowed_ast": '"app" / "core.py"',
        "missing": '"app" / "gone.py"',
    }
    code = HEADER.replace('"app" / "core.py"', paths[target]) + LOAD
    assert _findings(tmp_path, code, extra=extra) == [
        ("SKY-D202", _runner_lines(code)[0])
    ]


def test_symlink_out_of_the_project_is_reported(tmp_path):
    outside = tmp_path / "outside.py"
    outside.write_text(CORE)
    root = _project(tmp_path)
    os.symlink(outside, root / "app" / "linked.py")
    code = HEADER.replace('"core.py"', '"linked.py"') + LOAD
    path = root / "tests" / "test_core.py"
    path.write_text(code)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.context["project_root"] = str(root)
    linter.visit(ast.parse(code))
    assert [f["line"] for f in linter.findings if f["rule_id"] == "SKY-D202"] == (
        _runner_lines(code)
    )


def test_without_a_project_root_nothing_is_proven(tmp_path):
    root = _project(tmp_path)
    path = root / "tests" / "test_core.py"
    code = HEADER + LOAD
    path.write_text(code)
    linter = LinterVisitor([DangerousCallsRule()], str(path))
    linter.visit(ast.parse(code))
    assert [f["line"] for f in linter.findings if f["rule_id"] == "SKY-D202"] == (
        _runner_lines(code)
    )


def test_one_unproven_runner_keeps_every_runner_in_the_module_reported(tmp_path):
    code = HEADER + LOAD + "\n\ndef run(user):\n    exec(user, {})\n"
    assert _findings(tmp_path, code) == [
        ("SKY-D202", line) for line in _runner_lines(code)
    ]
