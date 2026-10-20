"""Trace path operands from source; never execute inspected fixture modules."""

import ast
import copy
from types import SimpleNamespace

import pytest

from skylos.core.gatekeeper import check_gate
from skylos.rules.danger.danger_fs.path_flow import scan
from skylos.security.receiver_resolution import ReceiverResolver
from skylos.security.static_trace import _sink_call, attach_security_traces
from test.fixture_paths import write_fixture


def _trace(tmp_path, source, expression, *, files=None, rule="SKY-D325"):
    path = write_fixture(tmp_path, "app.py", source)
    tree = ast.parse(source)
    selected = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and ast.unparse(node) == expression:
            selected = node
            break
    assert selected is not None
    finding = {
        "rule_id": rule,
        "file": str(path),
        "line": selected.lineno,
        "col": selected.col_offset,
        "severity": "HIGH",
        "metadata": {"security_evidence": {"preserved": True}},
    }
    original = copy.deepcopy(finding)
    paths = [path]
    if files is not None:
        paths.extend(files)
    attach_security_traces([finding], project_root=tmp_path, files=paths)
    trace = finding["metadata"].pop("security_trace")
    assert finding == original
    return trace


def _has_source(trace):
    for step in trace["steps"]:
        if step["kind"] == "source":
            return True
    return False


@pytest.mark.parametrize("rule", ["SKY-D215", "SKY-D324", "SKY-D325"])
@pytest.mark.parametrize("callee", ["os.unlink", "os.remove", "shutil.move", "custom"])
def test_exact_call_location_does_not_require_a_sink_name(rule, callee):
    tree = ast.parse(callee + "(path)\n")
    call = tree.body[0].value
    unit = SimpleNamespace(calls_by_line={1: [call]})
    assert _sink_call(unit, {"rule_id": rule, "line": 1, "col": 0}) is call


def test_nested_calls_at_the_same_start_remain_ambiguous():
    tree = ast.parse("open(path)(input())\n")
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            calls.append(node)
    finding = {"rule_id": "SKY-D325", "line": 1, "col": 0}
    assert _sink_call(SimpleNamespace(calls_by_line={1: calls}), finding) is None


def test_incorrect_explicit_column_does_not_pick_a_neighboring_call():
    tree = ast.parse("open(path)\n")
    unit = SimpleNamespace(calls_by_line={1: [tree.body[0].value]})
    finding = {"rule_id": "SKY-D325", "line": 1, "col": 4}
    assert _sink_call(unit, finding) is None


def test_exact_unlisted_call_does_not_trace_a_neighboring_sink(tmp_path):
    trace = _trace(
        tmp_path,
        "def custom(path): pass\nopen(input()); custom('fixed')\n",
        "custom('fixed')",
    )
    assert not _has_source(trace)
    assert trace["receiver"]["qualified_name"] == "app.custom"


@pytest.mark.parametrize(
    "imports,call",
    [
        ("import os", "os.open(src, os.O_RDONLY)"),
        ("import os as fs", "fs.open(src, fs.O_RDONLY)"),
        ("from os import open as open_fd", "open_fd(src, 0)"),
        ("import os\nopen_fd = os.open", "open_fd(src, 0)"),
        ("import os", "os.open(path=src, flags=os.O_RDONLY)"),
    ],
)
def test_real_os_open_traces_its_path_operand_and_aliases(tmp_path, imports, call):
    source = imports + "\nsrc = input()\n" + call + "\n"
    trace = _trace(tmp_path, source, call)
    assert _has_source(trace)
    assert trace["status"] == "source_to_sink"
    assert trace["receiver"]["qualified_name"] == "os.open"
    assert trace["receiver"]["path_argument_index"] == 0
    assert trace["receiver"]["path_argument_name"] == "path"
    assert trace["receiver"]["effects"]["filesystem"] == "wrapped_path_argument"


@pytest.mark.parametrize(
    "qualified,keyword",
    [
        ("os.unlink", "path"),
        ("os.remove", "path"),
        ("os.mkdir", "path"),
        ("os.rmdir", "path"),
        ("os.makedirs", "name"),
        ("shutil.copy", "src"),
        ("shutil.copy2", "src"),
        ("shutil.copytree", "src"),
        ("shutil.move", "src"),
        ("shutil.rmtree", "path"),
    ],
)
@pytest.mark.parametrize("use_keyword", [False, True])
def test_standard_filesystem_calls_trace_the_declared_path(
    tmp_path, qualified, keyword, use_keyword
):
    module = qualified.split(".")[0]
    argument = "src"
    if use_keyword:
        argument = keyword + "=src"
    if qualified in {"shutil.copy", "shutil.copy2", "shutil.copytree", "shutil.move"}:
        if use_keyword:
            argument += ", dst='fixed'"
        else:
            argument += ", 'fixed'"
    call = qualified + "(" + argument + ")"
    source = "import " + module + "\nsrc = input()\n" + call + "\n"
    trace = _trace(tmp_path, source, call, rule="SKY-D215")
    assert _has_source(trace)
    assert trace["receiver"]["qualified_name"] == qualified
    assert trace["receiver"]["path_argument_index"] == 0
    assert trace["receiver"]["path_argument_name"] == keyword


@pytest.mark.parametrize("method", ["unlink", "remove", "move", "copy2"])
def test_unrelated_method_names_do_not_establish_a_path_operand(tmp_path, method):
    call = "worker." + method + "(input())"
    trace = _trace(
        tmp_path, "def run(worker):\n    " + call + "\n", call, rule="SKY-D215"
    )
    assert trace["receiver"]["status"] == "unknown"
    assert not _has_source(trace)


@pytest.mark.parametrize(
    "source,call",
    [
        (
            "def run(os):\n    src = input()\n    os.open(src, 0)\n",
            "os.open(src, 0)",
        ),
        (
            "import os\nos.open = lambda *args: None\nsrc = input()\nos.open(src, 0)\n",
            "os.open(src, 0)",
        ),
        (
            "import os\nother = os\nother.open = lambda *args: None\nsrc = input()\nos.open(src, 0)\n",
            "os.open(src, 0)",
        ),
        (
            "import os\npatch(os)\nsrc = input()\nos.open(src, 0)\n",
            "os.open(src, 0)",
        ),
    ],
)
def test_shadowed_or_mutated_os_receiver_has_no_standard_contract(
    tmp_path, source, call
):
    trace = _trace(tmp_path, source, call)
    assert trace["receiver"]["qualified_name"] != "os.open"
    assert trace["receiver"].get("path_argument_index") is None
    assert not _has_source(trace)


@pytest.mark.parametrize("provider", ["os.py", "src/os.py", "os.pyc"])
def test_local_os_provider_prevents_standard_library_contract(tmp_path, provider):
    path = write_fixture(
        tmp_path, provider, "raise RuntimeError('never import target')\n"
    )
    trace = _trace(
        tmp_path,
        "import os\nsrc = input()\nos.open(src, 0)\n",
        "os.open(src, 0)",
        files=[path],
    )
    assert trace["receiver"]["qualified_name"] != "os.open"
    assert trace["receiver"].get("path_argument_index") is None
    assert not _has_source(trace)


def test_os_open_contract_is_trace_only_and_preserves_findings_and_gate(tmp_path):
    source = "import os\ndef sync(path):\n    return os.open(path, os.O_RDONLY)\n"
    path = write_fixture(tmp_path, "app.py", source)
    tree = ast.parse(source)
    call = tree.body[1].body[0].value
    proof = ReceiverResolver(tree, path, project_root=tmp_path).resolve_call(call)
    assert proof["status"] == "unknown"
    findings = []
    scan(tree, path, findings)
    assert findings
    original = copy.deepcopy(findings)
    config = {"gate": {"max_high": 0}}
    original_gate = check_gate({"danger": findings}, config)
    attach_security_traces(findings, project_root=tmp_path, files=[path])
    assert check_gate({"danger": findings}, config) == original_gate
    for finding in findings:
        trace = finding["metadata"].pop("security_trace")
        assert trace["receiver"]["qualified_name"] == "os.open"
    assert findings == original
