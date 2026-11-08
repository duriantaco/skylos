import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.core.linter import LinterVisitor
from skylos.rules.danger.calls import DangerousCallsRule
from skylos.rules.danger.callable_bindings import callable_names
from skylos.rules.danger.danger import scan_ctx


CASES = [
    (
        "direct",
        "import pickle\nclass PassThrough(pickle.Unpickler):\n    pass\ndef run(f):\n    return PassThrough(f).load()\n",
        [5],
        "SKY-D204",
    ),
    (
        "assigned",
        "import pickle\nclass PassThrough(pickle.Unpickler):\n    pass\ndef run(f):\n    obj = PassThrough(f)\n    return obj.load()\n",
        [6],
        "SKY-D204",
    ),
    (
        "chain",
        "import pickle\nclass Base(pickle.Unpickler):\n    pass\nclass Leaf(Base):\n    pass\ndef run(f):\n    return Leaf(f).load()\n",
        [7],
        "SKY-D204",
    ),
    (
        "import_alias",
        "from pickle import Unpickler as Native\nclass PassThrough(Native):\n    pass\ndef run(f):\n    return PassThrough(f).load()\n",
        [5],
        "SKY-D204",
    ),
    (
        "c_provider",
        "import _pickle as native\nclass PassThrough(native.Unpickler):\n    pass\ndef run(f):\n    return PassThrough(f).load()\n",
        [5],
        "SKY-D204",
    ),
    (
        "dill_provider",
        "import dill\nclass PassThrough(dill.Unpickler):\n    pass\ndef run(f):\n    return PassThrough(f).load()\n",
        [5],
        "SKY-D233",
    ),
    (
        "restricted",
        "import pickle\nclass Restricted(pickle.Unpickler):\n    def find_class(self, module, name):\n        raise pickle.UnpicklingError(name)\ndef run(f):\n    return Restricted(f).load()\n",
        [],
        "SKY-D204",
    ),
    (
        "restricted_inherited",
        "import pickle\nclass Restricted(pickle.Unpickler):\n    def find_class(self, module, name):\n        raise pickle.UnpicklingError(name)\nclass Leaf(Restricted):\n    pass\ndef run(f):\n    return Leaf(f).load()\n",
        [],
        "SKY-D204",
    ),
    (
        "local_lookalike",
        "class Unpickler:\n    def __init__(self, f): pass\n    def load(self): return None\nclass PassThrough(Unpickler):\n    pass\ndef run(f):\n    return PassThrough(f).load()\n",
        [],
        "SKY-D204",
    ),
    (
        "rebound_provider",
        "import pickle\nclass Local:\n    class Unpickler:\n        def __init__(self, f): pass\n        def load(self): return None\npickle = Local\nclass PassThrough(pickle.Unpickler):\n    pass\ndef run(f):\n    return PassThrough(f).load()\n",
        [],
        "SKY-D204",
    ),
    (
        "rebound_subclass",
        "import pickle\nclass PassThrough(pickle.Unpickler):\n    pass\nclass Local:\n    def __init__(self, f): pass\n    def load(self): return None\nPassThrough = Local\ndef run(f):\n    return PassThrough(f).load()\n",
        [],
        "SKY-D204",
    ),
    (
        "rebound_member",
        "import pickle\nclass Local:\n    def __init__(self, f): pass\n    def load(self): return None\npickle.Unpickler = Local\nclass PassThrough(pickle.Unpickler):\n    pass\ndef run(f):\n    return PassThrough(f).load()\n",
        [],
        "SKY-D204",
    ),
    (
        "native_direct",
        "import pickle\ndef run(f):\n    return pickle.Unpickler(f).load()\n",
        [3],
        "SKY-D204",
    ),
    (
        "native_assigned",
        "import pickle\ndef run(f):\n    obj = pickle.Unpickler(f)\n    return obj.load()\n",
        [4],
        "SKY-D204",
    ),
]


@pytest.mark.parametrize("engine", ["rule", "scan_ctx"])
@pytest.mark.parametrize(
    "name,source,expected_lines,rule_id", CASES, ids=[row[0] for row in CASES]
)
def test_unpickler_constructor_identity(
    tmp_path, engine, name, source, expected_lines, rule_id
):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    if engine == "rule":
        visitor = LinterVisitor([DangerousCallsRule()], str(path))
        visitor.visit(ast.parse(source))
        findings = visitor.findings
    else:
        findings = scan_ctx(tmp_path, [path])
    assert (
        sorted(f["line"] for f in findings if f["rule_id"] == rule_id) == expected_lines
    )


def test_unrestricted_subclass_survives_output_and_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = (
        "import io, pickle\n"
        "class Restricted(pickle.Unpickler):\n"
        "    def find_class(self, module, name):\n"
        "        raise pickle.UnpicklingError(name)\n"
        "class PassThrough(pickle.Unpickler):\n"
        "    pass\n"
        "def a(b):\n    return Restricted(io.BytesIO(b)).load()\n"
        "def c(b):\n    return PassThrough(io.BytesIO(b)).load()\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            grep_cache=False,
        )
    )
    assert not result.get("analysis_errors")
    rows = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D204"]
    assert [row["line"] for row in rows] == [10]
    assert all(row["listing"]["listed"] for row in rows)
    passed, _ = check_gate(result, {"gate": {"max_high": 0, "max_critical": 0}})
    assert not passed


@pytest.mark.parametrize("engine", ["rule", "scan_ctx"])
def test_project_unpickler_lookalike_is_not_native(tmp_path, engine):
    provider = tmp_path / "pickle.py"
    provider.write_text(
        "class Unpickler:\n"
        "    def __init__(self, stream): pass\n"
        "    def load(self): return None\n",
        encoding="utf-8",
    )
    source = (
        "import pickle\n"
        "class PassThrough(pickle.Unpickler):\n    pass\n"
        "def run(stream):\n    return PassThrough(stream).load()\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")
    if engine == "rule":
        visitor = LinterVisitor([DangerousCallsRule()], str(path))
        visitor.visit(ast.parse(source))
        findings = visitor.findings
    else:
        findings = scan_ctx(tmp_path, [path, provider])
    assert not any(row["rule_id"] == "SKY-D204" for row in findings)


def test_shared_tree_uses_the_current_project_provider_inventory(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    source = (
        "import pickle\n"
        "class PassThrough(pickle.Unpickler):\n    pass\n"
        "def run(stream):\n    return PassThrough(stream).load()\n"
    )
    path = package / "app.py"
    path.write_text(source, encoding="utf-8")
    (tmp_path / "pickle.py").write_text(
        "class Unpickler:\n"
        "    def __init__(self, stream): pass\n"
        "    def load(self): return None\n",
        encoding="utf-8",
    )
    tree = ast.parse(source)
    call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "load"
    )
    name = "pickle.Unpickler.load"
    assert callable_names(call, name, tree, str(path)) == (name,)
    assert callable_names(call, name, tree, str(path), tmp_path) == ()
