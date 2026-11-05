"""Finite reflective calls; fixture Python is parsed, never executed."""

import json
import ast
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from skylos.deadcode import finite_dispatch


FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks/dead_code/fixtures"


def _scan(tmp_path, fixture, mutate=None):
    shutil.copytree(FIXTURES / fixture, tmp_path, dirs_exist_ok=True)
    if fixture == "finite_method_registry":
        source = tmp_path / "app.py"
        source.write_text(source.read_text().replace("def render_c(", "def obsolete("))
    if mutate:
        source = tmp_path / "app.py"
        source.write_text(mutate(source.read_text()))
    report = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not report.get("analysis_errors")
    assert report["analysis_summary"]["total_files"] > 0
    return report, {r["full_name"] for r in report["unused_functions"]}


def test_globals_dispatch_selects_only_the_called_module_function(tmp_path):
    _, unused = _scan(tmp_path, "finite_globals_dispatch")
    assert "app.scale_a" not in unused
    assert "app.scale_b" in unused


def test_inherited_registry_is_bounded_to_exact_methods_and_owner(tmp_path):
    _, unused = _scan(tmp_path, "finite_method_registry")
    assert "app.Formatter.render_a" not in unused
    assert "app.Formatter.render_b" not in unused
    assert {"app.Formatter.obsolete", "peers.Peer.render_a"} <= unused


def test_registry_does_not_keep_same_named_method_on_same_file_receiver(tmp_path):
    def mutate(source):
        source = source.replace("from peers import Peer\n", "")
        return source.replace(
            "Peer()",
            "class Peer(OutputBase):\n    def render_a(self, value):\n        return value\n\nPeer()",
        )

    _, unused = _scan(tmp_path, "finite_method_registry", mutate)
    assert "app.Formatter.render_a" not in unused
    assert "app.Peer.render_a" in unused


@pytest.mark.parametrize(
    "change",
    [
        lambda s: "globals = lambda: {}\n" + s,
        lambda s: s.replace('"scale_a"', '"missing"'),
        lambda s: s.replace(
            'print(transform(2, "scale_a"))',
            'def retired():\n    return transform(2, "scale_a")',
        ),
        lambda s: s.replace(
            "selected = globals()[name]",
            'name = "scale_b"\n    selected = globals()[name]',
        ),
    ],
)
def test_globals_dispatch_does_not_invent_calls_for_lookalikes(tmp_path, change):
    _, unused = _scan(tmp_path, "finite_globals_dispatch", change)
    assert "app.scale_a" in unused


def test_globals_lookup_keeps_same_named_function_in_other_module_dead(tmp_path):
    (tmp_path / "other.py").write_text("def scale_a(value):\n    return value\n")
    _, unused = _scan(tmp_path, "finite_globals_dispatch")
    assert "app.scale_a" not in unused
    assert "other.scale_a" in unused


@pytest.mark.parametrize(
    "change",
    [
        lambda s: "getattr = lambda *args: lambda value: value\n" + s,
        lambda s: s.replace(
            "getattr(self, selected[0])", "getattr(Peer(), selected[0])"
        ),
        lambda s: s.replace(
            'value = result.get("value")',
            'self = Peer()\n        value = result.get("value")',
        ),
        lambda s: s.replace(
            "print(Formatter().render", "Formatter.MODES = {}\nprint(Formatter().render"
        ),
        lambda s: s.replace(
            "print(Formatter().render",
            "Formatter.MODES.update({})\nprint(Formatter().render",
        ),
        lambda s: s.replace(
            "print(Formatter().render",
            "alias = Formatter.MODES\nprint(Formatter().render",
        ),
    ],
)
def test_registry_rebinding_wrong_receiver_and_escaping_table_do_not_rescue(
    tmp_path, change
):
    _, unused = _scan(tmp_path, "finite_method_registry", change)
    assert {"app.Formatter.render_a", "app.Formatter.render_b"} <= unused


def test_registry_dispatch_in_dead_caller_stays_dead(tmp_path):
    def mutate(source):
        return source.replace(
            'print(Formatter().render({"value": 2, "mode": input()}))',
            'def retired():\n    return Formatter().render({"value": 2, "mode": "a"})',
        )

    report, unused = _scan(tmp_path, "finite_method_registry", mutate)
    assert "app.retired" in unused
    assert (
        any(row["full_name"] == "app.Formatter" for row in report["unused_classes"])
        or {
            "app.Formatter.render_a",
            "app.Formatter.render_b",
        }
        <= unused
    )


def test_literal_registry_key_does_not_keep_unselected_entry(tmp_path):
    _, unused = _scan(
        tmp_path,
        "finite_method_registry",
        lambda s: s.replace(
            'Formatter.MODES.get(result.get("mode"))', 'Formatter.MODES.get("a")'
        ),
    )
    assert "app.Formatter.render_a" not in unused
    assert "app.Formatter.render_b" in unused


@pytest.mark.parametrize("parameter", ["Formatter", "*unused, Formatter"])
def test_class_name_parameter_is_not_the_module_registry_owner(tmp_path, parameter):
    def mutate(source):
        source = source.replace(
            "def render(self, result):", "def render(self, result, " + parameter + "):"
        )
        source = source.replace(
            "print(Formatter().render",
            'class Alternate:\n    MODES = {"a": ("obsolete", 0)}\n\nprint(Formatter().render',
        )
        return source.replace(
            '"mode": input()}))', '"mode": "a"}, Formatter=Alternate))'
        )

    _, unused = _scan(tmp_path, "finite_method_registry", mutate)
    assert {"app.Formatter.render_a", "app.Formatter.render_b"} <= unused


@pytest.mark.parametrize("kind", ["table", "method"])
def test_subclass_lookup_cannot_claim_overridden_base_method(tmp_path, kind):
    def mutate(source):
        if kind == "table":
            source = source.replace("Formatter.MODES.get", "self.MODES.get")
            child = 'class Child(Formatter):\n    MODES = {"a": ("obsolete", 0)}\n\n'
        else:
            source = source.replace(
                'Formatter.MODES.get(result.get("mode"))', 'Formatter.MODES.get("a")'
            )
            child = "class Child(Formatter):\n    def render_a(self, value):\n        return value\n\n"
        return source.replace(
            "print(Formatter().render", child + "print(Child().render"
        )

    _, unused = _scan(tmp_path, "finite_method_registry", mutate)
    assert {"app.Formatter.render_a", "app.Formatter.render_b"} <= unused


def test_registry_write_from_another_module_does_not_keep_old_entries(tmp_path):
    (tmp_path / "driver.py").write_text(
        "import app\napp.Formatter.MODES = {}\n"
        'print(app.Formatter().render({"value": 2, "mode": "a"}))\n'
    )
    _, unused = _scan(
        tmp_path,
        "finite_method_registry",
        lambda s: s.replace(
            'print(Formatter().render({"value": 2, "mode": input()}))',
            "",
        ),
    )
    assert {"app.Formatter.render_a", "app.Formatter.render_b"} <= unused


def test_globals_provider_replaced_from_another_module_stays_dead(tmp_path):
    (tmp_path / "driver.py").write_text(
        'import app\napp.scale_a = app.scale_b\nprint(app.transform(2, "scale_a"))\n'
    )
    _, unused = _scan(
        tmp_path,
        "finite_globals_dispatch",
        lambda s: s.replace(
            'print(transform(2, "scale_a"))',
            "",
        ),
    )
    assert "app.scale_a" in unused
    assert "app.scale_b" not in unused


@pytest.mark.parametrize(
    "replacement",
    [
        "if False:\n        selected = globals()[name]\n        return selected(value)\n    return value",
        "return value\n    selected = globals()[name]\n    return selected(value)",
    ],
)
def test_unexecuted_globals_lookup_in_live_function_stays_dead(tmp_path, replacement):
    _, unused = _scan(
        tmp_path,
        "finite_globals_dispatch",
        lambda s: s.replace(
            "selected = globals()[name]\n    return selected(value)",
            replacement,
        ),
    )
    assert {"app.scale_a", "app.scale_b"} <= unused


@pytest.mark.parametrize(
    "replacement",
    [
        "if False:\n                method = getattr(self, selected[0])\n                return method(value)\n            return value",
        "return value\n            method = getattr(self, selected[0])\n            return method(value)",
    ],
)
def test_unexecuted_registry_lookup_in_live_method_stays_dead(tmp_path, replacement):
    _, unused = _scan(
        tmp_path,
        "finite_method_registry",
        lambda s: s.replace(
            "method = getattr(self, selected[0])\n            return method(value)",
            replacement,
        ),
    )
    assert {"app.Formatter.render_a", "app.Formatter.render_b"} <= unused


@pytest.mark.parametrize(
    "caller",
    [
        'from dispatch import transform\nprint(transform(2, "scale_a"))\n',
        'import dispatch as backend\nprint(backend.transform(2, "scale_a"))\n',
        'def load():\n    from dispatch import transform as invoke\n    return invoke(2, "scale_a")\nprint(load())\n',
    ],
)
def test_globals_finite_argument_is_followed_across_source_imports(tmp_path, caller):
    source = (FIXTURES / "finite_globals_dispatch/app.py").read_text()
    (tmp_path / "dispatch.py").write_text(
        source.replace('print(transform(2, "scale_a"))', "")
    )
    (tmp_path / "app.py").write_text(caller)
    report = json.loads(
        analyze(
            str(tmp_path),
            grep_verify=False,
            grep_cache=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert not report.get("analysis_errors")
    unused = {r["full_name"] for r in report["unused_functions"]}
    assert "dispatch.scale_a" not in unused
    assert "dispatch.scale_b" in unused


@pytest.mark.parametrize(
    "custom",
    [
        "def __getattribute__(self, name):\n        return lambda value: value",
        "__getattribute__ = lambda self, name: lambda value: value",
    ],
)
def test_custom_inherited_attribute_access_is_not_a_finite_native_proof(
    tmp_path, custom
):
    from skylos.deadcode.finite_dispatch import finite_dispatch_edges
    from skylos.deadcode.python_ast import parse_python_files
    from skylos.visitors.base import Definition
    import ast

    source = (FIXTURES / "finite_method_registry/app.py").read_text()
    source = source.replace(
        "class OutputBase:\n", "class OutputBase:\n    " + custom + "\n\n"
    )
    path = tmp_path / "app.py"
    path.write_text(source)
    definitions = {}
    for cls in ast.parse(source).body:
        if not isinstance(cls, ast.ClassDef):
            continue
        name = "app." + cls.name
        definitions[name] = Definition(name, "class", path, cls.lineno, cls)
        for fn in cls.body:
            if isinstance(fn, ast.FunctionDef):
                qname = name + "." + fn.name
                definitions[qname] = Definition(qname, "method", path, fn.lineno, fn)
    assert finite_dispatch_edges(definitions, parse_python_files([path])) == []


@pytest.mark.parametrize(
    "source",
    [
        "def inspect(value):\n    return getattr(value, 'description')\n",
        "def inspect():\n    return globals().get('version')\n",
        "def inspect():\n    return globals()\n",
        "class Item:\n    TABLE = {'a': 'handle'}\n    def inspect(self):\n        return getattr(object(), 'handle')\n",
        "class Item:\n    def inspect(self):\n        return getattr(self, 'handle')\n",
        "class Item:\n    TABLE = {'a': 'handle'}\n    def inspect(self):\n        return getattr(self, 'handle', None)\n",
        "import yaml\ndef read(text, Loader):\n    return yaml.load(text, Loader=Loader)\n",
    ],
)
def test_unsupported_reflection_skips_project_dispatch_work(
    tmp_path, monkeypatch, source
):
    path = tmp_path / "app.py"
    path.write_text(source)
    unrelated = tmp_path / "unrelated.py"
    unrelated.write_text("def independent(value):\n    return value + 1\n")
    parsed = [
        SimpleNamespace(path=p, tree=ast.parse(p.read_text()))
        for p in (path, unrelated)
    ]
    calls = {"reachable": 0, "arguments": 0, "classes": 0, "unrelated_walks": 0}
    walk = ast.walk

    def watched_walk(node):
        if node is parsed[1].tree:
            calls["unrelated_walks"] += 1
        return walk(node)

    def reachable(_):
        calls["reachable"] += 1
        return set()

    def arguments(*_):
        calls["arguments"] += 1
        return {}

    def classes(*_):
        calls["classes"] += 1
        return []

    monkeypatch.setattr(ast, "walk", watched_walk)
    monkeypatch.setattr(finite_dispatch, "_reachable_live_functions", reachable)
    monkeypatch.setattr(finite_dispatch, "_call_arguments", arguments)
    monkeypatch.setattr(finite_dispatch, "_class_edges", classes)
    assert finite_dispatch.finite_dispatch_edges({}, parsed) == []
    assert calls == {"reachable": 0, "arguments": 0, "classes": 0, "unrelated_walks": 0}


def test_empty_dispatch_edges_skip_active_graph_walk(monkeypatch):
    def unexpected(_):
        pytest.fail("No dispatch edges require no active-caller graph")

    monkeypatch.setattr(finite_dispatch, "finite_dispatch_edges", lambda *_: [])
    monkeypatch.setattr(finite_dispatch, "active_dispatch_callers", unexpected)
    assert finite_dispatch.record_finite_dispatch_references({}, []) == []
