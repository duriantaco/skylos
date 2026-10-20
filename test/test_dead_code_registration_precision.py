"""Registration requires the actual receiver and an executed source context."""

import ast
import json
import textwrap

import pytest

from test.fixture_paths import write_fixture

from skylos.analyzer import analyze
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode.registration_liveness import (
    find_method_registered_targets,
    find_patched_instance_methods,
)
from skylos.visitors.base import Visitor


def _reported(tmp_path, source):
    write_fixture(tmp_path, "app.py", textwrap.dedent(source), overwrite=True)
    report = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            grep_verify=False,
            grep_cache=False,
            trace_file=False,
        )
    )
    assert not report.get("analysis_errors")
    return {
        finding["full_name"]
        for section in ("unused_functions", "unused_classes", "unused_variables")
        for finding in report.get(section, [])
    }


_REGISTRY = """
from types import SimpleNamespace

class Registry:
    def __init__(self):
        self.callbacks = []

    def on_ready(self, fn):
        self.callbacks.append(fn)
        return fn
"""


@pytest.mark.parametrize(
    ("receiver", "reported"),
    [
        ("registry = Registry()", False),
        ("registry = SimpleNamespace(on_ready=lambda fn: fn)", True),
        ("registry = unknown_factory()", True),
        (
            "registry = Registry()\nregistry = SimpleNamespace(on_ready=lambda fn: fn)",
            True,
        ),
        ("class Derived(Registry):\n    pass\nregistry = Derived()", False),
        ("registry = Registry()\nregistry.description = 'events'", False),
        ("registry = Registry()\nregistry.on_ready = lambda fn: fn", True),
        ("registry = Registry()\nRegistry.on_ready = lambda self, fn: fn", True),
        ("def registry():\n    return None\nregistry.on_ready = lambda fn: fn", True),
    ],
)
def test_registration_uses_receiver_class(tmp_path, receiver, reported):
    unused = _reported(
        tmp_path,
        _REGISTRY + "\n" + receiver + "\n\n"
        "@registry.on_ready\ndef decorated():\n    return 1\n",
    )
    assert ("app.decorated" in unused) is reported


def test_unrelated_forwarding_method_is_not_registration(tmp_path):
    unused = _reported(
        tmp_path,
        """
        class Registry:
            def on_ready(self, fn):
                return self._store_callback(fn)

        class Other:
            def _store_callback(self, fn):
                self.callbacks.append(fn)
                return fn

        registry = Registry()

        @registry.on_ready
        def decorated():
            return 1
        """,
    )
    assert "app.decorated" in unused


def test_imported_receiver_keeps_inherited_registration_forwarding(tmp_path):
    (tmp_path / "registry.py").write_text(
        "callbacks = []\n"
        "def store(fn):\n    callbacks.append(fn)\n    return fn\n"
        "class Registry:\n"
        "    def on_ready(self, fn):\n        return store(fn)\n",
        encoding="utf-8",
    )
    unused = _reported(
        tmp_path,
        "from registry import Registry\n"
        "class Derived(Registry):\n    pass\n"
        "registry = Derived()\n"
        "@registry.on_ready\ndef decorated():\n    return 1\n",
    )
    assert "app.decorated" not in unused


@pytest.mark.parametrize(
    ("initialization", "reported"),
    [
        ("self.description = 'events'", False),
        ("self.on_ready = lambda fn: fn", True),
        ("if False:\n            self.on_ready = lambda fn: fn", False),
    ],
)
def test_constructor_member_replacement_is_not_class_method_registration(
    tmp_path, initialization, reported
):
    source = _REGISTRY.replace(
        "self.callbacks = []", "self.callbacks = []\n        " + initialization
    )
    unused = _reported(
        tmp_path,
        source + "\nregistry = Registry()\n"
        "@registry.on_ready\ndef decorated():\n    return 1\n",
    )
    assert ("app.decorated" in unused) is reported


def test_constructor_setattr_does_not_supply_registration_evidence(tmp_path):
    path = tmp_path / "app.py"
    source = _REGISTRY.replace(
        "self.callbacks = []",
        "self.callbacks = []\n        setattr(self, 'on_ready', lambda fn: fn)",
    )
    tree = ast.parse(
        source
        + "\nregistry = Registry()\n@registry.on_ready\ndef decorated():\n    return 1\n"
    )
    visitor = Visitor("app", str(path))
    visitor.visit(tree)
    visitor.finalize()
    definitions = {definition.name: definition for definition in visitor.defs}
    assert (
        find_method_registered_targets(definitions, [ParsedPythonFile(path, tree)])
        == []
    )


_PATCHED = """
import json

class Active:
    def extra(self):
        return 1

instance = Active()
"""


@pytest.mark.parametrize(
    ("installation", "reported"),
    [
        ("json.anything = Active()", False),
        ("def install():\n    json.anything = Active()\ninstall()", False),
        ("def never_called():\n    json.anything = Active()", True),
        (
            "def install():\n    json.anything = Active()\ndef never_called():\n    install()",
            True,
        ),
    ],
)
def test_external_patch_requires_reachable_owner_and_module_binding(
    tmp_path, installation, reported
):
    unused = _reported(tmp_path, _PATCHED + "\n" + installation + "\n")
    assert ("app.Active.extra" in unused) is reported


@pytest.mark.parametrize(
    "installation",
    [
        "json = object()\njson.anything = Active()",
        "def install(json):\n    json.anything = Active()\ninstall(object())",
        "def run():\n    json.anything = Active()",
        "if False:\n    json.anything = Active()",
        "def install():\n    if False:\n        json.anything = Active()\ninstall()",
    ],
)
def test_unknown_patch_receiver_has_no_registration_evidence(tmp_path, installation):
    # An object escaping through an unknown receiver can be protected by other
    # passes; this helper must not claim that the receiver is a library module.
    path = tmp_path / "app.py"
    tree = ast.parse(_PATCHED + "\n" + installation + "\n")
    visitor = Visitor("app", str(path))
    visitor.visit(tree)
    visitor.finalize()
    definitions = {definition.name: definition for definition in visitor.defs}
    assert (
        find_patched_instance_methods(definitions, [ParsedPythonFile(path, tree)]) == []
    )


@pytest.mark.parametrize(
    ("base", "field", "reported"),
    [
        ("", "thing = 1", True),
        ("(traitlets.HasTraits)", "thing = traitlets.Unicode()", False),
        ("(UnknownBase)", "thing = 1", True),
    ],
)
def test_traitlets_magic_requires_traitlets_ancestry(tmp_path, base, field, reported):
    unused = _reported(
        tmp_path,
        "import traitlets\n\n"
        "class UnknownBase:\n    pass\n\n"
        f"class Plain{base}:\n    {field}\n"
        "    def _thing_default(self):\n        return 10\n"
        "    def actual(self):\n        return self.thing\n\n"
        "print(Plain().actual())\n",
    )
    assert ("app.Plain._thing_default" in unused) is reported
