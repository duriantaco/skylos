"""Dead-code false positives found on blind repositories, each with a control.

- Method names held as strings in a class and called through
  ``getattr(obj, runtime_name)``.
- Callbacks registered through a decorator factory whose method name is not a
  known registration verb (proven from the factory body).
- An assigned ``runTest`` on a ``unittest.TestCase`` subclass.
- TypedDict fields of a class declared inside a function.
"""

import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _unused(tmp_path):
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    names = set()
    for key in ("unused_functions", "unused_classes", "unused_variables"):
        names.update(item["full_name"] for item in result.get(key, []))
    return names


def _backend_channel(tmp_path, dispatch):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/base.py",
        """
        class Action:
            def __init__(self, name, backends):
                self.name = name
                self.backends = backends
        """,
    )
    _write(
        tmp_path,
        "pkg/chan.py",
        """
        from .base import Action


        class Chan:
            @property
            def actions(self):
                return (Action("read", (("cli", "_cli_read"), ("api", "_api_read"))),)

            def _cli_read(self, *, target):
                return [target]

            def _api_read(self, *, target):
                return [target]

            def _stale(self):
                return None
        """,
    )
    _write(tmp_path, "pkg/dispatch.py", dispatch)


def test_method_names_built_in_a_method_and_dispatched_by_getattr_are_used(tmp_path):
    _backend_channel(
        tmp_path,
        """
        from .chan import Chan


        def run(channel, target):
            for action in channel.actions:
                for label, method_name in action.backends:
                    getattr(channel, method_name)(target=target)


        run(Chan(), "x")
        """,
    )
    unused = _unused(tmp_path)
    assert "pkg.chan.Chan._cli_read" not in unused
    assert "pkg.chan.Chan._api_read" not in unused
    assert "pkg.chan.Chan._stale" in unused


def test_method_name_strings_without_runtime_lookup_stay_text(tmp_path):
    _backend_channel(
        tmp_path,
        """
        from .chan import Chan


        def run(channel):
            return [action.name for action in channel.actions]


        run(Chan())
        """,
    )
    unused = _unused(tmp_path)
    assert {"pkg.chan.Chan._cli_read", "pkg.chan.Chan._api_read"} <= unused


def test_method_name_string_in_another_class_does_not_keep_method(tmp_path):
    _backend_channel(
        tmp_path,
        """
        from .chan import Chan


        def run(channel, target):
            for action in channel.actions:
                for label, method_name in action.backends:
                    return getattr(channel, method_name)(target=target)


        run(Chan(), "x")
        """,
    )
    _write(
        tmp_path,
        "pkg/chan.py",
        """
        from .base import Action


        class Registry:
            @property
            def actions(self):
                return (Action("read", (("cli", "_cli_read"),)),)


        class Chan:
            @property
            def actions(self):
                return Registry().actions

            def _cli_read(self, *, target):
                return [target]
        """,
    )
    assert "pkg.chan.Chan._cli_read" in _unused(tmp_path)


def test_base_class_hook_tuple_keeps_subclass_hook_only(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/hooks.py",
        """
        class Base:
            hooks = ("_on_start",)

            def fire(self):
                for hook in self.hooks:
                    getattr(self, hook)()


        class Impl(Base):
            def _on_start(self):
                return 1

            def _never(self):
                return 2


        Impl().fire()
        """,
    )
    unused = _unused(tmp_path)
    assert "pkg.hooks.Impl._on_start" not in unused
    assert "pkg.hooks.Impl._never" in unused


def _registry_project(tmp_path, verb, stores=True):
    store = "self.entries[key] = function" if stores else "self.seen += 1"
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/table.py",
        f"""
        class Table:
            def __init__(self):
                self.entries = {{}}
                self.seen = 0

            def {verb}(self, key):
                def remember(function):
                    {store}
                    return function

                return remember

            def run(self, key, value):
                function = self.entries.get(key)
                return function(value) if function is not None else None
        """,
    )
    _write(
        tmp_path,
        "pkg/app.py",
        f"""
        import sys

        from .table import Table

        table = Table()


        @table.{verb}("upper")
        def _upper(value):
            return value.upper()


        def _unregistered(value):
            return value


        print(table.run(sys.argv[1], "x"))
        """,
    )


@pytest.mark.parametrize("verb", ["register", "accepts", "on", "handles"])
def test_decorator_factory_registration_is_proven_from_the_body(tmp_path, verb):
    _registry_project(tmp_path, verb)
    unused = _unused(tmp_path)
    assert "pkg.app._upper" not in unused
    assert "pkg.app._unregistered" in unused


def test_decorator_factory_that_does_not_store_its_argument_registers_nothing(tmp_path):
    _registry_project(tmp_path, "accepts", stores=False)
    assert "pkg.app._upper" in _unused(tmp_path)


@pytest.mark.parametrize(
    "header, base",
    [
        ("from unittest import TestCase", "TestCase"),
        ("import unittest as checks", "checks.TestCase"),
    ],
)
def test_assigned_run_test_on_unittest_case_is_used(tmp_path, header, base):
    _write(
        tmp_path,
        "adapter.py",
        f"""
        {header}


        def describe(label):
            class Entry({base}):
                runTest = staticmethod(lambda: None)
                format_note = staticmethod(lambda: None)

                def __str__(self):
                    return label

            return Entry().shortDescription()


        print(describe("sample"))
        """,
    )
    members = {name.rsplit(".", 1)[-1] for name in _unused(tmp_path)}
    assert "runTest" not in members
    assert "format_note" in members


def test_run_test_on_a_local_lookalike_case_stays_unused(tmp_path):
    _write(
        tmp_path,
        "adapter.py",
        """
        class TestCase:
            def shortDescription(self):
                return None


        class Entry(TestCase):
            runTest = staticmethod(lambda: None)


        print(Entry().shortDescription())
        """,
    )
    assert "adapter.Entry.runTest" in _unused(tmp_path)


def _unused_variable_names(tmp_path):
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    return {item["simple_name"] for item in result.get("unused_variables", [])}


def test_nested_typeddict_fields_are_not_unused_variables(tmp_path):
    _write(
        tmp_path,
        "m.py",
        """
        from typing import TypedDict


        def build():
            class InfoTD(TypedDict, total=False):
                author_email: str
                author_date: int

            info: InfoTD = {}
            info["author_email"] = "a"
            stale = 1
            return info


        print(build())
        """,
    )
    unused = _unused_variable_names(tmp_path)
    assert "author_email" not in unused
    assert "author_date" not in unused
    assert "stale" in unused


def test_annotated_local_in_a_plain_nested_class_method_is_still_checked(tmp_path):
    _write(
        tmp_path,
        "m.py",
        """
        from typing import TypedDict


        class Info(TypedDict):
            name: str


        def build():
            class Holder:
                def method(self):
                    leftover: int = 1
                    return 2

            return Holder().method()


        print(build(), Info)
        """,
    )
    assert "leftover" in _unused_variable_names(tmp_path)
