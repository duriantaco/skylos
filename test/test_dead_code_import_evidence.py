"""Import liveness: what does and does not show that an import is used."""

import json
import textwrap

import pytest

from test.fixture_paths import write_fixture

from skylos.analyzer import analyze


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _unused_imports(tmp_path):
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))
    return {
        (item["file"].replace("\\\\", "/").rsplit("/", 1)[-1], item["name"])
        for item in result.get("unused_imports", [])
    }


def test_a_test_mentioning_the_word_does_not_keep_an_import(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path, "pkg/mod.py",
        "import json\nimport logging\nimport os\nimport time\n\n\ndef main():\n    return 1\n\n\nmain()\n",
    )
    _write(
        tmp_path, "tests/test_mod.py",
        """
        import logging
        import time
        from unittest import mock
        from pkg.mod import (
            json,
        )


        def test_x():
            logging.info(time.time())
            with mock.patch("pkg.mod.os"):
                assert json
        """,
    )

    unused = _unused_imports(tmp_path)
    assert {("mod.py", "logging"), ("mod.py", "time")} <= unused
    assert {("mod.py", "json"), ("mod.py", "os")}.isdisjoint(unused)


def test_an_import_after_the_functions_that_use_it_is_used(tmp_path):
    _write(
        tmp_path, "mod.py",
        """
        def f():
            return torch.zeros(1)


        def g():
            return json.dumps(1)


        if __name__ == "__main__":
            pass
        else:
            import torch

        import json
        import os

        f()
        g()
        """,
    )

    unused = _unused_imports(tmp_path)
    assert {("mod.py", "torch"), ("mod.py", "json")}.isdisjoint(unused)
    assert ("mod.py", "os") in unused


def test_a_lazy_module_attribute_import_is_used(tmp_path):
    _write(
        tmp_path, "pkg/__init__.py",
        """
        from typing import TYPE_CHECKING, Any

        if TYPE_CHECKING:
            from pkg.mod import Thing, Unlisted

        _LAZY = {"Thing": ("pkg.mod", "Thing")}
        __all__ = []


        def __getattr__(name: str) -> Any:
            module, attr = _LAZY[name]
            return getattr(__import__(module, fromlist=[attr]), attr)
        """,
    )
    _write(tmp_path, "pkg/mod.py", "class Thing:\n    pass\n\n\nclass Unlisted:\n    pass\n")

    unused = _unused_imports(tmp_path)
    assert ("__init__.py", "Thing") not in unused
    assert ("__init__.py", "Unlisted") in unused


def test_a_deprecated_module_keeps_its_reexports_hidden(tmp_path):
    _write(
        tmp_path, "pkg/old.py",
        """
        import warnings

        from pkg.new import handler

        warnings.warn("pkg.old is deprecated", DeprecationWarning, stacklevel=2)
        """,
    )
    _write(tmp_path, "pkg/new.py", "def handler():\n    return 1\n\n\nhandler()\n")

    result = json.loads(analyze(str(tmp_path), conf=60, grep_verify=True))
    assert "handler" not in {item["name"] for item in result.get("unused_imports", [])}
    listed = json.loads(analyze(str(tmp_path), conf=40, grep_verify=True))
    finding = next(item for item in listed["unused_imports"] if item["name"] == "handler")
    assert "deprecated_api" in finding["confidence_factors"]


def test_a_same_named_dictionary_key_elsewhere_does_not_keep_an_import(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/tool.py", "import os\nimport json\n\n\ndef run():\n    return globals()[\"json\"]\n\n\nrun()\n")
    _write(tmp_path, "pkg/cli.py", "def info():\n    data = {}\n    data[\"os\"] = 1\n    return data[\"os\"]\n\n\ninfo()\n")

    unused = _unused_imports(tmp_path)
    assert ("tool.py", "os") in unused
    assert ("tool.py", "json") not in unused


def test_a_qualified_name_in_a_comment_or_prose_does_not_keep_an_import(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path, "pkg/mod.py",
        "import json\nimport os\nimport time\n\n\ndef main():\n    return 1\n\n\nmain()\n",
    )
    _write(
        tmp_path, "pkg/other.py",
        """
        import pkg.mod


        def run():
            print("pkg.mod.time is slow here")
            return pkg.mod.json.dumps({})
        # pkg.mod.os is patched in tests
        """,
    )

    unused = _unused_imports(tmp_path)
    assert {("mod.py", "os"), ("mod.py", "time")} <= unused
    assert ("mod.py", "json") not in unused


def test_a_literal_getattr_on_the_module_elsewhere_keeps_an_import(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/mod.py", "import math\nimport os\n")
    _write(
        tmp_path, "app.py",
        """
        import importlib


        def run(info):
            module = importlib.import_module("pkg.mod")
            return getattr(module, "math").sqrt(4), info["os"]


        run({})
        """,
    )

    unused = _unused_imports(tmp_path)
    assert ("mod.py", "math") not in unused
    assert ("mod.py", "os") in unused


def _unused_functions(tmp_path):
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=True))
    return sorted(item["name"].rsplit(".", 1)[-1] for item in result.get("unused_functions", []))


def test_functions_registered_through_bound_container_methods_or_instances_are_live(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "fx"\nversion = "0"\n')
    _write(tmp_path, "app/__init__.py", "")
    _write(
        tmp_path, "app/plugins.py",
        """
        from sqlite_utils import Migrations
        from helpers import cache

        MIGRATIONS = []
        migration = MIGRATIONS.append
        hooks = set()
        hook = hooks.add
        embeddings = Migrations("demo")


        @migration
        def m001_initial(db):
            return db


        @hook
        def on_start():
            return 1


        @embeddings()
        def m001_create(db):
            return db


        @cache
        def cached_but_unused():
            return 2


        def plain_unused():
            return 3


        def migrate(db):
            for step in MIGRATIONS:
                step(db)
        """,
    )
    _write(tmp_path, "app/cli.py", "from app.plugins import migrate\n\nmigrate(None)\n")
    assert _unused_functions(tmp_path) == ["cached_but_unused", "plain_unused"]


def test_pytest_plugin_hooks_and_cog_blocks_are_entry_points(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "fx"\nversion = "0"\n')
    _write(tmp_path, "fx/__init__.py", "")
    _write(
        tmp_path, "fx/plugin.py",
        """
        import pytest


        def _install():
            return 1


        def pytest_configure(config):
            _install()


        def helper_nobody_calls():
            return 2
        """,
    )
    _write(
        tmp_path, "fx/plain.py",
        """
        def _install_plain():
            return 1


        def pytest_configure(config):
            _install_plain()
        """,
    )
    _write(
        tmp_path, "docs/snippets_doc.py",
        """
        def render_table(cog):
            cog.out("table")


        def unused_snippet(cog):
            cog.out("never")
        """,
    )
    _write(
        tmp_path, "docs/index.rst",
        """
        Settings
        ========

        .. [[[cog
            from snippets_doc import render_table
            render_table(cog)
        .. ]]]
        .. [[[end]]]
        """,
    )
    assert _unused_functions(tmp_path) == [
        "_install_plain",
        "helper_nobody_calls",
        "unused_snippet",
    ]


def _package(tmp_path, module_body):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(
        tmp_path,
        "pkg/core.py",
        "class Parameter:\n    pass\n\n\nclass Context:\n    pass\n\n\ndef fast(value):\n    return value\n",
    )
    _write(tmp_path, "pkg/mod.py", module_body)
    _write(tmp_path, "main.py", "from pkg.mod import use\n\nuse()\n")


def test_string_inside_an_annotation_is_a_forward_reference(tmp_path):
    _package(
        tmp_path,
        """
        from typing import TYPE_CHECKING, Callable, Optional, Union

        if TYPE_CHECKING:
            from pkg.core import Context, Parameter


        def use(param: Union["Parameter", None] = None, hook: Optional[Callable[["Context"], None]] = None):
            return param, hook
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_literal_and_annotated_metadata_strings_are_not_references(tmp_path):
    _package(
        tmp_path,
        """
        from typing import TYPE_CHECKING, Annotated, Literal

        if TYPE_CHECKING:
            from pkg.core import Context, Parameter


        def use(mode: Literal["Parameter"] = "Parameter", size: Annotated[int, "Context"] = 1):
            return mode, size
        """,
    )
    assert _unused_imports(tmp_path) == {("mod.py", "Parameter"), ("mod.py", "Context")}


def test_import_with_a_fallback_definition_on_another_path_is_used(tmp_path):
    _package(
        tmp_path,
        """
        import sys

        try:
            from pkg.core import fast
        except ImportError:

            def fast(value):
                return value


        if sys.platform == "win32":
            from pkg.core import Parameter
        else:

            class Parameter:
                pass


        def use():
            return fast(Parameter)
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_definition_that_overwrites_an_import_on_the_same_path_still_reports(tmp_path):
    _package(
        tmp_path,
        """
        from pkg.core import fast

        try:
            from pkg.core import Parameter
        except ImportError:
            pass
        else:

            class Parameter:
                pass


        def fast(value):
            return value * 2


        def use():
            return fast(Parameter)
        """,
    )
    assert _unused_imports(tmp_path) == {("mod.py", "fast"), ("mod.py", "Parameter")}


def test_function_above_the_alternatives_uses_the_import(tmp_path):
    _package(
        tmp_path,
        """
        import sys


        def use():
            return fast(1)


        if sys.platform == "win32":
            from pkg.core import fast
        else:

            def fast(value):
                return value
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_function_above_a_straight_overwrite_still_reports(tmp_path):
    _package(
        tmp_path,
        """
        def use():
            return fast(1)


        from pkg.core import fast


        def fast(value):
            return value
        """,
    )
    assert _unused_imports(tmp_path) == {("mod.py", "fast")}


@pytest.mark.parametrize(
    "typing_import, annotation",
    [
        ("from typing import Literal as Choice", 'Choice["Parameter"]'),
        ("from typing import Annotated as Metadata", 'Metadata[int, "Parameter"]'),
    ],
)
def test_typing_alias_value_strings_do_not_use_an_import(
    tmp_path, typing_import, annotation
):
    _package(
        tmp_path,
        f"{typing_import}\nfrom pkg.core import Parameter\n"
        f"def use(value: {annotation} = None):\n    return value\n",
    )
    assert _unused_imports(tmp_path) == {("mod.py", "Parameter")}


def test_a_fully_quoted_nested_type_keeps_its_import(tmp_path):
    _package(
        tmp_path,
        """
        from typing import Optional
        from pkg.core import Parameter

        def use(value: "Optional['Parameter']" = None):
            return value
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_a_local_generic_named_literal_still_has_type_arguments(tmp_path):
    _package(
        tmp_path,
        """
        from typing import Generic, TypeVar
        from pkg.core import Parameter

        T = TypeVar("T")

        class Literal(Generic[T]):
            pass

        def use(value: Literal["Parameter"] = None):
            return value
        """,
    )
    assert _unused_imports(tmp_path) == set()


@pytest.mark.parametrize(
    "body",
    [
        """
        try:
            from pkg.core import fast
            raise ImportError("fallback after a successful import")
        except ImportError:
            def fast(value):
                return value

        def use():
            return fast(1)
        """,
        """
        try:
            from pkg.core import fast
        except ImportError:
            def fast(value):
                return value

        def fast(value):
            return value * 2

        def use():
            return fast(1)
        """,
        """
        import sys

        if sys.platform == "win32":
            from pkg.core import fast
        else:
            def fast(value):
                return value
            fast(1)

        def use():
            return 1
        """,
    ],
    ids=["try-prefix", "later-overwrite", "opposite-branch-read"],
)
def test_fallbacks_do_not_rescue_an_import_that_is_never_read(tmp_path, body):
    _package(tmp_path, body)
    assert _unused_imports(tmp_path) == {("mod.py", "fast")}


def test_reversed_fallback_arms_keep_the_reachable_import(tmp_path):
    _package(
        tmp_path,
        """
        import sys

        if sys.platform == "win32":
            def fast(value):
                return value
        else:
            from pkg.core import fast

        def use():
            return fast(1)
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_a_function_called_before_the_import_is_overwritten_keeps_it(tmp_path):
    _package(
        tmp_path,
        """
        from pkg.core import fast

        def read():
            return fast(1)

        read()

        def fast(value):
            return value * 2

        def use():
            return fast(1)
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_a_function_called_only_after_the_overwrite_leaves_import_unused(tmp_path):
    _package(
        tmp_path,
        """
        from pkg.core import fast

        def read():
            return fast(1)

        def fast(value):
            return value * 2

        def use():
            return read()
        """,
    )
    assert _unused_imports(tmp_path) == {("mod.py", "fast")}


def test_a_function_defined_only_in_the_fallback_cannot_use_the_other_import(tmp_path):
    _package(
        tmp_path,
        """
        import sys

        if sys.platform == "win32":
            from pkg.core import fast
        else:
            def fast(value):
                return value

            def read():
                return fast(1)

            read()

        def use():
            return 1
        """,
    )
    assert _unused_imports(tmp_path) == {("mod.py", "fast")}


def test_a_conditional_function_can_read_an_import_bound_later_in_its_arm(tmp_path):
    _package(
        tmp_path,
        """
        import sys

        if sys.platform == "win32":
            def use():
                return fast(1)

            from pkg.core import fast
        else:
            def fast(value):
                return value

            def use():
                return fast(1)
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_copying_a_fallback_binding_reads_the_import_before_assignment(tmp_path):
    _package(
        tmp_path,
        """
        try:
            from pkg.core import fast
        except ImportError:
            def fast(value):
                return value

        fast = fast

        def use():
            return fast(1)
        """,
    )
    assert _unused_imports(tmp_path) == set()


def test_an_annotated_value_overwrites_the_import_but_a_declaration_does_not(tmp_path):
    _package(
        tmp_path,
        """
        import sys

        if sys.platform == "win32":
            from pkg.core import fast, Parameter
        else:
            def fast(value):
                return value

            class Parameter:
                pass

        fast: int = 1
        Parameter: object

        def use():
            return fast, Parameter
        """,
    )
    assert _unused_imports(tmp_path) == {("mod.py", "fast")}


@pytest.mark.parametrize("fallback", [False, True], ids=["plain", "fallback"])
@pytest.mark.parametrize(
    "early_use",
    [
        """
        class Base:
            def read(self):
                return fast(1)

        class Reader(Base):
            pass

        reader = Reader()
        reader.read()
        """,
        """
        def read():
            return fast(1)

        reader = read
        reader()
        """,
        """
        def decorate(fn):
            fast(1)
            return fn

        @decorate
        def fast(value):
            return value * 2
        """,
    ],
    ids=["inherited-method", "callable-alias", "decorator"],
)
def test_proven_early_calls_keep_the_import_before_a_later_overwrite(
    tmp_path, early_use, fallback
):
    header = "from pkg.core import fast\n"
    if fallback:
        header = (
            "try:\n    from pkg.core import fast\n"
            "except ImportError:\n    def fast(value):\n        return value\n"
        )
    _package(
        tmp_path,
        header + textwrap.dedent(early_use) + "\n"
        "def fast(value):\n    return value * 2\n"
        "def use():\n    return fast(1)\n",
    )
    assert _unused_imports(tmp_path) == set()


@pytest.mark.parametrize(
    "unrelated_call",
    [
        """
        class Base:
            def read(self):
                return fast(1)

        class Reader(Base):
            def read(self):
                return 1

        reader = Reader()
        reader.read()
        """,
        """
        def read():
            return fast(1)

        def other():
            return 1

        reader = read
        reader = other
        reader()
        """,
        """
        def decorate(fn):
            fast(1)
            return fn

        def other(fn):
            return fn

        @other
        def fast(value):
            return value * 2
        """,
    ],
    ids=["overridden-method", "rebound-alias", "unused-decorator"],
)
def test_unrelated_early_calls_cannot_keep_the_overwritten_import(
    tmp_path, unrelated_call
):
    _package(
        tmp_path,
        "try:\n    from pkg.core import fast\n"
        "except ImportError:\n    def fast(value):\n        return value\n"
        + textwrap.dedent(unrelated_call) + "\n"
        "def fast(value):\n    return value * 2\n"
        "def use():\n    return fast(1)\n",
    )
    assert _unused_imports(tmp_path) == {("mod.py", "fast")}
