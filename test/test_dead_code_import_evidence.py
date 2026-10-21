"""Import liveness: what does and does not show that an import is used."""

import json
import textwrap

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
