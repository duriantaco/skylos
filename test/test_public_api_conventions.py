"""A library's declared public API is not dead code; undeclared names still are."""

import json
import textwrap

from test.fixture_paths import write_fixture

from skylos.analyzer import analyze


def _write(root, relative, body):
    write_fixture(root, relative, textwrap.dedent(body).lstrip(), overwrite=True)


def _unused(tmp_path):
    result = json.loads(analyze(str(tmp_path), conf=0))
    names = set()
    for key in ("unused_functions", "unused_classes", "unused_variables"):
        for item in result.get(key, []):
            names.add(item["simple_name"])
    return names


def _body(name, doc=""):
    docstring = ""
    if doc:
        docstring = f'\n        """{doc}"""'
    return f"""
    def {name}(path):{docstring}
        with open(path, encoding="utf-8") as handle:
            rows = handle.read().splitlines()
        return [row.strip() for row in rows if row]
    """


def test_documented_module_attributes_are_public_unless_excluded(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "lib"\nversion = "1"\n')
    _write(tmp_path, "lib/__init__.py", "")
    _write(
        tmp_path,
        "lib/data.py",
        '''
        TRAIN_URL = "https://example.com/train.zip"
        """Training split."""

        #: Development split.
        DEV_URL = "https://example.com/dev.zip"

        TEST_URL = "https://example.com/test.zip"  #: Test split.

        _CACHE_URL = "https://example.com/cache.zip"
        """Private, even though documented."""

        INTERNAL_URL = "https://example.com/internal.zip"
        """Kept out of the docs. :meta private:"""

        PLAIN_URL = "https://example.com/plain.zip"
        ''',
    )
    _write(
        tmp_path,
        "lib/listed.py",
        '''
        __all__ = ["LISTED_URL"]

        LISTED_URL = "https://example.com/listed.zip"

        UNLISTED_URL = "https://example.com/unlisted.zip"
        """Documented, but __all__ is the module's exact API."""
        ''',
    )
    _write(
        tmp_path,
        "scripts/fetch.py",
        '''
        SCRIPT_URL = "https://example.com/script.zip"
        """Scripts are not importable API."""
        ''',
    )

    unused = _unused(tmp_path)

    assert {"TRAIN_URL", "DEV_URL", "TEST_URL", "LISTED_URL"}.isdisjoint(unused)
    assert {
        "_CACHE_URL",
        "INTERNAL_URL",
        "PLAIN_URL",
        "UNLISTED_URL",
        "SCRIPT_URL",
    } <= unused


def test_api_documentation_declares_public_names(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "lib"\nversion = "1"\n')
    _write(tmp_path, "lib/__init__.py", "")
    _write(tmp_path, "lib/catalog.py", 'CATALOG_URL = "https://example.com/c.zip"\n')
    _write(
        tmp_path,
        "lib/members.py",
        _body("documented_member", "Rendered by automodule.")
        + '''
    def _private_member():
        """Private names stay private under :members:."""
        return 1
    '''
        + _body("undocumented_member"),
    )
    _write(tmp_path, "lib/roles.py", _body("linked_function"))
    _write(tmp_path, "lib/myst.py", _body("myst_member"))
    _write(tmp_path, "lib/mk.py", _body("mk_member"))
    _write(tmp_path, "lib/elsewhere.py", _body("not_in_docs"))
    _write(tmp_path, "lib/history.py", _body("changelog_only"))
    _write(tmp_path, "scripts/release.py", _body("script_helper"))
    _write(
        tmp_path,
        "docs/api.rst",
        """
        .. autodata:: lib.catalog.CATALOG_URL

        .. automodule:: lib.members
           :members:

        .. currentmodule:: lib.roles

        See :func:`linked_function` and :func:`scripts.release.script_helper`.
        """,
    )
    _write(
        tmp_path,
        "docs/myst.md",
        """
        ```{eval-rst}
        .. automodule:: lib.myst
            :members:
            :undoc-members:
        ```

        ::: lib.mk
            options:
              show_if_no_docstring: true
        """,
    )
    _write(tmp_path, "CHANGELOG.md", "- Added :func:`lib.history.changelog_only`.\n")

    unused = _unused(tmp_path)

    assert {
        "CATALOG_URL",
        "documented_member",
        "linked_function",
        "myst_member",
        "mk_member",
    }.isdisjoint(unused)
    assert {
        "_private_member",
        "undocumented_member",
        "not_in_docs",
        "changelog_only",
        "script_helper",
    } <= unused


def test_stubs_and_lazy_export_tables_declare_public_names(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "lib"\nversion = "1"\n')
    _write(
        tmp_path,
        "lib/__init__.py",
        """
        import importlib

        _LAZY = {"lazy_export": ".lazy"}


        def __getattr__(name):
            if name in _LAZY:
                module = importlib.import_module(_LAZY[name], __name__)
                return getattr(module, name)
            raise AttributeError(name)
        """,
    )
    _write(tmp_path, "lib/lazy.py", _body("lazy_export") + _body("lazy_neighbour"))
    _write(tmp_path, "lib/typed.py", _body("stub_declared") + _body("stub_omitted"))
    _write(
        tmp_path, "lib/typed.pyi", "def stub_declared(path: str) -> list[str]: ...\n"
    )
    _write(
        tmp_path,
        "lib/retired/__init__.py",
        """
        _REMOVED = {"removed_api": "gone"}


        def __getattr__(name):
            if name in _REMOVED:
                raise AttributeError(f"{name} was removed")
            raise AttributeError(name)
        """,
    )
    _write(tmp_path, "lib/retired/impl.py", _body("removed_api"))
    _write(tmp_path, "lib/table.py", '_TABLE = {"table_only": ".tablemod"}\n')
    _write(tmp_path, "lib/tablemod.py", _body("table_only"))

    unused = _unused(tmp_path)

    assert {"lazy_export", "stub_declared"}.isdisjoint(unused)
    assert {"lazy_neighbour", "stub_omitted", "removed_api", "table_only"} <= unused
