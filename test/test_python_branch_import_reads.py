"""Actual import reads across alternative bindings, with overwrite controls."""

import ast
import json
import textwrap

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def _scan(tmp_path, body):
    files = {
        "pkg/__init__.py": "",
        "pkg/left.py": "def convert(value):\n    return value\n",
        "pkg/right.py": "def convert(value):\n    return value + 1\n",
        "pkg/consumer.py": textwrap.dedent(body).lstrip(),
        "main.py": "from pkg.consumer import use\nuse()\n",
    }
    for path, source in files.items():
        write_fixture(tmp_path, path, source)
    report = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert not report.get("analysis_errors")
    return report


def _consumer_imports(report):
    return {
        (item["full_name"], item["line"])
        for item in report.get("unused_imports", [])
        if item["file"].replace("\\", "/").endswith("/pkg/consumer.py")
    }


@pytest.mark.parametrize(
    "body",
    [
        """
        import sys
        if sys.platform == "win32":
            from pkg.left import convert as active
        else:
            from pkg.right import convert as active
        def use():
            return active(1)
        """,
        """
        try:
            from pkg.left import convert as active
        except ImportError:
            from pkg.right import convert as active
        def use():
            return active(1)
        """,
        """
        import sys
        try:
            if sys.platform == "win32":
                from pkg.left import convert as active
            else:
                from pkg.right import convert as active
        except ImportError:
            active = None
        def use():
            return active(1) if active is not None else None
        """,
        """
        try:
            import sys
        except ImportError:
            active = None
        else:
            from pkg.left import convert as active
        def use():
            return active(1) if active is not None else None
        """,
        """
        import sys
        if sys.platform == "win32":
            active = None
        else:
            from pkg.left import convert as active
        def use():
            return active(1) if active is not None else None
        """,
    ],
    ids=["if-providers", "try-providers", "nested-if", "try-else", "reversed-if"],
)
def test_module_alternative_imports_have_real_later_reads(tmp_path, body):
    report = _scan(tmp_path, body)
    assert not any(
        name in {"pkg.left.convert", "pkg.right.convert"}
        for name, _ in _consumer_imports(report)
    )


@pytest.mark.parametrize("warnings_context", [False, True])
def test_local_import_fallback_is_read_after_the_join(tmp_path, warnings_context):
    body = """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            return active(1) if active is not None else None
    """
    if warnings_context:
        body = """
            from warnings import catch_warnings
            def use():
                try:
                    with catch_warnings():
                        from pkg.left import convert as active
                except ImportError:
                    active = None
                return active(1) if active is not None else None
        """
    report = _scan(tmp_path, body)
    assert not any(
        name in {"pkg.left.convert", "pkg.right.convert"}
        for name, _ in _consumer_imports(report)
    )


@pytest.mark.parametrize(
    "body",
    [
        """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            active = None
            return active
        """,
        """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            active: object = None
            return active
        """,
        """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
                return active
            return 1
        """,
        """
        def use():
            try:
                from pkg.left import convert as active
                active = None
            except ImportError:
                active = None
            return active
        """,
        """
        def use():
            try:
                from pkg.left import convert as active
                raise ImportError()
            except ImportError:
                active = None
            return active
        """,
        """
        def use():
            from pkg.right import convert as active
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            return 1
        """,
    ],
    ids=[
        "later-overwrite",
        "annotated-overwrite",
        "handler-only",
        "try-overwrite",
        "try-prefix-raise",
        "never-read",
    ],
)
def test_local_fallback_does_not_rescue_unused_imports(tmp_path, body):
    report = _scan(tmp_path, body)
    assert any(name == "pkg.left.convert" for name, _ in _consumer_imports(report))


@pytest.mark.parametrize(
    "body",
    [
        """
        import sys
        if sys.platform == "win32":
            from pkg.left import convert as active
        else:
            from pkg.right import convert as active
        active = None
        def use():
            return active
        """,
        """
        import sys
        if sys.platform == "win32":
            from pkg.left import convert as active
        else:
            active = None
            print(active)
        def use():
            return 1
        """,
        """
        try:
            from pkg.left import convert as active
            raise ImportError()
        except ImportError:
            active = None
        def use():
            return active
        """,
    ],
    ids=["later-overwrite", "opposite-branch-read", "try-prefix-raise"],
)
def test_module_fallback_does_not_rescue_unused_imports(tmp_path, body):
    report = _scan(tmp_path, body)
    assert any(name == "pkg.left.convert" for name, _ in _consumer_imports(report))


@pytest.mark.parametrize(
    "body",
    [
        """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            def inner(value=(active := None)):
                return value
            return active
        """,
        """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            def replace():
                nonlocal active
                active = None
            replace()
            return active
        """,
        """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            callback = lambda active: active
            return callback(1)
        """,
    ],
    ids=["default-overwrite", "nonlocal-overwrite", "lambda-parameter"],
)
def test_nested_scope_operations_do_not_invent_import_reads(tmp_path, body):
    report = _scan(tmp_path, body)
    assert any(name == "pkg.left.convert" for name, _ in _consumer_imports(report))


def test_one_fallback_does_not_rescue_an_earlier_overwritten_provider(tmp_path):
    report = _scan(
        tmp_path,
        """
        def use():
            from pkg.right import convert as active
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            return active(1) if active is not None else None
        """,
    )
    assert any(name == "pkg.right.convert" for name, _ in _consumer_imports(report))


@pytest.mark.skipif(not hasattr(ast, "TypeVar"), reason="PEP 695 needs Python 3.12")
def test_type_parameter_in_class_base_is_not_an_outer_import_read(tmp_path):
    report = _scan(
        tmp_path,
        """
        def use():
            try:
                from pkg.left import convert as active
            except ImportError:
                active = None
            class Values[active](list[active]):
                pass
            return Values
        """,
    )
    assert any(name == "pkg.left.convert" for name, _ in _consumer_imports(report))


@pytest.mark.parametrize("local", [False, True])
def test_handler_only_import_after_a_nonraising_body_is_not_rescued(tmp_path, local):
    body = """
        try:
            active = None
        except ImportError:
            from pkg.left import convert as active
        def use():
            return active
    """
    if local:
        body = """
            def use():
                try:
                    active = None
                except ImportError:
                    from pkg.left import convert as active
                return active
        """
    report = _scan(tmp_path, body)
    assert any(name == "pkg.left.convert" for name, _ in _consumer_imports(report))
