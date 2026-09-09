"""Independent source-as-data checks for bounded refactor verification.

None of these snippets is imported or executed. The assertions exercise the
verifier's handling of observable effects and its refusal to certify code
outside the supported model.
"""

from textwrap import dedent

import pytest

from skylos.verification.behavior import compare_python_behavior


def _compare(before, after, *, before_extra=None, after_extra=None, **options):
    return compare_python_behavior(
        {"app.py": dedent(before), **(before_extra or {})},
        {"app.py": dedent(after), **(after_extra or {})},
        file="app.py",
        symbol="run",
        **options,
    )


def test_helper_extraction_preserves_callback_results_and_exceptions():
    result = _compare(
        """
        def run(callback, value):
            return callback(value)
        """,
        """
        def apply(transform, item):
            return transform(item)

        def run(callback, value):
            return apply(callback, value)
        """,
    )
    assert result["status"] == "equivalent", result


def test_imported_helper_implementation_is_part_of_the_comparison():
    source = "from helpers import prepare\ndef run(value):\n    return prepare(value)\n"
    result = _compare(
        source,
        source,
        before_extra={"helpers.py": "def prepare(value):\n    return 'original'\n"},
        after_extra={"helpers.py": "def prepare(value):\n    return 'changed'\n"},
    )
    assert result["status"] == "different", result


@pytest.mark.parametrize("body", ["return register(helper)", "return helper"])
def test_escaping_helper_does_not_hide_changed_implementation(body):
    result = _compare(
        f"def helper(value):\n    return 'original'\ndef run(register):\n    {body}\n",
        f"def helper(value):\n    return 'changed'\ndef run(register):\n    {body}\n",
    )
    assert result["status"] != "equivalent", result


@pytest.mark.parametrize(
    ("before_body", "after_body"),
    [
        ("return True", "return 1"),
        ("return 1", "return 1.0"),
        ("callback(value)\n    return None", "return None"),
        (
            "callback(value)\n    return callback(value)",
            "return callback(value)",
        ),
        ("return callback(value, label='a')", "return callback(value, label='b')"),
        (
            "return callback(first=value, second=1)",
            "return callback(second=1, first=value)",
        ),
    ],
)
def test_supported_observable_changes_are_not_certified(before_body, after_body):
    result = _compare(
        f"def run(callback, value):\n    {before_body}\n",
        f"def run(callback, value):\n    {after_body}\n",
    )
    assert result["status"] == "different", result


def test_finally_cleanup_survives_helper_extraction():
    result = _compare(
        """
        def run(callback, cleanup, value):
            try:
                return callback(value)
            finally:
                cleanup()
        """,
        """
        def apply(callback, cleanup, value):
            try:
                return callback(value)
            finally:
                cleanup()

        def run(callback, cleanup, value):
            return apply(callback, cleanup, value)
        """,
    )
    assert result["status"] == "equivalent", result


def test_finally_return_does_not_erase_prior_callback_effects():
    result = _compare(
        """
        def run(callback, value):
            try:
                callback(value)
            finally:
                return 'done'
        """,
        """
        def run(callback, value):
            return 'done'
        """,
    )
    assert result["status"] == "different", result


def test_moving_finally_cleanup_changes_exception_behavior_and_order():
    result = _compare(
        """
        def run(callback, cleanup, value):
            try:
                return callback(value)
            finally:
                cleanup()
        """,
        """
        def run(callback, cleanup, value):
            cleanup()
            return callback(value)
        """,
    )
    assert result["status"] == "different", result


def test_swallowing_callback_exception_changes_behavior():
    result = _compare(
        """
        def run(callback, value):
            return callback(value)
        """,
        """
        def run(callback, value):
            try:
                return callback(value)
            except BaseException:
                return None
        """,
    )
    assert result["status"] == "different", result


def test_catch_and_reraise_preserves_the_original_exception():
    result = _compare(
        """
        def run(callback, value):
            return callback(value)
        """,
        """
        def run(callback, value):
            try:
                return callback(value)
            except BaseException:
                raise
        """,
    )
    assert result["status"] == "equivalent", result


def test_finally_reraise_uses_the_current_exception_after_nested_call():
    result = _compare(
        """
        def run(callback, cleanup):
            try:
                callback()
            except BaseException:
                cleanup()
                raise
        """,
        """
        def run(callback, cleanup):
            try:
                callback()
            except BaseException:
                try:
                    cleanup()
                finally:
                    raise
        """,
    )
    assert result["status"] == "equivalent", result


def test_keyword_parameter_rename_cannot_be_certified_by_positional_trace():
    result = _compare(
        "def run(value):\n    return value\n",
        "def run(item):\n    return item\n",
    )
    assert result["status"] != "equivalent", result


@pytest.mark.parametrize(
    "source",
    [
        "def run(value=1):\n    return value\n",
        "@decorate\ndef run(value):\n    return value\n",
        "def run(value: int):\n    return value\n",
        "def run(value):\n    return value.name\n",
        "def run(value):\n    return value[0]\n",
        "def run(value):\n    return value + 0\n",
        "def run(value):\n    yield value\n",
        "async def run(value):\n    return value\n",
        "def run(value):\n    with value:\n        return None\n",
        "def run(callback):\n    try:\n        callback()\n    except Exception:\n        return None\n",
        "def run(value):\n    return run(value)\n",
        "def run(value, value):\n    return value\n",
        "def run(value):\n    __debug__ = value\n    return value\n",
    ],
)
def test_identical_unsupported_source_is_unknown(source):
    result = _compare(source, source)
    assert result["status"] == "unknown", result


def test_shadowed_baseexception_is_not_treated_as_builtin_catch_all():
    source = """
    def run(BaseException, callback):
        try:
            callback()
        except BaseException:
            return None
    """
    result = _compare(source, source)
    assert result["status"] == "unknown", result


def test_module_rebinding_is_not_ignored_even_with_identical_selected_function():
    result = _compare(
        """
        def helper(value):
            return value

        def run(value):
            return helper(value)
        """,
        """
        def helper(value):
            return value

        def run(value):
            return helper(value)

        helper = replacement
        """,
    )
    assert result["status"] == "unknown", result


@pytest.mark.parametrize(
    "header",
    [
        "@decorate\ndef unrelated(value):",
        "def unrelated(value=initialize()):",
        "def unrelated(value: initialize()):",
    ],
)
def test_unrelated_definition_headers_cannot_establish_stable_bindings(header):
    source = (
        "from opaque_library import decorate, initialize\n"
        f"{header}\n    return value\n"
        "def run(value):\n    return value\n"
    )
    result = _compare(source, source)
    assert result["status"] == "unknown", result


@pytest.mark.parametrize("source_root", ["src", "lib", "python"])
def test_src_layout_helper_change_is_not_hidden_as_an_opaque_import(source_root):
    app = (
        "from pkg.helpers import prepare\ndef run(value):\n    return prepare(value)\n"
    )
    result = compare_python_behavior(
        {
            f"{source_root}/pkg/app.py": app,
            f"{source_root}/pkg/helpers.py": "def prepare(value):\n    return 'original'\n",
        },
        {
            f"{source_root}/pkg/app.py": app,
            f"{source_root}/pkg/helpers.py": "def prepare(value):\n    return 'changed'\n",
        },
        file=f"{source_root}/pkg/app.py",
        symbol="run",
    )
    assert result["status"] != "equivalent", result


def test_root_package_relative_import_is_not_mistaken_for_external_dependency():
    app = "from .helpers import prepare\ndef run(value):\n    return prepare(value)\n"
    result = compare_python_behavior(
        {
            "__init__.py": app,
            "helpers.py": "def prepare(value):\n    return 'original'\n",
        },
        {
            "__init__.py": app,
            "helpers.py": "def prepare(value):\n    return 'changed'\n",
        },
        file="__init__.py",
        symbol="run",
    )
    assert result["status"] != "equivalent", result


def test_explicit_child_import_does_not_follow_conflicting_package_alias():
    app = "import pkg.child\ndef run(value):\n    return pkg.child.identity(value)\n"
    common = {
        "app.py": app,
        "pkg/__init__.py": "import other as child\n",
        "other.py": "def identity(value):\n    return None\n",
    }
    result = compare_python_behavior(
        {**common, "pkg/child.py": "def identity(value):\n    return value\n"},
        {**common, "pkg/child.py": "def identity(value):\n    return 'changed'\n"},
        file="app.py",
        symbol="run",
    )
    assert result["status"] != "equivalent", result


def test_local_assignment_prevents_resolving_an_earlier_global_call():
    result = _compare(
        """
        def helper(value):
            return value

        def run(value):
            result = helper(value)
            helper = value
            return result
        """,
        """
        def run(value):
            return value
        """,
    )
    assert result["status"] == "unknown", result


def test_path_budget_exhaustion_is_unknown_for_identical_sources():
    source = "def run(callback, value):\n    return callback(value)\n"
    result = _compare(source, source, max_paths=1)
    assert result["status"] == "unknown", result


def test_missing_selected_symbol_is_not_empty_trace_equivalence():
    result = _compare(
        "def other():\n    return None\n", "def other():\n    return None\n"
    )
    assert result["status"] == "unknown", result
