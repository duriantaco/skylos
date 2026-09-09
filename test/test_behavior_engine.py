"""Behavior-model unit tests; fixture sources are parsed, never executed."""

import json
from textwrap import dedent

import pytest

from skylos.verification.behavior import compare_python_behavior


def compare(before, after, **options):
    return compare_python_behavior(
        {"app.py": dedent(before)},
        {"app.py": dedent(after)},
        file="app.py",
        symbol="run",
        **options,
    )


def test_relative_import_helper_extraction_and_keyword_binding():
    before = {"pkg/app.py": "def run(callback, value):\n    return callback(value)\n"}
    after = {
        "pkg/app.py": (
            "from .helpers import apply\n"
            "def run(callback, value):\n"
            "    return apply(item=value, transform=callback)\n"
        ),
        "pkg/helpers.py": (
            "def apply(transform, *, item):\n    return transform(item)\n"
        ),
    }
    result = compare_python_behavior(before, after, file="pkg/app.py", symbol="run")
    assert result["status"] == "equivalent", result
    assert result["after_range"] == {"start_line": 2, "end_line": 3}
    assert result["model_version"] == 1
    json.dumps(result)


def test_assignment_alias_and_eager_argument_evaluation_preserve_effects():
    result = compare(
        """
        def run(callback, prepare, value):
            return callback(prepare(value))
        """,
        """
        def run(callback, prepare, value):
            invoke = callback
            item = prepare(value)
            return invoke(item)
        """,
    )
    assert result["status"] == "equivalent", result


def test_argument_evaluation_order_is_observable():
    result = compare(
        """
        def run(callback, left, right):
            return callback(left(), right())
        """,
        """
        def run(callback, left, right):
            second = right()
            first = left()
            return callback(first, second)
        """,
    )
    assert result["status"] == "different", result
    assert result["differences"][0]["runtime_witness"] is False


def test_active_exception_context_is_part_of_cleanup_observation():
    result = compare(
        """
        def run(callback, cleanup):
            try:
                callback()
            except BaseException:
                cleanup()
            else:
                cleanup()
        """,
        """
        def run(callback, cleanup):
            try:
                callback()
            except BaseException:
                pass
            cleanup()
        """,
    )
    assert result["status"] == "different", result
    evidence = result["differences"][0]
    assert any(
        call["active_exception"] is not None for call in evidence["before"]["calls"]
    )


def test_helper_keeps_caller_exception_context():
    result = compare(
        """
        def run(callback, cleanup):
            try:
                callback()
            except BaseException:
                cleanup()
                raise
        """,
        """
        def finish(cleanup):
            cleanup()
            raise

        def run(callback, cleanup):
            try:
                callback()
            except BaseException:
                finish(cleanup)
        """,
    )
    assert result["status"] == "equivalent", result


def test_except_alias_is_cleared_after_handler():
    source = """
    def run(callback):
        try:
            callback()
        except BaseException as error:
            pass
        return error
    """
    result = compare(source, source)
    assert result["status"] == "unknown", result
    assert any("before assignment" in reason for reason in result["reasons"])


def test_explicit_raise_of_saved_exception_under_new_context_is_unknown():
    source = """
    def run(callback, cleanup):
        try:
            callback()
        except BaseException as error:
            try:
                cleanup()
            except BaseException:
                raise error
    """
    assert compare(source, source)["status"] == "unknown"


def test_missing_previously_local_dependency_is_unknown():
    source = "from helper import apply\ndef run(value):\n    return apply(value)\n"
    result = compare_python_behavior(
        {"app.py": source, "helper.py": "def apply(value):\n    return value\n"},
        {"app.py": source},
        file="app.py",
        symbol="run",
    )
    assert result["status"] == "unknown", result
    assert any("unavailable" in reason for reason in result["reasons"])


@pytest.mark.parametrize(
    "call", ["apply()", "apply(value, value)", "apply(other=value)"]
)
def test_invalid_local_helper_argument_binding_is_unknown(call):
    source = (
        f"def apply(value):\n    return value\ndef run(value):\n    return {call}\n"
    )
    assert compare(source, source)["status"] == "unknown"


def test_helper_depth_budget_is_unknown():
    source = """
    def apply(value):
        return value
    def run(value):
        return apply(value)
    """
    result = compare(source, source, max_depth=1)
    assert result["status"] == "unknown", result
    assert any("depth budget" in reason for reason in result["reasons"])


@pytest.mark.parametrize("budget", [0, -1, True, 1.5])
def test_invalid_budgets_fail_closed(budget):
    source = "def run(value):\n    return value\n"
    assert compare(source, source, max_paths=budget)["status"] == "unknown"


def test_no_import_or_execution_of_fixture_code(tmp_path):
    marker = tmp_path / "must-not-be-created"
    source = f"open({str(marker)!r}, 'w')\ndef run(value):\n    return value\n"
    result = compare(source, source)
    assert result["status"] == "unknown", result
    assert not marker.exists()
