"""P401 resolves lambda reads without confusing expression and statement bodies."""

import ast
from textwrap import dedent

import pytest

from skylos.rules.quality.performance import PerformanceRule


def _analyze(source):
    rule = PerformanceRule()
    context = {"filename": "app.py"}
    return [
        finding
        for node in ast.walk(ast.parse(dedent(source)))
        for finding in rule.visit_node(node, context) or []
    ]


def _reads(source):
    return [row for row in _analyze(source) if row["rule_id"] == "SKY-P401"]


def test_django_style_streaming_lambda_keeps_other_quality_findings():
    source = """
        class FileResponse:
            block_size = 4096

            def stream(self, filelike):
                chunks = iter(lambda: filelike.read(self.block_size), b"")
                total = sum(iter(lambda: len(filelike.read(self.block_size)), 0))
                return chunks, total, User.query.all()
    """

    findings = _analyze(source)

    assert [row["rule_id"] for row in findings] == ["SKY-P404"]


@pytest.mark.parametrize(
    "size,method,expected",
    [
        ("4096", "read", False),
        ("1024 * 1024", "read", False),
        ("0", "read", False),
        ("-1", "read", True),
        ("None", "read", True),
        ("0", "readlines", True),
        ("4096", "readlines", False),
    ],
)
def test_lambda_resolves_captured_receiver_and_scalar_size(size, method, expected):
    source = f"""
        def factory(path):
            size = {size}
            handle = open(path, "rb")
            return lambda: handle.{method}(size)
    """

    findings = _reads(source)

    assert len(findings) == int(expected)
    if expected:
        assert "entire remaining file" in findings[0]["message"]


@pytest.mark.parametrize(
    "parameters", ["size", "size=4096", "size, /", "*, size", "*size", "**size"]
)
def test_lambda_parameters_shadow_captured_unbounded_size(parameters):
    source = f"""
        size = -1
        def factory(handle):
            return lambda {parameters}: handle.read(size)
    """

    assert _reads(source) == []


def test_nested_lambdas_preserve_outer_parameter_shadowing():
    source = """
        size = -1
        def factory(handle):
            return lambda size: lambda: handle.read(size)
    """

    assert _reads(source) == []


@pytest.mark.parametrize("initializer", ["-1", "None"])
def test_lambda_with_no_local_binding_retains_uncapped_captured_read(initializer):
    source = f"""
        size = {initializer}
        def factory(handle):
            return lambda: handle.read(size)
    """

    findings = _reads(source)

    assert len(findings) == 1
    assert "may materialize" in findings[0]["message"]


@pytest.mark.parametrize(
    "expression",
    [
        "(size := chosen)",
        "[(size := chosen) for chosen in sizes]",
        "{(size := chosen) for chosen in sizes}",
        "{chosen: (size := chosen) for chosen in sizes}",
        "((size := chosen) for chosen in sizes)",
    ],
)
def test_lambda_walrus_locals_do_not_borrow_outer_negative_size(expression):
    source = f"""
        size = -1
        def factory(handle, chosen, sizes):
            return lambda: ({expression}, handle.read(size))
    """

    assert _reads(source) == []


def test_nested_lambda_assignment_does_not_shadow_outer_lambda_capture():
    source = """
        size = -1
        def factory(handle):
            return lambda: (lambda: (size := 4096), handle.read(size))
    """

    assert len(_reads(source)) == 1


def test_lambda_receiver_parameter_does_not_inherit_memory_buffer_origin():
    source = """
        from io import BytesIO
        handle = BytesIO(b"fixed")
        factory = lambda handle: handle.read()
    """

    findings = _reads(source)

    assert len(findings) == 1
    assert "may materialize" in findings[0]["message"]


def test_uncapped_unknown_lambda_receiver_is_still_reported():
    assert len(_reads("factory = lambda handle: handle.read()")) == 1


def test_caller_chosen_lambda_read_size_stays_unknown():
    assert _reads("factory = lambda handle, size: handle.read(size)") == []
