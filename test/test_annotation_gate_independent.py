"""Independent source-only controls for annotation-policy applicability."""

import ast
import textwrap

import pytest

from test.fixture_paths import write_fixture

from skylos.rules.quality.practices import TypeAnnotationPracticeRule


def _scan(tmp_path, source, *, policy=None, stub=None, coverage=False):
    source = textwrap.dedent(source).lstrip("\n")
    filename = tmp_path / "surface.py"
    write_fixture(tmp_path, "surface.py", source, overwrite=True)
    if policy is not None:
        write_fixture(tmp_path, "pyproject.toml",
            '[tool.mypy]\nfiles = ["surface.py"]\n' + policy,
            overwrite=True,
        )
    if stub is not None:
        write_fixture(tmp_path, "surface.pyi", textwrap.dedent(stub), overwrite=True)
    context = {"filename": str(filename), "project_root": tmp_path, "source": source}
    findings = TypeAnnotationPracticeRule(coverage_advice=coverage).visit_node(
        ast.parse(source, type_comments=True), context
    ) or []
    return findings, context


def test_required_implementation_annotations_survive_a_complete_stub(tmp_path):
    findings, context = _scan(
        tmp_path,
        "__all__ = ['convert']\ndef convert(value): return value\n",
        policy="disallow_untyped_defs = true\n",
        stub="def convert(value: int) -> int: ...\n",
    )
    assert {finding["rule_id"] for finding in findings} == {"SKY-T101", "SKY-T102"}
    assert context["annotation_coverage"]["definitions_with_supplied_contract"] == 1


def test_required_implementation_annotations_survive_complete_overloads(tmp_path):
    findings, _ = _scan(
        tmp_path,
        """
        from typing import overload
        __all__ = ["convert"]
        @overload
        def convert(value: int) -> int: ...
        @overload
        def convert(value: str) -> str: ...
        def convert(value): return value
        """,
        policy="disallow_untyped_defs = true\n",
    )
    assert {finding["rule_id"] for finding in findings} == {"SKY-T101", "SKY-T102"}
    assert {finding["line"] for finding in findings} == {7}


def test_partial_only_policy_applies_even_with_supplied_overloads(tmp_path):
    findings, _ = _scan(
        tmp_path,
        """
        from typing import overload
        @overload
        def convert(value: int) -> int: ...
        @overload
        def convert(value: str) -> str: ...
        def convert(value: int): return value
        """,
        policy="disallow_incomplete_defs = true\n",
    )
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-T102", 6)
    ]


def test_optional_export_contract_does_not_need_redundant_implementation_annotations(tmp_path):
    findings, context = _scan(
        tmp_path,
        "__all__ = ['convert']\ndef convert(value): return value\n",
        stub="def convert(value: int) -> int: ...\n",
        coverage=True,
    )
    assert findings == []
    assert context["annotation_coverage"]["definitions_with_supplied_contract"] == 1
    assert context["annotation_coverage"]["unreported_missing_definitions"] == 1


def test_optional_interface_coverage_requires_a_proved_provider(tmp_path):
    findings, _ = _scan(
        tmp_path,
        """
        from custom import Protocol
        class Surface(Protocol):
            def convert(self, value): ...
        """,
        coverage=True,
    )
    assert findings == []


def test_local_typing_provider_does_not_prove_optional_interface(tmp_path):
    (tmp_path / "typing.py").write_text(
        "raise RuntimeError('target provider must never execute')\n",
        encoding="utf-8",
    )
    findings, _ = _scan(
        tmp_path,
        """
        from typing import Protocol
        class Surface(Protocol):
            def convert(self, value): ...
        """,
        coverage=True,
    )
    assert findings == []


def test_proved_protocol_still_receives_optional_interface_advice(tmp_path):
    findings, _ = _scan(
        tmp_path,
        """
        from typing import Protocol
        class Surface(Protocol):
            def convert(self, value): ...
        """,
        coverage=True,
    )
    assert {finding["rule_id"] for finding in findings} == {"SKY-T101", "SKY-T102"}


@pytest.mark.parametrize("boundary", ["export", "protocol"])
def test_unknown_class_decorator_does_not_prove_original_method_boundary(tmp_path, boundary):
    declaration = (
        "from typing import Protocol\n"
        if boundary == "protocol"
        else "__all__ = ['Surface']\n"
    )
    base = "(Protocol)" if boundary == "protocol" else ""
    findings, _ = _scan(
        tmp_path,
        declaration + "@replace_surface\n" + f"class Surface{base}:\n"
        "    def convert(self, value): ...\n",
        coverage=True,
    )
    assert findings == []


@pytest.mark.parametrize("boundary", ["export", "protocol"])
@pytest.mark.parametrize(
    "mutation",
    ["Surface.convert = replacement", "setattr(Surface, 'convert', replacement)"],
)
def test_replaced_class_method_does_not_prove_original_boundary(tmp_path, boundary, mutation):
    declaration = (
        "from typing import Protocol\n"
        if boundary == "protocol"
        else "__all__ = ['Surface']\n"
    )
    base = "(Protocol)" if boundary == "protocol" else ""
    findings, _ = _scan(
        tmp_path,
        declaration + f"class Surface{base}:\n"
        "    def convert(self, value): ...\n" + mutation + "\n",
        coverage=True,
    )
    assert findings == []


def test_analysis_does_not_execute_target_source(tmp_path):
    findings, _ = _scan(
        tmp_path,
        "raise RuntimeError('target module must never execute')\n"
        "__all__ = ['convert']\ndef convert(value): return value\n",
        coverage=True,
    )
    assert {finding["rule_id"] for finding in findings} == {"SKY-T101", "SKY-T102"}
