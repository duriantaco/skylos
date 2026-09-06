"""Inert source fixtures for declaration-only Python stub files."""

import json
import textwrap

import pytest

from skylos.analyzer import Skylos, analyze


def _sources(tmp_path, files):
    for filename, source in files.items():
        path = tmp_path / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as stream:
            stream.write(textwrap.dedent(source).lstrip())


def _scan(tmp_path, files):
    _sources(tmp_path, files)
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    assert result.get("analysis_errors", []) == []
    return result


def _names(result, bucket):
    return {item["full_name"] for item in result.get(bucket, [])}


@pytest.fixture(autouse=True)
def _single_worker(monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")


@pytest.mark.parametrize("scope", ["module", "class"])
def test_stub_annotation_and_ellipsis_bindings_are_not_unused(tmp_path, scope):
    declarations = """\
_bracket_re = ...
_annotation: object
_annotated_ellipsis: object = ...
_first = _second = ...
"""
    source = (
        declarations
        if scope == "module"
        else "class _Shape:\n" + textwrap.indent(declarations, "    ")
    )
    result = _scan(tmp_path, {"src/plotly-stubs/basedatatypes.pyi": source})

    assert result.get("unused_variables", []) == []


@pytest.mark.parametrize("scope", ["module", "class"])
def test_stub_annotated_literal_bindings_are_declarations(tmp_path, scope):
    declarations = "_typed: int = 0\n_negative: int = -1\n"
    source = (
        declarations
        if scope == "module"
        else "class _Shape:\n" + textwrap.indent(declarations, "    ")
    )
    result = _scan(tmp_path, {"contracts.pyi": source})

    assert result.get("unused_variables", []) == []
    assert result.get("unused_classes", []) == []


def test_stub_function_class_and_method_declarations_are_not_unused(tmp_path):
    result = _scan(
        tmp_path,
        {
            "contracts.pyi": '''
                def _declared(value: object) -> object: ...
                async def _async_declared(value: object) -> object: ...
                def _documented(value: object) -> object:
                    """Contract only."""
                    ...
                class _Empty: ...
                class _Shape:
                    _field: object
                    def _method(self, value: object) -> object: ...
                    def _documented_method(self, value: object) -> object:
                        """Contract only."""
                        ...
            ''',
        },
    )

    assert result.get("unused_functions", []) == []
    assert result.get("unused_classes", []) == []
    assert result.get("unused_parameters", []) == []


@pytest.mark.parametrize("suffix", [".py", ".pyw"])
def test_runtime_files_keep_identical_placeholder_warnings(tmp_path, suffix):
    result = _scan(
        tmp_path,
        {
            "runtime" + suffix: """
                _bracket_re = ...
                _annotation: object
                _first = _second = ...
                def _declared(value): ...
                class _Shape:
                    _field: object
            """,
        },
    )

    assert {
        "runtime._bracket_re",
        "runtime._annotation",
        "runtime._first",
        "runtime._second",
    } <= _names(result, "unused_variables")
    assert "runtime._declared" in _names(result, "unused_functions")
    assert "runtime._Shape" in _names(result, "unused_classes")


def test_stub_concrete_code_and_function_locals_remain_analyzed(tmp_path):
    result = _scan(
        tmp_path,
        {
            "contracts.pyi": """
                _concrete = 7
                _computed: int = int("7")
                def _implementation(unused):
                    _local: object
                    _placeholder = ...
                    return 1
                class _Implementation:
                    _concrete_field = 7
            """,
        },
    )

    assert {
        "contracts._concrete",
        "contracts._computed",
        "contracts._implementation._local",
        "contracts._implementation._placeholder",
    } <= _names(result, "unused_variables")
    assert "contracts._implementation" in _names(result, "unused_functions")
    assert "contracts._implementation.unused" in _names(result, "unused_parameters")
    assert "contracts._Implementation" in _names(result, "unused_classes")


@pytest.mark.parametrize("body", ["_local: int", "_local = ..."])
def test_single_local_binding_is_not_a_stub_function_body(tmp_path, body):
    result = _scan(
        tmp_path,
        {"contracts.pyi": "def _implementation(unused):\n    " + body + "\n"},
    )

    assert "contracts._implementation" in _names(result, "unused_functions")
    assert "contracts._implementation._local" in _names(result, "unused_variables")
    assert "contracts._implementation.unused" in _names(result, "unused_parameters")


def test_stub_conditional_class_declarations_are_not_unused(tmp_path):
    result = _scan(
        tmp_path,
        {
            "contracts.pyi": """
                import sys
                class _Versioned:
                    if sys.version_info >= (3, 11):
                        _field: int
                        def _read(self) -> int: ...
                    else:
                        _field: str
                        def _read(self) -> str: ...
            """,
        },
    )

    assert result.get("unused_variables", []) == []
    assert result.get("unused_functions", []) == []
    assert result.get("unused_classes", []) == []
    assert "sys" not in _names(result, "unused_imports")


@pytest.mark.parametrize(
    ("condition", "body"),
    [("predicate()", "_field: int"), ("True", "_field = int('7')")],
)
def test_stub_class_with_concrete_conditional_code_stays_reportable(
    tmp_path, condition, body
):
    result = _scan(
        tmp_path,
        {"contracts.pyi": f"class _Concrete:\n    if {condition}:\n        {body}\n"},
    )

    assert "contracts._Concrete" in _names(result, "unused_classes")


def test_stub_unused_imports_remain_visible_and_annotation_imports_stay_used(tmp_path):
    result = _scan(
        tmp_path,
        {
            "contracts.pyi": """
                import math
                from decimal import Decimal
                _amount: Decimal
            """,
        },
    )

    assert "math" in _names(result, "unused_imports")
    assert "decimal.Decimal" not in _names(result, "unused_imports")
    assert result.get("unused_variables", []) == []


@pytest.mark.parametrize(
    "binding",
    ["decorate = ...", "decorate: object", "def decorate(): ...", "class decorate: ..."],
)
def test_stub_binding_still_shadows_an_imported_decorator(tmp_path, binding):
    result = _scan(
        tmp_path,
        {
            "contracts.pyi": (
                "from numba.extending import overload as decorate\n"
                + binding
                + "\n@decorate(float)\ndef _implementation(unused): return 1\n"
            ),
        },
    )

    assert "contracts._implementation" in _names(result, "unused_functions")


@pytest.mark.parametrize("stub_first", [True, False])
def test_stub_sibling_cannot_replace_runtime_candidates(
    tmp_path, monkeypatch, stub_first
):
    _sources(
        tmp_path,
        {
            "api.py": "_value = 7\ndef _function(): return 1\nclass _Class: pass\n",
            "api.pyi": "_value: int\ndef _function() -> int: ...\nclass _Class: ...\n",
        },
    )
    paths = [tmp_path / "api.pyi", tmp_path / "api.py"]
    if not stub_first:
        paths.reverse()
    monkeypatch.setattr(
        Skylos, "_discover_files", lambda self, path, excludes: (paths, tmp_path)
    )

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))

    assert result.get("analysis_errors", []) == []
    for bucket, name, line in (
        ("unused_variables", "api._value", 1),
        ("unused_functions", "api._function", 2),
        ("unused_classes", "api._Class", 3),
    ):
        findings = [
            item for item in result.get(bucket, []) if item["full_name"] == name
        ]
        assert [(item["file"], item["line"]) for item in findings] == [
            (str(tmp_path / "api.py"), line)
        ]


@pytest.mark.parametrize("declaration_first", [True, False])
def test_stub_declarations_do_not_hide_same_name_concrete_bindings(
    tmp_path, declaration_first
):
    declaration = "_value: int\ndef _function() -> int: ...\nclass _Class: ...\n"
    concrete = "_value = 7\ndef _function(): return 1\nclass _Class:\n    _field = 7\n"
    source = declaration + concrete if declaration_first else concrete + declaration
    result = _scan(tmp_path, {"contracts.pyi": source})

    assert "contracts._value" in _names(result, "unused_variables")
    assert "contracts._function" in _names(result, "unused_functions")
    assert "contracts._Class" in _names(result, "unused_classes")
