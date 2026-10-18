import ast
import textwrap

import pytest

from skylos.rules.quality.logic_maintainability import DuplicateStringLiteralRule


def _findings(source):
    tree = ast.parse(textwrap.dedent(source))
    return DuplicateStringLiteralRule().visit_node(tree, {"filename": "app.py"}) or []


@pytest.mark.parametrize("module", ["typing", "typing_extensions"])
@pytest.mark.parametrize("import_style", ["member", "aliased_member", "module"])
def test_import_proven_cast_forward_references_are_type_context(module, import_style):
    imported, call = {
        "member": (f"from {module} import cast", "cast"),
        "aliased_member": (f"from {module} import cast as narrow", "narrow"),
        "module": (f"import {module} as types", "types.cast"),
    }[import_style]
    source = (
        imported
        + "\n"
        + "\n".join(
            f'def value_{i}(value):\n    return {call}("WidgetResult", value)'
            for i in range(3)
        )
    )
    assert _findings(source) == []


@pytest.mark.parametrize(
    "declaration", ["TypeVar", "ParamSpec", "TypeVarTuple", "NewType"]
)
def test_matching_typing_declaration_names_in_conditional_branches(declaration):
    assert (
        _findings(
            f"""
        import typing as t
        if t.TYPE_CHECKING:
            import typing_extensions as te
            WidgetResult = te.{declaration}("WidgetResult")
        elif newer:
            WidgetResult = t.{declaration}("WidgetResult")
        else:
            WidgetResult = t.{declaration}("WidgetResult")
        """
        )
        == []
    )


def test_only_type_argument_is_excluded_and_runtime_strings_keep_their_count():
    findings = _findings(
        """
        from typing import cast
        def read(value):
            cast("WidgetResult", value)
            cast("WidgetResult", value)
            cast("WidgetResult", value)
            consume("WidgetResult")
            consume("WidgetResult")
            consume("WidgetResult")
        """
    )
    assert [(row["name"], row["value"]) for row in findings] == [("WidgetResult", 3)]


def test_cast_runtime_value_string_is_still_counted():
    findings = _findings(
        """
        from typing import cast
        def read():
            cast(str, "WidgetResult")
            cast(str, "WidgetResult")
            cast(str, "WidgetResult")
        """
    )
    assert [(row["name"], row["value"]) for row in findings] == [("WidgetResult", 3)]


@pytest.mark.parametrize(
    "prefix",
    [
        "def cast(type_name, value): return value",
        "from custom_types import cast",
        "from .typing import cast",
        "from typing import cast\ncast = custom_cast",
        "from typing import cast\ndef cast(type_name, value): return value",
        "from typing import cast\nfrom somewhere import *",
        "from typing import cast\nexec(source)",
        "from typing import cast\n[(cast := custom_cast) for item in values]",
        "import custom_types as typing\ncast = typing.cast",
    ],
)
def test_cast_lookalikes_or_rebinding_do_not_suppress_runtime_strings(prefix):
    source = (
        prefix
        + "\ndef read(value):\n"
        + "\n".join('    cast("WidgetResult", value)' for _ in range(3))
    )
    assert [(row["name"], row["value"]) for row in _findings(source)] == [
        ("WidgetResult", 3)
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "types.cast = custom_cast",
        "del types.cast",
        'setattr(types, "cast", custom_cast)',
        'types.__dict__["cast"] = custom_cast',
        'types.__dict__.update({"cast": custom_cast})',
        'namespace = types.__dict__\nnamespace["cast"] = custom_cast',
        "other = types\nother.cast = custom_cast",
        "patch_module(types)",
    ],
)
def test_typing_module_mutation_or_escape_refutes_import_identity(mutation):
    source = (
        "import typing as types\n"
        + mutation
        + "\ndef read(value):\n"
        + "\n".join('    types.cast("WidgetResult", value)' for _ in range(3))
    )
    assert [(row["name"], row["value"]) for row in _findings(source)] == [
        ("WidgetResult", 3)
    ]


@pytest.mark.parametrize("binding", ["parameter", "local_assignment", "nested_import"])
def test_closer_bindings_shadow_imported_cast(binding):
    header, statements = {
        "parameter": ("def read(cast, value):", []),
        "local_assignment": ("def read(value):", ["cast = custom_cast"]),
        "nested_import": ("def read(value):", ["from custom_types import cast"]),
    }[binding]
    body = statements + ['cast("WidgetResult", value)'] * 3
    source = (
        "from typing import cast\n"
        + header
        + "\n"
        + "\n".join("    " + line for line in body)
    )
    assert [(row["name"], row["value"]) for row in _findings(source)] == [
        ("WidgetResult", 3)
    ]


def test_local_typing_import_can_prove_identity_without_affecting_other_scope():
    assert (
        _findings(
            """
        cast = custom_cast
        def read(value):
            from typing import cast
            cast("WidgetResult", value)
            cast("WidgetResult", value)
            cast("WidgetResult", value)
        """
        )
        == []
    )


@pytest.mark.parametrize(
    "prefix, call",
    [
        ("from custom_types import TypeVar", "TypeVar"),
        ("from typing import TypeVar\nTypeVar = custom_factory", "TypeVar"),
        ("import typing as t\nt.TypeVar = custom_factory", "t.TypeVar"),
    ],
)
def test_typing_declaration_lookalikes_are_still_counted(prefix, call):
    source = (
        prefix
        + "\n"
        + "\n".join(
            f'if condition_{i}:\n    WidgetResult = {call}("WidgetResult")'
            for i in range(3)
        )
    )
    assert [(row["name"], row["value"]) for row in _findings(source)] == [
        ("WidgetResult", 3)
    ]


def test_nonmatching_typevar_argument_and_non_declaration_calls_are_not_excluded():
    findings = _findings(
        """
        from typing import TypeVar
        if first:
            Other = TypeVar("WidgetResult")
        elif second:
            Other = TypeVar("WidgetResult")
        else:
            consume(TypeVar("WidgetResult"))
        """
    )
    assert [(row["name"], row["value"]) for row in findings] == [("WidgetResult", 3)]
