"""Overload advice stays complete while one callable gets one warning."""

import ast
import textwrap

import pytest

from skylos.rules.quality._overload_groups import (
    overload_groups,
    redundant_overload_definitions,
)
from skylos.rules.quality.structure import ArgCountRule
from skylos.rules.quality.class_size import GodFileRule


def _findings(code, filename="package/api.py", **thresholds):
    tree = ast.parse(textwrap.dedent(code))
    rule = ArgCountRule(**thresholds)
    context = {"filename": filename, "source": textwrap.dedent(code)}
    return [
        finding
        for node in ast.walk(tree)
        for finding in rule.visit_node(node, context) or []
    ]


def _signatures(decorator="overload", *, implementation=True, body="return values"):
    source = (
        f"@{decorator}\ndef parse(a, b, c, d, e, f): ...\n"
        f"@{decorator}\ndef parse(a, b, c, d, e, f, g): ...\n"
    )
    if implementation:
        source += f"def parse(*values):\n    {body}\n"
    return source


@pytest.mark.parametrize(
    "imports,decorator",
    [
        ("from typing import overload", "overload"),
        ("from typing import overload as signature", "signature"),
        ("from typing_extensions import overload as signature", "signature"),
        ("import typing as t", "t.overload"),
        ("import typing_extensions as t", "t.overload"),
    ],
)
def test_import_proven_overloads_report_widest_signature_at_implementation(
    imports, decorator
):
    code = imports + "\n" + _signatures(decorator)
    findings = _findings(code)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["value"] == 7
    assert finding["line"] == 6
    assert "overload signature with 7 required positional" in finding["message"]
    assert [
        (item["line"], item["required_positional"], item["kind"])
        for item in finding["overload_signatures"]
    ] == [
        (3, 6, "overload"),
        (5, 7, "overload"),
        (6, 0, "implementation"),
    ]
    assert finding["overload_signatures"][-1]["variadic_positional"] == "values"


def test_distinct_wide_shapes_remain_attached_when_required_violation_takes_priority():
    code = """
        from typing import overload
        @overload
        def parse(a, b, c, d, e, f): ...
        @overload
        def parse(a, *, b, c, d, e, f, g, h, i, j, k): ...
        def parse(*args, **kwargs):
            return args
    """
    (finding,) = _findings(code)
    assert finding["value"] == 6
    evidence = finding["overload_signatures"]
    assert [item["total_parameters"] for item in evidence] == [6, 11, 0]
    assert evidence[1]["required_keyword_only"] == list("bcdefghijk")
    assert evidence[1]["keyword_only_parameters"] == list("bcdefghijk")
    assert evidence[-1]["variadic_keyword"] == "kwargs"


def test_runtime_implementation_wider_than_overloads_still_reports_its_arity():
    code = """
        from typing import overload
        @overload
        def parse(a: int): ...
        @overload
        def parse(a: str): ...
        def parse(a, b, c, d, e, f, g):
            return a
    """
    (finding,) = _findings(code)
    assert finding["value"] == 7
    assert "Function has 7 required positional" in finding["message"]
    assert len(finding["overload_signatures"]) == 3


def test_stub_groups_collapse_but_do_not_hide_wide_signatures():
    code = "from typing import overload\n" + _signatures(implementation=False)
    (finding,) = _findings(code, "package/api.pyi")
    assert finding["line"] == 3
    assert finding["value"] == 7
    assert len(finding["overload_signatures"]) == 2
    tree = ast.parse(code)
    assert len(redundant_overload_definitions(tree, filename="package/api.pyi")) == 1
    assert redundant_overload_definitions(tree, filename="package/api.py") == set()
    assert len(_findings(code, "package/api.py")) == 2


def test_narrow_stub_overloads_do_not_invent_arity_warning():
    code = """
        from typing import overload
        @overload
        def parse(value: int): ...
        @overload
        def parse(value: str, *, encoding: str = ...): ...
    """
    assert _findings(code, "package/api.pyi") == []


@pytest.mark.parametrize("body", ["pass", "..."])
def test_empty_runtime_implementation_does_not_prove_a_real_callable(body):
    code = "from typing import overload\n" + _signatures(body=body)
    assert len(_findings(code)) == 2
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


@pytest.mark.parametrize(
    "prefix,decorator",
    [
        ("def overload(fn):\n    return fn\n", "overload"),
        ("from typing import overload\noverload = custom\n", "overload"),
        ("from typing import overload\ndel overload\n", "overload"),
        ("from somewhere import overload\n", "overload"),
        ("import typing as t\nt = custom\n", "t.overload"),
        ("import typing as t\nt.overload = custom\n", "t.overload"),
        ("import typing as t\nsetattr(t, 'overload', custom)\n", "t.overload"),
        ("import typing as t\nvars(t)['overload'] = custom\n", "t.overload"),
        ("import typing as t\nother = t\nother.overload = custom\n", "t.overload"),
        ("import typing as t\nt.__dict__['overload'] = custom\n", "t.overload"),
        ("from typing import overload\nglobals()['overload'] = custom\n", "overload"),
        (
            "from typing import overload\ndef patch():\n    global overload\n    overload = custom\n",
            "overload",
        ),
    ],
)
def test_custom_rebound_and_monkeypatched_overloads_keep_all_warnings(
    prefix, decorator
):
    code = prefix + _signatures(decorator)
    assert len(_findings(code)) == 2
    assert (
        redundant_overload_definitions(ast.parse(code), filename="package/api.pyi")
        == set()
    )


@pytest.mark.parametrize(
    "prefix,decorator",
    [
        ("import typing as t\npatch_typing(t)\n", "t.overload"),
        ("import typing_extensions as t\npatch_typing(types=t)\n", "t.overload"),
        ("import typing as t\nother = t\npatch_typing(other)\n", "t.overload"),
        ("import typing as t\npatch_typing([t])\n", "t.overload"),
        ("import typing as t\nnamespace.typing = t\n", "t.overload"),
        ("import typing as t\nregistry = {'types': t}\n", "t.overload"),
        (
            "import typing as t\ndef export_types():\n    return t\n",
            "t.overload",
        ),
        ("from typing import overload\npatch_decorator(overload)\n", "overload"),
        (
            "from typing import overload as signature\n"
            "patch_decorator(decorator=signature)\n",
            "signature",
        ),
        ("import typing as t\npatch_decorator(t.overload)\n", "t.overload"),
        ("from typing import overload\nvars()['overload'] = custom\n", "overload"),
    ],
)
def test_escaping_typing_module_or_decorator_does_not_prove_its_identity(
    prefix, decorator
):
    code = prefix + _signatures(decorator)
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()
    assert len(_findings(code)) == 2
    assert (
        redundant_overload_definitions(ast.parse(code), filename="package/api.pyi")
        == set()
    )


def _bound_method_signatures(decorator):
    return (
        f"@overload\n@{decorator}\ndef parse(a,b,c,d,e,f,g,h): ...\n"
        f"@overload\n@{decorator}\ndef parse(a,b,c,d,e,f,g,h,i): ...\n"
        f"@{decorator}\ndef parse(*values):\n    return values\n"
    )


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
@pytest.mark.parametrize("scope", ["module", "outer_function", "parameter"])
def test_shadowed_binding_decorators_in_outer_scopes_are_not_treated_as_builtins(
    decorator, scope
):
    code = "from typing import overload\n"
    class_body = "class Parser:\n" + textwrap.indent(
        _bound_method_signatures(decorator), "    "
    )
    if scope == "module":
        code += f"{decorator} = custom_decorator\n" + class_body
    elif scope == "outer_function":
        code += "def factory():\n" + textwrap.indent(
            f"{decorator} = custom_decorator\n" + class_body, "    "
        )
    else:
        code += f"def factory({decorator}):\n" + textwrap.indent(class_body, "    ")
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()
    assert len(_findings(code)) == 2


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
@pytest.mark.parametrize(
    "mutation",
    [
        "b.{decorator} = custom_decorator",
        "other = b\nother.{decorator} = custom_decorator",
        "patch_builtins(b)",
    ],
)
def test_mutated_builtin_namespace_does_not_prove_binding_decorators(
    decorator, mutation
):
    code = (
        "from typing import overload\nimport builtins as b\n"
        + mutation.format(decorator=decorator)
        + "\nclass Parser:\n"
        + textwrap.indent(_bound_method_signatures(decorator), "    ")
    )
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()
    assert len(_findings(code)) == 2


@pytest.mark.parametrize("decorator", ["staticmethod", "classmethod"])
def test_unchanged_builtin_binding_decorators_still_form_one_callable(decorator):
    code = "from typing import overload\nclass Parser:\n" + textwrap.indent(
        _bound_method_signatures(decorator), "    "
    )
    assert len(overload_groups(ast.parse(code), filename="package/api.py")) == 1
    (finding,) = _findings(code)
    # Existing receiver analysis treats an additional overload decorator as
    # ambiguous. Grouping preserves its full range instead of guessing binding.
    assert finding["value"] == 8
    assert finding["required_argument_range"] == [8, 9]
    assert finding["overload_signatures"][1]["required_argument_range"] == [8, 9]
    assert len(finding["overload_signatures"]) == 3


def test_class_local_decorator_shadowing_keeps_signatures_separate():
    code = "from typing import overload\nclass Parser:\n    overload = custom\n"
    code += textwrap.indent(_signatures(), "    ")
    assert len(_findings(code)) == 1  # Six explicit parameters minus the receiver.
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


def test_function_parameter_shadowing_keeps_signatures_separate():
    code = "from typing import overload\ndef factory(overload):\n"
    code += textwrap.indent(_signatures(), "    ")
    assert len(_findings(code)) == 2
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


def test_wildcard_imports_do_not_prove_an_unchanged_typing_alias():
    code = "from typing import overload\nfrom custom import *\n" + _signatures()
    assert len(_findings(code)) == 2
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


def test_class_local_import_does_not_become_a_method_closure():
    code = "class Parser:\n    from typing import overload\n    def build(self):\n"
    code += textwrap.indent(_signatures(), "        ")
    assert len(_findings(code)) == 2
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


def test_function_local_overload_import_is_proven_without_merging_distinct_scopes():
    inner = "from typing import overload\n" + _signatures()
    code = "def first_factory():\n" + textwrap.indent(inner, "    ")
    code += "def second_factory():\n" + textwrap.indent(inner, "    ")
    assert len(_findings(code)) == 2
    assert len(overload_groups(ast.parse(code), filename="package/api.py")) == 2


@pytest.mark.parametrize("separator", ["flag = True\n", "def other(): return None\n"])
def test_nonconsecutive_declarations_are_not_grouped(separator):
    code = "from typing import overload\n" + _signatures(implementation=False)
    code += separator + "def parse(*values):\n    return values\n"
    assert len(_findings(code)) == 2
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


def test_overload_with_executable_body_is_not_silently_folded_into_group():
    code = "from typing import overload\n" + _signatures(implementation=False)
    code += "@overload\ndef parse(a, b, c, d, e, f, g, h):\n    return a\n"
    assert len(_findings(code)) == 3
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


def test_unknown_additional_decorators_keep_independent_reports():
    code = "from typing import overload\n" + _signatures().replace(
        "@overload", "@custom\n@overload"
    )
    assert len(_findings(code)) == 2
    assert overload_groups(ast.parse(code), filename="package/api.py") == ()


def test_import_after_declarations_does_not_prove_the_decorator():
    code = _signatures() + "from typing import overload\n"
    assert len(_findings(code)) == 2


def test_async_overloads_are_one_callable_and_keep_all_shapes():
    code = "from typing import overload\n" + _signatures().replace(
        "def parse", "async def parse"
    )
    (finding,) = _findings(code)
    assert finding["value"] == 7
    assert len(finding["overload_signatures"]) == 3


def test_unrelated_wide_function_remains_unchanged():
    (finding,) = _findings("def wide(a, b, c, d, e, f): return a\n")
    assert finding["value"] == 6
    assert "overload_signatures" not in finding


def test_module_surface_preserves_distinct_names_and_runtime_implementations():
    code = "from typing import overload\n" + _signatures()
    code += "class Parser:\n" + textwrap.indent(_signatures(), "    ")
    code += "def another(a, b, c, d, e, f): return a\n"
    tree = ast.parse(code)
    redundant = redundant_overload_definitions(tree, filename="package/api.py")
    assert len(redundant) == 4
    assert (
        len(
            [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node not in redundant
            ]
        )
        == 3
    )


def test_stub_filename_alone_never_deduplicates_plain_or_custom_functions():
    plain = "def parse(a, b, c, d, e, f): ...\n" * 2
    assert len(_findings(plain, "package/api.pyi")) == 2
    assert (
        redundant_overload_definitions(ast.parse(plain), filename="package/api.pyi")
        == set()
    )


def _file_findings(code, filename="package/api.pyi", **thresholds):
    tree = ast.parse(code)
    return (
        GodFileRule(**thresholds).visit_node(
            tree, {"filename": filename, "source": code}
        )
        or []
    )


def _stub_surface(*, imported=True):
    code = (
        "from typing import overload\n" if imported else "def overload(fn): return fn\n"
    )
    # Thirty-one declarations implement twenty callable names, like attrs'
    # validators.pyi. The custom decorator adds one real callable of its own.
    for index in range(20):
        if index < 11:
            code += f"@overload\ndef validate_{index}(value: int): ...\n"
            code += f"@overload\ndef validate_{index}(value: str): ...\n"
        else:
            code += f"def validate_{index}(value): ...\n"
    return code


def test_god_file_counts_stub_callable_surface_and_preserves_exact_counts():
    code = _stub_surface()
    assert _file_findings(code) == []
    (finding,) = _file_findings(code, max_top_level_definitions=19)
    assert finding["top_level_definitions"] == 20
    assert finding["function_count"] == 20
    assert finding["total_definitions"] == 20
    assert finding["class_count"] == 0


def test_god_file_keeps_custom_decorator_declarations_and_distinct_functions():
    (custom,) = _file_findings(_stub_surface(imported=False))
    assert custom["top_level_definitions"] == 32
    assert custom["function_count"] == 32
    distinct = "".join(f"def validate_{index}(value): ...\n" for index in range(31))
    (finding,) = _file_findings(distinct)
    assert finding["top_level_definitions"] == 31
    assert finding["total_definitions"] == 31


def test_god_file_does_not_subtract_function_local_overloads_from_module_counts():
    code = "from typing import overload\n"
    code += "".join(f"def validate_{index}(value): ...\n" for index in range(20))
    code += "def factory():\n" + textwrap.indent(_signatures(), "    ")
    assert _file_findings(code) == []
    (finding,) = _file_findings(code, max_top_level_definitions=20)
    assert finding["top_level_definitions"] == 21
    assert finding["function_count"] == 21
    assert finding["total_definitions"] == 21


def test_god_file_runtime_groups_count_the_implementation_and_class_once():
    code = "from typing import overload\n" + _signatures()
    code += "class Parser:\n" + textwrap.indent(_signatures(), "    ")
    (finding,) = _file_findings(code, "package/api.py", max_definitions=2)
    assert finding["class_count"] == 1
    assert finding["function_count"] == 2
    assert finding["total_definitions"] == 3
    assert finding["top_level_definitions"] == 2


def test_god_file_keeps_definition_metric_for_unimplemented_runtime_overloads():
    code = "from typing import overload\n" + _signatures(implementation=False)
    (finding,) = _file_findings(code, "package/api.py", max_definitions=1)
    assert finding["function_count"] == 2
    assert finding["total_definitions"] == 2


def test_god_file_keeps_code_lines_of_collapsed_overload_declarations():
    code = (
        "from typing import overload\n" + "@overload\ndef validate(value): ...\n" * 30
    )
    (finding,) = _file_findings(code, max_lines=50)
    assert finding["metric"] == "code_lines"
    assert finding["code_lines"] == 61
    assert finding["function_count"] == 1
    assert finding["total_definitions"] == 1
