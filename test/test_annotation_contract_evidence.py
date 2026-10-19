"""Source proofs for optional typing advice, never target-code execution."""

import ast
import textwrap

import pytest

from skylos.rules.quality._annotation_contract import annotation_contract_evidence


def evidence(source, *, exports=None, **context):
    source = textwrap.dedent(source)
    tree = ast.parse(source, type_comments=True)
    result = annotation_contract_evidence(
        tree,
        source_lines=source.splitlines(keepends=True),
        exported_names=exports,
        **context,
    )
    named = {
        id(function): function.name
        for function in ast.walk(tree)
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return tree, result, named


def names(ids, named):
    return [named[identity] for identity in ids]


def test_public_spelling_alone_is_not_an_api_contract():
    _, result, _ = evidence("def public(value: int): return value")
    assert not result.boundary_ids
    assert not result.supplied_ids


def test_static_export_is_boundary_but_not_a_supplied_annotation():
    _, result, named = evidence(
        "def exported(value): return value\ndef helper(value): return value",
        exports={"exported"},
    )
    assert names(result.boundary_ids, named) == ["exported"]
    assert not result.supplied_ids


def test_exported_class_methods_require_known_binding():
    _, result, named = evidence(
        """
        class Public:
            def instance(self, value): return value
            @staticmethod
            def static(value): return value
            @classmethod
            def class_method(cls, value): return value
            @property
            def property_method(self): return 1
            @unknown
            def wrapped(self, value): return value
            def _private(self, value): return value
        class Internal:
            def internal(self, value): return value
        """,
        exports={"Public"},
    )
    assert set(names(result.boundary_ids, named)) == {
        "instance", "static", "class_method", "property_method"
    }


@pytest.mark.parametrize("mutation", ["exported = replacement", "del exported"])
def test_rebound_exports_do_not_establish_a_boundary(mutation):
    _, result, _ = evidence(
        f"def exported(value): return value\n{mutation}", exports={"exported"}
    )
    assert not result.boundary_ids


def test_redefined_export_is_ambiguous():
    _, result, _ = evidence(
        "def exported(value): return value\ndef exported(other): return other",
        exports={"exported"},
    )
    assert not result.boundary_ids


def test_rebound_exported_class_method_is_ambiguous():
    _, result, _ = evidence(
        """
        class Surface:
            def exported(self, value): return value
            exported = replacement
        """,
        exports={"Surface"},
    )
    assert not result.boundary_ids


@pytest.mark.parametrize(
    "mutation",
    [
        "Surface.convert = replacement",
        "setattr(Surface, 'convert', replacement)",
        "alias = Surface\nalias.convert = replacement",
    ],
)
def test_monkeypatched_exported_owner_does_not_establish_boundary(mutation):
    _, result, _ = evidence(
        "class Surface:\n def convert(self, value): return value\n" + mutation,
        exports={"Surface"},
    )
    assert not result.boundary_ids


def test_unknown_decorator_does_not_establish_optional_coverage_boundary():
    _, result, _ = evidence(
        "@unknown\ndef exported(value): return value", exports={"exported"}
    )
    assert not result.boundary_ids


@pytest.mark.parametrize("provider", ["typing", "typing_extensions"])
def test_import_proven_protocol_is_a_declared_interface(provider):
    _, result, named = evidence(
        f"""
        from {provider} import Protocol as Interface
        class Surface(Interface):
            def required(self, value): ...
        class Ordinary:
            def helper(self, value): ...
        """
    )
    assert names(result.boundary_ids, named) == ["required"]


def test_protocol_name_without_provider_proof_is_not_a_boundary():
    _, result, _ = evidence(
        "class Surface(Protocol):\n def required(self, value): ..."
    )
    assert not result.boundary_ids


@pytest.mark.parametrize(
    ("imports", "bases", "method_decorator", "exports"),
    [
        ("", "", "", {"Surface"}),
        ("from typing import Protocol", "(Protocol)", "", None),
        ("from abc import abstractmethod", "", "@abstractmethod", None),
    ],
)
def test_unknown_class_decorator_invalidates_boundary_evidence(
    imports, bases, method_decorator, exports
):
    for class_decorator in ("", "@unknown"):
        _, result, named = evidence(
            f"""
            {imports}
            {class_decorator}
            class Surface{bases}:
                {method_decorator}
                def required(self, value): ...
            """,
            exports=exports,
        )
        assert bool(result.boundary_ids) is (not class_decorator)
        if result.boundary_ids:
            assert names(result.boundary_ids, named) == ["required"]


def test_module_alias_protocol_and_import_proven_abstract_method():
    _, result, named = evidence(
        """
        import typing as t
        import abc as a
        class Surface(t.Protocol[int]):
            def required(self, value): ...
        class Base:
            @a.abstractmethod
            def abstract(self, value): ...
            def ordinary(self, value): ...
        """
    )
    assert set(names(result.boundary_ids, named)) == {"required", "abstract"}


@pytest.mark.parametrize("mutation", ["Protocol = Local", "typing.Protocol = Local"])
def test_rebound_protocol_provider_does_not_establish_interface(mutation):
    _, result, _ = evidence(
        f"""
        import typing
        from typing import Protocol
        {mutation}
        class Surface(Protocol):
            def required(self, value): ...
        """
    )
    assert not result.boundary_ids


def test_complete_overloads_supply_optional_implementation_contract():
    tree, result, _ = evidence(
        """
        from typing import overload as variant
        @variant
        def transform(value: int) -> int: ...
        @variant
        def transform(value: str) -> str: ...
        def transform(value): return value
        """,
        exports={"transform"},
    )
    functions = {id(node) for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert result.supplied_ids == functions
    assert result.boundary_ids == functions


@pytest.mark.parametrize(
    "replacement",
    [
        "def transform(value) -> str: ...",
        "def transform(value: str): ...",
    ],
)
def test_incomplete_overload_does_not_supply_contract(replacement):
    _, result, _ = evidence(
        f"""
        from typing import overload
        @overload
        def transform(value: int) -> int: ...
        @overload
        {replacement}
        def transform(value): return value
        """
    )
    assert not result.supplied_ids


@pytest.mark.parametrize(
    "provider",
    ["from custom import overload", "def overload(function): return function"],
)
def test_unknown_overload_provider_does_not_supply_contract(provider):
    _, result, _ = evidence(
        f"""
        {provider}
        @overload
        def transform(value: int) -> int: ...
        @overload
        def transform(value: str) -> str: ...
        def transform(value): return value
        """
    )
    assert not result.supplied_ids


def test_overload_requires_two_signatures_and_runtime_implementation():
    for source in (
        """
        from typing import overload
        @overload
        def transform(value: int) -> int: ...
        def transform(value): return value
        """,
        """
        from typing import overload
        @overload
        def transform(value: int) -> int: ...
        @overload
        def transform(value: str) -> str: ...
        """,
    ):
        _, result, _ = evidence(source)
        assert not result.supplied_ids


@pytest.mark.parametrize("binding", ["", "@classmethod", "@staticmethod"])
def test_overload_method_receivers_follow_proven_binding(binding):
    prefix = "" if binding == "@staticmethod" else "receiver, "
    _, result, named = evidence(
        f"""
        from typing import overload
        class Surface:
            @overload
            {binding}
            def transform({prefix}value: int) -> int: ...
            @overload
            {binding}
            def transform({prefix}value: str) -> str: ...
            {binding}
            def transform({prefix}value): return value
        """
    )
    assert len(result.supplied_ids) == 3
    assert names(result.supplied_ids, named) == ["transform"] * 3


def test_overload_binding_mismatch_does_not_supply_contract():
    _, result, _ = evidence(
        """
        from typing import overload
        class Surface:
            @overload
            @classmethod
            def transform(cls, value: int) -> int: ...
            @overload
            @classmethod
            def transform(cls, value: str) -> str: ...
            def transform(self, value): return value
        """
    )
    assert not result.supplied_ids


def test_overload_receiver_names_can_differ():
    _, result, _ = evidence(
        """
        from typing import overload
        class Surface:
            @overload
            def transform(receiver, value: int) -> int: ...
            @overload
            def transform(other, value: str) -> str: ...
            def transform(self, value): return value
        """
    )
    assert len(result.supplied_ids) == 3


def test_unknown_class_decorator_invalidates_overload_contract():
    _, result, _ = evidence(
        """
        from typing import overload
        @unknown
        class Surface:
            @overload
            def transform(self, value: int) -> int: ...
            @overload
            def transform(self, value: str) -> str: ...
            def transform(self, value): return value
        """
    )
    assert not result.supplied_ids


def test_monkeypatched_owner_does_not_supply_overload_contract():
    _, result, _ = evidence(
        """
        from typing import overload
        class Surface:
            @overload
            def transform(self, value: int) -> int: ...
            @overload
            def transform(self, value: str) -> str: ...
            def transform(self, value): return value
        Surface.transform = replacement
        """
    )
    assert not result.supplied_ids


def test_overload_type_comments_supply_a_complete_contract():
    _, result, _ = evidence(
        """
        from typing import overload
        @overload
        def transform(value):  # type: (int) -> int
            ...
        @overload
        def transform(value):  # type: (str) -> str
            ...
        def transform(value): return value
        """
    )
    assert len(result.supplied_ids) == 3


def test_local_typing_provider_does_not_supply_contract(tmp_path):
    (tmp_path / "typing.py").write_text("class Protocol: pass\ndef overload(f): return f")
    _, result, _ = evidence(
        """
        from typing import Protocol, overload
        class Surface(Protocol):
            def required(self, value): ...
        @overload
        def transform(value: int) -> int: ...
        @overload
        def transform(value: str) -> str: ...
        def transform(value): return value
        """,
        project_root=tmp_path,
        filename=tmp_path / "module.py",
    )
    assert not result.boundary_ids
    assert not result.supplied_ids


def test_exact_sibling_stub_supplies_complete_contract(tmp_path):
    (tmp_path / "module.pyi").write_text("def transform(value: int) -> int: ...\n")
    _, result, named = evidence(
        "def transform(value): return value",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
    )
    assert names(result.supplied_ids, named) == ["transform"]


@pytest.mark.parametrize(
    "declaration",
    [
        "def transform(other: int) -> int: ...",
        "def transform(value: int, /) -> int: ...",
        "def transform(*, value: int) -> int: ...",
        "def transform(value: int = ...) -> int: ...",
        "def transform(value) -> int: ...",
        "def transform(value: int): ...",
        "async def transform(value: int) -> int: ...",
        "@unknown\ndef transform(value: int) -> int: ...",
    ],
)
def test_mismatched_incomplete_or_unknown_stub_stays_uncovered(tmp_path, declaration):
    (tmp_path / "module.pyi").write_text(declaration)
    _, result, _ = evidence(
        "def transform(value): return value",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
    )
    assert not result.supplied_ids


def test_stub_method_receiver_may_have_a_different_name(tmp_path):
    (tmp_path / "module.pyi").write_text(
        "class Surface:\n def transform(receiver, value: int) -> int: ...\n"
    )
    _, result, named = evidence(
        "class Surface:\n def transform(self, value): return value",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
    )
    assert names(result.supplied_ids, named) == ["transform"]


@pytest.mark.parametrize("decorated", ["runtime", "stub"])
def test_unknown_class_decorator_invalidates_stub_contract(tmp_path, decorated):
    stub_decorator = "@unknown\n" if decorated == "stub" else ""
    runtime_decorator = "@unknown\n" if decorated == "runtime" else ""
    (tmp_path / "module.pyi").write_text(
        f"{stub_decorator}class Surface:\n def transform(self, value: int) -> int: ...\n"
    )
    _, result, _ = evidence(
        f"{runtime_decorator}class Surface:\n def transform(self, value): return value",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
    )
    assert not result.supplied_ids


def test_monkeypatched_owner_does_not_supply_stub_contract(tmp_path):
    (tmp_path / "module.pyi").write_text(
        "class Surface:\n def transform(self, value: int) -> int: ...\n"
    )
    _, result, _ = evidence(
        """
        class Surface:
            def transform(self, value): return value
        setattr(Surface, 'transform', replacement)
        """,
        filename=tmp_path / "module.py",
        project_root=tmp_path,
    )
    assert not result.supplied_ids


def test_historical_reader_never_falls_back_to_checkout_stub(tmp_path):
    (tmp_path / "module.pyi").write_text("def transform(value: int) -> int: ...\n")
    seen = []

    def reader(relative):
        seen.append(relative)
        raise FileNotFoundError(relative)

    _, result, _ = evidence(
        "def transform(value): return value",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
        source_reader=reader,
    )
    assert not result.supplied_ids
    assert seen


def test_snapshot_stub_can_supply_contract_without_working_tree_file(tmp_path):
    def reader(relative):
        if relative.as_posix() == "module.pyi":
            return "def transform(value: int) -> int: ...\n"
        raise FileNotFoundError(relative)

    _, result, named = evidence(
        "def transform(value): return value",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
        source_reader=reader,
    )
    assert names(result.supplied_ids, named) == ["transform"]


def test_stub_symlink_is_not_a_contract(tmp_path):
    (tmp_path / "other.pyi").write_text("def transform(value: int) -> int: ...\n")
    (tmp_path / "module.pyi").symlink_to(tmp_path / "other.pyi")
    _, result, _ = evidence(
        "def transform(value): return value",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
    )
    assert not result.supplied_ids


@pytest.mark.parametrize("dynamic", ["from unknown import *", "exec(code)"])
def test_dynamic_namespace_does_not_supply_a_stub_contract(tmp_path, dynamic):
    (tmp_path / "module.pyi").write_text("def transform(value: int) -> int: ...\n")
    _, result, _ = evidence(
        f"def transform(value): return value\n{dynamic}",
        filename=tmp_path / "module.py",
        project_root=tmp_path,
    )
    assert not result.supplied_ids


def test_evidence_does_not_mutate_input_ast():
    tree = ast.parse("def exported(value): return value")
    original = ast.dump(tree, include_attributes=True)
    annotation_contract_evidence(tree, exported_names={"exported"})
    assert ast.dump(tree, include_attributes=True) == original
