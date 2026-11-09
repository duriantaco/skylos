from __future__ import annotations

from skylos.analyzer import Skylos
from skylos.visitors.languages.csharp.core import CSharpDefinition
import pytest


def _definition(name, kind, file="Types.cs"):
    definition = CSharpDefinition(name, kind, file, 1)
    if kind == "method":
        definition.csharp_arity = 1
    return definition


def _mark(definitions, ref, context):
    engine = Skylos()
    engine.defs = {str(i): definition for i, definition in enumerate(definitions)}
    engine.refs = [(ref, "Caller.cs")]
    engine._csharp_reference_context_by_file = {"Caller.cs": {ref: [context]}}
    engine._mark_refs()


def test_attribute_binds_imported_suffix_without_crediting_other_namespace():
    used = _definition("Library.TraceAttribute", "class")
    unused = _definition("Other.TraceAttribute", "class")
    _mark(
        [used, unused], "@attribute:Trace", {"namespace": "App", "usings": ["Library"]}
    )
    assert used.references == 1
    assert unused.references == 0


def test_attribute_alias_binds_exact_type():
    used = _definition("Library.TraceAttribute", "class")
    unused = _definition("Other.TraceAttribute", "class")
    _mark(
        [used, unused],
        "@attribute:Alias",
        {"namespace": "App", "aliases": {"Alias": "Library.TraceAttribute"}},
    )
    assert used.references == 1
    assert unused.references == 0


def test_ambiguous_attribute_import_is_not_evidence_for_either_type():
    first = _definition("One.TraceAttribute", "class")
    second = _definition("Two.TraceAttribute", "class")
    _mark(
        [first, second],
        "@attribute:Trace",
        {"namespace": "App", "usings": ["One", "Two"]},
    )
    assert first.references == second.references == 0


def test_method_group_binds_lexical_owner_without_same_named_rescue():
    used = _definition("Demo.Factory.Build", "method")
    unused = _definition("Demo.Dormant.Build", "method")
    _mark(
        [used, unused], "@member:Build", {"owner": "Demo.Factory", "namespace": "Demo"}
    )
    assert used.references == 1
    assert unused.references == 0


def test_ambiguous_unqualified_method_group_does_not_credit_all_methods():
    first = _definition("One.Factory.Build", "method")
    second = _definition("Two.Factory.Build", "method")
    _mark([first, second], "@member:Build", {"namespace": "App"})
    assert first.references == second.references == 0


def test_external_member_call_preserves_its_exact_owner():
    owner = _definition("Demo.Helper", "class")
    method = _definition("Demo.Helper.Format", "method")
    other = _definition("Other.Helper", "class")
    _mark(
        [owner, method, other],
        "Demo.Helper.Format#1",
        {"owner": "App.Entry", "namespace": "App"},
    )
    assert method.references == 1
    assert owner.references == 1
    assert other.references == 0


def test_same_owner_internal_call_does_not_create_external_class_use():
    owner = _definition("Demo.Helper", "class", file="Caller.cs")
    method = _definition("Demo.Helper.Format", "method", file="Caller.cs")
    _mark(
        [owner, method],
        "Demo.Helper.Format#1",
        {"owner": "Demo.Helper", "namespace": "Demo"},
    )
    assert method.references == 1
    assert owner.references == 0


@pytest.mark.parametrize(
    "invalid", [{"aliases": None}, {"usings": None}, {"static_usings": 7}]
)
def test_invalid_context_fields_do_not_create_reference_evidence(invalid):
    target = _definition("Demo.Owner.Build", "method")
    _mark([target], "@member:Demo.Owner.Build", invalid)
    assert target.references == 0


def test_type_reference_is_not_shadowed_by_same_named_value_member():
    target = _definition("Demo.AccessMode", "class")
    _mark(
        [target],
        "@type:Demo.AccessMode",
        {
            "spelling": "AccessMode",
            "owner": "Demo.Container",
            "namespace": "Demo",
            "receiver_shadowed": True,
            "receiver_type": "AccessMode",
        },
    )
    assert target.references == 1


def test_attribute_reference_is_not_shadowed_by_same_named_value_member():
    target = _definition("Demo.TraceAttribute", "class")
    _mark(
        [target],
        "@attribute:Trace",
        {
            "spelling": "Trace",
            "owner": "Demo.Container",
            "namespace": "Demo",
            "receiver_shadowed": True,
        },
    )
    assert target.references == 1
