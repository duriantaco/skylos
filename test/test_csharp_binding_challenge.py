from __future__ import annotations

import json
from pathlib import Path

from skylos.analyzer import Skylos, analyze
from skylos.visitors.languages.csharp.core import CSharpDefinition


def _definition(name: str, kind: str) -> CSharpDefinition:
    definition = CSharpDefinition(name, kind, "Types.cs", 1)
    if kind == "method":
        definition.csharp_arity = 0
    return definition


def _engine(contexts) -> tuple[Skylos, CSharpDefinition, CSharpDefinition]:
    owner = _definition("Demo.Helper", "class")
    method = _definition("Demo.Helper.Ping", "method")
    engine = Skylos()
    engine.defs = {"owner": owner, "method": method}
    engine._csharp_reference_context_by_file = {"Caller.cs": contexts}
    return engine, owner, method


def test_shadowed_external_occurrence_does_not_activate_an_internal_owner():
    reference = "Demo.Helper.Ping#0"
    engine, owner, method = _engine(
        {
            reference: [
                {
                    "spelling": "Ping",
                    "owner": "Demo.Helper",
                    "receiver_shadowed": False,
                },
                {
                    "spelling": "Helper.Ping",
                    "owner": "App.Entry",
                    "receiver_shadowed": True,
                },
            ]
        }
    )
    engine.refs = [(reference, "Caller.cs")]
    engine._mark_refs()
    assert method.references > 0
    assert owner.references == 0


def test_unknown_instance_field_receiver_does_not_rescue_unrelated_classes(
    tmp_path: Path,
):
    path = tmp_path / "Types.cs"
    path.write_text(
        "namespace One { internal static class First { private static void Hidden() {} } } "
        "namespace Two { internal static class Second { private static void Hidden() {} } } "
        "public class Remote { public void Hidden() {} } "
        "public class Entry { private readonly Remote remote = new(); public void Run() { remote.Hidden(); } }",
        encoding="utf-8",
    )
    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    unused = {item["full_name"] for item in result.get("unused_classes", [])}
    assert {"One.First", "Two.Second"} <= unused


def test_malformed_binding_context_is_not_a_proof_or_a_crash():
    reference = "@member:Demo.Helper.Ping"
    engine, owner, method = _engine({reference: [None, "bad context", 7]})
    engine.refs = [(reference, "Caller.cs")]
    engine._mark_refs()
    assert owner.references == method.references == 0


def test_new_marker_without_context_cannot_create_external_owner_evidence():
    reference = "@member:Demo.Helper.Ping"
    engine, owner, method = _engine({})
    engine.refs = [(reference, "Caller.cs")]
    engine._mark_refs()
    assert owner.references == method.references == 0
