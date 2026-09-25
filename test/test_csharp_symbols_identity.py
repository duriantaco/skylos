from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.csharp import scan_csharp_file


def _write(path: Path, source: str) -> None:
    path.write_text(source, encoding="utf-8")


def _unused(result: dict, category: str) -> set[str]:
    return {item["full_name"] for item in result.get(category, [])}


def test_same_named_types_and_members_keep_namespace_identity(tmp_path: Path) -> None:
    source = (
        "namespace Alpha { internal class Worker { "
        "private void Hidden() {} public void Use() { Hidden(); } } } "
        "namespace Beta { internal class Worker { private void Hidden() {} } } "
        "namespace App { public class Entry { public void Run() { "
        "var item = new Alpha.Worker(); } } }"
    )
    path = tmp_path / "Workers.cs"
    _write(path, source)

    definitions = scan_csharp_file(str(path), {})[0]
    assert {definition.name for definition in definitions} >= {
        "Alpha.Worker",
        "Alpha.Worker.Hidden",
        "Beta.Worker",
        "Beta.Worker.Hidden",
    }

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Alpha.Worker" not in _unused(result, "unused_classes")
    assert "Beta.Worker" in _unused(result, "unused_classes")
    assert "Alpha.Worker.Hidden" not in _unused(result, "unused_functions")
    by_name = {item["name"]: item for item in result["definitions"].values()}
    assert by_name["Alpha.Worker.Hidden"]["dead"] is False
    assert by_name["Beta.Worker.Hidden"]["dead"] is True


def test_method_overloads_survive_and_calls_credit_matching_arity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Service.cs"
    _write(
        path,
        "public class Service {\n"
        "    private void Ping() {}\n"
        "    private void Ping(int value) {}\n"
        "    public void Use() { Ping(1); }\n"
        "}\n",
    )

    definitions = scan_csharp_file(str(path), {})[0]
    overloads = [
        definition for definition in definitions if definition.name == "Service.Ping"
    ]
    assert {definition.csharp_arity for definition in overloads} == {0, 1}

    result = json.loads(analyze(str(tmp_path), conf=0))
    unused_overloads = [
        item
        for item in result.get("unused_functions", [])
        if item["full_name"] == "Service.Ping"
    ]
    assert [item["line"] for item in unused_overloads] == [2]


def test_overload_call_from_another_file_matches_arity(tmp_path: Path) -> None:
    _write(
        tmp_path / "Service.cs",
        "namespace Demo; public class Service {\n"
        "    internal static void Ping() {}\n"
        "    internal static void Ping(int value) {}\n"
        "}\n",
    )
    _write(
        tmp_path / "Caller.cs",
        "namespace Demo; public class Caller { public void Run() { Service.Ping(1); } }",
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    overloads = [
        item
        for item in result["definitions"].values()
        if item["name"] == "Demo.Service.Ping"
    ]
    assert len(overloads) == 2
    assert {item["line"]: item["dead"] for item in overloads} == {2: True, 3: False}


def test_same_file_constructor_reference_keeps_namespaced_type_live(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Program.cs"
    _write(
        path,
        "namespace Demo; internal class Worker {} "
        "public class Entry { public void Run() { new Worker(); } }",
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Demo.Worker" not in _unused(result, "unused_classes")


def test_partial_type_is_one_class_across_files(tmp_path: Path) -> None:
    _write(
        tmp_path / "One.cs",
        "namespace Demo; internal partial class Worker { private void Hidden() {} }",
    )
    _write(
        tmp_path / "Two.cs",
        "namespace Demo; internal partial class Worker { "
        "private void Used() {} public void Run() { Used(); } } "
        "public class Entry { public void Start() { new Worker(); } }",
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Demo.Worker" not in _unused(result, "unused_classes")
    assert "Demo.Worker.Hidden" in _unused(result, "unused_functions")
    assert "Demo.Worker.Used" not in _unused(result, "unused_functions")


def test_csharp_type_forms_generic_method_and_field_declarators(tmp_path: Path) -> None:
    path = tmp_path / "Forms.cs"
    _write(
        path,
        "namespace Types; "
        "file class FileOnly {} "
        "public ref struct Buffer {} "
        "public record struct Point(int X, int Y); "
        "public class Service { "
        "private int first, second = 2, third = Sum(1, 2); "
        "private T Convert<T>(T value) { return value; } "
        "public int Read() { return first; } }",
    )

    definitions = scan_csharp_file(str(path), {})[0]
    names = {definition.name for definition in definitions}
    assert names >= {
        "Types.FileOnly",
        "Types.Buffer",
        "Types.Point",
        "Types.Service.Convert",
        "Types.Service.first",
        "Types.Service.second",
        "Types.Service.third",
    }
    by_name = {definition.name: definition for definition in definitions}
    assert by_name["Types.Service.first"].references == 1
    assert by_name["Types.Service.second"].references == 0
    assert by_name["Types.Service.third"].references == 0


def test_nested_namespace_and_type_names_are_qualified(tmp_path: Path) -> None:
    path = tmp_path / "Nested.cs"
    _write(
        path,
        "namespace Outer { namespace Inner { class Parent { class Child { "
        "private void Work() {} } } } }",
    )

    names = {definition.name for definition in scan_csharp_file(str(path), {})[0]}
    assert names >= {
        "Outer.Inner.Parent",
        "Outer.Inner.Parent.Child",
        "Outer.Inner.Parent.Child.Work",
    }


def test_parameter_shadow_does_not_keep_private_field_live(tmp_path: Path) -> None:
    path = tmp_path / "Fields.cs"
    _write(
        path,
        "public class Fields { private int shadowed; private int accessed; "
        "public void Read(int shadowed, int accessed) { "
        "System.Console.Write(shadowed); System.Console.Write(this.accessed); } }",
    )

    definitions = scan_csharp_file(str(path), {})[0]
    by_name = {definition.name: definition for definition in definitions}
    assert by_name["Fields.shadowed"].references == 0
    assert by_name["Fields.accessed"].references == 1


def test_local_shadow_does_not_keep_private_field_live(tmp_path: Path) -> None:
    path = tmp_path / "Fields.cs"
    _write(
        path,
        "public class Fields { private int x; "
        "public void Read() { int x = 1; System.Console.Write(x); } }",
    )

    definitions = scan_csharp_file(str(path), {})[0]
    field = next(
        definition for definition in definitions if definition.name == "Fields.x"
    )
    assert field.references == 0

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Fields.x" in _unused(result, "unused_variables")


def test_local_shadow_preserves_explicit_field_access_and_block_scope(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Fields.cs"
    _write(
        path,
        "public class Fields { private int explicitValue; private int outsideValue; "
        "public void Read() { "
        "{ int explicitValue = 1, outsideValue = 2; "
        "System.Console.Write(explicitValue); "
        "System.Console.Write(this.explicitValue); } "
        "System.Console.Write(outsideValue); } }",
    )

    definitions = scan_csharp_file(str(path), {})[0]
    by_name = {definition.name: definition for definition in definitions}
    assert by_name["Fields.explicitValue"].references == 1
    assert by_name["Fields.outsideValue"].references == 1


def test_local_shadow_preserves_type_qualified_static_field_access(
    tmp_path: Path,
) -> None:
    path = tmp_path / "Fields.cs"
    _write(
        path,
        "public class Fields { private static int x; "
        "public static void Read() { int x = 1; System.Console.Write(Fields.x); } }",
    )

    definitions = scan_csharp_file(str(path), {})[0]
    field = next(
        definition for definition in definitions if definition.name == "Fields.x"
    )
    assert field.references == 1


def test_private_run_is_not_implicitly_a_lifecycle_entrypoint(tmp_path: Path) -> None:
    path = tmp_path / "Runner.cs"
    _write(
        path,
        "public class Runner { private void Run() {} private static void Main() {} }",
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Runner.Run" in _unused(result, "unused_functions")
    assert "Runner.Main" not in _unused(result, "unused_functions")


def test_type_only_references_keep_model_live_but_unused_type_dead(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "Types.cs",
        "namespace Contracts; internal class Model {} "
        "internal class Unused { private Unused Clone() { return this; } }",
    )
    _write(
        tmp_path / "Consumer.cs",
        "namespace Contracts; public class Consumer { "
        "private Model current; "
        "public System.Collections.Generic.List<Model> Values { get; set; } "
        "public Model Echo(Model value) { return value; } }",
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Contracts.Model" not in _unused(result, "unused_classes")
    assert "Contracts.Unused" in _unused(result, "unused_classes")


@pytest.mark.parametrize(
    "member",
    [
        "private Model current;",
        "public Model Echo() => null;",
        "public void Accept(Model value) {}",
        "public System.Collections.Generic.List<Model> Values { get; set; }",
    ],
    ids=["field", "return", "parameter", "generic-property"],
)
def test_individual_type_use_keeps_cross_file_model_live(
    tmp_path: Path, member: str
) -> None:
    _write(
        tmp_path / "Types.cs",
        "namespace Contracts; internal class Model {} internal class Spare {}",
    )
    _write(
        tmp_path / "Consumer.cs",
        f"namespace Contracts; public class Consumer {{ {member} }}",
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Contracts.Model" not in _unused(result, "unused_classes")
    assert "Contracts.Spare" in _unused(result, "unused_classes")


def test_constructor_and_record_parameter_types_count_as_uses(tmp_path: Path) -> None:
    _write(
        tmp_path / "Domain.cs",
        "namespace Domain; internal class Dependency {} "
        "internal class Spare {} "
        "public class Consumer { public Consumer(Dependency dependency) {} } "
        "public record Receipt(Dependency Value);",
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    assert "Domain.Dependency" not in _unused(result, "unused_classes")
    assert "Domain.Spare" in _unused(result, "unused_classes")


def test_optional_and_params_methods_accept_call_argument_counts(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path / "Calls.cs",
        "public class Calls { "
        "private void Optional(int value = 1) {} "
        "private void Variadic(params string[] values) {} "
        "private void Never() {} "
        'public void Use() { Optional(); Variadic("a", "b"); } }',
    )

    result = json.loads(analyze(str(tmp_path), conf=0))
    unused = _unused(result, "unused_functions")
    assert "Calls.Optional" not in unused
    assert "Calls.Variadic" not in unused
    assert "Calls.Never" in unused
