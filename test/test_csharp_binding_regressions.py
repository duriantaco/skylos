from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.csharp import scan_csharp_file


def _write(root: Path, name: str, source: str) -> Path:
    path = root / name
    path.write_text(source, encoding="utf-8")
    return path


def _scan(root: Path) -> dict:
    return json.loads(analyze(str(root), conf=0, grep_verify=False))


def _names(result: dict, category: str) -> set[str]:
    return {item["full_name"] for item in result.get(category, [])}


@pytest.mark.parametrize(
    "kind", ["method", "constructor", "delegate", "record", "enum"]
)
def test_signature_contents_are_not_field_declarations(
    tmp_path: Path, kind: str
) -> None:
    declarations = {
        "method": "public int Read(\n int first,\n int second = 2) { return first + second; }",
        "constructor": "public Worker(\n int first,\n int second = 2) { System.Console.Write(first + second); }",
        "delegate": "private delegate int Convert(\n int first,\n int second);",
        "record": "private record Item(\n int first,\n int second);",
        "enum": "private enum Choice {\n First,\n Second,\n Third,\n Fourth\n }",
    }
    path = _write(
        tmp_path,
        "Fields.cs",
        "internal class Worker {\nprivate int spare;\n" + declarations[kind] + "\n}",
    )
    definitions = scan_csharp_file(str(path), {})[0]
    variables = {item.simple_name for item in definitions if item.type == "variable"}
    assert variables == {"spare"}


def test_generic_parameter_type_argument_does_not_become_field(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "Generic.cs",
        "internal class Work {\nprivate int spare;\npublic void Run(\n System.Func<AttributeData, CancellationToken, int> convert,\n int extra = 0) { convert(null, default); }\n}",
    )
    definitions = scan_csharp_file(str(path), {})[0]
    assert {item.simple_name for item in definitions if item.type == "variable"} == {
        "spare"
    }


def test_attribute_suffix_use_and_unused_attribute_control(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Attributes.cs",
        "namespace Tags; internal sealed class UsedAttribute : System.Attribute {} internal sealed class SpareAttribute : System.Attribute {} [Used] public class Entry {}",
    )
    unused = _names(_scan(tmp_path), "unused_classes")
    assert "Tags.UsedAttribute" not in unused
    assert "Tags.SpareAttribute" in unused


def test_attribute_import_binding_does_not_consume_other_namespace(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "Attributes.cs",
        "namespace Alpha { internal class MarkAttribute : System.Attribute {} } namespace Beta { internal class MarkAttribute : System.Attribute {} }",
    )
    _write(
        tmp_path,
        "Consumer.cs",
        "using Alpha; namespace App; [Mark] public class Entry {}",
    )
    unused = _names(_scan(tmp_path), "unused_classes")
    assert "Alpha.MarkAttribute" not in unused
    assert "Beta.MarkAttribute" in unused


def test_ordinary_call_is_not_an_attribute_use(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Lookalike.cs",
        "namespace Tags; internal class MarkAttribute : System.Attribute {} public class Entry { private void Mark() {} public void Run() { Mark(); } }",
    )
    assert "Tags.MarkAttribute" in _names(_scan(tmp_path), "unused_classes")


def test_local_method_group_and_unused_method_control(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Callbacks.cs",
        "namespace Demo; public class Entry { private static int Map(int value) => value; private static int Spare(int value) => value; public object Run() => new System.Func<int, int>(Map); }",
    )
    unused = _names(_scan(tmp_path), "unused_functions")
    assert "Demo.Entry.Map" not in unused
    assert "Demo.Entry.Spare" in unused


def test_parameter_shadow_is_not_a_method_group_reference(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Callbacks.cs",
        "public class Entry { private static int Map(int value) => value; public object Run(System.Func<int, int> Map) => new System.Func<int, int>(Map); }",
    )
    assert "Entry.Map" in _names(_scan(tmp_path), "unused_functions")


def test_local_delegate_shadow_is_not_a_method_group_reference(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Callbacks.cs",
        "public class Entry { private static int Map(int value) => value; public object Run() { System.Func<int, int> Map = value => value; return new System.Func<int, int>(Map); } }",
    )
    assert "Entry.Map" in _names(_scan(tmp_path), "unused_functions")


def test_collection_expression_is_not_an_attribute_use(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Collections.cs",
        "internal class MarkAttribute : System.Attribute {} public class Entry { public int[] Run(int Mark) { return\n[Mark]; } }",
    )
    assert "MarkAttribute" in _names(_scan(tmp_path), "unused_classes")


def test_all_attributes_in_consecutive_lists_have_references(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Attributes.cs",
        "internal class FirstAttribute : System.Attribute {} internal class SecondAttribute : System.Attribute {} [First][Second] public class Entry {}",
    )
    unused = _names(_scan(tmp_path), "unused_classes")
    assert "FirstAttribute" not in unused
    assert "SecondAttribute" not in unused


def test_method_group_member_keeps_exact_owner(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Callbacks.cs",
        "namespace Alpha { internal static class Callbacks { internal static int Map(int value) => value; } } namespace Beta { internal static class Callbacks { private static int Map(int value) => value; } } public class Entry { public object Run() => new System.Func<int, int>(Alpha.Callbacks.Map); }",
    )
    unused = _names(_scan(tmp_path), "unused_classes")
    assert "Alpha.Callbacks" not in unused
    assert "Beta.Callbacks" in unused


def test_nested_generic_receiver_keeps_exact_nested_type(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Cache.cs",
        "namespace Demo; public class First { private static class Cache<T> { public static int Value = 1; } public int Run() => Cache<int>.Value; } public class Second { private static class Cache<T> { public static int Value = 2; } }",
    )
    unused = _names(_scan(tmp_path), "unused_classes")
    assert "Demo.First.Cache" not in unused
    assert "Demo.Second.Cache" in unused


def test_static_member_read_keeps_class_without_preserving_unused_class(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "Constants.cs",
        "namespace Demo; internal static class Sizes { public const int Used = 1; } internal static class Spare { public const int Used = 1; } public class Entry { public int Read() => Sizes.Used; }",
    )
    unused = _names(_scan(tmp_path), "unused_classes")
    assert "Demo.Sizes" not in unused
    assert "Demo.Spare" in unused


def test_static_call_keeps_owner_and_unused_method_stays_reported(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "Statics.cs",
        "namespace Demo; internal static class Helper { public static int Used() => 1; private static int Spare() => 2; } internal class Other {} public class Entry { public int Run() => Helper.Used(); }",
    )
    result = _scan(tmp_path)
    assert "Demo.Helper" not in _names(result, "unused_classes")
    assert "Demo.Other" in _names(result, "unused_classes")
    assert "Demo.Helper.Spare" in _names(result, "unused_functions")


def test_main_owner_is_live_and_other_application_class_is_dead(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>',
    )
    _write(
        tmp_path,
        "Program.cs",
        "namespace Demo; internal static class Program { private static void Main() {} } public class Spare { public void Never() {} }",
    )
    unused = _names(_scan(tmp_path), "unused_classes")
    assert "Demo.Program" not in unused
    assert "Demo.Spare" in unused


def test_binding_context_retains_alias_namespace_and_owner(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "Context.cs",
        "using Marks; using Tag = Other.MarkAttribute; namespace App; [Tag] public class Entry { public object Read() => Helpers.Map; }",
    )
    result = scan_csharp_file(str(path), {})
    context = getattr(result[5], "csharp_reference_context", {})
    attribute = context["@attribute:Tag"][0]
    assert attribute["namespace"] == "App"
    assert attribute["aliases"] == {"Tag": "Other.MarkAttribute"}
    assert attribute["usings"] == ["Marks"]
    member = context["@member:Helpers.Map"][0]
    assert member["owner"] == "App.Entry"


def test_ordinary_call_context_records_parameter_receiver_shadow(
    tmp_path: Path,
) -> None:
    path = _write(
        tmp_path,
        "Shadow.cs",
        "namespace Demo; internal class Helper { public static void Ping() {} } public class Other { public void Ping() {} } public class Entry { public void Run(Other Helper) { Helper.Ping(); } }",
    )
    result = scan_csharp_file(str(path), {})
    contexts = result[5].csharp_reference_context
    calls = [
        item
        for key, values in contexts.items()
        if key.endswith("Helper.Ping#0")
        for item in values
    ]
    assert calls and calls[0]["receiver_shadowed"] is True
    assert "Helper" in calls[0]["shadowed_names"]


def test_lambda_parameter_is_not_a_method_group_use(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Lambda.cs",
        "public class Entry { private static int Map(int value) => value; public object Run() => new System.Func<System.Func<int, int>, object>(Map => Map); }",
    )
    assert "Entry.Map" in _names(_scan(tmp_path), "unused_functions")


def test_lambda_shadow_ends_before_an_outer_method_group_use(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Lambda.cs",
        "public class Entry { private static int Map(int value) => value; public object Run() { var a = new System.Func<System.Func<int, int>, object>(Map => Map); return new System.Func<int, int>(Map); } }",
    )
    assert "Entry.Map" not in _names(_scan(tmp_path), "unused_functions")


def test_unused_using_alias_does_not_keep_provider_live(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Alias.cs",
        "using Alias = Demo.Helper; namespace Demo; internal class Helper { private static int Map(int value) => value; } public class Entry {}",
    )
    assert "Demo.Helper" in _names(_scan(tmp_path), "unused_classes")


@pytest.mark.parametrize(
    ("parameters", "body", "receiver_type"),
    [
        ("", "var worker = new Pipeline(); worker.Emit();", "Pipeline"),
        ("", "Pipeline worker = new(); worker.Emit();", "Pipeline"),
        ("Tools.Pipeline<int> worker", "worker.Emit();", "Tools.Pipeline"),
        ("object worker", "worker.Emit();", "object"),
    ],
)
def test_instance_call_context_records_source_proven_receiver_type(
    tmp_path: Path, parameters: str, body: str, receiver_type: str
) -> None:
    path = _write(
        tmp_path,
        "Receiver.cs",
        f"public class Entry {{ public void Run({parameters}) {{ {body} }} }}",
    )
    contexts = scan_csharp_file(str(path), {})[5].csharp_reference_context
    calls = [
        item
        for key, values in contexts.items()
        if key.endswith("#0")
        for item in values
        if item["spelling"] == "worker.Emit"
    ]
    assert calls and calls[0]["receiver_shadowed"] is True
    assert calls[0].get("receiver_type") == receiver_type


def test_tuple_return_methods_keep_real_identity_and_unused_control(tmp_path: Path):
    path = _write(
        tmp_path,
        "Tuple.cs",
        "public class Entry { public static (int First, int Second) Read() => (1, 2); "
        "private static (int First, int Second) Spare() => (3, 4); }",
    )
    methods = {
        item.name
        for item in scan_csharp_file(str(path), {})[0]
        if item.type == "method"
    }
    assert methods == {"Entry.Read", "Entry.Spare"}
    assert "Entry.Spare" in _names(_scan(tmp_path), "unused_functions")


@pytest.mark.parametrize(
    "expression",
    [
        '$"{Header}"',
        '$@"{Header} ""Spare"""',
        '$"{{Spare}} {Header}"',
        '$"{Header:Spare}"',
        '$$"""class Generated { void Spare() {} } {{Header}}"""',
        '$$"""{Spare} {{Header}}"""',
        '$"{System.Convert.ToString(Header)}.g.cs"',
    ],
)
def test_interpolation_reads_preserve_only_expression_fields(
    tmp_path: Path, expression: str
):
    path = _write(
        tmp_path,
        "Interpolated.cs",
        'public class Entry { private const string Header = "used"; '
        'private const string Spare = "unused"; '
        f"public string Read() => {expression}; }}",
    )
    definitions = scan_csharp_file(str(path), {})[0]
    fields = {
        item.name: item.references for item in definitions if item.type == "variable"
    }
    assert fields["Entry.Header"] > 0
    assert fields["Entry.Spare"] == 0
    assert not any(item.name == "Entry.Generated" for item in definitions)


@pytest.mark.parametrize(
    "member",
    ["private Remote Helper = new();", "private Remote Helper { get; } = new();"],
)
def test_field_and_property_receiver_context_records_shadow_and_type(tmp_path, member):
    path = _write(
        tmp_path,
        "MemberShadow.cs",
        f"public class Entry {{ {member} public void Run() {{ Helper.Ping(); }} }}",
    )
    contexts = scan_csharp_file(str(path), {})[5].csharp_reference_context
    calls = [
        item
        for key, values in contexts.items()
        if key.endswith("#0")
        for item in values
        if item["spelling"] == "Helper.Ping"
    ]
    assert calls and calls[0]["receiver_shadowed"] is True
    assert calls[0].get("receiver_type") == "Remote"


@pytest.mark.parametrize(
    "expression",
    ["Header ?? Fallback", "Header ??= Fallback", "(Header ??= Fallback)"],
)
def test_null_coalescing_interpolation_keeps_format_text_as_data(
    tmp_path: Path, expression: str
) -> None:
    path = _write(
        tmp_path,
        "Coalescing.cs",
        "public class Entry { private string? Header; "
        'private const string Fallback = "fallback"; '
        'private const string Spare = "unused"; '
        f'public string Read() => $"{{{expression}:Spare}}"; }}',
    )
    fields = {
        item.simple_name: item.references
        for item in scan_csharp_file(str(path), {})[0]
        if item.type == "variable"
    }
    assert fields["Header"] > 0
    assert fields["Fallback"] > 0
    assert fields["Spare"] == 0
