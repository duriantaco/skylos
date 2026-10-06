from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.csharp.core import scan_symbols


def _write(root: Path, name: str, source: str) -> None:
    root = root.resolve(strict=True)
    path = root / name
    path.resolve().relative_to(root)
    assert path.parent.resolve(strict=True) == root
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(source)


def _scan(root: Path, *, grep_verify=False) -> dict:
    result = json.loads(analyze(str(root), conf=60, grep_verify=grep_verify))
    assert result.get("analysis_errors", []) == []
    return result


def _unused_classes(result: dict) -> set[str]:
    return {row["full_name"] for row in result.get("unused_classes", [])}


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "signature",
    [
        "static void Main()",
        "static int Main(string[] args)",
        "static async Task<int> Main(string[] args)",
        "static System.Threading.Tasks.Task Main()",
    ],
)
def test_csharp_real_executable_entry_keeps_owner_and_dead_control(
    tmp_path, signature, grep_verify
):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(
        tmp_path,
        "Program.cs",
        f"namespace App; class Program {{ {signature} {{ throw new System.Exception(); }} }} "
        "class Dormant { private void Unused() {} }",
    )
    unused = _unused_classes(_scan(tmp_path, grep_verify=grep_verify))
    assert "App.Program" not in unused
    assert "App.Dormant" in unused


@pytest.mark.parametrize(
    "declaration",
    [
        "class Program { void Main() {} }",
        "class Program { static string Main() => null; }",
        "class Program { static void Main(int[] args) {} }",
        "class Program { static void Main<T>() {} }",
        "class Program<T> { static void Main() {} }",
        "class Outer<T> { class Program { static void Main() {} } }",
        "class Program { static async void Main() {} }",
        "class Program { class Task {} static Task Main() => null; }",
    ],
)
def test_csharp_main_spelling_without_entry_contract_keeps_owner_dead(
    tmp_path, declaration
):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(tmp_path, "Program.cs", "namespace App; " + declaration)
    expected = "App.Outer.Program" if "class Outer" in declaration else "App.Program"
    assert expected in _unused_classes(_scan(tmp_path))


@pytest.mark.parametrize("prefix", ["class Task {}", "using Task = Other.Result;"])
def test_csharp_custom_task_return_does_not_create_entrypoint(tmp_path, prefix):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(
        tmp_path,
        "Program.cs",
        prefix + "\nclass Program { static Task Main() => null; }",
    )
    assert "Program" in _unused_classes(_scan(tmp_path))


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("grep_verify", [False, True])
def test_csharp_project_custom_task_does_not_displace_real_main(
    tmp_path, split, grep_verify
):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    source = (
        "namespace App; class Program { static void Main() {} } "
        "class Other { static Task Main() => null; }"
    )
    if split:
        _write(tmp_path, "Task.cs", "namespace App; class Task {}")
    else:
        source += " class Task {}"
    _write(tmp_path, "Program.cs", source)
    unused = _unused_classes(_scan(tmp_path, grep_verify=grep_verify))
    assert "App.Program" not in unused
    assert "App.Other" in unused


def test_csharp_project_custom_task_does_not_shadow_qualified_standard_task(tmp_path):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(tmp_path, "Task.cs", "namespace App; class Task {}")
    _write(
        tmp_path,
        "Program.cs",
        "namespace App; class Program { static System.Threading.Tasks.Task Main() => null; }",
    )
    assert "App.Program" not in _unused_classes(_scan(tmp_path))


def test_csharp_multiline_constructor_parameters_are_not_fields():
    definitions, _, _ = scan_symbols(
        "Factory.cs",
        "class Factory {\n"
        "private string used;\nprivate string dormant;\n"
        "Factory(\nstring first,\nstring second,\nstring last) {\n"
        "used = first; Use(second); Use(last); }\n}",
    )
    fields = {item.name: item for item in definitions if item.type == "variable"}
    assert set(fields) == {"Factory.used", "Factory.dormant"}
    assert fields["Factory.used"].references > 0
    assert fields["Factory.dormant"].references == 0


def test_csharp_multiline_abstract_method_parameters_are_not_fields():
    definitions, _, _ = scan_symbols(
        "Pattern.cs",
        "abstract class Pattern {\nprivate string dormant;\n"
        "public abstract bool TryExtract(\nstring input,\n"
        "string output,\nout string remainder);\n}",
    )
    fields = {item.name: item for item in definitions if item.type == "variable"}
    assert set(fields) == {"Pattern.dormant"}
    assert fields["Pattern.dormant"].references == 0


@pytest.mark.parametrize("output_type", ["Library", "Exe"])
def test_csharp_startup_object_selects_one_containing_type(tmp_path, output_type):
    _write(
        tmp_path,
        "App.csproj",
        f"<Project><PropertyGroup><OutputType>{output_type}</OutputType>"
        "<StartupObject>App.Selected</StartupObject></PropertyGroup></Project>",
    )
    _write(
        tmp_path,
        "Program.cs",
        "namespace App; class Selected { static void Main() {} } "
        "class Dormant { static void Main() {} }",
    )
    unused = _unused_classes(_scan(tmp_path))
    assert ("App.Selected" not in unused) == (output_type == "Exe")
    assert "App.Dormant" in unused


def test_csharp_multiple_entry_candidates_do_not_select_by_order(tmp_path):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(
        tmp_path,
        "Program.cs",
        "namespace App; class First { static void Main() {} } "
        "class Second { static void Main() {} }",
    )
    assert {"App.First", "App.Second"} <= _unused_classes(_scan(tmp_path))


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("external_usage", [False, True])
@pytest.mark.parametrize("kind", ["constant_read", "self_recursion"])
def test_csharp_type_own_static_references_need_an_external_consumer(
    tmp_path, kind, external_usage, grep_verify
):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    if kind == "constant_read":
        members = (
            "public const int Value=1; "
            "private static void Unused(){System.Console.Write(Factory.Value);}"
        )
        consumer = "System.Console.Write(Factory.Value);"
    else:
        members = "public static void unused(){Factory.unused();}"
        consumer = "Factory.unused();"
    source = (
        f"namespace App; class Factory {{ {members} }} "
        f"class Program {{ static void Main() {{ {consumer if external_usage else ''} }} }} "
        "class Dormant { private void Unused() {} }"
    )
    _write(tmp_path, "Program.cs", source)
    result = _scan(tmp_path, grep_verify=grep_verify)
    unused = _unused_classes(result)
    assert ("App.Factory" not in unused) == external_usage
    assert "App.Program" not in unused
    assert "App.Dormant" in unused
    if kind == "self_recursion" and external_usage:
        assert "App.Factory.unused" not in {
            row["full_name"] for row in result.get("unused_functions", [])
        }


@pytest.mark.parametrize("active_first", [False, True])
@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "access", ["Chosen.Call()", "Chosen.Value", "global::Live.Factory.Value"]
)
def test_csharp_static_member_access_credits_exact_alias_owner(
    tmp_path, active_first, grep_verify, access
):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    live = "namespace Live { internal static class Factory { public static void Call() {} public const int Value = 1; } }"
    dead = "namespace Other { internal static class Factory { public static void Call() {} public const int Value = 1; } }"
    _write(tmp_path, "Types.cs", live + dead if active_first else dead + live)
    statement = (
        access + ";" if access.endswith(")") else f"System.Console.Write({access});"
    )
    _write(
        tmp_path,
        "Program.cs",
        "using Chosen = Live.Factory; namespace App; "
        f"class Program {{ static void Main() {{ {statement} }} }}",
    )
    unused = _unused_classes(_scan(tmp_path, grep_verify=grep_verify))
    assert "Live.Factory" not in unused
    assert "Other.Factory" in unused


@pytest.mark.parametrize(
    "declaration,signature,body",
    [
        ("", "void Read(dynamic Factory)", "System.Console.Write(Factory.Value);"),
        (
            "",
            "void Read()",
            "dynamic Factory = null; System.Console.Write(Factory.Value);",
        ),
        ("dynamic Factory;", "void Read()", "System.Console.Write(Factory.Value);"),
        (
            "dynamic Factory { get; set; }",
            "void Read()",
            "System.Console.Write(Factory.Value);",
        ),
    ],
)
def test_csharp_bound_receiver_does_not_credit_same_named_type(
    declaration, signature, body
):
    source = (
        "namespace App; class Factory {} "
        f"class Reader {{ {declaration} {signature} {{ {body} }} }}"
    )
    _, refs, _ = scan_symbols("/project/Program.cs", source)
    assert not any(
        name
        in {
            "@type:Factory",
            "@type:App.Factory",
            "@owner-type:Factory",
            "@owner-type:App.Factory",
        }
        for name, _ in refs
    )


@pytest.mark.parametrize("active_first", [False, True])
def test_csharp_unknown_import_owner_preserves_ambiguity_without_order_choice(
    tmp_path, active_first
):
    live = "namespace First { internal static class Factory { public static void Call() {} } }"
    other = "namespace Second { internal static class Factory { public static void Call() {} } }"
    _write(tmp_path, "Types.cs", live + other if active_first else other + live)
    _write(
        tmp_path,
        "Program.cs",
        "using First; using Second; class Program { public void Run() { Factory.Call(); } }",
    )
    unused = _unused_classes(_scan(tmp_path))
    assert not {"First.Factory", "Second.Factory"} & unused


def test_csharp_member_text_in_comments_strings_imports_does_not_credit_owner():
    _, refs, _ = scan_symbols(
        "/project/Program.cs",
        "using Some.Factory; namespace App; class Reader { void Run() { "
        'System.Console.Write("Factory.Call()"); /* Factory.Value */ } }',
    )
    assert not any(
        name
        in {
            "@type:Factory",
            "@type:App.Factory",
            "@type:Some",
            "@owner-type:App.Factory",
            "@owner-type:Some",
        }
        for name, _ in refs
    )


@pytest.mark.parametrize(
    "literal", ['""', '"a,b"', "'x'", '$"value"', '"""raw, value"""']
)
def test_csharp_literal_argument_preserves_arity_and_dead_overload_control(
    tmp_path, literal
):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(
        tmp_path,
        "Program.cs",
        "class Program { static void Main() { Factory.Used(" + literal + "); } } "
        "class Factory { internal static void Used(object value) {} "
        "internal static void Spare(object value) {} }",
    )
    result = _scan(tmp_path)
    unused = {row["full_name"] for row in result.get("unused_functions", [])}
    assert "Factory.Used" not in unused
    assert "Factory.Spare" in unused


def test_csharp_comment_only_call_keeps_zero_arity():
    _, refs, _ = scan_symbols(
        "/project/Program.cs",
        "class Program { void Run() { Factory.Call(/* comment */); } }",
    )
    assert "Factory.Call#0" in {name for name, _ in refs}


def test_csharp_method_group_keeps_exact_containing_method_and_dead_control(tmp_path):
    _write(
        tmp_path,
        "Program.cs",
        "public class Program { public void Run() { System.Array.Sort(new int[0], Compare); } "
        "private int Compare(int left, int right) => left - right; "
        "private int Spare(int left, int right) => left - right; } "
        "public class Other { private int Compare(int left, int right) => left - right; }",
    )
    result = _scan(tmp_path)
    unused = {row["full_name"] for row in result.get("unused_functions", [])}
    assert "Program.Compare" not in unused
    assert "Program.Spare" in unused
    assert "Other.Compare" in unused
    _, refs, _ = scan_symbols(
        "/project/Program.cs", (tmp_path / "Program.cs").read_text()
    )
    assert "Program.Compare" in {name for name, _ in refs}
    assert "Other.Compare" not in {name for name, _ in refs}


def test_csharp_constructor_modifiers_do_not_invent_method_definitions():
    definitions, _, _ = scan_symbols(
        "/project/Program.cs",
        "class Factory { static Factory() {} public Factory() {} private void Spare() {} }",
    )
    assert "Factory.Factory" not in {definition.name for definition in definitions}
    assert "Factory.Spare" in {definition.name for definition in definitions}


@pytest.mark.parametrize(
    "member",
    [
        "Reader(dynamic Factory) { System.Console.Write(Factory.Value); }",
        "Reader() { dynamic Factory = Make(); System.Console.Write(Factory.Value); }",
        "void Read() { Use(Factory => Factory.Value); }",
        "void Read() { Use((dynamic Factory) => Factory.Value); }",
        "void Read() { Use(Factory => { return Factory.Value; }); }",
        "void Read() { foreach (dynamic Factory in Make()) { System.Console.Write(Factory.Value); } }",
        "void Read() { for (dynamic Factory = Make(); Ready();) { System.Console.Write(Factory.Value); } }",
        "void Read() { try { Fail(); } catch (System.Exception Factory) { System.Console.Write(Factory.Message); } }",
        "void Read() { try { Fail(); } catch (System.Exception Factory) when (Factory.Message != null) { System.Console.Write(Factory.Message); } }",
    ],
)
def test_csharp_scoped_bindings_do_not_credit_same_named_type(member):
    source = "namespace App; class Factory {} class Reader { " + member + " }"
    _, refs, _ = scan_symbols("/project/Program.cs", source)
    assert not any(
        name
        in {
            "@type:Factory",
            "@type:App.Factory",
            "@owner-type:Factory",
            "@owner-type:App.Factory",
        }
        for name, _ in refs
    )


@pytest.mark.parametrize(
    "body",
    [
        "Use(Factory => Factory.Value);",
        "Use((dynamic Factory) => Factory.Value);",
        "foreach (dynamic Factory in Make()) { System.Console.Write(Factory.Value); }",
        "for (dynamic Factory = Make(); Ready();) { System.Console.Write(Factory.Value); }",
        "try { Fail(); } catch (System.Exception Factory) { System.Console.Write(Factory.Message); }",
    ],
)
def test_csharp_static_type_evidence_survives_outside_binding_scope(body):
    source = (
        "namespace App; class Factory { internal static int Value = 1; } "
        f"class Reader {{ void Read() {{ {body} System.Console.Write(Factory.Value); }} }}"
    )
    _, refs, _ = scan_symbols("/project/Program.cs", source)
    assert sum(name == "@owner-type:App.Factory" for name, _ in refs) == 1


def test_csharp_external_qualified_owner_does_not_rescue_same_named_local_class(
    tmp_path,
):
    _write(
        tmp_path,
        "App.csproj",
        "<Project><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(
        tmp_path,
        "Program.cs",
        'namespace App; class Console {} class Program { static void Main() { System.Console.WriteLine("hello"); } }',
    )
    assert "App.Console" in _unused_classes(_scan(tmp_path))


@pytest.mark.parametrize(
    "body",
    [
        "Program(System.Action Compare) { Use(Compare); }",
        "Program() { System.Action Compare = null; Use(Compare); }",
        "void Run() { Use((System.Action Compare) => Use(Compare)); }",
    ],
)
def test_csharp_method_group_shadow_scopes_do_not_credit_containing_method(body):
    _, refs, _ = scan_symbols(
        "/project/Program.cs",
        "class Program { " + body + " private void Compare() {} }",
    )
    assert "Program.Compare" not in {name for name, _ in refs}


def test_csharp_task_alias_in_another_namespace_does_not_disable_real_main():
    definitions, _, _ = scan_symbols(
        "/project/Program.cs",
        "using System.Threading.Tasks; namespace Other { using Task = Other.Custom; } "
        "namespace App { class Program { static Task<int> Main() => null; } }",
    )
    main = next(item for item in definitions if item.name == "App.Program.Main")
    assert main.csharp_entrypoint_signature is True


def test_csharp_task_in_enclosing_namespace_is_not_standard_task():
    definitions, _, _ = scan_symbols(
        "/project/Program.cs",
        "namespace App { class Task {} class Outer { class Program { static Task Main() => null; } } }",
    )
    main = next(item for item in definitions if item.name == "App.Outer.Program.Main")
    assert main.csharp_entrypoint_signature is False


def test_csharp_constructor_local_binding_ends_at_its_block():
    _, refs, _ = scan_symbols(
        "/project/Program.cs",
        "namespace App; class Factory { internal static int Value = 1; } "
        "class Reader { Reader() { { dynamic Factory = Make(); System.Console.Write(Factory.Value); } System.Console.Write(Factory.Value); } }",
    )
    assert sum(name == "@owner-type:App.Factory" for name, _ in refs) == 1
