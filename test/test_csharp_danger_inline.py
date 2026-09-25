from __future__ import annotations

import json

import pytest

from skylos.analyzer import analyze
from skylos.visitors.languages.csharp.danger import scan_danger


def test_inline_method_parameter_reaches_command_sink():
    source = (
        "namespace Demo; public class Runner { "
        "public void Run(string command) { Process.Start(command); } }"
    )

    findings = scan_danger("Runner.cs", source)

    assert [
        (finding["rule_id"], finding["category"], finding["file"], finding["line"])
        for finding in findings
    ] == [("SKY-D212", "danger", "Runner.cs", 1)]


def test_inline_command_finding_reaches_analyzer_output(tmp_path):
    source = (
        "namespace Demo; public class Runner { "
        "public void Run(string command) { Process.Start(command); } }"
    )
    (tmp_path / "Runner.cs").write_text(source, encoding="utf-8")

    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))

    assert any(
        finding["rule_id"] == "SKY-D212"
        and finding["file"].endswith("Runner.cs")
        and finding["line"] == 1
        for finding in result.get("danger", [])
    )


def test_inline_method_literal_command_is_safe():
    source = (
        "namespace Demo { public class Runner { "
        'public void Run(string command) { Process.Start("dotnet", "--info"); } } }'
    )

    assert scan_danger("Runner.cs", source) == []


def test_inline_method_request_source_reaches_command_sink():
    source = (
        "namespace Demo { public class Runner { public void Run() { "
        'var command = Request.Query["command"].ToString(); '
        "Process.Start(command); } } }"
    )

    assert [finding["rule_id"] for finding in scan_danger("Runner.cs", source)] == [
        "SKY-D212"
    ]


@pytest.mark.parametrize(
    ("source", "rule_id"),
    [
        ("public void Run(string data) { Process.Start(data); }", "SKY-D212"),
        (
            "public void Run(string data) { if (data != null) { "
            "var selected = data; Process.Start(selected); } }",
            "SKY-D212",
        ),
        (
            'public void Run(string data, bool flag) { var selected = "dotnet"; '
            "if (flag) selected = data; Process.Start(selected); }",
            "SKY-D212",
        ),
        ('public void Run(string data) { Process.Start($"tool {data}"); }', "SKY-D212"),
        (
            'public void Run(string data) { var selected = $"tool {data}"; '
            "Process.Start(selected); }",
            "SKY-D212",
        ),
        ("public void Run(string data) => Process.Start(data);", "SKY-D212"),
        ("public Runner(string data) => Process.Start(data);", "SKY-D212"),
        (
            "public void Run(string data, string other) { "
            'File.ReadAllText(Path.Combine("/srv", Path.GetFileName(data), other)); }',
            "SKY-D215",
        ),
        (
            "public void Run(string data) { "
            "var safe = Path.GetFileName(data); Process.Start(safe); }",
            "SKY-D212",
        ),
        (
            "public void Run(string data, bool flag) { "
            'if (flag) { data = "literal"; } Process.Start(data); }',
            "SKY-D212",
        ),
        (
            "public void Run(string data) { "
            "new HttpRequestMessage(HttpMethod.Get, data); }",
            "SKY-D216",
        ),
        (
            'public void Run(Dictionary<string, string> data, string prefix = "x") { '
            'Process.Start(data["command"]); }',
            "SKY-D212",
        ),
    ],
)
def test_tainted_input_reaches_sink_across_csharp_forms(source, rule_id):
    findings = scan_danger("Runner.cs", "public class Runner { " + source + " }")

    assert [finding["rule_id"] for finding in findings] == [rule_id]


@pytest.mark.parametrize(
    "source",
    [
        'public void Run(string data) { if (data != null) Process.Start("dotnet"); }',
        'public void Run(string data) { if (data != null) { Process.Start("dotnet"); } }',
        'public void Run(string data) { File.WriteAllText("/srv/report", data); }',
        'public void Run(string data) { client.PostAsync("https://example.com", data); }',
        "public void Run(string data) { "
        'new HttpRequestMessage(HttpMethod.Get, "https://example.com"); }',
        "public void Run(string data, SqlConnection connection) { "
        'new SqlCommand("SELECT 1", connection); }',
        'public void Run(string data) { Process.Start($"tool {{literal}}"); }',
        'public void Run(string data) { var safe = /* $"tool {data}" */ "dotnet"; '
        "Process.Start(safe); }",
    ],
)
def test_tainted_input_outside_relevant_sink_argument_is_safe(source):
    assert scan_danger("Runner.cs", "public class Runner { " + source + " }") == []


def test_path_get_file_name_still_allows_sensitive_file_selection():
    source = (
        "public class Runner { public void Run(string data) { "
        "var name = Path.GetFileName(data); File.ReadAllText(name); } }"
    )

    assert [item["rule_id"] for item in scan_danger("Runner.cs", source)] == [
        "SKY-D215"
    ]


def test_inline_basename_with_fixed_directory_avoids_traversal():
    source = (
        "using System.IO; public class Runner { public void Run(string data) { "
        'File.ReadAllText(Path.Combine("uploads", Path.GetFileName(data))); } }'
    )

    assert scan_danger("Runner.cs", source) == []


@pytest.mark.parametrize(
    "body",
    [
        "File.ReadAllText(Path.Combine(data, Path.GetFileName(data)));",
        'File.ReadAllText(Path.Combine("uploads", Path.GetFileName(data), data));',
        'Directory.GetFiles(Path.Combine("uploads", Path.GetFileName(data)));',
        'File.ReadAllText(Path.Combine(".", Path.GetFileName(data)));',
        'File.ReadAllText(Path.Combine("/", Path.GetFileName(data)));',
        'File.ReadAllText(Path.Combine("uploads", Path.GetFileName(data) + "/secret"));',
        'File.ReadAllText(Path.Combine("uploads", CustomPath.GetFileName(data)));',
        "var name = Path.GetFileName(data); name = data; "
        'File.ReadAllText(Path.Combine("uploads", name));',
        'var name = Path.GetFileName(data); name += "/../secret"; '
        'File.ReadAllText(Path.Combine("uploads", name));',
        "var name = Path.GetFileName(data); Mutate(ref name); "
        'File.ReadAllText(Path.Combine("uploads", name));',
        "var name = data; if (flag) name = Path.GetFileName(data); "
        'File.ReadAllText(Path.Combine("uploads", name));',
    ],
)
def test_basename_containment_unsafe_lookalikes_still_flag(body):
    source = (
        "using System.IO; public class Runner { "
        f"public void Run(string data, bool flag) {{ {body} }} }}"
    )

    assert [item["rule_id"] for item in scan_danger("Runner.cs", source)] == [
        "SKY-D215"
    ]


@pytest.mark.parametrize(
    ("prefix", "prelude"),
    [
        (
            "public class Path { public static string GetFileName(string s) => s; "
            "public static string Combine(string root, string name) => name; }",
            "",
        ),
        ("using Path = Demo.CustomPath;", ""),
        (
            "public class CustomPath { public string GetFileName(string s) => s; "
            "public string Combine(string root, string name) => name; }",
            "var Path = new CustomPath();",
        ),
    ],
)
def test_shadowed_system_path_does_not_suppress_path_finding(prefix, prelude):
    source = (
        f"{prefix} public class Runner {{ public void Run(string data) {{ "
        f"{prelude} var name = Path.GetFileName(data); "
        'File.ReadAllText(Path.Combine("uploads", name)); } }'
    )

    assert [item["rule_id"] for item in scan_danger("Runner.cs", source)] == [
        "SKY-D215"
    ]


def test_fully_qualified_system_path_is_safe_despite_shadowed_short_name():
    source = (
        "public class Path { } public class Runner { public void Run(string data) { "
        "var name = System.IO.Path.GetFileName(data); "
        'File.ReadAllText(System.IO.Path.Combine("uploads", name)); } }'
    )

    assert scan_danger("Runner.cs", source) == []


def test_random_file_name_does_not_carry_tainted_input():
    source = (
        "public class Runner { public void Run(string data) { "
        "var name = Path.GetRandomFileName(); File.ReadAllText(name); } }"
    )

    assert scan_danger("Runner.cs", source) == []


@pytest.mark.parametrize(
    ("statement", "rule_id"),
    [
        ("var info = new ProcessStartInfo { FileName = data };", "SKY-D212"),
        ("var info = new ProcessStartInfo() { Arguments = data };", "SKY-D212"),
        ("ProcessStartInfo info = new() { FileName = data };", "SKY-D212"),
        ("var cmd = new SqlCommand { CommandText = data };", "SKY-D211"),
        ("SqlCommand cmd = new() { CommandText = data };", "SKY-D211"),
    ],
)
def test_tainted_object_initializer_properties_are_sinks(statement, rule_id):
    source = f"public class Runner {{ public void Run(string data) {{ {statement} }} }}"

    assert [item["rule_id"] for item in scan_danger("Runner.cs", source)] == [rule_id]


@pytest.mark.parametrize(
    "statement",
    [
        'var info = new ProcessStartInfo { FileName = "dotnet" };',
        'var info = new ProcessStartInfo { Environment = { ["key"] = data } };',
        "var info = new UiInfo { FileName = data };",
        "var cmd = new UiCommand { CommandText = data };",
    ],
)
def test_unrelated_object_initializer_properties_are_safe(statement):
    source = f"public class Runner {{ public void Run(string data) {{ {statement} }} }}"

    assert scan_danger("Runner.cs", source) == []


@pytest.mark.parametrize(
    ("declaration", "assignment", "rule_id"),
    [
        ("ProcessStartInfo info = new();", "info.FileName = data;", "SKY-D212"),
        ("SqlCommand cmd = new();", "cmd.CommandText = data;", "SKY-D211"),
    ],
)
def test_target_typed_new_tracks_security_sink_owner(declaration, assignment, rule_id):
    source = (
        "public class Runner { public void Run(string data) { "
        f"{declaration} {assignment} }} }}"
    )

    assert [item["rule_id"] for item in scan_danger("Runner.cs", source)] == [rule_id]


@pytest.mark.parametrize(
    ("declaration", "assignment", "rule_id"),
    [
        (
            'var info = new ProcessStartInfo { FileName = "dotnet" };',
            "info.Arguments = data;",
            "SKY-D212",
        ),
        (
            'ProcessStartInfo info = new() { FileName = "dotnet" };',
            "info.Arguments = data;",
            "SKY-D212",
        ),
        (
            'var cmd = new SqlCommand { CommandText = "SELECT 1" };',
            "cmd.CommandText = data;",
            "SKY-D211",
        ),
    ],
)
def test_object_initializer_preserves_later_property_sink_owner(
    declaration, assignment, rule_id
):
    source = (
        "public class Runner { public void Run(string data) { "
        f"{declaration} {assignment} }} }}"
    )

    assert [item["rule_id"] for item in scan_danger("Runner.cs", source)] == [rule_id]


def test_renamed_parameter_interpolation_reaches_analyzer_output(tmp_path):
    (tmp_path / "Runner.cs").write_text(
        'public class Runner { public void Run(string data) => Process.Start($"tool {data}"); }',
        encoding="utf-8",
    )

    result = json.loads(analyze(str(tmp_path), enable_danger=True, grep_verify=False))

    assert any(
        finding["rule_id"] == "SKY-D212"
        and finding["file"].endswith("Runner.cs")
        and finding["line"] == 1
        for finding in result.get("danger", [])
    )


def test_multiline_sink_reports_sink_line():
    source = "public class Runner {\n  public void Run(string data) {\n    Process.Start(data);\n  }\n}"

    findings = scan_danger("Runner.cs", source)

    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D212", 3)
    ]
