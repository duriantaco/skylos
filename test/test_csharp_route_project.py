from pathlib import Path

import pytest

from skylos.visitors.languages.csharp.route_project import build_route_handler_index

PROGRAM = 'var app = WebApplication.Create();\napp.MapGet("/", Endpoints.Get);'
HANDLER = (
    "public static class Endpoints { public static string Get(string value) => value; }"
)


def route_targets(root, sources):
    files = []
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        if path.suffix == ".cs":
            files.append(path)
    index = build_route_handler_index(files, root)
    return {
        Path(file).relative_to(root).as_posix()
        for file, facts in index.items()
        if facts.method_offsets
    }


@pytest.mark.parametrize(
    "program",
    [
        "using Demo;\n" + PROGRAM,
        "using Ep = Demo.Endpoints;\n" + PROGRAM.replace("Endpoints.Get", "Ep.Get"),
        PROGRAM.replace("Endpoints.Get", "global::Demo.Endpoints.Get"),
        PROGRAM.replace(
            '"/", Endpoints.Get', 'handler: global::Demo.Endpoints.Get, pattern: "/"'
        ),
        PROGRAM.replace("MapGet", "MapFallback").replace(
            '"/", Endpoints.Get', "global::Demo.Endpoints.Get"
        ),
    ],
)
def test_binds_visible_static_method_group(tmp_path, program):
    assert route_targets(
        tmp_path,
        {
            "A.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
            "Program.cs": program,
            "Endpoints.cs": "namespace Demo;\n" + HANDLER,
            "Other.cs": "namespace Unrelated;\n" + HANDLER,
        },
    ) == {"Endpoints.cs"}


@pytest.mark.parametrize(
    "target,extra,program",
    [
        (
            HANDLER.replace(
                "=> value;", "=> value; public static int Get(int value) => value;"
            ),
            "",
            PROGRAM,
        ),
        (
            HANDLER,
            "namespace Other;\n" + HANDLER,
            "using Demo;\nusing Other;\n" + PROGRAM,
        ),
        (HANDLER.replace("public static class", "file static class"), "", PROGRAM),
        (HANDLER.replace("public static string", "private static string"), "", PROGRAM),
        (
            HANDLER,
            "",
            PROGRAM.replace("app.MapGet", "var Endpoints = new Table();\napp.MapGet"),
        ),
        (
            HANDLER,
            "",
            PROGRAM.replace("app.MapGet", "#if ENABLE_ROUTE\napp.MapGet") + "\n#endif",
        ),
    ],
)
def test_skips_ambiguous_or_out_of_scope_handlers(tmp_path, target, extra, program):
    assert not route_targets(
        tmp_path,
        {
            "A.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
            "Program.cs": "using Demo;\n" + program,
            "Endpoints.cs": "namespace Demo;\n" + target,
            "Other.cs": extra,
        },
    )


@pytest.mark.parametrize(
    "extra",
    [
        {"Other.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />'},
        {
            "A.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><Compile Remove="Endpoints.cs" /></ItemGroup></Project>'
        },
        {
            "Directory.Build.props": "<Project><PropertyGroup><EnableDefaultCompileItems>false</EnableDefaultCompileItems></PropertyGroup></Project>"
        },
    ],
)
def test_declines_cross_file_binding_for_uncertain_compile_items(tmp_path, extra):
    assert not route_targets(
        tmp_path,
        {
            "A.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
            "Program.cs": PROGRAM,
            "Endpoints.cs": HANDLER,
            **extra,
        },
    )


def test_project_usings_and_metadata_only_compile_updates(tmp_path):
    assert route_targets(
        tmp_path,
        {
            "A.csproj": """<Project Sdk="Microsoft.NET.Sdk.Web">
            <PropertyGroup><EnableDefaultCompileItems>true</EnableDefaultCompileItems></PropertyGroup>
            <ItemGroup>
                <Compile Update="Endpoints.cs"><DependentUpon>View.cs</DependentUpon></Compile>
                <Using Include="Demo" />
            </ItemGroup>
        </Project>""",
            "Program.cs": PROGRAM,
            "Endpoints.cs": "namespace Demo;\n" + HANDLER,
        },
    ) == {"Endpoints.cs"}


def test_global_using_and_using_static_bind_only_visible_method(tmp_path):
    assert route_targets(
        tmp_path,
        {
            "A.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
            "Imports.cs": "global using static Demo.Endpoints;",
            "Program.cs": PROGRAM.replace("Endpoints.Get", "Get"),
            "Endpoints.cs": "namespace Demo;\n" + HANDLER,
            "Other.cs": "namespace Other;\n" + HANDLER,
        },
    ) == {"Endpoints.cs"}


VERSIONED = """
using Microsoft.AspNetCore.Builder;
using Asp.Versioning;
using Asp.Versioning.Conventions;
var app = WebApplication.Create();
var api = app.NewVersionedApi("todos").MapGroup("/todos").HasApiVersion(1, 0);
api.MapGet("/", Endpoints.Get);
"""


@pytest.mark.parametrize(
    ("package_items", "override", "expected"),
    [
        ('<PackageReference Include="Asp.Versioning.Http" />', "", {"Program.cs"}),
        (
            '<PackageReference Include="Asp.Versioning.Http" Condition="false" />',
            "",
            set(),
        ),
        (
            '<PackageReference Include="Asp.Versioning.Http"><ExcludeAssets>compile</ExcludeAssets></PackageReference>',
            "",
            set(),
        ),
        ('<PackageReference Include="Other.Package" />', "", set()),
        (
            '<PackageReference Include="Asp.Versioning.Http" /><PackageReference Remove="Asp.Versioning.Http" />',
            "",
            set(),
        ),
        (
            '<PackageReference Include="Asp.Versioning.Http" />',
            "public static class LocalExtensions { public static Table NewVersionedApi(this WebApplication app, string name) => new Table(); }",
            set(),
        ),
    ],
)
def test_versioned_groups_require_package_and_unique_extension(
    tmp_path, package_items, override, expected
):
    # A linked source may add overloads; same-file handlers still have lexical
    # registration evidence. Another file's declaration must not join the graph.
    metadata = f'<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup>{package_items}<Compile Include="../Shared/Tool.cs" /></ItemGroup></Project>'
    assert (
        route_targets(
            tmp_path,
            {
                "Test.csproj": metadata,
                "Program.cs": VERSIONED + 'api.MapGet("/other", Other.Get);' + HANDLER,
                "Other.cs": HANDLER.replace("class Endpoints", "class Other"),
                "Custom.cs": override,
            },
        )
        == expected
    )


@pytest.mark.parametrize(
    "other,expected",
    [
        (
            "public static class Other { public static int Count() => 4; }",
            {"Program.cs"},
        ),
        (
            "public static class Other { public static string Get(string v) => v; }",
            set(),
        ),
        (
            "public static class Other { public static Func<string, string> Get { get; set; } }",
            set(),
        ),
        ("public static partial class Other { }", set()),
        ("", set()),  # The member set of an external import is unknown.
    ],
)
def test_multiple_static_imports_consider_possible_members(tmp_path, other, expected):
    source = (
        "using static Demo.Endpoints;\nusing static Demo.Other;\n"
        + PROGRAM.replace("Endpoints.Get", "Get")
        + "\nnamespace Demo {\n"
        + HANDLER
        + "\n"
        + other
        + "\n}"
    )
    assert (
        route_targets(
            tmp_path,
            {
                "Demo.csproj": '<Project Sdk="Microsoft.NET.Sdk.Web" />',
                "Program.cs": source,
            },
        )
        == expected
    )
