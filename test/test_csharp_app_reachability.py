from __future__ import annotations

import json
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.constants import DEFAULT_EXCLUDE_FOLDERS


def _write(root: Path, relative: str, source: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _scan(root: Path) -> dict:
    return json.loads(analyze(str(root), grep_verify=False))


def _names(result: dict, category: str) -> set[str]:
    return {item["full_name"] for item in result.get(category, [])}


def test_web_app_reports_local_public_candidates_and_preserves_entrypoints(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "Web.csproj", '<Project Sdk="Microsoft.NET.Sdk.Web" />')
    _write(
        tmp_path,
        "Types.cs",
        "namespace Demo; "
        "public class Dormant { public void Call() {} } "
        "public class Active { public void Used() {} public void Stale() {} "
        "protected void FrameworkHook() {} } "
        "public interface ITask { void Run(); } "
        "public class Task : ITask { public void Run() {} public void Stale() {} } "
        "[ApiController] public class ItemController { "
        '[HttpGet] public string List() => "ok"; '
        "public void ConventionalAction() {} } "
        "public class Dynamic { public void Execute() {} } "
        "namespace Other { public class Dynamic {} } "
        "public partial class Generated { public void Hook() {} } "
        "public static class Extensions { "
        "public static string Expand(this string value) => value; }",
    )
    _write(
        tmp_path,
        "Program.cs",
        "new Demo.Active().Used(); new Demo.Task();",
    )
    _write(tmp_path, "appsettings.json", '{"ProcessorType":"Demo.Dynamic"}')

    result = _scan(tmp_path)
    classes = _names(result, "unused_classes")
    methods = _names(result, "unused_functions")

    assert "Demo.Dormant" in classes
    assert "Demo.Other.Dynamic" in classes
    assert "Demo.Active" not in classes
    assert "Demo.Task" not in classes
    assert "Demo.ItemController" not in classes
    assert "Demo.Dynamic" not in classes
    assert "Demo.Generated" not in classes
    assert "Demo.Extensions" not in classes
    assert "Demo.Active.Stale" in methods
    assert "Demo.Active.FrameworkHook" not in methods
    assert "Demo.Task.Stale" in methods
    assert "Demo.Task.Run" not in methods
    assert "Demo.ItemController.List" not in methods
    assert "Demo.ItemController.ConventionalAction" not in methods
    assert "Demo.Dynamic.Execute" not in methods
    assert "Demo.Extensions.Expand" not in methods
    assert all(
        item["confidence"] == 60
        for item in result["unused_classes"] + result["unused_functions"]
        if item["full_name"].startswith("Demo.")
    )

    cli_scope = json.loads(
        analyze(
            str(tmp_path),
            exclude_folders=list(DEFAULT_EXCLUDE_FOLDERS),
            grep_verify=False,
        )
    )
    assert _names(cli_scope, "unused_classes") == classes
    assert _names(cli_scope, "unused_functions") == methods


def test_library_and_file_scoped_scans_preserve_public_api(tmp_path: Path) -> None:
    _write(tmp_path, "Library.csproj", '<Project Sdk="Microsoft.NET.Sdk" />')
    _write(
        tmp_path,
        "PublicApi.cs",
        "namespace Library; public class PublicApi { public void Call() {} }",
    )

    result = _scan(tmp_path)
    assert "Library.PublicApi" not in _names(result, "unused_classes")
    assert "Library.PublicApi.Call" not in _names(result, "unused_functions")

    _write(tmp_path, "Library.csproj", '<Project Sdk="Microsoft.NET.Sdk.Web" />')
    scoped = json.loads(analyze(str(tmp_path / "PublicApi.cs"), grep_verify=False))
    assert "Library.PublicApi" not in _names(scoped, "unused_classes")
    assert "Library.PublicApi.Call" not in _names(scoped, "unused_functions")

    excluded = json.loads(
        analyze(str(tmp_path), exclude_folders=["custom"], grep_verify=False)
    )
    assert "Library.PublicApi" not in _names(excluded, "unused_classes")

    changed = json.loads(
        analyze(
            str(tmp_path),
            changed_files=[str(tmp_path / "PublicApi.cs")],
            grep_verify=False,
        )
    )
    assert "Library.PublicApi" not in _names(changed, "unused_classes")


def test_nested_library_keeps_its_public_api_during_app_scan(tmp_path: Path) -> None:
    _write(tmp_path, "App.csproj", '<Project Sdk="Microsoft.NET.Sdk.Web" />')
    _write(tmp_path, "Local.cs", "public class Local {}")
    _write(tmp_path, "Nested/Library.csproj", '<Project Sdk="Microsoft.NET.Sdk" />')
    _write(
        tmp_path,
        "Nested/Api.cs",
        "public class LibraryApi { public void Exported() {} }",
    )

    result = _scan(tmp_path)
    assert "Local" in _names(result, "unused_classes")
    assert "LibraryApi" not in _names(result, "unused_classes")
    assert "LibraryApi.Exported" not in _names(result, "unused_functions")


def test_framework_entrypoint_protection_follows_local_inheritance(
    tmp_path: Path,
) -> None:
    _write(tmp_path, "Web.csproj", '<Project Sdk="Microsoft.NET.Sdk.Web" />')
    _write(
        tmp_path,
        "Controllers.cs",
        "namespace App; "
        "public class FrameworkBase : ControllerBase {} "
        "public class Intermediate : FrameworkBase {} "
        "public class Orders : Intermediate { public void Index() {} } "
        "public class Detached { public void Cleanup() {} }",
    )

    result = _scan(tmp_path)
    classes = _names(result, "unused_classes")
    methods = _names(result, "unused_functions")
    assert "App.FrameworkBase" not in classes
    assert "App.Intermediate" not in classes
    assert "App.Orders" not in classes
    assert "App.Orders.Index" not in methods
    assert "App.Detached" in classes


def test_exe_output_type_is_application_but_ambiguous_metadata_is_not(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    _write(tmp_path, "Local.cs", "public class Local {}")
    assert "Local" in _names(_scan(tmp_path), "unused_classes")

    _write(
        tmp_path,
        "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<OutputType>Exe</OutputType><OutputType>Library</OutputType>"
        "</PropertyGroup></Project>",
    )
    assert "Local" not in _names(_scan(tmp_path), "unused_classes")

    _write(
        tmp_path,
        "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup Condition="true">'
        "<OutputType>Exe</OutputType></PropertyGroup></Project>",
    )
    assert "Local" not in _names(_scan(tmp_path), "unused_classes")


def test_untrusted_project_xml_declarations_do_not_enable_public_demotion(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "App.csproj",
        '<!DOCTYPE Project [<!ENTITY value "Exe">]>'
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        "<OutputType>&value;</OutputType></PropertyGroup></Project>",
    )
    _write(tmp_path, "Local.cs", "public class Local {}")

    result = _scan(tmp_path)
    assert "Local" not in _names(result, "unused_classes")


@pytest.mark.parametrize(
    "project_xml",
    [
        '<Project Sdk="Microsoft.NET.Sdk"><Sdk Name="Microsoft.NET.Sdk.Web" '
        'Condition="false" /></Project>',
        '<Project Sdk="Microsoft.NET.Sdk.Web" Condition="false" />',
        '<Project Sdk="Microsoft.NET.Sdk"><Choose><When Condition="false">'
        '<Sdk Name="Microsoft.NET.Sdk.Web" /></When></Choose></Project>',
        '<Project Sdk="Microsoft.NET.Sdk" Condition="false">'
        "<PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>",
        '<Project Sdk="Microsoft.NET.Sdk"><Choose><When Condition="false">'
        "<PropertyGroup><OutputType>Exe</OutputType></PropertyGroup>"
        "</When></Choose></Project>",
        '<Project Sdk="Microsoft.NET.Sdk"><Choose><Otherwise>'
        "<PropertyGroup><OutputType>Exe</OutputType></PropertyGroup>"
        "</Otherwise></Choose></Project>",
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
        '<OutputType Condition="false">Exe</OutputType>'
        "</PropertyGroup></Project>",
    ],
)
def test_conditional_project_metadata_does_not_demote_public_api(
    tmp_path: Path, project_xml: str
) -> None:
    _write(tmp_path, "App.csproj", project_xml)
    _write(tmp_path, "PublicApi.cs", "public class PublicApi {}")

    result = _scan(tmp_path)
    assert "PublicApi" not in _names(result, "unused_classes")


def test_unrelated_conditional_property_keeps_unconditional_app_classification(
    tmp_path: Path,
) -> None:
    _write(
        tmp_path,
        "App.csproj",
        '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup Condition="false">'
        "<DefineConstants>TRACE</DefineConstants></PropertyGroup></Project>",
    )
    _write(tmp_path, "Local.cs", "public class Local {}")

    result = _scan(tmp_path)
    assert "Local" in _names(result, "unused_classes")
