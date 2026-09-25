import json

import pytest

from skylos import cli
from skylos.commands.sbom_cmd import run_sbom_command
from skylos.reporting.sbom import cyclonedx_bom
from skylos.rules.sca import vulnerability_scanner as sca


def test_csproj_inventory_distinguishes_minimum_and_exact_versions(tmp_path):
    project = tmp_path / "App.csproj"
    project.write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        '  <!-- <PackageReference Include="Commented" Version="[9.9.9]" /> -->\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Dapper" Version="2.1.66" />\n'
        '    <PackageReference Include="Pinned"><Version>[3.14.0]</Version>'
        "</PackageReference>\n"
        '    <PackageReference Include="PreRelease" VersionOverride="[1.2.3-beta.1]" />\n'
        '    <PackageReference Include="Floating" Version="2.*" />\n'
        '    <PackageReference Include="Dynamic" Version="$(DynamicVersion)" />\n'
        '    <PackageReference Include="Central" />\n'
        '    <PackageReference Update="Imported" Version="[1.0.0]" />\n'
        "  </ItemGroup>\n"
        '  <Target Name="Untrusted"><Exec Command="never execute target scripts" />'
        "</Target>\n"
        "</Project>\n",
        encoding="utf-8",
    )

    inventory = sca.collect_dependencies(tmp_path)

    assert [(dep["name"], dep["version"], dep["exact"]) for dep in inventory] == [
        ("Dapper", "2.1.66", False),
        ("Pinned", "3.14.0", True),
        ("PreRelease", "1.2.3-beta.1", True),
    ]
    assert all(dep["ecosystem"] == "NuGet" for dep in inventory)
    assert inventory[0]["line"] == 4
    assert inventory.receipt["supported_manifest_count"] == 1
    assert inventory.receipt["unresolved_dependency_count"] == 6
    assert inventory.receipt["nuget_unresolved_count"] == 6
    assert inventory.receipt["nuget_unpinned_count"] == 1
    assert inventory.receipt["nuget_override_count"] == 1
    assert inventory.receipt["complete"] is False
    assert inventory.receipt["status"] == "complete_with_unresolved_versions"
    assert inventory.receipt["category_complete"] is False
    assert "nuget_minimum_versions_not_exact" in inventory.receipt["limitations"]
    assert "nuget_version_overrides_not_evaluated" in inventory.receipt["limitations"]
    assert inventory.manifest_gaps == [
        {
            "file": str(project),
            "ecosystem": "NuGet",
            "unresolved_dependency_count": 6,
        }
    ]


def test_nuget_sca_queries_only_unconditional_exact_pins(monkeypatch, tmp_path):
    project = tmp_path / "App.csproj"
    project.write_text(
        "<Project><ItemGroup>\n"
        '  <PackageReference Include="Minimum" Version="2.1.66" />\n'
        '  <PackageReference Include="Exact" Version="[1.2.3]" />\n'
        '  <PackageReference Include="Conditional" Version="[4.5.6]" '
        "Condition=\"'$(TargetFramework)' == 'net8.0'\" />\n"
        '  <PackageReference Include="Override" VersionOverride="[8.0.0]" />\n'
        '  <PackageReference Include="Range" Version="[1.0,2.0)" />\n'
        '</ItemGroup><Target Name="Later"><ItemGroup>'
        '<PackageReference Include="FromTarget" Version="[9.0.0]" />'
        "</ItemGroup></Target></Project>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sca, "_requests", object())
    queried = []

    def fake_query(dependencies, _cache):
        queried.extend(dependencies)
        finding = sca._make_finding(
            dependencies[0],
            {"vuln_id": "GHSA-nuget-test", "summary": "known vulnerable pin"},
        )
        return sca.OsvQueryResult(
            [finding],
            receipt={"status": "complete", "complete": True},
        )

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    result = sca.scan_dependencies(tmp_path)

    assert [(dep["ecosystem"], dep["name"], dep["version"]) for dep in queried] == [
        ("NuGet", "Exact", "1.2.3")
    ]
    assert result[0]["rule_id"] == "SKY-SCA-GHSA-nuget-test"
    assert result[0]["metadata"]["ecosystem"] == "NuGet"
    assert result[0]["metadata"]["exact"] is True
    assert result.receipt["queried_dependency_count"] == 1
    assert result.receipt["unresolved_dependency_count"] == 5
    assert result.receipt["nuget_unresolved_count"] == 5
    assert result.receipt["nuget_conditional_count"] == 2
    assert result.receipt["nuget_override_count"] == 1
    assert "nuget_conditions_not_evaluated" in result.receipt["limitations"]
    assert result.receipt["complete"] is False
    assert result.receipt["status"] == "complete_with_unresolved_versions"
    assert result.receipt["category_complete"] is False


def test_conditional_version_children_are_not_queried(monkeypatch, tmp_path):
    (tmp_path / "App.csproj").write_text(
        "<Project><ItemGroup>\n"
        '  <PackageReference Include="Exact" Version="[1.2.3]" />\n'
        '  <PackageReference Include="ConditionalVersion">'
        "<Version Condition=\"'$(TargetFramework)' == 'net8.0'\">"
        "[2.0.0]</Version></PackageReference>\n"
        '  <PackageReference Include="ConditionalOverride">'
        "<VersionOverride Condition=\"'$(UseOverride)' == 'true'\">"
        "[3.0.0]</VersionOverride></PackageReference>\n"
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sca, "_requests", object())
    queried = []

    def fake_query(dependencies, _cache):
        queried.extend(dependencies)
        return sca.OsvQueryResult([], receipt={"status": "complete", "complete": True})

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    result = sca.scan_dependencies(tmp_path)

    assert [dep["name"] for dep in queried] == ["Exact"]
    assert result.receipt["nuget_conditional_count"] == 2
    assert result.receipt["nuget_override_count"] == 1
    assert result.receipt["unresolved_dependency_count"] == 2
    assert result.receipt["nuget_unresolved_count"] == 2
    assert result.receipt["complete"] is False
    assert result.receipt["status"] == "complete_with_unresolved_versions"


@pytest.mark.parametrize(
    "mutation",
    [
        '<PackageReference Update="UPDATED" Version="[9.0.0]" />',
        '<PackageReference Remove="UPDATED" />',
    ],
)
def test_package_reference_mutation_invalidates_matching_exact_pin(
    monkeypatch, tmp_path, mutation
):
    (tmp_path / "App.csproj").write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="Updated" Version="[1.0.0]" />'
        '<PackageReference Include="Clean" Version="[2.0.0]" />'
        f"{mutation}"
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sca, "_requests", object())
    queried = []

    def fake_query(dependencies, _cache):
        queried.extend(dependencies)
        return sca.OsvQueryResult([], receipt={"status": "complete", "complete": True})

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    result = sca.scan_dependencies(tmp_path)

    assert [(dep["name"], dep["version"]) for dep in queried] == [("Clean", "2.0.0")]
    assert result.receipt["nuget_reference_mutation_count"] == 1
    assert result.receipt["unresolved_dependency_count"] == 2
    assert result.receipt["nuget_unresolved_count"] == 2
    assert "nuget_reference_mutations_not_evaluated" in result.receipt["limitations"]
    assert result.receipt["complete"] is False
    assert result.receipt["status"] == "complete_with_unresolved_versions"


def test_dynamic_package_reference_update_invalidates_all_exact_pins(
    monkeypatch, tmp_path
):
    (tmp_path / "App.csproj").write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="First" Version="[1.0.0]" />'
        '<PackageReference Include="Second" Version="[2.0.0]" />'
        '<PackageReference Update="$(PackageToUpdate)" Version="[9.0.0]" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sca, "_requests", object())
    queried = []

    def fake_query(dependencies, _cache):
        queried.extend(dependencies)
        return sca.OsvQueryResult([], receipt={"status": "complete", "complete": True})

    monkeypatch.setattr(sca, "_query_osv_batch", fake_query)

    result = sca.scan_dependencies(tmp_path)

    assert queried == []
    assert result.receipt["nuget_reference_mutation_count"] == 2
    assert result.receipt["unresolved_dependency_count"] == 3
    assert result.receipt["nuget_unresolved_count"] == 3
    assert result.receipt["queried_dependency_count"] == 0
    assert result.receipt["complete"] is False
    assert result.receipt["status"] == "complete_with_unresolved_versions"


def test_nuget_minimum_version_is_coverage_gap_not_cli_failure(monkeypatch, tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "App.csproj").write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="Dapper" Version="2.1.66" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sca, "_requests", object())
    report_path = tmp_path / "report.json"
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(project),
            "-a",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
            "--output",
            str(report_path),
        ],
    )

    exit_code = 0
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code

    assert exit_code == 0
    coverage = json.loads(report_path.read_text(encoding="utf-8"))["analysis_summary"][
        "sca_coverage"
    ]
    assert coverage["status"] == "complete_with_unresolved_versions"
    assert coverage["complete"] is False
    assert coverage["category_complete"] is False
    assert coverage["nuget_unresolved_count"] == 1


def test_central_only_nuget_version_has_explicit_gap_evidence(monkeypatch, tmp_path):
    (tmp_path / "App.csproj").write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="Central" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sca, "_requests", object())

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "complete_with_unresolved_versions"
    assert result.receipt["complete"] is False
    assert result.receipt["category_complete"] is False
    assert result.receipt["unresolved_dependency_count"] == 1
    assert result.receipt["nuget_unresolved_count"] == 1
    assert result.receipt["query"]["complete"] is True


def test_nuget_query_failure_remains_operationally_incomplete(monkeypatch, tmp_path):
    (tmp_path / "App.csproj").write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="Exact" Version="[1.0.0]" />'
        '<PackageReference Include="Minimum" Version="2.0.0" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    monkeypatch.setattr(sca, "_requests", object())
    monkeypatch.setattr(
        sca,
        "_query_osv_batch",
        lambda _deps, _cache: sca.OsvQueryResult(
            [], receipt={"status": "incomplete", "complete": False}
        ),
    )

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False


def test_csproj_line_numbers_follow_xml_elements_not_comments(tmp_path):
    (tmp_path / "App.csproj").write_text(
        "<Project>\n"
        '  <!-- <PackageReference Include="Duplicate" Version="[9.9.9]" /> -->\n'
        "  <ItemGroup>\n"
        '    <PackageReference Include="Duplicate" Version="[1.0.0]" />\n'
        '    <PackageReference Include="Duplicate" Version="[1.0.0]" />\n'
        "  </ItemGroup>\n"
        "</Project>\n",
        encoding="utf-8",
    )

    inventory = sca.collect_dependencies(tmp_path)

    assert len(inventory) == 1
    assert inventory[0]["line"] == 4
    assert [item["line"] for item in inventory[0]["dependency_occurrences"]] == [
        4,
        5,
    ]


def test_deep_valid_csproj_is_inventoried_without_recursion_limit(tmp_path):
    depth = 1_500
    (tmp_path / "App.csproj").write_text(
        "<Project>"
        + "<ItemGroup>" * depth
        + '<PackageReference Include="Deep" Version="[1.2.3]" />'
        + "</ItemGroup>" * depth
        + "</Project>",
        encoding="utf-8",
    )

    inventory = sca.collect_dependencies(tmp_path)

    assert [(dep["name"], dep["version"]) for dep in inventory] == [("Deep", "1.2.3")]
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["parse_error_count"] == 0


def test_only_exact_nuget_pins_have_complete_direct_inventory(tmp_path):
    (tmp_path / "App.csproj").write_text(
        '<Project xmlns="urn:msbuild"><ItemGroup>'
        '<PackageReference Include="Exact" Version="[1.2.3]" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )
    (tmp_path / "Other.csproj").write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="exact" Version="[1.2.3]" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    inventory = sca.collect_dependencies(tmp_path)

    assert [(dep["name"], dep["version"]) for dep in inventory] == [("Exact", "1.2.3")]
    assert len(inventory[0]["dependency_occurrences"]) == 2
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["unresolved_dependency_count"] == 0


def test_nuget_versions_are_normalized_for_osv_identity(tmp_path):
    (tmp_path / "App.csproj").write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="Normalized" Version="[01.00.0.0+build]" />'
        '<PackageReference Include="Short" Version="[2]" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    inventory = sca.collect_dependencies(tmp_path)

    assert [(dep["name"], dep["version"]) for dep in inventory] == [
        ("Normalized", "1.0.0"),
        ("Short", "2.0.0"),
    ]
    assert inventory.receipt["complete"] is True


def test_nuget_sbom_exports_only_exact_pins_and_preserves_gap(tmp_path):
    project = tmp_path / "App.csproj"
    project.write_text(
        "<Project><ItemGroup>"
        '<PackageReference Include="Newtonsoft.Json" Version="[13.0.1]" />'
        '<PackageReference Include="Dapper" Version="2.1.66" />'
        "</ItemGroup></Project>",
        encoding="utf-8",
    )

    document = cyclonedx_bom(sca.collect_dependencies(tmp_path), tmp_path)

    assert [item["purl"] for item in document["components"]] == [
        "pkg:nuget/newtonsoft.json@13.0.1"
    ]
    assert document.receipt["complete"] is False
    assert document.receipt["unresolved_dependency_count"] == 1
    assert document.receipt["invalid_identity_count"] == 1


def test_sbom_output_cannot_replace_csproj(tmp_path, capsys):
    project = tmp_path / "App.csproj"
    contents = "<Project><ItemGroup /></Project>"
    project.write_text(contents, encoding="utf-8")

    assert run_sbom_command([str(tmp_path), "-o", str(project)]) == 2
    assert project.read_text(encoding="utf-8") == contents
    assert "must not overwrite a dependency input" in capsys.readouterr().err


@pytest.mark.parametrize(
    "contents",
    [
        '<!DOCTYPE Project [<!ENTITY payload "[9.9.9]">]>'
        '<Project><PackageReference Include="Injected" Version="&payload;" />'
        "</Project>",
        '<!DOCTYPE Project SYSTEM "file:///etc/passwd">'
        '<Project><PackageReference Include="External" Version="[1.0.0]" />'
        "</Project>",
        '<Project><PackageReference Include="Broken" Version="[1.0.0]" />',
        '<NotProject><PackageReference Include="WrongRoot" Version="[1.0.0]" />'
        "</NotProject>",
    ],
)
def test_csproj_rejects_unsafe_or_invalid_xml_with_incomplete_receipt(
    tmp_path, contents
):
    project = tmp_path / "App.csproj"
    project.write_text(contents, encoding="utf-8")

    inventory = sca.collect_dependencies(tmp_path)

    assert inventory == []
    assert inventory.receipt["parse_error_count"] == 1
    assert inventory.receipt["complete"] is False
    assert inventory.receipt["status"] == "incomplete"
    assert inventory.receipt["supported_manifest_candidate_count"] == 1


def test_csproj_symlink_is_not_read(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "outside.csproj"
    target.write_text(
        '<Project><PackageReference Include="Target" Version="[1.0.0]" /></Project>',
        encoding="utf-8",
    )
    project = repo / "App.csproj"
    try:
        project.symlink_to(target)
    except OSError:
        pytest.skip("filesystem does not allow symlinks")

    assert sca.parse_csproj(project) == []
    inventory = sca.collect_dependencies(repo)
    assert inventory == []
    assert inventory.receipt["parse_error_count"] == 1
