"""Offline export contracts: components are inventory, not advisory matches."""

import json
from pathlib import Path

import pytest

from skylos.commands.sbom_cmd import run_sbom_command
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    write_text_no_symlink,
)
from skylos.reporting.sbom import cyclonedx_bom
from skylos.rules.sca import vulnerability_scanner as sca


def _write(root, filename, text):
    assert write_text_no_symlink(root / filename, text)


def _npm(root):
    data = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"parent": "^1"}},
            "node_modules/parent": {
                "version": "1.0.0",
                "dependencies": {"@example/child": "^2"},
            },
            "node_modules/@example/child": {"version": "2.0.0", "dev": True},
            "node_modules/other/node_modules/@example/child": {
                "version": "3.0.0",
                "optional": True,
            },
        },
    }
    _write(root, "package-lock.json", json.dumps(data))


def _receipt(document):
    return json.loads(
        next(
            prop["value"]
            for prop in document["metadata"]["properties"]
            if prop["name"] == "skylos:inventory:receipt"
        )
    )


@pytest.fixture(autouse=True)
def no_advisory_calls(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("SBOM must not query advisories")

    monkeypatch.setattr(sca, "_requests", None)
    monkeypatch.setattr(sca, "_query_osv_batch", forbidden)


def test_inventory_is_available_without_requests(tmp_path):
    _npm(tmp_path)
    inventory = sca.collect_dependencies(tmp_path)
    assert len(inventory) == 3
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["queried_dependency_count"] == 0
    assert inventory.receipt["local_lockfile_package_count"] == 1
    assert sca.scan_dependencies(tmp_path).receipt["status"] == "unavailable"


def test_cyclonedx_inventory_versions_context_and_resolved_graph(tmp_path):
    _npm(tmp_path)
    document = cyclonedx_bom(sca.collect_dependencies(tmp_path), tmp_path)
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["metadata"]["lifecycles"] == [{"phase": "pre-build"}]
    components = {item["purl"]: item for item in document["components"]}
    assert set(components) == {
        "pkg:npm/parent@1.0.0",
        "pkg:npm/%40example/child@2.0.0",
        "pkg:npm/%40example/child@3.0.0",
    }
    child = components["pkg:npm/%40example/child@2.0.0"]
    assert child["group"] == "@example"
    assert child["name"] == "child"
    assert child["evidence"]["occurrences"] == [
        {"location": "package-lock.json", "line": 1}
    ]
    occurrence = json.loads(child["properties"][1]["value"])
    assert occurrence["dependency_dev"] is True
    assert occurrence["file"] == "package-lock.json"
    assert {item["ref"]: item["dependsOn"] for item in document["dependencies"]} == {
        "pkg:npm/parent@1.0.0": ["pkg:npm/%40example/child@2.0.0"],
        "pkg:npm/%40example/child@2.0.0": [],
        "pkg:npm/%40example/child@3.0.0": [],
    }
    assert document["compositions"] == [{"aggregate": "incomplete"}]
    assert "vulnerabilities" not in document
    assert all(
        "licenses" not in item and "scope" not in item for item in components.values()
    )
    assert "queried_dependency_count" not in _receipt(document)
    assert str(tmp_path) not in json.dumps(document)


def test_pypi_and_go_identifiers_are_encoded(tmp_path):
    _write(tmp_path, "requirements.txt", "My_Package==1.2.3+local\n")
    _write(
        tmp_path,
        "go.mod",
        "module example.org/app\nrequire example.org/team/lib/v2 v2.1.0\n",
    )
    document = cyclonedx_bom(sca.collect_dependencies(tmp_path), tmp_path)
    assert {item["purl"] for item in document["components"]} == {
        "pkg:pypi/my-package@1.2.3%2Blocal",
        "pkg:golang/example.org/team/lib/v2@v2.1.0",
    }
    assert document["dependencies"] == []  # manifest pins do not define package edges


def test_same_identity_occurrences_survive_and_output_is_stable(tmp_path):
    _npm(tmp_path)
    _write(tmp_path, "package.json", '{"dependencies":{"parent":"1.0.0"}}')
    inventory = sca.collect_dependencies(tmp_path)
    first = cyclonedx_bom(inventory, tmp_path)
    inventory.reverse()
    for entry in inventory:
        entry["dependency_occurrences"].reverse()
    assert cyclonedx_bom(inventory, tmp_path) == first
    parent = next(item for item in first["components"] if item["name"] == "parent")
    assert {item["location"] for item in parent["evidence"]["occurrences"]} == {
        "package-lock.json",
        "package.json",
    }


def test_checkout_location_does_not_change_document(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    _npm(first)
    _npm(second)
    assert cyclonedx_bom(sca.collect_dependencies(first), first) == cyclonedx_bom(
        sca.collect_dependencies(second), second
    )


def test_cli_defaults_to_json_stdout(tmp_path, capsys):
    _npm(tmp_path)
    assert run_sbom_command([str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert len(json.loads(captured.out)["components"]) == 3
    assert captured.err == ""


def test_cli_dispatch_and_help(tmp_path, monkeypatch, capsys):
    import skylos.cli as cli

    _npm(tmp_path)
    monkeypatch.setattr("sys.argv", ["skylos", "sbom", str(tmp_path)])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 0
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"
    monkeypatch.setattr("sys.argv", ["skylos", "sbom", "--help"])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 0
    assert "--output" in capsys.readouterr().out


def test_cli_writes_requested_file(tmp_path, capsys):
    _npm(tmp_path)
    output = tmp_path / "sbom.cdx.json"
    assert run_sbom_command([str(tmp_path), "-o", str(output)]) == 0
    assert json.loads(output.read_text())["bomFormat"] == "CycloneDX"
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("filename", ["poetry.lock", "yarn.lock"])
def test_incomplete_lockfile_retains_available_components(tmp_path, capsys, filename):
    _npm(tmp_path)
    _write(tmp_path, filename, "invalid input\n")
    assert run_sbom_command([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert len(document["components"]) == 3
    assert _receipt(document)["parse_error_count"] == 1
    assert _receipt(document)["complete"] is False
    assert document["dependencies"] == []
    assert "incomplete" in captured.err


def test_invalid_pipfile_lock_is_explicit_export_gap(tmp_path, capsys):
    _npm(tmp_path)
    _write(tmp_path, "Pipfile.lock", "{}")
    assert run_sbom_command([str(tmp_path)]) == 2
    receipt = _receipt(json.loads(capsys.readouterr().out))
    assert receipt["lockfile_candidate_count"] == 2
    assert receipt["parse_error_count"] == 1
    assert receipt["unsupported_lockfile_count"] == 0
    assert receipt["complete"] is False


def test_range_only_inventory_is_not_a_successful_empty_sbom(tmp_path, capsys):
    _write(tmp_path, "package.json", '{"dependencies":{"example":"^1.0.0"}}')
    assert sca.collect_dependencies(tmp_path).receipt["complete"] is True
    assert run_sbom_command([str(tmp_path)]) == 2
    document = json.loads(capsys.readouterr().out)
    assert document["components"] == []
    assert _receipt(document)["unresolved_dependency_count"] == 1


def test_range_with_lock_preserves_freshness_limitations(tmp_path, capsys):
    _npm(tmp_path)
    _write(tmp_path, "package.json", '{"dependencies":{"parent":"^1"}}')
    assert run_sbom_command([str(tmp_path)]) == 0
    receipt = _receipt(json.loads(capsys.readouterr().out))
    assert "lockfile_freshness_not_verified" in receipt["limitations"]
    assert receipt["unresolved_dependency_count"] == 1


def test_no_supported_inputs_is_incomplete(tmp_path, capsys):
    assert run_sbom_command([str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().out)["components"] == []


@pytest.mark.parametrize("target", ["missing", "file"])
def test_invalid_root_is_rejected(tmp_path, capsys, target):
    _write(tmp_path, "file", "data")
    assert run_sbom_command([str(tmp_path / target)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "directory" in captured.err


@pytest.mark.parametrize(
    "name", ["package.json", "PACKAGE.JSON", "Poetry.Lock", "Pipfile.lock"]
)
def test_output_cannot_replace_dependency_input(tmp_path, capsys, name):
    _write(tmp_path, name, "preserve input")
    assert run_sbom_command([str(tmp_path), "--output", str(tmp_path / name)]) == 2
    assert (
        read_project_text_no_symlink(tmp_path, tmp_path / name, max_bytes=1024)
        == "preserve input"
    )
    assert "overwrite" in capsys.readouterr().err


def test_missing_output_directory_is_error_not_stdout_fallback(tmp_path, capsys):
    _npm(tmp_path)
    assert (
        run_sbom_command([str(tmp_path), "-o", str(tmp_path / "absent/bom.json")]) == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "safely write" in captured.err


def test_invalid_identity_is_a_gap_not_exported_text(tmp_path, capsys):
    _write(tmp_path, "go.mod", "require invalid:module v1.2.3\n")
    assert run_sbom_command([str(tmp_path)]) == 2
    document = json.loads(capsys.readouterr().out)
    assert document["components"] == []
    assert _receipt(document)["invalid_identity_count"] == 1
    assert "invalid:module" not in json.dumps(document)


def test_incomplete_edges_are_not_exported_as_known_leaf(tmp_path):
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/example": {"version": "1.0.0", "dependencies": []}
                },
            }
        ),
    )
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["unresolved_lockfile_dependency_count"]
    document = cyclonedx_bom(inventory, tmp_path)
    assert len(document["components"]) == 1
    assert document["dependencies"] == []


def test_inventory_limit_retains_prior_components_without_advisories(
    tmp_path, monkeypatch
):
    _write(tmp_path, "requirements.txt", "example==1.0.0\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    _npm(nested)
    monkeypatch.setattr(sca, "MAX_SUPPORTED_MANIFESTS", 1)
    inventory = sca.collect_dependencies(tmp_path)
    assert len(inventory) == 1
    document = cyclonedx_bom(inventory, tmp_path)
    assert document.receipt["complete"] is False
    assert document.receipt["limit_reasons"] == ["manifest_count_limit_exceeded"]
    assert len(document["components"]) == 1


def test_context_does_not_include_source_transport_or_absolute_location(tmp_path):
    dependency = {
        "name": "example",
        "version": "1.0.0",
        "ecosystem": "npm",
        "file": str(Path("/outside") / "package.json"),
        "line": 1,
        "snippet": "not exported",
        "dependency_markers": {
            "source": "not exported",
            "reference": "https://example.invalid/source",
        },
    }
    inventory = sca.DependencyInventory([dependency], receipt={"complete": True})
    document = cyclonedx_bom(inventory, tmp_path)
    serialized = json.dumps(document)
    assert "not exported" not in serialized
    assert "https://example.invalid/source" not in serialized
    assert "/outside" not in serialized
    assert "redacted:source:" in serialized
