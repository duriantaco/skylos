"""Shrinkwrap export uses offline data and npm's same-directory precedence."""

import json
import socket
import subprocess

import pytest

from skylos.commands.sbom_cmd import run_sbom_command
from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    write_text_no_symlink,
)
from skylos.reporting.sbom import cyclonedx_bom
from skylos.rules.sca import vulnerability_scanner as sca


def _write(root, filename, data):
    text = data if isinstance(data, str) else json.dumps(data, indent=2)
    assert write_text_no_symlink(root / filename, text)


def _lock(version="1.0.0", *, lockfile_version=3):
    entry = {
        "version": version,
        "dev": True,
        "optional": True,
        "os": ["linux", "!win32"],
        "cpu": ["x64"],
        "engines": {"node": ">=18"},
    }
    if lockfile_version == 1:
        return {"lockfileVersion": 1, "dependencies": {"example": entry}}
    return {
        "lockfileVersion": lockfile_version,
        "packages": {
            "": {"name": "local-app", "devDependencies": {"example": "^1"}},
            "node_modules/example": entry,
        },
    }


def _receipt(document):
    return json.loads(
        next(
            item["value"]
            for item in document["metadata"]["properties"]
            if item["name"] == "skylos:inventory:receipt"
        )
    )


def _occurrences(component):
    return [
        json.loads(item["value"])
        for item in component["properties"]
        if item["name"] == "skylos:dependency:occurrence"
    ]


@pytest.fixture(autouse=True)
def no_network_or_project_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Shrinkwrap SBOM must not access networks or execute a project")

    monkeypatch.setattr(sca, "_requests", None)
    monkeypatch.setattr(sca, "_query_osv_batch", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("lockfile_version", [1, 2, 3])
def test_shrinkwrap_formats_export_offline_with_source_and_environment_context(
    tmp_path, capsys, lockfile_version
):
    _write(
        tmp_path,
        "npm-shrinkwrap.json",
        _lock(lockfile_version=lockfile_version),
    )
    _write(tmp_path, "package.json", {"scripts": {"preinstall": "exit 97"}})

    assert run_sbom_command([str(tmp_path)]) == 0

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert captured.err == ""
    assert [item["purl"] for item in document["components"]] == [
        "pkg:npm/example@1.0.0"
    ]
    component = document["components"][0]
    assert component["evidence"]["occurrences"][0]["location"] == "npm-shrinkwrap.json"
    assert component["evidence"]["occurrences"][0]["line"] > 1
    occurrence = _occurrences(component)[0]
    assert occurrence["file"] == "npm-shrinkwrap.json"
    assert occurrence["lockfile_version"] == lockfile_version
    assert occurrence["source_type"] == "registry_unspecified"
    assert occurrence["dependency_dev"] is True
    assert occurrence["dependency_optional"] is True
    assert occurrence["dependency_markers"] == {
        "os": ["linux", "!win32"],
        "cpu": ["x64"],
        "engines": {"node": ">=18"},
    }
    receipt = _receipt(document)
    assert receipt["complete"] is True
    assert receipt["supported_lockfile_count"] == 1
    assert receipt["unsupported_lockfile_count"] == 0
    assert "queried_dependency_count" not in receipt
    assert "vulnerabilities" not in document
    assert str(tmp_path) not in captured.out


@pytest.mark.parametrize("ignored_contents", [_lock("9.0.0"), "{invalid"])
def test_shrinkwrap_overrides_package_lock_and_exports_relative_receipt(
    tmp_path, capsys, ignored_contents
):
    _write(tmp_path, "npm-shrinkwrap.json", _lock())
    _write(tmp_path, "package-lock.json", ignored_contents)

    assert run_sbom_command([str(tmp_path)]) == 0

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert [item["purl"] for item in document["components"]] == [
        "pkg:npm/example@1.0.0"
    ]
    receipt = _receipt(document)
    assert receipt["complete"] is True
    assert receipt["parse_error_count"] == 0
    assert receipt["supported_lockfile_count"] == 1
    assert receipt["ignored_lockfile_count"] == 1
    assert receipt["ignored_lockfiles"] == [
        {
            "file": "package-lock.json",
            "selected_file": "npm-shrinkwrap.json",
            "reason": "npm_shrinkwrap_precedence",
        }
    ]
    assert str(tmp_path) not in captured.out


def test_shrinkwrap_keeps_workspace_origins_transitives_and_multiple_versions(tmp_path):
    _write(
        tmp_path,
        "npm-shrinkwrap.json",
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "workspaces": ["packages/*"]},
                "packages/tool": {
                    "name": "local-tool",
                    "dependencies": {"parent": "^1"},
                },
                "node_modules/local-tool": {"link": True, "resolved": "packages/tool"},
                "node_modules/parent": {
                    "version": "1.0.0",
                    "dependencies": {"child": "^2"},
                },
                "node_modules/child": {"version": "2.0.0"},
                "node_modules/other/node_modules/child": {
                    "version": "3.0.0",
                    "optional": True,
                },
            },
        },
    )

    document = cyclonedx_bom(sca.collect_dependencies(tmp_path), tmp_path)

    components = {item["purl"]: item for item in document["components"]}
    assert set(components) == {
        "pkg:npm/parent@1.0.0",
        "pkg:npm/child@2.0.0",
        "pkg:npm/child@3.0.0",
    }
    parent = _occurrences(components["pkg:npm/parent@1.0.0"])[0]
    assert parent["dependency_roots"] == ["packages/tool"]
    assert parent["dependency_kind"] == "direct"
    child = _occurrences(components["pkg:npm/child@2.0.0"])[0]
    assert child["dependency_kind"] == "transitive"
    assert _receipt(document)["local_lockfile_package_count"] == 3
    assert {item["ref"]: item["dependsOn"] for item in document["dependencies"]} == {
        "pkg:npm/parent@1.0.0": ["pkg:npm/child@2.0.0"],
        "pkg:npm/child@2.0.0": [],
        "pkg:npm/child@3.0.0": [],
    }


@pytest.mark.parametrize("failure", ["malformed", "symlink"])
def test_failed_shrinkwrap_retains_unrelated_components_without_fallback(
    tmp_path, capsys, failure
):
    _write(tmp_path, "package-lock.json", _lock("9.0.0"))
    _write(tmp_path, "requirements.txt", "urllib3==1.26.4\n")
    if failure == "symlink":
        (tmp_path / "npm-shrinkwrap.json").symlink_to(tmp_path / "package-lock.json")
    else:
        _write(tmp_path, "npm-shrinkwrap.json", "{invalid")

    assert run_sbom_command([str(tmp_path), "--strict"]) == 2

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert [item["purl"] for item in document["components"]] == [
        "pkg:pypi/urllib3@1.26.4"
    ]
    receipt = _receipt(document)
    assert receipt["complete"] is False
    assert receipt["parse_error_count"] == 1
    assert receipt["ignored_lockfile_count"] == 1
    assert document["dependencies"] == []
    assert "incomplete" in captured.err
    assert str(tmp_path) not in captured.out


def test_private_shrinkwrap_source_is_not_exported_as_public_registry_package(
    tmp_path, capsys
):
    selected = _lock()
    selected["packages"]["node_modules/example"]["resolved"] = (
        "https://private.invalid/example.tgz"
    )
    _write(tmp_path, "npm-shrinkwrap.json", selected)
    _write(tmp_path, "package-lock.json", _lock("9.0.0"))
    _write(tmp_path, "package.json", {"dependencies": {"example": "1.0.0"}})
    _write(tmp_path, "requirements.txt", "urllib3==1.26.4\n")

    assert run_sbom_command([str(tmp_path), "--strict"]) == 2

    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert [item["purl"] for item in document["components"]] == [
        "pkg:pypi/urllib3@1.26.4"
    ]
    receipt = _receipt(document)
    assert receipt["manifest_source_conflict_count"] == 1
    assert receipt["ignored_lockfile_count"] == 1
    assert receipt["complete"] is False
    assert receipt["lockfile_issues"][0]["file"] == "npm-shrinkwrap.json"
    assert receipt["lockfile_issues"][0]["reason"] == "non_registry_source"
    assert "private.invalid" not in captured.out
    assert str(tmp_path) not in captured.out


@pytest.mark.parametrize("filename", ["npm-shrinkwrap.json", "NPM-SHRINKWRAP.JSON"])
def test_sbom_cannot_overwrite_shrinkwrap_input(tmp_path, capsys, filename):
    _write(tmp_path, filename, "preserve input")

    assert run_sbom_command([str(tmp_path), "-o", str(tmp_path / filename)]) == 2

    assert (
        read_project_text_no_symlink(tmp_path, tmp_path / filename, max_bytes=1024)
        == "preserve input"
    )
    assert "overwrite" in capsys.readouterr().err


def test_ignored_lockfile_receipt_counts_all_but_bounds_examples(tmp_path):
    for number in range(27):
        project = tmp_path / f"project-{number:02d}"
        project.mkdir()
        _write(project, "package-lock.json", _lock("9.0.0"))
        _write(project, "npm-shrinkwrap.json", _lock())

    document = cyclonedx_bom(sca.collect_dependencies(tmp_path), tmp_path)

    receipt = _receipt(document)
    assert receipt["complete"] is True
    assert receipt["ignored_lockfile_count"] == 27
    assert len(receipt["ignored_lockfiles"]) == 25
    assert receipt["ignored_lockfiles"][0] == {
        "file": "project-00/package-lock.json",
        "selected_file": "project-00/npm-shrinkwrap.json",
        "reason": "npm_shrinkwrap_precedence",
    }
    assert [item["purl"] for item in document["components"]] == [
        "pkg:npm/example@1.0.0"
    ]
    assert len(_occurrences(document["components"][0])) == 27
    assert str(tmp_path) not in json.dumps(document)


def test_precedence_receipt_is_stable_across_checkout_locations(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    for root in (first, second):
        root.mkdir()
        _write(root, "package-lock.json", _lock("9.0.0"))
        _write(root, "npm-shrinkwrap.json", _lock())

    assert cyclonedx_bom(sca.collect_dependencies(first), first) == cyclonedx_bom(
        sca.collect_dependencies(second), second
    )


def test_outside_root_ignored_receipt_paths_are_not_disclosed(tmp_path):
    inventory = sca.DependencyInventory(
        receipt={
            "complete": True,
            "ignored_lockfile_count": 1,
            "ignored_lockfiles": [
                {
                    "file": "/outside/package-lock.json",
                    "selected_file": "/outside/npm-shrinkwrap.json",
                    "reason": "npm_shrinkwrap_precedence",
                }
            ],
        }
    )

    document = cyclonedx_bom(inventory, tmp_path)

    assert _receipt(document)["ignored_lockfiles"] == [
        {
            "file": "[outside-scan-root]",
            "selected_file": "[outside-scan-root]",
            "reason": "npm_shrinkwrap_precedence",
        }
    ]
    assert "/outside" not in json.dumps(document)
