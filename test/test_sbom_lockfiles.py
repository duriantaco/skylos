"""Offline end-to-end SBOM checks using trusted synthetic lockfile data."""

import json

import pytest

from skylos.commands.sbom_cmd import run_sbom_command
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.sbom import cyclonedx_bom
from skylos.rules.sca import vulnerability_scanner as sca


POETRY = """[[package]]
name = "parent"
version = "1.0.0"
groups = ["main", "dev"]
optional = true
python-versions = ">=3.9"
markers = {main = 'sys_platform == "win32"', dev = 'python_version < "3.12"'}
[package.dependencies]
child = {version = "2.0.0", optional = true, extras = ["fast"]}
[package.extras]
speed = ["child (>=2)"]

[[package]]
name = "child"
version = "2.0.0"
groups = ["dev"]
optional = true
python-versions = ">=3.10"

[extras]
web = ["parent"]
[metadata]
lock-version = "2.1"
python-versions = ">=3.9"
"""

CLASSIC = """# yarn lockfile v1

parent@^1:
  version "1.0.0"
  dependencies:
    child "^2"

child@^2:
  version "2.0.0"
"""


def _berry():
    return {
        "__metadata": {"version": 8},
        "app@workspace:.": {
            "version": "0.0.0-use.local",
            "resolution": "app@workspace:.",
            "linkType": "soft",
            "dependencies": {"parent": "npm:^1"},
        },
        "parent@npm:^1": {
            "version": "1.0.0",
            "resolution": "parent@npm:1.0.0",
            "linkType": "hard",
            "dependencies": {"child": "npm:^2"},
            "dependenciesMeta": {"child": {"optional": True}},
        },
        "child@npm:^2": {
            "version": "2.0.0",
            "resolution": "child@npm:2.0.0",
            "linkType": "hard",
            "conditions": "os=linux & cpu=x64",
        },
    }


def _write(root, filename, value):
    assert write_text_no_symlink(root / filename, value)


def _export(root):
    return cyclonedx_bom(sca.collect_dependencies(root), root)


def _components(document):
    return {item["purl"]: item for item in document["components"]}


def _occurrences(component):
    return [
        json.loads(item["value"])
        for item in component["properties"]
        if item["name"] == "skylos:dependency:occurrence"
    ]


def _graph(document):
    return {item["ref"]: item["dependsOn"] for item in document["dependencies"]}


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("SBOM export must not query advisories")

    monkeypatch.setattr(sca, "_requests", None)
    monkeypatch.setattr(sca, "_query_osv_batch", forbidden)


def test_poetry_metadata_survives_collection_and_export(tmp_path):
    _write(tmp_path, "poetry.lock", POETRY)
    document = _export(tmp_path)
    assert document.receipt["complete"] is True
    components = _components(document)
    assert set(components) == {"pkg:pypi/parent@1.0.0", "pkg:pypi/child@2.0.0"}
    occurrence = _occurrences(components["pkg:pypi/parent@1.0.0"])[0]
    assert occurrence["file"] == "poetry.lock"
    assert occurrence["dependency_groups"] == ["dev", "main"]
    assert occurrence["dependency_optional"] is True
    assert occurrence["dependency_dev"] is False
    assert (
        occurrence["dependency_markers"]["groups"]["main"] == 'sys_platform == "win32"'
    )
    assert occurrence["dependency_extras"] == ["web"]
    assert occurrence["dependency_extra_requirements"]["speed"] == [
        {"name": "child", "requirement": "child (>=2)"}
    ]
    assert occurrence["requires_python"] == ">=3.9"
    assert occurrence["lockfile_requires_python"] == ">=3.9"
    assert occurrence["dependency_kind"] == "unknown"
    assert occurrence["marker_evaluation"] == "not_evaluated"
    assert _graph(document) == {
        "pkg:pypi/parent@1.0.0": ["pkg:pypi/child@2.0.0"],
        "pkg:pypi/child@2.0.0": [],
    }
    assert str(tmp_path) not in json.dumps(document)


def test_poetry_range_is_retained_without_inventing_graph_target(tmp_path):
    _write(
        tmp_path,
        "poetry.lock",
        POETRY.replace('version = "2.0.0", optional', 'version = "^2.0", optional'),
    )
    document = _export(tmp_path)
    parent = _occurrences(_components(document)["pkg:pypi/parent@1.0.0"])[0]
    assert parent["dependencies"][0]["version_spec"] == "^2.0"
    assert parent["dependencies"][0]["resolution"] == "version_constraint_not_evaluated"
    assert parent["dependency_graph_complete"] is False
    assert "pkg:pypi/parent@1.0.0" not in _graph(document)
    assert document.receipt["complete"] is True


def test_poetry_manifest_and_lock_occurrences_are_both_retained(tmp_path):
    _write(tmp_path, "poetry.lock", POETRY)
    _write(tmp_path, "requirements.txt", "parent==1.0.0\n")
    document = _export(tmp_path)
    parent = _components(document)["pkg:pypi/parent@1.0.0"]
    assert {item["file"] for item in _occurrences(parent)} == {
        "poetry.lock",
        "requirements.txt",
    }
    assert _graph(document)["pkg:pypi/parent@1.0.0"] == ["pkg:pypi/child@2.0.0"]


@pytest.mark.parametrize(
    "text", [CLASSIC, json.dumps(_berry())], ids=["classic", "berry"]
)
def test_yarn_resolved_graph_survives_export(tmp_path, text):
    _write(tmp_path, "yarn.lock", text)
    document = _export(tmp_path)
    assert document.receipt["complete"] is True
    assert set(_components(document)) == {"pkg:npm/parent@1.0.0", "pkg:npm/child@2.0.0"}
    assert _graph(document) == {
        "pkg:npm/parent@1.0.0": ["pkg:npm/child@2.0.0"],
        "pkg:npm/child@2.0.0": [],
    }
    assert all(
        item["location"] == "yarn.lock"
        for component in document["components"]
        for item in component["evidence"]["occurrences"]
    )


def test_berry_workspace_optional_and_environment_context(tmp_path):
    _write(tmp_path, "yarn.lock", json.dumps(_berry()))
    document = _export(tmp_path)
    assert document.receipt["local_lockfile_package_count"] == 1
    child = _occurrences(_components(document)["pkg:npm/child@2.0.0"])[0]
    assert child["dependency_roots"] == [""]
    assert child["dependency_kind"] == "transitive"
    assert child["dependency_markers"]["conditions"] == "os=linux & cpu=x64"
    assert all(item["optional"] for item in child["dependency_markers"]["yarn_usage"])
    assert all(component["name"] != "app" for component in document["components"])
    assert document["compositions"] == [{"aggregate": "incomplete"}]


def test_berry_optional_peer_is_not_fabricated_as_resolved_graph_edge(tmp_path):
    data = _berry()
    data["parent@npm:^1"].update(
        peerDependencies={"react": "^18"},
        peerDependenciesMeta={"react": {"optional": True}},
    )
    _write(tmp_path, "yarn.lock", json.dumps(data))
    document = _export(tmp_path)
    parent = _occurrences(_components(document)["pkg:npm/parent@1.0.0"])[0]
    peer = next(edge for edge in parent["dependencies"] if edge["name"] == "react")
    assert peer["optional"] is True
    assert "package_path" not in peer
    assert "pkg:npm/parent@1.0.0" not in _graph(document)


def test_cross_ecosystem_same_names_do_not_merge_components_or_graphs(tmp_path):
    _write(tmp_path, "poetry.lock", POETRY)
    _write(tmp_path, "yarn.lock", CLASSIC)
    document = _export(tmp_path)
    assert set(_components(document)) == {
        "pkg:npm/parent@1.0.0",
        "pkg:npm/child@2.0.0",
        "pkg:pypi/parent@1.0.0",
        "pkg:pypi/child@2.0.0",
    }
    assert _graph(document)["pkg:npm/parent@1.0.0"] == ["pkg:npm/child@2.0.0"]
    assert _graph(document)["pkg:pypi/parent@1.0.0"] == ["pkg:pypi/child@2.0.0"]


def test_private_poetry_source_is_gap_and_never_serialized(tmp_path, capsys):
    text = POETRY.replace(
        'groups = ["dev"]',
        'groups = ["dev"]\nsource = {type = "legacy", url = "https://private.example/simple", reference = "private-source"}',
    )
    _write(tmp_path, "poetry.lock", text)
    assert run_sbom_command([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert set(_components(document)) == {"pkg:pypi/parent@1.0.0"}
    assert "private.example" not in captured.out
    assert "private-source" not in captured.out
    assert document["dependencies"] == []
    assert "incomplete" in captured.err


@pytest.mark.parametrize("manifest", ["requirements.txt", "pyproject.toml"])
def test_unrelated_yarn_lock_does_not_cover_python_manifest_ranges(
    tmp_path, capsys, manifest
):
    _write(tmp_path, "yarn.lock", CLASSIC)
    text = (
        "python-only>=1.0\n"
        if manifest == "requirements.txt"
        else '[project]\ndependencies = ["python-only>=1.0"]\n'
    )
    _write(tmp_path, manifest, text)
    assert run_sbom_command([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert len(json.loads(captured.out)["components"]) == 2
    assert "incomplete" in captured.err


def test_lock_in_other_project_does_not_cover_root_manifest_ranges(tmp_path, capsys):
    _write(tmp_path, "package.json", '{"dependencies":{"root-only":"^1"}}')
    nested = tmp_path / "other-project"
    nested.mkdir()
    _write(nested, "yarn.lock", CLASSIC)
    assert run_sbom_command([str(tmp_path)]) == 2
    captured = capsys.readouterr()
    assert len(json.loads(captured.out)["components"]) == 2


def test_matching_poetry_lock_covers_project_range_without_resolving_it(
    tmp_path, capsys
):
    _write(tmp_path, "poetry.lock", POETRY)
    _write(tmp_path, "pyproject.toml", '[project]\ndependencies = ["parent>=1"]\n')
    assert run_sbom_command([str(tmp_path)]) == 0
    document = json.loads(capsys.readouterr().out)
    receipt = json.loads(
        next(
            item["value"]
            for item in document["metadata"]["properties"]
            if item["name"] == "skylos:inventory:receipt"
        )
    )
    assert receipt["unresolved_dependency_count"] == 1
    assert "lockfile_freshness_not_verified" in receipt["limitations"]


def test_berry_workspace_lock_covers_recorded_workspace_manifest(tmp_path, capsys):
    data = _berry()
    data["app@workspace:."]["dependencies"]["sub-app"] = "workspace:packages/sub-app"
    data["sub-app@workspace:packages/sub-app"] = {
        "version": "0.0.0-use.local",
        "resolution": "sub-app@workspace:packages/sub-app",
        "linkType": "soft",
        "dependencies": {"child": "npm:^2"},
    }
    _write(tmp_path, "yarn.lock", json.dumps(data))
    packages = tmp_path / "packages"
    packages.mkdir()
    workspace = packages / "sub-app"
    workspace.mkdir()
    _write(workspace, "package.json", '{"dependencies":{"child":"^2"}}')
    assert run_sbom_command([str(tmp_path)]) == 0
    document = json.loads(capsys.readouterr().out)
    child = _occurrences(_components(document)["pkg:npm/child@2.0.0"])[0]
    assert "packages/sub-app" in child["dependency_roots"]
