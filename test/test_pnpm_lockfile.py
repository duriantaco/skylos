"""Data-only parser cases: no pnpm execution, package installs, or network."""

import json
from pathlib import Path

import pytest
import yaml

from skylos.rules.sca import pnpm_lockfile
from skylos.rules.sca.lockfile_types import LockfileLimitError, LockfileParseError
from skylos.rules.sca.pnpm_lockfile import parse_pnpm_lock


def parse(data, **kwargs):
    return parse_pnpm_lock(Path("pnpm-lock.yaml"), text=json.dumps(data), **kwargs)


def registry(**metadata):
    return {"resolution": {"integrity": "sha512-fixture"}, **metadata}


def document(version=9, *, packages=None, snapshots=None, importers=None):
    packages = {"parent@1.0.0": registry()} if packages is None else packages
    snapshots = {key: {} for key in packages} if snapshots is None else snapshots
    result = {
        "lockfileVersion": f"{version}.0",
        "importers": {".": {}} if importers is None else importers,
    }
    if version == 9:
        result.update(packages=packages, snapshots=snapshots)
    else:
        result["packages"] = {
            "/" + key: {**metadata, **snapshots.get(key, {})}
            for key, metadata in packages.items()
        }
    return result


def reasons(inventory):
    return {issue["reason"] for issue in inventory.unresolved}


@pytest.mark.parametrize("version", [6, 9])
def test_transitives_multiple_versions_and_all_environment_metadata(version):
    result = parse(
        document(
            version,
            packages={
                "parent@1.0.0": registry(),
                "child@1.0.0": registry(),
                "child@2.0.0": registry(
                    os=["darwin", "linux"],
                    cpu=["arm64"],
                    libc=["musl"],
                    engines={"node": ">=18"},
                ),
            },
            snapshots={
                "parent@1.0.0": {"dependencies": {"child": "1.0.0"}},
                "child@1.0.0": {},
                "child@2.0.0": {"optional": True},
            },
            importers={
                ".": {
                    "devDependencies": {
                        "parent": {"specifier": "^1", "version": "1.0.0"}
                    }
                },
                "apps/web": {
                    "optionalDependencies": {
                        "child": {"specifier": "^2", "version": "2.0.0"}
                    }
                },
            },
        )
    )
    parent, child1, child2 = result.dependencies
    assert result.unresolved == []
    assert result.package_count == 5
    assert result.local_package_count == 2
    assert result.workspace_paths == ["", "apps/web"]
    assert parent["dependency_kind"] == "direct"
    assert child1["dependency_kind"] == "transitive"
    assert child1["dependency_dev"] is True
    assert child1["dependency_roots"] == [""]
    assert child2["dependency_optional"] is True
    assert child2["dependency_roots"] == ["apps/web"]
    assert child2["dependency_markers"]["os"] == ["darwin", "linux"]
    assert child2["dependency_markers"]["libc"] == ["musl"]
    assert all(
        dep["source_type"] == "registry_unspecified" for dep in result.dependencies
    )


@pytest.mark.parametrize("version", [6, 9])
def test_local_workspace_links_propagate_usage_without_querying_local_names(version):
    result = parse(
        document(
            version,
            packages={"parent@1.0.0": registry(), "tool@2.0.0": registry()},
            importers={
                ".": {
                    "dependencies": {
                        "@local/lib": {
                            "specifier": "workspace:*",
                            "version": "link:packages/lib",
                        }
                    }
                },
                "packages/lib": {
                    "dependencies": {"parent": {"specifier": "^1", "version": "1.0.0"}},
                    "devDependencies": {
                        "tool": {"specifier": "^2", "version": "2.0.0"}
                    },
                },
            },
        )
    )
    parent, tool = result.dependencies
    assert result.unresolved == []
    assert result.non_registry_names == ["@local/lib"]
    assert parent["dependency_roots"] == ["", "packages/lib"]
    assert parent["dependency_kinds"] == ["direct", "transitive"]
    assert tool["dependency_roots"] == ["packages/lib"]
    assert tool["dependency_dev"] is True


@pytest.mark.parametrize(
    "version,reference",
    [
        (6, "actual@1.0.0"),
        (9, "actual@1.0.0"),
        (6, "npm:actual@1.0.0"),
        (9, "npm:actual@1.0.0"),
        (6, "/actual@1.0.0"),
    ],
)
def test_alias_references_use_real_identity(version, reference):
    result = parse(
        document(
            version,
            packages={"actual@1.0.0": registry()},
            importers={
                ".": {
                    "dependencies": {
                        "alias": {"specifier": "npm:actual@^1", "version": reference}
                    }
                }
            },
        )
    )
    assert result.unresolved == []
    assert result.dependencies[0]["name"] == "actual"
    assert result.dependencies[0]["dependency_kind"] == "direct"


@pytest.mark.parametrize("version", [6, 9])
def test_private_alias_excludes_both_installed_and_real_names(version):
    result = parse(
        document(
            version,
            packages={
                "actual@1.0.0": {
                    "resolution": {
                        "tarball": "https://registry.example.invalid/actual/-/actual-1.0.0.tgz"
                    }
                }
            },
            importers={
                ".": {
                    "dependencies": {
                        "alias": {
                            "specifier": "npm:actual@1.0.0",
                            "version": "actual@1.0.0",
                        }
                    }
                }
            },
        )
    )
    assert result.dependencies == []
    assert result.non_registry_names == ["actual", "alias"]
    assert "non_registry_source" in reasons(result)


@pytest.mark.parametrize(
    "resolution",
    [
        {"tarball": "https://registry.example.invalid/parent/-/parent-1.0.0.tgz"},
        {
            "tarball": "https://registry.npmjs.org.evil.invalid/parent/-/parent-1.0.0.tgz"
        },
        {"tarball": "https://user@registry.npmjs.org/parent/-/parent-1.0.0.tgz"},
        {"tarball": "https://registry.npmjs.org:443/parent/-/parent-1.0.0.tgz"},
        {"tarball": "https://registry.npmjs.org/other/-/other-1.0.0.tgz"},
        {
            "type": "git",
            "repo": "https://example.invalid/parent.git",
            "commit": "fixture",
        },
        {"type": "directory", "directory": "packages/parent", "commit": "x"},
        {"tarball": "file:vendor/parent.tgz", "registry": "https://x.invalid/"},
        {"integrity": "fixture", "registry": "https://private.example.invalid/"},
        {"integrity": "fixture", "path": "subdir"},
        {"integrity": "fixture", "unexpected": "source"},
        {},
        None,
    ],
)
def test_non_public_or_unproven_resolution_is_not_queried(resolution):
    result = parse(document(packages={"parent@1.0.0": {"resolution": resolution}}))
    assert result.dependencies == []
    assert result.unresolved
    assert result.non_registry_names == ["parent"]


@pytest.mark.parametrize(
    "tarball",
    [
        "https://registry.npmjs.org/parent/-/parent-1.0.0.tgz",
        "http://registry.npmjs.org/parent/-/parent-1.0.0.tgz",
        "parent/-/parent-1.0.0.tgz",
    ],
)
def test_public_and_registry_relative_tarballs(tarball):
    result = parse(
        document(packages={"parent@1.0.0": {"resolution": {"tarball": tarball}}})
    )
    assert result.unresolved == []
    assert result.dependencies[0]["source_type"] == (
        "npm_registry" if tarball.startswith("http") else "registry_unspecified"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "different"),
        ("version", "2.0.0"),
        ("id", "alternate-identity"),
    ],
)
def test_conflicting_explicit_identity_is_not_inferred_from_key(field, value):
    result = parse(document(packages={"parent@1.0.0": registry(**{field: value})}))
    assert result.dependencies == []
    assert result.unresolved


def test_v9_snapshot_alternate_id_is_not_ignored():
    result = parse(document(snapshots={"parent@1.0.0": {"id": "alternate-identity"}}))
    assert result.dependencies == []
    assert reasons(result) == {"non_registry_source"}


def test_private_parent_keeps_public_children_and_their_importer_context():
    result = parse(
        document(
            packages={
                "private@1.0.0": {
                    "resolution": {"tarball": "https://example.invalid/private.tgz"}
                },
                "parent@1.0.0": registry(),
            },
            snapshots={
                "private@1.0.0": {"dependencies": {"parent": "1.0.0"}},
                "parent@1.0.0": {},
            },
            importers={
                ".": {
                    "devDependencies": {
                        "private": {"specifier": "^1", "version": "1.0.0"}
                    }
                }
            },
        )
    )
    assert [dep["name"] for dep in result.dependencies] == ["parent"]
    assert result.dependencies[0]["dependency_roots"] == [""]
    assert result.dependencies[0]["dependency_dev"] is True
    assert result.dependencies[0]["dependency_kind"] == "transitive"


@pytest.mark.parametrize("version", [6, 9])
def test_dependency_free_lock_omits_inventory_tables(version):
    result = parse({"lockfileVersion": f"{version}.0"})
    assert result.unresolved == []
    assert result.dependencies == []
    assert result.package_count == result.local_package_count == 1


@pytest.mark.parametrize("version", ["5.4", "8.0", "9.1", "9", 9, None, True])
def test_unsupported_versions_are_explicit(version):
    with pytest.raises(LockfileParseError, match="unsupported pnpm"):
        parse({"lockfileVersion": version})


@pytest.mark.parametrize("value", [6.0, 9.0])
def test_numeric_comver_is_accepted(value):
    assert parse({"lockfileVersion": value}).format_version == int(value)


def test_source_lines_use_actual_snapshot_key_not_repeated_version_text():
    text = """lockfileVersion: '9.0'
importers: {'.': {}}
packages:
  'parent@1.0.0': {resolution: {integrity: fixture}}
snapshots:
  'parent@1.0.0(peer@2.0.0)': {}
  'parent@1.0.0(peer@3.0.0)': {}
"""
    result = parse_pnpm_lock(Path("pnpm-lock.yaml"), text=text)
    assert [dep["line"] for dep in result.dependencies] == [6, 7]
    assert [dep["version"] for dep in result.dependencies] == ["1.0.0", "1.0.0"]


@pytest.mark.parametrize("version", [6, 9])
def test_malformed_entry_retains_valid_sibling(version):
    data = document(version, packages={"parent@1.0.0": registry()})
    key = "broken@1.0.0" if version == 9 else "/broken@1.0.0"
    data["packages"][key] = []
    if version == 9:
        data["snapshots"][key] = {}
    result = parse(data)
    assert [dep["name"] for dep in result.dependencies] == ["parent"]
    assert result.unresolved


def test_orphan_metadata_is_retained_and_missing_snapshot_reported():
    result = parse(document(snapshots={}))
    assert [dep["name"] for dep in result.dependencies] == ["parent"]
    assert reasons(result) == {"missing_package_snapshot"}


def test_missing_metadata_does_not_guess_registry_from_snapshot_key():
    result = parse(document(packages={}, snapshots={"parent@1.0.0": {}}))
    assert result.dependencies == []
    assert "missing_package_metadata" in reasons(result)


@pytest.mark.parametrize(
    "section,value",
    [
        ("packages", []),
        ("snapshots", []),
        ("importers", []),
    ],
)
def test_wrong_table_type_is_reported(section, value):
    data = document()
    data[section] = value
    assert "invalid_lockfile_table" in reasons(parse(data))


@pytest.mark.parametrize("section", ["dependencies", "optionalDependencies"])
def test_missing_graph_edge_does_not_hide_queryable_parent(section):
    result = parse(
        document(snapshots={"parent@1.0.0": {section: {"missing": "2.0.0"}}})
    )
    assert len(result.dependencies) == 1
    assert reasons(result) == {"missing_locked_dependency"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("dev", "true"),
        ("optional", "false"),
        ("os", {"name": "linux"}),
        ("cpu", [1]),
        ("libc", None),
        ("engines", {"node": 18}),
        ("peerDependencies", []),
        ("transitivePeerDependencies", False),
    ],
)
def test_invalid_context_is_reported_without_losing_exact_inventory(field, value):
    result = parse(document(packages={"parent@1.0.0": registry(**{field: value})}))
    assert len(result.dependencies) == 1
    assert "invalid_package_metadata" in reasons(result)


@pytest.mark.parametrize(
    "section",
    ["configDependencies", "packageManagerDependencies", "ignoredOptionalDependencies"],
)
def test_new_or_uncovered_inventory_sections_are_explicit(section):
    data = document()
    data[section] = {"plugin": "1.0.0"}
    assert "unsupported_lockfile_section" in reasons(parse(data))


def test_pnpm_environment_and_project_documents_are_combined():
    environment = document(
        packages={"pnpm@12.4.1": registry(engines={"node": ">=20"})},
        importers={
            ".": {
                "configDependencies": {},
                "packageManagerDependencies": {
                    "pnpm": {"specifier": "12.4.1", "version": "12.4.1"}
                },
            }
        },
    )
    project = document(
        packages={"left-pad@1.3.0": registry()},
        importers={
            ".": {
                "dependencies": {"left-pad": {"specifier": "1.3.0", "version": "1.3.0"}}
            }
        },
    )

    result = parse_pnpm_lock(
        Path("pnpm-lock.yaml"),
        text=yaml.safe_dump_all(
            [environment, project], explicit_start=True, sort_keys=False
        ),
    )

    assert result.unresolved == []
    assert result.package_count == 3
    assert {dependency["name"] for dependency in result.dependencies} == {
        "left-pad",
        "pnpm",
    }
    groups = {
        dependency["name"]: dependency["dependency_groups"]
        for dependency in result.dependencies
    }
    assert groups == {
        "left-pad": ["dependencies"],
        "pnpm": ["packageManagerDependencies"],
    }


def _environment_document(*, packages=None, snapshots=None, root=None):
    return document(
        packages={} if packages is None else packages,
        snapshots=snapshots,
        importers={
            ".": {"configDependencies": {}} if root is None else root,
        },
    )


def _dump_documents(*documents):
    return yaml.safe_dump_all(documents, explicit_start=True, sort_keys=False)


@pytest.mark.parametrize(
    "layout",
    ["project_then_environment", "two_environments", "second_env_with_settings"],
)
def test_pnpm_rejects_ambiguous_multidocument_layouts(layout):
    environment = _environment_document()
    project = document(packages={}, importers={".": {}})
    if layout == "project_then_environment":
        documents = (project, environment)
    else:
        second = _environment_document()
        if layout == "second_env_with_settings":
            second["settings"] = {"autoInstallPeers": True}
        documents = (environment, second)

    with pytest.raises(LockfileParseError, match="unsupported pnpm"):
        parse_pnpm_lock(Path("pnpm-lock.yaml"), text=_dump_documents(*documents))


@pytest.mark.parametrize("with_empty_project", [False, True])
def test_pnpm_environment_document_requires_a_project_document(with_empty_project):
    environment = _environment_document()
    text = (
        _dump_documents(environment, None)
        if with_empty_project
        else yaml.safe_dump(environment, sort_keys=False)
    )

    with pytest.raises(LockfileParseError):
        parse_pnpm_lock(Path("pnpm-lock.yaml"), text=text)


@pytest.mark.parametrize("trailing", ["---\n", "---\nextra: document\n"])
def test_pnpm_rejects_third_or_empty_trailing_document(trailing):
    environment = _environment_document()
    project = document(packages={}, importers={".": {}})
    text = _dump_documents(environment, project) + trailing

    with pytest.raises(LockfileParseError, match="document stream"):
        parse_pnpm_lock(Path("pnpm-lock.yaml"), text=text)


@pytest.mark.parametrize("table", ["packages", "snapshots"])
def test_pnpm_multidocument_duplicate_records_must_agree(table):
    package_key = "shared@1.0.0"
    environment_packages = {package_key: registry()}
    project_packages = {package_key: registry()}
    environment_snapshots = {package_key: {}}
    project_snapshots = {package_key: {}}
    if table == "packages":
        project_packages[package_key] = registry(engines={"node": ">=20"})
    else:
        environment_snapshots[package_key] = {"optional": True}
    environment = _environment_document(
        packages=environment_packages,
        snapshots=environment_snapshots,
    )
    project = document(
        packages=project_packages,
        snapshots=project_snapshots,
        importers={".": {}},
    )

    with pytest.raises(LockfileParseError, match="conflicting"):
        parse_pnpm_lock(
            Path("pnpm-lock.yaml"),
            text=_dump_documents(environment, project),
        )


@pytest.mark.parametrize("metadata_document", ["environment", "project"])
def test_pnpm_documents_cannot_supply_each_others_package_snapshot_half(
    metadata_document,
):
    package_key = "shared@1.0.0"
    environment = _environment_document(
        packages={package_key: registry()}
        if metadata_document == "environment"
        else {},
        snapshots={package_key: {}} if metadata_document == "project" else {},
    )
    project = document(
        packages={package_key: registry()} if metadata_document == "project" else {},
        snapshots={package_key: {}} if metadata_document == "environment" else {},
        importers={".": {}},
    )

    with pytest.raises(LockfileParseError, match="cross-document pnpm package"):
        parse_pnpm_lock(
            Path("pnpm-lock.yaml"),
            text=_dump_documents(environment, project),
        )


def test_pnpm_documents_cannot_resolve_each_others_dependency_references():
    package_key = "shared@1.0.0"
    environment = _environment_document(
        packages={},
        snapshots={},
        root={
            "configDependencies": {"shared": {"specifier": "1.0.0", "version": "1.0.0"}}
        },
    )
    project = document(
        packages={package_key: registry()},
        snapshots={package_key: {}},
        importers={".": {}},
    )

    with pytest.raises(LockfileParseError, match="cross-document pnpm dependency"):
        parse_pnpm_lock(
            Path("pnpm-lock.yaml"),
            text=_dump_documents(environment, project),
        )


def test_pnpm_environment_dependencies_cannot_link_to_project_workspaces():
    environment = _environment_document(
        root={
            "configDependencies": {
                "@local/tool": {
                    "specifier": "workspace:*",
                    "version": "link:packages/tool",
                }
            }
        },
    )
    project = document(
        packages={},
        importers={".": {}, "packages/tool": {}},
    )

    with pytest.raises(LockfileParseError):
        parse_pnpm_lock(
            Path("pnpm-lock.yaml"),
            text=_dump_documents(environment, project),
        )


def test_pnpm_environment_root_cannot_repair_a_missing_project_root():
    environment = _environment_document()
    project = document(
        packages={},
        importers={
            "packages/app": {
                "dependencies": {
                    "root": {"specifier": "workspace:*", "version": "link:../.."}
                }
            }
        },
    )

    with pytest.raises(LockfileParseError, match="no root importer"):
        parse_pnpm_lock(
            Path("pnpm-lock.yaml"),
            text=_dump_documents(environment, project),
        )


def test_pnpm_multidocument_node_bound_is_cumulative(monkeypatch):
    environment = _environment_document()
    project = document(packages={}, importers={".": {}})
    monkeypatch.setattr(pnpm_lockfile, "_MAX_NODES", 20)

    for single_document in (environment, project):
        loader = pnpm_lockfile._LockLoader(
            yaml.safe_dump(single_document, sort_keys=False)
        )
        try:
            assert loader.get_single_data() is not None
        finally:
            loader.dispose()
    with pytest.raises(LockfileLimitError, match="YAML tree"):
        parse_pnpm_lock(
            Path("pnpm-lock.yaml"),
            text=_dump_documents(environment, project),
        )


def test_pnpm_multidocument_preserves_second_document_source_lines():
    package_key = "left-pad@1.3.0"
    environment = _environment_document()
    project = document(
        packages={package_key: registry()},
        importers={
            ".": {
                "dependencies": {"left-pad": {"specifier": "1.3.0", "version": "1.3.0"}}
            }
        },
    )
    text = _dump_documents(environment, project)
    expected_line = next(
        line_number
        for line_number, line in enumerate(text.splitlines(), 1)
        if line == f"  {package_key}: {{}}"
    )

    result = parse_pnpm_lock(Path("pnpm-lock.yaml"), text=text)

    assert len(result.dependencies) == 1
    assert result.dependencies[0]["line"] == expected_line


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize("field", ["bundledDependencies", "bundleDependencies"])
@pytest.mark.parametrize("value", [True, ["some-bundled-dep"]], ids=["all", "named"])
def test_bundled_dependencies_are_a_coverage_limitation_not_unresolved_inventory(
    version, field, value
):
    result = parse(
        document(version, packages={"bundler-pkg@1.0.0": registry(**{field: value})})
    )

    assert [dependency["name"] for dependency in result.dependencies] == ["bundler-pkg"]
    assert result.unresolved == []
    assert len(result.limitations) == 1
    assert result.limitations[0]["reason"] == "bundled_dependencies_not_enumerated"
    assert result.limitations[0]["name"] == "bundler-pkg"
    assert result.limitations[0]["version"] == "1.0.0"
    assert result.dependencies[0]["dependency_graph_complete"] is False


@pytest.mark.parametrize("field", ["bundledDependencies", "bundleDependencies"])
@pytest.mark.parametrize("value", [False, []], ids=["false", "empty"])
def test_empty_bundled_dependencies_do_not_create_a_limitation(field, value):
    result = parse(document(packages={"bundler-pkg@1.0.0": registry(**{field: value})}))

    assert result.unresolved == []
    assert result.limitations == []
    assert "dependency_graph_complete" not in result.dependencies[0]


@pytest.mark.parametrize(
    "value",
    [None, "some-bundled-dep", [1], [""]],
    ids=["null", "string", "non-string-name", "invalid-name"],
)
def test_malformed_bundled_dependencies_remain_an_inventory_error(value):
    result = parse(
        document(packages={"bundler-pkg@1.0.0": registry(bundledDependencies=value)})
    )

    assert reasons(result) == {"invalid_package_metadata"}
    assert result.limitations == []


@pytest.mark.parametrize("root", ["../outside", "/absolute", "a/../b", "a\\b", "a//b"])
def test_unsafe_importer_paths_are_not_workspace_origins(root):
    result = parse(document(importers={root: {}}))
    assert result.workspace_paths == []
    assert "invalid_importer" in reasons(result)


@pytest.mark.parametrize(
    "yaml_text",
    [
        "lockfileVersion: '9.0'\nlockfileVersion: '6.0'\n",
        "lockfileVersion: '9.0'\npackages: {a: {}, a: {}}\n",
        "lockfileVersion: '9.0'\npackages: &ref {}\nsnapshots: *ref\n",
        "lockfileVersion: !!str '9.0'\n",
        "lockfileVersion: '9.0'\npackages: !custom {}\n",
        "lockfileVersion: '9.0'\npackages: {1: {}}\n",
        "lockfileVersion: '9.0'\n---\nlockfileVersion: '9.0'\n",
        "lockfileVersion: '9.0'\npackages: [\n",
        "[]",
        "null",
    ],
)
def test_unsupported_or_ambiguous_yaml_is_rejected(yaml_text):
    with pytest.raises(LockfileParseError):
        parse_pnpm_lock(Path("pnpm-lock.yaml"), text=yaml_text)


def test_byte_bound(monkeypatch):
    monkeypatch.setattr(pnpm_lockfile, "_MAX_BYTES", 20)
    with pytest.raises(LockfileLimitError, match="size"):
        parse(document())


def test_node_bound_before_construction(monkeypatch):
    monkeypatch.setattr(pnpm_lockfile, "_MAX_NODES", 8)
    with pytest.raises(LockfileLimitError, match="YAML tree"):
        parse(document())


def test_depth_bound_before_construction(monkeypatch):
    monkeypatch.setattr(pnpm_lockfile, "_MAX_DEPTH", 5)
    with pytest.raises(LockfileLimitError, match="YAML tree"):
        parse({"lockfileVersion": "9.0", "extra": {"a": {"b": {"c": {"d": {}}}}}})


@pytest.mark.parametrize("version", [6, 9])
def test_combined_snapshot_and_importer_package_bound(version):
    with pytest.raises(LockfileLimitError, match="package count"):
        parse(document(version), max_packages=1)
    assert parse(document(version), max_packages=2).package_count == 2


def test_snapshot_multiplication_is_bounded_separately_from_package_identities():
    snapshots = {f"parent@1.0.0(peer@{index}.0.0)": {} for index in range(4)}
    with pytest.raises(LockfileLimitError, match="package count"):
        parse(document(snapshots=snapshots), max_packages=3)


def test_graph_scheduling_is_bounded_not_only_dequeued_work(monkeypatch):
    monkeypatch.setattr(pnpm_lockfile, "_MAX_GRAPH_WORK", 12)
    node = ("package", "parent@1.0.0")
    roots = {f"apps/{index}": {} for index in range(4)}
    adjacency = {("importer", root): [(node, "dependencies")] for root in roots}
    adjacency[node] = [(node, "dependencies")] * 4
    with pytest.raises(LockfileLimitError, match="graph"):
        pnpm_lockfile._contexts(adjacency, roots, {node[1]: ({}, {}, 1)})


def test_cycles_terminate_and_preserve_every_exact_package():
    result = parse(
        document(
            packages={"parent@1.0.0": registry(), "child@1.0.0": registry()},
            snapshots={
                "parent@1.0.0": {"dependencies": {"child": "1.0.0"}},
                "child@1.0.0": {"dependencies": {"parent": "1.0.0"}},
            },
            importers={
                ".": {
                    "dependencies": {
                        "parent": {"specifier": "1.0.0", "version": "1.0.0"}
                    }
                }
            },
        )
    )
    assert result.unresolved == []
    assert {dep["name"] for dep in result.dependencies} == {"parent", "child"}


def test_read_only_bounded_file_and_symlink_refusal(tmp_path):
    lock = tmp_path / "pnpm-lock.yaml"
    fixture = json.dumps(document())
    lock.write_text(fixture)  # skylos: ignore[SKY-D324] pytest tmp_path
    assert len(parse_pnpm_lock(lock).dependencies) == 1
    link = tmp_path / "linked-lock.yaml"
    link.symlink_to(lock)
    with pytest.raises(LockfileParseError, match="cannot be read"):
        parse_pnpm_lock(link)


def test_text_snapshot_does_not_open_the_supplied_path(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parser attempted filesystem I/O despite text snapshot")

    monkeypatch.setattr(pnpm_lockfile, "read_text_no_symlink", forbidden)
    assert parse(document()).dependencies


def test_invalid_utf8_surrogate_is_a_parse_error():
    with pytest.raises(LockfileParseError, match="invalid lockfile YAML"):
        parse_pnpm_lock(Path("pnpm-lock.yaml"), text="\ud800")


def test_safe_loader_globals_are_not_changed():
    import yaml

    assert yaml.safe_load("value: on")["value"] is True
    assert parse({"lockfileVersion": "9.0", "extra": "2026-09-15"}).unresolved == []


# ---------------------------------------------------------------------------
# Real-world reference forms (zod, vite, vitest, nuxt, svelte, pnpm lockfiles).
# Each one used to leave the inventory incomplete. Local code is listed as
# ``not_checked``; public packages are inventoried; remote non-registry code
# stays unresolved.
# ---------------------------------------------------------------------------


def parse_text(text):
    return parse_pnpm_lock(Path("pnpm-lock.yaml"), text=text)


def not_checked(inventory):
    return sorted(
        (entry["reason"], entry.get("dependency") or entry.get("package"))
        for entry in inventory.not_checked
    )


ZOD_V9 = """\
lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      zod:
        specifier: workspace:*
        version: link:packages/zod

  packages/bench:
    devDependencies:
      zod443:
        specifier: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz
        version: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz

  packages/docs:
    dependencies:
      ai:
        specifier: ^6.0.5
        version: 6.0.5(zod@4.6.6)
      zod:
        specifier: workspace:*
        version: link:../zod

  packages/zod: {}

packages:

  ai@6.0.5:
    resolution: {integrity: sha512-ai}
    peerDependencies:
      zod: ^3.25.76 || ^4.1.8

  zod443@https://registry.npmjs.org/zod/-/zod-4.4.3.tgz:
    resolution: {integrity: sha512-zod, tarball: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz}
    version: 4.4.3

snapshots:

  ai@6.0.5(zod@4.6.6):
    dependencies:
      zod: 4.6.6

  zod443@https://registry.npmjs.org/zod/-/zod-4.4.3.tgz: {}
"""


def test_zod_public_tarball_alias_is_inventoried_as_the_real_package():
    result = parse_text(ZOD_V9)
    assert result.unresolved == []
    identities = {(dep["name"], dep["version"]) for dep in result.dependencies}
    assert identities == {("ai", "6.0.5"), ("zod", "4.4.3")}
    zod = next(dep for dep in result.dependencies if dep["name"] == "zod")
    assert zod["source_type"] == "npm_registry"
    assert zod["dependency_kind"] == "direct"
    assert zod["dependency_roots"] == ["packages/bench"]
    assert "https://" not in json.dumps(result.dependencies)


def test_zod_peer_resolved_to_workspace_package_is_not_checked():
    result = parse_text(ZOD_V9)
    assert not_checked(result) == [("workspace_package", "zod")]
    assert result.not_checked[0]["source_type"] == "local"
    assert "zod" in result.non_registry_names


def test_bare_version_without_record_is_unresolved_unless_a_workspace_name():
    text = ZOD_V9.replace("      zod: 4.6.6\n", "      other: 4.6.6\n")
    result = parse_text(text)
    assert reasons(result) == {"missing_locked_dependency"}
    assert result.not_checked == []


@pytest.mark.parametrize(
    "resolution,version",
    [
        # Not the public registry: an external or private tarball.
        (
            "{integrity: sha512-zod, tarball: https://npm.example.invalid/zod/-/zod-4.4.3.tgz}",
            "4.4.3",
        ),
        # Recorded version disagrees with the tarball.
        (
            "{integrity: sha512-zod, tarball: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz}",
            "4.4.4",
        ),
        # Tarball name is not the canonical registry path.
        (
            "{integrity: sha512-zod, tarball: https://registry.npmjs.org/zod/-/other-4.4.3.tgz}",
            "4.4.3",
        ),
        (
            "{integrity: sha512-zod, tarball: 'https://registry.npmjs.org/zod/-/zod-4.4.3.tgz?x=1'}",
            "4.4.3",
        ),
    ],
)
def test_unproven_tarball_alias_stays_unresolved(resolution, version):
    text = ZOD_V9.replace(
        "    resolution: {integrity: sha512-zod, tarball: https://registry.npmjs.org/zod/-/zod-4.4.3.tgz}\n"
        "    version: 4.4.3\n",
        f"    resolution: {resolution}\n    version: {version}\n",
    )
    result = parse_text(text)
    assert ("zod", "4.4.3") not in {
        (dep["name"], dep["version"]) for dep in result.dependencies
    }
    assert "non_registry_source" in reasons(result)
    assert "zod443" in result.non_registry_names


VITE_V9 = """\
lockfileVersion: '9.0'

settings:
  autoInstallPeers: false
  excludeLinksFromLockfile: false

catalogs:
  default:
    pathe:
      specifier: ^2.0.3
      version: 2.0.3

overrides:
  vite: workspace:*

patchedDependencies:
  chokidar@3.6.0: e17269188c54412478078f7ac7877c1d5a475a2f2438328e3a7e725513ccbf1f

importers:

  .:
    devDependencies:
      chokidar:
        specifier: ^3.6.0
        version: 3.6.0(patch_hash=e17269188c54412478078f7ac7877c1d5a475a2f2438328e3a7e725513ccbf1f)
      pathe:
        specifier: 'catalog:'
        version: 2.0.3
      plugin-vue:
        specifier: ^6.0.8
        version: '@vitejs/plugin-vue@6.0.8(vite@packages+vite)'

  packages/vite:
    dependencies:
      sass-embedded-linux-x64:
        specifier: ^1.105.1
        version: 1.105.1

  playground/css:
    devDependencies:
      '@vitejs/test-css-js-dep':
        specifier: file:./css-js-dep
        version: file:playground/css/css-js-dep
      bundled-lib:
        specifier: link:./bundled-lib
        version: link:playground/css/bundled-lib
      vendored:
        specifier: file:./vendor/vendored-1.0.0.tgz
        version: file:playground/css/vendor/vendored-1.0.0.tgz
      outside:
        specifier: link:../../../outside
        version: link:../../../outside

packages:

  '@vitejs/plugin-vue@6.0.8':
    resolution: {integrity: sha512-pv}
    peerDependencies:
      vite: ^5.0.0

  '@vitejs/test-css-js-dep@file:playground/css/css-js-dep':
    resolution: {directory: playground/css/css-js-dep, type: directory}

  chokidar@3.6.0:
    resolution: {integrity: sha512-ch}

  pathe@2.0.3:
    resolution: {integrity: sha512-pa}

  sass-embedded-linux-x64@1.105.1:
    resolution: {integrity: sha512-sa}
    engines: {node: '>=14.0.0'}
    cpu: [x64]
    os: [linux]
    libc: glibc

  vendored@file:playground/css/vendor/vendored-1.0.0.tgz:
    resolution: {integrity: sha512-ve, tarball: file:playground/css/vendor/vendored-1.0.0.tgz}
    version: 1.0.0

snapshots:

  '@vitejs/plugin-vue@6.0.8(vite@packages+vite)':
    dependencies:
      vite: link:packages/vite

  '@vitejs/test-css-js-dep@file:playground/css/css-js-dep':
    dependencies:
      pathe: 2.0.3

  chokidar@3.6.0(patch_hash=e17269188c54412478078f7ac7877c1d5a475a2f2438328e3a7e725513ccbf1f): {}

  pathe@2.0.3: {}

  sass-embedded-linux-x64@1.105.1:
    optional: true

  vendored@file:playground/css/vendor/vendored-1.0.0.tgz: {}
"""


def test_vite_local_directories_tarballs_and_links_are_not_checked():
    result = parse_text(VITE_V9)
    assert result.unresolved == []
    assert not_checked(result) == [
        ("local_link", "bundled-lib"),
        ("local_link", "outside"),
        ("local_package", "@vitejs/test-css-js-dep@<local>"),
        ("local_package", "vendored@<local>"),
    ]
    assert {entry["source_type"] for entry in result.not_checked} == {"local"}
    assert {"@vitejs/test-css-js-dep", "vendored", "bundled-lib"} <= set(
        result.non_registry_names
    )
    # Local record keys (``name@file:<path>``) are not copied into labels.
    assert "css-js-dep@file" not in json.dumps(result.not_checked)
    assert "vendor/" not in json.dumps(result.not_checked)


def test_vite_patch_catalog_peer_workspace_and_string_libc_forms_resolve():
    result = parse_text(VITE_V9)
    by_name = {dep["name"]: dep for dep in result.dependencies}
    assert set(by_name) == {
        "@vitejs/plugin-vue",
        "chokidar",
        "pathe",
        "sass-embedded-linux-x64",
    }
    assert by_name["chokidar"]["version"] == "3.6.0"
    # pathe is reached directly (catalog:) and through a local package.
    assert by_name["pathe"]["dependency_roots"] == ["", "playground/css"]
    # ``vite: link:packages/vite`` from a snapshot is the workspace project.
    plugin_edges = by_name["@vitejs/plugin-vue"]["dependencies"]
    assert plugin_edges == [
        {
            "name": "vite",
            "version_spec": "<local>",
            "group": "dependencies",
            "workspace": "packages/vite",
        }
    ]
    assert by_name["sass-embedded-linux-x64"]["dependency_markers"]["libc"] == ["glibc"]


def test_git_dependency_stays_unresolved_not_silently_unchecked():
    text = VITE_V9.replace(
        "  pathe@2.0.3:\n    resolution: {integrity: sha512-pa}\n",
        "  pathe@2.0.3:\n    resolution: {type: git, repo: 'https://github.com/x/pathe.git', commit: abc}\n",
    )
    result = parse_text(text)
    assert reasons(result) == {"non_registry_source"}
    assert "pathe" not in {dep["name"] for dep in result.dependencies}
    assert "pathe" in result.non_registry_names


def test_pnpm_runtime_dependency_is_not_checked():
    text = """\
lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      node:
        specifier: runtime:26.11.1
        version: runtime:26.11.1

packages:

  node@runtime:26.11.1:
    resolution:
      type: variations
      variants:
        - resolution:
            archive: tarball
            integrity: sha256-fixture
            type: binary
            url: https://nodejs.org/download/release/v26.11.1/node-v26.11.1-linux-x64.tar.gz
          targets:
            - cpu: x64
              os: linux

snapshots:

  node@runtime:26.11.1: {}
"""
    result = parse_text(text)
    assert result.unresolved == []
    assert result.dependencies == []
    assert not_checked(result) == [("runtime", "node@runtime:26.11.1")]


VITE_V6 = """\
lockfileVersion: '6.0'

importers:

  .:
    dependencies:
      dep-that-imports:
        specifier: file:./dep-that-imports
        version: file:playground/dep-that-imports(typescript@5.2.2)

  packages/svelte: {}

packages:

  /@sveltejs/kit@1.22.4(svelte@packages+svelte):
    resolution: {integrity: sha512-kit}
    dependencies:
      svelte: link:packages/svelte
    dev: false

  /slash@3.0.0:
    resolution: {integrity: sha512-sl}
    dev: false

  file:playground/dep-that-imports(typescript@5.2.2):
    resolution: {directory: playground/dep-that-imports, type: directory}
    id: file:playground/dep-that-imports
    name: '@vitejs/test-dep-that-imports'
    dependencies:
      '@sveltejs/kit': 1.22.4(svelte@packages+svelte)
      slash3: /slash@3.0.0
    dev: false
"""


def test_v6_file_keys_snapshot_workspace_links_and_aliases():
    result = parse_text(VITE_V6)
    assert result.unresolved == []
    assert not_checked(result) == [
        ("local_package", "@vitejs/test-dep-that-imports@<local>")
    ]
    by_name = {dep["name"]: dep for dep in result.dependencies}
    assert set(by_name) == {"@sveltejs/kit", "slash"}
    # Children of a local package are still inventoried with its context.
    assert by_name["slash"]["dependency_roots"] == [""]
    assert by_name["slash"]["dependency_kind"] == "transitive"


def test_v6_local_record_with_a_foreign_id_stays_unresolved():
    text = VITE_V6.replace(
        "    id: file:playground/dep-that-imports\n",
        "    id: registry.example.invalid/other/1.0.0\n",
    )
    result = parse_text(text)
    assert "non_registry_source" in reasons(result)
    assert result.not_checked == []


@pytest.mark.parametrize("version", [6, 9])
def test_local_directory_and_file_tarball_records_with_exact_keys(version):
    result = parse(
        document(
            version,
            packages={
                "parent@1.0.0": {
                    "resolution": {"type": "directory", "directory": "pkgs/parent"}
                },
                "vendored@1.0.0": {
                    "resolution": {"tarball": "file:vendor/vendored-1.0.0.tgz"}
                },
            },
        )
    )
    assert result.dependencies == []
    assert result.unresolved == []
    assert sorted(
        (entry["reason"], entry["name"], entry["version"])
        for entry in result.not_checked
    ) == [
        ("local_package", "parent", "1.0.0"),
        ("local_package", "vendored", "1.0.0"),
    ]
    assert result.non_registry_names == ["parent", "vendored"]


def test_local_resolution_with_a_foreign_alternate_id_stays_unresolved():
    result = parse(
        document(
            packages={
                "parent@1.0.0": {
                    "resolution": {"type": "directory", "directory": "pkgs/parent"},
                    "id": "registry.example.invalid/parent/1.0.0",
                }
            },
        )
    )
    assert result.not_checked == []
    assert reasons(result) == {"non_registry_source"}
