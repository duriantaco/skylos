"""Data-only parser cases: no pnpm execution, package installs, or network."""

import json
from pathlib import Path

import pytest

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
        {"tarball": "file:vendor/parent.tgz"},
        {
            "type": "git",
            "repo": "https://example.invalid/parent.git",
            "commit": "fixture",
        },
        {"type": "directory", "directory": "packages/parent"},
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
        ("os", "linux"),
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
