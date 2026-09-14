import json
from pathlib import Path

import pytest

from skylos.rules.sca.lockfile_types import LockfileLimitError, LockfileParseError
from skylos.rules.sca.npm_lockfile import parse_package_lock


def parse(data, **kwargs):
    text = json.dumps(data, indent=2)
    return parse_package_lock(Path("package-lock.json"), text=text, **kwargs)


def registry(name, version, **metadata):
    basename = name.rsplit("/", 1)[-1]
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz",
        **metadata,
    }


def test_v1_keeps_nested_versions_and_hoisted_kind_unknown():
    result = parse(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "parent": registry(
                    "parent",
                    "2.0.0",
                    requires={"shared": "^1.0.0"},
                    dependencies={"shared": registry("shared", "1.0.0")},
                ),
                "shared": registry("shared", "2.0.0"),
            },
        }
    )
    deps = {d["package_path"]: d for d in result.dependencies}
    assert result.package_count == 3
    assert result.unresolved == []
    assert deps["node_modules/shared"]["version"] == "2.0.0"
    nested = deps["node_modules/parent/node_modules/shared"]
    assert nested["version"] == "1.0.0"
    assert nested["dependency_kind"] == "transitive"
    assert deps["node_modules/parent"]["dependency_kind"] == "unknown"
    assert deps["node_modules/parent"]["dependencies"] == [
        {
            "name": "shared",
            "version_spec": "^1.0.0",
            "group": "dependencies",
            "package_path": "node_modules/parent/node_modules/shared",
        }
    ]


@pytest.mark.parametrize("version", [2, 3])
def test_packages_table_is_authoritative_and_marks_transitives(version):
    result = parse(
        {
            "lockfileVersion": version,
            "packages": {
                "": {"name": "project", "dependencies": {"parent": "^1"}},
                "node_modules/parent": registry(
                    "parent", "1.0.0", dependencies={"child": "^2"}
                ),
                "node_modules/child": registry("child", "2.0.0"),
            },
            "dependencies": {"legacy-only": {"version": "9.9.9"}},
        }
    )
    assert [(d["name"], d["dependency_kind"]) for d in result.dependencies] == [
        ("parent", "direct"),
        ("child", "transitive"),
    ]
    assert result.local_package_count == 1
    assert (
        result.dependencies[0]["dependencies"][0]["package_path"]
        == "node_modules/child"
    )


def test_workspace_origins_scoped_names_and_environment_context():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": "project",
                    "version": "1.0.0",
                    "devDependencies": {"tool": "^1"},
                    "workspaces": ["packages/*"],
                },
                "packages/app": {
                    "name": "@local/app",
                    "version": "1.0.0",
                    "optionalDependencies": {"@scope/native": "^2"},
                },
                "node_modules/@local/app": {"resolved": "packages/app", "link": True},
                "node_modules/tool": registry("tool", "1.0.0", dev=True),
                "node_modules/@scope/native": registry(
                    "@scope/native",
                    "2.0.0",
                    optional=True,
                    os=["darwin", "linux"],
                    cpu=["arm64"],
                    engines={"node": ">=18"},
                ),
            },
        }
    )
    assert result.local_package_count == 3
    assert result.package_count == 5
    assert len(result.dependencies) == 2
    tool, native = result.dependencies
    assert tool["dependency_dev"] is True
    assert tool["dependency_roots"] == [""]
    assert tool["dependency_groups"] == ["devDependencies"]
    assert native["name"] == "@scope/native"
    assert native["dependency_roots"] == ["packages/app"]
    assert native["dependency_kind"] == "direct"
    assert native["dependency_optional"] is True
    assert native["dependency_groups"] == ["optionalDependencies"]
    assert native["dependency_markers"] == {
        "os": ["darwin", "linux"],
        "cpu": ["arm64"],
        "engines": {"node": ">=18"},
    }


def test_workspace_local_install_takes_precedence_over_hoisted_copy():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "packages/app": {"dependencies": {"shared": "^1"}},
                "packages/app/node_modules/shared": {"version": "1.0.0"},
                "node_modules/shared": {"version": "2.0.0"},
            },
        }
    )
    local, hoisted = result.dependencies
    assert local["dependency_kind"] == "direct"
    assert hoisted["dependency_kind"] == "transitive"
    assert local["dependency_roots"] == ["packages/app"]


@pytest.mark.parametrize("version", [1, 2, 3])
def test_npm_alias_uses_real_registry_identity(version):
    entry = registry("@scope/actual", "1.2.3")
    if version == 1:
        entry["version"] = "npm:@scope/actual@1.2.3"
        data = {"lockfileVersion": 1, "dependencies": {"alias": entry}}
    else:
        entry["name"] = "@scope/actual"
        data = {
            "lockfileVersion": version,
            "packages": {
                "": {"dependencies": {"alias": "npm:@scope/actual@^1"}},
                "node_modules/alias": entry,
            },
        }
    result = parse(data)
    assert result.unresolved == []
    assert result.dependencies[0]["name"] == "@scope/actual"
    assert result.dependencies[0]["version"] == "1.2.3"
    assert result.dependencies[0]["package_path"] == "node_modules/alias"


@pytest.mark.parametrize(
    "resolved,source_type",
    [
        ("https://packages.example.org/pkg/-/pkg-1.0.0.tgz", "external"),
        ("git+https://example.org/pkg.git#revision", "git"),
        ("file:vendor/pkg.tgz", "local"),
        ("https://example.org/pkg.tar.gz", "external"),
    ],
)
def test_non_registry_sources_are_explicit_unresolved_entries(resolved, source_type):
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/pkg": {"version": "1.0.0", "resolved": resolved}
            },
        }
    )
    assert result.dependencies == []
    assert result.package_count == 1
    assert result.unresolved[0]["reason"] == "non_registry_source"
    assert result.unresolved[0]["source_type"] == source_type
    assert result.unresolved[0]["name"] == "pkg"
    assert result.unresolved[0]["installed_name"] == "pkg"
    assert result.unresolved[0]["version"] == "1.0.0"


@pytest.mark.parametrize(
    "source", ["git+https://example.org/pkg.git#revision", "file:local/pkg"]
)
def test_legacy_non_registry_version_spec_is_not_queried(source):
    result = parse({"lockfileVersion": 1, "dependencies": {"pkg": {"version": source}}})
    assert not result.dependencies
    assert result.unresolved[0]["reason"] == "non_registry_source"


def test_unspecified_registry_and_legacy_relative_tarball_are_recorded():
    result = parse(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "pkg": {"version": "1.0.0"},
                "other": {"version": "2.0.0", "resolved": "other/-/other-2.0.0.tgz"},
            },
        }
    )
    assert len(result.dependencies) == 2
    assert {dep["source_type"] for dep in result.dependencies} == {
        "registry_unspecified"
    }


def test_registry_url_identity_must_match_actual_package_name():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/alias": registry("actual", "1.0.0")},
        }
    )
    assert not result.dependencies
    assert result.unresolved[0]["reason"] == "unverified_registry_identity"


def test_version_lines_use_structural_paths_not_matching_text():
    text = """{
  "lockfileVersion": 3,
  "description": "version: 1.0.0",
  "packages": {
    "": {"version": "1.0.0"},
    "node_modules/one": {
      "description": "version",
      "version": "1.0.0"
    },
    "node_modules/two": {
      "version": "1.0.0"
    },
    "node_modules/escaped\\u002dname": {"version": "2.0.0"}
  },
  "dependencies": {"one": {"version": "1.0.0"}}
}"""
    result = parse_package_lock(Path("package-lock.json"), text=text)
    assert [(d["name"], d["line"]) for d in result.dependencies] == [
        ("one", 8),
        ("two", 11),
        ("escaped-name", 13),
    ]


def test_legacy_duplicate_versions_have_distinct_structural_lines():
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "one": {"version": "1.0.0", "dependencies": {"two": {"version": "1.0.0"}}},
            "two": {"version": "1.0.0"},
        },
    }
    text = json.dumps(data, indent=2)
    result = parse_package_lock(Path("package-lock.json"), text=text)
    expected = [
        i for i, line in enumerate(text.splitlines(), 1) if '"version":' in line
    ]
    assert sorted(d["line"] for d in result.dependencies) == expected


@pytest.mark.parametrize(
    "data",
    [
        [],
        {},
        {"lockfileVersion": 0},
        {"lockfileVersion": 4},
        {"lockfileVersion": True},
        {"lockfileVersion": "3"},
        {"lockfileVersion": 3},
        {"lockfileVersion": 2, "packages": []},
        {"lockfileVersion": 1, "dependencies": []},
    ],
)
def test_unsupported_or_invalid_schema_raises(data):
    with pytest.raises(LockfileParseError):
        parse(data)


@pytest.mark.parametrize(
    "text",
    [
        '{"lockfileVersion": 3,',
        '{"lockfileVersion": 3, "packages": {}, "packages": {}}',
        '{"lockfileVersion": 3, "packages": {}, "other": NaN}',
    ],
)
def test_invalid_or_ambiguous_json_raises(text):
    with pytest.raises(LockfileParseError):
        parse_package_lock(Path("package-lock.json"), text=text)


def test_empty_inventories_are_valid():
    for data in ({"lockfileVersion": 1}, {"lockfileVersion": 3, "packages": {}}):
        result = parse(data)
        assert result.package_count == 0
        assert result.dependencies == []
        assert result.unresolved == []


def test_malformed_entries_and_missing_optional_versions_are_counted():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/invalid": [],
                "node_modules/optional-peer": {"optional": True, "peer": True},
                "node_modules/range": {"version": "^1.0.0"},
            },
        }
    )
    assert result.package_count == 4
    assert result.local_package_count == 1
    assert result.dependencies == []
    assert [entry["reason"] for entry in result.unresolved] == [
        "invalid_package_entry",
        "missing_or_invalid_version",
        "non_exact_version",
    ]


@pytest.mark.parametrize("version", [1, 3])
def test_package_bound_includes_local_and_unresolved_entries(version):
    data = {"lockfileVersion": version}
    if version == 1:
        data["dependencies"] = {
            "parent": {"dependencies": {"child": {"version": "1.0.0"}}}
        }
    else:
        data["packages"] = {"": {}, "node_modules/missing": {}}
    with pytest.raises(LockfileLimitError):
        parse(data, max_packages=1)


def test_excessive_nesting_and_input_size_are_bounded():
    text = (
        '{"lockfileVersion":3,"packages":{},"extra":'
        + "[" * 130
        + "0"
        + "]" * 130
        + "}"
    )
    with pytest.raises(LockfileLimitError):
        parse_package_lock(Path("package-lock.json"), text=text)
    with pytest.raises(LockfileLimitError):
        parse_package_lock(Path("package-lock.json"), text=" " * 10_000_001)


def test_reads_utf8_lockfile_and_refuses_symlinks_or_invalid_encoding(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        '{"lockfileVersion":3,"packages":{"node_modules/pkg":{"version":"1.0.0"}}}'
    )
    assert parse_package_lock(path).dependencies[0]["file"] == str(path)
    link = tmp_path / "linked-lock.json"
    link.symlink_to(path)
    with pytest.raises(LockfileParseError):
        parse_package_lock(link)
    path.write_bytes(b'\xff{"lockfileVersion":3,"packages":{}}')
    with pytest.raises(LockfileParseError):
        parse_package_lock(path)


def test_optional_precedence_peer_and_dev_optional_context():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {"pkg": "^1"},
                    "optionalDependencies": {"pkg": "^2"},
                },
                "node_modules/pkg": {
                    "version": "2.0.0",
                    "devOptional": True,
                    "peer": True,
                },
            },
        }
    )
    dep = result.dependencies[0]
    assert dep["dependency_groups"] == [
        "devOptional",
        "optionalDependencies",
        "peerDependencies",
    ]
    assert dep["dependency_dev"] is False
    assert dep["dependency_optional"] is False


def test_version_build_metadata_is_normalized_and_prerelease_preserved():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/pkg": {"version": "1.2.3-beta.4+build.5"}},
        }
    )
    assert result.dependencies[0]["version"] == "1.2.3-beta.4"


@pytest.mark.parametrize("version", [1, 3])
def test_node_modules_in_scope_name_is_not_a_path_segment(version):
    entry = registry("@node_modules/pkg", "1.0.0")
    if version == 1:
        data = {"lockfileVersion": 1, "dependencies": {"@node_modules/pkg": entry}}
    else:
        data = {
            "lockfileVersion": 3,
            "packages": {"node_modules/@node_modules/pkg": entry},
        }
    result = parse(data)
    assert result.unresolved == []
    assert result.dependencies[0]["name"] == "@node_modules/pkg"
    assert result.dependencies[0]["dependency_kind"] == "unknown"


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("dependencies", [], "invalid_dependency_section"),
        ("devDependencies", {"tool": None}, "invalid_dependency_declaration"),
        ("optionalDependencies", {"optional": 1}, "invalid_dependency_declaration"),
        ("peerDependencies", "peer", "invalid_dependency_section"),
        ("peerDependenciesMeta", [], "invalid_peer_dependencies_metadata"),
        (
            "peerDependenciesMeta",
            {"peer": {"optional": "yes"}},
            "invalid_peer_dependencies_metadata",
        ),
        ("workspaces", "packages/*", "invalid_workspaces"),
        ("name", [], "invalid_package_name"),
        ("version", 123, "invalid_package_version"),
    ],
)
@pytest.mark.parametrize("location", ["", "packages/app"])
def test_malformed_local_metadata_is_an_explicit_gap(field, value, reason, location):
    result = parse({"lockfileVersion": 3, "packages": {location: {field: value}}})
    assert result.dependencies == []
    assert any(issue["reason"] == reason for issue in result.unresolved)


def test_missing_required_edges_are_reported_in_roots_workspaces_and_packages():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {"runtime": "^1"},
                    "devDependencies": {"tool": "^1"},
                },
                "packages/app": {"dependencies": {"workspace-dep": "^1"}},
                "node_modules/parent": {
                    "version": "1.0.0",
                    "dependencies": {"transitive": "^1"},
                    "peerDependencies": {"required-peer": "^1"},
                },
            },
        }
    )
    assert {issue["dependency"] for issue in result.unresolved} == {
        "runtime",
        "tool",
        "workspace-dep",
        "transitive",
        "required-peer",
    }
    assert {issue["reason"] for issue in result.unresolved} == {
        "missing_locked_dependency"
    }
    assert result.dependencies[0]["name"] == "parent"


def test_missing_optional_peers_optional_dependencies_and_package_dev_deps_are_allowed():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "dependencies": {"optional": "^1"},
                    "optionalDependencies": {"optional": "^2"},
                    "peerDependencies": {"optional-peer": "^1"},
                    "peerDependenciesMeta": {"optional-peer": {"optional": True}},
                },
                "node_modules/parent": {
                    "version": "1.0.0",
                    "devDependencies": {"author-tool": "^1"},
                    "optionalDependencies": {"platform-package": "^1"},
                    "peerDependencies": {"optional-peer": "^1"},
                    "peerDependenciesMeta": {"optional-peer": {"optional": True}},
                },
            },
        }
    )
    assert result.unresolved == []


def test_legacy_requires_does_not_prove_missing_optional_dependency_is_required():
    result = parse(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "parent": {"version": "1.0.0", "requires": {"possibly-optional": "^1"}},
            },
        }
    )
    assert result.unresolved == []
    assert result.dependencies[0]["dependencies"][0]["name"] == "possibly-optional"


def test_legacy_malformed_requires_is_reported_and_valid_package_kept():
    result = parse(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "parent": {"version": "1.0.0", "requires": ["child"]},
            },
        }
    )
    assert result.dependencies[0]["name"] == "parent"
    assert result.unresolved[0]["reason"] == "invalid_dependency_section"


@pytest.mark.parametrize("target", [None, "packages/missing"])
def test_missing_workspace_link_targets_remain_explicit(target):
    entry = {"link": True}
    if target is not None:
        entry["resolved"] = target
    result = parse(
        {"lockfileVersion": 3, "packages": {"node_modules/local-app": entry}}
    )
    assert result.dependencies == []
    assert result.unresolved[0]["reason"] == "missing_link_target"
    assert result.non_registry_names == ["local-app"]


def test_local_names_include_root_workspace_and_link_alias_identity():
    result = parse(
        {
            "lockfileVersion": 3,
            "name": "root-app",
            "packages": {
                "": {},
                "packages/app": {"name": "@local/app", "version": "1.0.0"},
                "node_modules/alias-app": {"link": True, "resolved": "packages/app"},
            },
        }
    )
    assert result.unresolved == []
    assert result.non_registry_names == ["@local/app", "alias-app", "root-app"]
    assert result.workspace_paths == ["", "packages/app"]


def test_workspace_paths_are_recorded_local_descriptors_not_link_install_paths():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "packages/worker": {"name": "worker"},
                "node_modules/worker": {"link": True, "resolved": "packages/worker"},
                "node_modules/public": {"version": "1.0.0"},
            },
        }
    )
    assert result.workspace_paths == ["", "packages/worker"]
    assert parse({"lockfileVersion": 1, "dependencies": {}}).workspace_paths == []


def test_invalid_workspace_path_or_link_metadata_is_not_silent():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {
                "/absolute-workspace": {"name": "invalid-local"},
                "node_modules/pkg": {"version": "1.0.0", "link": "yes"},
            },
        }
    )
    assert {issue["reason"] for issue in result.unresolved} == {
        "invalid_package_path",
        "invalid_package_metadata",
    }


def test_explicit_null_resolved_source_is_invalid_not_an_unspecified_registry():
    result = parse(
        {
            "lockfileVersion": 3,
            "packages": {"node_modules/pkg": {"version": "1.0.0", "resolved": None}},
        }
    )
    assert result.dependencies == []
    assert result.unresolved[0]["reason"] == "invalid_package_source"
