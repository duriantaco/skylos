from pathlib import Path

import pytest

from skylos.rules.sca.lockfile_types import LockfileLimitError, LockfileParseError
from skylos.rules.sca.uv_lockfile import parse_uv_lock


def _parse(text, **kwargs):
    return parse_uv_lock(Path("uv.lock"), text=text, **kwargs)


def _package(
    name, version="1.0", source='registry = "https://pypi.org/simple"', **fields
):
    return (
        f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = {{ {source} }}\n'
        + "\n".join(f"{key} = {value}" for key, value in fields.items())
        + "\n"
    )


def test_runtime_transitive_packages_keep_workspace_and_source_locations():
    text = (
        'version = 1\nrevision = 3\nrequires-python = ">=3.10"\n'
        + _package("app", source='editable = "."', dependencies='[{ name = "HTTPX" }]')
        + _package("HTTPX", "0.23.0", dependencies='[{ name = "httpcore" }]')
        + _package("httpcore", "0.15.0")
    )
    result = _parse(text)
    assert result.package_count == 3
    assert result.local_package_count == 1
    assert result.unresolved == []
    httpx, httpcore = result.dependencies
    assert (httpx["name"], httpx["version"], httpx["dependency_kind"]) == (
        "httpx",
        "0.23.0",
        "direct",
    )
    assert httpcore["dependency_kind"] == "transitive"
    assert httpcore["dependency_groups"] == ["production"]
    assert httpcore["dependency_roots"] == ["app"]
    assert httpcore["dependency_optional"] is False
    assert httpcore["dependency_dev"] is False
    assert httpcore["environment_scope"] == "all_locked_environments"
    assert httpx["dependencies"][0]["package_path"] == "package[2]"
    for package in result.dependencies:
        assert (
            text.splitlines()[package["line"] - 1].lower()
            == f'name = "{package["name"]}"'
        )


@pytest.mark.parametrize("group_section", ["dev-dependencies", "dependency-groups"])
def test_dev_groups_propagate_to_transitives_and_mixed_runtime_use(group_section):
    result = _parse(
        "version = 1\n"
        + _package("app", source='virtual = "."', dependencies='[{ name = "shared" }]')
        + f'\n[package.{group_section}]\nlint = [{{ name = "linter" }}]\n'
        + _package("linter", dependencies='[{ name = "shared" }, { name = "helper" }]')
        + _package("shared")
        + _package("helper")
    )
    linter, shared, helper = result.dependencies
    assert linter["dependency_kind"] == "direct"
    assert helper["dependency_kind"] == "transitive"
    assert helper["dependency_groups"] == ["lint"]
    assert helper["dependency_dev"] is True
    assert shared["dependency_kinds"] == ["direct", "transitive"]
    assert shared["dependency_groups"] == ["lint", "production"]
    assert shared["dependency_dev"] is False


def test_root_extras_and_dependency_extras_preserve_selection_evidence():
    result = _parse(
        "version = 1\n"
        + _package(
            "app",
            source='editable = "."',
            dependencies='[{ name = "client", extra = ["http2"] }]',
        )
        + '\n[package.optional-dependencies]\ncloud = [{ name = "cloud-client" }]\n'
        + _package("client")
        + '\n[package.optional-dependencies]\nhttp2 = [{ name = "h2" }]\nsocks = [{ name = "socks" }]\n'
        + _package("cloud-client", dependencies='[{ name = "cloud-helper" }]')
        + _package("h2")
        + _package("socks")
        + _package("cloud-helper")
    )
    packages = {dep["name"]: dep for dep in result.dependencies}
    assert packages["client"]["dependency_extras"] == ["http2"]
    assert packages["h2"]["dependency_kind"] == "transitive"
    assert packages["h2"]["dependency_optional"] is False
    assert packages["h2"]["dependency_groups"] == ["production"]
    assert packages["cloud-helper"]["dependency_optional"] is True
    assert packages["cloud-helper"]["dependency_dev"] is False
    assert packages["cloud-helper"]["dependency_groups"] == ["extra:cloud"]
    # Still inventory every locked distribution, without inventing a root path.
    assert packages["socks"]["dependency_kind"] == "unknown"
    assert packages["socks"]["dependency_optional"] is None


def test_multiple_versions_keep_branch_markers_and_graph_resolution():
    text = (
        "version = 1\nresolution-markers = [\"python_full_version < '3.11'\", \"python_full_version >= '3.11'\"]\n"
        + _package(
            "app",
            source='virtual = "."',
            dependencies='[{ name = "urllib3", version = "1.26.0", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version < \'3.11\'" }, { name = "urllib3", version = "2.0.0", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version >= \'3.11\'" }]',
        )
        + _package("urllib3", "1.26.0", dependencies='[{ name = "helper" }]')
        + _package("urllib3", "2.0.0")
        + _package("helper")
    )
    result = _parse(text)
    old, new, helper = result.dependencies
    assert result.unresolved == []
    assert [p["version"] for p in result.dependencies[:2]] == ["1.26.0", "2.0.0"]
    assert old["dependency_markers"] == ["python_full_version < '3.11'"]
    assert new["dependency_markers"] == ["python_full_version >= '3.11'"]
    assert helper["dependency_markers"] == old["dependency_markers"]
    assert old["package_path"] != new["package_path"]


def test_workspace_members_are_roots_but_external_local_directories_are_not():
    result = _parse(
        'version = 1\n[manifest]\nmembers = ["app", "worker"]\n'
        + _package("app", source='editable = "."', dependencies='[{ name = "vendor" }]')
        + _package(
            "worker",
            source='editable = "packages/worker"',
            dependencies='[{ name = "shared" }]',
        )
        + _package(
            "vendor",
            source='directory = "../vendor"',
            dependencies='[{ name = "shared" }]',
        )
        + _package("shared")
    )
    dep = result.dependencies[0]
    assert result.local_package_count == 3
    assert dep["dependency_roots"] == ["app", "worker"]
    assert dep["dependency_kinds"] == ["direct", "transitive"]


@pytest.mark.parametrize(
    "source,reason",
    [
        ('registry = "https://private.example/simple"', "non_public_registry"),
        ('registry = "https://pypi.org.example/simple"', "non_public_registry"),
        ('registry = "https://user:secret@pypi.org/simple"', "non_public_registry"),
        ('registry = "https://pypi.org/simple?token=secret"', "non_public_registry"),
        ('git = "https://example.test/pkg.git#abcdef"', "non_registry_source"),
        ('url = "https://files.pythonhosted.org/example.whl"', "non_registry_source"),
        ('path = "vendor/pkg.whl"', "non_registry_source"),
        (
            'registry = "https://pypi.org/simple", git = "other"',
            "unsupported_package_source",
        ),
    ],
)
def test_non_public_sources_are_explicit_gaps_without_credential_disclosure(
    source, reason
):
    result = _parse("version = 1\n" + _package("requests", source=source))
    assert result.dependencies == []
    assert result.local_package_count == 0
    assert result.unresolved == [
        {
            "reason": reason,
            "package": "requests",
            "line": 4,
            "name": "requests",
            "version": "1.0",
        }
    ]
    assert "secret" not in repr(result)


def test_public_transitives_of_private_packages_are_still_inventoried():
    result = _parse(
        "version = 1\n"
        + _package(
            "app", source='virtual = "."', dependencies='[{ name = "private-pkg" }]'
        )
        + _package(
            "private-pkg",
            source='registry = "https://private.test/simple"',
            dependencies='[{ name = "public-pkg" }]',
        )
        + _package("public-pkg")
    )
    assert len(result.unresolved) == 1
    assert result.dependencies[0]["dependency_kind"] == "transitive"
    assert result.dependencies[0]["dependency_roots"] == ["app"]


def test_toml_location_scope_ignores_metadata_comments_and_multiline_strings():
    text = '''version = 1
description = """
[[package]]
name = "misleading"
"""
# [[package]]
[["package"]]
"name" = "Actual_Package"
version = "2.0"
source = { registry = "https://pypi.org/simple" }
[package.metadata]
name = "metadata"
requires-dist = [{name = "not-locked", specifier = "==0.1"}]
[[package]]
name = "other"
version = "3.0"
source = { registry = "https://pypi.org/simple" }
'''
    result = _parse(text)
    assert [(p["name"], p["line"]) for p in result.dependencies] == [
        ("actual-package", 8),
        ("other", 15),
    ]
    assert result.dependencies[0]["dependency_kind"] == "unknown"
    assert result.unresolved == []


def test_empty_lock_inventory_and_compatible_revision():
    result = _parse("version = 1\nrevision = 999\npackage = []")
    assert result.format_version == 1
    assert result.package_count == 0
    assert result.dependencies == []


@pytest.mark.parametrize("version", ["0", "2", "true", '"1"'])
def test_unsupported_schema_is_not_a_clean_empty_scan(version):
    with pytest.raises(LockfileParseError):
        _parse(f"version = {version}\npackage = []")


@pytest.mark.parametrize(
    "text",
    [
        "not TOML",
        "version = 1",
        "version = 1\npackage = {}",
        'version = 1\nrevision = "3"\npackage = []',
        "version = 1\npackage = [4]",
        "version = 1\n[[package]]\nname='x'\ndependencies = ['not-an-edge']",
        "version = 1\n[[package]]\nname='x'\noptional-dependencies = []",
        "version = 1\n[[package]]\nname='x'\nresolution-markers = 1",
    ],
)
def test_malformed_lockfiles_raise_parse_errors(text):
    with pytest.raises(LockfileParseError):
        _parse(text)


@pytest.mark.parametrize("version", ["", ">=1.0", "1.*", "garbage"])
def test_unresolved_version_does_not_become_osv_query(version):
    result = _parse("version = 1\n" + _package("requests", version))
    assert result.dependencies == []
    assert result.unresolved[0]["reason"] == "invalid_locked_version"


@pytest.mark.parametrize(
    "version", ["1!2.0", "1.0rc1", "1.0.post2", "1.0.dev3", "1.0+abc.4"]
)
def test_normalized_pep440_versions_remain_exact(version):
    result = _parse("version = 1\n" + _package("example", version))
    assert result.dependencies[0]["version"] == version


def test_ambiguous_and_missing_graph_edges_are_explicit_coverage_gaps():
    result = _parse(
        "version = 1\n"
        + _package(
            "app",
            source='virtual = "."',
            dependencies='[{ name = "multi" }, { name = "absent" }]',
        )
        + _package("multi", "1.0")
        + _package("multi", "2.0")
    )
    assert {p["reason"] for p in result.unresolved} == {
        "ambiguous_locked_dependency",
        "missing_locked_dependency",
    }
    assert len(result.dependencies) == 2
    assert all(p["dependency_kind"] == "unknown" for p in result.dependencies)


def test_dependency_cycles_terminate_with_group_and_marker_evidence():
    result = _parse(
        "version = 1\n"
        + _package("app", source='virtual = "."', dependencies='[{ name = "first" }]')
        + _package(
            "first",
            dependencies='[{ name = "second", marker = "sys_platform == \'linux\'" }]',
        )
        + _package("second", dependencies='[{ name = "first" }]')
    )
    assert len(result.dependencies) == 2
    assert all(p["dependency_groups"] == ["production"] for p in result.dependencies)


def test_package_and_graph_bounds_are_failures_not_truncated_inventories(monkeypatch):
    text = (
        "version = 1\n"
        + _package("app", source='virtual = "."', dependencies='[{ name = "x" }]')
        + _package("x")
    )
    with pytest.raises(LockfileLimitError, match="package limit"):
        _parse(text, max_packages=1)
    monkeypatch.setattr("skylos.rules.sca.uv_lockfile.MAX_GRAPH_STATES", 1)
    with pytest.raises(LockfileLimitError, match="context limit"):
        _parse(text)


def test_bounded_strict_reads_reject_symlinks_and_invalid_utf8(tmp_path):
    path = tmp_path / "uv.lock"
    path.write_text("version = 1\n" + _package("example"))
    assert parse_uv_lock(path).dependencies[0]["name"] == "example"
    link = tmp_path / "linked.lock"
    link.symlink_to(path)
    with pytest.raises(LockfileParseError):
        parse_uv_lock(link)
    path.write_bytes(b"version = 1\n# \xff")
    with pytest.raises(LockfileParseError):
        parse_uv_lock(path)
    with pytest.raises(LockfileParseError):
        parse_uv_lock(tmp_path / "missing.lock")


def test_text_byte_limit_is_enforced(monkeypatch):
    monkeypatch.setattr("skylos.rules.sca.uv_lockfile.MAX_UV_LOCK_BYTES", 16)
    with pytest.raises(LockfileLimitError, match="byte limit"):
        _parse("version = 1\npackage = []")


def test_file_byte_limit_is_enforced(tmp_path, monkeypatch):
    path = tmp_path / "uv.lock"
    path.write_text("version = 1\npackage = []")
    monkeypatch.setattr("skylos.rules.sca.uv_lockfile.MAX_UV_LOCK_BYTES", 16)
    with pytest.raises(LockfileLimitError, match="byte limit"):
        parse_uv_lock(path)


def test_dependency_edge_bound_applies_even_without_workspace_roots(monkeypatch):
    monkeypatch.setattr("skylos.rules.sca.uv_lockfile.MAX_DEPENDENCY_EDGES", 1)
    with pytest.raises(LockfileLimitError, match="dependency edge limit"):
        _parse(
            "version = 1\n"
            + _package("example", dependencies='[{ name = "one" }, { name = "two" }]')
        )


def test_non_project_manifest_requirements_and_groups_propagate_context():
    result = _parse(
        'version = 1\n[manifest]\nrequirements = [{ name = "client", specifier = ">=1", extras = ["http2"] }]\n'
        '[manifest.dependency-groups]\ndev = [{ name = "pytest", specifier = ">=8", marker = "sys_platform == \'linux\'" }]\n'
        + _package("client")
        + '[package.optional-dependencies]\nhttp2 = [{ name = "h2" }]\n'
        + _package("h2")
        + _package("pytest", "8.0", dependencies='[{ name = "helper" }]')
        + _package("helper")
    )
    assert result.package_count == 4
    assert result.local_package_count == 0
    assert result.unresolved == []
    client, h2, pytest_package, helper = result.dependencies
    assert client["dependency_kind"] == "direct"
    assert client["dependency_groups"] == ["production"]
    assert client["dependency_dev"] is False
    assert client["dependency_extras"] == ["http2"]
    assert h2["dependency_kind"] == "transitive"
    assert pytest_package["dependency_kind"] == "direct"
    assert helper["dependency_kind"] == "transitive"
    assert helper["dependency_dev"] is True
    assert helper["dependency_groups"] == ["dev"]
    assert helper["dependency_roots"] == ["<manifest>"]
    assert helper["dependency_markers"] == ["sys_platform == 'linux'"]


@pytest.mark.parametrize("section", ["dev-dependencies", "dependency-groups"])
def test_group_named_production_is_still_dev_and_does_not_merge_runtime_state(section):
    result = _parse(
        "version = 1\n"
        + _package("app", source='virtual = "."', dependencies='[{ name = "mixed" }]')
        + f'[package.{section}]\nproduction = [{{ name = "dev-only" }}, {{ name = "mixed" }}]\n'
        + _package("dev-only", dependencies='[{ name = "dev-helper" }]')
        + _package("dev-helper")
        + _package("mixed", dependencies='[{ name = "mixed-helper" }]')
        + _package("mixed-helper")
    )
    dev_only, dev_helper, mixed, mixed_helper = result.dependencies
    assert dev_only["dependency_dev"] is True
    assert dev_helper["dependency_dev"] is True
    assert dev_helper["dependency_sections"] == [section]
    assert mixed["dependency_dev"] is False
    assert mixed_helper["dependency_dev"] is False
    assert mixed_helper["dependency_sections"] == sorted(["dependencies", section])


def test_manifest_group_named_production_retains_dev_identity():
    result = _parse(
        'version = 1\n[manifest.dependency-groups]\nproduction = [{name = "tool"}]\n'
        + _package("tool")
    )
    assert result.dependencies[0]["dependency_dev"] is True
    assert result.dependencies[0]["dependency_sections"] == ["dependency-groups"]


def test_manifest_declarations_do_not_supply_query_versions_or_guess_ambiguous_forks():
    result = _parse(
        'version = 1\n[manifest]\nrequirements = [{name = "multi", specifier = ">=1"}, {name = "absent", specifier = "==3.0"}]\n'
        + _package("multi", "1.0")
        + _package("multi", "2.0")
    )
    assert [(d["name"], d["version"]) for d in result.dependencies] == [
        ("multi", "1.0"),
        ("multi", "2.0"),
    ]
    assert all(d["dependency_kind"] == "unknown" for d in result.dependencies)
    assert {p["reason"] for p in result.unresolved} == {
        "ambiguous_locked_dependency",
        "missing_locked_dependency",
    }


def test_manifest_exact_pin_selects_existing_locked_version():
    result = _parse(
        'version = 1\n[manifest]\nrequirements = [{name = "multi", specifier = "==2.0"}]\n'
        + _package("multi", "1.0")
        + _package("multi", "2.0")
    )
    assert result.unresolved == []
    assert [d["dependency_kind"] for d in result.dependencies] == ["unknown", "direct"]


@pytest.mark.parametrize(
    "manifest",
    [
        "requirements = {}",
        "requirements = ['example']",
        "dependency-groups = []",
        "dependency-groups = {dev = {}}",
        "requirements = [{name='example',specifier=2}]",
        "requirements = [{name='example',extras='fast'}]",
        "requirements = [{name='example',marker=3}]",
    ],
)
def test_malformed_manifest_context_is_not_silently_ignored(manifest):
    with pytest.raises(LockfileParseError):
        _parse("version = 1\n[manifest]\n" + manifest + "\n" + _package("example"))


def test_validated_local_source_tree_names_are_exposed_for_manifest_source_guard():
    result = _parse(
        "version = 1\n"
        + _package("App_Root", source='virtual = "."')
        + _package("local-editable", source='editable = "packages/one"')
        + _package("local-directory", source='directory = "../local"')
        + _package("bad name", source='editable = "packages/bad"')
        + _package("archive", source='path = "archive.whl"')
        + _package("public")
    )
    assert result.non_registry_names == [
        "app-root",
        "local-directory",
        "local-editable",
    ]


def test_workspace_paths_include_only_root_and_declared_source_tree_members():
    result = _parse(
        'version = 1\n[manifest]\nmembers = ["app", "worker", "service", "external", "archive"]\n'
        + _package("app", source='virtual = "."')
        + _package("worker", source='editable = "packages/worker"')
        + _package("service", source='directory = "packages/service"')
        + _package("external", source='editable = "../external"')
        + _package("vendor", source='directory = "vendor/library"')
        + _package("archive", source='path = "archive.whl"')
        + _package("public")
    )
    # Keep the recorded strings. The scanner owns directory-boundary checks;
    # this parser must not resolve or read a member's filesystem location.
    assert result.workspace_paths == [
        ".",
        "../external",
        "packages/service",
        "packages/worker",
    ]
    assert "vendor/library" not in result.workspace_paths
    assert "archive.whl" not in result.workspace_paths


def test_manifest_only_root_has_no_invented_workspace_paths():
    result = _parse(
        'version = 1\n[manifest.dependency-groups]\ndev = [{name = "tool"}]\n'
        + _package("tool")
    )
    assert result.workspace_paths == []
