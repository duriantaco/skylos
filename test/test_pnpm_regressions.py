"""Parser-to-baseline invariants for pnpm's peer and workspace contexts."""

import json
from pathlib import Path

import pytest
import yaml

from skylos.core.sca_baseline import dependency_fingerprints
from skylos.rules.sca.pnpm_lockfile import parse_pnpm_lock
from skylos.rules.sca.vulnerability_scanner import (
    _make_finding,
    _unique_dependency_inventory,
)


def _lock(version, importers, records):
    data = {"lockfileVersion": f"{version}.0", "importers": importers}
    packages = {}
    snapshots = {}
    for key, snapshot in records.items():
        metadata = {"resolution": {"integrity": "sha512-fixture"}}
        if version == 6:
            packages[f"/{key}"] = {**metadata, **snapshot}
        else:
            packages[key.partition("(")[0]] = metadata
            snapshots[key] = snapshot
    data["packages"] = packages
    if version == 9:
        data["snapshots"] = snapshots
    return data


def _declaration(version):
    return {"specifier": version, "version": version}


def _parse(data):
    return parse_pnpm_lock(
        Path("pnpm-lock.yaml"),
        text=data if isinstance(data, str) else yaml.safe_dump(data, sort_keys=False),
    )


def _identities(data, name="shared"):
    inventory = _parse(data)
    assert inventory.unresolved == []
    dependencies = _unique_dependency_inventory(inventory.dependencies)
    dependency = next(item for item in dependencies if item["name"] == name)
    finding = _make_finding(
        dependency,
        {
            "vuln_id": "GHSA-pnpm-fixture",
            "summary": "Local test advisory",
            "severity": "HIGH",
            "advisory_status": "complete",
        },
    )
    identities = dependency_fingerprints(finding)
    assert identities
    return identities


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize("second_section", ["devDependencies", "optionalDependencies"])
def test_workspace_usage_swap_changes_dependency_identity(version, second_section):
    records = {"shared@1.0.0": {}}
    before = _lock(
        version,
        {
            "apps/runtime": {"dependencies": {"shared": _declaration("1.0.0")}},
            "apps/tooling": {second_section: {"shared": _declaration("1.0.0")}},
        },
        records,
    )
    after = _lock(
        version,
        {
            "apps/runtime": {second_section: {"shared": _declaration("1.0.0")}},
            "apps/tooling": {"dependencies": {"shared": _declaration("1.0.0")}},
        },
        records,
    )
    # The aggregate roots and groups are unchanged, but the runtime consumer is
    # different. A baseline must not accept this as the previously seen usage.
    assert _identities(before) != _identities(after)


@pytest.mark.parametrize("version", [6, 9])
def test_transitive_workspace_usage_swap_changes_dependency_identity(version):
    records = {
        "parent@2.0.0": {"dependencies": {"shared": "1.0.0"}},
        "shared@1.0.0": {},
    }
    before = _lock(
        version,
        {
            "apps/runtime": {"dependencies": {"parent": _declaration("2.0.0")}},
            "apps/tooling": {"devDependencies": {"parent": _declaration("2.0.0")}},
        },
        records,
    )
    after = _lock(
        version,
        {
            "apps/runtime": {"devDependencies": {"parent": _declaration("2.0.0")}},
            "apps/tooling": {"dependencies": {"parent": _declaration("2.0.0")}},
        },
        records,
    )
    assert _identities(before) != _identities(after)


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize(
    "before_suffix,after_suffix",
    [
        ("(peer@1.0.0)", "(peer@2.0.0)"),
        ("(patch_hash=one)", "(patch_hash=two)"),
        ("(patch_hash=one)(peer@1.0.0)", "(patch_hash=two)(peer@1.0.0)"),
    ],
)
def test_snapshot_peer_and_patch_changes_are_not_baseline_equivalent(
    version, before_suffix, after_suffix
):
    def fixture(suffix):
        peer_version = "2.0.0" if "peer@2.0.0" in suffix else "1.0.0"
        records = {f"shared@1.0.0{suffix}": {}}
        if "peer@" in suffix:
            records[f"shared@1.0.0{suffix}"]["dependencies"] = {"peer": peer_version}
            records[f"peer@{peer_version}"] = {}
        return _lock(
            version,
            {".": {"dependencies": {"shared": _declaration(f"1.0.0{suffix}")}}},
            records,
        )

    assert _identities(fixture(before_suffix)) != _identities(fixture(after_suffix))


@pytest.mark.parametrize("version", [6, 9])
def test_mapping_reordering_and_line_changes_preserve_baseline_identity(version):
    data = _lock(
        version,
        {
            "apps/runtime": {
                "dependencies": {"parent": _declaration("2.0.0(peer@1.0.0)")}
            },
            "apps/tooling": {
                "devDependencies": {"parent": _declaration("2.0.0(peer@1.0.0)")}
            },
        },
        {
            "parent@2.0.0(peer@1.0.0)": {
                "dependencies": {"shared": "1.0.0", "peer": "1.0.0"}
            },
            "shared@1.0.0": {},
            "peer@1.0.0": {},
        },
    )

    def reversed_mappings(value):
        if isinstance(value, dict):
            return {
                key: reversed_mappings(item) for key, item in reversed(value.items())
            }
        return value

    reordered = "# Relocated declarations\n\n" + yaml.safe_dump(
        reversed_mappings(data), sort_keys=False
    )
    assert _identities(data) == _identities(reordered)


@pytest.mark.parametrize("version", [6, 9])
def test_yaml12_compatible_unquoted_package_names_are_not_coerced(version):
    prefix = "/" if version == 6 else ""
    names = ("on", "off", "yes", "no")
    text = f"lockfileVersion: '{version}.0'\ndependencies:\n"
    for name in names:
        text += f"  {name}: {{specifier: 1.0.0, version: 1.0.0}}\n"
    text += "packages:\n"
    for name in names:
        text += (
            f"  {prefix}{name}@1.0.0:\n    resolution: {{integrity: sha512-fixture}}\n"
        )
    if version == 9:
        text += "snapshots:\n"
        for name in names:
            text += f"  {name}@1.0.0: {{}}\n"
    inventory = _parse(text)
    assert inventory.unresolved == []
    assert {item["name"] for item in inventory.dependencies} == set(names)
    assert all(item["dependency_kind"] == "direct" for item in inventory.dependencies)


def test_pnpm_loader_does_not_change_global_yaml_safe_loader():
    # Existing CI/config consumers still rely on PyYAML's original resolver.
    legacy_document = "on: yes\noff: no\n"
    assert yaml.safe_load(legacy_document) == {True: True, False: False}
    resolvers = {
        key: list(rules)
        for key, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    constructors = dict(yaml.SafeLoader.yaml_constructors)
    _parse("lockfileVersion: '9.0'\nimporters: {.: {}}\n")
    assert yaml.safe_load(legacy_document) == {True: True, False: False}
    assert yaml.SafeLoader.yaml_implicit_resolvers == resolvers
    assert yaml.SafeLoader.yaml_constructors == constructors


def test_url_source_credentials_are_not_copied_into_inventory_output():
    # These are public, inert fixture markers, never real credentials. The
    # parser must report the source gap without echoing URL authentication.
    source = (
        "https://fixture-user:fixture-password@packages.invalid/private.tgz"
        "?key=fixture-query"
    )
    private_key = f"private@{source}"
    data = _lock(
        9,
        {".": {"dependencies": {"shared": _declaration("1.0.0")}}},
        {"shared@1.0.0": {"dependencies": {"private": private_key}}, private_key: {}},
    )
    data["packages"][private_key] = {
        "name": "private",
        "version": "1.0.0",
        "resolution": {"tarball": source},
    }

    inventory = _parse(data)

    assert inventory.unresolved
    assert {dependency["name"] for dependency in inventory.dependencies} == {"shared"}
    serialized = json.dumps(vars(inventory))
    for marker in ("fixture-user", "fixture-password", "fixture-query"):
        assert marker not in serialized


@pytest.mark.parametrize("version", [6, 9])
def test_redacted_peer_source_contexts_keep_distinct_baseline_identities(version):
    def fixture(marker):
        suffix = f"(peer@https://packages.invalid/peer.tgz?fixture-key={marker})"
        return _lock(
            version,
            {".": {"dependencies": {"shared": _declaration(f"1.0.0{suffix}")}}},
            {f"shared@1.0.0{suffix}": {}},
        )

    first = fixture("fixture-first")
    second = fixture("fixture-second")
    for document in (first, second):
        inventory = _parse(document)
        assert inventory.unresolved == []
        serialized = json.dumps(vars(inventory))
        assert "fixture-key" not in serialized
        assert "packages.invalid" not in serialized
    assert _identities(first) != _identities(second)
