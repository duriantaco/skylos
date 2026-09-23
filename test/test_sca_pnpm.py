"""pnpm inventories reach the scanner without installing or executing packages."""

import json

import pytest
import yaml

from skylos.analyzer import analyze
from skylos.rules.sca import vulnerability_scanner as sca
from test.test_cli_sca_sarif import osv as osv


def _document(version=9, *, importers=None, packages=None):
    """Build the equivalent v6 or v9 lockfile from one small inventory."""
    if importers is None:
        importers = {
            ".": {
                "dependencies": {"example": {"specifier": "^1.2.3", "version": "1.2.3"}}
            }
        }
    if packages is None:
        packages = {"example@1.2.3": {}}
    records = {
        key: {"resolution": {"integrity": "sha512-local-test-fixture"}, **value}
        for key, value in packages.items()
    }
    document = {"lockfileVersion": f"{version}.0", "importers": importers}
    if version == 6:
        document["packages"] = {f"/{key}": value for key, value in records.items()}
    else:
        edge_fields = {
            "dependencies",
            "optionalDependencies",
            "transitivePeerDependencies",
        }
        document["packages"] = {
            key: {
                name: value for name, value in record.items() if name not in edge_fields
            }
            for key, record in records.items()
        }
        document["snapshots"] = {
            key: {name: value for name, value in record.items() if name in edge_fields}
            for key, record in records.items()
        }
    return document


def _write_lockfile(project, document=None):
    path = project / "pnpm-lock.yaml"
    path.write_text(  # skylos: ignore[SKY-D324] all callers use a fresh pytest tmp_path directory
        yaml.safe_dump(_document() if document is None else document, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _write_lockfile_documents(project, *documents):
    path = project / "pnpm-lock.yaml"
    path.write_text(  # skylos: ignore[SKY-D324] all callers use a fresh pytest tmp_path directory
        yaml.safe_dump_all(documents, explicit_start=True, sort_keys=False),
        encoding="utf-8",
    )
    return path


def _query_identities(osv):
    return {
        (query["package"]["name"], query["version"], query["package"]["ecosystem"])
        for query in osv.queries
    }


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize("with_source", [False, True])
def test_pnpm_discovery_reaches_analyzer_without_target_execution(
    tmp_path, osv, version, with_source
):
    lockfile = _write_lockfile(tmp_path, _document(version))
    if with_source:
        source = tmp_path / "app.py"
        source.write_text(
            'raise AssertionError("scanner must not execute this module")\n',
            encoding="utf-8",
        )

    result = json.loads(analyze(str(tmp_path), enable_sca=True, grep_verify=False))

    coverage = result["analysis_summary"]["sca_coverage"]
    assert coverage["complete"] is True
    assert coverage["supported_lockfile_count"] == 1
    assert coverage["unsupported_lockfile_count"] == 0
    assert coverage["locked_dependency_count"] == 1
    assert coverage["inventory_scope"] == "all_recorded_lockfile_environments"
    assert coverage["category_complete"] is False
    assert _query_identities(osv) == {("example", "1.2.3", "npm")}
    finding = result["dependency_vulnerabilities"][0]
    assert finding["file"] == str(lockfile)
    assert finding["line"] > 1
    metadata = finding["metadata"]
    assert metadata["lockfile_version"] == version
    assert metadata["dependency_kind"] == "direct"
    assert metadata["dependency_roots"] == [""]
    assert metadata["dependency_occurrences"][0]["file"] == str(lockfile)


def test_pnpm_environment_and_project_documents_have_complete_coverage(tmp_path, osv):
    _write_lockfile_documents(
        tmp_path,
        _document(
            importers={
                ".": {
                    "configDependencies": {},
                    "packageManagerDependencies": {
                        "pnpm": {"specifier": "12.4.1", "version": "12.4.1"}
                    },
                }
            },
            packages={"pnpm@12.4.1": {"engines": {"node": ">=20"}}},
        ),
        _document(
            importers={
                ".": {
                    "dependencies": {
                        "left-pad": {
                            "specifier": "1.3.0",
                            "version": "1.3.0",
                        }
                    }
                }
            },
            packages={"left-pad@1.3.0": {}},
        ),
    )

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "complete"
    assert result.receipt["complete"] is True
    assert result.receipt["parse_error_count"] == 0
    assert result.receipt["supported_lockfile_count"] == 1
    assert result.receipt["unresolved_lockfile_dependency_count"] == 0
    assert _query_identities(osv) == {
        ("left-pad", "1.3.0", "npm"),
        ("pnpm", "12.4.1", "npm"),
    }


def test_pnpm_bundled_dependencies_are_reported_as_a_complete_scan_limitation(
    tmp_path, osv
):
    _write_lockfile(
        tmp_path,
        _document(
            importers={
                ".": {
                    "dependencies": {
                        "bundler-pkg": {
                            "specifier": "1.0.0",
                            "version": "1.0.0",
                        }
                    }
                }
            },
            packages={
                "bundler-pkg@1.0.0": {"bundledDependencies": ["some-bundled-dep"]}
            },
        ),
    )

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "complete"
    assert result.receipt["complete"] is True
    assert result.receipt["unresolved_lockfile_dependency_count"] == 0
    assert result.receipt["lockfile_limitation_count"] == 1
    assert result.receipt["lockfile_limitations"][0]["reason"] == (
        "bundled_dependencies_not_enumerated"
    )
    assert "bundled_dependencies_not_enumerated" in result.receipt["limitations"]
    assert _query_identities(osv) == {("bundler-pkg", "1.0.0", "npm")}


@pytest.mark.parametrize("version", [6, 9])
def test_pnpm_keeps_transitive_versions_alias_identity_and_workspace_context(
    tmp_path, osv, version
):
    document = _document(
        version,
        importers={
            ".": {
                "dependencies": {
                    "tool": {"specifier": "^1.0.0", "version": "1.0.0"},
                    "alias": {
                        "specifier": "npm:example@1.2.3",
                        "version": "example@1.2.3",
                    },
                }
            },
            "packages/worker": {
                "devDependencies": {
                    "example": {"specifier": "1.2.3", "version": "1.2.3"}
                },
                "optionalDependencies": {
                    "native": {"specifier": "1.0.0", "version": "1.0.0"}
                },
            },
        },
        packages={
            "tool@1.0.0": {"dependencies": {"example": "2.0.0"}},
            "example@1.2.3": {},
            "example@2.0.0": {},
            "native@1.0.0": {"os": ["linux"], "cpu": ["x64"]},
        },
    )
    _write_lockfile(tmp_path, document)

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["complete"] is True
    assert _query_identities(osv) == {
        ("tool", "1.0.0", "npm"),
        ("example", "1.2.3", "npm"),
        ("example", "2.0.0", "npm"),
        ("native", "1.0.0", "npm"),
    }
    assert len(osv.queries) == 4
    assert len(osv.advisory_requests) == 1
    findings = {
        (item["metadata"]["package_name"], item["metadata"]["package_version"]): item[
            "metadata"
        ]
        for item in result
    }
    shared = findings[("example", "1.2.3")]
    shared_occurrences = shared["dependency_occurrences"]
    assert {
        root for entry in shared_occurrences for root in entry["dependency_roots"]
    } == {"", "packages/worker"}
    assert {
        group for entry in shared_occurrences for group in entry["dependency_groups"]
    } >= {"dependencies", "devDependencies"}
    assert any(
        "" in entry["dependency_roots"] and entry["dependency_dev"] is False
        for entry in shared_occurrences
    )
    transitive = findings[("example", "2.0.0")]
    assert transitive["dependency_kind"] == "transitive"
    assert transitive["dependency_roots"] == [""]
    native = findings[("native", "1.0.0")]
    assert native["dependency_roots"] == ["packages/worker"]
    assert native["dependency_optional"] is True
    assert native["dependency_markers"]["os"] == ["linux"]
    assert native["dependency_markers"]["cpu"] == ["x64"]


@pytest.mark.parametrize("version", [6, 9])
@pytest.mark.parametrize("section", ["devDependencies", "optionalDependencies"])
def test_pnpm_transitive_dependency_keeps_its_root_usage_context(
    tmp_path, osv, version, section
):
    _write_lockfile(
        tmp_path,
        _document(
            version,
            importers={
                "packages/worker": {
                    section: {"tool": {"specifier": "1.0.0", "version": "1.0.0"}}
                }
            },
            packages={
                "tool@1.0.0": {"dependencies": {"example": "1.2.3"}},
                "example@1.2.3": {},
            },
        ),
    )

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["complete"] is True
    metadata = next(
        item["metadata"]
        for item in result
        if item["metadata"]["package_name"] == "example"
    )
    assert metadata["dependency_kind"] == "transitive"
    assert metadata["dependency_roots"] == ["packages/worker"]
    assert section in metadata["dependency_groups"]
    assert metadata["dependency_dev"] is (section == "devDependencies")
    assert metadata["dependency_optional"] is (section == "optionalDependencies")


@pytest.mark.parametrize("version", [6, 9])
def test_pnpm_deduplicates_manifest_and_independent_lockfile_queries(
    tmp_path, osv, version
):
    lockfile = _write_lockfile(tmp_path, _document(version))
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies": {"example": "1.2.3"}}', encoding="utf-8")
    nested = tmp_path / "independent"
    nested.mkdir()
    nested_lockfile = _write_lockfile(nested, _document(version))

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["complete"] is True
    assert len(osv.queries) == 1
    assert len(osv.advisory_requests) == 1
    assert len(result) == 1
    assert result[0]["file"].endswith("pnpm-lock.yaml")
    occurrences = result[0]["metadata"]["dependency_occurrences"]
    assert {item["file"] for item in occurrences} == {
        str(lockfile),
        str(manifest),
        str(nested_lockfile),
    }


@pytest.mark.parametrize("version", [6, 9])
def test_pnpm_nonregistry_and_workspace_links_are_not_queried_as_public_packages(
    tmp_path, osv, version
):
    _write_lockfile(
        tmp_path,
        _document(
            version,
            importers={
                ".": {
                    "dependencies": {
                        "example": {"specifier": "1.2.3", "version": "1.2.3"},
                        "private": {"specifier": "1.0.0", "version": "1.0.0"},
                        "workspace-tool": {
                            "specifier": "workspace:*",
                            "version": "link:packages/workspace-tool",
                        },
                    }
                },
                "packages/workspace-tool": {},
            },
            packages={
                "example@1.2.3": {},
                "private@1.0.0": {
                    "resolution": {"tarball": "https://private.invalid/private.tgz"}
                },
            },
        ),
    )
    manifest = tmp_path / "package.json"
    manifest.write_text(
        '{"dependencies": {"private": "1.0.0", "workspace-tool": "1.0.0"}}',
        encoding="utf-8",
    )

    result = sca.scan_dependencies(tmp_path)

    assert _query_identities(osv) == {("example", "1.2.3", "npm")}
    assert result.receipt["complete"] is False
    assert result.receipt["unresolved_lockfile_dependency_count"] >= 1
    assert result.receipt["manifest_source_conflict_count"] == 2
    assert "private.invalid" not in json.dumps(result.receipt)
    assert [item["metadata"]["package_name"] for item in result] == ["example"]


@pytest.mark.parametrize("version", [6, 9])
def test_pnpm_stale_manifest_pin_does_not_hide_a_different_version(
    tmp_path, osv, version
):
    _write_lockfile(tmp_path, _document(version))
    manifest = tmp_path / "package.json"
    manifest.write_text('{"dependencies": {"example": "2.0.0"}}', encoding="utf-8")

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["complete"] is True
    assert _query_identities(osv) == {
        ("example", "1.2.3", "npm"),
        ("example", "2.0.0", "npm"),
    }
    assert "lockfile_freshness_not_verified" in result.receipt["limitations"]


@pytest.mark.parametrize("version", [6, 9])
def test_pnpm_missing_transitive_graph_target_retains_known_findings(
    tmp_path, osv, version
):
    _write_lockfile(
        tmp_path,
        _document(
            version,
            packages={"example@1.2.3": {"dependencies": {"missing": "2.0.0"}}},
        ),
    )

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["complete"] is False
    assert result.receipt["unresolved_lockfile_dependency_count"] >= 1
    assert "missing_locked_dependency" in json.dumps(result.receipt)
    assert _query_identities(osv) == {("example", "1.2.3", "npm")}
    assert [item["metadata"]["package_name"] for item in result] == ["example"]


@pytest.mark.parametrize("version", [6, 9])
def test_pnpm_malformed_package_row_preserves_valid_sibling_findings(
    tmp_path, osv, version
):
    document = _document(version)
    key = "/broken@2.0.0" if version == 6 else "broken@2.0.0"
    document["packages"][key] = "not a package record"
    _write_lockfile(tmp_path, document)

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["complete"] is False
    assert result.receipt["unresolved_lockfile_dependency_count"] >= 1
    assert _query_identities(osv) == {("example", "1.2.3", "npm")}
    assert [item["metadata"]["package_name"] for item in result] == ["example"]


@pytest.mark.parametrize("missing_table", ["packages", "snapshots"])
def test_pnpm_v9_missing_inventory_half_is_explicitly_incomplete(
    tmp_path, osv, missing_table
):
    document = _document()
    del document[missing_table]
    _write_lockfile(tmp_path, document)

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "incomplete"
    assert result.receipt["complete"] is False
    assert (
        result.receipt["unresolved_lockfile_dependency_count"]
        + result.receipt["parse_error_count"]
    ) >= 1


@pytest.mark.parametrize(
    "invalid",
    ["malformed", "duplicate_key", "future_version", "invalid_utf8", "symlink"],
)
def test_pnpm_invalid_lockfile_cannot_be_reported_as_a_complete_scan(
    tmp_path, osv, invalid
):
    lockfile = tmp_path / "pnpm-lock.yaml"
    if invalid == "symlink":
        target = tmp_path / "target.yaml"
        target.write_text(yaml.safe_dump(_document()), encoding="utf-8")
        lockfile.symlink_to(target)
    elif invalid == "invalid_utf8":
        lockfile.write_bytes(b"\xff")
    else:
        content = {
            "malformed": "lockfileVersion: [\n",
            "duplicate_key": "lockfileVersion: '9.0'\nlockfileVersion: '6.0'\n",
            "future_version": "lockfileVersion: '999.0'\npackages: {}\n",
        }[invalid]
        lockfile.write_text(content, encoding="utf-8")

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["status"] == "incomplete"
    assert result.receipt["parse_error_count"] == 1
    assert osv.queries == []


def test_pnpm_inventory_limit_stops_before_any_advisory_requests(
    tmp_path, osv, monkeypatch
):
    _write_lockfile(
        tmp_path,
        _document(packages={"example@1.2.3": {}, "example@2.0.0": {}}),
    )
    monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 1)

    result = sca.scan_dependencies(tmp_path)

    assert result.receipt["complete"] is False
    assert result.receipt["limit_reasons"] == ["dependency_limit_exceeded"]
    assert osv.queries == []
