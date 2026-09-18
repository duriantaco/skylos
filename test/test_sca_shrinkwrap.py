"""npm shrinkwrap inventory contracts using data-only, local fixtures."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.commands.sbom_cmd import run_sbom_command
from skylos.core.gatekeeper import check_gate
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.sarif import SarifExporter
from skylos.reporting.sbom import cyclonedx_bom
from skylos.rules.sca import vulnerability_scanner as sca


def _write(root, filename, value):
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    assert write_text_no_symlink(root / filename, text)


def _lock(version=3, *, name="example", package_version="1.2.3"):
    if version == 1:
        return {
            "lockfileVersion": version,
            "dependencies": {name: {"version": package_version}},
        }
    return {
        "lockfileVersion": version,
        "packages": {
            "": {"name": "app", "dependencies": {name: "^1"}},
            f"node_modules/{name}": {"version": package_version},
        },
    }


def _identities(inventory):
    return {(item["name"], item["version"]) for item in inventory}


def _ignored(root):
    return {
        "file": str(root / "package-lock.json"),
        "selected_file": str(root / "npm-shrinkwrap.json"),
        "reason": "npm_shrinkwrap_precedence",
    }


@pytest.fixture(autouse=True)
def forbid_real_advisory_requests(monkeypatch):
    class Forbidden:
        def post(self, *args, **kwargs):
            pytest.fail("shrinkwrap tests must not use the network")

        def get(self, *args, **kwargs):
            pytest.fail("shrinkwrap tests must not use the network")

    monkeypatch.setattr(sca, "_requests", Forbidden())


@pytest.fixture
def osv(monkeypatch, forbid_real_advisory_requests):
    class Response:
        status_code = 200
        headers = {}

        def __init__(self, payload):
            self.payload = payload

        def iter_content(self, chunk_size):
            yield json.dumps(self.payload).encode("utf-8")

        def close(self):
            pass

    class LocalOSV:
        def __init__(self):
            self.queries = []
            self.details = []
            self.fail_details = False

        def post(self, url, *, json, **kwargs):
            assert url == sca.OSV_BATCH_URL
            assert kwargs["allow_redirects"] is False
            self.queries.extend(json["queries"])
            return Response(
                {
                    "results": [
                        {"vulns": [{"id": "GHSA-test-shrinkwrap"}]}
                        for _ in json["queries"]
                    ]
                }
            )

        def get(self, url, **kwargs):
            assert url == "https://api.osv.dev/v1/vulns/GHSA-test-shrinkwrap"
            self.details.append(url)
            if self.fail_details:
                raise ConnectionError("local advisory fixture unavailable")
            return Response(
                {
                    "id": "GHSA-test-shrinkwrap",
                    "summary": "Local shrinkwrap advisory fixture",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {"package": query["package"]} for query in self.queries
                    ],
                }
            )

    transport = LocalOSV()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


@pytest.mark.parametrize("version", [1, 2, 3])
def test_shrinkwrap_is_supported_inventory(tmp_path, version):
    _write(tmp_path, "npm-shrinkwrap.json", _lock(version))
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["supported_lockfile_count"] == 1
    assert inventory.receipt["unsupported_lockfile_count"] == 0
    assert {(item["name"], item["version"]) for item in inventory} == {
        ("example", "1.2.3")
    }
    assert inventory[0]["file"] == str(tmp_path / "npm-shrinkwrap.json")
    assert inventory[0]["lockfile_version"] == version


@pytest.mark.parametrize("version", [1, 2, 3])
def test_shrinkwrap_overrides_package_lock_before_reading(
    tmp_path, monkeypatch, version
):
    _write(tmp_path, "npm-shrinkwrap.json", _lock(version))
    _write(tmp_path, "package-lock.json", _lock(name="stale", package_version="9.0.0"))
    original_read = sca.read_text_no_symlink
    reads = []

    def record_read(path, **kwargs):
        reads.append(path.name)
        assert path.name != "package-lock.json"
        return original_read(path, **kwargs)

    monkeypatch.setattr(sca, "read_text_no_symlink", record_read)
    inventory = sca.collect_dependencies(tmp_path)
    assert reads == ["npm-shrinkwrap.json"]
    assert _identities(inventory) == {("example", "1.2.3")}
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["supported_manifest_count"] == 1
    assert inventory.receipt["supported_manifest_candidate_count"] == 1
    assert inventory.receipt["lockfile_candidate_count"] == 1
    assert inventory.receipt["ignored_lockfile_count"] == 1
    assert inventory.receipt["ignored_lockfiles"] == [_ignored(tmp_path)]


@pytest.mark.parametrize(
    "invalid",
    [
        "malformed",
        "empty",
        "missing_version",
        "future_version",
        "invalid_utf8",
        "unreadable",
        "symlink",
        "dangling_symlink",
        "directory",
        "directory_symlink",
    ],
)
def test_invalid_selected_shrinkwrap_never_falls_back(
    tmp_path, monkeypatch, osv, invalid
):
    _write(tmp_path, "package-lock.json", _lock(name="stale"))
    selected = tmp_path / "npm-shrinkwrap.json"
    if invalid == "symlink":
        _write(tmp_path, "target.txt", _lock())
        selected.symlink_to(tmp_path / "target.txt")
    elif invalid == "dangling_symlink":
        selected.symlink_to(tmp_path / "missing.txt")
    elif invalid in {"directory", "directory_symlink"}:
        if invalid == "directory":
            selected.mkdir()
        else:
            target = tmp_path / "target"
            target.mkdir()
            selected.symlink_to(target, target_is_directory=True)
    elif invalid == "invalid_utf8":
        assert write_text_no_symlink(selected, "\xff", encoding="latin-1")
    else:
        values = {
            "malformed": "{invalid",
            "empty": "",
            "missing_version": {"packages": {}},
            "future_version": {"lockfileVersion": 999, "packages": {}},
            "unreadable": _lock(),
        }
        _write(tmp_path, "npm-shrinkwrap.json", values[invalid])
    original_read = sca.read_text_no_symlink

    def selected_read(path, **kwargs):
        assert path.name != "package-lock.json"
        if invalid == "unreadable" and path == selected:
            return None
        return original_read(path, **kwargs)

    monkeypatch.setattr(sca, "read_text_no_symlink", selected_read)
    result = sca.scan_dependencies(tmp_path)
    assert result == []
    assert osv.queries == []
    assert result.receipt["complete"] is False
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["parse_error_count"] == 1
    assert result.receipt["supported_lockfile_count"] == 0
    assert result.receipt["lockfile_candidate_count"] == 1
    assert result.receipt["ignored_lockfile_count"] == 1
    assert result.receipt["ignored_lockfiles"] == [_ignored(tmp_path)]


@pytest.mark.parametrize("invalid", ["malformed", "symlink", "directory"])
def test_ignored_bad_package_lock_does_not_poison_selected_inventory(tmp_path, invalid):
    _write(tmp_path, "npm-shrinkwrap.json", _lock())
    if invalid == "malformed":
        _write(tmp_path, "package-lock.json", "invalid data")
    elif invalid == "symlink":
        (tmp_path / "package-lock.json").symlink_to(tmp_path / "missing.txt")
    else:
        (tmp_path / "package-lock.json").mkdir()
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["parse_error_count"] == 0
    assert inventory.receipt["ignored_lockfile_count"] == 1
    assert _identities(inventory) == {("example", "1.2.3")}


def test_directory_named_shrinkwrap_is_not_a_nested_project(tmp_path):
    selected = tmp_path / "npm-shrinkwrap.json"
    selected.mkdir()
    _write(selected, "package-lock.json", _lock(name="hidden"))
    _write(tmp_path, "package-lock.json", _lock(name="stale"))
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory == []
    assert inventory.receipt["parse_error_count"] == 1
    assert inventory.receipt["supported_manifest_candidate_count"] == 1


def test_ignored_package_lock_directory_does_not_hide_nested_project(tmp_path):
    _write(tmp_path, "npm-shrinkwrap.json", _lock())
    nested = tmp_path / "package-lock.json"
    nested.mkdir()
    _write(nested, "package-lock.json", _lock(name="independent"))
    _write(nested, "package.json", {"dependencies": {"independent": "1.2.3"}})
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["ignored_lockfile_count"] == 1
    assert inventory.receipt["supported_lockfile_count"] == 2
    assert inventory.receipt["supported_manifest_count"] == 3
    assert _identities(inventory) == {("example", "1.2.3"), ("independent", "1.2.3")}
    independent = next(item for item in inventory if item["name"] == "independent")
    assert {item["file"] for item in independent["dependency_occurrences"]} == {
        str(nested / "package-lock.json"),
        str(nested / "package.json"),
    }


def test_precedence_is_local_to_each_project_directory(tmp_path):
    _write(tmp_path, "npm-shrinkwrap.json", _lock())
    _write(tmp_path, "package-lock.json", _lock(name="stale"))
    first = tmp_path / "first"
    first.mkdir()
    _write(first, "package-lock.json", _lock(name="independent"))
    second = tmp_path / "second"
    second.mkdir()
    _write(second, "npm-shrinkwrap.json", _lock(name="nested"))
    _write(second, "package-lock.json", _lock(name="nested-stale"))
    inventory = sca.collect_dependencies(tmp_path)
    assert _identities(inventory) == {
        ("example", "1.2.3"),
        ("independent", "1.2.3"),
        ("nested", "1.2.3"),
    }
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["supported_lockfile_count"] == 3
    assert inventory.receipt["ignored_lockfile_count"] == 2
    assert inventory.receipt["ignored_lockfiles"] == [
        _ignored(tmp_path),
        _ignored(second),
    ]


@pytest.mark.parametrize("version", [2, 3])
def test_modern_workspace_environment_and_multiple_version_context(tmp_path, version):
    data = {
        "lockfileVersion": version,
        "packages": {
            "": {"name": "app", "devDependencies": {"tool": "^1"}},
            "packages/web": {
                "name": "web",
                "optionalDependencies": {"@example/native": "^2"},
            },
            "node_modules/web": {"link": True, "resolved": "packages/web"},
            "node_modules/tool": {
                "version": "1.0.0",
                "dev": True,
                "dependencies": {"@example/native": "^2"},
            },
            "node_modules/@example/native": {
                "version": "2.0.0",
                "optional": True,
                "os": ["linux", "darwin"],
                "cpu": ["arm64"],
                "engines": {"node": ">=18"},
            },
            "node_modules/tool/node_modules/@example/native": {"version": "3.0.0"},
        },
    }
    _write(tmp_path, "npm-shrinkwrap.json", data)
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["local_lockfile_package_count"] == 3
    assert inventory.receipt["inventory_scope"] == "all_recorded_lockfile_environments"
    deps = {(item["name"], item["version"]): item for item in inventory}
    assert set(deps) == {
        ("tool", "1.0.0"),
        ("@example/native", "2.0.0"),
        ("@example/native", "3.0.0"),
    }
    tool = deps[("tool", "1.0.0")]
    assert tool["dependency_kind"] == "direct"
    assert tool["dependency_dev"] is True
    assert tool["dependency_roots"] == [""]
    native = deps[("@example/native", "2.0.0")]
    assert native["dependency_roots"] == ["packages/web"]
    assert native["dependency_optional"] is True
    assert native["dependency_groups"] == ["optionalDependencies"]
    assert native["dependency_markers"] == {
        "os": ["linux", "darwin"],
        "cpu": ["arm64"],
        "engines": {"node": ">=18"},
    }
    assert deps[("@example/native", "3.0.0")]["dependency_kind"] == "transitive"
    assert all(item["line"] > 1 for item in inventory)


def test_legacy_nested_dependency_versions_and_flags_survive(tmp_path):
    data = {
        "lockfileVersion": 1,
        "dependencies": {
            "parent": {
                "version": "1.0.0",
                "requires": {"child": "^2"},
                "dependencies": {"child": {"version": "2.0.0", "optional": True}},
            },
            "child": {"version": "3.0.0", "dev": True},
        },
    }
    _write(tmp_path, "npm-shrinkwrap.json", data)
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is True
    deps = {(item["name"], item["version"]): item for item in inventory}
    assert set(deps) == {("parent", "1.0.0"), ("child", "2.0.0"), ("child", "3.0.0")}
    assert deps[("parent", "1.0.0")]["dependency_kind"] == "unknown"
    assert deps[("child", "2.0.0")]["dependency_kind"] == "transitive"
    assert deps[("child", "2.0.0")]["dependency_optional"] is True
    assert deps[("child", "3.0.0")]["dependency_dev"] is True


def test_query_dedup_preserves_manifest_and_multiple_occurrences(tmp_path, osv):
    data = _lock()
    data["packages"]["node_modules/other/node_modules/example"] = {
        "version": "1.2.3",
        "dev": True,
    }
    _write(tmp_path, "npm-shrinkwrap.json", data)
    _write(tmp_path, "package-lock.json", _lock(name="ignored"))
    _write(tmp_path, "package.json", {"dependencies": {"example": "1.2.3"}})
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["complete"] is True
    assert result.receipt["dependency_count"] == 1
    assert result.receipt["dependency_occurrence_count"] == 3
    assert len(osv.queries) == 1
    assert len(osv.details) == 1
    assert len(result) == 1
    occurrences = result[0]["metadata"]["dependency_occurrences"]
    assert len(occurrences) == 3
    assert {item.get("dependency_dev") for item in occurrences} == {None, False, True}
    assert {item["file"] for item in occurrences} == {
        str(tmp_path / "npm-shrinkwrap.json"),
        str(tmp_path / "package.json"),
    }


def test_shrinkwrap_does_not_hide_a_stale_direct_manifest_pin(tmp_path, osv):
    _write(tmp_path, "npm-shrinkwrap.json", _lock(package_version="2.0.0"))
    _write(tmp_path, "package-lock.json", _lock(package_version="9.0.0"))
    _write(tmp_path, "package.json", {"dependencies": {"example": "1.2.3"}})
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["complete"] is True
    assert {query["version"] for query in osv.queries} == {"1.2.3", "2.0.0"}
    assert "lockfile_freshness_not_verified" in result.receipt["limitations"]


@pytest.mark.parametrize("private_selected", [False, True])
def test_only_selected_source_controls_manifest_registry_identity(
    tmp_path, osv, private_selected
):
    public = _lock()
    private = _lock()
    private["packages"]["node_modules/example"]["resolved"] = (
        "https://private.invalid/example.tgz"
    )
    _write(tmp_path, "npm-shrinkwrap.json", private if private_selected else public)
    _write(tmp_path, "package-lock.json", public if private_selected else private)
    _write(tmp_path, "package.json", {"dependencies": {"example": "1.2.3"}})
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["complete"] is not private_selected
    assert result.receipt["manifest_source_conflict_count"] == int(private_selected)
    assert result.receipt["unresolved_lockfile_dependency_count"] == int(
        private_selected
    )
    assert len(osv.queries) == (0 if private_selected else 1)
    assert "private.invalid" not in json.dumps(result.receipt)


@pytest.mark.parametrize("version", [1, 2, 3])
def test_missing_package_version_is_explicit_and_valid_findings_survive(
    tmp_path, osv, version
):
    data = _lock(version)
    entries = data["dependencies"] if version == 1 else data["packages"]
    entries["broken" if version == 1 else "node_modules/broken"] = {"optional": True}
    _write(tmp_path, "npm-shrinkwrap.json", data)
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["complete"] is False
    assert result.receipt["unresolved_lockfile_dependency_count"] == 1
    assert (
        result.receipt["lockfile_issues"][0]["reason"] == "missing_or_invalid_version"
    )
    assert len(result) == 1
    assert result[0]["metadata"]["package_name"] == "example"


@pytest.mark.parametrize("limit", ["manifest_count", "bytes", "dependency_count"])
def test_ignored_package_lock_does_not_consume_inventory_budget(
    tmp_path, monkeypatch, limit
):
    selected = json.dumps(_lock())
    _write(tmp_path, "npm-shrinkwrap.json", selected)
    _write(tmp_path, "package-lock.json", "X" * 10000)
    if limit == "manifest_count":
        monkeypatch.setattr(sca, "MAX_SUPPORTED_MANIFESTS", 1)
    elif limit == "bytes":
        monkeypatch.setattr(sca, "MAX_TOTAL_MANIFEST_BYTES", len(selected.encode()))
    else:
        monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 2)
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["total_manifest_bytes"] == len(selected.encode())
    assert inventory.receipt["supported_manifest_count"] == 1
    assert inventory.receipt["ignored_lockfile_count"] == 1


@pytest.mark.parametrize("limit", ["bytes", "dependency_count"])
def test_selected_shrinkwrap_remains_subject_to_inventory_limits(
    tmp_path, monkeypatch, limit
):
    selected = json.dumps(_lock())
    _write(tmp_path, "npm-shrinkwrap.json", selected)
    _write(tmp_path, "package-lock.json", _lock(name="stale"))
    if limit == "bytes":
        monkeypatch.setattr(sca, "MAX_TOTAL_MANIFEST_BYTES", len(selected.encode()) - 1)
        reason = "manifest_bytes_limit_exceeded"
    else:
        monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 1)
        reason = "dependency_limit_exceeded"
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is False
    assert reason in inventory.receipt["limit_reasons"]
    assert inventory.receipt["ignored_lockfile_count"] == 1
    assert not any(item["name"] == "stale" for item in inventory)


def test_ignored_examples_are_bounded_but_count_is_complete(tmp_path):
    for index in range(30):
        project = tmp_path / f"project-{index:02}"
        project.mkdir()
        _write(project, "npm-shrinkwrap.json", _lock())
        _write(project, "package-lock.json", _lock(name="ignored"))
    inventory = sca.collect_dependencies(tmp_path)
    assert inventory.receipt["complete"] is True
    assert inventory.receipt["supported_lockfile_count"] == 30
    assert inventory.receipt["ignored_lockfile_count"] == 30
    assert len(inventory.receipt["ignored_lockfiles"]) == 25
    assert len(inventory[0]["dependency_occurrences"]) == 30


@pytest.mark.parametrize("broken_sibling", [False, True])
def test_findings_reach_analyzer_sarif_and_gate_with_inventory_receipt(
    tmp_path, osv, broken_sibling
):
    _write(tmp_path, "npm-shrinkwrap.json", _lock())
    _write(tmp_path, "package-lock.json", _lock(name="ignored"))
    if broken_sibling:
        project = tmp_path / "broken"
        project.mkdir()
        _write(project, "npm-shrinkwrap.json", "{invalid")
    report = json.loads(analyze(str(tmp_path), enable_sca=True, grep_verify=False))
    receipt = report["analysis_summary"]["sca_coverage"]
    assert receipt["complete"] is not broken_sibling
    assert receipt["ignored_lockfile_count"] == 1
    assert len(report["dependency_vulnerabilities"]) == 1
    finding = report["dependency_vulnerabilities"][0]
    assert finding["file"] == str(tmp_path / "npm-shrinkwrap.json")
    sarif = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    assert sarif["properties"]["skylos_metadata"]["package_name"] == "example"
    passed, reasons = check_gate(
        report, {"gate": {"max_dependency_vulnerabilities": 0}}
    )
    assert passed is False
    assert any("dependency" in reason.lower() for reason in reasons)
    if broken_sibling:
        assert any("incomplete" in reason.lower() for reason in reasons)


def test_advisory_detail_failure_retains_selected_lockfile_findings(tmp_path, osv):
    _write(tmp_path, "npm-shrinkwrap.json", _lock())
    _write(tmp_path, "package-lock.json", _lock(name="ignored"))
    osv.fail_details = True
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["complete"] is False
    assert len(result) == 1
    assert result[0]["file"] == str(tmp_path / "npm-shrinkwrap.json")
    assert result[0]["metadata"]["advisory_status"] == "unavailable"
    assert [query["package"]["name"] for query in osv.queries] == ["example"]


def test_sbom_makes_ignored_and_selected_paths_relative(tmp_path):
    project = tmp_path / "nested"
    project.mkdir()
    _write(project, "npm-shrinkwrap.json", _lock())
    _write(project, "package-lock.json", _lock(name="ignored"))
    document = cyclonedx_bom(sca.collect_dependencies(tmp_path), tmp_path)
    assert document.receipt["complete"] is True
    assert document.receipt["ignored_lockfiles"] == [
        {
            "file": "nested/package-lock.json",
            "selected_file": "nested/npm-shrinkwrap.json",
            "reason": "npm_shrinkwrap_precedence",
        }
    ]
    assert str(tmp_path) not in json.dumps(document)
    assert [item["name"] for item in document["components"]] == ["example"]


@pytest.mark.parametrize("invalid_selected", [False, True])
def test_sbom_cli_preserves_components_and_returns_incomplete_exit(
    tmp_path, capsys, invalid_selected
):
    _write(tmp_path, "npm-shrinkwrap.json", "{invalid" if invalid_selected else _lock())
    _write(tmp_path, "package-lock.json", _lock(name="ignored"))
    _write(tmp_path, "requirements.txt", "fixture-package==1.0.0\n")
    exit_code = run_sbom_command([str(tmp_path)])
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    receipt = json.loads(
        next(
            item["value"]
            for item in document["metadata"]["properties"]
            if item["name"] == "skylos:inventory:receipt"
        )
    )
    assert exit_code == (2 if invalid_selected else 0)
    assert receipt["complete"] is not invalid_selected
    expected_names = (
        {"fixture-package"} if invalid_selected else {"fixture-package", "example"}
    )
    assert {item["name"] for item in document["components"]} == expected_names
    assert receipt["ignored_lockfiles"][0]["selected_file"] == "npm-shrinkwrap.json"
