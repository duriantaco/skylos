"""Trusted end-to-end Poetry/Yarn fixtures, replacing only the OSV transport."""

import json

import pytest

import skylos.cli as cli
from skylos.analyzer import analyze
from skylos.core.safe_cache_io import read_text_no_symlink
from skylos.reporting.sarif import SarifExporter
from skylos.rules.sca import vulnerability_scanner as sca


ADVISORY = "GHSA-29mw-wpgm-hmr9"
KINDS = ("poetry", "classic", "berry")


def _write(path, text):
    path.write_text(  # skylos: ignore[SKY-D324] callers use literal fixture filenames below pytest tmp_path
        text, encoding="utf-8"
    )
    return path


def _poetry_package(version, *, private=False):
    return (
        '[[package]]\nname = "example"\n'
        f'version = "{version}"\n'
        'optional = true\npython-versions = ">=3.9"\n'
        'groups = ["dev"]\nmarkers = { dev = "sys_platform == \'win32\'" }\n'
        + (
            '[package.source]\ntype = "legacy"\n'
            'url = "https://user:TOPSECRET@private.example/simple"\n'
            if private
            else ""
        )
    )


def _lock_text(kind, *, multiple=False, private=False):
    if kind == "poetry":
        return (
            _poetry_package("1.2.3", private=private)
            + (_poetry_package("2.0.0") if multiple else "")
            + '[metadata]\nlock-version = "2.1"\npython-versions = ">=3.10"\n'
        )
    if kind == "classic":
        return (
            '# yarn lockfile v1\n\nexample@^1, example@~1:\n  version "1.2.3"\n'
            + (
                '  resolved "https://user:TOPSECRET@private.example/example/-/example-1.2.3.tgz"\n'
                if private
                else '  resolved "https://registry.yarnpkg.com/example/-/example-1.2.3.tgz"\n'
            )
            + ('\nexample@^2:\n  version "2.0.0"\n' if multiple else "")
        )
    data = {
        "__metadata": {"version": 8},
        "local-app@workspace:.": {
            "version": "0.0.0-use.local",
            "resolution": "local-app@workspace:.",
            "linkType": "soft",
            "dependencies": {"example": "npm:^1"},
            "dependenciesMeta": {"example": {"optional": True}},
        },
        "example@npm:^1": {
            "version": "1.2.3",
            "resolution": "example@npm:1.2.3",
            "linkType": "hard",
            "conditions": "os=darwin & cpu=arm64",
            "peerDependencies": {"react": "^18"},
            "peerDependenciesMeta": {"react": {"optional": True}},
        },
    }
    if private:
        data["example@npm:^1"]["resolution"] = (
            "example@npm:1.2.3::__archiveUrl=https%3A%2F%2FTOPSECRET%40private.example"
        )
    if multiple:
        data["local-app@workspace:."]["dependencies"]["local-tool"] = "workspace:*"
        data["local-tool@workspace:*, local-tool@workspace:apps/tool"] = {
            "version": "0.0.0-use.local",
            "resolution": "local-tool@workspace:apps/tool",
            "linkType": "soft",
            "dependencies": {"example": "npm:^2"},
        }
        data["example@npm:^2"] = {
            "version": "2.0.0",
            "resolution": "example@npm:2.0.0",
            "linkType": "hard",
        }
    return json.dumps(data, indent=2)


def _lock(project, kind, **kwargs):
    filename = "poetry.lock" if kind == "poetry" else "yarn.lock"
    return _write(project / filename, _lock_text(kind, **kwargs))


def _manifest(project, kind):
    if kind == "poetry":
        return _write(project / "requirements.txt", "Example==1.2.3\n")
    return _write(project / "package.json", '{"dependencies":{"example":"1.2.3"}}')


@pytest.fixture
def project(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)

    def no_upload(*args, **kwargs):
        pytest.fail("local integration tests must not upload reports")

    monkeypatch.setattr(cli, "upload_report", no_upload)
    return project


@pytest.fixture
def osv(monkeypatch):
    class Response:
        status_code = 200
        headers = {"Content-Type": "application/json"}

        def __init__(self, payload):
            self.payload = payload

        def iter_content(self, chunk_size):
            yield json.dumps(self.payload).encode("utf-8")

        def close(self):
            pass

    class Transport:
        def __init__(self):
            self.queries = []
            self.details = []
            self.fail_details = False

        def post(self, url, *, json, **kwargs):
            assert url == sca.OSV_BATCH_URL
            assert kwargs["timeout"] == 30
            self.queries.extend(json["queries"])
            return Response(
                {"results": [{"vulns": [{"id": ADVISORY}]} for _ in json["queries"]]}
            )

        def get(self, url, **kwargs):
            assert url == f"https://api.osv.dev/v1/vulns/{ADVISORY}"
            assert kwargs["allow_redirects"] is False
            self.details.append(url)
            if self.fail_details:
                raise ConnectionError("fixture advisory retrieval unavailable")
            return Response(
                {
                    "id": ADVISORY,
                    "summary": "Synthetic dependency advisory",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": query["package"],
                            "ranges": [
                                {
                                    "type": "SEMVER"
                                    if query["package"]["ecosystem"] == "npm"
                                    else "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "9.9.9"}],
                                }
                            ],
                        }
                        for query in self.queries
                    ],
                }
            )

    transport = Transport()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


def _run_cli(project, monkeypatch, *extra):
    json_path = project.parent / "report.json"
    sarif_path = project.parent / "report.sarif"
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(project),
            "--sca",
            "--gate",
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
            "--output",
            str(json_path),
            "--sarif",
            str(sarif_path),
            *extra,
        ],
    )
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = exc.code
    json_text = read_text_no_symlink(json_path, max_bytes=2_000_000)
    sarif_text = read_text_no_symlink(sarif_path, max_bytes=2_000_000)
    assert json_text is not None and sarif_text is not None
    return code, json.loads(json_text), json.loads(sarif_text)


def _assert_exported_metadata(exported, metadata):
    # SARIF's existing depth budget bounds nested occurrence details. Top-level
    # package context and occurrence locations/scalars must still survive.
    assert {
        key: value for key, value in exported.items() if key != "dependency_occurrences"
    } == {
        key: value for key, value in metadata.items() if key != "dependency_occurrences"
    }
    assert len(exported["dependency_occurrences"]) == len(
        metadata["dependency_occurrences"]
    )
    for actual, expected in zip(
        exported["dependency_occurrences"], metadata["dependency_occurrences"]
    ):
        nested = {"dependency_markers", "dependencies", "dependency_extra_requirements"}
        assert {key: value for key, value in actual.items() if key not in nested} == {
            key: value for key, value in expected.items() if key not in nested
        }


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("with_source", [False, True])
def test_new_lockfiles_reach_cli_analyzer_json_sarif_and_gate(
    project, monkeypatch, osv, kind, with_source
):
    lockfile = _lock(project, kind)
    if with_source:
        _write(
            project / "app.py",
            'raise AssertionError("target code must never execute")\n',
        )
    code, result, sarif = _run_cli(project, monkeypatch)
    assert code == 1
    coverage = result["analysis_summary"]["sca_coverage"]
    assert coverage["complete"] is True
    assert coverage["category_complete"] is False
    assert coverage["supported_lockfile_count"] == 1
    assert coverage["unsupported_lockfile_count"] == 0
    assert coverage["locked_dependency_count"] == 1
    assert coverage["local_lockfile_package_count"] == (1 if kind == "berry" else 0)
    assert osv.queries == [
        {
            "package": {
                "name": "example",
                "ecosystem": "PyPI" if kind == "poetry" else "npm",
            },
            "version": "1.2.3",
        }
    ]
    finding = result["dependency_vulnerabilities"][0]
    assert finding["file"] == str(lockfile)
    assert finding["metadata"]["advisory_status"] == "complete"
    assert finding["metadata"]["fixed_version"] == "9.9.9"
    exported = sarif["runs"][0]["results"][0]
    assert exported["ruleId"] == finding["rule_id"] == f"SKY-SCA-{ADVISORY}"
    _assert_exported_metadata(
        exported["properties"]["skylos_metadata"], finding["metadata"]
    )
    physical = exported["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == lockfile.name
    assert physical["region"]["startLine"] == finding["line"]


@pytest.mark.parametrize("kind", KINDS)
def test_versions_and_manifest_occurrences_deduplicate_queries_not_evidence(
    project, osv, kind
):
    lockfile = _lock(project, kind, multiple=True)
    manifest = _manifest(project, kind)
    nested = project / "apps" / "tool"
    nested.mkdir(parents=True)
    second_manifest = _manifest(nested, kind)
    result = sca.scan_dependencies(project)
    assert result.receipt["complete"] is True
    assert result.receipt["dependency_count"] == 2
    assert result.receipt["dependency_occurrence_count"] == 4
    assert {query["version"] for query in osv.queries} == {"1.2.3", "2.0.0"}
    assert len(osv.queries) == 2
    assert len(osv.details) == 1
    first = next(
        finding
        for finding in result
        if finding["metadata"]["package_version"] == "1.2.3"
    )
    assert first["file"] == str(lockfile)
    occurrences = first["metadata"]["dependency_occurrences"]
    assert {item["file"] for item in occurrences} == {
        str(lockfile),
        str(manifest),
        str(second_manifest),
    }
    if kind == "berry":
        second = next(
            finding
            for finding in result
            if finding["metadata"]["package_version"] == "2.0.0"
        )
        assert second["metadata"]["dependency_roots"] == ["", "apps/tool"]
        assert second["metadata"]["dependency_kinds"] == ["direct", "transitive"]


@pytest.mark.parametrize("kind", KINDS)
def test_private_sources_suppress_conflicting_pin_only_inside_recorded_project(
    project, osv, kind
):
    _lock(project, kind, private=True)
    _manifest(project, kind)
    unrelated = project / "unrelated"
    unrelated.mkdir()
    public_manifest = _manifest(unrelated, kind)
    result = sca.scan_dependencies(project)
    assert result.receipt["complete"] is False
    assert result.receipt["manifest_source_conflict_count"] == 1
    assert result.receipt["unresolved_lockfile_dependency_count"] == 1
    assert len(osv.queries) == len(result) == 1
    assert result[0]["file"] == str(public_manifest)
    assert "TOPSECRET" not in json.dumps(result.receipt)
    assert "private.example" not in json.dumps(result.receipt)


def test_berry_private_source_guard_includes_recorded_workspace(project, osv):
    _lock(project, "berry", multiple=True, private=True)
    nested = project / "apps" / "tool"
    nested.mkdir(parents=True)
    _manifest(nested, "berry")
    result = sca.scan_dependencies(project)
    assert result.receipt["manifest_source_conflict_count"] == 1
    assert [query["version"] for query in osv.queries] == ["2.0.0"]
    assert [finding["metadata"]["package_version"] for finding in result] == ["2.0.0"]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("invalid", ["malformed", "new_format"])
def test_invalid_lockfile_keeps_other_findings_and_cli_exits_two(
    project, monkeypatch, osv, kind, invalid
):
    filename = "poetry.lock" if kind == "poetry" else "yarn.lock"
    text = "malformed ! lockfile"
    if invalid == "new_format":
        text = {
            "poetry": 'package = []\n[metadata]\nlock-version = "99.0"\n',
            "classic": "# yarn lockfile v99\n",
            "berry": '{"__metadata":{"version":99}}',
        }[kind]
    _write(project / filename, text)
    healthy = _write(project / "requirements.txt", "example==1.2.3\n")
    code, result, sarif = _run_cli(project, monkeypatch, "--force")
    assert code == 2
    coverage = result["analysis_summary"]["sca_coverage"]
    assert coverage["complete"] is False
    assert coverage["parse_error_count"] == 1
    assert len(osv.queries) == 1
    assert (
        len(result["dependency_vulnerabilities"])
        == len(sarif["runs"][0]["results"])
        == 1
    )
    assert result["dependency_vulnerabilities"][0]["file"] == str(healthy)


@pytest.mark.parametrize("kind", KINDS)
def test_lockfile_package_bound_prevents_any_osv_request(
    project, monkeypatch, osv, kind
):
    _lock(project, kind, multiple=True)
    monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 1)
    result = sca.scan_dependencies(project)
    assert result.receipt["complete"] is False
    assert result.receipt["limit_reasons"] == ["dependency_limit_exceeded"]
    assert result == []
    assert osv.queries == osv.details == []


@pytest.mark.parametrize("kind", KINDS)
def test_detail_failure_preserves_matches_in_both_reports(
    project, monkeypatch, osv, kind
):
    _lock(project, kind)
    osv.fail_details = True
    code, result, sarif = _run_cli(project, monkeypatch, "--force")
    assert code == 2
    assert result["analysis_summary"]["sca_coverage"]["complete"] is False
    finding = result["dependency_vulnerabilities"][0]
    assert finding["metadata"]["advisory_status"] == "unavailable"
    assert finding["metadata"]["advisory_error"] == "advisory_transport_error"
    _assert_exported_metadata(
        sarif["runs"][0]["results"][0]["properties"]["skylos_metadata"],
        finding["metadata"],
    )


def test_poetry_environment_context_survives_analyzer_and_sarif(project, osv):
    _lock(project, "poetry")
    result = json.loads(analyze(str(project), enable_sca=True, grep_verify=False))
    finding = result["dependency_vulnerabilities"][0]
    metadata = finding["metadata"]
    assert metadata["dependency_groups"] == ["dev"]
    assert metadata["dependency_dev"] is True
    assert metadata["dependency_optional"] is True
    assert metadata["dependency_markers"]["groups"] == {
        "dev": "sys_platform == 'win32'"
    }
    assert metadata["requires_python"] == ">=3.9"
    assert metadata["lockfile_requires_python"] == ">=3.10"
    assert metadata["lockfile_revision"] == 1
    assert metadata["marker_evaluation"] == "not_evaluated"
    assert metadata["dependency_kind"] == "unknown"
    exported = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    _assert_exported_metadata(exported["properties"]["skylos_metadata"], metadata)


def test_berry_optional_peer_environment_context_survives_findings(project, osv):
    _lock(project, "berry")
    finding = sca.scan_dependencies(project)[0]
    metadata = finding["metadata"]
    assert metadata["dependency_roots"] == [""]
    assert "dependency_dev" not in metadata
    assert metadata["dependency_markers"]["conditions"] == "os=darwin & cpu=arm64"
    assert metadata["dependency_markers"]["yarn_usage"] == [
        {"root": "", "optional": True}
    ]
    assert metadata["dependencies"] == [
        {
            "name": "react",
            "version_spec": "^18",
            "group": "peerDependencies",
            "optional": True,
        }
    ]
    assert (
        metadata["dependency_occurrences"][0]["dependency_markers"]
        == metadata["dependency_markers"]
    )


def test_poetry_transitive_edges_and_extras_survive_scan_context(project, osv):
    _write(
        project / "poetry.lock",
        """[[package]]
name = "example"
version = "1.2.3"
optional = false
python-versions = ">=3.9"
groups = ["main"]
extras = { speed = ["child (==2.0.0)"] }
[package.dependencies]
child = { version = "2.0.0", optional = true, extras = ["fast"], markers = "sys_platform == 'win32'" }
[[package]]
name = "child"
version = "2.0.0"
optional = true
python-versions = ">=3.9"
groups = ["main"]
[extras]
web = ["example"]
[metadata]
lock-version = "2.1"
python-versions = ">=3.10"
""",
    )
    result = sca.scan_dependencies(project)
    assert result.receipt["complete"] is True
    assert {query["package"]["name"] for query in osv.queries} == {"example", "child"}
    parent = next(
        finding
        for finding in result
        if finding["metadata"]["package_name"] == "example"
    )
    child = next(
        finding for finding in result if finding["metadata"]["package_name"] == "child"
    )
    metadata = parent["metadata"]
    assert metadata["dependency_extras"] == ["web"]
    assert metadata["dependency_extra_requirements"] == {
        "speed": [{"name": "child", "requirement": "child (==2.0.0)"}]
    }
    edge = metadata["dependencies"][0]
    assert edge["package_path"] == child["metadata"]["package_path"]
    assert edge["optional"] is True
    assert edge["extras"] == ["fast"]
    assert edge["markers"] == "sys_platform == 'win32'"
    assert (
        metadata["dependency_occurrences"][0]["dependencies"]
        == metadata["dependencies"]
    )


def test_berry_alias_queries_real_identity_and_keeps_alias_evidence(project, osv):
    data = json.loads(_lock_text("berry"))
    data["alias@npm:example@^1"] = data.pop("example@npm:^1")
    data["local-app@workspace:."]["dependencies"] = {"alias": "npm:example@^1"}
    _write(project / "yarn.lock", json.dumps(data))
    result = sca.scan_dependencies(project)
    assert result.receipt["complete"] is True
    assert [query["package"]["name"] for query in osv.queries] == ["example"]
    assert result[0]["metadata"]["dependency_markers"]["yarn_descriptors"] == [
        "alias@npm:example@^1"
    ]


def test_same_name_version_in_different_ecosystems_is_not_collapsed(project, osv):
    _lock(project, "poetry")
    _lock(project, "classic")
    result = sca.scan_dependencies(project)
    assert result.receipt["complete"] is True
    assert result.receipt["supported_lockfile_count"] == 2
    assert len(osv.queries) == len(result) == 2
    assert {query["package"]["ecosystem"] for query in osv.queries} == {"PyPI", "npm"}
    assert len(osv.details) == 1


@pytest.mark.parametrize("kind", KINDS)
def test_inventory_collection_is_offline_even_without_requests(
    project, monkeypatch, osv, kind
):
    _lock(project, kind)
    monkeypatch.setattr(sca, "_requests", None)
    inventory = sca.collect_dependencies(project)
    assert inventory.receipt["complete"] is True
    assert [(item["name"], item["version"]) for item in inventory] == [
        ("example", "1.2.3")
    ]
    assert osv.queries == osv.details == []
