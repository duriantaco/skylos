"""End-to-end locked inventories using local data and a mocked OSV transport."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.core.gatekeeper import check_gate
from skylos.reporting.sarif import SarifExporter
from skylos.rules.sca import vulnerability_scanner as sca


def _npm_lock(path, *, version="1.2.3", resolved=None, duplicate=False):
    record = {"version": version}
    if resolved is not None:
        record["resolved"] = resolved
    packages = {
        "": {"name": "local-app", "dependencies": {"example": "^1.0.0"}},
        "node_modules/example": record,
    }
    if duplicate:
        packages["node_modules/other/node_modules/example"] = dict(record, dev=True)
    path.write_text(  # skylos: ignore[SKY-D324] all callers pass literal filenames under pytest tmp_path
        json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2),
        encoding="utf-8",
    )


def _uv_lock(path, *, version="1.2.3", registry="https://pypi.org/simple"):
    path.write_text(  # skylos: ignore[SKY-D324] all callers pass literal filenames under pytest tmp_path
        'version = 1\nrevision = 3\nrequires-python = ">=3.10"\n'
        '[[package]]\nname = "local-app"\nversion = "0.1.0"\n'
        'source = { virtual = "." }\n'
        'dependencies = [{ name = "example" }]\n'
        '[[package]]\nname = "example"\n'
        f'version = "{version}"\nsource = {{ registry = "{registry}" }}\n',
        encoding="utf-8",
    )


@pytest.fixture
def osv(monkeypatch):
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
            self.fail = False
            self.vulnerable = True

        def post(self, url, *, json, **kwargs):
            assert url == sca.OSV_BATCH_URL
            assert kwargs["timeout"] == 30
            self.queries.extend(json["queries"])
            if self.fail:
                raise ConnectionError("test advisory service unavailable")
            # querybatch's minimal response contains advisory IDs.
            return Response(
                {
                    "results": [
                        {"vulns": [{"id": "GHSA-test-lockfile"}]}
                        if self.vulnerable
                        else {}
                        for _ in json["queries"]
                    ]
                }
            )

        def get(self, url, **kwargs):
            assert url == "https://api.osv.dev/v1/vulns/GHSA-test-lockfile"
            return Response(
                {
                    "id": "GHSA-test-lockfile",
                    "summary": "Advisory detail from the local test fixture",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {"package": {"name": name, "ecosystem": ecosystem}}
                        for name in ("example", "local-app")
                        for ecosystem in ("npm", "PyPI")
                    ],
                }
            )

    transport = LocalOSV()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


@pytest.mark.parametrize(
    "filename,writer,ecosystem",
    [
        ("package-lock.json", _npm_lock, "npm"),
        ("uv.lock", _uv_lock, "PyPI"),
    ],
)
@pytest.mark.parametrize("with_source", [False, True])
def test_lockfile_reaches_analyzer_json_sarif_and_gate(
    tmp_path, osv, filename, writer, ecosystem, with_source
):
    path = tmp_path / filename
    writer(path)
    if with_source:
        (tmp_path / "app.py").write_text(
            'print("local test fixture")\n', encoding="utf-8"
        )
    result = json.loads(analyze(str(tmp_path), enable_sca=True, grep_verify=False))
    coverage = result["analysis_summary"]["sca_coverage"]
    assert coverage["status"] == "complete"
    assert coverage["category_complete"] is False
    assert coverage["supported_lockfile_count"] == 1
    assert coverage["locked_dependency_count"] == 1
    assert coverage["local_lockfile_package_count"] == 1
    assert coverage["inventory_scope"] == "all_recorded_lockfile_environments"
    assert osv.queries == [
        {"package": {"name": "example", "ecosystem": ecosystem}, "version": "1.2.3"}
    ]
    finding = result["dependency_vulnerabilities"][0]
    assert finding["file"] == str(path)
    assert finding["line"] > 1
    assert finding["metadata"]["dependency_kind"] == "direct"
    assert finding["metadata"]["dependency_occurrences"][0]["file"] == str(path)
    sarif = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    assert sarif["properties"]["skylos_metadata"]["package_version"] == "1.2.3"
    assert (
        sarif["locations"][0]["physicalLocation"]["region"]["startLine"]
        == finding["line"]
    )
    passed, reasons = check_gate(
        result, {"gate": {"max_dependency_vulnerabilities": 0}}
    )
    assert passed is False
    assert any("dependency" in reason.lower() for reason in reasons)


def test_queries_deduplicate_but_locations_and_versions_survive(tmp_path, osv):
    _npm_lock(tmp_path / "package-lock.json", duplicate=True)
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"example": "1.2.3"}}', encoding="utf-8"
    )
    nested = tmp_path / "apps" / "nested"
    nested.mkdir(parents=True)
    _npm_lock(nested / "package-lock.json", version="2.0.0")
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["complete"] is True
    assert result.receipt["dependency_count"] == 2
    assert result.receipt["dependency_occurrence_count"] == 4
    assert [query["version"] for query in osv.queries] == ["1.2.3", "2.0.0"]
    first = result[0]
    assert first["file"].endswith("package-lock.json")
    occurrences = first["metadata"]["dependency_occurrences"]
    assert len(occurrences) == 3
    assert {entry.get("dependency_dev") for entry in occurrences} == {None, False, True}


@pytest.mark.parametrize(
    "filename,writer", [("package-lock.json", _npm_lock), ("uv.lock", _uv_lock)]
)
@pytest.mark.parametrize(
    "invalid", ["{invalid", "", "future_version", "invalid_utf8", "symlink"]
)
def test_unreadable_or_unsupported_lockfile_is_operational_failure(
    tmp_path, osv, filename, writer, invalid
):
    path = tmp_path / filename
    if invalid == "symlink":
        target = tmp_path / "data.txt"
        writer(target)
        path.symlink_to(target)
    elif invalid == "invalid_utf8":
        path.write_bytes(  # skylos: ignore[SKY-D215,SKY-D324] literal pytest parametrization under tmp_path
            b"\xff"
        )
    elif invalid == "future_version":
        path.write_text(  # skylos: ignore[SKY-D215,SKY-D324] literal pytest parametrization under tmp_path
            '{"lockfileVersion": 999, "packages": {}}'
            if filename.endswith("json")
            else "version = 999\npackage = []\n",
            encoding="utf-8",
        )
    else:
        path.write_text(  # skylos: ignore[SKY-D215,SKY-D324] literal pytest parametrization under tmp_path
            invalid, encoding="utf-8"
        )
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["parse_error_count"] == 1
    assert result.receipt["queried_dependency_count"] == 0
    assert osv.queries == []


@pytest.mark.parametrize(
    "filename,writer", [("package-lock.json", _npm_lock), ("uv.lock", _uv_lock)]
)
def test_lockfile_failure_cannot_be_a_clean_gate(tmp_path, osv, filename, writer):
    writer(tmp_path / filename)
    osv.fail = True
    result = json.loads(analyze(str(tmp_path), enable_sca=True, grep_verify=False))
    coverage = result["analysis_summary"]["sca_coverage"]
    assert coverage["complete"] is False
    assert coverage["query"]["failed_batches"] == 1
    assert result["dependency_vulnerabilities"] == []
    passed, reasons = check_gate(result, {})
    assert passed is False
    assert any("incomplete" in reason.lower() for reason in reasons)


@pytest.mark.parametrize("ecosystem", ["npm", "PyPI"])
def test_private_lock_source_prevents_manifest_public_registry_guess(
    tmp_path, osv, ecosystem
):
    if ecosystem == "npm":
        _npm_lock(
            tmp_path / "package-lock.json",
            resolved="https://private.invalid/example.tgz",
        )
        (tmp_path / "package.json").write_text(
            '{"dependencies": {"example": "1.2.3"}}', encoding="utf-8"
        )
    else:
        _uv_lock(tmp_path / "uv.lock", registry="https://private.invalid/simple")
        (tmp_path / "requirements.txt").write_text("example==1.2.3\n", encoding="utf-8")
    result = sca.scan_dependencies(tmp_path)
    assert osv.queries == []
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["manifest_source_conflict_count"] == 1
    assert result.receipt["unresolved_lockfile_dependency_count"] == 1
    assert "private.invalid" not in json.dumps(result.receipt)


def test_lockfile_does_not_hide_a_stale_manifest_pin(tmp_path, osv):
    _npm_lock(tmp_path / "package-lock.json", version="2.0.0")
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"example": "1.2.3"}}', encoding="utf-8"
    )
    result = sca.scan_dependencies(tmp_path)
    assert {query["version"] for query in osv.queries} == {"1.2.3", "2.0.0"}
    assert "lockfile_freshness_not_verified" in result.receipt["limitations"]


def test_pypi_normalization_merges_manifest_and_lock_occurrences(tmp_path, osv):
    _uv_lock(tmp_path / "uv.lock")
    (tmp_path / "requirements.txt").write_text("Example==1.2.3\n", encoding="utf-8")
    result = sca.scan_dependencies(tmp_path)
    assert len(osv.queries) == 1
    assert len(result) == 1
    assert result[0]["file"].endswith("uv.lock")
    assert len(result[0]["metadata"]["dependency_occurrences"]) == 2


@pytest.mark.parametrize("ecosystem", ["npm", "PyPI"])
def test_local_identity_guard_is_scoped_to_recorded_project_directories(
    tmp_path, osv, ecosystem
):
    if ecosystem == "npm":
        _npm_lock(tmp_path / "package-lock.json")
        filename = "package.json"
        manifest = '{"dependencies": {"local-app": "0.1.0"}}'
    else:
        _uv_lock(tmp_path / "uv.lock")
        filename = "requirements.txt"
        manifest = "local-app==0.1.0\n"
    (tmp_path / filename).write_text(manifest, encoding="utf-8")
    independent = tmp_path / "unrelated-project"
    independent.mkdir()
    (independent / filename).write_text(manifest, encoding="utf-8")
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["manifest_source_conflict_count"] == 1
    assert result.receipt["complete"] is True
    local_name_finding = next(
        f for f in result if f["metadata"]["package_name"] == "local-app"
    )
    assert local_name_finding["file"] == str(independent / filename)


@pytest.mark.parametrize(
    "filename,writer", [("package-lock.json", _npm_lock), ("uv.lock", _uv_lock)]
)
def test_lockfile_inventory_bound_prevents_network_queries(
    tmp_path, osv, monkeypatch, filename, writer
):
    writer(tmp_path / filename)
    monkeypatch.setattr(sca, "MAX_UNIQUE_DEPENDENCIES", 1)
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["status"] == "incomplete"
    assert result.receipt["limit_reasons"] == ["dependency_limit_exceeded"]
    assert osv.queries == []


def test_supported_lockfiles_no_longer_count_as_unsupported(tmp_path, osv):
    _npm_lock(tmp_path / "package-lock.json")
    _uv_lock(tmp_path / "uv.lock")
    (tmp_path / "yarn.lock").write_text(
        "# unsupported Yarn lockfile\n", encoding="utf-8"
    )
    result = sca.scan_dependencies(tmp_path)
    assert result.receipt["supported_lockfile_count"] == 2
    assert result.receipt["unsupported_lockfile_count"] == 1
    assert result.receipt["scope"] == sca.SCA_LOCKFILE_COVERAGE_SCOPE
    assert {query["package"]["ecosystem"] for query in osv.queries} == {"PyPI", "npm"}
