"""Pipfile.lock SCA and offline SBOM integration using only local fixtures."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.commands.sbom_cmd import run_sbom_command
from skylos.core.gatekeeper import check_gate
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.sarif import SarifExporter
from skylos.reporting.sbom import cyclonedx_bom
from skylos.rules.sca import vulnerability_scanner as sca


def _lock(root, *, private=False):
    sources = [{"name": "pypi", "url": "https://pypi.org/simple"}]
    if private:
        sources.append(
            {
                "name": "private",
                "url": "https://user:secret@private.example/simple",
            }
        )
    data = {
        "_meta": {"pipfile-spec": 6, "sources": sources},
        "default": {
            "example": {"version": "==1.2.3"},
            "private-pkg": {"version": "==4.0.0", "index": "private"}
            if private
            else {"version": "==4.0.0"},
        },
        "develop": {"example": {"version": "==1.2.3"}},
        "docs": {"other": {"version": "==2.0.0"}},
    }
    assert write_text_no_symlink(root / "Pipfile.lock", json.dumps(data, indent=2))


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

        def post(self, url, *, json, **kwargs):
            assert url == sca.OSV_BATCH_URL
            self.queries.extend(json["queries"])
            return Response(
                {
                    "results": [
                        {"vulns": [{"id": "GHSA-test-pipfile"}]}
                        if query["package"]["name"] == "example"
                        else {}
                        for query in json["queries"]
                    ]
                }
            )

        def get(self, url, **kwargs):
            assert url == "https://api.osv.dev/v1/vulns/GHSA-test-pipfile"
            return Response(
                {
                    "id": "GHSA-test-pipfile",
                    "summary": "Test advisory",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [{"package": {"name": "example", "ecosystem": "PyPI"}}],
                }
            )

    transport = LocalOSV()
    monkeypatch.setattr(sca, "_requests", transport)
    return transport


def _occurrences(component):
    return [
        json.loads(item["value"])
        for item in component["properties"]
        if item["name"] == "skylos:dependency:occurrence"
    ]


def test_pipfile_reaches_analyzer_json_sarif_and_gate(tmp_path, osv):
    _lock(tmp_path)
    result = json.loads(analyze(str(tmp_path), enable_sca=True, grep_verify=False))
    coverage = result["analysis_summary"]["sca_coverage"]
    assert coverage["status"] == "complete"
    assert coverage["supported_lockfile_count"] == 1
    assert coverage["locked_package_count"] == 4
    assert coverage["locked_dependency_count"] == 3
    assert osv.queries == [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in (
            ("example", "1.2.3"),
            ("private-pkg", "4.0.0"),
            ("other", "2.0.0"),
        )
    ]
    finding = result["dependency_vulnerabilities"][0]
    assert finding["file"] == str(tmp_path / "Pipfile.lock")
    assert finding["line"] > 1
    assert finding["metadata"]["dependency_kind"] == "unknown"
    assert {
        tuple(o["dependency_groups"])
        for o in finding["metadata"]["dependency_occurrences"]
    } == {
        ("default",),
        ("develop",),
    }
    sarif = SarifExporter([finding]).generate()["runs"][0]["results"][0]
    assert sarif["properties"]["skylos_metadata"]["package_version"] == "1.2.3"
    passed, reasons = check_gate(
        result, {"gate": {"max_dependency_vulnerabilities": 0}}
    )
    assert passed is False
    assert any("dependency" in reason.lower() for reason in reasons)


def test_private_source_blocks_manifest_guess_but_keeps_public_findings(tmp_path, osv):
    _lock(tmp_path, private=True)
    assert write_text_no_symlink(tmp_path / "requirements.txt", "private-pkg==4.0.0\n")
    result = sca.scan_dependencies(tmp_path)
    assert {query["package"]["name"] for query in osv.queries} == {
        "example",
        "other",
    }
    assert result.receipt["complete"] is False
    assert result.receipt["manifest_source_conflict_count"] == 1
    assert result.receipt["unresolved_lockfile_dependency_count"] == 1
    assert [finding["metadata"]["package_name"] for finding in result] == ["example"]
    assert "secret" not in json.dumps(result.receipt)


def test_offline_sbom_preserves_categories_and_does_not_invent_graph(
    tmp_path, monkeypatch, capsys
):
    _lock(tmp_path)

    def forbidden(*args, **kwargs):
        raise AssertionError("SBOM must not query OSV")

    monkeypatch.setattr(sca, "_query_osv_batch", forbidden)
    inventory = sca.collect_dependencies(tmp_path)
    document = cyclonedx_bom(inventory, tmp_path)
    assert document.receipt["complete"] is True
    assert document["dependencies"] == []
    components = {item["purl"]: item for item in document["components"]}
    assert set(components) == {
        "pkg:pypi/example@1.2.3",
        "pkg:pypi/private-pkg@4.0.0",
        "pkg:pypi/other@2.0.0",
    }
    occurrences = _occurrences(components["pkg:pypi/example@1.2.3"])
    assert {tuple(item["dependency_groups"]) for item in occurrences} == {
        ("default",),
        ("develop",),
    }
    assert all(item["file"] == "Pipfile.lock" for item in occurrences)
    assert str(tmp_path) not in json.dumps(document)
    assert run_sbom_command([str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["components"] == document["components"]


def test_offline_sbom_retains_public_components_when_private_gap_exists(
    tmp_path, capsys
):
    _lock(tmp_path, private=True)
    assert run_sbom_command([str(tmp_path), "--strict"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert {component["purl"] for component in output["components"]} == {
        "pkg:pypi/example@1.2.3",
        "pkg:pypi/other@2.0.0",
    }
    assert "private.example" not in json.dumps(output)
