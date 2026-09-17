"""Image finding identities are machine data, not source-code locations."""

from copy import deepcopy

from skylos.integrations.trivy_image import normalize_trivy_image_report
from skylos.reporting.container_sarif import container_sarif


def _report():
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "ArtifactName": "example-image",
        "Metadata": {
            "RepoDigests": [
                "example.com/a@sha256:" + "a" * 64,
                "example.com/b@sha256:" + "a" * 64,
            ],
            "ImageConfig": {"os": "linux", "architecture": "amd64"},
        },
        "Results": [
            {
                "Class": "lang-pkgs",
                "Type": "npm",
                "Target": "opt/app/package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "EXAMPLE-1",
                        "PkgName": "example-lib",
                        "InstalledVersion": "1.0",
                        "Severity": "HIGH",
                        "PkgIdentifier": {"PURL": "pkg:npm/example-lib@1.0"},
                    }
                ],
            }
        ],
    }


def test_exact_checked_digest_and_purl_survive_sarif():
    raw = _report()
    checked = raw["Metadata"]["RepoDigests"][1]
    document = normalize_trivy_image_report(raw, expected_image=checked)
    run = container_sarif(document)["runs"][0]
    assert run["properties"]["image"]["repo_digests"] == raw["Metadata"]["RepoDigests"]
    assert run["properties"]["receipt"]["verified_image"] == checked
    assert run["results"][0]["properties"]["purl"] == "pkg:npm/example-lib@1.0"


def test_long_distinct_advisory_ids_do_not_collapse_into_one_sarif_rule():
    raw = _report()
    first = raw["Results"][0]["Vulnerabilities"][0]
    first["VulnerabilityID"] = "EXAMPLE-" + "a" * 300
    second = deepcopy(first)
    second["VulnerabilityID"] += "b"
    raw["Results"][0]["Vulnerabilities"].append(second)
    run = container_sarif(normalize_trivy_image_report(raw))["runs"][0]
    ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert ids == {
        "TRIVY:" + first["VulnerabilityID"],
        "TRIVY:" + second["VulnerabilityID"],
    }
    assert {result["ruleId"] for result in run["results"]} == ids


def test_logical_location_selects_checked_alias_not_joined_aliases():
    raw = _report()
    checked = raw["Metadata"]["RepoDigests"][1]
    run = container_sarif(normalize_trivy_image_report(raw, expected_image=checked))[
        "runs"
    ][0]
    location = run["results"][0]["locations"][0]
    assert "physicalLocation" not in location
    name = location["logicalLocations"][0]["fullyQualifiedName"]
    assert "example.com/b" in name
    assert "example.com/a" not in name


def test_partial_import_has_failed_invocation_and_retains_result():
    raw = _report()
    raw["Results"].append({"Class": "unsupported"})
    run = container_sarif(normalize_trivy_image_report(raw))["runs"][0]
    assert len(run["results"]) == 1
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["toolExecutionNotifications"][0]["level"] == "error"
    assert run["properties"]["receipt"]["scan_complete"] is None


def test_imported_target_stays_logical_and_does_not_become_a_uri():
    raw = _report()
    raw["Results"][0]["Target"] = "https://example.com/report-only"
    run = container_sarif(normalize_trivy_image_report(raw))["runs"][0]
    assert "artifacts" not in run
    assert set(run["results"][0]["locations"][0]) == {"logicalLocations"}


def test_unknown_engine_version_is_not_fabricated():
    run = container_sarif(normalize_trivy_image_report(_report()))["runs"][0]
    assert "version" not in run["tool"]["driver"]
    assert run["properties"]["receipt"]["database_freshness"] == "unknown"
