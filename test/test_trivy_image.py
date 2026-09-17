"""Offline container-report import contracts, independent of installed Trivy."""

import copy
import hashlib
import json
import os
import socket
import subprocess

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.integrations import trivy_image as importer


IMAGE = "registry.example/app@sha256:" + "a" * 64
OTHER_IMAGE = "registry.example/app@sha256:" + "b" * 64


def _vulnerability(**changes):
    return {
        "VulnerabilityID": "CVE-2026-1234",
        "PkgName": "example",
        "InstalledVersion": "1.0.0",
        "FixedVersion": "1.0.1",
        "Severity": "HIGH",
        "PkgID": "example@1.0.0",
        "PkgPath": "usr/lib/example/METADATA",
        "PkgIdentifier": {"PURL": "pkg:pypi/example@1.0.0"},
        "Layer": {"Digest": "sha256:" + "c" * 64},
        "Title": "Example advisory",
        "Description": "Example description\nwith another line.",
        "PrimaryURL": "https://advisories.example/CVE-2026-1234",
        "Status": "fixed",
        **changes,
    }


def _report():
    return {
        "SchemaVersion": 2,
        "ArtifactName": "registry.example/app:latest",
        "ArtifactType": "container_image",
        "Trivy": {"Version": "0.69.0"},
        "CreatedAt": "2026-09-17T00:00:00Z",
        "Metadata": {
            "ImageID": "sha256:" + "d" * 64,
            "RepoDigests": [IMAGE],
            "ImageConfig": {"os": "linux", "architecture": "amd64"},
            "OS": {"Family": "alpine", "Name": "3.22"},
        },
        "Results": [
            {
                "Target": "registry.example/app:latest (alpine 3.22)",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Packages": [{"Name": "example", "Version": "1.0.0"}],
                "Vulnerabilities": [_vulnerability()],
            }
        ],
    }


def _codes(document, kind="errors"):
    return {entry["code"] for entry in document["receipt"][kind]}


def _write_report(tmp_path, data):
    path = tmp_path / "report.json"
    assert write_text_no_symlink(path, json.dumps(data))
    return path


@pytest.fixture(autouse=True)
def forbid_execution_and_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError(
            "Report imports must not execute programs or connect to the network"
        )

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


def test_import_preserves_vulnerability_and_image_evidence():
    document = importer.normalize_trivy_image_report(
        _report(), expected_image=IMAGE, expected_platform="linux/amd64"
    )
    finding = document["container_vulnerabilities"][0]
    assert finding["rule_id"] == "TRIVY:CVE-2026-1234"
    assert finding["package"] == "example"
    assert finding["version"] == "1.0.0"
    assert finding["fixed_version"] == "1.0.1"
    assert finding["severity"] == "HIGH"
    assert finding["package_path"] == "usr/lib/example/METADATA"
    assert finding["purl"] == "pkg:pypi/example@1.0.0"
    assert finding["layer"] == {"Digest": "sha256:" + "c" * 64}
    assert document["engine"] == {"name": "Trivy", "version": "0.69.0"}
    assert document["image"]["repo_digests"] == [IMAGE]
    receipt = document["receipt"]
    assert receipt["import_complete"] is True
    assert receipt["scan_complete"] is None
    assert receipt["identity_verified"] is True
    assert receipt["platform_verified"] is True
    assert receipt["supported_result_count"] == 1
    assert receipt["reported_package_count"] == 1
    assert receipt["database_freshness"] == "unknown"


def test_optional_inventory_and_metadata_do_not_create_false_totals():
    data = _report()
    del data["Trivy"]
    del data["CreatedAt"]
    del data["Metadata"]
    del data["Results"][0]["Packages"]
    document = importer.normalize_trivy_image_report(data)
    assert document["receipt"]["import_complete"] is True
    assert document["engine"]["version"] is None
    assert document["receipt"]["created_at"] is None
    assert document["receipt"]["reported_package_count"] == 0
    assert document["receipt"]["results_with_package_inventory"] == 0
    assert document["image"]["platform"] is None
    assert len(document["container_vulnerabilities"]) == 1


@pytest.mark.parametrize("results", ["missing", []])
def test_empty_results_are_an_empty_import_not_scan_coverage(results):
    data = _report()
    if results == "missing":
        del data["Results"]
    else:
        data["Results"] = results
    document = importer.normalize_trivy_image_report(data)
    assert document["receipt"]["import_complete"] is True
    assert document["receipt"]["supported_result_count"] == 0
    assert document["receipt"]["scan_complete"] is None
    assert "no_supported_results" in _codes(document, "warnings")


@pytest.mark.parametrize("value", [[], None, "json"])
def test_nonobject_report_is_incomplete(value):
    assert "invalid_report" in _codes(importer.normalize_trivy_image_report(value))


@pytest.mark.parametrize("value", [1, 3, True, 2.0, "2", None])
def test_only_exact_integer_schema_two_is_supported(value):
    data = _report()
    data["SchemaVersion"] = value
    document = importer.normalize_trivy_image_report(data)
    assert "unsupported_schema" in _codes(document)
    assert document["container_vulnerabilities"] == []


@pytest.mark.parametrize("value", ["filesystem", "repository", "cyclonedx", None])
def test_only_container_images_are_supported(value):
    data = _report()
    data["ArtifactType"] = value
    assert "unsupported_artifact" in _codes(importer.normalize_trivy_image_report(data))


@pytest.mark.parametrize("replacement", [None, {}, "invalid"])
def test_invalid_results_shape_is_incomplete(replacement):
    data = _report()
    data["Results"] = replacement
    assert "invalid_results" in _codes(importer.normalize_trivy_image_report(data))


def test_mixed_invalid_results_and_findings_retain_valid_evidence():
    data = _report()
    data["Results"].extend([None, {"Class": "config", "Target": "Dockerfile"}])
    data["Results"][0]["Vulnerabilities"].extend([None, {"PkgName": "missing"}])
    document = importer.normalize_trivy_image_report(data)
    assert len(document["container_vulnerabilities"]) == 1
    assert document["receipt"]["import_complete"] is False
    assert {
        "invalid_result",
        "unsupported_result_class",
        "invalid_vulnerability",
        "invalid_text_field",
    } <= _codes(document)


@pytest.mark.parametrize("severity", ["UNKNOWN", "invalid", None, [], ""])
def test_unknown_severity_is_retained_but_never_complete(severity):
    data = _report()
    data["Results"][0]["Vulnerabilities"][0]["Severity"] = severity
    document = importer.normalize_trivy_image_report(data)
    assert document["container_vulnerabilities"][0]["severity"] == "UNKNOWN"
    assert "unknown_severity" in _codes(document)
    assert document["receipt"]["import_complete"] is False


def test_exact_duplicates_only_are_collapsed_and_order_is_stable():
    data = _report()
    findings = data["Results"][0]["Vulnerabilities"]
    findings.extend(
        [
            copy.deepcopy(findings[0]),
            _vulnerability(Severity="CRITICAL"),
            _vulnerability(InstalledVersion="0.9"),
            _vulnerability(PkgPath="opt/example/METADATA"),
            _vulnerability(Layer={"Digest": "sha256:" + "e" * 64}),
        ]
    )
    first = importer.normalize_trivy_image_report(data)
    assert first == importer.normalize_trivy_image_report(copy.deepcopy(data))
    assert len(first["container_vulnerabilities"]) == 5
    assert first["receipt"]["duplicate_vulnerability_count"] == 1
    assert (
        len({finding["fingerprint"] for finding in first["container_vulnerabilities"]})
        == 4
    )


@pytest.mark.parametrize("expected", [OTHER_IMAGE, "app:latest", "sha256:" + "a" * 64])
def test_expected_image_requires_exact_pinned_repository_match(expected):
    document = importer.normalize_trivy_image_report(_report(), expected_image=expected)
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["identity_verified"] is False
    assert len(document["container_vulnerabilities"]) == 1


def test_tags_artifact_name_and_image_id_never_replace_repository_digest():
    data = _report()
    data["ArtifactName"] = IMAGE
    data["Metadata"]["ImageID"] = IMAGE.split("@", 1)[1]
    data["Metadata"]["RepoTags"] = [IMAGE]
    del data["Metadata"]["RepoDigests"]
    assert "image_identity_mismatch" in _codes(
        importer.normalize_trivy_image_report(data, expected_image=IMAGE)
    )


@pytest.mark.parametrize("platform", ["linux/arm64", "linux/amd64/v3", "invalid"])
def test_platform_mismatch_or_invalid_expectation_is_incomplete(platform):
    document = importer.normalize_trivy_image_report(
        _report(), expected_platform=platform
    )
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["platform_verified"] is False


def test_platform_variant_and_lowercase_oci_fields():
    data = _report()
    data["Metadata"]["ImageConfig"] = {
        "os": "linux",
        "architecture": "arm",
        "variant": "v7",
    }
    document = importer.normalize_trivy_image_report(
        data, expected_platform="linux/arm/v7"
    )
    assert document["image"]["platform"] == "linux/arm/v7"
    assert document["receipt"]["platform_verified"] is True


def test_metadata_is_allowlisted_and_eosl_is_explicit():
    data = _report()
    data["Metadata"]["OS"]["EOSL"] = True
    data["Metadata"]["ImageConfig"].update(
        {
            "config": {
                "Env": ["PASSWORD=private-value"],
                "Labels": {"private": "value"},
            },
            "history": [{"created_by": "private-build-command"}],
            "created": "2000-01-01T00:00:00Z",
        }
    )
    document = importer.normalize_trivy_image_report(data)
    serialized = json.dumps(document)
    assert "private-value" not in serialized
    assert "private-build-command" not in serialized
    assert "2000-01-01" not in serialized
    assert "os_end_of_support" in _codes(document, "warnings")
    assert document["receipt"]["import_complete"] is True


@pytest.mark.parametrize(
    "section",
    ["Secrets", "Misconfigurations", "ExperimentalModifiedFindings", "Licenses"],
)
def test_out_of_scope_findings_are_explicit(section):
    data = _report()
    data["Results"][0][section] = [{"secret": "not-exported"}]
    document = importer.normalize_trivy_image_report(data)
    assert "unsupported_findings" in _codes(document)
    assert "not-exported" not in json.dumps(document)
    assert len(document["container_vulnerabilities"]) == 1


@pytest.mark.parametrize("field", ["VulnerabilityID", "PkgName", "InstalledVersion"])
def test_missing_required_vulnerability_field_does_not_create_fake_finding(field):
    data = _report()
    del data["Results"][0]["Vulnerabilities"][0][field]
    document = importer.normalize_trivy_image_report(data)
    assert document["container_vulnerabilities"] == []
    assert document["receipt"]["import_complete"] is False


def test_result_and_finding_limits_preserve_bounded_prior_evidence(monkeypatch):
    monkeypatch.setattr(importer, "MAX_RESULTS", 1)
    monkeypatch.setattr(importer, "MAX_FINDINGS", 1)
    data = _report()
    data["Results"][0]["Vulnerabilities"].append(_vulnerability(PkgName="other"))
    data["Results"].append(copy.deepcopy(data["Results"][0]))
    document = importer.normalize_trivy_image_report(data)
    assert {"result_limit", "vulnerability_limit"} <= _codes(document)
    assert len(document["container_vulnerabilities"]) == 1


def test_package_inventory_limit_is_not_silent(monkeypatch):
    monkeypatch.setattr(importer, "MAX_PACKAGES", 1)
    data = _report()
    data["Results"][0]["Packages"].append({"Name": "other", "Version": "1"})
    document = importer.normalize_trivy_image_report(data)
    assert "package_limit" in _codes(document)
    assert document["receipt"]["reported_package_count"] == 1


def test_paths_and_urls_remain_data_not_io(tmp_path):
    data = _report()
    data["Results"][0]["Target"] = "../../nonexistent/package.json"
    data["Results"][0]["Vulnerabilities"][0]["PrimaryURL"] = "http://127.0.0.1/private"
    document = importer.load_trivy_image_report(_write_report(tmp_path, data))
    assert document["receipt"]["import_complete"] is True
    assert (
        document["container_vulnerabilities"][0]["target"]
        == "../../nonexistent/package.json"
    )


@pytest.mark.parametrize(
    "text",
    ["{", '{"SchemaVersion":2,"SchemaVersion":2}', '{"x":NaN}', '{"x":Infinity}'],
)
def test_invalid_json_has_fixed_error_and_input_digest(tmp_path, text):
    path = tmp_path / "report.json"
    assert write_text_no_symlink(path, text)
    document = importer.load_trivy_image_report(path)
    assert _codes(document) == {"invalid_json"}
    assert (
        document["receipt"]["report_sha256"]
        == hashlib.sha256(text.encode()).hexdigest()
    )


def test_crlf_utf8_input_hash_is_over_exact_file_bytes(tmp_path):
    path = tmp_path / "report.json"
    text = json.dumps(_report(), indent=2, ensure_ascii=False).replace("\n", "\r\n")
    assert write_text_no_symlink(path, text)
    document = importer.load_trivy_image_report(path)
    assert (
        document["receipt"]["report_sha256"]
        == hashlib.sha256(text.encode()).hexdigest()
    )
    assert document["receipt"]["import_complete"] is True


def test_missing_directory_symlink_and_linked_parent_are_rejected(tmp_path):
    report = _write_report(tmp_path, _report())
    linked_file = tmp_path / "linked.json"
    linked_file.symlink_to(report)
    parent = tmp_path / "linked-parent"
    parent.symlink_to(tmp_path, target_is_directory=True)
    for candidate in (
        tmp_path / "missing.json",
        tmp_path,
        linked_file,
        parent / "report.json",
    ):
        assert "unreadable_report" in _codes(
            importer.load_trivy_image_report(candidate)
        )


def test_oversized_input_is_rejected_before_parsing(tmp_path, monkeypatch):
    report = _write_report(tmp_path, _report())
    monkeypatch.setattr(importer, "MAX_REPORT_BYTES", 10)
    assert "unreadable_report" in _codes(importer.load_trivy_image_report(report))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO is unavailable")
def test_fifo_input_is_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "input.fifo"
    os.mkfifo(fifo)
    assert "unreadable_report" in _codes(importer.load_trivy_image_report(fifo))


@pytest.mark.parametrize("bad", ["\x00private", "\ud800", "x" * 4097])
def test_invalid_or_oversized_text_is_bounded_and_incomplete(bad):
    data = _report()
    data["Results"][0]["Vulnerabilities"][0]["PkgName"] = bad
    document = importer.normalize_trivy_image_report(data)
    assert document["receipt"]["import_complete"] is False
    assert document["container_vulnerabilities"] == []
    assert bad not in json.dumps(document)


def test_input_is_not_mutated():
    data = _report()
    original = copy.deepcopy(data)
    importer.normalize_trivy_image_report(data)
    assert data == original


def test_fingerprint_keeps_identity_stable_when_advisory_details_change():
    data = _report()
    first = importer.normalize_trivy_image_report(data)["container_vulnerabilities"][0]
    raw = data["Results"][0]["Vulnerabilities"][0]
    raw.update(
        Title="Updated title",
        Description="Updated details",
        FixedVersion="1.0.2",
        Severity="CRITICAL",
    )
    updated = importer.normalize_trivy_image_report(data)["container_vulnerabilities"][
        0
    ]
    assert first["fingerprint"] == updated["fingerprint"]


@pytest.mark.parametrize("changed", ["digest", "platform"])
def test_fingerprint_is_bound_to_image_identity_and_platform(changed):
    data = _report()
    first = importer.normalize_trivy_image_report(data)["container_vulnerabilities"][0]
    if changed == "digest":
        data["Metadata"]["RepoDigests"] = [OTHER_IMAGE]
    else:
        data["Metadata"]["ImageConfig"]["architecture"] = "arm64"
    updated = importer.normalize_trivy_image_report(data)["container_vulnerabilities"][
        0
    ]
    assert first["fingerprint"] != updated["fingerprint"]


def test_advisory_provenance_preserved_without_custom_metadata():
    data = _report()
    raw = data["Results"][0]["Vulnerabilities"][0]
    raw.update(
        SeveritySource="alpine",
        DataSource={
            "ID": "alpine",
            "Name": "Alpine Secdb",
            "URL": "https://secdb.alpinelinux.org/",
            "Custom": "private-data",
        },
    )
    document = importer.normalize_trivy_image_report(data)
    finding = document["container_vulnerabilities"][0]
    assert finding["severity_source"] == "alpine"
    assert finding["data_source"] == {
        "ID": "alpine",
        "Name": "Alpine Secdb",
        "URL": "https://secdb.alpinelinux.org/",
    }
    assert "private-data" not in json.dumps(document)


@pytest.mark.parametrize(
    "reference",
    [
        "registry.example:5000/group/image",
        "image",
        "group/my__image",
        "group/my--image",
    ],
)
def test_supported_repository_reference_forms(reference):
    data = _report()
    reference += "@sha256:" + "e" * 64
    data["Metadata"]["RepoDigests"] = [reference]
    document = importer.normalize_trivy_image_report(data, expected_image=reference)
    assert document["receipt"]["identity_verified"] is True


@pytest.mark.parametrize("reference", ["a//b", "a/../b", "a:/b", "a/", "a:tag"])
def test_malformed_repository_names_cannot_verify_identity(reference):
    data = _report()
    reference += "@sha256:" + "e" * 64
    data["Metadata"]["RepoDigests"] = [reference]
    document = importer.normalize_trivy_image_report(data, expected_image=reference)
    assert {"invalid_repo_digests", "invalid_expected_image"} <= _codes(document)


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("RepoDigests", "not-array", "invalid_repo_digests"),
        ("RepoDigests", [None], "invalid_repo_digests"),
        ("OS", None, "invalid_os_metadata"),
        ("OS", {"EOSL": "true"}, "invalid_os_metadata"),
        ("ImageConfig", [], "invalid_platform"),
        (
            "ImageConfig",
            {"os": "linux", "architecture": "bad/arch"},
            "invalid_platform",
        ),
    ],
)
def test_malformed_metadata_never_discards_valid_findings(field, value, code):
    data = _report()
    data["Metadata"][field] = value
    document = importer.normalize_trivy_image_report(data)
    assert code in _codes(document)
    assert len(document["container_vulnerabilities"]) == 1


def test_omitted_vulnerabilities_is_valid_clean_report_result():
    data = _report()
    del data["Results"][0]["Vulnerabilities"]
    document = importer.normalize_trivy_image_report(data)
    assert document["receipt"]["import_complete"] is True
    assert document["receipt"]["supported_result_count"] == 1
    assert document["container_vulnerabilities"] == []


def test_language_results_keep_their_distinct_target_and_type():
    data = _report()
    result = copy.deepcopy(data["Results"][0])
    result.update(
        Class="lang-pkgs", Target="usr/lib/python3.12/site-packages", Type="python-pkg"
    )
    data["Results"].append(result)
    document = importer.normalize_trivy_image_report(data)
    assert document["receipt"]["supported_result_count"] == 2
    assert len(document["container_vulnerabilities"]) == 2
    assert document["container_vulnerabilities"][1]["type"] == "python-pkg"


def test_sibling_report_path_is_normalized_without_following_links(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    reports = tmp_path / "reports"
    workspace.mkdir()
    reports.mkdir()
    _write_report(reports, _report())
    monkeypatch.chdir(workspace)
    document = importer.load_trivy_image_report("../reports/report.json")
    assert document["receipt"]["import_complete"] is True
    assert len(document["container_vulnerabilities"]) == 1


def test_quoted_home_report_path_is_expanded(tmp_path, monkeypatch):
    report_path = _write_report(tmp_path, _report())
    original_expanduser = os.path.expanduser

    def expand_test_home(path):
        if str(path) == "~":
            return str(tmp_path)
        if str(path) == "~/report.json":
            return str(report_path)
        return original_expanduser(path)

    monkeypatch.setattr(os.path, "expanduser", expand_test_home)
    document = importer.load_trivy_image_report("~/report.json")
    assert document["receipt"]["import_complete"] is True
    assert len(document["container_vulnerabilities"]) == 1


def test_verified_identity_records_exact_matched_repository_alias():
    data = _report()
    alias = "registry.example/second@sha256:" + "a" * 64
    data["Metadata"]["RepoDigests"].append(alias)
    document = importer.normalize_trivy_image_report(
        data, expected_image=alias, expected_platform="linux/amd64"
    )
    assert document["image"]["repo_digests"] == [IMAGE, alias]
    assert document["receipt"]["verified_image"] == alias
    assert document["receipt"]["verified_platform"] == "linux/amd64"


@pytest.mark.parametrize("expected", [None, OTHER_IMAGE])
def test_unverified_expectations_do_not_populate_verified_values(expected):
    document = importer.normalize_trivy_image_report(
        _report(), expected_image=expected, expected_platform="linux/arm64"
    )
    assert document["receipt"]["verified_image"] is None
    assert document["receipt"]["verified_platform"] is None


def test_fingerprints_are_stable_across_finding_and_digest_order():
    data = _report()
    data["Metadata"]["RepoDigests"].append(OTHER_IMAGE)
    data["Results"][0]["Vulnerabilities"].append(_vulnerability(PkgName="second"))
    first = importer.normalize_trivy_image_report(data)
    data["Metadata"]["RepoDigests"].reverse()
    data["Results"][0]["Vulnerabilities"].reverse()
    second = importer.normalize_trivy_image_report(data)
    assert {
        finding["package"]: finding["fingerprint"]
        for finding in first["container_vulnerabilities"]
    } == {
        finding["package"]: finding["fingerprint"]
        for finding in second["container_vulnerabilities"]
    }


def test_image_identity_hash_is_computed_once_per_report(monkeypatch):
    data = _report()
    data["Results"][0]["Vulnerabilities"].append(_vulnerability(PkgName="second"))
    calls = []
    original = importer._image_fingerprint

    def counted(image):
        calls.append(image)
        return original(image)

    monkeypatch.setattr(importer, "_image_fingerprint", counted)
    document = importer.normalize_trivy_image_report(data)
    assert len(document["container_vulnerabilities"]) == 2
    assert len(calls) == 1
