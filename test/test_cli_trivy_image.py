"""Offline container-report imports through the real CLI dispatch path."""

import json
import os
import socket
import subprocess

import pytest
import requests

import skylos.cli as cli


DIGEST = "sha256:" + "a" * 64
IMAGE = "registry.example.com/team/app@" + DIGEST
ADVISORY = "CVE-2024-0001"


@pytest.fixture(autouse=True)
def offline_import(tmp_path, monkeypatch):
    """Importing a supplied report must not execute scanners or upload data."""
    monkeypatch.chdir(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Report import must remain offline and must not run programs")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(cli, "upload_report", forbidden)


@pytest.fixture
def report():
    return {
        "SchemaVersion": 2,
        "ArtifactName": "registry.example.com/team/app:release",
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageID": "sha256:" + "b" * 64,
            "RepoTags": ["registry.example.com/team/app:release"],
            "RepoDigests": [IMAGE],
            "OS": {"Family": "alpine", "Name": "3.20.0"},
            "ImageConfig": {"architecture": "amd64", "os": "linux"},
        },
        "Results": [
            {
                "Target": "registry.example.com/team/app:release (alpine 3.20.0)",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": ADVISORY,
                        "PkgID": "example-lib@1.0.0-r0",
                        "PkgName": "example-lib",
                        "InstalledVersion": "1.0.0-r0",
                        "FixedVersion": "1.0.1-r0",
                        "Severity": "HIGH",
                        "Title": "Example advisory for report-import tests",
                        "PrimaryURL": "https://example.com/advisory",
                        "Layer": {"Digest": "sha256:" + "c" * 64},
                    }
                ],
            }
        ],
    }


def _invoke(monkeypatch, *arguments):
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "ingest", "trivy", *arguments])
    with pytest.raises(SystemExit) as error:
        cli.main()
    return error.value.code


def _assert_finding(document):
    assert len(document["container_vulnerabilities"]) == 1
    finding = document["container_vulnerabilities"][0]
    assert finding["rule_id"] == "TRIVY:" + ADVISORY
    assert finding["vulnerability_id"] == ADVISORY
    assert finding["package"] == "example-lib"
    assert finding["version"] == "1.0.0-r0"
    assert finding["fixed_version"] == "1.0.1-r0"
    assert "file" not in finding
    assert "line" not in finding
    return finding


def test_cli_defaults_to_offline_json_stdout(tmp_path, report, monkeypatch, capsys):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    _assert_finding(document)
    assert document["receipt"]["import_complete"] is True
    assert document["receipt"]["scan_complete"] is None
    assert document["receipt"]["identity_verified"] is False
    assert document["receipt"]["supported_result_count"] == 1
    assert document["receipt"]["errors"] == []
    assert document["gate"] == {
        "threshold": None,
        "status": "not_requested",
        "blocking_count": 0,
        "scope": "supplied_report",
    }
    assert captured.err == ""


def test_cli_help_exposes_report_import_and_identity_options(monkeypatch, capsys):
    assert _invoke(monkeypatch, "--help") == 0
    help_text = capsys.readouterr().out
    for option in ("--input", "--output", "--sarif", "--fail-on", "--expect-image"):
        assert option in help_text


def test_cli_writes_json_file_without_polluting_stdout(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "normalized.json"),
        )
        == 0
    )
    _assert_finding(json.loads((tmp_path / "normalized.json").read_text()))
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("severity", "threshold", "exit_code", "status"),
    [
        ("CRITICAL", "critical", 1, "failed"),
        ("HIGH", "critical", 0, "passed"),
        ("HIGH", "high", 1, "failed"),
        ("MEDIUM", "high", 0, "passed"),
        ("MEDIUM", "medium", 1, "failed"),
        ("LOW", "medium", 0, "passed"),
        ("LOW", "low", 1, "failed"),
    ],
)
def test_bound_report_gate_severity_thresholds(
    tmp_path, report, monkeypatch, capsys, severity, threshold, exit_code, status
):
    report["Results"][0]["Vulnerabilities"][0]["Severity"] = severity
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "--input",
            str(tmp_path / "trivy.json"),
            "--fail-on",
            threshold,
            "--expect-image",
            IMAGE,
            "--expect-platform",
            "linux/amd64",
        )
        == exit_code
    )
    document = json.loads(capsys.readouterr().out)
    assert _assert_finding(document)["severity"] == severity
    assert document["receipt"]["identity_verified"] is True
    assert document["receipt"]["scan_complete"] is None
    assert document["gate"]["status"] == status
    assert document["gate"]["threshold"] == threshold.upper()
    assert document["gate"]["blocking_count"] == (1 if status == "failed" else 0)


def test_gate_without_expected_digest_is_incomplete(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json"), "--fail-on", "high")
        == 2
    )
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    _assert_finding(document)
    assert document["gate"]["status"] == "incomplete"
    assert document["receipt"]["identity_verified"] is False
    assert document["receipt"]["errors"]
    assert captured.err


@pytest.mark.parametrize(
    "expected_image",
    [
        "registry.example.com/team/app:release",
        "registry.example.com/team/app@sha256:short",
        "registry.example.com/team/app@sha256:" + "d" * 64,
        "registry.example.com/another/app@" + DIGEST,
    ],
)
def test_invalid_or_mismatched_expected_image_retains_findings(
    tmp_path, report, monkeypatch, capsys, expected_image
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--fail-on",
            "high",
            "--expect-image",
            expected_image,
        )
        == 2
    )
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    _assert_finding(document)
    assert document["receipt"]["identity_verified"] is False
    assert document["receipt"]["errors"]
    assert document["gate"]["status"] == "incomplete"
    assert captured.err


def test_image_config_id_is_not_a_repository_manifest_digest(
    tmp_path, report, monkeypatch, capsys
):
    report["Metadata"]["ImageID"] = DIGEST
    report["Metadata"]["RepoDigests"] = []
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--fail-on",
            "high",
            "--expect-image",
            IMAGE,
        )
        == 2
    )
    document = json.loads(capsys.readouterr().out)
    _assert_finding(document)
    assert document["receipt"]["identity_verified"] is False
    assert document["gate"]["status"] == "incomplete"


def test_platform_mismatch_is_incomplete(tmp_path, report, monkeypatch, capsys):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--fail-on",
            "high",
            "--expect-image",
            IMAGE,
            "--expect-platform",
            "linux/arm64",
        )
        == 2
    )
    document = json.loads(capsys.readouterr().out)
    _assert_finding(document)
    assert document["receipt"]["errors"]
    assert document["gate"]["status"] == "incomplete"


def test_empty_vulnerability_result_can_pass_bound_report_gate(
    tmp_path, report, monkeypatch, capsys
):
    report["Results"][0]["Vulnerabilities"] = []
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--fail-on",
            "high",
            "--expect-image",
            IMAGE,
        )
        == 0
    )
    document = json.loads(capsys.readouterr().out)
    assert document["container_vulnerabilities"] == []
    assert document["receipt"]["supported_result_count"] == 1
    assert document["receipt"]["scan_complete"] is None
    assert document["gate"]["status"] == "passed"


def test_empty_results_can_import_but_cannot_pass_a_gate(
    tmp_path, report, monkeypatch, capsys
):
    report["Results"] = []
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["receipt"]["import_complete"] is True
    assert document["receipt"]["supported_result_count"] == 0
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--fail-on",
            "high",
            "--expect-image",
            IMAGE,
        )
        == 2
    )
    document = json.loads(capsys.readouterr().out)
    assert document["gate"]["status"] == "incomplete"


def test_language_package_result_is_supported(tmp_path, report, monkeypatch, capsys):
    report["Results"][0].update(
        {"Class": "lang-pkgs", "Type": "npm", "Target": "app/package-lock.json"}
    )
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 0
    document = json.loads(capsys.readouterr().out)
    finding = _assert_finding(document)
    assert finding["class"] == "lang-pkgs"
    assert finding["type"] == "npm"
    assert finding["target"] == "app/package-lock.json"


@pytest.mark.parametrize("mutation", ["schema", "artifact", "results", "top_level"])
def test_non_container_or_invalid_report_schema_is_rejected(
    tmp_path, report, monkeypatch, capsys, mutation
):
    if mutation == "schema":
        report["SchemaVersion"] = 999
    elif mutation == "artifact":
        report["ArtifactType"] = "filesystem"
    elif mutation == "results":
        report["Results"] = "not an array"
    else:
        report = []
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["errors"]
    assert captured.err


@pytest.mark.parametrize(
    "malformed", ["result", "vulnerability", "severity", "unknown_severity"]
)
def test_malformed_mixed_report_preserves_supported_finding(
    tmp_path, report, monkeypatch, capsys, malformed
):
    if malformed == "result":
        report["Results"].append("invalid result")
    elif malformed == "vulnerability":
        report["Results"][0]["Vulnerabilities"].append({"Severity": "HIGH"})
    else:
        invalid = dict(report["Results"][0]["Vulnerabilities"][0])
        invalid.update(
            {
                "VulnerabilityID": "CVE-2024-0002",
                "Severity": "UNKNOWN" if malformed == "unknown_severity" else "EXTREME",
            }
        )
        report["Results"][0]["Vulnerabilities"].append(invalid)
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--fail-on",
            "high",
            "--expect-image",
            IMAGE,
        )
        == 2
    )
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert any(
        item["vulnerability_id"] == ADVISORY
        for item in document["container_vulnerabilities"]
    )
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["errors"]
    assert document["gate"]["status"] == "incomplete"
    assert captured.err


def test_unknown_result_class_is_not_silently_dropped(
    tmp_path, report, monkeypatch, capsys
):
    report["Results"].append({"Class": "future-class", "Type": "future", "Target": "x"})
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 2
    document = json.loads(capsys.readouterr().out)
    _assert_finding(document)
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["errors"]


def test_invalid_json_returns_machine_readable_incomplete_receipt(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text('{"Results":', encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["container_vulnerabilities"] == []
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["errors"]
    assert captured.err


def test_missing_input_returns_incomplete_receipt(tmp_path, monkeypatch, capsys):
    assert _invoke(monkeypatch, "-i", str(tmp_path / "missing.json")) == 2
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["errors"]
    assert captured.err


def test_sarif_is_attributed_to_trivy_without_fake_source_locations(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--sarif",
            str(tmp_path / "container.sarif"),
        )
        == 0
    )
    document = json.loads(capsys.readouterr().out)
    sarif = json.loads((tmp_path / "container.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert "trivy" in run["tool"]["driver"]["name"].lower()
    assert run["invocations"][0]["executionSuccessful"] is True
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == document["container_vulnerabilities"][0]["rule_id"]
    assert result["level"] == "error"
    assert result["locations"]
    assert all("physicalLocation" not in item for item in result["locations"])
    assert any(item.get("logicalLocations") for item in result["locations"])
    assert "scan_complete" in json.dumps(run)


def test_partial_import_sarif_retains_finding_and_failed_invocation(
    tmp_path, report, monkeypatch, capsys
):
    report["Results"].append(None)
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--sarif",
            str(tmp_path / "container.sarif"),
        )
        == 2
    )
    _assert_finding(json.loads(capsys.readouterr().out))
    run = json.loads((tmp_path / "container.sarif").read_text())["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False
    assert [finding["ruleId"] for finding in run["results"]] == ["TRIVY:" + ADVISORY]


def test_output_cannot_overwrite_input(tmp_path, report, monkeypatch, capsys):
    original = json.dumps(report)
    (tmp_path / "trivy.json").write_text(original, encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "trivy.json"),
        )
        == 2
    )
    assert (tmp_path / "trivy.json").read_text() == original
    captured = capsys.readouterr()
    _assert_finding(json.loads(captured.out))
    assert captured.err


def test_sarif_cannot_overwrite_input(tmp_path, report, monkeypatch, capsys):
    original = json.dumps(report)
    (tmp_path / "trivy.json").write_text(original, encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--sarif",
            str(tmp_path / "trivy.json"),
        )
        == 2
    )
    assert (tmp_path / "trivy.json").read_text() == original
    _assert_finding(json.loads(capsys.readouterr().out))


def test_json_and_sarif_collision_is_rejected_before_either_write(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "output.json").write_text("preserve output", encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "output.json"),
            "--sarif",
            str(tmp_path / "output.json"),
        )
        == 2
    )
    assert (tmp_path / "output.json").read_text() == "preserve output"
    _assert_finding(json.loads(capsys.readouterr().out))


def test_symlink_output_is_rejected_without_modifying_target(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "preserve.txt").write_text("preserve target", encoding="utf-8")
    (tmp_path / "output.json").symlink_to(tmp_path / "preserve.txt")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "output.json"),
        )
        == 2
    )
    assert (tmp_path / "output.json").is_symlink()
    assert (tmp_path / "preserve.txt").read_text() == "preserve target"
    _assert_finding(json.loads(capsys.readouterr().out))


def test_hardlinked_output_is_rejected_without_modifying_target(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "preserve.txt").write_text("preserve target", encoding="utf-8")
    os.link(tmp_path / "preserve.txt", tmp_path / "output.json")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "output.json"),
        )
        == 2
    )
    assert (tmp_path / "preserve.txt").read_text() == "preserve target"
    assert (tmp_path / "output.json").read_text() == "preserve target"
    _assert_finding(json.loads(capsys.readouterr().out))


def test_symlink_parent_output_is_rejected(tmp_path, report, monkeypatch, capsys):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "real").mkdir()
    (tmp_path / "linked").symlink_to(tmp_path / "real", target_is_directory=True)
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "linked" / "output.json"),
        )
        == 2
    )
    assert not (tmp_path / "real" / "output.json").exists()
    _assert_finding(json.loads(capsys.readouterr().out))


def test_output_cannot_overwrite_project_manifest(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("preserve manifest", encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "pyproject.toml"),
        )
        == 2
    )
    assert (tmp_path / "pyproject.toml").read_text() == "preserve manifest"
    _assert_finding(json.loads(capsys.readouterr().out))


def test_output_cannot_overwrite_git_metadata(tmp_path, report, monkeypatch, capsys):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("preserve config", encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / ".git" / "config"),
        )
        == 2
    )
    assert (tmp_path / ".git" / "config").read_text() == "preserve config"
    _assert_finding(json.loads(capsys.readouterr().out))


def test_missing_output_parent_retains_findings_and_reports_write_failure(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "absent" / "output.json"),
        )
        == 2
    )
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    _assert_finding(document)
    assert document["receipt"]["errors"]
    assert captured.err


@pytest.mark.parametrize("flag", ["--force", "--strict", "--no-upload"])
def test_report_import_does_not_accept_unrelated_gate_or_upload_flags(
    tmp_path, report, monkeypatch, capsys, flag
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json"), flag) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unrecognized arguments" in captured.err


def test_unknown_gate_threshold_is_not_accepted(tmp_path, report, monkeypatch, capsys):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json"), "--fail-on", "unknown")
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "invalid choice" in captured.err


def test_unknown_severity_is_retained_but_import_remains_incomplete(
    tmp_path, report, monkeypatch, capsys
):
    report["Results"][0]["Vulnerabilities"][0]["Severity"] = "UNKNOWN"
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 2
    document = json.loads(capsys.readouterr().out)
    assert _assert_finding(document)["severity"] == "UNKNOWN"
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["errors"]


def test_failing_threshold_does_not_mean_sarif_import_failed(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "--sarif",
            str(tmp_path / "container.sarif"),
            "--fail-on",
            "high",
            "--expect-image",
            IMAGE,
        )
        == 1
    )
    document = json.loads(capsys.readouterr().out)
    assert document["gate"]["status"] == "failed"
    run = json.loads((tmp_path / "container.sarif").read_text())["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["properties"]["gate"]["status"] == "failed"


def test_sarif_write_failure_retains_findings_in_json_output(
    tmp_path, report, monkeypatch, capsys
):
    from skylos.commands import trivy_image_cmd

    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    real_writer = trivy_image_cmd.write_text_no_symlink

    def fail_sarif(path, text):
        if str(path) == str(tmp_path / "container.sarif"):
            return False
        return real_writer(path, text)

    monkeypatch.setattr(trivy_image_cmd, "write_text_no_symlink", fail_sarif)
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "normalized.json"),
            "--sarif",
            str(tmp_path / "container.sarif"),
        )
        == 2
    )
    document = json.loads((tmp_path / "normalized.json").read_text())
    _assert_finding(document)
    assert document["receipt"]["import_complete"] is False
    assert any(
        error["code"] == "sarif_write_failed" for error in document["receipt"]["errors"]
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err


def test_json_write_failure_updates_previously_written_sarif_receipt(
    tmp_path, report, monkeypatch, capsys
):
    from skylos.commands import trivy_image_cmd

    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    real_writer = trivy_image_cmd.write_text_no_symlink

    def fail_json(path, text):
        if str(path) == str(tmp_path / "normalized.json"):
            return False
        return real_writer(path, text)

    monkeypatch.setattr(trivy_image_cmd, "write_text_no_symlink", fail_json)
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "normalized.json"),
            "--sarif",
            str(tmp_path / "container.sarif"),
        )
        == 2
    )
    document = json.loads(capsys.readouterr().out)
    _assert_finding(document)
    assert document["receipt"]["import_complete"] is False
    run = json.loads((tmp_path / "container.sarif").read_text())["runs"][0]
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["properties"]["gate"]["status"] == "incomplete"
    assert run["properties"]["receipt"]["errors"] == document["receipt"]["errors"]


def test_linked_json_output_prevents_sibling_sarif_write(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "preserve.json").write_text("preserve target", encoding="utf-8")
    (tmp_path / "normalized.json").symlink_to(tmp_path / "preserve.json")
    (tmp_path / "container.sarif").write_text("preserve sarif", encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "normalized.json"),
            "--sarif",
            str(tmp_path / "container.sarif"),
        )
        == 2
    )
    assert (tmp_path / "preserve.json").read_text() == "preserve target"
    assert (tmp_path / "container.sarif").read_text() == "preserve sarif"
    _assert_finding(json.loads(capsys.readouterr().out))


def test_sarif_and_json_hardlink_collision_preserves_both_outputs(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "normalized.json").write_text("preserve outputs", encoding="utf-8")
    os.link(tmp_path / "normalized.json", tmp_path / "container.sarif")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "normalized.json"),
            "--sarif",
            str(tmp_path / "container.sarif"),
        )
        == 2
    )
    assert (tmp_path / "normalized.json").read_text() == "preserve outputs"
    assert (tmp_path / "container.sarif").read_text() == "preserve outputs"
    _assert_finding(json.loads(capsys.readouterr().out))


def test_input_output_hardlink_collision_preserves_report(
    tmp_path, report, monkeypatch, capsys
):
    original = json.dumps(report)
    (tmp_path / "trivy.json").write_text(original, encoding="utf-8")
    os.link(tmp_path / "trivy.json", tmp_path / "normalized.json")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "normalized.json"),
        )
        == 2
    )
    assert (tmp_path / "trivy.json").read_text() == original
    assert (tmp_path / "normalized.json").read_text() == original
    _assert_finding(json.loads(capsys.readouterr().out))


def test_symlink_input_is_not_followed(tmp_path, report, monkeypatch, capsys):
    (tmp_path / "original.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "trivy.json").symlink_to(tmp_path / "original.json")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json")) == 2
    document = json.loads(capsys.readouterr().out)
    assert document["container_vulnerabilities"] == []
    assert document["receipt"]["import_complete"] is False
    assert document["receipt"]["errors"]


def test_sarif_cannot_share_json_stdout(tmp_path, report, monkeypatch, capsys):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    assert _invoke(monkeypatch, "-i", str(tmp_path / "trivy.json"), "--sarif", "-") == 2
    _assert_finding(json.loads(capsys.readouterr().out))
    assert not (tmp_path / "-").exists()


def test_json_suffix_does_not_allow_overwriting_package_input(
    tmp_path, report, monkeypatch, capsys
):
    (tmp_path / "trivy.json").write_text(json.dumps(report), encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name":"preserve"}', encoding="utf-8")
    assert (
        _invoke(
            monkeypatch,
            "-i",
            str(tmp_path / "trivy.json"),
            "-o",
            str(tmp_path / "package.json"),
        )
        == 2
    )
    assert (tmp_path / "package.json").read_text() == '{"name":"preserve"}'
    _assert_finding(json.loads(capsys.readouterr().out))
