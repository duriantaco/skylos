"""One-command image scans through the CLI, with Trivy fully faked."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess

import pytest

import skylos.cli as cli
from skylos.core.safe_cache_io import write_text_no_symlink


IMAGE = "registry.example.com/team/app@sha256:" + "a" * 64
OTHER_IMAGE = "registry.example.com/team/app@sha256:" + "b" * 64


def _report(*, image=IMAGE, architecture="amd64", severity="HIGH"):
    return {
        "SchemaVersion": 2,
        "ArtifactName": "registry.example.com/team/app:release",
        "ArtifactType": "container_image",
        "Trivy": {"Version": "0.69.0"},
        "Metadata": {
            "ImageID": "sha256:" + "c" * 64,
            "RepoDigests": [image],
            "ImageConfig": {"os": "linux", "architecture": architecture},
        },
        "Results": [
            {
                "Target": "registry.example.com/team/app:release (alpine 3.20)",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-1234",
                        "PkgName": "example-lib",
                        "InstalledVersion": "1.0.0-r0",
                        "FixedVersion": "1.0.1-r0",
                        "Severity": severity,
                    }
                ],
            }
        ],
    }


def _invoke(monkeypatch, *arguments):
    if "--platform" not in arguments and "--help" not in arguments:
        arguments = (*arguments, "--platform", "linux/amd64")
    monkeypatch.setattr(cli.sys, "argv", ["skylos", "image", "scan", *arguments])
    with pytest.raises(SystemExit) as error:
        cli.main()
    return error.value.code


def _document(capsys):
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["receipt"]["scan_complete"] is None
    assert document["gate"]["scope"] == "direct_image_scan"
    return document, captured.err


def _assert_finding(document):
    findings = document["container_vulnerabilities"]
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "TRIVY:CVE-2026-1234"
    assert findings[0]["package"] == "example-lib"


@pytest.fixture
def scanner(tmp_path, monkeypatch):
    """The fake process writes a report only; it never contacts a registry."""
    from skylos.commands import image_cmd

    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    tool = tmp_path / "tools" / "trivy"
    tool.parent.mkdir()
    assert write_text_no_symlink(tool, "#!/bin/sh\nexit 99\n")
    tool.chmod(0o755)

    state = {"calls": [], "report": _report(), "returncode": 0, "timeout": False}
    monkeypatch.setattr(
        image_cmd.shutil, "which", lambda name: str(tool) if name == "trivy" else None
    )

    def fake_run(argv, **kwargs):
        state["calls"].append((list(argv), kwargs))
        assert argv[0] == str(tool)
        assert Path(kwargs["cwd"]).is_dir()
        assert Path(kwargs["cwd"]).resolve() != project.resolve()
        report_path = Path(argv[argv.index("--output") + 1])
        if state["report"] is not None:
            assert write_text_no_symlink(report_path, json.dumps(state["report"]))
        if state["timeout"]:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        return subprocess.CompletedProcess(
            argv,
            state["returncode"],
            stdout="TRIVY_STDOUT_SENTINEL",
            stderr="TRIVY_STDERR_SENTINEL",
        )

    monkeypatch.setattr(image_cmd.subprocess, "run", fake_run)

    def no_network(*_args, **_kwargs):
        pytest.fail("The fake image scan must not use a network connection")

    monkeypatch.setattr(socket, "create_connection", no_network)
    return state


def test_help_exposes_image_scan_options(monkeypatch, capsys):
    assert _invoke(monkeypatch, "--help") == 0
    help_text = capsys.readouterr().out
    for option in (
        "--platform",
        "--fail-on",
        "--output",
        "--sarif",
        "--timeout-seconds",
    ):
        assert option in help_text


def test_scan_runs_bounded_trivy_with_isolated_cwd_and_environment(
    scanner, tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("TRIVY_CONFIG", str(tmp_path / "attacker.yaml"))
    monkeypatch.setenv("TRIVY_SKIP_DB_UPDATE", "true")
    monkeypatch.setenv("TRIVY_PASSWORD", "must-not-leak")
    monkeypatch.setenv("SKYLOS_IMAGE_SCAN_TEST", "preserved")

    assert _invoke(monkeypatch, IMAGE, "--platform", "linux/amd64") == 0
    document, error_text = _document(capsys)
    _assert_finding(document)
    assert error_text == ""
    assert document["receipt"]["execution"]["status"] == "completed"
    assert document["receipt"]["execution"]["scanner"] == "Trivy"
    assert document["receipt"]["execution"]["source"] == "remote"
    assert document["receipt"]["identity_verified"] is True
    assert document["receipt"]["platform_verified"] is True

    assert len(scanner["calls"]) == 1
    argv, options = scanner["calls"][0]
    assert argv[1] == "image"
    assert argv[-1] == IMAGE
    for flag, value in (
        ("--image-src", "remote"),
        ("--scanners", "vuln"),
        ("--pkg-types", "os,library"),
        ("--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"),
        ("--exit-code", "0"),
        ("--format", "json"),
        ("--platform", "linux/amd64"),
        ("--timeout", "300s"),
    ):
        assert argv[argv.index(flag) + 1] == value
    for flag in (
        "--config",
        "--ignorefile",
        "--output",
        "--disable-telemetry",
        "--no-progress",
        "--ignore-unfixed=false",
    ):
        assert flag in argv
    assert options.get("shell", False) is False
    assert Path(options["cwd"]).resolve() != (tmp_path / "project").resolve()
    assert options["timeout"] <= 315
    assert all(not key.startswith("TRIVY_") for key in options["env"])
    assert options["env"]["SKYLOS_IMAGE_SCAN_TEST"] == "preserved"


@pytest.mark.parametrize(
    ("requested", "reported"),
    [
        ("docker.io/library/alpine", "alpine"),
        ("index.docker.io/library/alpine", "alpine"),
        ("library/alpine", "alpine"),
        ("docker.io/team/app", "team/app"),
        ("docker.io", "docker.io"),
        ("registry.example.com/team/app", "registry.example.com/team/app"),
    ],
)
def test_direct_scan_accepts_only_trivy_docker_hub_spelling(
    scanner, monkeypatch, capsys, requested, reported
):
    digest = "a" * 64
    requested_image = f"{requested}@sha256:{digest}"
    reported_image = f"{reported}@sha256:{digest}"
    scanner["report"] = _report(image=reported_image)
    assert _invoke(monkeypatch, requested_image, "--fail-on", "high") == 1
    document, _ = _document(capsys)
    assert document["receipt"]["identity_verified"] is True
    assert document["receipt"]["verified_image"] == reported_image


def test_direct_scan_rejects_another_repository_with_same_digest(
    scanner, monkeypatch, capsys
):
    scanner["report"] = _report(image="another.example.com/team/app@sha256:" + "a" * 64)
    assert _invoke(monkeypatch, IMAGE, "--fail-on", "high") == 2
    document, _ = _document(capsys)
    assert document["receipt"]["identity_verified"] is False
    assert document["gate"]["status"] == "incomplete"


@pytest.mark.parametrize(
    ("severity", "threshold", "exit_code", "gate_status"),
    [
        ("HIGH", "critical", 0, "passed"),
        ("HIGH", "high", 1, "failed"),
        ("CRITICAL", "critical", 1, "failed"),
    ],
)
def test_scan_applies_severity_gate(
    scanner, monkeypatch, capsys, severity, threshold, exit_code, gate_status
):
    scanner["report"] = _report(severity=severity)
    assert _invoke(monkeypatch, IMAGE, "--fail-on", threshold) == exit_code
    document, _ = _document(capsys)
    _assert_finding(document)
    assert document["gate"]["status"] == gate_status
    assert document["gate"]["blocking_count"] == (1 if exit_code else 0)


def test_json_and_sarif_files_keep_stdout_clean(scanner, tmp_path, monkeypatch, capsys):
    json_path = tmp_path / "result.json"
    sarif_path = tmp_path / "result.sarif"
    assert (
        _invoke(
            monkeypatch,
            IMAGE,
            "-o",
            str(json_path),
            "--sarif",
            str(sarif_path),
        )
        == 0
    )
    assert capsys.readouterr().out == ""
    document = json.loads(json_path.read_text(encoding="utf-8"))
    _assert_finding(document)
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "TRIVY:CVE-2026-1234"


@pytest.mark.parametrize(
    ("image", "platform"),
    [
        ("registry.example.com/team/app:latest", "linux/amd64"),
        ("registry.example.com/team/app@sha256:" + "A" * 64, "linux/amd64"),
        ("registry.example.com/team/app@sha256:" + "a" * 64 + " extra", "linux/amd64"),
        (IMAGE, "linux/amd64/"),
    ],
)
def test_invalid_image_or_platform_never_launches_scanner(
    scanner, monkeypatch, capsys, image, platform
):
    assert _invoke(monkeypatch, image, "--platform", platform) == 2
    document, error_text = _document(capsys)
    assert scanner["calls"] == []
    assert document["receipt"]["execution"]["status"] == "invalid_request"
    assert document["gate"]["status"] == "incomplete"
    assert document["receipt"]["errors"]
    assert error_text


def test_symlink_output_is_rejected_before_scanner_runs(
    scanner, tmp_path, monkeypatch, capsys
):
    preserved = tmp_path / "preserved.json"
    assert write_text_no_symlink(preserved, "preserve this")
    link = tmp_path / "result.json"
    link.symlink_to(preserved)
    assert _invoke(monkeypatch, IMAGE, "--output", str(link)) == 2
    document, _ = _document(capsys)
    assert scanner["calls"] == []
    assert preserved.read_text(encoding="utf-8") == "preserve this"
    assert document["receipt"]["execution"]["status"] == "invalid_request"


def test_colliding_outputs_are_rejected_before_scanner_runs(
    scanner, tmp_path, monkeypatch, capsys
):
    output = tmp_path / "result.json"
    assert _invoke(monkeypatch, IMAGE, "-o", str(output), "--sarif", str(output)) == 2
    document, _ = _document(capsys)
    assert scanner["calls"] == []
    assert not output.exists()
    assert document["gate"]["status"] == "incomplete"


@pytest.mark.parametrize("timeout_seconds", ["0", "901"])
def test_invalid_timeout_never_launches_scanner(
    scanner, monkeypatch, capsys, timeout_seconds
):
    assert _invoke(monkeypatch, IMAGE, "--timeout-seconds", timeout_seconds) == 2
    document, _ = _document(capsys)
    assert scanner["calls"] == []
    assert document["receipt"]["execution"]["status"] == "invalid_request"


def test_custom_timeout_reaches_trivy_and_execution_receipt(
    scanner, monkeypatch, capsys
):
    assert _invoke(monkeypatch, IMAGE, "--timeout-seconds", "12") == 0
    document, _ = _document(capsys)
    assert document["receipt"]["execution"]["timeout_seconds"] == 12
    argv, options = scanner["calls"][0]
    assert argv[argv.index("--timeout") + 1] == "12s"
    assert options["timeout"] == 27


@pytest.mark.parametrize("failure", ["nonzero", "timeout", "invalid_report"])
def test_incomplete_scans_retain_readable_findings(
    scanner, monkeypatch, capsys, failure
):
    if failure == "nonzero":
        scanner["returncode"] = 7
    elif failure == "timeout":
        scanner["timeout"] = True
    else:
        scanner["report"] = _report()
        scanner["report"]["Results"].append(None)
    assert _invoke(monkeypatch, IMAGE, "--fail-on", "high") == 2
    document, error_text = _document(capsys)
    _assert_finding(document)
    assert document["gate"]["status"] == "incomplete"
    assert document["receipt"]["errors"]
    assert error_text
    assert "TRIVY_STDERR_SENTINEL" not in error_text
    expected_status = (
        "timed_out"
        if failure == "timeout"
        else "failed"
        if failure == "nonzero"
        else "completed"
    )
    assert document["receipt"]["execution"]["status"] == expected_status


def test_unavailable_scanner_returns_receipt_without_running(
    scanner, monkeypatch, capsys
):
    from skylos.commands import image_cmd

    monkeypatch.setattr(image_cmd.shutil, "which", lambda _name: None)
    assert _invoke(monkeypatch, IMAGE, "--fail-on", "high") == 2
    document, error_text = _document(capsys)
    assert scanner["calls"] == []
    assert document["receipt"]["execution"]["status"] == "unavailable"
    assert document["gate"]["status"] == "incomplete"
    assert error_text


def test_private_workspace_failure_returns_incomplete_without_running(
    scanner, monkeypatch, capsys
):
    from skylos.commands import image_cmd

    def no_workspace(*_args, **_kwargs):
        raise OSError("simulated private workspace failure")

    monkeypatch.setattr(image_cmd.tempfile, "TemporaryDirectory", no_workspace)
    assert _invoke(monkeypatch, IMAGE) == 2
    document, _ = _document(capsys)
    assert scanner["calls"] == []
    assert document["receipt"]["execution"]["status"] == "failed"
    assert document["gate"]["status"] == "incomplete"


def test_project_local_executable_is_not_trusted(
    scanner, tmp_path, monkeypatch, capsys
):
    from skylos.commands import image_cmd

    project_tool = tmp_path / "project" / "trivy"
    assert write_text_no_symlink(project_tool, "#!/bin/sh\nexit 99\n")
    project_tool.chmod(0o755)
    monkeypatch.setattr(image_cmd.shutil, "which", lambda _name: str(project_tool))
    assert _invoke(monkeypatch, IMAGE) == 2
    document, _ = _document(capsys)
    assert scanner["calls"] == []
    assert document["receipt"]["execution"]["status"] == "unavailable"


def test_executable_in_parent_checkout_is_not_trusted(
    scanner, tmp_path, monkeypatch, capsys
):
    from skylos.commands import image_cmd

    project = tmp_path / "project"
    (project / ".git").mkdir()
    nested = project / "nested"
    nested.mkdir()
    project_tool = project / "trivy"
    assert write_text_no_symlink(project_tool, "#!/bin/sh\nexit 99\n")
    project_tool.chmod(0o755)
    monkeypatch.chdir(nested)
    monkeypatch.setattr(image_cmd.shutil, "which", lambda _name: str(project_tool))
    assert _invoke(monkeypatch, IMAGE) == 2
    document, _ = _document(capsys)
    assert scanner["calls"] == []
    assert document["receipt"]["execution"]["status"] == "unavailable"


def test_ingest_trivy_still_imports_without_running_scanner(
    scanner, tmp_path, monkeypatch, capsys
):
    report_path = tmp_path / "existing-report.json"
    assert write_text_no_symlink(report_path, json.dumps(_report()))
    monkeypatch.setattr(
        cli.sys,
        "argv",
        ["skylos", "ingest", "trivy", "-i", str(report_path)],
    )
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 0
    document = json.loads(capsys.readouterr().out)
    _assert_finding(document)
    assert scanner["calls"] == []
    assert "execution" not in document["receipt"]
