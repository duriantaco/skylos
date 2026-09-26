"""Exercise opt-in npm publisher review through the real scan CLI."""

import json

import pytest

import skylos.cli as cli
from skylos.rules.sca import publisher_changes


RULE_ID = "SKY-SCA-NPM-PUB001"


@pytest.fixture
def project(tmp_path, monkeypatch):
    path = tmp_path / "project"
    path.mkdir()
    (path / "package-lock.json").write_text(
        json.dumps({"name": "local-app", "lockfileVersion": 3, "packages": {"": {}}}),
        encoding="utf-8",
    )
    monkeypatch.chdir(path)
    monkeypatch.delenv("SKYLOS_CONFIG_FILE", raising=False)
    monkeypatch.setattr(
        cli,
        "upload_report",
        lambda *args, **kwargs: pytest.fail("CLI test must not upload"),
    )
    return path


def _finding(project):
    return {
        "rule_id": RULE_ID,
        "severity": "WARN",
        "message": "bob first published example after a 210-day release gap",
        "file": str(project / "package-lock.json"),
        "line": 1,
        "metadata": {
            "package_name": "example",
            "package_version": "2.0.0",
            "previous_publisher": "alice",
            "new_publisher": "bob",
            "dormancy_days": 210,
        },
    }


def _run_cli(project, monkeypatch, *flags):
    report_path = project.parent / "publisher-report.json"
    sarif_path = project.parent / "publisher-report.sarif"
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(project),
            "--format",
            "json",
            "--no-upload",
            "--no-provenance",
            "--no-grep-verify",
            "--output",
            str(report_path),
            "--sarif",
            str(sarif_path),
            *flags,
        ],
    )
    try:
        cli.main()
    except SystemExit as exc:
        exit_code = exc.code
    else:
        exit_code = 0
    return (
        exit_code,
        json.loads(report_path.read_text(encoding="utf-8")),
        json.loads(sarif_path.read_text(encoding="utf-8")),
    )


def test_publisher_review_reaches_json_and_sarif_without_failing_gate(
    project, monkeypatch
):
    calls = []
    finding = _finding(project)

    def fake_scan(root, *, enabled=False):
        calls.append((root, enabled))
        return publisher_changes.PublisherScanResult(
            findings=[finding],
            receipt={
                "status": "complete",
                "complete": True,
                "selected_lockfiles": 1,
                "submitted_packages": 1,
                "finding_count": 1,
            },
        )

    monkeypatch.setattr(publisher_changes, "scan_publisher_changes", fake_scan)
    exit_code, result, sarif = _run_cli(
        project, monkeypatch, "--scan-publisher-changes", "--gate"
    )

    assert calls == [(project, True)]
    assert exit_code == 0
    assert result.get("dependency_vulnerabilities", []) == []
    assert result["publisher_change_findings"] == [finding]
    summary = result["analysis_summary"]
    assert summary["publisher_change_count"] == 1
    assert summary["publisher_change_scan"] == {
        "status": "complete",
        "complete": True,
        "selected_lockfiles": 1,
        "submitted_packages": 1,
        "finding_count": 1,
        "warnings": [],
    }
    assert "sca_coverage" in summary  # The flag also enables normal SCA.

    run = sarif["runs"][0]
    assert [item["ruleId"] for item in run["results"]] == [RULE_ID]
    exported = run["results"][0]
    assert exported["level"] == "note"
    assert exported["properties"]["category"] == "PUBLISHER_CHANGE"
    assert exported["properties"]["review_only"] is True
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == RULE_ID
    assert "security-severity" not in rule["properties"]


def test_publisher_warnings_are_visible_in_json_receipt(project, monkeypatch):
    def fake_scan(root, *, enabled=False):
        assert root == project
        assert enabled is True
        return publisher_changes.PublisherScanResult(
            warnings=["npm registry unavailable"],
            receipt={"status": "partial", "complete": False, "finding_count": 0},
        )

    monkeypatch.setattr(publisher_changes, "scan_publisher_changes", fake_scan)
    exit_code, result, sarif = _run_cli(
        project, monkeypatch, "--scan-publisher-changes"
    )

    assert exit_code == 0
    assert result["publisher_change_findings"] == []
    assert result["analysis_summary"]["publisher_change_count"] == 0
    assert result["analysis_summary"]["publisher_change_scan"] == {
        "status": "partial",
        "complete": False,
        "finding_count": 0,
        "warnings": ["npm registry unavailable"],
    }
    assert sarif["runs"][0]["results"] == []


def test_plain_sca_never_starts_publisher_review(project, monkeypatch):
    def unexpected_scan(*args, **kwargs):
        pytest.fail("plain --sca must not call the publisher scanner")

    monkeypatch.setattr(publisher_changes, "scan_publisher_changes", unexpected_scan)
    exit_code, result, sarif = _run_cli(project, monkeypatch, "--sca", "--gate")

    assert exit_code == 0
    assert "publisher_change_findings" not in result
    assert "publisher_change_scan" not in result["analysis_summary"]
    assert result.get("dependency_vulnerabilities", []) == []
    assert sarif["runs"][0]["results"] == []
