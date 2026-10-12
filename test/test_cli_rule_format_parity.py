"""Use real analysis to prove renderer selection cannot omit Cloud rules."""

import json
import sys

import pytest

import skylos.cli as cli


RULE = {
    "rule_id": "CUSTOM-AUTH-001", "name": "Route requires auth",
    "rule_type": "yaml", "severity": "HIGH", "enabled": True,
    "yaml_config": {
        "pattern": {"type": "function", "decorators": {
            "has_any": ["route"], "must_also_have_any": ["auth"],
        }}, "message": "Route is missing required auth decorator",
    },
}


@pytest.mark.parametrize("output_format", ["pretty", "json", "json-ci", "concise", "github"])
def test_same_cloud_rule_runs_and_blocks_all_formats(tmp_path, monkeypatch, capsys, output_format):
    (tmp_path / "app.py").write_text("@route\ndef handler():\n    return 'ok'\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setenv("SKYLOS_TOKEN", "SYNTHETIC_TEST_TOKEN")
    monkeypatch.delenv("SKYLOS_CUSTOM_RULES", raising=False)
    endpoints, reports = [], []

    def api_get(endpoint, token):
        endpoints.append(endpoint)
        assert endpoint == "/api/sync/rules"
        return {"rules": [RULE]}

    monkeypatch.setattr("skylos.cloud.sync.api_get", api_get)
    monkeypatch.setattr("skylos.analysis.file_processing.load_community_rules", lambda: [])
    original = cli.run_analyze

    def record_analysis(*args, **kwargs):
        assert kwargs["custom_rules_data"] == [RULE]
        report = original(*args, **kwargs)
        reports.append(json.loads(report))
        return report

    monkeypatch.setattr(cli, "run_analyze", record_analysis)
    monkeypatch.setattr(sys, "argv", [
        "skylos", str(tmp_path), "--quality", "--strict", "--no-upload",
        "--select", RULE["rule_id"],
        "--no-provenance", "--no-grep-verify", "--format", output_format,
    ])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert endpoints == ["/api/sync/rules"]
    assert len([item for item in reports[-1]["custom_rules"]
                if item["rule_id"] == RULE["rule_id"]]) == 1
    output = capsys.readouterr()
    if output_format in {"json", "json-ci"}:
        report = json.loads(output.out)
        assert report["analysis_summary"]["custom_rules_coverage"] == {
            "status": "complete", "rule_count": 1,
        }


@pytest.mark.parametrize("status,expected", [("not_connected", 1), ("unavailable", 2), ("complete", 0)])
def test_required_rule_coverage_reports_missing_and_outage(tmp_path, monkeypatch, capsys, status, expected):
    (tmp_path / "app.py").write_text("print('ok')\n")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.skylos.gate.coverage]\nrequired = ["custom_rules"]\n'
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.delenv("SKYLOS_CUSTOM_RULES", raising=False)
    monkeypatch.setattr("skylos.cloud.sync.load_custom_rules", lambda: {"status": status, "rules": []})
    monkeypatch.setattr(sys, "argv", [
        "skylos", str(tmp_path), "--gate", "--format", "json", "--no-upload",
        "--no-provenance", "--no-grep-verify",
    ])
    code = 0
    try:
        cli.main()
    except SystemExit as exc:
        code = int(exc.code or 0)
    report = json.loads(capsys.readouterr().out)
    assert code == expected
    assert report["analysis_summary"]["custom_rules_coverage"]["status"] == status
    if status == "unavailable":
        assert any(item["kind"] == "custom_rules_unavailable" for item in report["analysis_errors"])


def test_required_custom_rules_enable_quality_in_credential_free_artifact_scan(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("@route\ndef handler():\n    return 'ok'\n")
    (tmp_path / "pyproject.toml").write_text('[tool.skylos.gate.coverage]\nrequired = ["custom_rules"]\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", json.dumps([RULE]))
    monkeypatch.delenv("SKYLOS_TOKEN", raising=False)
    monkeypatch.setattr("skylos.cloud.sync.api_get", lambda *_: pytest.fail("Artifact scan must not fetch rules"))
    monkeypatch.setattr(sys, "argv", [
        "skylos", str(tmp_path), "--danger", "--gate", "--strict", "--no-upload",
        "--no-provenance", "--no-grep-verify", "--format", "json", "--select", RULE["rule_id"],
    ])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["analysis_summary"]["custom_rules_coverage"]["status"] == "complete"
    assert report["analysis_summary"]["custom_rules_coverage"]["source"] == "environment"
    assert [item["rule_id"] for item in report["custom_rules"]] == [RULE["rule_id"]]


def test_loaded_rules_without_quality_are_not_reported_as_checked(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", json.dumps([RULE]))
    monkeypatch.setattr(sys, "argv", [
        "skylos", str(tmp_path), "--no-upload", "--no-provenance",
        "--no-grep-verify", "--format", "json",
    ])
    cli.main()
    report = json.loads(capsys.readouterr().out)
    assert report["analysis_summary"]["custom_rules_coverage"]["status"] == "not_scanned"


def test_invalid_environment_rules_report_unavailable_without_fetch(monkeypatch):
    from skylos.cloud.sync import load_custom_rules

    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "not-json")
    monkeypatch.setattr("skylos.cloud.sync.api_get", lambda *_: pytest.fail("No fallback to a different ruleset"))
    assert load_custom_rules()["status"] == "unavailable"


def test_python_rule_source_is_not_claimed_checked_or_executed(tmp_path, monkeypatch, capsys):
    (tmp_path / "app.py").write_text("print('ok')\n")
    (tmp_path / "pyproject.toml").write_text('[tool.skylos.gate.coverage]\nrequired = ["custom_rules"]\n')
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", json.dumps([{
        "rule_id": "CUSTOM-PYTHON", "enabled": True, "rule_type": "python",
        "python_code": "raise RuntimeError('DO_NOT_EXECUTE_CLOUD_RULE')",
    }]))
    monkeypatch.setattr(sys, "argv", [
        "skylos", str(tmp_path), "--gate", "--no-upload", "--no-provenance",
        "--no-grep-verify", "--format", "json", "--select", "CUSTOM-PYTHON",
    ])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    receipt = json.loads(capsys.readouterr().out)["analysis_summary"]["custom_rules_coverage"]
    assert receipt["status"] == "unsupported"
    assert receipt["reason"] == "unsupported_custom_rule_type"
