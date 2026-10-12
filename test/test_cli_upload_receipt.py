"""One JSON report includes the scan and its Cloud upload outcome."""

import copy
import json
from unittest.mock import Mock

import pytest

import skylos.api as api
import skylos.cli as cli
from test.test_cli_report_serialization import _configure, _report


@pytest.mark.parametrize("output_format", ["json", "json-ci"])
@pytest.mark.parametrize("failed_gate", [False, True])
@pytest.mark.parametrize("output_file", [False, True])
def test_json_contains_confirmed_upload_and_cloud_gate(
    monkeypatch, capsys, tmp_path, output_format, failed_gate, output_file
):
    _configure(monkeypatch, tmp_path, output_format, upload=True)
    argv = [*cli.sys.argv, "--gate"]
    path = tmp_path / "scan.json"
    if output_file:
        argv.extend(["--output", str(path)])
    monkeypatch.setattr(cli.sys, "argv", argv)
    monkeypatch.setattr(cli, "load_config", lambda *_a, **_k: {"gate": {"max_dead_code": 10}})
    response = {
        "success": True,
        "scan_id": "fixture-scan",
        "quality_gate_passed": not failed_gate,
        "quality_gate": {
            "passed": not failed_gate,
            "reasons": ["required coverage missing"] if failed_gate else [],
            "coverage_failures": ["Required dependency scan has no SCA coverage receipt"] if failed_gate else [],
        },
        "authorization": "must-not-appear",
        "transport": {"token": "must-not-appear"},
    }
    upload = Mock(return_value=response)
    monkeypatch.setattr(cli, "upload_report", upload)
    if failed_gate:
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code == 1
    else:
        cli.main()
    captured = capsys.readouterr()
    raw = path.read_text(encoding="utf-8") if output_file else captured.out
    report = json.loads(raw)
    assert report["unused_functions"][0]["name"] == "unused"
    assert report["upload"] == {
        "status": "uploaded",
        "scan_id": "fixture-scan",
        "url": f"{api.BASE_URL.rstrip('/')}/dashboard/scans/fixture-scan",
        "quality_gate": response["quality_gate"],
    }
    assert "must-not-appear" not in raw
    upload.assert_called_once()
    assert upload.call_args.kwargs["quiet"] is True
    assert upload.call_args.kwargs["strict"] is False
    if output_file:
        assert captured.out == ""
    if output_format == "json-ci":
        assert "definitions" not in report
        assert "dead_code_evidence" not in report


@pytest.mark.parametrize("output_format", ["json", "json-ci"])
@pytest.mark.parametrize("failure", ["transport", "exception"])
def test_failed_upload_keeps_parseable_scan_and_receipt(
    monkeypatch, capsys, tmp_path, output_format, failure
):
    _configure(monkeypatch, tmp_path, output_format, upload=True)
    if failure == "exception":
        upload = Mock(side_effect=ConnectionError("Authorization: private-value"))
    else:
        upload = Mock(return_value={"success": False, "code": "UPLOAD_REJECTED", "error": "upload rejected"})
    monkeypatch.setattr(cli, "upload_report", upload)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    raw = capsys.readouterr().out
    report = json.loads(raw)
    assert report["unused_functions"]
    assert report["upload"]["status"] == "failed"
    assert report["upload"]["code"] == ("UPLOAD_UNAVAILABLE" if failure == "exception" else "UPLOAD_REJECTED")
    assert "private-value" not in raw


@pytest.mark.parametrize("output_format", ["json", "json-ci"])
def test_incomplete_analysis_has_skipped_upload_receipt(
    monkeypatch, capsys, tmp_path, output_format
):
    _configure(monkeypatch, tmp_path, output_format, upload=True)
    result = _report()
    result["analysis_errors"] = [{"rule_id": "SKY-ANALYSIS-INCOMPLETE", "file": "bad.py", "kind": "parse_error"}]
    monkeypatch.setattr(cli, "run_analyze", lambda *_a, **_k: json.dumps(result))
    upload = Mock()
    monkeypatch.setattr(cli, "upload_report", upload)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["analysis_errors"]
    assert report["upload"] == {"status": "skipped", "reason": "analysis_incomplete"}
    upload.assert_not_called()


def test_json_preserves_saved_scan_when_gitlab_delivery_is_unconfirmed(
    monkeypatch, capsys, tmp_path
):
    _configure(monkeypatch, tmp_path, "json", upload=True)
    monkeypatch.setattr(cli, "upload_report", lambda *_a, **_k: {
        "success": True,
        "scan_id": "saved-scan",
        "quality_gate_passed": True,
        "gitlab_delivery": {"status": "failed", "reason": "delivery_unconfirmed"},
        "gitlab_delivery_exit_code": 2,
        "gitlab_delivery_message": "Scan saved. GitLab comment delivery was not confirmed.",
    })
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    receipt = json.loads(captured.out)["upload"]
    assert receipt["status"] == "uploaded"
    assert receipt["scan_id"] == "saved-scan"
    assert receipt["delivery"] == {"status": "failed", "reason": "delivery_unconfirmed", "exit_code": 2}
    assert "Scan saved" in captured.err


@pytest.mark.parametrize("output_format", ["rich", "pretty", "json", "json-ci"])
def test_complete_strict_failure_uploads_in_every_format(
    monkeypatch, capsys, tmp_path, output_format
):
    _configure(monkeypatch, tmp_path, output_format, upload=True)
    monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, "--strict"])
    monkeypatch.setattr(cli, "_print_upload_destination", lambda *_a: (True, False))
    upload = Mock(return_value={"success": True, "scan_id": "saved-scan", "quality_gate_passed": True})
    monkeypatch.setattr(cli, "upload_report", upload)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    upload.assert_called_once()
    assert upload.call_args.kwargs["strict"] is False
    capsys.readouterr()


def test_api_keeps_coverage_receipts_in_all_report_transports(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "get_git_info", lambda: ("a" * 40, "main", "tester", None))
    monkeypatch.setattr(api, "get_git_root", lambda: str(tmp_path))
    monkeypatch.setattr(api, "_load_repo_link", lambda root: {})
    monkeypatch.setattr(api, "detect_ai_code", lambda root: {})
    result = _report()
    result["provenance"] = None
    coverage = {
        "sca_coverage": {"status": "complete_with_unresolved_versions", "complete": True, "unresolved_dependency_count": 1},
        "custom_rules_coverage": {"status": "complete", "rule_count": 1},
    }
    result["analysis_summary"].update(copy.deepcopy(coverage))
    snapshot = copy.deepcopy(result)
    prepared = api._prepare_report_upload(result, analyzer_owned=True)
    for key, receipt in coverage.items():
        assert prepared.scan_summary[key] == receipt
        assert prepared.legacy_payload["summary"][key] == receipt
        assert prepared.compatibility_payload["summary"][key] == receipt
        assert prepared.core_payload["runs"][0]["properties"]["summary"][key] == receipt
    assert result == snapshot


def test_api_success_receipt_retains_cloud_gate_reasons():
    gate = {"passed": False, "reasons": ["required SCA missing"], "message": "required SCA missing", "new_violations": 0, "coverage_failures": ["Required dependency scan has no SCA coverage receipt"]}
    result = api._report_upload_success_result({"quality_gate": gate}, "saved-scan", False, "free")
    assert result["quality_gate"] == gate
    assert result["quality_gate_reported"] is True
    assert result["url"].endswith("/dashboard/scans/saved-scan")


def test_missing_cloud_gate_is_not_presented_as_a_confirmed_pass():
    from skylos.commands.scan_cmd import _public_upload_receipt

    result = api._report_upload_success_result({}, "saved-scan", True, "free")
    assert result["quality_gate_reported"] is False
    receipt = _public_upload_receipt(result)
    assert "quality_gate" not in receipt
    assert receipt["quality_gate_status"] == "not_reported"


@pytest.mark.parametrize("output_format", ["rich", "pretty", "concise"])
def test_report_only_dependency_coverage_warning_is_visible(
    monkeypatch, capsys, tmp_path, output_format
):
    _configure(monkeypatch, tmp_path, output_format)
    result = _report()
    result["analysis_summary"]["sca_coverage"] = {"status": "no_supported_manifests", "complete": False}
    monkeypatch.setattr(cli, "run_analyze", lambda *_a, **_k: json.dumps(result))
    try:
        cli.main()
    except SystemExit as exc:
        assert output_format == "concise" and exc.code == 1
    output = capsys.readouterr()
    assert "SCA coverage limited" in output.out + output.err
