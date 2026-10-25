"""A confirmed upload leaves an exact results link without changing gate exits."""

import json
from unittest.mock import Mock

import pytest

import skylos.api as api
import skylos.cli as cli
from test.test_cli_report_serialization import _configure, _report


FORMATTED = ["json", "json-ci", "concise", "llm", "github", "gitlab"]
SCAN_ID = "saved-scan-123"


def _gate_scan(monkeypatch, tmp_path, output_format, *, upload=True, forced=False):
    _configure(monkeypatch, tmp_path, output_format, upload=upload)
    monkeypatch.setattr(
        cli.sys, "argv", [*cli.sys.argv, "--gate", *(["--force"] if forced else [])]
    )
    result = _report()
    result["unused_functions"] = []
    monkeypatch.setattr(cli, "run_analyze", lambda *_a, **_k: json.dumps(result))
    return result


def _run_exit():
    try:
        cli.main()
    except SystemExit as exc:
        return exc.code
    return 0


@pytest.mark.parametrize("output_format", FORMATTED)
@pytest.mark.parametrize("gate", ["passed", "failed", "forced"])
def test_formatted_gate_upload_prints_exact_saved_scan_on_stderr(
    monkeypatch, capsys, tmp_path, output_format, gate
):
    _gate_scan(monkeypatch, tmp_path, output_format, forced=gate == "forced")
    response = {
        "success": True,
        "scan_id": SCAN_ID,
        "quality_gate_passed": gate == "passed",
        "quality_gate": {"passed": gate == "passed"},
        "url": "https://untrusted.example/ignored-response-url",
    }
    upload = Mock(return_value=response)
    monkeypatch.setattr(cli, "upload_report", upload)
    browser = Mock()
    monkeypatch.setattr("webbrowser.open", browser)

    assert _run_exit() == (1 if gate == "failed" else 0)
    captured = capsys.readouterr()
    url = f"{api.BASE_URL.rstrip('/')}/dashboard/scans/{SCAN_ID}"
    assert captured.err.count(url) == 1
    assert "View Cloud gate and results:" in captured.err
    assert "untrusted.example" not in captured.out + captured.err
    if output_format in ("json", "json-ci"):
        assert json.loads(captured.out)["upload"]["url"] == url
    else:
        assert url not in captured.out
    if output_format == "gitlab":
        assert json.loads(captured.out) == []
    upload.assert_called_once()
    assert upload.call_args.kwargs["quiet"] is True
    assert upload.call_args.kwargs["strict"] is False
    browser.assert_not_called()


@pytest.mark.parametrize("output_format", ["json", "json-ci"])
def test_output_file_stays_machine_only_with_link_on_stderr(
    monkeypatch, capsys, tmp_path, output_format
):
    _gate_scan(monkeypatch, tmp_path, output_format)
    path = tmp_path / "report.json"
    monkeypatch.setattr(cli.sys, "argv", [*cli.sys.argv, "--output", str(path)])
    monkeypatch.setattr(
        cli,
        "upload_report",
        lambda *_a, **_k: {
            "success": True,
            "scan_id": SCAN_ID,
            "quality_gate_passed": False,
        },
    )
    assert _run_exit() == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert json.loads(path.read_text())["upload"]["scan_id"] == SCAN_ID
    assert captured.err.count(f"/dashboard/scans/{SCAN_ID}") == 1


@pytest.mark.parametrize("output_format", FORMATTED)
def test_local_gate_never_uploads_or_claims_a_saved_cloud_scan(
    monkeypatch, capsys, tmp_path, output_format
):
    _gate_scan(monkeypatch, tmp_path, output_format, upload=False)
    upload = Mock()
    monkeypatch.setattr(cli, "upload_report", upload)
    browser = Mock()
    monkeypatch.setattr("webbrowser.open", browser)
    assert _run_exit() == 0
    captured = capsys.readouterr()
    assert "View Cloud gate and results:" not in captured.out + captured.err
    assert "/dashboard/scans/" not in captured.out + captured.err
    upload.assert_not_called()
    browser.assert_not_called()


@pytest.mark.parametrize(
    "response,exit_code",
    [
        ({"success": False, "scan_id": SCAN_ID}, 1),
        ({"success": True}, 0),
        ({"success": True, "scan_id": "bad\nhttps://untrusted.example"}, 0),
    ],
)
def test_unconfirmed_or_invalid_upload_never_prints_a_results_link(
    monkeypatch, capsys, tmp_path, response, exit_code
):
    _gate_scan(monkeypatch, tmp_path, "json")
    monkeypatch.setattr(cli, "upload_report", lambda *_a, **_k: response)
    assert _run_exit() == exit_code
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert "View Cloud gate and results:" not in captured.err
    assert "untrusted.example" not in captured.out + captured.err


def test_rich_upload_still_prints_one_saved_scan_link_before_enforcing_gate(capsys):
    response = Mock(status_code=200)
    response.json.return_value = {
        "scan_id": SCAN_ID,
        "quality_gate": {"passed": False},
    }
    with pytest.raises(SystemExit) as exc:
        api._finalize_report_upload(response, grade_data=None, strict=True)
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out.count(f"/dashboard/scans/{SCAN_ID}") == 1
    assert "Commit blocked by quality gate" in captured.out
