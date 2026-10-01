"""Exercise the rich upload flow with a real local analysis."""

import json
from io import StringIO
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

import skylos.cli as cli


@pytest.mark.parametrize("source,expected_exit,should_upload,cloud_gate_passed", [
    ("def broken(:\n    pass\n", 2, False, True),
    ("def working():\n    return 1\n", 0, True, True),
    ("def working():\n    return 1\n", 0, True, False),
])
def test_rich_upload_waits_for_complete_analysis(
    tmp_path, monkeypatch, source, expected_exit, should_upload, cloud_gate_passed
):
    source_path = tmp_path / "app.py"
    source_path.write_text(source, encoding="utf-8")
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "-a",
            "--upload",
            "--no-provenance",
            "--no-clipboard",
            "--limit",
            "1",
        ],
    )
    output = StringIO()
    logger = Mock()
    logger.console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        theme=cli._skylos_console_theme(),
        width=180,
    )

    with (
        patch("skylos.cli.setup_logger", return_value=logger),
        patch("skylos.cli._print_upload_destination", return_value=(True, False)),
        patch("skylos.api.get_project_token", return_value="test-token"),
        patch("skylos.api.get_credit_balance", return_value=None),
        patch("skylos.cli.print_badge"),
        patch(
            "skylos.cli.upload_report",
            return_value={"success": True, "quality_gate_passed": cloud_gate_passed},
        ) as upload,
    ):
        if expected_exit:
            with pytest.raises(SystemExit) as exc:
                cli.main()
            assert exc.value.code == expected_exit
        else:
            cli.main()
    rendered = output.getvalue()
    assert "Analyzing locally; Cloud upload starts after the scan completes." in rendered
    if should_upload:
        assert "Source analysis complete; preparing Cloud upload." in rendered
        assert "Scan incomplete" not in rendered
        upload.assert_called_once()
    else:
        assert "Scan incomplete; Cloud upload was not started." in rendered
        assert "Source analysis complete; preparing Cloud upload." not in rendered
        assert "app.py" in rendered
        assert "syntax error: invalid syntax" in rendered
        upload.assert_not_called()


def test_rich_upload_shows_grep_budget_failure_without_cloud_call(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "import os\n\ndef orphan(unused_arg):\n    return 1\n",
        encoding="utf-8",
    )
    (tmp_path / "utils.py").write_text(
        "def another_orphan():\n    return 2\n", encoding="utf-8"
    )
    monkeypatch.setenv("SKYLOS_GREP_BUDGET", "0")
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "-a",
            "--upload",
            "--confidence",
            "0",
            "--no-provenance",
            "--no-clipboard",
            "--limit",
            "1",
        ],
    )
    output = StringIO()
    logger = Mock()
    logger.console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        theme=cli._skylos_console_theme(),
        width=180,
    )

    with (
        patch("skylos.cli.setup_logger", return_value=logger),
        patch("skylos.cli.upload_report") as upload,
    ):
        with pytest.raises(SystemExit) as exc:
            cli.main()

    assert exc.value.code == 2
    rendered = output.getvalue()
    assert "Scan incomplete; Cloud upload was not started." in rendered
    assert "Source analysis complete; preparing Cloud upload." not in rendered
    assert "Analysis Errors" in rendered
    assert "grep budget exhausted" in rendered
    assert "Increase SKYLOS_GREP_BUDGET" in rendered
    upload.assert_not_called()


@pytest.mark.parametrize("output_format", ["json", "json-ci"])
def test_formatted_upload_keeps_advisory_cloud_gate(tmp_path, monkeypatch, capsys, output_format):
    (tmp_path / "app.py").write_text(
        "def working():\n    return 1\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        cli.sys,
        "argv",
        [
            "skylos",
            str(tmp_path),
            "-a",
            "--upload",
            "--format",
            output_format,
            "--no-provenance",
            "--no-clipboard",
        ],
    )

    with patch(
        "skylos.cli.upload_report",
        return_value={"success": True, "quality_gate_passed": False},
    ) as upload:
        cli.main()

    upload.assert_called_once()
    assert json.loads(capsys.readouterr().out)["analysis_errors"] == []
