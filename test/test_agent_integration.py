from unittest.mock import MagicMock, patch

import pytest


def test_agent_review_passes_exclude_folders():
    with (
        patch("skylos.cli.run_pipeline") as mock_pipeline,
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.get_git_changed_files", return_value=["fake.py"]),
        patch("skylos.cli.inquirer.confirm", return_value=True),
        patch("sys.argv", ["skylos", "agent", "scan", ".", "--changed"]),
    ):
        mock_pipeline.return_value = []

        from skylos.cli import main

        try:
            main()
        except SystemExit:
            pass

        call = mock_pipeline.call_args
        assert call is not None, "run_pipeline was not called"
        assert "exclude_folders" in call.kwargs
        assert "node_modules" in call.kwargs["exclude_folders"]


def test_agent_analyze_exits_zero_by_default(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    findings = [
        {
            "file": str(sample),
            "line": 1,
            "message": "Issue found",
            "_category": "security",
            "_source": "llm",
        }
    ]

    with (
        patch("skylos.cli.run_pipeline", return_value=findings),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("sys.argv", ["skylos", "agent", "scan", str(tmp_path)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0


def test_agent_analyze_strict_exits_one_when_findings_exist(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    findings = [
        {
            "file": str(sample),
            "line": 1,
            "message": "Issue found",
            "_category": "security",
            "_source": "llm",
        }
    ]

    with (
        patch("skylos.cli.run_pipeline", return_value=findings),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("sys.argv", ["skylos", "agent", "scan", str(tmp_path), "--strict"]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 1


def test_security_audit_skips_confirmation_without_tty(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    fake_llm = MagicMock()
    fake_llm.analyze_files.return_value = MagicMock(has_blockers=False)

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.INTERACTIVE_AVAILABLE", True),
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.inquirer.confirm") as mock_confirm,
        patch("skylos.cli.SkylosLLM", return_value=fake_llm),
        patch(
            "sys.argv",
            ["skylos", "agent", "scan", str(tmp_path), "--security", "--interactive"],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_confirm.assert_not_called()
