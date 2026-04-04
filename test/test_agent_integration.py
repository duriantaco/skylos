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


def test_agent_scan_disables_api_key_prompt_without_tty(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch("skylos.cli.run_pipeline", return_value=[]),
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ) as mock_runtime,
        patch("skylos.cli._is_tty", return_value=False),
        patch("sys.argv", ["skylos", "agent", "scan", str(sample)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    assert mock_runtime.call_args.kwargs["allow_prompt"] is False


def test_agent_scan_without_api_key_non_tty_exits_with_message(tmp_path, capsys):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", None, None, False),
        ),
        patch("skylos.cli._is_tty", return_value=False),
        patch("sys.argv", ["skylos", "agent", "scan", str(sample)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    captured = capsys.readouterr()
    assert exc.value.code == 1
    assert "No OPENAI_API_KEY configured" in captured.out


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


def test_agent_scan_defaults_to_fast_review_without_dead_code_verification(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch("skylos.cli.run_pipeline", return_value=[]) as mock_pipeline,
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("sys.argv", ["skylos", "agent", "scan", str(sample)]),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    args = mock_pipeline.call_args.kwargs["agent_args"]
    assert args.skip_verification is True


def test_agent_scan_can_opt_into_dead_code_verification(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    with (
        patch("skylos.cli.run_pipeline", return_value=[]) as mock_pipeline,
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch(
            "sys.argv",
            ["skylos", "agent", "scan", str(sample), "--verify-dead-code"],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    args = mock_pipeline.call_args.kwargs["agent_args"]
    assert args.skip_verification is False


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


def test_security_audit_uses_gitignore_aware_discovery(tmp_path):
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
        patch("skylos.cli.llm_estimate_cost", return_value=(1, 0.01)),
        patch("skylos.cli.SkylosLLM", return_value=fake_llm),
        patch(
            "skylos.cli.discover_source_files", return_value=[sample]
        ) as mock_discover,
        patch(
            "sys.argv",
            ["skylos", "agent", "scan", str(tmp_path), "--security", "--interactive"],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_discover.assert_called_once()
    fake_llm.analyze_files.assert_called_once_with(
        [sample], issue_types=["security_audit"]
    )


def test_security_audit_passes_provider_and_base_url_into_analyzer_config(tmp_path):
    sample = tmp_path / "sample.py"
    sample.write_text("print('hi')\n")

    fake_llm = MagicMock()
    fake_llm.analyze_files.return_value = MagicMock(has_blockers=False)
    sentinel_config = object()

    with (
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("anthropic", "fake-key", "https://custom.endpoint", False),
        ),
        patch(
            "skylos.cli._build_analyzer_config", return_value=sentinel_config
        ) as mock_build,
        patch("skylos.cli._is_tty", return_value=False),
        patch("skylos.cli.SkylosLLM", return_value=fake_llm),
        patch(
            "sys.argv",
            [
                "skylos",
                "agent",
                "scan",
                str(tmp_path),
                "--security",
                "--provider",
                "anthropic",
                "--base-url",
                "https://custom.endpoint",
            ],
        ),
    ):
        from skylos.cli import main

        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_build.assert_called_once()
    kwargs = mock_build.call_args.kwargs
    assert kwargs["provider"] == "anthropic"
    assert kwargs["base_url"] == "https://custom.endpoint"
