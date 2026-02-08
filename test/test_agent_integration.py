from unittest.mock import patch


def test_agent_review_passes_exclude_folders():
    with (
        patch("skylos.cli.run_pipeline") as mock_pipeline,
        patch(
            "skylos.cli.resolve_llm_runtime",
            return_value=("openai", "fake-key", None, False),
        ),
        patch("skylos.cli.get_git_changed_files", return_value=["fake.py"]),
        patch("skylos.cli.inquirer.confirm", return_value=True),
        patch("sys.argv", ["skylos", "agent", "review", "."]),
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
