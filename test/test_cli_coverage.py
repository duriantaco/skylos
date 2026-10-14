import shlex
import sys
from pathlib import PurePath
from unittest.mock import MagicMock, call, patch

import pytest


@pytest.fixture(autouse=True)
def _placeholder_scan_paths(monkeypatch):
    """These tests mock the analyzer and pass placeholder paths such as
    ``/some/project``; the missing-path check has its own tests."""
    import skylos.commands.scan_cmd as scan_cmd

    monkeypatch.setattr(
        scan_cmd, "_exit_on_missing_scan_paths", lambda args, *, cli_module: None
    )


def _command_text(call) -> str:
    """The command a mocked subprocess.run call ran, without its environment.

    The environment carries PYTEST_CURRENT_TEST, which names this file and so
    contains "coverage" for every subprocess (e.g. git) the scan makes.
    """
    command = call.args[0] if call.args else call.kwargs.get("args", "")
    return (
        " ".join(map(str, command))
        if isinstance(command, (list, tuple))
        else str(command)
    )


def _command_argv(call) -> list[str]:
    command = call.args[0] if call.args else call.kwargs.get("args", "")
    if isinstance(command, (list, tuple)):
        return [str(part) for part in command]
    return shlex.split(str(command))


def _runs_coverage(call) -> bool:
    """Whether a mocked subprocess.run call starts a coverage run.

    It looks at what is executed (``coverage run``, ``python -m coverage``,
    ``pytest --cov``), never at substrings: the scan's own subprocesses (git)
    can carry a checkout path that contains the word "coverage".
    """
    argv = _command_argv(call)
    if not argv:
        return False
    program = PurePath(argv[0]).name.lower()
    if program in {"coverage", "coverage.exe"}:
        return True
    module = (
        argv[argv.index("-m") + 1].lower()
        if "-m" in argv[:-1] and program.startswith("python")
        else None
    )
    if module == "coverage":
        return True
    runs_pytest = program in {"pytest", "pytest.exe", "py.test"} or module == "pytest"
    return runs_pytest and any(
        arg == "--cov" or arg.startswith("--cov=") for arg in argv[1:]
    )


def test_coverage_run_matcher_looks_at_the_command_not_its_paths():
    def call(command):
        return MagicMock(args=(command,), kwargs={})

    for command in (
        ["coverage", "run", "-m", "pytest", "-q"],
        ["/venv/bin/coverage", "run", "-m", "unittest", "discover"],
        ["python3", "-m", "coverage", "run", "-m", "pytest"],
        ["pytest", "--cov=skylos", "-q"],
        ["python", "-m", "pytest", "--cov"],
        "coverage run -m pytest",
    ):
        assert _runs_coverage(call(command)), command
    for command in (
        ["git", "-C", "/work/t0-exit-and-coverage", "rev-parse", "HEAD"],
        ["pytest", "-q", "tests/test_coverage.py"],
        ["python", "/tools/coverage_report.py"],
        ["git", "log", "--", "coverage"],
    ):
        assert not _runs_coverage(call(command)), command


class TestCoverageFlag:
    @patch("skylos.cli.subprocess.run")
    @patch("skylos.cli.run_analyze")
    def test_coverage_runs_pytest_first(self, mock_analyze, mock_run):
        """--coverage should run pytest with coverage before analysis."""
        from skylos.cli import main

        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'

        with patch.object(
            sys,
            "argv",
            [
                "skylos",
                ".",
                "--coverage",
                "--allow-coverage-execution",
                "--json",
                "--no-provenance",
            ],
        ):
            try:
                main()
            except SystemExit:
                pass

        calls = mock_run.call_args_list
        assert any(
            _runs_coverage(call) and "pytest" in _command_argv(call) for call in calls
        )

    @patch("skylos.cli.subprocess.run")
    @patch("skylos.cli.run_analyze")
    def test_coverage_skips_test_execution_without_trust_flag(
        self, mock_analyze, mock_run
    ):
        """--coverage must not execute project tests unless the repo is trusted."""
        from skylos.cli import main

        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'

        with patch.object(
            sys, "argv", ["skylos", ".", "--coverage", "--json", "--no-provenance"]
        ):
            try:
                main()
            except SystemExit:
                pass

        coverage_calls = [
            call for call in mock_run.call_args_list if _runs_coverage(call)
        ]
        assert coverage_calls == []
        mock_analyze.assert_called_once()

    @patch("skylos.cli.subprocess.run")
    @patch("skylos.cli.run_analyze")
    def test_coverage_falls_back_to_unittest(self, mock_analyze, mock_run):
        from skylos.cli import main

        test_runs = iter(
            [
                MagicMock(returncode=1),  # pytest fails
                MagicMock(returncode=0),  # unittest succeeds
            ]
        )

        def run(*args, **kwargs):
            command = args[0] if args else kwargs.get("args")
            # Other subprocesses (e.g. git) are not test runs.
            if isinstance(command, (list, tuple)) and command and command[0] == "git":
                return MagicMock(returncode=1, stdout="", stderr="")
            return next(test_runs)

        mock_run.side_effect = run
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'

        with patch.object(
            sys,
            "argv",
            [
                "skylos",
                ".",
                "--coverage",
                "--allow-coverage-execution",
                "--json",
                "--no-provenance",
            ],
        ):
            try:
                main()
            except SystemExit:
                pass

        calls = [
            _command_text(c)
            for c in mock_run.call_args_list
            if not _command_text(c).startswith("git ")
        ]
        assert len(calls) == 2
        assert any("pytest" in c for c in calls)
        assert any("unittest" in c for c in calls)

    @patch("skylos.cli.subprocess.run")
    @patch("skylos.cli.run_analyze")
    def test_coverage_runs_before_analysis(self, mock_analyze, mock_run):
        """Coverage collection must happen BEFORE analysis."""
        from skylos.cli import main

        call_order = []

        def track_subprocess(*args, **kwargs):
            # Only a coverage run counts; the scan's git calls do not.
            if _runs_coverage(call(*args, **kwargs)):
                call_order.append("coverage")
            return MagicMock(returncode=0)

        def track_analyze(*args, **kwargs):
            call_order.append("analyze")
            return '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'

        mock_run.side_effect = track_subprocess
        mock_analyze.side_effect = track_analyze

        with patch.object(
            sys,
            "argv",
            [
                "skylos",
                ".",
                "--coverage",
                "--allow-coverage-execution",
                "--json",
                "--no-provenance",
            ],
        ):
            try:
                main()
            except SystemExit:
                pass

        assert call_order.index("coverage") < call_order.index("analyze")

    @patch("skylos.cli.subprocess.run")
    @patch("skylos.cli.run_analyze")
    def test_coverage_uses_project_root_cwd(self, mock_analyze, mock_run):
        """Coverage should run in the project root directory."""
        from skylos.cli import main

        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'

        with patch.object(
            sys,
            "argv",
            [
                "skylos",
                "/some/project",
                "--coverage",
                "--allow-coverage-execution",
                "--json",
                "--no-provenance",
            ],
        ):
            try:
                main()
            except SystemExit:
                pass

        call_kwargs = mock_run.call_args_list[0][1]
        assert "cwd" in call_kwargs

    @patch("skylos.cli.run_analyze")
    def test_no_coverage_flag_skips_coverage(self, mock_analyze):
        from skylos.cli import main

        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'

        with patch("skylos.cli.subprocess.run") as mock_run:
            with patch.object(
                sys, "argv", ["skylos", ".", "--json", "--no-provenance"]
            ):
                try:
                    main()
                except SystemExit:
                    pass

            # subprocess.run should not be called for coverage
            coverage_calls = [c for c in mock_run.call_args_list if _runs_coverage(c)]
            assert len(coverage_calls) == 0

    @patch("skylos.cli.subprocess.run")
    @patch("skylos.cli.run_analyze")
    def test_coverage_with_other_flags(self, mock_analyze, mock_run):
        """--coverage should work with other flags like --danger."""
        from skylos.cli import main

        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "danger": [], "analysis_summary": {"total_files": 1}}'

        with patch.object(
            sys,
            "argv",
            [
                "skylos",
                ".",
                "--coverage",
                "--allow-coverage-execution",
                "--danger",
                "--json",
                "--no-provenance",
            ],
        ):
            try:
                main()
            except SystemExit:
                pass

        assert mock_run.called
        mock_analyze.assert_called_once()
        call_kwargs = mock_analyze.call_args[1]
        assert call_kwargs.get("enable_danger") is True


class TestCoverageIntegration:
    @patch("skylos.analysis.implicit_refs.pattern_tracker")
    @patch("skylos.cli.subprocess.run")
    @patch("skylos.cli.run_analyze")
    def test_coverage_data_loaded_before_analysis(
        self, mock_analyze, mock_run, mock_tracker
    ):
        """After coverage runs, the .coverage file should be loaded."""
        from skylos.cli import main
        from pathlib import Path

        mock_run.return_value = MagicMock(returncode=0)
        mock_analyze.return_value = '{"unused_functions": [], "unused_imports": [], "unused_classes": [], "unused_variables": [], "unused_parameters": [], "analysis_summary": {"total_files": 1}}'

        with patch.object(Path, "exists", return_value=True):
            with patch.object(
                sys,
                "argv",
                [
                    "skylos",
                    ".",
                    "--coverage",
                    "--allow-coverage-execution",
                    "--json",
                    "--no-provenance",
                ],
            ):
                try:
                    main()
                except SystemExit:
                    pass

        assert mock_analyze.called
