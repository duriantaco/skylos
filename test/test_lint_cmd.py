import subprocess
from pathlib import Path
from unittest.mock import Mock

from rich.console import Console

from skylos.commands.lint_cmd import run_lint_command


def test_lint_command_defaults_to_current_directory():
    find_spec = Mock(return_value=object())
    run = Mock(
        return_value=subprocess.CompletedProcess(
            args=["python", "-m", "ruff", "check", "."],
            returncode=0,
        )
    )

    exit_code = run_lint_command(
        [],
        find_spec_func=find_spec,
        run_func=run,
        executable="/venv/bin/python",
    )

    assert exit_code == 0
    find_spec.assert_called_once_with("ruff")
    run.assert_called_once_with(
        ["/venv/bin/python", "-m", "ruff", "check", "."],
        check=False,
    )


def test_lint_command_forwards_ruff_arguments_and_exit_code():
    find_spec = Mock(return_value=object())
    run = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=1,
        )
    )
    argv = ["src", "test", "--select", "E,F", "--no-cache"]

    exit_code = run_lint_command(
        argv,
        find_spec_func=find_spec,
        run_func=run,
        executable="/venv/bin/python",
    )

    assert exit_code == 1
    run.assert_called_once_with(
        ["/venv/bin/python", "-m", "ruff", "check", *argv],
        check=False,
    )


def test_lint_command_reports_missing_optional_extra():
    console = Console(record=True, width=120)
    run = Mock()

    exit_code = run_lint_command(
        ["src"],
        find_spec_func=Mock(return_value=None),
        run_func=run,
        console_factory=lambda: console,
    )

    assert exit_code == 2
    run.assert_not_called()
    output = console.export_text()
    assert "Ruff is not installed" in output
    assert 'pip install "skylos[lint]"' in output


def test_lint_command_reports_launch_failure():
    console = Console(record=True, width=120)
    run = Mock(side_effect=OSError("executable unavailable"))

    exit_code = run_lint_command(
        ["src"],
        find_spec_func=Mock(return_value=object()),
        run_func=run,
        console_factory=lambda: console,
        executable="/missing/python",
    )

    assert exit_code == 2
    assert "Could not start Ruff" in console.export_text()


def test_lint_extra_is_optional_and_included_in_all():
    import tomllib

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    metadata = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    extras = metadata["project"]["optional-dependencies"]

    assert extras["lint"] == ["ruff>=0.15.0"]
    assert "ruff>=0.15.0" in extras["all"]
