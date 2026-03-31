from unittest.mock import Mock, patch

import pytest

from skylos import cli
from skylos.commands import rules_cmd


def test_run_rules_command_returns_validate_failure():
    console = Mock()

    with patch("skylos.commands.rules_cmd.validate_rules", return_value=1) as validate:
        exit_code = rules_cmd.run_rules_command(
            ["validate", "missing.yml"],
            console_factory=lambda: console,
        )

    assert exit_code == 1
    validate.assert_called_once_with(console, "missing.yml")


def test_remove_rules_missing_pack_returns_one(tmp_path):
    console = Mock()

    exit_code = rules_cmd.remove_rules(console, tmp_path, "missing")

    assert exit_code == 1
    console.print.assert_called_once()


def test_validate_rules_missing_file_returns_one(tmp_path):
    console = Mock()

    exit_code = rules_cmd.validate_rules(console, str(tmp_path / "missing.yml"))

    assert exit_code == 1
    console.print.assert_called_once()


def test_cli_rules_remove_legacy_wrapper_raises_on_missing_pack(tmp_path):
    console = Mock()

    with pytest.raises(SystemExit) as exc:
        cli._rules_remove(console, tmp_path, "missing")

    assert exc.value.code == 1
