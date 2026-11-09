"""`skylos key` explains itself instead of crashing without a terminal."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from rich.console import Console

from skylos.commands import key_cmd


@pytest.fixture
def console(monkeypatch):
    recorder = Console(record=True, width=200)
    monkeypatch.setattr(key_cmd, "Console", lambda: recorder)
    return recorder


def _eof(_prompt=""):
    raise EOFError


def test_menu_without_a_terminal_prints_usage(monkeypatch, console):
    monkeypatch.setattr(
        key_cmd, "sys", SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: False))
    )
    monkeypatch.setattr("builtins.input", Mock(side_effect=AssertionError("no prompt")))

    assert key_cmd.run_key_command(["menu"]) == 2

    text = console.export_text()
    assert "skylos key opens an interactive menu and needs a terminal." in text
    assert "Usage: skylos key [list|add PROVIDER|remove PROVIDER]" in text


def test_menu_end_of_input_in_a_terminal_exits_quietly(monkeypatch, console):
    monkeypatch.setattr(key_cmd, "_stdin_is_terminal", lambda: True)
    monkeypatch.setattr("builtins.input", _eof)

    assert key_cmd.run_key_command([]) == 0


def test_menu_still_lists_keys_in_a_terminal(monkeypatch, console):
    monkeypatch.setattr(key_cmd, "_stdin_is_terminal", lambda: True)
    answers = iter(["1", "4"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    monkeypatch.setattr(key_cmd, "get_key", lambda provider: None)

    assert key_cmd.run_key_command([]) == 0
    assert "Skylos API Keys" in console.export_text()


def test_add_without_input_saves_nothing(monkeypatch, console):
    monkeypatch.setattr("builtins.input", _eof)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    save = Mock()
    monkeypatch.setattr(key_cmd, "save_key", save)

    assert key_cmd.run_key_command(["add", "openai"]) == 1

    save.assert_not_called()
    assert "No key received; nothing was saved." in console.export_text()


def test_add_reads_a_piped_key(monkeypatch, console):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "sk-test\n")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    save = Mock()
    monkeypatch.setattr(key_cmd, "save_key", save)

    assert key_cmd.run_key_command(["add", "openai"]) == 0

    save.assert_called_once_with("openai", "sk-test")


def test_add_without_provider_or_input_saves_nothing(monkeypatch, console):
    monkeypatch.setattr("builtins.input", _eof)
    save = Mock()
    monkeypatch.setattr(key_cmd, "save_key", save)

    assert key_cmd.run_key_command(["add"]) == 1

    save.assert_not_called()
    assert "No provider entered." in console.export_text()


def test_remove_without_an_answer_removes_nothing(monkeypatch, console):
    monkeypatch.setattr("builtins.input", _eof)
    monkeypatch.setattr(key_cmd, "get_key", lambda provider: "stored")
    delete = Mock()
    monkeypatch.setattr(key_cmd, "delete_key", delete)

    assert key_cmd.run_key_command(["remove", "openai"]) == 1

    delete.assert_not_called()
    assert "No answer received; nothing was removed." in console.export_text()


def test_remove_after_yes_still_removes(monkeypatch, console):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")
    monkeypatch.setattr(key_cmd, "get_key", lambda provider: "stored")
    delete = Mock(return_value=True)
    monkeypatch.setattr(key_cmd, "delete_key", delete)

    assert key_cmd.run_key_command(["remove", "openai"]) == 0

    delete.assert_called_once_with("openai")


def test_unknown_subcommand_prints_the_literal_usage(console):
    assert key_cmd.run_key_command(["bogus[x]"]) == 2

    text = console.export_text()
    assert "Unknown subcommand: bogus[x]" in text
    assert "Usage: skylos key [list|add PROVIDER|remove PROVIDER]" in text
