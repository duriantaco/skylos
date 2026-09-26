"""The score badge must never overwrite the clipboard in non-interactive runs."""

import io
import sys
import types

import pytest
from rich.console import Console as _RichConsole

from skylos.cli import _skylos_console_theme
from skylos.ui import clipboard
from skylos.ui.rich_report import _render_grade


def Console(file):  # noqa: N802 - themed console factory for tests
    return _RichConsole(file=file, theme=_skylos_console_theme())


class _TTY(io.StringIO):
    def isatty(self):
        return True


GRADE = {
    "overall": {"score": 90, "letter": "A"},
    "categories": {},
}


@pytest.fixture
def fake_pyperclip(monkeypatch):
    module = types.SimpleNamespace(copied=[])
    module.copy = module.copied.append
    monkeypatch.setitem(sys.modules, "pyperclip", module)
    return module


@pytest.fixture
def interactive(monkeypatch):
    for name in clipboard._CI_ENV_VARS + ("SKYLOS_NO_CLIPBOARD",):
        monkeypatch.delenv(name, raising=False)
    # pytest re-installs its own sys.stdout between fixture setup and the test
    # call, so point the guard at a fake stdout instead of patching sys itself.
    monkeypatch.setattr(clipboard, "sys", types.SimpleNamespace(stdout=_TTY()))


def test_copies_in_interactive_terminal(interactive, fake_pyperclip):
    console = Console(file=_TTY())
    _render_grade(console, GRADE)
    assert len(fake_pyperclip.copied) == 1
    assert "Copied to clipboard!" in console.file.getvalue()


def test_redirected_stdout_does_not_copy(interactive, fake_pyperclip, monkeypatch):
    monkeypatch.setattr(clipboard, "sys", types.SimpleNamespace(stdout=io.StringIO()))
    console = Console(file=io.StringIO())
    _render_grade(console, GRADE)
    assert fake_pyperclip.copied == []
    assert "Copied to clipboard" not in console.file.getvalue()


def test_non_tty_console_file_does_not_copy(interactive, fake_pyperclip):
    console = Console(file=io.StringIO())
    _render_grade(console, GRADE)
    assert fake_pyperclip.copied == []


@pytest.mark.parametrize("var", ["CI", "GITHUB_ACTIONS", "GITLAB_CI"])
def test_ci_does_not_copy(interactive, fake_pyperclip, monkeypatch, var):
    monkeypatch.setenv(var, "true")
    _render_grade(Console(file=_TTY()), GRADE)
    assert fake_pyperclip.copied == []


def test_ci_false_value_is_not_treated_as_ci(interactive, fake_pyperclip, monkeypatch):
    monkeypatch.setenv("CI", "false")
    _render_grade(Console(file=_TTY()), GRADE)
    assert len(fake_pyperclip.copied) == 1


def test_env_opt_out(interactive, fake_pyperclip, monkeypatch):
    monkeypatch.setenv("SKYLOS_NO_CLIPBOARD", "1")
    _render_grade(Console(file=_TTY()), GRADE)
    assert fake_pyperclip.copied == []


def test_copy_badge_false_does_not_copy(interactive, fake_pyperclip):
    _render_grade(Console(file=_TTY()), GRADE, copy_badge=False)
    assert fake_pyperclip.copied == []


def test_no_clipboard_flag_reaches_render(monkeypatch, tmp_path):
    import json
    from unittest.mock import patch

    import skylos.cli as cli

    (tmp_path / "a.py").write_text("x = 1\n")
    monkeypatch.setattr(
        cli.sys, "argv", ["skylos", str(tmp_path), "--no-clipboard", "--no-provenance"]
    )
    result = {"analysis_summary": {"total_files": 1}, "unused_functions": []}
    with (
        patch("skylos.cli.run_analyze", return_value=json.dumps(result)),
        patch("skylos.cli.load_config", return_value={}),
        patch("skylos.cli.render_results") as render,
        patch("skylos.cli.print_badge"),
    ):
        try:
            cli.main()
        except SystemExit:
            pass
    assert render.call_args.kwargs["copy_badge"] is False
