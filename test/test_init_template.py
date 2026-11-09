"""`skylos init` writes only settings that Skylos reads."""

from __future__ import annotations

from skylos.commands.init_cmd import run_init_command
from skylos.config import load_config
from skylos.core.gatekeeper import gate_config_notes

try:
    import tomllib
except ImportError:
    import tomli as tomllib

INERT_KEYS = ("model", "templates")


def test_init_writes_no_inert_or_unrelaxable_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()

    run_init_command()
    text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")
    written = tomllib.loads(text)["tool"]["skylos"]

    for key in INERT_KEYS:
        assert key not in written
    assert "fail_on_critical" not in written["gate"]
    assert "max_critical" not in written["gate"]
    assert "max_secrets" not in written["gate"]
    assert "gpt-4.1" not in text
    assert "[tool.skylos.templates]" not in text
    assert "Any critical security issue and any secret always fail the gate." in text
    assert gate_config_notes(load_config(tmp_path)) == []


def test_init_whitelist_example_uses_a_quoted_date(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    run_init_command()
    text = (tmp_path / "pyproject.toml").read_text(encoding="utf-8")

    assert '# "legacy_*" = { reason = "migration", expires = "2026-12-31" }' in text
