"""Temporary whitelist entries hide findings only until a readable expiry date."""

from __future__ import annotations

import datetime
import json
import textwrap

import pytest

from skylos.analyzer import analyze
from skylos.config import (
    get_expired_whitelists,
    get_invalid_whitelist_expiries,
    is_whitelisted,
    load_config,
    temporary_whitelist_state,
    whitelist_warnings,
)

PYPROJECT = """
[tool.skylos.whitelist.temporary]
"expired_*" = { reason = "migration", expires = "2020-01-01" }
"vague_*" = { reason = "later", expires = "someday" }
"number_*" = { reason = "typo", expires = 30 }
"empty_*" = { reason = "blank", expires = "" }
"tomldate_*" = { reason = "toml date", expires = 2020-01-01 }
"future_*" = { reason = "still valid", expires = "2099-01-01" }
"futuredate_*" = { reason = "still valid toml date", expires = 2099-01-01 }
"forever_*" = { reason = "no expiry" }
"""

MODULE = (
    "\n\n".join(
        f"def {name}_helper():\n    return {index}"
        for index, name in enumerate(
            [
                "expired",
                "vague",
                "number",
                "empty",
                "tomldate",
                "future",
                "futuredate",
                "forever",
                "plain",
            ]
        )
    )
    + "\n"
)


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "pyproject.toml").write_text(textwrap.dedent(PYPROJECT), encoding="utf-8")
    (root / "mod.py").write_text(MODULE, encoding="utf-8")
    return root


def test_toml_dates_are_read_as_dates(project):
    config = load_config(project)
    temporary = config["whitelist_temporary"]

    assert temporary["tomldate_*"]["expires"] == "2020-01-01"
    assert temporary["futuredate_*"]["expires"] == "2099-01-01"
    assert temporary["number_*"]["expires"] == "30"
    assert "expires" not in temporary["forever_*"]


def test_expired_and_unreadable_entries_hide_nothing(project):
    result = json.loads(analyze(str(project), conf=0))
    reported = sorted(
        item["simple_name"] for item in result.get("unused_functions", [])
    )
    hidden = sorted(item["name"] for item in result.get("whitelisted", []))

    assert reported == [
        "empty_helper",
        "expired_helper",
        "number_helper",
        "plain_helper",
        "tomldate_helper",
        "vague_helper",
    ]
    assert hidden == ["forever_helper", "future_helper", "futuredate_helper"]


def test_state_and_lists_name_each_entry(project):
    config = load_config(project)
    today = datetime.date(2026, 10, 27)
    temporary = config["whitelist_temporary"]

    assert temporary_whitelist_state(temporary["future_*"], today) == "active"
    assert temporary_whitelist_state(temporary["forever_*"], today) == "active"
    assert temporary_whitelist_state(temporary["expired_*"], today) == "expired"
    assert temporary_whitelist_state(temporary["vague_*"], today) == "invalid"
    assert temporary_whitelist_state({"expires": "2026-10-27"}, today) == "active"
    assert temporary_whitelist_state({"expires": "2026-10-26"}, today) == "expired"
    assert sorted(entry[0] for entry in get_expired_whitelists(config)) == [
        "expired_*",
        "tomldate_*",
    ]
    assert sorted(entry[0] for entry in get_invalid_whitelist_expiries(config)) == [
        "empty_*",
        "number_*",
        "vague_*",
    ]
    ok, reason, _ = is_whitelisted("future_helper", None, config)
    assert ok and reason == "still valid (expires: 2099-01-01)"
    assert is_whitelisted("vague_helper", None, config)[0] is False


def test_warnings_explain_what_to_change(project):
    warnings = whitelist_warnings(load_config(project))

    assert (
        "Temporary whitelist entry 'expired_*' expired on 2020-01-01; its findings "
        "are reported again. Renew or remove it under "
        "[tool.skylos.whitelist.temporary]."
    ) in warnings
    assert (
        "Temporary whitelist entry 'vague_*' has an unreadable expires value "
        "'someday', so it hides nothing. Use a date such as "
        'expires = "2026-12-31".'
    ) in warnings
    assert len(warnings) == 5
    assert not any("future" in line or "forever" in line for line in warnings)


def test_warning_text_cannot_carry_terminal_control_characters():
    config = {"whitelist_temporary": {"evil\x1b[2J_*": {"expires": "2000-01-01\x07"}}}

    (warning,) = whitelist_warnings(config)

    assert "\x1b" not in warning and "\x07" not in warning
    assert "evil\\x1b[2J_*" in warning


def test_scan_prints_warnings_on_stderr_and_keeps_json_clean(
    project, monkeypatch, capsys
):
    from skylos import cli

    monkeypatch.chdir(project)
    monkeypatch.setattr("sys.argv", ["skylos", ".", "--json"])

    cli.main()
    captured = capsys.readouterr()

    assert captured.err.count("Warning: Temporary whitelist entry") == 5
    assert "'expired_*' expired on 2020-01-01" in captured.err
    report = json.loads(captured.out)
    assert any(
        item["simple_name"] == "expired_helper" for item in report["unused_functions"]
    )
