import io
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from skylos import cli
from skylos.commands import rules_cmd
from skylos.rules.catalog import get_rule_catalog


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


def test_rules_init_creates_valid_starter_pack(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()
    dest = Path(".skylos") / "rules" / "local.yml"

    exit_code = rules_cmd.init_rules(console, str(dest))

    assert exit_code == 0
    written = tmp_path / dest
    assert written.exists()
    assert "CUSTOM-VIBE-001" in written.read_text(encoding="utf-8")
    assert rules_cmd.validate_rules(console, str(written)) == 0


def test_rules_list_json_reports_installed_packs(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "local.yml").write_text(
        "rules:\n"
        "  - id: LOCAL-001\n"
        "    name: Local rule\n"
        "    pattern:\n"
        "      type: function\n",
        encoding="utf-8",
    )
    buffer = io.StringIO()

    exit_code = rules_cmd.list_rule_packs(
        Console(file=buffer, force_terminal=False),
        rules_dir,
        json_output=True,
    )

    assert exit_code == 0
    payload = json.loads(buffer.getvalue())
    assert payload["total_packs"] == 1
    assert payload["total_rules"] == 1
    assert payload["packs"][0]["name"] == "local"
    assert payload["packs"][0]["status"] == "ok"


def test_rules_list_json_skips_symlinked_rule_packs(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    outside = tmp_path / "outside.yml"
    outside.write_text("rules:\n  - id: OUTSIDE\n", encoding="utf-8")
    try:
        (rules_dir / "outside.yml").symlink_to(outside)
    except OSError:
        return
    buffer = io.StringIO()

    exit_code = rules_cmd.list_rule_packs(
        Console(file=buffer, force_terminal=False),
        rules_dir,
        json_output=True,
    )

    assert exit_code == 0
    payload = json.loads(buffer.getvalue())
    assert payload["total_packs"] == 0
    assert payload["total_rules"] == 0
    assert payload["packs"][0]["status"] == "skipped_symlink"


def test_rules_list_human_escapes_terminal_control_chars(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "evil\x1b[2J.yml").write_text("rules: []\n", encoding="utf-8")
    buffer = io.StringIO()

    exit_code = rules_cmd.list_rule_packs(
        Console(file=buffer, force_terminal=False),
        rules_dir,
    )

    assert exit_code == 0
    output = buffer.getvalue()
    assert "\x1b" not in output
    assert "\\x1b" in output


def test_rules_list_accepts_json_alias(tmp_path, monkeypatch):
    rules_dir = tmp_path / ".skylos" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "local.yml").write_text("rules: []\n", encoding="utf-8")
    buffer = io.StringIO()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    exit_code = rules_cmd.run_rules_command(
        ["list", "json"],
        console_factory=lambda: Console(file=buffer, force_terminal=False),
    )

    assert exit_code == 0
    payload = json.loads(buffer.getvalue())
    assert payload["source"] == "builtin"
    assert any(rule["id"] == "SKY-D226" for rule in payload["rules"])


def test_rules_list_filters_builtin_rules_by_rough_match():
    buffer = io.StringIO()

    exit_code = rules_cmd.run_rules_command(
        ["list", "cross", "json"],
        console_factory=lambda: Console(file=buffer, force_terminal=False),
    )

    assert exit_code == 0
    payload = json.loads(buffer.getvalue())
    rule_ids = {rule["id"] for rule in payload["rules"]}
    assert {"SKY-D226", "SKY-D227", "SKY-D228"}.issubset(rule_ids)
    assert "SKY-D201" not in rule_ids


def test_builtin_catalog_exposes_nextjs_security_rule_contracts():
    rules_by_id = {rule["id"]: rule for rule in get_rule_catalog()}

    assert rules_by_id["SKY-D280"] == {
        "id": "SKY-D280",
        "name": "Next.js mutating API route missing authentication",
        "category": "security",
        "severity": "HIGH",
        "source": "builtin",
        "aliases": [],
    }
    assert rules_by_id["SKY-D281"] == {
        "id": "SKY-D281",
        "name": "Next.js server action SQL injection",
        "category": "security",
        "severity": "CRITICAL",
        "source": "builtin",
        "aliases": [],
    }
    assert rules_by_id["SKY-S102"] == {
        "id": "SKY-S102",
        "name": "Client-side secret exposure",
        "category": "secrets",
        "severity": "HIGH",
        "source": "builtin",
        "aliases": [],
    }


def test_builtin_catalog_exposes_typescript_quality_signal_rules():
    rules_by_id = {rule["id"]: rule for rule in get_rule_catalog()}

    assert {
        rule_id: {
            "name": rules_by_id[rule_id]["name"],
            "category": rules_by_id[rule_id]["category"],
            "severity": rules_by_id[rule_id]["severity"],
        }
        for rule_id in (
            "SKY-T103",
            "SKY-T104",
            "SKY-T105",
            "SKY-T106",
            "SKY-Q405",
            "SKY-Q406",
            "SKY-Q407",
            "SKY-L035",
        )
    } == {
        "SKY-T103": {
            "name": "Suspicious chained type assertion",
            "category": "quality",
            "severity": "MEDIUM",
        },
        "SKY-T104": {
            "name": "TypeScript compiler suppression directive",
            "category": "quality",
            "severity": "MEDIUM",
        },
        "SKY-T105": {
            "name": "Unvalidated JSON type assertion",
            "category": "quality",
            "severity": "MEDIUM",
        },
        "SKY-T106": {
            "name": "Unsafe exported API type",
            "category": "quality",
            "severity": "MEDIUM",
        },
        "SKY-Q405": {
            "name": "Async Promise executor",
            "category": "quality",
            "severity": "HIGH",
        },
        "SKY-Q406": {
            "name": "Async Array.forEach callback",
            "category": "quality",
            "severity": "HIGH",
        },
        "SKY-Q407": {
            "name": "Discarded async Array.map result",
            "category": "quality",
            "severity": "HIGH",
        },
        "SKY-L035": {
            "name": "Blanket ESLint disable",
            "category": "quality",
            "severity": "HIGH",
        },
    }


def test_builtin_catalog_exposes_python_mutable_alias_rule():
    rules_by_id = {rule["id"]: rule for rule in get_rule_catalog()}

    assert rules_by_id["SKY-L034"] == {
        "id": "SKY-L034",
        "name": "Repeated mutable alias",
        "category": "quality",
        "severity": "MEDIUM",
        "source": "builtin",
        "aliases": [],
    }


def test_rules_list_packs_json_keeps_community_pack_listing(tmp_path, monkeypatch):
    rules_dir = tmp_path / ".skylos" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "local.yml").write_text("rules: []\n", encoding="utf-8")
    buffer = io.StringIO()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    exit_code = rules_cmd.run_rules_command(
        ["list", "--packs", "--json"],
        console_factory=lambda: Console(file=buffer, force_terminal=False),
    )

    assert exit_code == 0
    payload = json.loads(buffer.getvalue())
    assert payload["total_packs"] == 1


def test_rules_init_refuses_to_overwrite_without_force(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()
    dest = tmp_path / "local.yml"
    dest.write_text("rules: []\n", encoding="utf-8")

    exit_code = rules_cmd.init_rules(console, str(dest))

    assert exit_code == 1
    assert dest.read_text(encoding="utf-8") == "rules: []\n"


def test_rules_init_rejects_paths_outside_project(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    console = Mock()

    exit_code = rules_cmd.init_rules(console, "../outside.yml")

    assert exit_code == 1
    assert not (tmp_path.parent / "outside.yml").exists()
    console.print.assert_called_once()


def test_cli_rules_remove_legacy_wrapper_raises_on_missing_pack(tmp_path):
    console = Mock()

    with pytest.raises(SystemExit) as exc:
        cli._rules_remove(console, tmp_path, "missing")

    assert exc.value.code == 1
