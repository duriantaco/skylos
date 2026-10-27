"""Project rule packs in .skylos/rules/: scaffolded by `skylos rules init`, applied by scans."""

from __future__ import annotations

import json
import os
import subprocess
import textwrap
from pathlib import Path

import pytest
from rich.console import Console

from skylos.analyzer import analyze
from skylos.commands.rules_cmd import run_rules_command
from skylos.config import POLICY_BASE_ENV_VAR
from skylos.rules import project_rules
from skylos.rules.project_rules import (
    load_project_rules,
    project_rule_warnings,
)

APP = """
from flask import Flask
from auth import login_required

app = Flask(__name__)


@app.route("/open")
def open_route():
    return "open"


@app.route("/admin")
@login_required
def protected_route():
    return "admin"
"""

ROUTE_RULE = """
rules:
  - id: CUSTOM-ROUTE-AUTH
    name: Route missing auth decorator
    severity: {severity}
    category: security
    message: Route handler has no auth decorator.
    pattern:
      type: function
      decorators:
        has_any:
          - {trigger}
        must_also_have_any:
          - login_required
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv(POLICY_BASE_ENV_VAR, raising=False)
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    root = tmp_path / "proj"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "t")
    _git(root, "config", "commit.gpgsign", "false")
    _write(root / "app.py", APP)
    _write(root / "auth.py", "def login_required(fn):\n    return fn\n")
    return root


def _custom_hits(root: Path, *, danger=False):
    result = json.loads(
        analyze(str(root), conf=0, enable_quality=True, enable_danger=danger)
    )
    hits = sorted(
        (item["rule_id"], item["name"], item["severity"])
        for item in result.get("custom_rules", [])
    )
    return hits, result


def _commit(root: Path, message: str) -> str:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)
    return _git(root, "rev-parse", "HEAD")


def test_rules_init_pack_is_applied_by_quality_scans(project, monkeypatch):
    before, _ = _custom_hits(project)
    monkeypatch.chdir(project)

    assert run_rules_command(["init"], console_factory=lambda: Console(width=200)) == 0
    after, _ = _custom_hits(project)

    assert before == []
    assert after == [("CUSTOM-VIBE-002", "open_route", "MEDIUM")]


def test_rules_init_says_where_scans_load_packs(project, monkeypatch, capsys):
    monkeypatch.chdir(project)

    run_rules_command(["init"], console_factory=lambda: Console(width=300))
    run_rules_command(
        ["init", "--path", "rules/extra.yml"],
        console_factory=lambda: Console(width=300),
    )
    out = capsys.readouterr().out

    assert "Scans with --quality or -a apply it" in out
    assert "the copy committed on the base branch applies" in out
    assert "Scans only load .yml/.yaml packs directly in a .skylos/rules/ folder" in out


def test_packs_up_to_the_repository_root_apply_and_the_nearest_wins(project):
    _write(project / "pkg/app.py", APP)
    _write(project / "pkg/auth.py", "def login_required(fn):\n    return fn\n")
    _write(
        project / ".skylos/rules/root.yml",
        ROUTE_RULE.format(severity="HIGH", trigger="route"),
    )
    _write(
        project / "pkg/.skylos/rules/pkg.yml",
        ROUTE_RULE.format(severity="LOW", trigger="route"),
    )

    hits, result = _custom_hits(project)
    by_file = sorted(
        (Path(item["file"]).parent.name, item["severity"])
        for item in result["custom_rules"]
    )

    assert hits == [
        ("CUSTOM-ROUTE-AUTH", "open_route", "HIGH"),
        ("CUSTOM-ROUTE-AUTH", "open_route", "LOW"),
    ]
    assert by_file == [("pkg", "LOW"), ("proj", "HIGH")]


def test_pr_ci_reads_packs_from_the_base_commit_only(project, monkeypatch):
    base_without_pack = _commit(project, "base")
    _write(
        project / ".skylos/rules/local.yml",
        ROUTE_RULE.format(severity="HIGH", trigger="route"),
    )

    monkeypatch.setenv(POLICY_BASE_ENV_VAR, base_without_pack)
    added_by_pr, _ = _custom_hits(project)

    monkeypatch.delenv(POLICY_BASE_ENV_VAR)
    base_with_pack = _commit(project, "add pack")
    _write(
        project / ".skylos/rules/local.yml",
        ROUTE_RULE.format(severity="LOW", trigger="never_matches"),
    )
    monkeypatch.setenv(POLICY_BASE_ENV_VAR, base_with_pack)
    weakened_by_pr, _ = _custom_hits(project)

    (project / ".skylos/rules/local.yml").unlink()
    deleted_by_pr, _ = _custom_hits(project)

    assert added_by_pr == []
    assert weakened_by_pr == [("CUSTOM-ROUTE-AUTH", "open_route", "HIGH")]
    assert deleted_by_pr == [("CUSTOM-ROUTE-AUTH", "open_route", "HIGH")]


def test_a_pack_cannot_hide_or_downgrade_a_builtin_finding(project):
    _write(
        project / "db.py",
        """
        import sqlite3
        from flask import request


        def lookup():
            name = request.args.get("name")
            conn = sqlite3.connect("app.db")
            return conn.execute(f"SELECT * FROM users WHERE name = '{name}'")
        """,
    )
    _, before = _custom_hits(project, danger=True)
    _write(
        project / ".skylos/rules/shadow.yml",
        """
        rules:
          - id: SKY-D211
            name: Shadow of the SQL injection rule
            severity: LOW
            message: not a problem
            pattern:
              type: call
              function_match:
                - nothing_calls_this
        """,
    )
    _, after = _custom_hits(project, danger=True)

    def sql_rows(result):
        return sorted(
            (item["rule_id"], item["line"], item["severity"])
            for item in result.get("danger", [])
            if item["rule_id"] == "SKY-D211"
        )

    assert sql_rows(before)
    assert sql_rows(after) == sql_rows(before)


def test_unusable_packs_are_skipped_and_named(project, tmp_path):
    rules_dir = project / ".skylos/rules"
    _write(rules_dir / "good.yml", ROUTE_RULE.format(severity="HIGH", trigger="route"))
    _write(rules_dir / "broken.yml", "rules: [unclosed\n")
    _write(rules_dir / "empty.yaml", "name: no rules key\n")
    _write(
        rules_dir / "aliases.yml",
        """
        base: &base
          id: CUSTOM-ALIAS
          name: alias
          pattern: {type: call, function_match: [eval]}
        rules:
          - *base
        """,
    )
    outside = tmp_path / "outside.yml"
    _write(outside, ROUTE_RULE.format(severity="HIGH", trigger="route"))
    os.symlink(outside, rules_dir / "linked.yml")
    (rules_dir / "huge.yml").write_text("#" * (project_rules.MAX_PACK_BYTES + 1))
    _write(rules_dir / "notes.txt", "not a pack\n")

    loaded = load_project_rules(project / "app.py")
    warnings = project_rule_warnings(project)
    named = {
        Path(line.split(" is not used")[0].removeprefix("Rule pack ")).name
        for line in warnings
    }

    assert [rule["rule_id"] for rule in loaded] == ["CUSTOM-ROUTE-AUTH"]
    assert named == {
        "broken.yml",
        "empty.yaml",
        "aliases.yml",
        "linked.yml",
        "huge.yml",
    }
    assert any("YAML aliases are not allowed" in line for line in warnings)


def test_scan_warns_about_an_unusable_pack(project, monkeypatch, capsys):
    from skylos import cli

    _write(project / ".skylos/rules/broken.yml", "rules: [unclosed\n")
    monkeypatch.chdir(project)
    monkeypatch.setattr("sys.argv", ["skylos", ".", "--quality", "--json"])

    cli.main()
    captured = capsys.readouterr()

    assert "Warning: Rule pack" in captured.err
    assert "broken.yml is not used: invalid YAML at line 2." in captured.err
    json.loads(captured.out)
