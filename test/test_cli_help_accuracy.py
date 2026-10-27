import re
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest
from rich.console import Console

import skylos.cloud.sync as syncmod
from skylos import cli
from skylos.cli_core.dispatch import run_early_command_help
from skylos.cli_core.main_parser import build_main_parser
from skylos.commands import install_hooks_cmd
from skylos.commands.cicd_cmd import run_cicd_command
from skylos.commands.doctor_cmd import run_doctor_command
from skylos.commands.hook_cmd import EVENTS
from skylos.constants import SUPPORTED_LANGUAGES, SUPPORTED_LANGUAGES_TEXT
from skylos.ui.help import COMMANDS
from skylos.ui.tour import STEPS

REPO = Path(__file__).resolve().parents[1]

LANGUAGE_PACKAGES = {
    "TypeScript/JavaScript": "typescript",
    "Java": "java",
    "Go": "go",
    "PHP": "php",
    "Rust": "rust",
    "Dart": "dart",
    "C#": "csharp",
    "Kotlin": "kotlin",
    "C++": "cpp",
    "Shell": "shell",
}


def _flat(text):
    return " ".join(text.split())


def _registry_help(command):
    console = Console(record=True, width=400)
    assert run_early_command_help(command, console_factory=lambda: console) == 0
    return console.export_text()


def _cli_help(monkeypatch, capsys, argv):
    monkeypatch.setattr(sys, "argv", ["skylos", *argv])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    return capsys.readouterr().out


def test_hook_help_lists_every_event_and_recheck():
    output = _registry_help("hook")

    for event in EVENTS:
        assert event in output
    assert "skylos hook recheck FILE..." in output
    assert "post-edit|pre-read|pre-bash|stop" not in output


def test_installer_writes_only_known_events_and_every_event():
    installed = {
        name
        for specs in (
            install_hooks_cmd.CLAUDE_HOOKS,
            install_hooks_cmd.CODEX_HOOKS,
            install_hooks_cmd.CURSOR_HOOKS,
        )
        for _event, _matcher, name, _timeout in specs
    }

    assert installed == set(EVENTS)


def test_agent_hooks_doc_matches_installer():
    doc = (REPO / "docs" / "agent-hooks.md").read_text(encoding="utf-8")
    flat = _flat(doc)

    for event in EVENTS:
        assert f"| `{event}` |" in doc
    assert f"{install_hooks_cmd.STOP_TIMEOUT_SECONDS:,} s (`stop`)" in flat
    assert "180 s (`stop`)" not in flat
    assert (
        f"the installer sets it to {install_hooks_cmd.CURSOR_STOP_LOOP_LIMIT}." in flat
    )


def test_sbom_help_matches_its_options_and_exit_codes(monkeypatch, capsys):
    output = _flat(_cli_help(monkeypatch, capsys, ["sbom", "--help"]))

    assert "spdx-json" in output
    assert "--license-lookup" in output
    assert "--strict" in output
    assert (
        "Exit codes: 0 the SBOM was written, also when the inventory is incomplete"
        in output
    )
    assert "Exit 2 on unreadable, unsupported, or incomplete inputs" not in output


def test_sbom_registry_entry_does_not_claim_exit_2_without_strict():
    entry = next(c for c in COMMANDS if c["name"].startswith("skylos sbom"))
    text = " ".join([entry["name"], entry["desc"], *entry.get("details", [])])

    assert "spdx-json" in text
    assert "--license-lookup" in text
    assert "--strict" in text
    assert "incomplete inputs; keeps partial output" not in text


@pytest.mark.parametrize(
    ("command", "required"),
    [
        ("debt", ("--min-score", "--fail-on-status", "--save-baseline")),
        ("baseline", ("--sca",)),
        ("discover", ("--json", "--exclude")),
        ("provenance", ("--with-risk", "--diff-base")),
        ("compare", ("--against", "--skylos-results", "--upload")),
        ("badge", ("--plain",)),
        ("sync", ("connect [token]", "pull", "setup [token]", "upgrade")),
        ("project", ("status", "list", "use", "create", "unlink")),
        ("cicd", ("skylos cicd agent-review", "skylos cicd risk-review")),
    ],
)
def test_family_help_shows_real_flags(monkeypatch, capsys, command, required):
    output = _cli_help(monkeypatch, capsys, [command, "--help"])

    for expected in required:
        assert expected in output


@pytest.mark.parametrize("command", ["debt", "baseline", "discover", "sbom", "badge"])
def test_family_help_has_no_side_effects(tmp_path, monkeypatch, capsys, command):
    monkeypatch.chdir(tmp_path)
    copy = Mock()
    monkeypatch.setattr("skylos.ui.clipboard.copy_to_clipboard", copy)

    _cli_help(monkeypatch, capsys, [command, "--help"])

    assert list(tmp_path.iterdir()) == []
    copy.assert_not_called()


def test_badge_help_after_a_path_prints_help_not_the_badge(monkeypatch, capsys):
    copy = Mock()
    monkeypatch.setattr("skylos.ui.clipboard.copy_to_clipboard", copy)

    output = _cli_help(monkeypatch, capsys, ["badge", ".", "--help"])

    assert "--plain" in output
    assert "img.shields.io" not in output
    copy.assert_not_called()


def test_badge_still_ignores_extra_arguments(monkeypatch, capsys):
    from skylos.commands.badge_cmd import run_badge_command

    assert run_badge_command([".", "--plain"]) == 0
    assert capsys.readouterr().out.strip().startswith("[![")


@pytest.mark.parametrize(
    ("entry", "argv", "handler"),
    [
        ("main", ["connect", "--help"], "cmd_connect"),
        ("main", ["setup", "-h"], "cmd_setup"),
        ("project_main", ["use", "--help"], "cmd_project_use"),
        ("project_main", ["--help"], "cmd_project_status"),
    ],
)
def test_sync_and_project_help_never_run_a_subcommand(
    monkeypatch, capsys, entry, argv, handler
):
    monkeypatch.setattr(syncmod, handler, Mock(side_effect=AssertionError(handler)))

    getattr(syncmod, entry)(argv)

    assert "Usage: skylos" in capsys.readouterr().out


def test_sync_pull_help_is_still_its_own_argparse_help(capsys):
    with pytest.raises(SystemExit) as exc:
        syncmod.main(["pull", "--help"])

    assert exc.value.code == 0
    assert "--dry-run" in capsys.readouterr().out


def test_cicd_family_help_lists_every_subcommand(capsys):
    assert (
        run_cicd_command(
            [],
            console_factory=Console,
            load_config_func=Mock(),
            run_gate_interaction_func=Mock(),
            emit_github_annotations_func=Mock(),
        )
        == 0
    )
    choices = re.search(r"\{([a-z,-]+)\}", capsys.readouterr().out).group(1)
    documented = {
        parts[2]
        for item in COMMANDS
        if len(parts := item["name"].split()) >= 3 and parts[:2] == ["skylos", "cicd"]
    }

    assert set(choices.split(",")) <= documented


def test_scan_help_says_concise_exits_1_on_findings():
    help_text = _flat(build_main_parser(version="0").format_help())

    assert "'concise' exits 1 when it lists findings" in help_text
    assert "--force exits 0" in help_text
    assert "Exit codes:" in help_text


@pytest.mark.parametrize(
    "argv",
    [
        ["--format", "text", "--help"],
        ["--format", "json", "-h"],
        ["--help"],
    ],
)
def test_doctor_help_after_format_prints_help(capsys, argv):
    with pytest.raises(SystemExit) as exc:
        run_doctor_command(argv)

    assert exc.value.code == 0
    assert "--format {text,json}" in capsys.readouterr().out


def test_tour_does_not_claim_cicd_review_posts_llm_fixes():
    cicd_step = next(step for step in STEPS if "skylos cicd review" in step["body"])

    assert "LLM-generated" not in cicd_step["body"]
    assert "Post Skylos findings as inline PR comments" in cicd_step["body"]


def test_supported_languages_match_the_language_analyzers():
    packages = {
        path.name
        for path in (REPO / "skylos" / "visitors" / "languages").iterdir()
        if path.is_dir() and (path / "__init__.py").exists()
    }

    assert SUPPORTED_LANGUAGES[0] == "Python"
    assert set(SUPPORTED_LANGUAGES[1:]) == set(LANGUAGE_PACKAGES)
    assert set(LANGUAGE_PACKAGES.values()) == packages


@pytest.mark.parametrize(
    ("readme", "heading"),
    [
        ("README.md", "## Language Support"),
        ("docs/i18n/README.de.md", "## Sprachunterstützung"),
        ("docs/i18n/README.zh-CN.md", "## 语言支持"),
    ],
)
def test_readme_language_tables_list_the_supported_languages(readme, heading):
    text = (REPO / readme).read_text(encoding="utf-8")
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    rows = [
        line.split("|")[1].strip().replace(" / ", "/")
        for line in section.splitlines()
        if line.startswith("| ") and not line.startswith("|:")
    ]

    assert rows[1:] == list(SUPPORTED_LANGUAGES)


def test_tour_and_scan_help_use_the_supported_language_list():
    welcome = STEPS[0]["body"]
    description = build_main_parser(version="0").description

    assert SUPPORTED_LANGUAGES_TEXT in welcome
    assert SUPPORTED_LANGUAGES_TEXT in description
