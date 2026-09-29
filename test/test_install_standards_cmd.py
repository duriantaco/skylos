import json
import sys
from pathlib import Path

import pytest

import skylos.cli as cli
from skylos.commands import install_standards_cmd as standards
from skylos.commands.agent_standards_policy import load_agent_standards_policy
from skylos.core.safe_cache_io import write_text_no_symlink


def _run(project: Path, *flags: str, path: Path | None = None):
    args = cli._build_agent_parser().parse_args(
        ["install-standards", "--path", str(path or project), *flags]
    )
    printed = []
    code = standards.run_install_standards_command(args, print_func=printed.append)
    return code, printed


def _source(project: Path, content: str = "# Style\n\nUse clear names.\n") -> Path:
    source = project / ".skylos" / "standards.md"
    source.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(source, content)
    return source


def test_install_standards_from_nested_directory_and_rerun_without_writes(
    tmp_path, monkeypatch
):
    (tmp_path / ".git").mkdir()
    source = _source(tmp_path)
    nested = tmp_path / "src" / "nested"
    nested.mkdir(parents=True)

    code, _ = _run(
        tmp_path,
        "--enforce",
        "SKY-Q301",
        "SKY-C304",
        "--enforce",
        "SKY-Q301",
        path=nested,
    )
    assert code == 0
    policy = json.loads((tmp_path / standards.POLICY_RELATIVE_PATH).read_text())
    assert policy == {
        "schema_version": 1,
        "standards_file": ".skylos/standards.md",
        "enforce_rule_ids": ["SKY-C304", "SKY-Q301"],
    }
    for relative in standards.SKILL_RELATIVE_PATHS:
        skill = (tmp_path / relative).read_text()
        assert skill.startswith("---\nname: skylos-project-standards\n")
        assert "coding standards" in skill
        assert ".skylos/agent-standards.json" in skill
        assert source.read_text() not in skill

    monkeypatch.setattr(
        standards,
        "write_text_no_symlink",
        lambda *_args, **_kwargs: pytest.fail("idempotent install wrote a file"),
    )
    code, printed = _run(
        tmp_path,
        "--enforce",
        "SKY-Q301",
        "SKY-C304",
        path=nested,
    )
    assert code == 0
    assert "no change" in printed[-1]


def test_install_standards_in_non_git_project_with_custom_source(tmp_path):
    source = tmp_path / "docs" / "coding-style.md"
    source.parent.mkdir()
    source.write_text("# Coding style\n\nPrefer small functions.\n")

    code, _ = _run(tmp_path, "--standards", "docs/coding-style.md")
    assert code == 0
    policy = json.loads((tmp_path / standards.POLICY_RELATIVE_PATH).read_text())
    assert policy["standards_file"] == "docs/coding-style.md"
    assert policy["enforce_rule_ids"] == []


def test_install_standards_with_spaces_in_project_and_source_paths(tmp_path):
    project = tmp_path / "project with spaces"
    project.mkdir()
    source = project / "style guides" / "team rules.md"
    source.parent.mkdir()
    source.write_text("# Team rules\n\nPrefer clear names.\n")

    code, _ = _run(project, "--standards", "style guides/team rules.md")
    assert code == 0
    policy = json.loads((project / standards.POLICY_RELATIVE_PATH).read_text())
    assert policy["standards_file"] == "style guides/team rules.md"
    assert (
        load_agent_standards_policy(project).standards_file == policy["standards_file"]
    )


def test_install_standards_cli_dispatch(tmp_path, monkeypatch):
    _source(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "skylos",
            "agent",
            "install-standards",
            "--path",
            str(tmp_path),
            "--enforce",
            "SKY-Q301",
        ],
    )
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 0
    policy = json.loads((tmp_path / standards.POLICY_RELATIVE_PATH).read_text())
    assert policy["enforce_rule_ids"] == ["SKY-Q301"]


def test_install_standards_dry_run_does_not_write(tmp_path):
    _source(tmp_path)
    code, printed = _run(tmp_path, "--enforce", "SKY-C304", "--dry-run")
    assert code == 0
    assert "write: .agents/skills/skylos-project-standards/SKILL.md" in printed
    assert not (tmp_path / standards.POLICY_RELATIVE_PATH).exists()
    assert not (tmp_path / standards.SKILL_RELATIVE_PATHS[0]).exists()


@pytest.mark.parametrize("rule_id", ["SKY-D201", "SKY-NOT-A-RULE", "sky-c304"])
def test_install_standards_rejects_non_quality_or_unknown_rules(tmp_path, rule_id):
    _source(tmp_path)
    code, printed = _run(tmp_path, "--enforce", rule_id)
    assert code == 2
    assert "quality rule IDs only" in printed[0]
    assert not (tmp_path / standards.POLICY_RELATIVE_PATH).exists()
    assert not (tmp_path / standards.SKILL_RELATIVE_PATHS[0]).exists()


@pytest.mark.parametrize("content", ["", " \n", "x" * (256 * 1024 + 1)])
def test_install_standards_rejects_empty_or_oversize_source(tmp_path, content):
    _source(tmp_path, content)
    code, _ = _run(tmp_path)
    assert code == 2
    assert not (tmp_path / standards.POLICY_RELATIVE_PATH).exists()


def test_install_standards_rejects_out_of_project_and_symlink_source(tmp_path):
    outside = tmp_path.parent / "outside-standards.md"
    outside.write_text("# Outside\n")
    code, _ = _run(tmp_path, "--standards", str(outside))
    assert code == 2

    source = tmp_path / ".skylos" / "standards.md"
    source.parent.mkdir()
    source.symlink_to(outside)
    code, _ = _run(tmp_path)
    assert code == 2
    assert not (tmp_path / standards.POLICY_RELATIVE_PATH).exists()


def test_install_standards_rejects_symlink_source_parent(tmp_path):
    source_dir = tmp_path / "source-files"
    source_dir.mkdir()
    (source_dir / "standards.md").write_text("# Style\n")
    (tmp_path / ".skylos").symlink_to(source_dir, target_is_directory=True)

    code, _ = _run(tmp_path)
    assert code == 2
    assert not (source_dir / "agent-standards.json").exists()


def test_install_standards_rejects_backslash_in_source_path(tmp_path):
    (tmp_path / "style\\guide.md").write_text("# Style\n")
    code, _ = _run(tmp_path, "--standards", "style\\guide.md")
    assert code == 2
    assert not (tmp_path / standards.POLICY_RELATIVE_PATH).exists()


def test_install_standards_rejects_symlink_output_parent_without_writing(tmp_path):
    _source(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / ".agents").symlink_to(outside, target_is_directory=True)

    code, printed = _run(tmp_path)
    assert code == 1
    assert "parent is a symlink" in printed[0]
    assert list(outside.iterdir()) == []
    assert not (tmp_path / standards.POLICY_RELATIVE_PATH).exists()


def test_install_standards_rejects_existing_user_skill_and_symlink_target(tmp_path):
    _source(tmp_path)
    skill = tmp_path / standards.SKILL_RELATIVE_PATHS[1]
    skill.parent.mkdir(parents=True)
    skill.write_text("User instructions\n")
    code, printed = _run(tmp_path)
    assert code == 1
    assert "user changes" in printed[0]
    assert skill.read_text() == "User instructions\n"
    assert not (tmp_path / standards.POLICY_RELATIVE_PATH).exists()
    assert not (tmp_path / standards.SKILL_RELATIVE_PATHS[0]).exists()

    skill.unlink()
    skill.symlink_to(tmp_path / ".skylos" / "standards.md")
    code, printed = _run(tmp_path)
    assert code == 1
    assert "target is a symlink" in printed[0]


def test_install_standards_rejects_invalid_existing_policy_before_writes(tmp_path):
    _source(tmp_path)
    policy = tmp_path / standards.POLICY_RELATIVE_PATH
    policy.write_text("{broken")
    code, printed = _run(tmp_path)
    assert code == 1
    assert "invalid JSON" in printed[0]
    assert policy.read_text() == "{broken"
    assert not (tmp_path / standards.SKILL_RELATIVE_PATHS[0]).exists()


def test_install_standards_updates_managed_policy_and_preserves_skill_edits(tmp_path):
    _source(tmp_path)
    assert _run(tmp_path)[0] == 0
    assert _run(tmp_path, "--enforce", "SKY-C304")[0] == 0
    policy = json.loads((tmp_path / standards.POLICY_RELATIVE_PATH).read_text())
    assert policy["enforce_rule_ids"] == ["SKY-C304"]

    skill = tmp_path / standards.SKILL_RELATIVE_PATHS[0]
    skill.write_text(skill.read_text() + "\nMy local note.\n")
    code, printed = _run(tmp_path, "--enforce", "SKY-C304")
    assert code == 1
    assert "user changes" in printed[0]
    assert skill.read_text().endswith("My local note.\n")
