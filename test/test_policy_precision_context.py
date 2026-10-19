"""Configured equivalent tooling is not a missing Python policy."""

import pytest

from test.fixture_paths import write_fixture

from skylos.rules.quality.policy import analyze_repo_policy


def rules(root):
    write_fixture(root, "app.py", "def process(value): return value\n", overwrite=True)
    return {row["rule_id"] for row in analyze_repo_policy(root, {})}


@pytest.mark.parametrize("tool", ["mypy", "pyright"])
def test_empty_type_checker_table_selects_its_default_policy(tmp_path, tool):
    (tmp_path / "pyproject.toml").write_text(f"[tool.{tool}]\n")
    assert "SKY-R101" not in rules(tmp_path)


@pytest.mark.parametrize("tool", ["ruff", "flake8", "pylint"])
def test_empty_linter_table_selects_default_policy(tmp_path, tool):
    (tmp_path / "pyproject.toml").write_text(f"[tool.{tool}]\n")
    assert "SKY-R102" not in rules(tmp_path)


@pytest.mark.parametrize("filename", [".flake8", ".pylintrc", "pylintrc"])
def test_equivalent_linter_config_files_are_recognized(tmp_path, filename):
    write_fixture(tmp_path, filename,
        "[flake8]\n" if filename == ".flake8" else "[MAIN]\n"
    )
    assert "SKY-R102" not in rules(tmp_path)


@pytest.mark.parametrize("filename", ["setup.cfg", "tox.ini"])
@pytest.mark.parametrize("section", ["flake8", "pylint", "pylint.messages control"])
def test_ini_linter_sections_are_recognized(tmp_path, filename, section):
    (tmp_path / filename).write_text(f"[{section}]\nignore = W123\n")
    assert "SKY-R102" not in rules(tmp_path)


def test_formatters_alone_do_not_establish_a_lint_policy(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.black]\nline-length = 88\n")
    assert "SKY-R102" in rules(tmp_path)


def test_mypy_word_in_a_comment_is_not_a_type_checker_policy(tmp_path):
    (tmp_path / "setup.cfg").write_text(
        "[metadata]\n# We do not run mypy yet.\nname=app\n"
    )
    assert "SKY-R101" in rules(tmp_path)


def test_actual_mypy_section_is_a_type_checker_policy(tmp_path):
    (tmp_path / "setup.cfg").write_text("[mypy]\npython_version=3.11\n")
    assert "SKY-R101" not in rules(tmp_path)


def test_tool_names_in_arbitrary_ini_options_do_not_establish_lint_policy(tmp_path):
    (tmp_path / "setup.cfg").write_text(
        "[metadata]\ndescription=flake8 and pylint are not configured\n"
    )
    assert "SKY-R102" in rules(tmp_path)


def test_actual_missing_policies_remain_reported(tmp_path):
    assert {"SKY-R101", "SKY-R102", "SKY-R103", "SKY-R104"} <= rules(tmp_path)
