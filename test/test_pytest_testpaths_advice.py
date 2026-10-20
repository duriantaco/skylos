"""Configured collection must respect root discovery selections in testpaths."""

import ast
import json
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.advice_scope import advice_source_context
from skylos.rules.quality._pytest_collection import is_collected_pytest_file
from skylos.rules.quality._typing import is_typing_test_path
from skylos.rules.quality.class_size import GodClassRule, GodFileRule
from skylos.rules.quality.practices import TypeAnnotationPracticeRule


SOURCE = """def test_connection(value, enabled: bool) -> str:
    return str(value)

class TestCases:
    def test_a(self): return self.value
    def test_b(self): return self.value + 1
    def test_c(self): return self.value * 2
"""


def _write(root, relative, source):
    root = root.resolve()
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("fixture path leaves root")
    path = root / relative
    path.resolve().relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _config(root, testpaths, *, legacy=False, norecursedirs=None):
    table = "[tool.pytest.ini_options]" if legacy else "[tool.pytest]"
    excludes = (
        "" if norecursedirs is None
        else f"norecursedirs = {json.dumps(norecursedirs)}\n"
    )
    return _write(
        root, "pyproject.toml",
        f'{table}\npython_files = ["*.py"]\ntestpaths = {json.dumps(testpaths)}\n'
        + excludes
        + '\n[tool.mypy]\nfiles = ["app"]\ndisallow_untyped_defs = true\n',
    )


@pytest.mark.parametrize("legacy", [False, True])
def test_broad_file_pattern_does_not_relabel_production_outside_testpaths(tmp_path, legacy):
    _config(tmp_path, ["tests"], legacy=legacy)
    _write(tmp_path, "tests/test_app.py", "def test_app():\n    assert True\n")
    path = _write(tmp_path, "app/health.py", SOURCE)
    assert not is_collected_pytest_file(path, tmp_path)
    assert not is_collected_pytest_file(path, tmp_path, SOURCE)
    assert not is_typing_test_path(path, tmp_path, source=SOURCE)
    assert advice_source_context({"rule_id": "SKY-Q301", "file": str(path)}, tmp_path) is None
    context = {"filename": str(path), "source": SOURCE, "project_root": tmp_path}
    findings = TypeAnnotationPracticeRule().visit_node(ast.parse(SOURCE), context)
    assert any(row["rule_id"] == "SKY-T101" for row in findings)
    # These methods contain behavior: declaration-only stubs are intentionally
    # exempt, but this production implementation must still receive advice.
    file_findings = GodFileRule(max_definitions=2).visit_node(ast.parse(SOURCE), context)
    assert len(file_findings) == 1
    assert file_findings[0]["rule_id"] == "SKY-Q502"
    assert file_findings[0]["total_definitions"] == 5
    class_rule = GodClassRule(max_methods=2)
    tree = ast.parse(SOURCE)
    class_rule.visit_node(tree, context)
    class_findings = class_rule.visit_node(tree.body[1], context)
    assert len(class_findings) == 1
    assert class_findings[0]["rule_id"] == "SKY-Q501"
    assert class_findings[0]["value"] == 3


@pytest.mark.parametrize("legacy", [False, True])
def test_production_declarations_are_exempt_without_becoming_pytest_files(
    tmp_path, legacy
):
    _config(tmp_path, ["tests"], legacy=legacy)
    source = """class TestCases:
    def test_a(self): pass
    def test_b(self): pass
    def test_c(self): pass
"""
    path = _write(tmp_path, "app/health.py", source)
    assert not is_collected_pytest_file(path, tmp_path, source)
    assert advice_source_context({"rule_id": "SKY-Q301", "file": str(path)}, tmp_path) is None
    context = {"filename": str(path), "source": source, "project_root": tmp_path}
    tree = ast.parse(source)
    # An interface made only of stubs has no implementation to split. This
    # exemption is separate from pytest collection and applies in production.
    assert not GodFileRule(max_definitions=2).visit_node(tree, context)
    class_rule = GodClassRule(max_methods=2)
    class_rule.visit_node(tree, context)
    assert not class_rule.visit_node(tree.body[0], context)


@pytest.mark.parametrize(
    "pattern,relative,expected",
    [
        ("checks", "checks/cases.py", True),
        ("checks", "checks/nested/cases.py", True),
        ("checks", "checks_extra/cases.py", False),
        ("checks/cases.py", "checks/cases.py", True),
        ("checks/cases.py", "checks/other.py", False),
        ("checks/*", "checks/nested/cases.py", True),
        ("checks/*.py", "checks/cases.py", True),
        ("checks/*.py", "checks/nested/cases.py", False),
        ("checks/ca?es.py", "checks/cases.py", True),
        ("checks/[ab]*.py", "checks/apple.py", True),
        ("checks/[ab]*.py", "checks/cases.py", False),
        ("checks/**/*.py", "checks/cases.py", True),
        ("checks/**/*.py", "checks/deep/nested/cases.py", True),
        ("**/checks", "suite/checks/nested/cases.py", True),
        ("**/checks", "suite/app/cases.py", False),
        ("**", "cases.py", True),
        ("**", ".private/cases.py", False),
        ("*", ".private/cases.py", False),
        (".private", ".private/cases.py", True),
        (".", "app/cases.py", True),
        ("./checks", "checks/cases.py", True),
    ],
)
def test_testpaths_globs_match_components_and_selected_directory_descendants(
    tmp_path, pattern, relative, expected
):
    _config(tmp_path, [pattern])
    path = _write(tmp_path, relative, SOURCE)
    assert is_collected_pytest_file(path, tmp_path) is expected
    assert is_collected_pytest_file(path, tmp_path, SOURCE) is expected


@pytest.mark.parametrize("paths", [[], ["missing", "checks"], ["unknown*", "checks"]])
def test_empty_or_additional_unmatched_patterns_do_not_hide_valid_local_selections(tmp_path, paths):
    _config(tmp_path, paths)
    path = _write(tmp_path, "checks/cases.py", SOURCE)
    assert is_collected_pytest_file(path, tmp_path)


@pytest.mark.parametrize(
    "paths",
    [
        ["missing"], ["other*"], [""], ["   "], ["../checks"],
        ["checks/../checks"], ["checks/cases.py::test_connection"],
        ["checks\\cases.py"], ["checks\u0000"], ["checks", "../outside"],
        ["checks"] * 129,
    ],
)
def test_invalid_escaping_or_unmatched_testpaths_cannot_supply_new_scope(tmp_path, paths):
    _config(tmp_path, paths)
    path = _write(tmp_path, "checks/cases.py", SOURCE)
    assert not is_collected_pytest_file(path, tmp_path)
    assert not is_collected_pytest_file(path, tmp_path, SOURCE)


def test_absolute_testpaths_must_remain_inside_root(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    path = _write(root, "checks/cases.py", SOURCE)
    _config(root, [str(root / "checks")])
    assert is_collected_pytest_file(path, root)
    _config(root, [str(tmp_path / "checks")])
    assert not is_collected_pytest_file(path, root, SOURCE)


def test_testpaths_and_source_rewrites_invalidate_scope(tmp_path):
    config = _config(tmp_path, ["checks"])
    path = _write(tmp_path, "checks/cases.py", SOURCE)
    assert is_collected_pytest_file(path, tmp_path)
    assert write_text_no_symlink(config, '[tool.pytest]\npython_files = ["*.py"]\ntestpaths = ["other"]\n')
    assert not is_collected_pytest_file(path, tmp_path)
    _config(tmp_path, ["checks"])
    assert is_collected_pytest_file(path, tmp_path)
    assert write_text_no_symlink(path, "def process():\n    return 'production'\n")
    assert not is_collected_pytest_file(path, tmp_path)


def test_symlinked_selected_directories_and_missing_sources_do_not_supply_scope(tmp_path):
    _config(tmp_path, ["alias"])
    path = _write(tmp_path, "real/cases.py", SOURCE)
    (tmp_path / "alias").symlink_to(path.parent, target_is_directory=True)
    assert not is_collected_pytest_file(tmp_path / "alias/cases.py", tmp_path, SOURCE)
    _config(tmp_path, ["checks"])
    assert not is_collected_pytest_file(tmp_path / "checks/missing.py", tmp_path, SOURCE)


def test_conventional_test_rules_remain_separate_from_configured_root_discovery(tmp_path):
    _config(tmp_path, ["checks"])
    path = _write(tmp_path, "tests/test_cases.py", SOURCE)
    assert not is_collected_pytest_file(path, tmp_path)
    assert is_typing_test_path(path, tmp_path, source=SOURCE)
    context = {"filename": str(path), "source": SOURCE, "project_root": tmp_path}
    assert not TypeAnnotationPracticeRule().visit_node(ast.parse(SOURCE), context)
    assert not GodFileRule(max_definitions=2).visit_node(ast.parse(SOURCE), context)
    rule = GodClassRule(max_methods=2)
    tree = ast.parse(SOURCE)
    rule.visit_node(tree, context)
    assert not rule.visit_node(tree.body[1], context)


@pytest.mark.parametrize("directory", [".private", "build", "dist", "venv", "node_modules", "__pycache__"])
@pytest.mark.parametrize("paths", [[], ["checks"], ["checks/*"]])
def test_selected_directories_do_not_recurse_into_default_ignored_descendants(
    tmp_path, directory, paths
):
    _config(tmp_path, paths)
    # For checks/* the explicitly selected prefix is visible/, so the
    # ignored directory is still a recursively discovered descendant.
    path = _write(tmp_path, f"checks/visible/{directory}/cases.py", SOURCE)
    assert not is_collected_pytest_file(path, tmp_path)
    assert not is_collected_pytest_file(path, tmp_path, SOURCE)


@pytest.mark.parametrize("explicit_file", [False, True])
def test_explicit_initial_selection_can_name_an_otherwise_ignored_directory(
    tmp_path, explicit_file
):
    relative = "checks/build/cases.py"
    _config(tmp_path, [relative if explicit_file else "checks/build"])
    path = _write(tmp_path, relative, SOURCE)
    assert is_collected_pytest_file(path, tmp_path)


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize(
    "patterns,relative,expected",
    [
        ([], "checks/build/cases.py", True),
        (["generated*"], "checks/generated_files/cases.py", False),
        (["generated*"], "checks/normal/cases.py", True),
        (["checks/generated"], "checks/generated/cases.py", False),
        (["generated/*"], "checks/generated/deep/cases.py", False),
        ([""], "checks/cases.py", False),
    ],
)
def test_static_norecursedirs_overrides_replace_defaults(
    tmp_path, legacy, patterns, relative, expected
):
    _config(tmp_path, ["checks"], legacy=legacy, norecursedirs=patterns)
    path = _write(tmp_path, relative, SOURCE)
    assert is_collected_pytest_file(path, tmp_path) is expected


def test_ini_norecursedirs_and_absolute_patterns_are_respected(tmp_path):
    path = _write(tmp_path, "checks/generated/cases.py", SOURCE)
    config = _write(
        tmp_path,
        "pytest.ini",
        f"[pytest]\npython_files = *.py\ntestpaths = checks\nnorecursedirs = {tmp_path / 'checks/generated'}\n",
    )
    assert not is_collected_pytest_file(path, tmp_path)
    assert write_text_no_symlink(
        config, "[pytest]\npython_files = *.py\ntestpaths = checks\nnorecursedirs = other*\n"
    )
    assert is_collected_pytest_file(path, tmp_path)


def test_malformed_native_norecursedirs_does_not_supply_scope(tmp_path):
    _config(tmp_path, ["checks"], norecursedirs="build")
    path = _write(tmp_path, "checks/cases.py", SOURCE)
    assert not is_collected_pytest_file(path, tmp_path, SOURCE)
