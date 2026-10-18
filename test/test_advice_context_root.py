"""Advice uses checkout-relative folders regardless of the requested scan path."""

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.advice_policy import prepare_advice_view
from skylos.reporting.advice_scope import advice_source_context


def _write(root, relative, source="def process(value):\n    return value\n"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _advice(path):
    return {"rule_id": "SKY-Q301", "file": str(path), "line": 1}


@pytest.mark.parametrize("marker", ["git-directory", "git-file", "archive"])
def test_shipped_test_package_stays_visible_from_every_scan_root(tmp_path, marker):
    if marker == "git-directory":
        (tmp_path / ".git").mkdir()
    elif marker == "git-file":
        _write(tmp_path, ".git", "gitdir: /unread/worktree-metadata\n")
    else:
        _write(tmp_path, "pyproject.toml", '[project]\nname = "widget"\n')
    path = _write(tmp_path, "widget/test/client.py")
    report = {"quality": [_advice(path)]}
    for root in (tmp_path, tmp_path / "widget", path.parent):
        assert advice_source_context(_advice(path), root) is None
        relative = path.relative_to(root)
        assert advice_source_context(_advice(relative), root) is None
        focused, visibility = prepare_advice_view(report, project_root=root)
        assert focused is report
        assert visibility.omitted_checks == 0


@pytest.mark.parametrize("relative", ["tests/helper.py", "widget/tests/helper.py"])
def test_real_test_folder_context_is_stable_for_nested_scans(tmp_path, relative):
    (tmp_path / ".git").mkdir()
    path = _write(tmp_path, relative)
    for root in (tmp_path, path.parent):
        assert advice_source_context(_advice(path), root) == "test"
        assert advice_source_context(_advice(path.relative_to(root)), root) == "test"


def test_git_root_wins_over_manifest_in_shipped_package(tmp_path):
    (tmp_path / ".git").mkdir()
    _write(tmp_path, "widget/pyproject.toml", '[project]\nname = "widget"\n')
    path = _write(tmp_path, "widget/test/client.py")
    assert advice_source_context(_advice(path), tmp_path / "widget") is None


def test_root_lookup_does_not_widen_the_explicit_scan_boundary(tmp_path):
    (tmp_path / ".git").mkdir()
    inside = _write(tmp_path, "widget/test/client.py")
    outside = _write(tmp_path, "tests/test_client.py")
    scan_root = tmp_path / "widget"
    assert advice_source_context(_advice(inside), scan_root) is None
    assert advice_source_context(_advice(outside), scan_root) is None
    assert advice_source_context(_advice("../tests/test_client.py"), scan_root) is None


def test_symlink_git_boundary_cannot_establish_context(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = _write(tmp_path, "outside/marker", "gitdir: elsewhere\n")
    (root / ".git").symlink_to(outside)
    path = _write(root, "tests/helper.py")
    assert advice_source_context(_advice(path), root) is None


def test_symlink_manifest_cannot_rebase_a_package_scan(tmp_path):
    root = tmp_path / "widget"
    root.mkdir()
    outside = _write(tmp_path, "outside/project.toml", "[project]\n")
    (root / "pyproject.toml").symlink_to(outside)
    path = _write(root, "test/client.py")
    assert advice_source_context(_advice(path), root) is None


def test_project_boundary_is_rechecked_after_marker_creation(tmp_path):
    path = _write(tmp_path, "widget/test/client.py")
    scan_root = tmp_path / "widget"
    assert advice_source_context(_advice(path), scan_root) == "test"
    (tmp_path / ".git").mkdir()
    assert advice_source_context(_advice(path), scan_root) is None


def test_clone_members_keep_the_scan_relative_path_base(tmp_path):
    (tmp_path / ".git").mkdir()
    one = _write(tmp_path, "widget/tests/one.py")
    _write(tmp_path, "widget/tests/two.py")
    row = {
        **_advice(one),
        "rule_id": "SKY-C401",
        "message": (
            "Clone group detected (type1, sim=1.0, members=2) examples: "
            "tests/one.py:1-2 (function first), tests/two.py:1-2 (function second)"
        ),
    }
    assert advice_source_context(row, tmp_path / "widget") == "test"


def test_no_source_or_target_code_is_executed_for_root_discovery(tmp_path):
    (tmp_path / ".git").mkdir()
    _write(tmp_path, "setup.py", "raise AssertionError('never execute metadata')\n")
    path = _write(tmp_path, "widget/test/client.py")
    assert advice_source_context(_advice(path), tmp_path / "widget") is None
