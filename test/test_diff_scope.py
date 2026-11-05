"""Changed mandatory scope survives automatic discovery exclusions safely."""

from dataclasses import replace
import subprocess

import pytest

from skylos.config import ConfigError
from skylos.core import diff_scope
from skylos.core.diff_scope import changed_source_files
from skylos.core.git_context import GitContext


def _write(root, relative):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("value = 1\n", encoding="utf-8")
    return path


def _select(root, files, *, scan_paths=None, excludes=()):
    return changed_source_files(
        scan_paths if scan_paths is not None else root,
        root,
        changed_files=files,
        explicit_exclude_folders=excludes,
        diff_base=None,
    )


def _git(root, *args):
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Skylos Tests",
            "-c",
            "user.email=test@example.invalid",
            *args,
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def test_only_named_changes_are_included_under_default_excluded_folders(tmp_path):
    root = tmp_path.resolve()
    ordinary = _write(root, "src/app.py")
    root_vendor = _write(root, "vendor/changed.py")
    nested_vendor = _write(root, "src/vendor/changed.py")
    node_module = _write(root, "node_modules/changed.mjs")
    _write(root, "vendor/unchanged.py")
    _write(root, "node_modules/unchanged.js")

    assert _select(root, [ordinary, root_vendor, nested_vendor, node_module]) == sorted(
        [ordinary, root_vendor, nested_vendor, node_module]
    )


@pytest.mark.parametrize(
    "suffix", [".pyi", ".pyw", ".mjs", ".cjs", ".mts", ".cts", ".sh", ".kts"]
)
def test_changed_scope_uses_all_supported_source_suffixes(tmp_path, suffix):
    root = tmp_path.resolve()
    source = _write(root, "vendor/changed" + suffix)
    assert _select(root, [source]) == [source]


@pytest.mark.parametrize("relative", ["vendor/.env", "vendor/config.yaml"])
def test_changed_scope_includes_existing_secret_config_file_types(tmp_path, relative):
    root = tmp_path.resolve()
    config = _write(root, relative)
    assert _select(root, [config]) == [config]


@pytest.mark.parametrize(
    "excludes, expected",
    [
        (["vendor"], ["src/app.py"]),
        (["src/vendor/**"], ["src/app.py", "vendor/changed.py"]),
        (["**/vendor/**"], ["src/app.py"]),
    ],
)
def test_explicit_policy_exclusions_remain_authoritative(tmp_path, excludes, expected):
    root = tmp_path.resolve()
    files = [
        _write(root, path)
        for path in ("src/app.py", "vendor/changed.py", "src/vendor/changed.py")
    ]
    assert _select(root, files, excludes=excludes) == sorted(
        root / path for path in expected
    )


def test_requested_directory_and_file_scopes_are_preserved(tmp_path):
    root = tmp_path.resolve()
    first = _write(root, "src/first.py")
    second = _write(root, "src/second.py")
    outside = _write(root, "other/changed.py")
    changes = [first, second, outside]
    assert _select(root, changes, scan_paths=root / "src") == [first, second]
    assert _select(root, changes, scan_paths=first) == [first]


def test_exclusion_ancestors_above_the_requested_scan_root_do_not_hide_changes(
    tmp_path,
):
    root = tmp_path.resolve()
    source = _write(root, "vendor/project/changed.py")
    assert _select(
        root, [source], scan_paths=root / "vendor/project", excludes=["vendor"]
    ) == [source]


def test_missing_deleted_unsupported_and_outside_paths_are_absent(tmp_path):
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    source = _write(root, "changed.py")
    outside = _write(root.parent, "outside.py")
    unsupported = _write(root, "vendor/document.txt")
    deleted = root / "deleted.py"
    assert _select(root, [source, outside, unsupported, deleted, "../outside.py"]) == [
        source
    ]


def test_file_symlinks_and_parent_directory_escapes_are_not_included(tmp_path):
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    ordinary = _write(root, "src/ordinary.py")
    outside = _write(root.parent, "outside/secret.py")
    leaf = root / "src/leaf.py"
    internal_leaf = root / "src/internal.py"
    directory = root / "src/linked"
    try:
        leaf.symlink_to(outside)
        internal_leaf.symlink_to(ordinary)
        directory.symlink_to(outside.parent, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not support symlinks")
    assert _select(root, [ordinary, leaf, internal_leaf, directory / "secret.py"]) == [
        ordinary
    ]


def test_internal_directory_link_cannot_escape_requested_subdirectory(tmp_path):
    root = tmp_path.resolve()
    inside = _write(root, "src/changed.py")
    outside_scope = _write(root, "other/changed.py")
    link = root / "src/linked"
    try:
        link.symlink_to(outside_scope.parent, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not support symlinks")
    assert _select(root, [inside, link / "changed.py"], scan_paths=root / "src") == [
        inside
    ]


def test_repository_aliases_do_not_break_containment(tmp_path):
    root = tmp_path.resolve() / "repo"
    root.mkdir()
    source = _write(root, "vendor/changed.py")
    alias = root.parent / "alias"
    try:
        alias.symlink_to(root, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not support symlinks")
    assert _select(root, [alias / "vendor/changed.py"], scan_paths=alias) == [source]


def test_empty_explicit_change_set_does_not_fall_back_to_git(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    _write(root, "vendor/unchanged.py")

    def refuse_git(*args, **kwargs):
        pytest.fail("explicit empty change sets must not ask Git for more files")

    monkeypatch.setattr(GitContext, "from_path", refuse_git)
    assert _select(root, []) == []


@pytest.fixture
def compared_repo(tmp_path, monkeypatch):
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
        monkeypatch.delenv(name, raising=False)
    root = tmp_path.resolve()
    _write(root, "main.py")
    tracked_vendor = _write(root, "vendor/tracked.py")
    _git(root, "init", "-q")
    _git(root, "add", "--", "main.py", "vendor/tracked.py")
    _git(root, "commit", "-qm", "baseline")
    _git(root, "tag", "base")
    committed = _write(root, "src/vendor/committed.py")
    committed_cr = _write(root, "src/vendor/committed\rfile.py")
    _git(root, "add", "--", "src/vendor/committed.py", "src/vendor/committed\rfile.py")
    _git(root, "commit", "-qm", "committed change")
    staged = _write(root, "vendor/staged.cts")
    staged_cr = _write(root, "vendor/staged\rfile.cts")
    _git(root, "add", "--", "vendor/staged.cts", "vendor/staged\rfile.cts")
    tracked_vendor.write_text("value = 2\n", encoding="utf-8")
    untracked = _write(root, "vendor/new name[1]\nline.mjs")
    untracked_cr = _write(root, "vendor/new name[1]\rline.mjs")
    return root, sorted(
        [
            committed,
            committed_cr,
            staged,
            staged_cr,
            tracked_vendor,
            untracked,
            untracked_cr,
        ]
    )


def test_git_comparison_collects_committed_staged_unstaged_and_literal_untracked_paths(
    compared_repo,
):
    root, expected = compared_repo
    selected = changed_source_files(
        root, root, changed_files=None, explicit_exclude_folders=[], diff_base="base"
    )
    assert selected == expected


def test_unknown_git_comparison_fails_instead_of_passing_empty(compared_repo):
    root, _ = compared_repo
    with pytest.raises(ConfigError, match="comparison base"):
        changed_source_files(
            root,
            root,
            changed_files=None,
            explicit_exclude_folders=[],
            diff_base="missing-base",
        )


def test_untracked_inventory_failure_is_not_an_empty_success(
    compared_repo, monkeypatch
):
    root, _ = compared_repo
    original = diff_scope._git_inventory

    def fail_inventory(context, *args):
        if args[:1] == ("ls-files",):
            return subprocess.CompletedProcess(
                args, 1, stdout=b"", stderr=b"unavailable"
            )
        return original(context, *args)

    monkeypatch.setattr(diff_scope, "_git_inventory", fail_inventory)
    with pytest.raises(ConfigError, match="inspect changed source"):
        changed_source_files(
            root,
            root,
            changed_files=None,
            explicit_exclude_folders=[],
            diff_base="base",
        )


def test_inventory_refuses_worktree_diff_when_filter_guards_are_unavailable(
    compared_repo, monkeypatch
):
    root, _ = compared_repo
    context = replace(GitContext.from_path(root), filter_config_overrides=None)

    def refuse_process(*args, **kwargs):
        pytest.fail("an unguarded worktree diff must not execute")

    monkeypatch.setattr(diff_scope.subprocess, "run", refuse_process)
    with pytest.raises(ConfigError, match="safely"):
        diff_scope._git_inventory(context, "diff", "--name-only", "-z", "base", "--")


def test_content_free_inventory_preserves_cr_when_filter_guards_are_unavailable(
    compared_repo,
):
    root, _ = compared_repo
    context = replace(GitContext.from_path(root), filter_config_overrides=None)
    result = diff_scope._git_inventory(
        context, "ls-files", "--others", "--exclude-standard", "-z"
    )
    assert result.returncode == 0
    assert b"vendor/new name[1]\rline.mjs" in result.stdout.split(b"\0")
