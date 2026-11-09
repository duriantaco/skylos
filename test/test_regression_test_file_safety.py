from __future__ import annotations

import os

import pytest

from skylos.llm import executor as module
from skylos.remediation.regression_tests import RegressionTestCandidate


requires_directory_handles = pytest.mark.skipif(
    os.name != "posix"
    or not hasattr(os, "O_DIRECTORY")
    or not hasattr(os, "O_NOFOLLOW")
    or any(
        operation not in os.supports_dir_fd
        for operation in (os.open, os.stat, os.unlink)
    ),
    reason="secure regression-file creation requires no-follow directory handles",
)


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    (root / "tests" / "nested").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    return root.resolve(), outside.resolve()


def candidate(
    path="tests/nested/test_generated.py",
    content="def test_guard():\n    assert True\n",
):
    return RegressionTestCandidate(
        rule_id="SKY-D211",
        family="sql_injection",
        source_file="app.py",
        test_file=path,
        description="Generated static regression test",
        content=content,
    )


def install_open_hook(monkeypatch, hook):
    real_open = os.open

    def intercepted(path, flags, mode=0o777, *, dir_fd=None):
        return hook(real_open, path, flags, mode, dir_fd)

    monkeypatch.setattr(module.os, "open", intercepted)
    monkeypatch.setattr(
        module.os, "supports_dir_fd", os.supports_dir_fd | {intercepted}
    )


def open_at(real_open, path, flags, mode, directory):
    if directory is None:
        return real_open(path, flags, mode)
    return real_open(path, flags, mode, dir_fd=directory)


def exclusive_create(flags):
    return flags & os.O_CREAT and flags & os.O_EXCL


@requires_directory_handles
def test_creates_a_nested_regression_test_without_replacing_existing_content(project):
    root, _ = project
    executor = module.RemediationExecutor(project_root=root)
    first = candidate()
    assert executor.write_regression_test(first)
    destination = root / first.test_file
    assert destination.read_text(encoding="utf-8") == first.content
    assert not executor.write_regression_test(candidate(content="replacement"))
    assert destination.read_text(encoding="utf-8") == first.content


@pytest.mark.parametrize(
    "path", ["../outside/test_generated.py", "tests/../../outside/test_generated.py"]
)
def test_rejects_paths_outside_the_project(project, path):
    root, outside = project
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate(path)
    )
    assert list(outside.iterdir()) == []


def test_rejects_absolute_destinations(project):
    root, outside = project
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate(str(outside / "test_generated.py"))
    )
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize("inside", [False, True])
@requires_directory_handles
def test_rejects_symlink_ancestors_even_when_the_link_stays_inside(project, inside):
    root, outside = project
    target = root / "real" if inside else outside
    (target / "nested").mkdir(parents=True)
    (root / "alias").symlink_to(target, target_is_directory=True)
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate("alias/nested/test_generated.py")
    )
    assert not (target / "nested" / "test_generated.py").exists()


@pytest.mark.parametrize("kind", ["regular", "symlink", "dangling_symlink", "hardlink"])
@requires_directory_handles
def test_rejects_existing_targets_without_modifying_them(project, kind):
    root, outside = project
    target = outside / "untouched.py"
    target.write_text("preserve", encoding="utf-8")
    destination = root / "tests" / "nested" / "test_generated.py"
    if kind == "regular":
        destination.write_text("preserve", encoding="utf-8")
    elif kind == "symlink":
        destination.symlink_to(target)
    elif kind == "dangling_symlink":
        destination.symlink_to(outside / "missing.py")
    else:
        os.link(target, destination)
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate()
    )
    assert target.read_text(encoding="utf-8") == "preserve"
    assert not (outside / "missing.py").exists()


@pytest.mark.parametrize("when", ["before_open", "after_open"])
@requires_directory_handles
def test_parent_swap_cannot_redirect_creation_or_report_success(
    project, monkeypatch, when
):
    root, outside = project
    executor = module.RemediationExecutor(project_root=root)
    parent = root / "tests" / "nested"
    retained = root / "tests" / "retained"
    changed = False

    def swap():
        nonlocal changed
        parent.rename(retained)
        parent.symlink_to(outside, target_is_directory=True)
        changed = True

    def hook(real_open, path, flags, mode, directory):
        if exclusive_create(flags):
            if when == "before_open":
                swap()
            descriptor = open_at(real_open, path, flags, mode, directory)
            if when == "after_open":
                swap()
            return descriptor
        return open_at(real_open, path, flags, mode, directory)

    install_open_hook(monkeypatch, hook)
    assert not executor.write_regression_test(candidate())
    assert changed
    assert list(outside.iterdir()) == []
    assert not (retained / "test_generated.py").exists()


@requires_directory_handles
def test_final_entry_swap_is_not_reported_as_a_successful_write(project, monkeypatch):
    root, outside = project
    target = outside / "untouched.py"
    target.write_text("preserve", encoding="utf-8")
    destination = root / "tests" / "nested" / "test_generated.py"

    def hook(real_open, path, flags, mode, directory):
        descriptor = open_at(real_open, path, flags, mode, directory)
        if exclusive_create(flags):
            destination.unlink()
            destination.symlink_to(target)
        return descriptor

    install_open_hook(monkeypatch, hook)
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate()
    )
    assert target.read_text(encoding="utf-8") == "preserve"
    assert destination.is_symlink()


@requires_directory_handles
def test_hardlink_added_during_creation_is_rejected_before_content_is_written(
    project, monkeypatch
):
    root, outside = project
    destination = root / "tests" / "nested" / "test_generated.py"
    linked = outside / "linked.py"

    def hook(real_open, path, flags, mode, directory):
        descriptor = open_at(real_open, path, flags, mode, directory)
        if exclusive_create(flags):
            os.link(destination, linked)
        return descriptor

    install_open_hook(monkeypatch, hook)
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate()
    )
    assert linked.read_bytes() == b""
    assert not destination.exists()


def test_unsupported_directory_descriptor_platform_fails_closed(project, monkeypatch):
    root, _ = project
    monkeypatch.setattr(module.os, "supports_dir_fd", set())
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate()
    )
    assert not (root / "tests" / "nested" / "test_generated.py").exists()


@requires_directory_handles
def test_encoding_failure_removes_only_the_new_file(project):
    root, _ = project
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate(content="\ud800")
    )
    assert not (root / "tests" / "nested" / "test_generated.py").exists()


@pytest.mark.parametrize("traversal", [False, True])
def test_helper_itself_enforces_project_containment(project, traversal):
    root, outside = project
    destination = (
        root / ".." / "outside" / "test_generated.py"
        if traversal
        else outside / "test_generated.py"
    )
    assert not module._write_new_text_no_symlink(
        destination, "payload", project_root=root
    )
    assert list(outside.iterdir()) == []


@requires_directory_handles
def test_helper_rejects_a_symlinked_project_root(project):
    root, outside = project
    alias = outside / "project"
    alias.symlink_to(root, target_is_directory=True)
    assert not module._write_new_text_no_symlink(
        alias / "test_generated.py", "payload", project_root=alias
    )
    assert not (root / "test_generated.py").exists()


@requires_directory_handles
def test_parent_swap_after_writing_is_detected_and_only_owned_file_is_removed(
    project, monkeypatch
):
    root, outside = project
    parent = root / "tests" / "nested"
    retained = root / "tests" / "retained"
    real_fsync = os.fsync

    def swap_after_flush(descriptor):
        real_fsync(descriptor)
        parent.rename(retained)
        parent.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(module.os, "fsync", swap_after_flush)
    assert not module.RemediationExecutor(project_root=root).write_regression_test(
        candidate()
    )
    assert list(outside.iterdir()) == []
    assert not (retained / "test_generated.py").exists()
