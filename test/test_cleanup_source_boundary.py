"""The lowest cleanup file boundary rejects paths before opening source."""

from pathlib import Path

import pytest

from skylos.cleanup_execution import _read_source, _replace_unchanged


@pytest.mark.parametrize("file", ["../outside.py", "nested/../../outside.py"])
def test_cleanup_reader_rejects_parent_traversal(tmp_path, file):
    project = tmp_path / "project"
    (project / "nested").mkdir(parents=True)
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside = True\n")

    with pytest.raises(ValueError, match="inside the project"):
        _read_source(project, Path(file))

    assert outside.read_bytes() == b"outside = True\n"


def test_cleanup_reader_rejects_absolute_outside_path(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"outside = True\n")

    with pytest.raises(ValueError):
        _read_source(project, outside)


def test_cleanup_writer_rejects_parent_traversal_without_touching_source(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.py"
    original = b"outside = True\n"
    outside.write_bytes(original)

    with pytest.raises(ValueError, match="inside the project"):
        _replace_unchanged(project, Path("../outside.py"), original, b"changed\n")

    assert outside.read_bytes() == original
    assert not list(tmp_path.rglob(".skylos-cleanup-*.tmp"))


@pytest.mark.parametrize("absolute", [False, True])
def test_cleanup_boundary_allows_regular_in_project_source(tmp_path, absolute):
    project = tmp_path / "project"
    source = project / "nested" / "app.py"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"answer = 42\n")
    requested = source if absolute else source.relative_to(project)

    assert _read_source(project, requested) == b"answer = 42\n"
    _replace_unchanged(project, requested, b"answer = 42\n", b"answer = 43\n")
    assert source.read_bytes() == b"answer = 43\n"


@pytest.mark.parametrize("link_kind", ["root", "ancestor", "leaf"])
def test_cleanup_boundary_refuses_symlinks_without_reading_or_writing_target(
    tmp_path, link_kind
):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    source = outside / "app.py"
    original = b"outside = True\n"
    source.write_bytes(original)
    if link_kind == "root":
        link = tmp_path / "linked-project"
        link.symlink_to(outside, target_is_directory=True)
        root, requested = link, Path("app.py")
    elif link_kind == "ancestor":
        (project / "linked").symlink_to(outside, target_is_directory=True)
        root, requested = project, Path("linked/app.py")
    else:
        (project / "app.py").symlink_to(source)
        root, requested = project, Path("app.py")

    with pytest.raises((ValueError, OSError)):
        _read_source(root, requested)
    with pytest.raises((ValueError, OSError)):
        _replace_unchanged(root, requested, original, b"changed\n")

    assert source.read_bytes() == original
    assert not list(tmp_path.rglob(".skylos-cleanup-*.tmp"))


def test_cleanup_boundary_refuses_hardlinked_source(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside.py"
    original = b"outside = True\n"
    outside.write_bytes(original)
    (project / "app.py").hardlink_to(outside)

    with pytest.raises(ValueError, match="one link"):
        _read_source(project, Path("app.py"))
    with pytest.raises(ValueError, match="one link"):
        _replace_unchanged(project, Path("app.py"), original, b"changed\n")

    assert outside.read_bytes() == original
