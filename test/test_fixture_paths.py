"""Fixture I/O rejects unsafe paths without changing analyzer expectations."""

import ast
import os
from pathlib import Path, PureWindowsPath

import pytest

from skylos.rules.danger.danger_fs.path_flow import scan
from test import fixture_paths
from test.fixture_paths import make_fixture_directory, write_fixture


@pytest.fixture(params=[False, True], ids=["directory-handles", "portable-fallback"])
def fixture_io(request, monkeypatch):
    if request.param:
        monkeypatch.setattr(fixture_paths.os, "supports_dir_fd", set())


def test_fixture_content_and_nested_directories_are_preserved(tmp_path, fixture_io):
    payload = b"inert provider\x00\xff\r\n"
    path = write_fixture(tmp_path, "src/provider.pyc", payload)
    assert path.read_bytes() == payload
    text = "# inert provider\nmessage = 'caf\u00e9'\n"
    source = write_fixture(tmp_path, "src/provider.py", text)
    assert source.read_text(encoding="utf-8") == text
    assert make_fixture_directory(tmp_path, "src/package").is_dir()
    assert make_fixture_directory(tmp_path) == tmp_path.resolve()


@pytest.mark.parametrize(
    "relative",
    [
        "../outside.py", "nested/../../outside.py", "/outside.py",
        "C:\\outside.py", "C:outside.py", "\\\\server\\share\\outside.py",
        "nested\\outside.py",
    ],
)
def test_invalid_fixture_paths_create_nothing(tmp_path, fixture_io, relative):
    root = make_fixture_directory(tmp_path, "project")
    before = sorted(tmp_path.rglob("*"))
    with pytest.raises(ValueError):
        write_fixture(root, relative, "must not write")
    with pytest.raises(ValueError):
        make_fixture_directory(root, relative)
    assert sorted(tmp_path.rglob("*")) == before


@pytest.mark.parametrize("operation", ["write", "directory"])
def test_windows_string_separators_are_rejected_before_path_normalization(
    tmp_path, fixture_io, monkeypatch, operation
):
    relative = "nested\\outside.py"
    real_path = fixture_paths.Path

    def parse_like_windows(value):
        # Emulate Windows separator normalization without claiming native execution.
        if isinstance(value, str) and value == relative:
            return PureWindowsPath(value)
        return real_path(value)

    monkeypatch.setattr(fixture_paths, "Path", parse_like_windows)
    with pytest.raises(ValueError):
        if operation == "write":
            write_fixture(tmp_path, relative, "must not write")
        else:
            make_fixture_directory(tmp_path, relative)
    assert not (tmp_path / "nested").exists()


def test_parsed_relative_windows_paths_preserve_fixture_layout(tmp_path, fixture_io):
    path = write_fixture(
        tmp_path, PureWindowsPath("nested", "case.py"), "inert fixture\n"
    )
    assert path == tmp_path.resolve() / "nested" / "case.py"
    assert path.read_text(encoding="utf-8") == "inert fixture\n"
    directory = make_fixture_directory(
        tmp_path, PureWindowsPath("nested", "package")
    )
    assert directory == tmp_path.resolve() / "nested" / "package"
    assert directory.is_dir()


def test_fixture_overwrite_requires_explicit_intent(tmp_path, fixture_io):
    path = write_fixture(tmp_path, "case.py", "original")
    with pytest.raises(FileExistsError):
        write_fixture(tmp_path, "case.py", "unexpected")
    assert path.read_text(encoding="utf-8") == "original"
    write_fixture(tmp_path, "case.py", "short", overwrite=True)
    assert path.read_text(encoding="utf-8") == "short"


@pytest.mark.parametrize("outside_root", [False, True])
@pytest.mark.parametrize("overwrite", [False, True])
def test_fixture_leaf_symlinks_never_change_target(
    tmp_path, fixture_io, outside_root, overwrite
):
    root = make_fixture_directory(tmp_path, "project")
    if outside_root:
        target = write_fixture(tmp_path, "outside.py", "original")
    else:
        target = write_fixture(root, "inside.py", "original")
    link = root / "link.py"
    link.symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        write_fixture(root, "link.py", "unexpected", overwrite=overwrite)
    assert target.read_text(encoding="utf-8") == "original"
    assert link.is_symlink()


@pytest.mark.parametrize("outside_root", [False, True])
def test_fixture_symlinked_parents_do_not_create_descendants(
    tmp_path, fixture_io, outside_root
):
    root = make_fixture_directory(tmp_path, "project")
    if outside_root:
        target = make_fixture_directory(tmp_path, "outside")
    else:
        target = make_fixture_directory(root, "inside")
    (root / "link").symlink_to(target, target_is_directory=True)
    with pytest.raises((ValueError, OSError)):
        write_fixture(root, "link/new/fixture.py", "unexpected")
    with pytest.raises((ValueError, OSError)):
        make_fixture_directory(root, "link/new")
    assert list(target.iterdir()) == []


def test_fixture_hardlink_overwrite_preserves_both_files(tmp_path, fixture_io):
    original = write_fixture(tmp_path, "original.py", "original")
    linked = tmp_path / "linked.py"
    os.link(original, linked)
    with pytest.raises(ValueError):
        write_fixture(tmp_path, "linked.py", "unexpected", overwrite=True)
    assert original.read_text(encoding="utf-8") == "original"
    assert linked.read_text(encoding="utf-8") == "original"


@pytest.mark.parametrize("overwrite", [False, True])
def test_dangling_fixture_symlink_cannot_create_target(tmp_path, fixture_io, overwrite):
    target = tmp_path / "missing.py"
    (tmp_path / "link.py").symlink_to(target)
    with pytest.raises((ValueError, OSError)):
        write_fixture(tmp_path, "link.py", "unexpected", overwrite=overwrite)
    assert not target.exists()


def test_fixture_helper_source_has_no_path_security_findings():
    path = Path(fixture_paths.__file__)
    findings = []
    scan(ast.parse(path.read_text(encoding="utf-8")), str(path), findings)
    assert findings == []


@pytest.mark.parametrize(
    "body, expected",
    [
        ("path = Path(root) / relative\npath.write_text('payload')",
         {"SKY-D215", "SKY-D324"}),
        ("path = Path(root) / relative\npath.mkdir(parents=True, exist_ok=True)",
         {"SKY-D215"}),
        ("path = (Path(root) / relative).resolve()\npath.write_text('payload')",
         {"SKY-D215"}),
    ],
)
def test_unsafe_fixture_lookalikes_still_report_path_risk(body, expected):
    lines = body.splitlines()
    source = "from pathlib import Path\ndef fixture_writer(root, relative):\n"
    for line in lines:
        source += "    " + line + "\n"
    findings = []
    scan(ast.parse(source), "test/test_fixture_lookalike.py", findings)
    assert expected <= {row["rule_id"] for row in findings}
