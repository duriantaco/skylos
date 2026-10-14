"""Repository paths that start with "~" are folders in the repository.

Git never expands "~". Expanding it crashed on "~name" when no such user
exists ("Could not determine home directory") and read from outside the
project for "~/x" or "~root/x", so `skylos done` missed secrets there.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import (
    read_project_text_no_symlink,
    write_text_no_symlink,
)
from skylos.done.base import open_comparison
from skylos.done.checks import CheckContext, check_secrets
from skylos.done.config import DoneConfig

GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, text)
    return path


@pytest.mark.parametrize(
    "relative", ["~notes/todo.py", "~/x.py", "~root/x.py", "~skylos-no-such-user/x"]
)
def test_tilde_path_is_read_from_the_project(tmp_path, monkeypatch, relative):
    home = tmp_path / "home"
    _write(home / "x.py", "from home\n")
    monkeypatch.setenv("HOME", str(home))
    root = tmp_path / "repo"
    _write(root / relative, "from repo\n")

    text = read_project_text_no_symlink(root, relative, max_bytes=1000)

    assert text == "from repo\n"


def test_missing_tilde_path_is_none_not_a_crash(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()

    assert read_project_text_no_symlink(root, "~nobody-zz/x", max_bytes=10) is None


def test_containment_is_unchanged(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = _write(tmp_path / "outside.txt", "secret\n")

    assert read_project_text_no_symlink(root, "../outside.txt", max_bytes=100) is None
    assert read_project_text_no_symlink(root, str(outside), max_bytes=100) is None


def test_project_root_with_unknown_tilde_user_is_literal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write(tmp_path / "~proj-no-such-user" / "a.txt", "literal\n")

    assert (
        read_project_text_no_symlink("~proj-no-such-user", "a.txt", max_bytes=100)
        == "literal\n"
    )


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("relative", ["~notes/todo.py", "~/x.py", "~root/x.py"])
def test_done_finds_a_secret_added_under_a_tilde_folder(tmp_path, relative):
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root / "app.py", "x = 1\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _write(root / relative, f'TOKEN = "{GH_TOKEN}"\n')

    result = check_secrets(CheckContext(open_comparison(root, "main"), DoneConfig()))

    assert result.status == "fail"
    assert [(f.file, f.line) for f in result.findings] == [(relative, 1)]
