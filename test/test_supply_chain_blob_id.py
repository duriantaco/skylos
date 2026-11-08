"""Unread lockfiles must stay unread when a parent path leaves the checkout."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.rules.sca import supply_chain_diff as diff


def _sides(root: Path, path: str, content: bytes, length: int = 40) -> diff.GitSides:
    digest = hashlib.new("sha256" if length == 64 else "sha1")
    digest.update(f"blob {len(content)}\0".encode())
    digest.update(content)
    sides = diff.GitSides(SimpleNamespace(root=root), "", [path], [path])
    sides._entries = {path: ("100644", digest.hexdigest())}
    sides.unread[path] = "not readable as UTF-8 text"
    return sides


@pytest.mark.parametrize("length", [40, 64])
@pytest.mark.parametrize("content", [b"", b"\xff\x00\r\n", b"x" * (2**20 + 7)])
def test_unchanged_regular_blob_keeps_its_git_object_id(tmp_path, length, content):
    path = tmp_path / "package-lock.json"
    path.write_bytes(content)
    sides = _sides(tmp_path, path.name, content, length)

    assert sides._same_on_both_sides(path.name)
    assert sides.unread_changes(diff.upgrade_path) == []


def test_changed_regular_blob_remains_an_unread_change(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_bytes(b"changed")
    sides = _sides(tmp_path, path.name, b"original")

    assert not sides._same_on_both_sides(path.name)
    assert sides.unread_changes(diff.upgrade_path) == [
        {"file": path.name, "reason": "not readable as UTF-8 text"}
    ]


@pytest.mark.parametrize("length", [40, 64])
@pytest.mark.parametrize("escape", ["absolute", "parent", "symlink_parent"])
def test_outside_blob_cannot_hide_an_unread_change(tmp_path, length, escape):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "repo-sibling"
    outside.mkdir()
    content = b"same bytes as the committed lockfile"
    path = outside / "package-lock.json"
    path.write_bytes(content)
    if escape == "absolute":
        name = str(path)
    elif escape == "parent":
        name = "../repo-sibling/package-lock.json"
    else:
        (root / "web").symlink_to(outside, target_is_directory=True)
        name = "web/package-lock.json"
    sides = _sides(root, name, content, length)

    assert not sides._same_on_both_sides(name)
    assert sides.unread_changes(diff.upgrade_path) == [
        {"file": name, "reason": "not readable as UTF-8 text"}
    ]
