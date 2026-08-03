from __future__ import annotations

import os
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink


def test_write_text_no_symlink_creates_and_replaces_regular_file(tmp_path: Path):
    output = tmp_path / "report.json"

    assert write_text_no_symlink(output, "first") is True
    assert write_text_no_symlink(output, "second") is True

    assert output.read_text(encoding="utf-8") == "second"


def test_write_text_no_symlink_rejects_leaf_symlink(tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("KEEP", encoding="utf-8")
    link = tmp_path / "report.txt"
    try:
        link.symlink_to(victim)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")

    assert write_text_no_symlink(link, "OVERWRITE") is False
    assert victim.read_text(encoding="utf-8") == "KEEP"


def test_write_text_no_symlink_rejects_symlinked_parent(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "report.txt"
    victim.write_text("KEEP", encoding="utf-8")
    linked_parent = tmp_path / "reports"
    try:
        linked_parent.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")

    assert write_text_no_symlink(linked_parent / "report.txt", "OVERWRITE") is False
    assert victim.read_text(encoding="utf-8") == "KEEP"


def test_write_text_no_symlink_rejects_hard_link(tmp_path: Path):
    victim = tmp_path / "victim.txt"
    victim.write_text("KEEP", encoding="utf-8")
    linked_output = tmp_path / "report.txt"
    try:
        os.link(victim, linked_output)
    except (OSError, NotImplementedError):
        pytest.skip("hard links unavailable")

    assert write_text_no_symlink(linked_output, "OVERWRITE") is False
    assert victim.read_text(encoding="utf-8") == "KEEP"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_write_text_no_symlink_rejects_fifo(tmp_path: Path):
    output = tmp_path / "report.pipe"
    os.mkfifo(output)

    assert write_text_no_symlink(output, "payload") is False
