"""The cached parser must enforce its own filesystem read boundary."""

import io
import os
from pathlib import Path

import pytest

from skylos.rules.danger import project_source
from skylos.rules.danger.danger import scan_ctx


def _entry(path, relative):
    metadata = path.stat()
    return (
        relative,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_size,
        metadata.st_ino,
    )


def _parse(root, entry, maximum=4096):
    return project_source._parse_snapshot(
        str(root), (entry,), (maximum, project_source._MAX_NODES)
    )


@pytest.mark.parametrize("absolute", [False, True], ids=["parent", "absolute"])
def test_forged_inventory_cannot_read_outside_root(tmp_path, absolute):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("private_value = 1\n")
    relative = str(outside) if absolute else "../outside.py"

    assert _parse(root, _entry(outside, relative)) == ({}, False)


def test_sibling_prefix_is_not_root_containment(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    sibling = tmp_path / "project_extra"
    sibling.mkdir()
    outside = sibling / "module.py"
    outside.write_text("private_value = 1\n")

    assert _parse(root, _entry(outside, "../project_extra/module.py")) == ({}, False)


@pytest.mark.parametrize("directory", [False, True], ids=["file", "directory"])
def test_cached_parser_rejects_symlink_escape(tmp_path, directory):
    root = tmp_path / "project"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "module.py"
    target.write_text("private_value = 1\n")
    if directory:
        (root / "linked").symlink_to(outside, target_is_directory=True)
        relative = "linked/module.py"
    else:
        (root / "linked.py").symlink_to(target)
        relative = "linked.py"

    assert _parse(root, _entry(target, relative)) == ({}, False)


def test_inside_root_symlink_still_cannot_hide_source(tmp_path):
    source = tmp_path / "actual.py"
    source.write_text("value = 1\n")
    link = tmp_path / "linked.py"
    link.symlink_to(source)

    assert _parse(tmp_path, _entry(source, link.name)) == ({}, False)


def test_directory_inventory_member_is_incomplete(tmp_path):
    directory = tmp_path / "module.py"
    directory.mkdir()

    assert _parse(tmp_path, _entry(directory, directory.name)) == ({}, False)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes require POSIX")
def test_named_pipe_is_rejected_before_reading(tmp_path, monkeypatch):
    pipe = tmp_path / "module.py"
    os.mkfifo(pipe)

    def forbidden_read(_path):
        raise AssertionError("attempted an unbounded read of a named pipe")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    assert _parse(tmp_path, _entry(pipe, pipe.name)) == ({}, False)


def test_file_growth_cannot_trigger_an_unbounded_read(tmp_path, monkeypatch):
    source = tmp_path / "module.py"
    source.write_text("x=1\n")
    entry = _entry(source, source.name)
    identity = source.stat()
    maximum = 16
    requested = []
    grown = False
    real_open = io.open
    real_read = os.read

    def is_source(value):
        if isinstance(value, int):
            try:
                metadata = os.fstat(value)
            except OSError:
                return False
            return (metadata.st_dev, metadata.st_ino) == (
                identity.st_dev,
                identity.st_ino,
            )
        try:
            return Path(value) == source
        except TypeError:
            return False

    def grow():
        nonlocal grown
        if not grown:
            grown = True
            with real_open(source, "wb") as writer:
                writer.write(b"x=" + b"1" * 2000 + b"\n")

    class ObservedReader:
        def __init__(self, stream):
            self.stream = stream

        def read(self, size=-1):
            grow()
            requested.append(size)
            return self.stream.read(size)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def observe_open(value, *args, **kwargs):
        target = is_source(value)
        stream = real_open(value, *args, **kwargs)
        return ObservedReader(stream) if target else stream

    def observe_read(fd, size):
        if is_source(fd):
            grow()
            requested.append(size)
        return real_read(fd, size)

    monkeypatch.setattr(io, "open", observe_open)
    monkeypatch.setattr(os, "read", observe_read)

    assert _parse(tmp_path, entry, maximum) == ({}, False)
    assert grown
    assert requested
    assert all(0 < size <= maximum + 1 for size in requested)


def test_regular_source_still_parses_under_the_same_inventory_identity(tmp_path):
    path = tmp_path / "module.py"
    path.write_text("value = 1\n")

    trees, complete = _parse(tmp_path, _entry(path, path.name))

    assert complete
    assert list(trees) == [path]
    assert trees[path].body[0].value.value == 1


def test_actual_snapshot_reader_has_a_visible_containment_proof(tmp_path):
    path = tmp_path / "snapshot_reader.py"
    path.write_text(Path(project_source.__file__).read_text())

    findings = scan_ctx(tmp_path, [path])

    assert not [row for row in findings if row["rule_id"] == "SKY-D215"]


def test_bounded_nofollow_read_without_containment_still_reports(tmp_path):
    path = tmp_path / "uncontained_reader.py"
    path.write_text(
        "import os\nfrom pathlib import Path\n"
        "def read(root, relative):\n"
        "    path = Path(root) / relative\n"
        '    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))\n'
        "    try:\n"
        '        with os.fdopen(fd, "rb", closefd=False) as stream:\n'
        "            return stream.read(4097)\n"
        "    finally:\n"
        "        os.close(fd)\n"
    )

    findings = scan_ctx(tmp_path, [path])

    rows = [row for row in findings if row["rule_id"] == "SKY-D215"]
    assert rows
    assert all(row["severity"] == "HIGH" for row in rows)
