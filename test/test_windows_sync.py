"""Native sync ABI tests plus portable handle-race contract checks.

Fake handles test the selected native operations; they do not substitute for
the conditional tests on a real Windows filesystem below.
"""

import ctypes
import os
from pathlib import PureWindowsPath
from types import SimpleNamespace

import pytest

from skylos.cloud import windows_sync as sync


class _FakeApi:
    def __init__(self, *, has_directory=True):
        self.nodes = {
            1: self.directory(),
            2: self.directory(),
            3: self.directory(),
            4: self.directory(),
        }
        self.nodes[1].children["users"] = 2
        self.nodes[2].children["repo"] = 3
        if has_directory:
            self.nodes[3].children[".skylos"] = 4
        self.closed = []
        self.calls = []
        self.next_handle = 5

    @staticmethod
    def directory():
        return SimpleNamespace(attributes=sync._FILE_ATTRIBUTE_DIRECTORY, children={})

    def open_anchor(self, anchor):
        self.calls.append(("anchor", anchor))
        return 1

    def open_relative(
        self, parent, name, *, access, create=False, create_directory=False
    ):
        self.calls.append(("relative", parent, name, access, create, create_directory))
        node = self.nodes[parent]
        if create or create_directory:
            if name in node.children:
                raise FileExistsError(name)
            result = self.next_handle
            self.next_handle += 1
            self.nodes[result] = (
                self.directory()
                if create_directory
                else SimpleNamespace(attributes=0, contents=b"")
            )
            node.children[name] = result
            return result
        return node.children.get(name)

    def information(self, handle):
        node = self.nodes[handle]
        return SimpleNamespace(
            attributes=node.attributes,
            volume_serial=1,
            index_high=0,
            index_low=handle,
            size_high=0,
            size_low=len(getattr(node, "contents", b"")),
        ), None

    def close_handle(self, handle):
        self.closed.append(handle)

    def read(self, handle, limit):
        self.calls.append(("read", handle, limit))
        return self.nodes[handle].contents[:limit]

    def write(self, handle, contents):
        self.calls.append(("write", handle))
        self.nodes[handle].contents = contents

    def rename(self, handle, parent, name):
        self.calls.append(("rename", handle, parent, name))
        for node in self.nodes.values():
            for old_name, old_handle in list(getattr(node, "children", {}).items()):
                if old_handle == handle:
                    del node.children[old_name]
        self.nodes[parent].children[name] = handle

    def remove(self, handle):
        self.calls.append(("delete", handle))
        for node in self.nodes.values():
            for name, child in list(getattr(node, "children", {}).items()):
                if child == handle:
                    del node.children[name]


def _directory(monkeypatch, *, has_directory=True, create=True):
    api = _FakeApi(has_directory=has_directory)
    monkeypatch.setattr(sync, "_SyncApi", lambda: api)
    return sync._WindowsSyncDirectory(
        PureWindowsPath("C:/users/repo"), create=create
    ), api


def test_all_repository_components_are_opened_relative_to_held_parents(monkeypatch):
    directory, api = _directory(monkeypatch)
    assert [(call[1], call[2]) for call in api.calls if call[0] == "relative"] == [
        (1, "users"),
        (2, "repo"),
        (3, ".skylos"),
    ]
    assert directory.exists
    directory.close()
    assert api.closed == [4, 3, 2, 1]
    directory.close()
    assert api.closed == [4, 3, 2, 1]


@pytest.mark.parametrize("changed", [1, 2, 3, 4])
def test_reparse_conversion_of_any_held_directory_is_rejected(monkeypatch, changed):
    directory, api = _directory(monkeypatch)
    api.nodes[changed].attributes |= sync._FILE_ATTRIBUTE_REPARSE_POINT
    with pytest.raises(OSError, match="reparse"):
        directory.stage("config.yaml", b"new")
    assert not any(call[0] == "write" for call in api.calls)
    directory.close()


@pytest.mark.parametrize(
    "bad",
    [
        "../escape",
        "a/b",
        "a\\b",
        "config.yaml:stream",
        "NUL",
        "CON.txt",
        "end.",
        "end ",
        "",
        ".",
        "..",
        "null\0name",
    ],
)
def test_bad_basenames_fail_before_any_native_child_operation(monkeypatch, bad):
    directory, api = _directory(monkeypatch)
    before = len(api.calls)
    for operation in (
        lambda: directory.stat(bad),
        lambda: directory.read(bad),
        lambda: directory.stage(bad, b"x"),
        lambda: directory.remove(bad),
        lambda: directory.replace("temporary", bad),
        lambda: directory.replace(bad, "config.yaml"),
    ):
        with pytest.raises(OSError):
            operation()
    # replace checks the valid destination's attributes before its invalid
    # source; no operation ever receives the malformed basename.
    assert all(call[2] != bad for call in api.calls[before:] if call[0] == "relative")
    directory.close()


def test_stage_activate_read_delete_use_handles_and_support_empty_contents(monkeypatch):
    directory, api = _directory(monkeypatch)
    first = directory.stage("config.yaml", b"old")
    directory.replace(first, "config.yaml")
    assert directory.read("config.yaml") == b"old"
    second = directory.stage("config.yaml", b"")
    directory.replace(second, "config.yaml")
    assert directory.read("config.yaml") == b""
    assert directory.stat("config.yaml").st_size == 0
    directory.remove("config.yaml")
    assert directory.read("config.yaml") is None
    assert all(call[2] == 4 for call in api.calls if call[0] == "rename")
    directory.close()


def test_missing_sync_directory_validation_does_not_create_it(monkeypatch):
    directory, api = _directory(monkeypatch, has_directory=False, create=False)
    assert not directory.exists
    assert directory.stat("config.yaml") is None
    assert directory.read("config.yaml") is None
    directory.close()
    assert not any(call[0] == "relative" and call[-1] for call in api.calls)


def test_missing_sync_directory_is_created_relative_to_repository_handle(monkeypatch):
    directory, api = _directory(monkeypatch, has_directory=False)
    assert directory.exists
    assert ("relative", 3, ".skylos", sync._DIRECTORY_ACCESS, False, True) in api.calls
    directory.close()


def test_constructor_rejects_reparse_component_and_closes_every_opened_handle(
    monkeypatch,
):
    api = _FakeApi()
    api.nodes[2].attributes |= sync._FILE_ATTRIBUTE_REPARSE_POINT
    monkeypatch.setattr(sync, "_SyncApi", lambda: api)
    with pytest.raises(OSError, match="reparse"):
        sync._WindowsSyncDirectory(PureWindowsPath("C:/users/repo"), create=True)
    assert api.closed == [2, 1]


def test_replaced_staged_file_reparse_is_rejected_before_rename(monkeypatch):
    directory, api = _directory(monkeypatch)
    temporary = directory.stage("config.yaml", b"new")
    staged = api.nodes[4].children[temporary]
    api.nodes[staged].attributes |= sync._FILE_ATTRIBUTE_REPARSE_POINT
    with pytest.raises(OSError, match="reparse"):
        directory.replace(temporary, "config.yaml")
    assert not any(call[0] == "rename" for call in api.calls)
    assert api.closed.count(staged) == 2
    directory.close()


def test_oversized_read_is_rejected_before_reading_and_handle_is_closed(monkeypatch):
    directory, api = _directory(monkeypatch)
    temporary = directory.stage("config.yaml", b"x")
    directory.replace(temporary, "config.yaml")
    handle = api.nodes[4].children["config.yaml"]
    api.nodes[handle].contents = b"x" * (sync._MAX_BYTES + 1)
    before = api.closed.count(handle)
    with pytest.raises(OSError, match="size limit"):
        directory.read("config.yaml")
    assert not any(call[0] == "read" for call in api.calls)
    assert api.closed.count(handle) == before + 1
    directory.close()


def test_growing_read_is_still_bounded_and_handle_is_closed(monkeypatch):
    directory, api = _directory(monkeypatch)
    temporary = directory.stage("config.yaml", b"x")
    directory.replace(temporary, "config.yaml")
    handle = api.nodes[4].children["config.yaml"]
    limits = []

    def growing_read(opened, limit):
        limits.append(limit)
        assert opened == handle
        return b"x" * limit

    api.read = growing_read
    before = api.closed.count(handle)
    with pytest.raises(OSError, match="size limit"):
        directory.read("config.yaml")
    assert limits == [sync._MAX_BYTES + 1]
    assert api.closed.count(handle) == before + 1
    directory.close()


def test_failed_staging_write_deletes_the_opened_file_and_closes_its_handle(
    monkeypatch,
):
    directory, api = _directory(monkeypatch)

    def fail_write(handle, content):
        raise OSError("disk full")

    api.write = fail_write
    with pytest.raises(OSError, match="disk full"):
        directory.stage("config.yaml", b"new")
    assert api.nodes[4].children == {}
    assert ("delete", 5) in api.calls
    assert api.closed.count(5) == 1
    directory.close()


def test_failed_rename_closes_source_without_deleting_it(monkeypatch):
    directory, api = _directory(monkeypatch)
    temporary = directory.stage("config.yaml", b"new")
    handle = api.nodes[4].children[temporary]

    def fail_rename(source, parent, name):
        raise PermissionError("destination is read only")

    api.rename = fail_rename
    before = api.closed.count(handle)
    with pytest.raises(PermissionError):
        directory.replace(temporary, "config.yaml")
    assert api.nodes[4].children[temporary] == handle
    assert api.closed.count(handle) == before + 1
    directory.close()


def test_native_open_uses_no_reparse_object_attribute_and_create_new_disposition():
    api = object.__new__(sync._SyncApi)
    api.case_sensitive = lambda parent: False
    calls = []

    def create(
        result,
        access,
        attributes,
        io_status,
        allocation,
        attrs,
        share,
        disposition,
        options,
        ea,
        ea_size,
    ):
        obj = ctypes.cast(attributes, ctypes.POINTER(sync._ObjectAttributes)).contents
        name = obj.object_name.contents
        calls.append(
            (obj.root_directory, name.buffer, obj.attributes, disposition, options)
        )
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p)).contents.value = 123
        return 0

    api.nt_create_file = create
    assert (
        api.open_relative(42, "config.yaml", access=sync._FILE_WRITE_DATA, create=True)
        == 123
    )
    assert calls == [
        (
            42,
            "config.yaml",
            sync._OBJ_DONT_REPARSE | sync._OBJ_CASE_INSENSITIVE,
            2,
            sync._FILE_SYNCHRONOUS_IO_NONALERT | sync._FILE_OPEN_REPARSE_POINT,
        )
    ]
    api.open_relative(
        42, ".skylos", access=sync._DIRECTORY_ACCESS, create_directory=True
    )
    assert (
        calls[-1][-1] == sync._FILE_SYNCHRONOUS_IO_NONALERT | sync._FILE_DIRECTORY_FILE
    )
    assert calls[-1][2] & sync._OBJ_DONT_REPARSE


def test_rename_native_layout_preserves_utf16_basename_and_parent_handle():
    api = object.__new__(sync._SyncApi)
    calls = []

    def set_info(handle, io, buffer, size, kind):
        info = sync._RenameInformation.from_buffer(buffer)
        data = ctypes.string_at(
            ctypes.addressof(buffer) + sync._RenameInformation.name.offset,
            info.name_length,
        )
        calls.append(
            (
                handle,
                info.replace_if_exists,
                info.root_directory,
                data.decode("utf-16-le"),
                size,
                kind,
            )
        )
        return 0

    api.nt_set_information_file = set_info
    api.rename(11, 42, "config-\U0001f34b.yaml")
    assert calls[0][:4] == (11, 1, 42, "config-\U0001f34b.yaml")
    assert calls[0][-1] == 10
    assert calls[0][4] >= ctypes.sizeof(sync._RenameInformation) + len(
        "config-\U0001f34b.yaml".encode("utf-16-le")
    )


def test_delete_native_layout_is_a_one_byte_boolean():
    api = object.__new__(sync._SyncApi)
    calls = []

    def set_info(handle, io, buffer, size, kind):
        calls.append((handle, ctypes.string_at(buffer, size), kind))
        return 0

    api.nt_set_information_file = set_info
    api.remove(11)
    assert calls == [(11, b"\x01", 13)]


def test_native_open_closes_handle_if_parent_case_sensitivity_changes():
    api = object.__new__(sync._SyncApi)
    values = iter([False, True])
    api.case_sensitive = lambda parent: next(values)
    closed = []
    api.close_handle = closed.append

    def create(result, *args):
        ctypes.cast(result, ctypes.POINTER(ctypes.c_void_p)).contents.value = 123
        return 0

    api.nt_create_file = create
    with pytest.raises(OSError, match="case sensitivity"):
        api.open_relative(42, "config.yaml", access=sync._FILE_READ_DATA)
    assert closed == [123]


def test_native_read_handles_short_reads_and_stops_at_the_requested_limit():
    api = object.__new__(sync._SyncApi)
    pieces = iter([b"ab", b"cd", b"e"])
    limits = []

    def read(handle, buffer, limit, count, overlapped):
        assert handle == 42
        assert overlapped is None
        limits.append(limit)
        piece = next(pieces)
        ctypes.memmove(buffer, piece, len(piece))
        ctypes.cast(count, ctypes.POINTER(sync._DWORD)).contents.value = len(piece)
        return 1

    api.read_file = read
    assert api.read(42, 5) == b"abcde"
    assert limits == [5, 3, 1]


def test_native_read_stops_at_eof_before_limit():
    api = object.__new__(sync._SyncApi)

    def read(handle, buffer, limit, count, overlapped):
        ctypes.cast(count, ctypes.POINTER(sync._DWORD)).contents.value = 0
        return 1

    api.read_file = read
    assert api.read(42, 5) == b""


def test_native_write_retries_short_writes_and_flushes_once():
    api = object.__new__(sync._SyncApi)
    writes = []
    flushed = []

    def write(handle, buffer, length, count, overlapped):
        assert handle == 42
        assert overlapped is None
        written = min(length, 2)
        writes.append(ctypes.string_at(buffer, written))
        ctypes.cast(count, ctypes.POINTER(sync._DWORD)).contents.value = written
        return 1

    api.write_file = write
    api.flush_file = lambda handle: flushed.append(handle) or 1
    api.write(42, b"abcde")
    assert writes == [b"ab", b"cd", b"e"]
    assert flushed == [42]


def test_native_empty_write_flushes_without_writing_a_nul_byte():
    api = object.__new__(sync._SyncApi)
    flushed = []
    api.write_file = lambda *args: pytest.fail("empty content must not call WriteFile")
    api.flush_file = lambda handle: flushed.append(handle) or 1
    api.write(42, b"")
    assert flushed == [42]


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handle operations")
def test_native_windows_sync_read_activate_delete(tmp_path):
    directory = sync._WindowsSyncDirectory(tmp_path.resolve(), create=True)
    try:
        temporary = directory.stage("config.yaml", b"first")
        directory.replace(temporary, "config.yaml")
        assert directory.read("config.yaml") == b"first"
        temporary = directory.stage("config.yaml", b"second")
        directory.replace(temporary, "config.yaml")
        assert directory.read("config.yaml") == b"second"
        directory.remove("config.yaml")
        assert directory.read("config.yaml") is None
    finally:
        directory.close()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handle operations")
def test_native_windows_directory_cannot_be_renamed_while_pinned(tmp_path):
    directory = sync._WindowsSyncDirectory(tmp_path.resolve(), create=True)
    try:
        with pytest.raises(OSError):
            os.replace(tmp_path / ".skylos", tmp_path / "moved")
        temporary = directory.stage("config.yaml", b"new")
        directory.replace(temporary, "config.yaml")
        assert directory.read("config.yaml") == b"new"
    finally:
        directory.close()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handle operations")
def test_native_windows_leaf_symlink_cannot_redirect_read_or_replace(tmp_path):
    directory = sync._WindowsSyncDirectory(tmp_path.resolve(), create=True)
    try:
        first = directory.stage("outside.yaml", b"sentinel")
        directory.replace(first, "outside.yaml")
        try:
            (tmp_path / ".skylos" / "config.yaml").symlink_to("outside.yaml")
        except OSError as error:
            pytest.skip(f"Windows symlink creation unavailable: {error}")
        with pytest.raises(OSError):
            directory.read("config.yaml")
        temporary = directory.stage("config.yaml", b"new")
        with pytest.raises(OSError):
            directory.replace(temporary, "config.yaml")
        assert directory.read("outside.yaml") == b"sentinel"
        directory.remove(temporary)
    finally:
        directory.close()
