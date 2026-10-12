"""Handle-relative sync I/O on Windows; no ordinary path I/O fallback.

Sharing flags do not lock all reparse metadata.  Every child is therefore
opened relative to an already held directory handle, with reparse processing
disabled.  Rename and deletion also operate on handles, not absolute paths.
"""

from __future__ import annotations

import ctypes
import os
import stat
from ctypes import wintypes
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from uuid import uuid4

from skylos.verification.windows_snapshot import (
    _BOOL,
    _DWORD,
    _FILE_ATTRIBUTE_DIRECTORY,
    _FILE_ATTRIBUTE_NORMAL,
    _FILE_ATTRIBUTE_REPARSE_POINT,
    _FILE_FLAG_BACKUP_SEMANTICS,
    _FILE_FLAG_OPEN_REPARSE_POINT,
    _FILE_FLAG_POSIX_SEMANTICS,
    _FILE_LIST_DIRECTORY,
    _FILE_OPEN,
    _FILE_OPEN_REPARSE_POINT,
    _FILE_READ_ATTRIBUTES,
    _FILE_READ_DATA,
    _FILE_SHARE_READ,
    _FILE_SYNCHRONOUS_IO_NONALERT,
    _FILE_TRAVERSE,
    _INVALID_HANDLE_VALUE,
    _MISSING_STATUSES,
    _OBJ_CASE_INSENSITIVE,
    _SYNCHRONIZE,
    _IoStatusBlock,
    _ObjectAttributes,
    _relative_parts,
    _UnicodeString,
    _WindowsApi,
)

_FILE_SHARE_WRITE = 0x0002
_FILE_WRITE_DATA = 0x0002
_DELETE = 0x00010000
_FILE_CREATE = 2
_FILE_DIRECTORY_FILE = 0x0001
_OBJ_DONT_REPARSE = 0x1000
_FILE_RENAME_INFORMATION = 10
_FILE_DISPOSITION_INFORMATION = 13
_STATUS_NAME_COLLISION = 0xC0000035
_MAX_BYTES = 2_000_000
_DIRECTORY_ACCESS = (
    _FILE_LIST_DIRECTORY | _FILE_TRAVERSE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
)


class _RenameInformation(ctypes.Structure):
    # BOOLEAN, HANDLE, ULONG, WCHAR[1]; native alignment includes the padding
    # before RootDirectory. WCHAR is always two bytes, including on Unix tests.
    _fields_ = [
        ("replace_if_exists", ctypes.c_ubyte),
        ("root_directory", wintypes.HANDLE),
        ("name_length", _DWORD),
        ("name", ctypes.c_uint16 * 1),
    ]


class _DispositionInformation(ctypes.Structure):
    _fields_ = [("delete_file", ctypes.c_ubyte)]


def _basename(name: str) -> str:
    try:
        parts = _relative_parts(name)
    except ValueError as error:
        raise OSError("Unsafe sync file name") from error
    if len(parts) != 1:
        raise OSError("Sync file name must be a single component")
    return parts[0]


def _identity(info) -> tuple[int, int, int]:
    return info.volume_serial, info.index_high, info.index_low


class _SyncApi(_WindowsApi):
    def __init__(self) -> None:
        super().__init__()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll")
        self.nt_set_information_file = ntdll.NtSetInformationFile
        self.nt_set_information_file.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_IoStatusBlock),
            ctypes.c_void_p,
            _DWORD,
            ctypes.c_int,
        )
        self.nt_set_information_file.restype = ctypes.c_int32
        self.read_file = kernel32.ReadFile
        self.write_file = kernel32.WriteFile
        for operation in (self.read_file, self.write_file):
            operation.argtypes = (
                wintypes.HANDLE,
                ctypes.c_void_p,
                _DWORD,
                ctypes.POINTER(_DWORD),
                ctypes.c_void_p,
            )
            operation.restype = _BOOL
        self.flush_file = kernel32.FlushFileBuffers
        self.flush_file.argtypes = (wintypes.HANDLE,)
        self.flush_file.restype = _BOOL

    def _raise_status(self, status: int) -> None:
        error = self.nt_status_to_dos_error(status)
        raise ctypes.WinError(error)

    def open_anchor(self, anchor: str) -> int:
        handle = self.create_file(
            anchor,
            _DIRECTORY_ACCESS,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            3,  # OPEN_EXISTING
            _FILE_FLAG_BACKUP_SEMANTICS
            | _FILE_FLAG_OPEN_REPARSE_POINT
            | _FILE_FLAG_POSIX_SEMANTICS,
            None,
        )
        if handle in (None, _INVALID_HANDLE_VALUE):
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def open_relative(
        self,
        parent: int,
        name: str,
        *,
        access: int,
        create: bool = False,
        create_directory: bool = False,
    ) -> int | None:
        name = _basename(name)
        buffer = ctypes.create_unicode_buffer(name)
        length = len(name.encode("utf-16-le"))
        string = _UnicodeString(
            length, length + 2, ctypes.cast(buffer, ctypes.c_wchar_p)
        )
        case_sensitive = self.case_sensitive(parent)
        attributes = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes),
            parent,
            ctypes.pointer(string),
            _OBJ_DONT_REPARSE | (0 if case_sensitive else _OBJ_CASE_INSENSITIVE),
            None,
            None,
        )
        options = _FILE_SYNCHRONOUS_IO_NONALERT
        if create_directory:
            # FILE_DIRECTORY_FILE's documented compatible option list excludes
            # FILE_OPEN_REPARSE_POINT. OBJ_DONT_REPARSE supplies no-follow here.
            options |= _FILE_DIRECTORY_FILE
        else:
            options |= _FILE_OPEN_REPARSE_POINT
        result = wintypes.HANDLE()
        status = self.nt_create_file(
            ctypes.byref(result),
            access,
            ctypes.byref(attributes),
            ctypes.byref(_IoStatusBlock()),
            None,
            _FILE_ATTRIBUTE_DIRECTORY if create_directory else _FILE_ATTRIBUTE_NORMAL,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE
            if access == _DIRECTORY_ACCESS
            else _FILE_SHARE_READ,
            _FILE_CREATE if create or create_directory else _FILE_OPEN,
            options,
            None,
            0,
        )
        if status != 0:
            unsigned = status & 0xFFFFFFFF
            if not (create or create_directory) and unsigned in _MISSING_STATUSES:
                return None
            if unsigned == _STATUS_NAME_COLLISION:
                raise FileExistsError("Sync staging name already exists")
            self._raise_status(status)
        if result.value in (None, _INVALID_HANDLE_VALUE):
            raise OSError("NtCreateFile returned an invalid sync handle")
        try:
            if self.case_sensitive(parent) != case_sensitive:
                raise OSError("Sync directory case sensitivity changed during open")
        except BaseException:
            self.close_handle(result.value)
            raise
        return result.value

    def read(self, handle: int, limit: int) -> bytes:
        pieces: list[bytes] = []
        total = 0
        while total < limit:
            buffer = ctypes.create_string_buffer(min(65536, limit - total))
            count = _DWORD()
            if not self.read_file(
                handle, buffer, len(buffer), ctypes.byref(count), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if count.value > len(buffer):
                raise OSError("Invalid native sync read length")
            if not count.value:
                break
            pieces.append(buffer.raw[: count.value])
            total += count.value
        return b"".join(pieces)

    def write(self, handle: int, contents: bytes) -> None:
        offset = 0
        while offset < len(contents):
            piece = contents[offset : offset + 65536]
            buffer = ctypes.create_string_buffer(piece)
            count = _DWORD()
            if not self.write_file(
                handle, buffer, len(piece), ctypes.byref(count), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not 0 < count.value <= len(piece):
                raise OSError("Invalid native sync write length")
            offset += count.value
        if not self.flush_file(handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def rename(self, handle: int, parent: int, name: str) -> None:
        encoded = _basename(name).encode("utf-16-le")
        # Microsoft requires sizeof(FILE_RENAME_INFORMATION) plus name bytes;
        # the string begins at the field offset, not the padded structure end.
        buffer = ctypes.create_string_buffer(
            ctypes.sizeof(_RenameInformation) + len(encoded)
        )
        info = _RenameInformation.from_buffer(buffer)
        info.replace_if_exists = 1
        info.root_directory = parent
        info.name_length = len(encoded)
        ctypes.memmove(
            ctypes.addressof(buffer) + _RenameInformation.name.offset,
            encoded,
            len(encoded),
        )
        status = self.nt_set_information_file(
            handle,
            ctypes.byref(_IoStatusBlock()),
            buffer,
            len(buffer),
            _FILE_RENAME_INFORMATION,
        )
        if status != 0:
            self._raise_status(status)

    def remove(self, handle: int) -> None:
        info = _DispositionInformation(1)
        status = self.nt_set_information_file(
            handle,
            ctypes.byref(_IoStatusBlock()),
            ctypes.byref(info),
            ctypes.sizeof(info),
            _FILE_DISPOSITION_INFORMATION,
        )
        if status != 0:
            self._raise_status(status)


class _WindowsSyncDirectory:
    def __init__(self, root: Path, *, create: bool):
        self.api = _SyncApi()
        self.handles: list[int] = []
        self.identities: list[tuple[int, int, int]] = []
        self.root_handle: int | None = None
        self.handle: int | None = None
        path = PureWindowsPath(os.fspath(root))
        if not path.is_absolute() or not path.anchor:
            raise OSError("Windows sync requires an absolute repository path")
        try:
            parent = self.api.open_anchor(path.anchor)
            self._hold_directory(parent)
            for part in path.parts[1:]:
                child = self.api.open_relative(parent, part, access=_DIRECTORY_ACCESS)
                if child is None:
                    raise FileNotFoundError(
                        "Repository directory disappeared during sync"
                    )
                self._hold_directory(child)
                parent = child
            self.root_handle = parent
            child = self.api.open_relative(parent, ".skylos", access=_DIRECTORY_ACCESS)
            if child is None and create:
                try:
                    child = self.api.open_relative(
                        parent,
                        ".skylos",
                        access=_DIRECTORY_ACCESS,
                        create_directory=True,
                    )
                except FileExistsError:
                    child = self.api.open_relative(
                        parent, ".skylos", access=_DIRECTORY_ACCESS
                    )
            if child is not None:
                self._hold_directory(child)
                self.handle = child
            self.check_directory()
        except BaseException:
            self.close()
            raise

    @property
    def exists(self) -> bool:
        return self.handle is not None

    def _checked_information(self, handle: int, *, directory: bool):
        info, _ = self.api.information(handle)
        if info.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("Refusing a reparse point during Skylos sync")
        if bool(info.attributes & _FILE_ATTRIBUTE_DIRECTORY) != directory:
            raise OSError("Sync path has the wrong file type")
        return info

    def _hold_directory(self, handle: int) -> None:
        # Record before metadata validation so construction failures close it.
        self.handles.append(handle)
        info = self._checked_information(handle, directory=True)
        self.identities.append(_identity(info))

    def check_directory(self) -> None:
        for handle, identity in zip(self.handles, self.identities):
            if _identity(self._checked_information(handle, directory=True)) != identity:
                raise OSError("Sync directory changed identity")

    def _open_file(self, name: str, *, access: int) -> int | None:
        name = _basename(name)
        self.check_directory()
        if self.handle is None:
            return None
        handle = self.api.open_relative(self.handle, name, access=access)
        if handle is not None:
            try:
                self._checked_information(handle, directory=False)
            except BaseException:
                self.api.close_handle(handle)
                raise
        return handle

    def stat(self, name: str):
        handle = self._open_file(name, access=_FILE_READ_ATTRIBUTES | _SYNCHRONIZE)
        if handle is None:
            return None
        try:
            info = self._checked_information(handle, directory=False)
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_size=(info.size_high << 32) | info.size_low,
                st_dev=info.volume_serial,
                st_ino=(info.index_high << 32) | info.index_low,
            )
        finally:
            self.api.close_handle(handle)

    def read(self, name: str) -> bytes | None:
        handle = self._open_file(
            name, access=_FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
        )
        if handle is None:
            return None
        try:
            info = self._checked_information(handle, directory=False)
            if ((info.size_high << 32) | info.size_low) > _MAX_BYTES:
                raise OSError("Sync file exceeds size limit")
            contents = self.api.read(handle, _MAX_BYTES + 1)
            self._checked_information(handle, directory=False)
            if len(contents) > _MAX_BYTES:
                raise OSError("Sync file exceeds size limit")
            return contents
        finally:
            self.api.close_handle(handle)

    def stage(self, name: str, contents: bytes) -> str:
        name = _basename(name)
        if len(contents) > _MAX_BYTES:
            raise OSError("Sync file exceeds size limit")
        self.check_directory()
        if self.handle is None:
            raise OSError("Skylos sync directory is missing")
        temporary = f".{name}.{uuid4().hex}.tmp"
        handle = self.api.open_relative(
            self.handle,
            temporary,
            access=_FILE_WRITE_DATA | _FILE_READ_ATTRIBUTES | _DELETE | _SYNCHRONIZE,
            create=True,
        )
        if handle is None:
            raise OSError("Sync staging did not create a file")
        try:
            self._checked_information(handle, directory=False)
            self.api.write(handle, contents)
            self._checked_information(handle, directory=False)
        except BaseException:
            try:
                self.api.remove(handle)
            finally:
                self.api.close_handle(handle)
            raise
        self.api.close_handle(handle)
        return temporary

    def replace(self, temporary: str, name: str) -> None:
        name = _basename(name)
        self.stat(name)
        handle = self._open_file(
            temporary, access=_DELETE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
        )
        if handle is None:
            raise FileNotFoundError("Sync staged file is missing")
        try:
            self.api.rename(handle, self.handle, name)
        finally:
            self.api.close_handle(handle)

    def remove(self, name: str) -> None:
        handle = self._open_file(
            name, access=_DELETE | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE
        )
        if handle is None:
            return
        try:
            self.api.remove(handle)
        finally:
            self.api.close_handle(handle)

    def close(self) -> None:
        for handle in reversed(self.handles):
            self.api.close_handle(handle)
        self.handles.clear()
        self.identities.clear()
        self.root_handle = self.handle = None
