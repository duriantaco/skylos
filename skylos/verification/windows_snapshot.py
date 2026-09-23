"""Bounded, no-follow working-tree reads on Windows.

`CreateFileW` cannot open a child relative to a directory handle.  Only the
repository root is opened by name; every Git-relative component is then
opened relative to the *held* parent handle with `NtCreateFile`.  This is the
Windows counterpart of the descriptor-relative walk in ``refactor.py``.
Neither path resolution nor a pre-open symlink check is a security boundary.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
from pathlib import Path


_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_GENERIC_READ = 0x80000000
_FILE_READ_DATA = 0x0001
_FILE_LIST_DIRECTORY = 0x0001
_FILE_TRAVERSE = 0x0020
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x0001
_OPEN_EXISTING = 3
_FILE_OPEN = 1
_FILE_ATTRIBUTE_DIRECTORY = 0x0010
_FILE_ATTRIBUTE_NORMAL = 0x0080
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_POSIX_SEMANTICS = 0x01000000
_FILE_SYNCHRONOUS_IO_NONALERT = 0x0020
_FILE_OPEN_REPARSE_POINT = 0x00200000
_FILE_TYPE_DISK = 1
_FILE_CASE_SENSITIVE_INFO_CLASS = 23
_FILE_CS_FLAG_CASE_SENSITIVE_DIR = 0x00000001
_OBJ_CASE_INSENSITIVE = 0x0040
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_MISSING_STATUSES = frozenset((0xC000000F, 0xC0000034, 0xC000003A))
_DEVICE_NUMBERS = "123456789\N{SUPERSCRIPT ONE}\N{SUPERSCRIPT TWO}\N{SUPERSCRIPT THREE}"
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{number}" for number in _DEVICE_NUMBERS}
    | {f"LPT{number}" for number in _DEVICE_NUMBERS}
)


class _FileTime(ctypes.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", _DWORD),
        ("creation_time", _FileTime),
        ("access_time", _FileTime),
        ("write_time", _FileTime),
        ("volume_serial", _DWORD),
        ("size_high", _DWORD),
        ("size_low", _DWORD),
        ("link_count", _DWORD),
        ("index_high", _DWORD),
        ("index_low", _DWORD),
    ]


class _FileBasicInfo(ctypes.Structure):
    _fields_ = [
        ("creation_time", ctypes.c_int64),
        ("access_time", ctypes.c_int64),
        ("write_time", ctypes.c_int64),
        ("change_time", ctypes.c_int64),
        ("attributes", _DWORD),
    ]


class _FileCaseSensitiveInfo(ctypes.Structure):
    _fields_ = [("flags", _DWORD)]


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", ctypes.c_wchar_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", _DWORD),
        ("root_directory", wintypes.HANDLE),
        ("object_name", ctypes.POINTER(_UnicodeString)),
        ("attributes", _DWORD),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _IoStatusUnion(ctypes.Union):
    _fields_ = [("status", ctypes.c_int32), ("pointer", ctypes.c_void_p)]


class _IoStatusBlock(ctypes.Structure):
    _fields_ = [("result", _IoStatusUnion), ("information", ctypes.c_size_t)]


def _relative_parts(name: str) -> tuple[str, ...]:
    """Reject aliases, streams, devices, and separators before native opens."""
    if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
        raise ValueError("Unsafe path in working source snapshot")
    parts = name.split("/")
    for part in parts:
        stem = part.split(".", 1)[0].rstrip(" ").upper()
        if (
            part in ("", ".", "..")
            or part.endswith((" ", "."))
            or any(ord(char) < 32 or char in '<>:"|?*' for char in part)
            or stem in _WINDOWS_RESERVED
        ):
            raise ValueError("Unsafe path in working source snapshot")
        # UNICODE_STRING lengths are USHORT byte counts, including a UTF-16 NUL
        # in maximum_length.  Do not let a long component wrap that count.
        try:
            encoded_length = len(part.encode("utf-16-le"))
        except UnicodeError as exc:
            raise ValueError("Unsafe path in working source snapshot") from exc
        if encoded_length > 0xFFFC:
            raise ValueError("Unsafe path in working source snapshot")
    return tuple(parts)


class _WindowsApi:
    def __init__(self) -> None:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll")

        self.create_file = kernel32.CreateFileW
        self.create_file.argtypes = (
            wintypes.LPCWSTR,
            _DWORD,
            _DWORD,
            ctypes.c_void_p,
            _DWORD,
            _DWORD,
            wintypes.HANDLE,
        )
        self.create_file.restype = wintypes.HANDLE

        self.close_handle = kernel32.CloseHandle
        self.close_handle.argtypes = (wintypes.HANDLE,)
        self.close_handle.restype = _BOOL

        self.get_file_type = kernel32.GetFileType
        self.get_file_type.argtypes = (wintypes.HANDLE,)
        self.get_file_type.restype = _DWORD

        self.get_file_info = kernel32.GetFileInformationByHandle
        self.get_file_info.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        )
        self.get_file_info.restype = _BOOL

        self.get_basic_info = kernel32.GetFileInformationByHandleEx
        self.get_basic_info.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            _DWORD,
        )
        self.get_basic_info.restype = _BOOL

        self.nt_create_file = ntdll.NtCreateFile
        self.nt_create_file.argtypes = (
            ctypes.POINTER(wintypes.HANDLE),
            _DWORD,
            ctypes.POINTER(_ObjectAttributes),
            ctypes.POINTER(_IoStatusBlock),
            ctypes.c_void_p,
            _DWORD,
            _DWORD,
            _DWORD,
            _DWORD,
            ctypes.c_void_p,
            _DWORD,
        )
        self.nt_create_file.restype = ctypes.c_int32

        self.nt_status_to_dos_error = ntdll.RtlNtStatusToDosError
        self.nt_status_to_dos_error.argtypes = (ctypes.c_int32,)
        self.nt_status_to_dos_error.restype = _DWORD

    def open_root(self, root: str | Path) -> int:
        handle = self.create_file(
            os.fspath(root),
            _GENERIC_READ,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS
            | _FILE_FLAG_OPEN_REPARSE_POINT
            | _FILE_FLAG_POSIX_SEMANTICS,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def open_child(
        self,
        parent: int,
        part: str,
        *,
        directory: bool,
        case_sensitive: bool,
    ) -> int | None:
        # A single validated component means RootDirectory remains the only
        # traversal anchor.  FILE_OPEN_REPARSE_POINT exposes a leaf junction or
        # symlink to the post-open attribute check instead of following it.
        buffer = ctypes.create_unicode_buffer(part)
        length = len(part.encode("utf-16-le"))
        name = _UnicodeString(length, length + 2, ctypes.cast(buffer, ctypes.c_wchar_p))
        attributes = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes),
            parent,
            ctypes.pointer(name),
            0 if case_sensitive else _OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        result = wintypes.HANDLE()
        io_status = _IoStatusBlock()
        access = (
            _FILE_LIST_DIRECTORY | _FILE_TRAVERSE | _FILE_READ_ATTRIBUTES
            if directory
            else _FILE_READ_DATA | _FILE_READ_ATTRIBUTES
        ) | _SYNCHRONIZE
        # The documented FILE_DIRECTORY_FILE compatibility list excludes
        # FILE_OPEN_REPARSE_POINT.  Open type-neutrally, then verify the kind
        # from the returned handle before traversing or reading.
        options = _FILE_SYNCHRONOUS_IO_NONALERT | _FILE_OPEN_REPARSE_POINT
        status = self.nt_create_file(
            ctypes.byref(result),
            access,
            ctypes.byref(attributes),
            ctypes.byref(io_status),
            None,
            _FILE_ATTRIBUTE_NORMAL,
            _FILE_SHARE_READ,
            _FILE_OPEN,
            options,
            None,
            0,
        )
        if status != 0:
            if (status & 0xFFFFFFFF) in _MISSING_STATUSES:
                return None
            error = self.nt_status_to_dos_error(status)
            raise ctypes.WinError(error)
        if result.value is None or result.value == _INVALID_HANDLE_VALUE:
            raise OSError("NtCreateFile returned an invalid handle")
        return result.value

    def case_sensitive(self, handle: int) -> bool:
        info = _FileCaseSensitiveInfo()
        if not self.get_basic_info(
            handle,
            _FILE_CASE_SENSITIVE_INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(info.flags & _FILE_CS_FLAG_CASE_SENSITIVE_DIR)

    def information(
        self, handle: int
    ) -> tuple[_ByHandleFileInformation, _FileBasicInfo]:
        if self.get_file_type(handle) != _FILE_TYPE_DISK:
            raise ValueError("Working source is not a disk file")
        info = _ByHandleFileInformation()
        basic = _FileBasicInfo()
        if not self.get_file_info(handle, ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not self.get_basic_info(
            handle, 0, ctypes.byref(basic), ctypes.sizeof(basic)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if basic.attributes != info.attributes:
            raise ValueError("Working source changed while reading metadata")
        return info, basic


def _signature(
    info: _ByHandleFileInformation, basic: _FileBasicInfo
) -> tuple[int, ...]:
    return (
        info.attributes,
        info.volume_serial,
        info.index_high,
        info.index_low,
        info.size_high,
        info.size_low,
        basic.creation_time,
        basic.write_time,
        basic.change_time,
    )


class WindowsSourceReader:
    """Read Git-listed source files beneath a pinned Windows directory handle.

    Filesystems or Windows versions that cannot satisfy these handle-based
    checks abstain with ValueError; they never fall back to ordinary open().
    """

    def __init__(self, root: str | Path, *, max_file_bytes: int) -> None:
        if type(max_file_bytes) is not int or max_file_bytes < 0:
            raise ValueError("Invalid working source size limit")
        self._root = root
        self._max_file_bytes = max_file_bytes
        self._api: _WindowsApi | None = None
        self._root_handle: int | None = None

    def __enter__(self) -> WindowsSourceReader:
        if os.name != "nt":
            raise ValueError(
                "Platform does not support safe working source snapshot reads"
            )
        try:
            self._api = _WindowsApi()
            root_handle = self._api.open_root(self._root)
            self._root_handle = root_handle
            info, _ = self._api.information(root_handle)
            if (
                info.attributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or not info.attributes & _FILE_ATTRIBUTE_DIRECTORY
            ):
                raise ValueError("Cannot open working source snapshot root")
        except ValueError:
            self.__exit__(None, None, None)
            raise
        except Exception as exc:
            self.__exit__(None, None, None)
            raise ValueError("Cannot open working source snapshot root") from exc
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._root_handle is not None and self._api is not None:
            self._api.close_handle(self._root_handle)
            self._root_handle = None

    def read(self, name: str) -> bytes | None:
        parts = _relative_parts(name)
        if self._api is None or self._root_handle is None:
            raise ValueError("Working source reader is not open")

        parent = self._root_handle
        directory_handles: list[int] = []
        file_handle: int | None = None
        try:
            import msvcrt

            parent_case_sensitive = self._api.case_sensitive(parent)
            for part in parts[:-1]:
                opened = self._api.open_child(
                    parent,
                    part,
                    directory=True,
                    case_sensitive=parent_case_sensitive,
                )
                if opened is not None:
                    directory_handles.append(opened)
                if self._api.case_sensitive(parent) != parent_case_sensitive:
                    raise ValueError(
                        f"Working source parent changed case sensitivity: {name}"
                    )
                if opened is None:
                    return None
                info, _ = self._api.information(opened)
                if info.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError(
                        f"Working source traverses a reparse point: {name}"
                    )
                if not info.attributes & _FILE_ATTRIBUTE_DIRECTORY:
                    raise ValueError(
                        f"Working source parent is not a directory: {name}"
                    )
                parent = opened
                parent_case_sensitive = self._api.case_sensitive(parent)

            file_handle = self._api.open_child(
                parent,
                parts[-1],
                directory=False,
                case_sensitive=parent_case_sensitive,
            )
            if self._api.case_sensitive(parent) != parent_case_sensitive:
                raise ValueError(
                    f"Working source parent changed case sensitivity: {name}"
                )
            if file_handle is None:
                return None
            before, before_basic = self._api.information(file_handle)
            if (
                before.attributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or before.attributes & _FILE_ATTRIBUTE_DIRECTORY
            ):
                raise ValueError(f"Working source is not a regular file: {name}")
            size = (before.size_high << 32) | before.size_low
            if size > self._max_file_bytes:
                raise ValueError(
                    f"Working source exceeds the verification size limit: {name}"
                )

            descriptor = msvcrt.open_osfhandle(
                file_handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT
            )
            file_handle = None  # The CRT descriptor now owns the Windows handle.
            try:
                stream = os.fdopen(descriptor, "rb")
            except Exception:
                os.close(descriptor)
                raise
            with stream:
                raw = stream.read(self._max_file_bytes + 1)
                after, after_basic = self._api.information(
                    msvcrt.get_osfhandle(stream.fileno())
                )
            if _signature(before, before_basic) != _signature(after, after_basic):
                raise ValueError(f"Working source changed while being read: {name}")
            if len(raw) > self._max_file_bytes:
                raise ValueError(
                    f"Working source exceeds the verification size limit: {name}"
                )
            return raw
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Cannot read working source: {name}") from exc
        finally:
            if file_handle is not None:
                self._api.close_handle(file_handle)
            for handle in reversed(directory_handles):
                self._api.close_handle(handle)
