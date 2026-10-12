"""Stage synced files and restore their previous contents on caught failures.

This is not a crash-atomic multi-file transaction. On systems with directory
descriptors, operations stay anchored to the opened repository directory and
refuse symlinked directories and destination files.
"""

from __future__ import annotations

import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from uuid import uuid4


MAX_SYNC_FILE_BYTES = 2_000_000


class UnsafeSyncPath(OSError):
    pass


class _SyncDirectory:
    def __init__(self, repo_root: Path, *, create: bool):
        self.root = Path(repo_root).resolve(strict=True)
        self.path = self.root / ".skylos"
        self.root_fd: int | None = None
        self.fd: int | None = None
        self.anchored = all(
            operation in os.supports_dir_fd
            for operation in (os.open, os.stat, os.rename, os.unlink)
        )
        try:
            if self.anchored:
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                self.root_fd = os.open(self.root, flags)
                try:
                    os.stat(".skylos", dir_fd=self.root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        return
                    os.mkdir(".skylos", mode=0o700, dir_fd=self.root_fd)
                self._check_directory()
                self.fd = os.open(
                    ".skylos", flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=self.root_fd
                )
                self._check_directory()
            else:
                if not self.path.exists() and not self.path.is_symlink():
                    if not create:
                        return
                    self.path.mkdir(mode=0o700)
                self._check_directory()
        except BaseException:
            self.close()
            raise

    def _check_directory(self) -> None:
        directory_stat = (
            os.stat(".skylos", dir_fd=self.root_fd, follow_symlinks=False)
            if self.anchored
            else self.path.lstat()
        )
        if stat.S_ISLNK(directory_stat.st_mode):
            raise UnsafeSyncPath(f"Refusing symlinked Skylos directory: {self.path}")
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise UnsafeSyncPath(f"Skylos path is not a directory: {self.path}")
        if self.fd is not None:
            opened = os.fstat(self.fd)
            if (opened.st_dev, opened.st_ino) != (
                directory_stat.st_dev,
                directory_stat.st_ino,
            ):
                raise UnsafeSyncPath("Skylos directory changed during sync")

    def _stat(self, name: str):
        self._check_directory()
        try:
            value = (
                os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if self.anchored
                else (self.path / name).lstat()
            )
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(value.st_mode):
            raise UnsafeSyncPath(f"Refusing symlinked sync file: {self.path / name}")
        if not stat.S_ISREG(value.st_mode):
            raise UnsafeSyncPath(f"Sync path is not a regular file: {self.path / name}")
        return value

    def read(self, name: str) -> bytes | None:
        file_stat = self._stat(name)
        if file_stat is None:
            return None
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = (
            os.open(name, flags, dir_fd=self.fd)
            if self.anchored
            else os.open(self.path / name, flags)
        )
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise UnsafeSyncPath("Sync destination changed while reading")
            if opened.st_size > MAX_SYNC_FILE_BYTES:
                raise UnsafeSyncPath(f"Sync file exceeds size limit: {name}")
            contents = handle.read(MAX_SYNC_FILE_BYTES + 1)
        if len(contents) > MAX_SYNC_FILE_BYTES:
            raise UnsafeSyncPath(f"Sync file exceeds size limit: {name}")
        return contents

    def stage(self, name: str, contents: bytes) -> str:
        if len(contents) > MAX_SYNC_FILE_BYTES:
            raise UnsafeSyncPath(f"Sync file exceeds size limit: {name}")
        self._check_directory()
        temporary = f".{name}.{uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = (
            os.open(temporary, flags, 0o600, dir_fd=self.fd)
            if self.anchored
            else os.open(self.path / temporary, flags, 0o600)
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            self.remove(temporary)
            raise
        return temporary

    def replace(self, temporary: str, name: str) -> None:
        self._stat(name)
        self._replace(temporary, name)

    def _replace(self, temporary: str, name: str) -> None:
        if self.anchored:
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        else:
            self._check_directory()
            os.replace(self.path / temporary, self.path / name)

    def remove(self, name: str) -> None:
        try:
            if self.anchored:
                os.unlink(name, dir_fd=self.fd)
            else:
                self._check_directory()
                (self.path / name).unlink()
        except FileNotFoundError:
            pass

    def close(self) -> None:
        for descriptor in (self.fd, self.root_fd):
            if descriptor is not None:
                os.close(descriptor)
        self.fd = self.root_fd = None


def validate_sync_paths(repo_root: Path, names: tuple[str, ...]) -> None:
    directory = _SyncDirectory(repo_root, create=False)
    try:
        if directory.anchored and directory.fd is None:
            return
        if (
            not directory.anchored
            and not directory.path.exists()
            and not directory.path.is_symlink()
        ):
            return
        for name in names:
            directory._stat(name)
    finally:
        directory.close()


@contextmanager
def activate_sync_files(repo_root: Path, files: dict[str, str]) -> Iterator[None]:
    """Activate prepared files, rolling back if activation or the caller fails."""
    directory = _SyncDirectory(repo_root, create=True)
    staged: dict[str, str] = {}
    backups: dict[str, str | None] = {}
    activated: list[str] = []
    try:
        for name, content in files.items():
            previous = directory.read(name)
            backups[name] = (
                directory.stage(name, previous) if previous is not None else None
            )
            staged[name] = directory.stage(name, content.encode("utf-8"))
        for name, temporary in staged.items():
            directory.replace(temporary, name)
            activated.append(name)
        directory._check_directory()
        yield
        directory._check_directory()
    except BaseException as error:
        rollback_errors: list[str] = []
        for name in reversed(activated):
            try:
                backup = backups[name]
                if backup is None:
                    directory.remove(name)
                else:
                    directory._replace(backup, name)
            except OSError as rollback_error:
                rollback_errors.append(f"{name}: {rollback_error}")
        if rollback_errors:
            raise UnsafeSyncPath(
                "Sync failed and rollback could not restore " + "; ".join(rollback_errors)
            ) from error
        raise
    finally:
        try:
            temporary_names = (
                *staged.values(), *(value for value in backups.values() if value)
            )
            for temporary in temporary_names:
                directory.remove(temporary)
        finally:
            directory.close()
