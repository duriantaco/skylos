"""Stage synced files and restore their previous contents on caught failures.

This is not a crash-atomic multi-file transaction. Operations stay anchored to
opened directories, using no-follow descriptors or native Windows handles.
There is no path-checked fallback: checking a path cannot prevent a rename race.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

MAX_SYNC_FILE_BYTES = 2_000_000
SYNC_FILE_NAMES = frozenset({"config.yaml", "suppressions.json"})
_TEMPORARY_NAME = re.compile(
    r"\.(?:config\.yaml|suppressions\.json)\.[0-9a-f]{32}\.tmp\Z"
)


class UnsafeSyncPath(OSError):
    pass


def _sync_name(name: str, *, temporary: bool = False) -> str:
    if not isinstance(name, str) or (
        name not in SYNC_FILE_NAMES
        and not (temporary and _TEMPORARY_NAME.fullmatch(name))
    ):
        raise UnsafeSyncPath("Sync filename must be config.yaml or suppressions.json")
    return name


def _open_repository(root: Path) -> int:
    """Walk the canonical root without following substituted parent components."""
    expected = root.lstat()
    if not stat.S_ISDIR(expected.st_mode):
        raise UnsafeSyncPath("Repository root is not a regular directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(  # skylos: ignore[SKY-D215] absolute filesystem anchor; descendants are opened relative and no-follow
        root.anchor, flags
    )
    try:
        for component in root.parts[1:]:
            if component in {"", ".", ".."} or Path(component).name != component:
                raise UnsafeSyncPath("Unsafe repository directory component")
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (expected.st_dev, expected.st_ino):
            raise UnsafeSyncPath(
                "Repository directory changed while opening sync state"
            )
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class _SyncDirectory:
    def __init__(self, repo_root: Path, *, create: bool):
        self.root = Path(repo_root).resolve(strict=True)
        self.path = self.root / ".skylos"
        self.root_fd: int | None = None
        self.fd: int | None = None
        self.windows = None
        self.anchored = (
            {os.open, os.stat, os.rename, os.unlink, os.mkdir} <= os.supports_dir_fd
            and hasattr(os, "O_DIRECTORY")
            and hasattr(os, "O_NOFOLLOW")
        )
        try:
            if self.anchored:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                self.root_fd = _open_repository(self.root)
                try:
                    os.stat(".skylos", dir_fd=self.root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    if not create:
                        return
                    os.mkdir(".skylos", mode=0o700, dir_fd=self.root_fd)
                self._check_directory()
                self.fd = os.open(".skylos", flags, dir_fd=self.root_fd)
                self._check_directory()
            elif os.name == "nt":
                from skylos.cloud.windows_sync import _WindowsSyncDirectory

                self.windows = _WindowsSyncDirectory(self.root, create=create)
            else:
                raise UnsafeSyncPath(
                    "Safe sync requires no-follow directory descriptors or native Windows handles"
                )
        except BaseException:
            self.close()
            raise

    @property
    def present(self) -> bool:
        return self.windows.exists if self.windows is not None else self.fd is not None

    def _check_directory(self) -> None:
        if self.windows is not None:
            self.windows.check_directory()
            return
        directory_stat = os.stat(".skylos", dir_fd=self.root_fd, follow_symlinks=False)
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
        name = _sync_name(name, temporary=True)
        if self.windows is not None:
            return self.windows.stat(name)
        self._check_directory()
        try:
            value = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(value.st_mode):
            raise UnsafeSyncPath(f"Refusing symlinked sync file: {self.path / name}")
        if not stat.S_ISREG(value.st_mode):
            raise UnsafeSyncPath(f"Sync path is not a regular file: {self.path / name}")
        return value

    def read(self, name: str) -> bytes | None:
        name = _sync_name(name)
        if self.windows is not None:
            return self.windows.read(name)
        file_stat = self._stat(name)
        if file_stat is None:
            return None
        flags = (
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        )
        descriptor = os.open(  # skylos: ignore[SKY-D215] allowlisted basename beneath a held no-follow directory descriptor
            name, flags, dir_fd=self.fd
        )
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise UnsafeSyncPath("Sync destination changed while reading")
            if (opened.st_dev, opened.st_ino) != (file_stat.st_dev, file_stat.st_ino):
                raise UnsafeSyncPath("Sync destination changed while reading")
            if opened.st_size > MAX_SYNC_FILE_BYTES:
                raise UnsafeSyncPath(f"Sync file exceeds size limit: {name}")
            contents = handle.read(MAX_SYNC_FILE_BYTES + 1)
        if len(contents) > MAX_SYNC_FILE_BYTES:
            raise UnsafeSyncPath(f"Sync file exceeds size limit: {name}")
        return contents

    def stage(self, name: str, contents: bytes) -> str:
        name = _sync_name(name)
        if len(contents) > MAX_SYNC_FILE_BYTES:
            raise UnsafeSyncPath(f"Sync file exceeds size limit: {name}")
        if self.windows is not None:
            return self.windows.stage(name, contents)
        self._check_directory()
        temporary = f".{name}.{uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(  # skylos: ignore[SKY-D215] generated temporary basename, exclusive no-follow create beneath the held directory
            temporary, flags, 0o600, dir_fd=self.fd
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
        temporary = _sync_name(temporary, temporary=True)
        name = _sync_name(name)
        if self.windows is not None:
            self.windows.replace(temporary, name)
            return
        if self._stat(temporary) is None:
            raise UnsafeSyncPath("Staged sync file disappeared before activation")
        self._stat(name)
        self._replace(temporary, name)

    def _replace(self, temporary: str, name: str) -> None:
        temporary = _sync_name(temporary, temporary=True)
        name = _sync_name(name)
        if self.windows is not None:
            self.windows.replace(temporary, name)
        else:
            os.replace(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)

    def remove(self, name: str) -> None:
        name = _sync_name(name, temporary=True)
        if self.windows is not None:
            self.windows.remove(name)
            return
        try:
            os.unlink(  # skylos: ignore[SKY-D215] allowlisted/generated basename beneath the same held directory; unlink does not follow leaf symlinks
                name, dir_fd=self.fd
            )
        except FileNotFoundError:
            pass

    def close(self) -> None:
        if self.windows is not None:
            self.windows.close()
            self.windows = None
        for descriptor in (self.fd, self.root_fd):
            if descriptor is not None:
                os.close(descriptor)
        self.fd = self.root_fd = None


def validate_sync_paths(repo_root: Path, names: tuple[str, ...]) -> None:
    for name in names:
        _sync_name(name)
    directory = _SyncDirectory(repo_root, create=False)
    try:
        if not directory.present:
            return
        for name in names:
            directory._stat(name)
    finally:
        directory.close()


@contextmanager
def activate_sync_files(repo_root: Path, files: dict[str, str]) -> Iterator[None]:
    """Activate prepared files, rolling back if activation or the caller fails."""
    for name in files:
        _sync_name(name)
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
        for name, content in files.items():
            if directory.read(name) != content.encode("utf-8"):
                raise UnsafeSyncPath("Activated sync file changed before trust storage")
        yield
        directory._check_directory()
        for name, content in files.items():
            if directory.read(name) != content.encode("utf-8"):
                raise UnsafeSyncPath("Activated sync file changed during trust storage")
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
                "Sync failed and rollback could not restore "
                + "; ".join(rollback_errors)
            ) from error
        raise
    finally:
        try:
            temporary_names = (
                *staged.values(),
                *(value for value in backups.values() if value),
            )
            for temporary in temporary_names:
                directory.remove(temporary)
        finally:
            directory.close()
