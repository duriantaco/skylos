from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any


DEFAULT_MAX_JSON_CACHE_BYTES = 2_000_000


def read_text_no_symlink(
    path: str | Path,
    *,
    max_bytes: int,
    encoding: str = "utf-8",
    errors: str | None = None,
    newline: str | None = None,
) -> str | None:
    try:
        if Path(path).is_symlink():
            return None
    except OSError:
        return None

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] caller supplies guarded source/cache path
            path, flags
        )
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            return None
        if stat_result.st_size > max_bytes:
            return None
        with os.fdopen(
            fd,
            "r",
            encoding=encoding,
            errors=errors,
            newline=newline,
        ) as handle:
            fd = None
            text = handle.read(max_bytes + 1)
    except (OSError, UnicodeError):
        return None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    encoded_errors = errors or "strict"
    if len(text.encode(encoding, encoded_errors)) > max_bytes:
        return None
    return text


def read_project_text_no_symlink(
    project_root: str | Path,
    path: str | Path,
    *,
    max_bytes: int,
    encoding: str = "utf-8",
    errors: str | None = None,
    newline: str | None = None,
) -> str | None:
    project_path = _project_relative_path(project_root, path)
    if project_path is None:
        return None
    root, relative = project_path
    if os.open not in os.supports_dir_fd:
        return _read_project_text_fallback(
            root,
            relative,
            max_bytes=max_bytes,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )

    directory_fd: int | None = None
    file_fd: int | None = None
    try:
        directory_fd = os.open(root, _directory_open_flags(follow_symlinks=True))
        for part in relative.parts[:-1]:
            next_fd = os.open(part, _directory_open_flags(), dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_fd = os.open(relative.parts[-1], flags, dir_fd=directory_fd)
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > max_bytes:
            return None
        with os.fdopen(
            file_fd,
            "r",
            encoding=encoding,
            errors=errors,
            newline=newline,
        ) as handle:
            file_fd = None
            text = handle.read(max_bytes + 1)
    except (OSError, UnicodeError):
        return None
    finally:
        _close_file_descriptor(file_fd)
        _close_file_descriptor(directory_fd)

    encoded_errors = errors or "strict"
    if len(text.encode(encoding, encoded_errors)) > max_bytes:
        return None
    return text


def _project_relative_path(
    project_root: str | Path,
    path: str | Path,
) -> tuple[Path, Path] | None:
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except OSError:
        return None
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return None
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        return None
    return root, relative


def _read_project_text_fallback(
    root: Path,
    relative: Path,
    *,
    max_bytes: int,
    encoding: str,
    errors: str | None,
    newline: str | None,
) -> str | None:
    current = root
    try:
        for part in relative.parts[:-1]:
            current = current / part
            if current.is_symlink() or not current.is_dir():
                return None
        candidate = current / relative.parts[-1]
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError):
        return None
    return read_text_no_symlink(
        candidate,
        max_bytes=max_bytes,
        encoding=encoding,
        errors=errors,
        newline=newline,
    )


def _directory_open_flags(*, follow_symlinks: bool = False) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if not follow_symlinks and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _close_file_descriptor(file_descriptor: int | None) -> None:
    if file_descriptor is None:
        return
    try:
        os.close(file_descriptor)
    except OSError:
        pass


def write_existing_text_no_symlink(
    path: str | Path,
    text: str,
    *,
    encoding: str = "utf-8",
) -> bool:
    try:
        if Path(path).is_symlink():
            return False
    except OSError:
        return False

    flags = os.O_WRONLY | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] caller supplies guarded existing file path
            path, flags
        )
        stat_result = os.fstat(fd)
        if not stat.S_ISREG(stat_result.st_mode):
            return False
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            fd = None
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        return True
    except (OSError, UnicodeError):
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _project_cache_path(
    project_root: str | Path,
    cache_path: str | Path,
    *,
    create: bool,
) -> Path | None:
    resolved = _resolve_project_cache_path(project_root, cache_path)
    if resolved is None:
        return None
    root, path = resolved
    if not _ensure_cache_parent(root, path, create=create):
        return None
    if not _is_regular_cache_file(path):
        return None
    return path


def _resolve_project_cache_path(
    project_root: str | Path,
    cache_path: str | Path,
) -> tuple[Path, Path] | None:
    try:
        root = Path(project_root).resolve(strict=True)
    except OSError:
        return None

    path = Path(cache_path)
    if not path.is_absolute():
        path = root / path

    try:
        relative = path.relative_to(root)
    except ValueError:
        return None
    if any(part == ".." for part in relative.parts):
        return None

    return root, path


def _ensure_cache_parent(root: Path, path: Path, *, create: bool) -> bool:
    try:
        relative_parent = path.parent.relative_to(root)
    except ValueError:
        return False

    current = root
    for part in relative_parent.parts:
        current = current / part
        if not _ensure_cache_dir(root, current, create=create):
            return False
    return True


def _ensure_cache_dir(root: Path, current: Path, *, create: bool) -> bool:
    try:
        if current.is_symlink():
            return False
        if current.exists():
            current.resolve(strict=True).relative_to(root)
            return current.is_dir()
        if not create:
            return False
        current.mkdir(  # skylos: ignore[SKY-D215] bounded project-local cache directory
            mode=0o700
        )
        return True
    except (OSError, ValueError):
        return False


def _is_regular_cache_file(path: Path) -> bool:
    try:
        if path.is_symlink():
            return False
        if path.exists():
            path.resolve(strict=True).relative_to(path.parent.resolve(strict=True))
            return path.is_file()
    except (OSError, ValueError):
        return False
    return True


def load_project_json_cache(
    project_root: str | Path,
    cache_path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_CACHE_BYTES,
) -> dict[str, Any]:
    path = _project_cache_path(project_root, cache_path, create=False)
    if path is None:
        return {}

    text = read_text_no_symlink(path, max_bytes=max_bytes, encoding="utf-8")
    if text is None:
        return {}

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_project_json_cache(
    project_root: str | Path,
    cache_path: str | Path,
    payload: dict[str, Any],
) -> bool:
    path = _project_cache_path(project_root, cache_path, create=True)
    if path is None:
        return False

    temp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd: int | None = None
    try:
        fd = os.open(  # skylos: ignore[SKY-D215] guarded project-local cache temp path
            temp_path, flags, 0o600
        )
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = None
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink():
            return False
        os.replace(temp_path, path)
        return True
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            if temp_path.exists() and not temp_path.is_symlink():
                temp_path.unlink()
        except OSError:
            pass
