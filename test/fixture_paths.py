"""Contained fixture I/O; provider and source files are never imported.

The caller supplies a pytest-owned directory as the trust anchor. Descendants
are opened relative to held, no-follow directory descriptors when supported.
Other platforms use checked private directories and Skylos's output-file guard.
"""

from contextlib import contextmanager
import os
from pathlib import Path, PureWindowsPath
import stat

from skylos.core.safe_cache_io import _open_output_file


def _fixture_path(root, relative):
    root = Path(root).resolve(strict=True)
    if isinstance(relative, str) and "\\" in relative:
        raise ValueError("fixture string paths must use forward slashes")
    relative = Path(relative)
    windows = PureWindowsPath(str(relative))
    if relative.is_absolute() or windows.drive or windows.root:
        raise ValueError("fixture path must be relative")
    for component in relative.parts:
        if component == ".." or "\\" in component:
            raise ValueError("fixture path must stay within its root")
    path = root / relative
    path.resolve().relative_to(root)
    return root, relative, path


@contextmanager
def _fixture_directory(root, relative):
    if (
        os.open not in os.supports_dir_fd
        or os.mkdir not in os.supports_dir_fd
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        current = root
        for component in relative.parts:
            current = current / component
            if current.is_symlink():
                raise ValueError("fixture directory must not be a symlink")
            current.resolve().relative_to(root)
            current.mkdir(mode=0o700, exist_ok=True)
            if current.is_symlink() or not current.is_dir():
                raise ValueError("fixture output requires a real directory")
        yield None
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(os.path.sep, flags)
    try:
        for component in root.parts[1:]:
            following = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        for component in relative.parts:
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            following = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        yield descriptor
    finally:
        os.close(descriptor)


def make_fixture_directory(root, relative="."):
    root, relative, path = _fixture_path(root, relative)
    with _fixture_directory(root, relative):
        pass
    return path


def write_fixture(root, relative, content, *, overwrite=False):
    """Create a fixture; replacing an existing regular file requires opt-in."""
    root, relative, path = _fixture_path(root, relative)
    basename = Path(relative).name
    if not basename:
        raise ValueError("fixture file requires a basename")
    if isinstance(content, str):
        content = content.encode("utf-8")
    elif not isinstance(content, bytes):
        raise TypeError("fixture content must be text or bytes")
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    if not overwrite:
        flags |= os.O_EXCL
    with _fixture_directory(root, relative.parent) as directory:
        if directory is not None:
            descriptor = os.open(basename, flags, 0o600, dir_fd=directory)
        elif overwrite:
            descriptor = _open_output_file(path)
            if descriptor is None:
                raise ValueError("fixture output cannot be opened safely")
        else:
            path.resolve().relative_to(root)
            descriptor = os.open(path, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise ValueError("fixture output must be a regular single-link file")
            os.ftruncate(descriptor, 0)
            with os.fdopen(descriptor, "wb") as output:
                descriptor = None
                output.write(content)
        finally:
            if descriptor is not None:
                os.close(descriptor)
    return path
