from __future__ import annotations

from collections.abc import Iterator
from contextlib import chdir, contextmanager
from pathlib import Path


@contextmanager
def command_project_context(project_root: Path) -> Iterator[None]:
    """Bind cwd-based Cloud helpers to the scanned project, then restore cwd."""
    with chdir(project_root):
        yield
