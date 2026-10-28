"""How the CLI prints a file or folder path to the user."""

from __future__ import annotations

from pathlib import Path


def shown_path(path) -> str:
    """Relative to the current folder when inside it, ``~/...`` under the home
    folder, otherwise the path as given."""
    target = Path(path)
    try:
        resolved = target.resolve()
    except (OSError, RuntimeError):
        return str(path)
    try:
        relative = resolved.relative_to(Path.cwd().resolve())
    except (OSError, ValueError):
        relative = None
    if relative is not None:
        if str(relative) == ".":
            return resolved.name or str(path)
        return str(relative)
    try:
        return f"~/{resolved.relative_to(Path.home().resolve())}"
    except (OSError, RuntimeError, ValueError):
        return str(path)
