"""Agent and editor config files as the agent or editor opens them.

ca9 walks the scanned folder without following symbolic links, so two kinds
of config it would miss are collected here and handed to ca9 as a temporary
copy under the path the client opens:

- configs reached through a link that stays inside the repository
  (``.claude -> tools/claude``, ``.claude/settings.json -> ../x.json``). A
  link that leaves the repository or points nowhere is a problem: the client
  may read it, Skylos cannot. Each real file is read once per client path,
  and only regular files Git lists are followed, so a link loop adds nothing.
- for a scan of a subfolder of a Git repository, the repository-level
  configs at its top (``.claude/``, ``.mcp.json``, ``.vscode/`` ...), which
  apply to every agent session opened at the top.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath

from skylos.core.safe_cache_io import read_project_text_no_symlink

AGENT_FOLDERS = frozenset(
    {
        ".claude",
        ".gemini",
        ".cursor",
        ".codex",
        ".vscode",
        ".kiro",
        ".roo",
        ".amazonq",
        ".windsurf",
    }
)
MAX_LINKED_FILES = 400
MAX_TEXT_BYTES = 2_000_000
MAX_WALK_ENTRIES = 50_000
_SKIP_DIRS = frozenset({".git", "node_modules", ".venv", "venv", "vendor"})


def agent_path(path: str) -> bool:
    pure = PurePosixPath(path)
    if pure.name == ".mcp.json" or pure.name.endswith(".code-workspace"):
        return True
    return any(part in AGENT_FOLDERS for part in pure.parts[:-1]) and pure.suffix in {
        ".json",
        ".toml",
    }


def repository_level(path: str) -> bool:
    """A config at the repository top: what an agent opened there reads."""
    pure = PurePosixPath(path)
    if not agent_path(path):
        return False
    return len(pure.parts) == 1 or pure.parts[0] in AGENT_FOLDERS


def link_candidate(path: str) -> bool:
    """A link whose own path names an agent folder or config."""
    return PurePosixPath(path).name in AGENT_FOLDERS or agent_path(path)


def contained(path: Path, top: Path) -> bool:
    real = Path(os.path.realpath(path))
    return real == top or real.is_relative_to(top)


def link_components(path: Path, top: Path) -> list[Path]:
    """The links on the way from ``top`` to ``path`` (written spelling)."""
    try:
        parts = Path(os.path.abspath(path)).relative_to(top).parts
    except ValueError:
        return []
    found = []
    current = top
    for part in parts:
        current = current / part
        if current.is_symlink():
            found.append(current)
    return found


def _walk_links(top: Path) -> list[str]:
    found = []
    seen = 0
    for directory, dirnames, filenames in os.walk(top, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        seen += len(dirnames) + len(filenames)
        base = Path(directory)
        for name in [*dirnames, *filenames]:
            relative = (base / name).relative_to(top).as_posix()
            if link_candidate(relative) and (base / name).is_symlink():
                found.append(relative)
        if seen > MAX_WALK_ENTRIES:
            break
    return sorted(found)


def _walk_files(directory: Path) -> list[Path]:
    found = []
    seen = 0
    for current, dirnames, filenames in os.walk(directory, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if name not in _SKIP_DIRS)
        seen += len(dirnames) + len(filenames)
        found.extend(Path(current) / name for name in sorted(filenames))
        if seen > MAX_WALK_ENTRIES:
            break
    return found


class LinkedConfigs:
    """Agent configs reached through links under ``scope`` (a folder inside
    ``top``, the repository or the scanned folder outside Git).

    ``files`` are the paths (relative to ``top``) Git lists, or None outside
    Git. ``texts`` maps the client path (relative to ``top``) to the target's
    text, ``real`` to the target, and ``problems`` lists links that leave
    ``top`` or point nowhere."""

    def __init__(self, top: Path, files: set[str] | None, scope: Path | None = None):
        self.top = Path(os.path.realpath(top))
        self.files = files
        self.scope = Path(os.path.realpath(scope or top))
        self.texts: dict[str, str] = {}
        self.real: dict[str, Path] = {}
        self.problems: list[dict] = []
        for link in self._links():
            self._follow(link)

    def _links(self) -> list[str]:
        try:
            prefix = self.scope.relative_to(self.top).as_posix()
        except ValueError:
            return []
        if self.files is None:
            found = _walk_links(self.scope)
            if prefix == ".":
                return found
            return [f"{prefix}/{link}" for link in found]
        candidates = []
        for path in sorted(self.files):
            if prefix != "." and not path.startswith(prefix + "/"):
                continue
            if link_candidate(path) and (self.top / path).is_symlink():
                candidates.append(path)
        return candidates

    def _follow(self, link: str) -> None:
        path = self.top / link
        target = Path(os.path.realpath(path))
        if not target.exists():
            self.problems.append({"file": link, "reason": "points to a missing file"})
            return
        if not contained(target, self.top):
            self.problems.append(
                {"file": link, "reason": "points outside the repository"}
            )
            return
        if target.is_file():
            if agent_path(link):
                self._add(link, target)
            return
        if not target.is_dir():
            return
        for real in self._under(target):
            client = f"{link}/{real.relative_to(target).as_posix()}"
            if agent_path(client):
                self._add(client, real)

    def _under(self, directory: Path) -> Iterable[Path]:
        if self.files is None:
            return _walk_files(directory)
        prefix = directory.relative_to(self.top).as_posix()
        found = []
        for path in sorted(self.files):
            if prefix == "." or path.startswith(prefix + "/"):
                found.append(self.top / path)
        return found

    def _add(self, client: str, real: Path) -> None:
        if client in self.texts or real.is_symlink() or not real.is_file():
            return
        if self.files is not None and (
            real.relative_to(self.top).as_posix() not in self.files
        ):
            return
        if len(self.texts) >= MAX_LINKED_FILES:
            if not any(item["file"] == client for item in self.problems):
                self.problems.append(
                    {"file": client, "reason": "too many linked config files"}
                )
            return
        text = read_text(self.top, real)
        if text is None:
            self.problems.append({"file": client, "reason": "target is unreadable"})
            return
        self.texts[client] = text
        self.real[client] = real


def read_text(top: Path, real: Path) -> str | None:
    """A bounded read of a regular file inside ``top`` (the resolved target)."""
    try:
        relative = Path(os.path.realpath(real)).relative_to(top).as_posix()
    except ValueError:
        return None
    return read_project_text_no_symlink(top, relative, max_bytes=MAX_TEXT_BYTES)


def repository_texts(top: Path, files: set[str] | None) -> dict[str, str]:
    """Regular repository-level config files at ``top`` (see ``repository_level``)."""
    if files is None:
        return {}
    texts = {}
    for path in sorted(files):
        if not repository_level(path):
            continue
        if link_components(top / path, top):
            continue
        text = read_project_text_no_symlink(top, path, max_bytes=MAX_TEXT_BYTES)
        if text is not None:
            texts[path] = text
        if len(texts) >= MAX_LINKED_FILES:
            break
    return texts


def call_on_copy(api, function: str, texts: dict[str, str], call: Callable):
    """``call(api, function, folder)`` on a temporary copy of ``texts``."""
    if not texts:
        return None, None
    with tempfile.TemporaryDirectory(prefix="skylos-agent-config-") as temp:
        folder = Path(temp)
        for name, text in texts.items():
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        return call(api, function, folder)


__all__ = [
    "AGENT_FOLDERS",
    "LinkedConfigs",
    "agent_path",
    "call_on_copy",
    "contained",
    "link_candidate",
    "link_components",
    "read_text",
    "repository_level",
    "repository_texts",
]
