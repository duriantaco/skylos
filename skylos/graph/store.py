from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

GRAPH_DIR = Path(".skylos") / "graph"
GRAPH_FILE = "graph.json"
CACHE_FILE = "cache.json"
NOTES_FILE = "notes.json"
CHANGES_FILE = "changes.json"
AREAS_FILE = "areas.json"
GITIGNORE = "*\n!.gitignore\n!notes.json\n"


def graph_dir(root: str | Path) -> Path:
    return Path(root) / GRAPH_DIR


def ensure_dir(root: str | Path) -> Path:
    directory = graph_dir(root)
    for part in (Path(root) / ".skylos", directory):
        if part.is_symlink():
            raise ValueError(f"Refusing to write through the symlink {part}: remove it or point Skylos at a different folder")
    directory.mkdir(parents=True, exist_ok=True)
    ignore = directory / ".gitignore"
    if not ignore.exists():
        ignore.write_text(GITIGNORE, encoding="utf-8")
    return directory


def write_json(path: Path, data, *, indent: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    separators = (",", ":")
    if indent:
        separators = None
    handle, temp = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            json.dump(data, out, ensure_ascii=False, indent=indent, separators=separators)
        os.chmod(temp, 0o644)
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def read_json(path: Path):
    try:
        with open(path, encoding="utf-8") as handle:  # skylos: ignore[SKY-D215,SKY-D325] fixed file names under .skylos/graph; ensure_dir refuses a symlinked .skylos or graph folder
            return json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return None


def load_graph(root: str | Path) -> dict | None:
    data = read_json(graph_dir(root) / GRAPH_FILE)
    if isinstance(data, dict) and isinstance(data.get("nodes"), list):
        return data
    return None


def load_notes(root: str | Path) -> dict:
    data = read_json(graph_dir(root) / NOTES_FILE)
    if isinstance(data, dict) and isinstance(data.get("nodes"), dict):
        data.setdefault("changes", {})
        return data
    return {"schema_version": 1, "nodes": {}, "changes": {}}


def save_notes(root: str | Path, notes: dict) -> None:
    ensure_dir(root)
    write_json(graph_dir(root) / NOTES_FILE, notes, indent=1)


def load_changes(root: str | Path) -> dict | None:
    data = read_json(graph_dir(root) / CHANGES_FILE)
    if isinstance(data, dict) and isinstance(data.get("symbols"), list):
        return data
    return None
