"""Python code in Jupyter notebooks, read as reference evidence only.

Only code cells count; outputs and markdown are text. Cell magics and shell
escapes (``%timeit``, ``!pip``) are not Python and are dropped before a cell
is parsed. A cell that does not parse is skipped rather than guessed at.
"""

from __future__ import annotations

import ast
import json
from functools import lru_cache
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink

_MAX_NOTEBOOK_BYTES = 8_000_000
_NON_PYTHON_PREFIXES = ("%", "!", "?")


def _cell_source(cell: dict) -> str:
    source = cell.get("source", "")
    if isinstance(source, list):
        source = "".join(part for part in source if isinstance(part, str))
    if not isinstance(source, str):
        return ""
    return "\n".join(
        line
        for line in source.splitlines()
        if not line.lstrip().startswith(_NON_PYTHON_PREFIXES)
    )


def notebook_tree(text: str) -> ast.Module | None:
    """One module holding every code cell that parses, or None."""
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return None
    cells = document.get("cells") if isinstance(document, dict) else None
    if not isinstance(cells, list):
        return None
    body: list[ast.stmt] = []
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        try:
            body.extend(ast.parse(_cell_source(cell)).body)
        except (SyntaxError, ValueError, RecursionError):
            continue
    return ast.Module(body=body, type_ignores=[])


def _names_in(tree: ast.Module) -> frozenset[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.alias):
            names.add(node.name.rsplit(".", 1)[-1])
            if node.asname:
                names.add(node.asname)
    return frozenset(names)


@lru_cache(maxsize=256)
def _cached_names(path: str, _mtime_ns: int, _size: int) -> frozenset[str]:
    text = read_text_no_symlink(
        path, max_bytes=_MAX_NOTEBOOK_BYTES, encoding="utf-8", errors="ignore"
    )
    if not text:
        return frozenset()
    tree = notebook_tree(text)
    if tree is None:
        return frozenset()
    return _names_in(tree)


def notebook_code_names(path: str | Path) -> frozenset[str]:
    """Names, attributes and imported names used by the notebook's code."""
    try:
        stat_result = Path(path).stat()
    except OSError:
        return frozenset()
    return _cached_names(str(path), stat_result.st_mtime_ns, stat_result.st_size)


def is_notebook(path: str | Path) -> bool:
    return str(path).lower().endswith(".ipynb")
