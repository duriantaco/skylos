"""Source-derived cleanup anchors, independent of line shifts."""

from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path

from skylos.core.safe_cache_io import read_project_text_no_symlink


def _syntax(source: str):
    tree = ast.parse(source)
    statements = tuple(node for node in ast.walk(tree) if isinstance(node, ast.stmt))
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    return statements, parents


def _statement_anchor(finding: dict, syntax) -> str | None:
    statements, parents = syntax
    line = finding.get("line", finding.get("lineno"))
    if type(line) is not int or line < 1:
        return None
    column = finding.get("col", finding.get("column"))
    candidates = [
        node
        for node in statements
        if node.lineno <= line <= getattr(node, "end_lineno", node.lineno)
    ]
    if not candidates:
        return None
    if type(column) is int:
        exact = [
            node
            for node in candidates
            if node.lineno == line and node.col_offset <= column
        ]
        if exact:
            candidates = exact
    target = min(
        candidates,
        key=lambda node: (
            getattr(node, "end_lineno", node.lineno) - node.lineno,
            -node.lineno,
            -node.col_offset,
        ),
    )
    owners = []
    current = target
    while current in parents:
        current = parents[current]
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            owners.append(current.name)
    return json.dumps(
        {
            "symbol": ".".join(reversed(owners)),
            "ast": ast.dump(target, include_attributes=False),
        },
        sort_keys=True,
        ensure_ascii=True,
    )


def source_anchor_from_text(finding: dict, source: str) -> str | None:
    """Anchor a scanner observation against its captured source snapshot."""
    try:
        return _statement_anchor(finding, _syntax(source))
    except (ValueError, TypeError, SyntaxError, RecursionError):
        return None


def source_anchor(
    finding: dict, root: str | Path, *, cache: dict | None = None
) -> str | None:
    """Return statement syntax and its lexical owner without source locations.

    Missing source, uncertain locations and project symlinks cannot produce an
    anchor. The optional cache belongs to one report build, never a later scan.
    """
    root = Path(root)
    if root.is_symlink():
        return None
    try:
        root = root.resolve(strict=True)
        file = Path(str(finding.get("file") or finding.get("file_path") or ""))
        if not file.is_absolute():
            file = root / file
        file.relative_to(root)
        if file.suffix not in {".py", ".pyi", ".pyw"}:
            return None
        key = (str(root), str(file))
        syntax = cache.get(key) if cache is not None else None
        if syntax is None:
            source = read_project_text_no_symlink(
                root, file, max_bytes=5_000_000, newline=""
            )
            if source is None:
                return None
            syntax = _syntax(source)
            if cache is not None:
                cache[key] = syntax
        return _statement_anchor(finding, syntax)
    except (OSError, ValueError, TypeError, SyntaxError, RecursionError):
        return None


def source_anchor_digest(
    finding: dict, root: str | Path, *, cache: dict | None = None
) -> str | None:
    anchor = source_anchor(finding, root, cache=cache)
    return sha256(anchor.encode("utf-8")).hexdigest() if anchor is not None else None
