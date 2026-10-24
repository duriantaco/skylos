"""Function-local Python bindings for dead-code verification.

A name bound inside a function (and not declared ``global`` or ``nonlocal``)
can only be read by that function and the functions nested in it, or by code
that inspects the frame's ``f_locals`` by name. Equal spellings anywhere else
belong to other bindings and cannot keep the local alive.
"""

from __future__ import annotations

import ast
import functools
from pathlib import Path

from skylos.core.safe_cache_io import read_text_no_symlink

_MAX_SOURCE_BYTES = 2_000_000
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef)


def parsed_python_source(file_path: str):
    try:
        stat_result = Path(file_path).stat()
    except OSError:
        return None
    return _parse_cached(str(file_path), stat_result.st_mtime_ns, stat_result.st_size)


@functools.lru_cache(maxsize=64)
def _parse_cached(file_path: str, _mtime_ns: int, _size: int):
    source = read_text_no_symlink(file_path, max_bytes=_MAX_SOURCE_BYTES)
    if source is None:
        return None
    try:
        return ast.parse(source)
    except (SyntaxError, ValueError):
        return None


def _binds_at(node: ast.AST, name: str, line: int) -> bool:
    if isinstance(node, ast.Name):
        return (
            node.id == name and isinstance(node.ctx, ast.Store) and node.lineno == line
        )
    if isinstance(node, ast.ExceptHandler):
        return node.name == name and node.lineno == line
    return False


def local_binding_owner(file_path: str, name: str, line: int):
    """The innermost function that binds ``name`` at ``line``, or None."""
    tree = parsed_python_source(file_path)
    if tree is None or not name or not isinstance(line, int):
        return None
    owner = None
    for node in ast.walk(tree):
        if not isinstance(node, _SCOPES):
            continue
        end = getattr(node, "end_lineno", None)
        if end is None or not node.lineno <= line <= end:
            continue
        if owner is None or node.lineno > owner.lineno:
            owner = node
    if owner is None:
        return None
    binds = False
    for node in ast.walk(owner):
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return None
        if _binds_at(node, name, line):
            binds = True
    if not binds:
        return None
    return owner


def local_binding_span(file_path: str, name: str, line: int):
    owner = local_binding_owner(file_path, name, line)
    if owner is None:
        return None
    return owner.lineno, owner.end_lineno


def local_binding_reads(file_path: str, name: str, line: int):
    """Line numbers where the owning function (or a nested one) reads ``name``.

    Returns None when ``name`` is not a function-local binding at ``line``.
    """
    owner = local_binding_owner(file_path, name, line)
    if owner is None:
        return None
    return sorted(
        {
            node.lineno
            for node in ast.walk(owner)
            if isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, ast.Load)
        }
    )
