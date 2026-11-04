"""Whether code that moved to another module still finds every name it reads.

A function moved verbatim keeps its logic only if the module it moved to
defines or imports every global name the function reads. A constant or helper
left behind in the old module would make the moved code fail at run time,
even though its text is identical.
"""

from __future__ import annotations

import ast
import builtins
import textwrap

_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_BUILTINS = frozenset(dir(builtins)) | {"__name__", "__file__", "__doc__", "__spec__", "__package__", "__builtins__"}


def _parse(code: str):
    try:
        return ast.parse(textwrap.dedent(code))
    except (SyntaxError, ValueError, RecursionError):
        return None


def _stored(tree) -> set[str]:
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.alias):
            names.add((node.asname or node.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
    return names


def _loaded(tree) -> set[str]:
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}


def free_names(code: str) -> set[str] | None:
    tree = _parse(code)
    if tree is None:
        return None
    return _loaded(tree) - _stored(tree) - _BUILTINS


def module_names(source: str) -> set[str] | None:
    tree = _parse(source)
    if tree is None:
        return None
    names = set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            return None
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
        elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For, ast.With, ast.If, ast.Try)):
            names.update(n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
    return names


def unresolved_names(code: str, module_source: str) -> list[str] | None:
    reads = free_names(code)
    available = module_names(module_source)
    if reads is None or available is None:
        return None
    return sorted(reads - available)
