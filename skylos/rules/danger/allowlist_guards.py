"""`if value not in FIXED: raise`, the check OWASP names for values that cannot be bound."""

from __future__ import annotations

import ast

EXIT_CALLS = frozenset({"abort", "flask.abort", "exit", "sys.exit"})


def always_exits(body: list[ast.stmt]) -> bool:
    last = body[-1]
    if isinstance(last, (ast.Raise, ast.Return, ast.Continue, ast.Break)):
        return True
    if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
        return _dotted(last.value.func) in EXIT_CALLS
    return False


def not_in_terms(test: ast.AST) -> list[tuple[str, ast.AST]]:
    """``(name, collection)`` for each ``name not in collection`` that must all hold after the guard."""
    terms = [test]
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
        terms = list(test.values)
    found = []
    for term in terms:
        if (
            isinstance(term, ast.Compare)
            and len(term.ops) == 1
            and isinstance(term.ops[0], ast.NotIn)
            and isinstance(term.left, ast.Name)
        ):
            found.append((term.left.id, term.comparators[0]))
    return found


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""
