"""Shared literal and class-member evidence for web framework contracts."""

from __future__ import annotations

import ast


def _literal(node):
    return node.value if isinstance(node, ast.Constant) else None


def _assigned(node):
    if isinstance(node, ast.Assign):
        return node.targets, node.value
    if isinstance(node, ast.AnnAssign):
        return [node.target], node.value
    return [], None


def _main_guard(node):
    return (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "__name__"
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
        and len(node.comparators) == 1
        and _literal(node.comparators[0]) == "__main__"
    )


def _has_base(name, expected, classes, seen=None):
    if name in expected:
        return True
    seen = set() if seen is None else seen
    if name in seen or name not in classes:
        return False
    seen.add(name)
    return any(_has_base(base, expected, classes, seen) for base in classes[name][1])


def _member_value(members, name):
    return _assigned(members.get(name))[1]


def _member_names(value):
    if isinstance(value, (ast.Tuple, ast.List)):
        return {
            _literal(item) for item in value.elts if isinstance(_literal(item), str)
        }
    return set()


def _has_member(name, member, classes, seen=None):
    seen = set() if seen is None else seen
    if name in seen or name not in classes:
        return False
    seen.add(name)
    return member in classes[name][2] or any(
        _has_member(base, member, classes, seen) for base in classes[name][1]
    )


def _dict_values(node):
    if not isinstance(node, ast.Dict) or any(
        not isinstance(_literal(key), str) for key in node.keys
    ):
        return None
    return {_literal(key): value for key, value in zip(node.keys, node.values)}
