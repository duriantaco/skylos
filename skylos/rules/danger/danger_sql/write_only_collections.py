"""Statements built from SQLAlchemy write-only relationship collections.

``WriteOnlyCollection.select()/insert()/update()/delete()`` return Core
statements whose values travel as bound parameters, so
``db.session.execute(self.notifications.delete().where(...))`` is not SQL text.
The proof is narrow: the attribute is declared on the enclosing class with an
imported ``sqlalchemy.orm.WriteOnlyMapped`` annotation or
``sqlalchemy.orm.relationship(lazy="write_only")``, it is bound once in the
class body and never assigned through any receiver in the class, and it is
read through the first parameter of a plain method that never rebinds it.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass


_ORM_PREFIX = "sqlalchemy.orm"
_METHOD_DECORATORS_WITHOUT_INSTANCE = frozenset({"staticmethod", "classmethod"})


@dataclass(frozen=True)
class WriteOnlyReceiver:
    name: str
    attributes: frozenset[str]

    def owns(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == self.name
            and node.attr in self.attributes
        )


def _qualified(node: ast.AST) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _orm_name(node: ast.AST, resolve: Callable[[str], str | None], last: str) -> bool:
    name = _qualified(node)
    if name is None:
        return False
    resolved = resolve(name)
    return bool(
        resolved
        and resolved.startswith(_ORM_PREFIX)
        and resolved.rsplit(".", 1)[-1] == last
    )


def _write_only_annotation(annotation: ast.AST, resolve) -> bool:
    return isinstance(annotation, ast.Subscript) and _orm_name(
        annotation.value, resolve, "WriteOnlyMapped"
    )


def _write_only_relationship(value: ast.AST | None, resolve) -> bool:
    if not isinstance(value, ast.Call) or not _orm_name(
        value.func, resolve, "relationship"
    ):
        return False
    return any(
        keyword.arg == "lazy"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value == "write_only"
        for keyword in value.keywords
    )


def _class_body_bindings(class_node: ast.ClassDef) -> Counter:
    bindings: Counter = Counter()
    for statement in class_node.body:
        targets: list[ast.AST] = []
        if isinstance(statement, ast.Assign):
            targets = list(statement.targets)
        elif isinstance(statement, (ast.AnnAssign, ast.AugAssign)):
            targets = [statement.target]
        elif isinstance(
            statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            bindings[statement.name] += 1
            continue
        for target in targets:
            for node in ast.walk(target):
                if isinstance(node, ast.Name):
                    bindings[node.id] += 1
    return bindings


def _declared_write_only(class_node: ast.ClassDef, resolve) -> frozenset[str]:
    declared: set[str] = set()
    for statement in class_node.body:
        if isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target, ast.Name
        ):
            if _write_only_annotation(
                statement.annotation, resolve
            ) or _write_only_relationship(statement.value, resolve):
                declared.add(statement.target.id)
        elif (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and _write_only_relationship(statement.value, resolve)
        ):
            declared.add(statement.targets[0].id)
    if not declared:
        return frozenset()
    bindings = _class_body_bindings(class_node)
    assigned = {
        node.attr
        for node in ast.walk(class_node)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, (ast.Store, ast.Del))
    }
    return frozenset(
        name for name in declared if bindings[name] == 1 and name not in assigned
    )


def _decorator_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _instance_parameter(method: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    if any(
        _decorator_name(decorator) in _METHOD_DECORATORS_WITHOUT_INSTANCE
        for decorator in method.decorator_list
    ):
        return None
    positional = [*method.args.posonlyargs, *method.args.args]
    if not positional:
        return None
    name = positional[0].arg
    for node in ast.walk(method):
        if (
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return None
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return None
    return name


def write_only_methods(
    class_node: ast.ClassDef, resolve: Callable[[str], str | None]
) -> dict[int, WriteOnlyReceiver]:
    """Methods of ``class_node`` keyed by ``id`` with their proven receiver."""
    attributes = _declared_write_only(class_node, resolve)
    if not attributes:
        return {}
    methods: dict[int, WriteOnlyReceiver] = {}
    for statement in class_node.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        receiver = _instance_parameter(statement)
        if receiver is not None:
            methods[id(statement)] = WriteOnlyReceiver(receiver, attributes)
    return methods
