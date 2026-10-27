"""Statements built from SQLAlchemy write-only relationship collections.

``WriteOnlyCollection.select()/insert()/update()/delete()`` return Core
statements whose values travel as bound parameters, so
``db.session.execute(self.notifications.delete().where(...))`` is not SQL text.
The proof is narrow: the attribute has an imported ``sqlalchemy.orm.relationship``
initializer with a ``WriteOnlyMapped`` annotation or explicit ``lazy="write_only"``.
It is bound once in the class body, has no source-visible receiver replacement,
and is read through an unrebound first parameter of an undecorated instance
method. Known local bases and bounded attribute-update loops are checked too.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass


_ORM_PREFIX = "sqlalchemy.orm"


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
        and resolved.startswith(_ORM_PREFIX + ".")
        and resolved.rsplit(".", 1)[-1] == last
    )


def _write_only_annotation(annotation: ast.AST, resolve) -> bool:
    return isinstance(annotation, ast.Subscript) and _orm_name(
        annotation.value, resolve, "WriteOnlyMapped"
    )


def _write_only_relationship(
    value: ast.AST | None, resolve, *, annotated=False
) -> bool:
    if not isinstance(value, ast.Call) or not _orm_name(
        value.func, resolve, "relationship"
    ):
        return False
    if any(keyword.arg is None for keyword in value.keywords):
        return False
    lazy = [keyword.value for keyword in value.keywords if keyword.arg == "lazy"]
    if not lazy:
        return annotated
    return (
        len(lazy) == 1
        and isinstance(lazy[0], ast.Constant)
        and lazy[0].value == "write_only"
    )


def _class_body_bindings(class_node: ast.ClassDef) -> Counter:
    bindings: Counter = Counter()
    pending = list(class_node.body)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings[node.name] += 1
            continue
        bindings.update(_binding_names(node))
        if not isinstance(node, ast.Lambda):
            pending.extend(ast.iter_child_nodes(node))
    return bindings


def _binding_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return (node.name,)
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return (node.id,)
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return tuple(alias.asname or alias.name.split(".")[0] for alias in node.names)
    if isinstance(node, ast.ExceptHandler) and node.name:
        return (node.name,)
    if isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
        return (node.name,)
    if isinstance(node, ast.MatchMapping) and node.rest:
        return (node.rest,)
    return ()


def _setattr_names(call, parents):
    if len(call.args) < 2:
        return None
    name = call.args[1]
    if isinstance(name, ast.Constant) and isinstance(name.value, str):
        return {name.value}
    if not isinstance(name, ast.Name):
        return None
    current = parents.get(call)
    while current is not None and not isinstance(
        current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
    ):
        if (
            isinstance(current, ast.For)
            and isinstance(current.target, ast.Name)
            and current.target.id == name.id
        ):
            if not any(call in ast.walk(statement) for statement in current.body):
                return None
            values = current.iter
            if not isinstance(values, (ast.List, ast.Tuple, ast.Set)) or not all(
                isinstance(item, ast.Constant) and isinstance(item.value, str)
                for item in values.elts
            ):
                return None
            for statement in current.body:
                for node in ast.walk(statement):
                    if name.id in _binding_names(node) or (
                        isinstance(node, (ast.Global, ast.Nonlocal))
                        and name.id in node.names
                    ):
                        return None
            return {item.value for item in values.elts}
        current = parents.get(current)
    return None


def _local_receiver_classes(class_node, mutation_scope):
    indexed = {}
    for node in ast.walk(mutation_scope):
        if isinstance(node, ast.ClassDef):
            indexed.setdefault(node.name, []).append(node)
    pending = [class_node]
    seen = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current.decorator_list or any(
            isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
            and statement.name == "__getattribute__"
            for statement in current.body
        ):
            return None
        for base in current.bases:
            if not isinstance(base, (ast.Name, ast.Attribute)):
                return None
            if isinstance(base, ast.Name):
                candidates = indexed.get(base.id, [])
                if len(candidates) > 1:
                    return None
                pending.extend(candidates)
    return seen


def _declared_write_only(
    class_node: ast.ClassDef, resolve, mutation_scope
) -> frozenset[str]:
    bindings = _class_body_bindings(class_node)
    outer_resolve = resolve

    def resolve(name):
        return None if name.split(".")[0] in bindings else outer_resolve(name)

    declared: set[str] = set()
    for statement in class_node.body:
        if isinstance(statement, ast.AnnAssign) and isinstance(
            statement.target, ast.Name
        ):
            if _write_only_relationship(
                statement.value,
                resolve,
                annotated=_write_only_annotation(statement.annotation, resolve),
            ):
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
    receiver_classes = _local_receiver_classes(class_node, mutation_scope)
    if receiver_classes is None:
        return frozenset()
    local_nodes = {node for owner in receiver_classes for node in ast.walk(owner)}
    receivers = {class_node.name}
    for node in ast.walk(mutation_scope):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if (
                isinstance(node.value.func, ast.Name)
                and node.value.func.id == class_node.name
            ):
                receivers.update(
                    target.id for target in node.targets if isinstance(target, ast.Name)
                )
    assigned = set()
    parents = {
        child: node
        for node in ast.walk(mutation_scope)
        for child in ast.iter_child_nodes(node)
    }
    for node in ast.walk(mutation_scope):
        if isinstance(node, ast.Attribute) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            if node in local_nodes or (
                isinstance(node.value, ast.Name) and node.value.id in receivers
            ):
                assigned.add(node.attr)
        if not isinstance(node, ast.Call):
            continue
        if _qualified(node.func) in {
            "setattr",
            "delattr",
            "builtins.setattr",
            "builtins.delattr",
        }:
            owner = node.args[0] if node.args else None
            if node not in local_nodes and not (
                isinstance(owner, ast.Name) and owner.id in receivers
            ):
                continue
            names = _setattr_names(node, parents)
            if names is None:
                return frozenset()
            assigned.update(names)
        elif _qualified(node.func) in {"exec", "builtins.exec"}:
            return frozenset()
    if bindings["__getattribute__"]:
        return frozenset()
    return frozenset(
        name for name in declared if bindings[name] == 1 and name not in assigned
    )


def _instance_parameter(method: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    if method.decorator_list:
        return None
    positional = [*method.args.posonlyargs, *method.args.args]
    if not positional:
        return None
    name = positional[0].arg
    for node in ast.walk(method):
        if node is not method and name in _binding_names(node):
            return None
        if isinstance(node, (ast.Global, ast.Nonlocal)) and name in node.names:
            return None
    return name


def write_only_methods(
    class_node: ast.ClassDef,
    resolve: Callable[[str], str | None],
    mutation_scope: ast.AST,
) -> dict[int, WriteOnlyReceiver]:
    """Methods of ``class_node`` keyed by ``id`` with their proven receiver."""
    attributes = _declared_write_only(class_node, resolve, mutation_scope)
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
