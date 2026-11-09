"""What one Python class body binds, read with ``ast``, and why more may exist."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass, field

from skylos.rules.sca.python_module_reader import (
    FUNCTION_NODES,
    SCOPE_NODES,
    Binding,
    assigned_names,
    call_name,
    first_parameter,
    is_namespace_call,
)

_TRY_NODES = (ast.Try, ast.TryStar)
_CLASS_NAMESPACE_CALLS = frozenset({"vars", "locals"})
_PLAIN_CLASS_DECORATORS = frozenset(
    {"dataclass", "final", "runtime_checkable", "total_ordering", "unique"}
)
_CLOSED_METACLASSES = frozenset({"ABCMeta", "type"})
_PROPERTY_DECORATORS = frozenset(
    {"property", "cached_property", "setter", "getter", "deleter"}
)


@dataclass
class ClassBody:
    members: dict[str, list[Binding]] = field(default_factory=dict)
    fields: set[str] = field(default_factory=set)
    open_reason: str = ""
    is_dataclass: bool = False


def _class_writes_attributes(node: ast.ClassDef) -> bool:
    pending = list(node.body)
    while pending:
        item = pending.pop()
        if isinstance(item, SCOPE_NODES):
            continue
        if (
            isinstance(item, ast.Subscript)
            and isinstance(item.ctx, ast.Store)
            and is_namespace_call(item.value, _CLASS_NAMESPACE_CALLS)
        ):
            return True
        pending.extend(ast.iter_child_nodes(item))
    return False


def _is_property(node: ast.AST) -> bool:
    return any(call_name(item) in _PROPERTY_DECORATORS for item in node.decorator_list)


def _add_class_function(body: ClassBody, node: ast.AST) -> None:
    kind = "function"
    if _is_property(node):
        kind = "value"
    body.members.setdefault(node.name, []).append(Binding(kind, node=node))


def _add_class_assignment(
    body: ClassBody, target: ast.expr, value: ast.expr | None
) -> None:
    expression = None
    if isinstance(value, (ast.Name, ast.Attribute)):
        expression = value
    for name in assigned_names(target):
        if name == "__slots__" and value is not None:
            for item in ast.walk(value):
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    body.members.setdefault(item.value, []).append(Binding("value"))
        body.members.setdefault(name, []).append(
            Binding("value", expression=expression)
        )


def _nested_statements(node: ast.stmt) -> list[ast.stmt]:
    if isinstance(node, ast.If):
        return [*node.body, *node.orelse]
    if isinstance(node, _TRY_NODES):
        handlers = [item for handler in node.handlers for item in handler.body]
        return [*node.body, *handlers, *node.orelse]
    if isinstance(node, (ast.With, ast.AsyncWith)):
        return list(node.body)
    return []


def _read_class_statements(body: ClassBody, statements: Iterable[ast.stmt]) -> None:
    for node in statements:
        if isinstance(node, FUNCTION_NODES):
            _add_class_function(body, node)
        elif isinstance(node, ast.ClassDef):
            body.members.setdefault(node.name, []).append(Binding("class", node=node))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                _add_class_assignment(body, target, node.value)
        elif isinstance(node, ast.AnnAssign):
            _add_class_assignment(body, node.target, node.value)
            if isinstance(node.target, ast.Name):
                body.fields.add(node.target.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                name = (alias.asname or alias.name).split(".", 1)[0]
                body.members.setdefault(name, []).append(Binding("value"))
        else:
            _read_class_statements(body, _nested_statements(node))


def _add_instance_attributes(body: ClassBody, node: ast.ClassDef) -> None:
    for method in node.body:
        first = ""
        if isinstance(method, FUNCTION_NODES):
            first = first_parameter(method)
        if not first:
            continue
        for item in ast.walk(method):
            if (
                isinstance(item, ast.Attribute)
                and isinstance(item.ctx, ast.Store)
                and isinstance(item.value, ast.Name)
                and item.value.id == first
            ):
                body.members.setdefault(item.attr, []).append(Binding("value"))


def _class_open_reason(body: ClassBody, node: ast.ClassDef) -> str:
    reason = ""
    for decorator in node.decorator_list:
        name = call_name(getattr(decorator, "func", decorator))
        if name == "dataclass":
            body.is_dataclass = True
        elif name not in _PLAIN_CLASS_DECORATORS:
            reason = f"the class uses the decorator {name or 'expression'}"
    for keyword in node.keywords:
        if (
            keyword.arg == "metaclass"
            and call_name(keyword.value) not in _CLOSED_METACLASSES
        ):
            reason = "the class has a custom metaclass"
    for name in ("__getattr__", "__getattribute__"):
        if name in body.members:
            reason = f"the class defines {name}"
    if _class_writes_attributes(node):
        reason = "the class writes attributes through locals()"
    return reason


def read_class(node: ast.ClassDef) -> ClassBody:
    """Members a class body and its methods bind, and why more may exist."""
    body = ClassBody()
    _read_class_statements(body, node.body)
    _add_instance_attributes(body, node)
    body.open_reason = _class_open_reason(body, node)
    return body
