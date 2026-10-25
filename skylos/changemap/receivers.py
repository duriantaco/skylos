from __future__ import annotations

import ast

from skylos.changemap.facts import FUNCTION_NODES, dotted

_WRAPPERS = frozenset({"Optional", "Union", "Annotated", "Final", "ClassVar", "Required", "NotRequired", "ReadOnly"})
_OWN = frozenset({"self", "cls"})


def _simple(name: str | None) -> str:
    return (name or "").rsplit(".", 1)[-1]


def _subscript_names(annotation: ast.Subscript) -> set[str]:
    wrapper = _simple(dotted(annotation.value))
    if wrapper not in _WRAPPERS:
        return set()
    items = [annotation.slice]
    if isinstance(annotation.slice, ast.Tuple):
        items = list(annotation.slice.elts)
    if wrapper == "Annotated":
        items = items[:1]
    found = set()
    for item in items:
        found |= type_names(item)
    return found


def _string_names(text: str) -> set[str]:
    try:
        return type_names(ast.parse(text, mode="eval").body)
    except SyntaxError:
        return set()


def _constant_names(annotation: ast.AST) -> set[str]:
    return _string_names(annotation.value)


def _union_names(annotation: ast.AST) -> set[str]:
    return type_names(annotation.left) | type_names(annotation.right)


def _is_string(annotation: ast.AST) -> bool:
    return isinstance(annotation, ast.Constant) and isinstance(annotation.value, str)


def _is_union(annotation: ast.AST) -> bool:
    return isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr)


_SHAPES = (
    (_is_string, _constant_names),
    (_is_union, _union_names),
    (lambda a: isinstance(a, ast.Subscript), _subscript_names),
)


def type_names(annotation: ast.AST | None) -> set[str]:
    if annotation is None:
        return set()
    for matches, names in _SHAPES:
        if matches(annotation):
            return names(annotation)
    name = _simple(dotted(annotation))
    return {name} - {"", "None"}


def _created(value: ast.AST) -> set[str]:
    if isinstance(value, ast.Call):
        name = _simple(dotted(value.func))
        if name:
            return {name}
    return set()


def _add(env: dict[str, set[str]], name: str, types: set[str]) -> None:
    if types:
        env.setdefault(name, set()).update(types)


def _record_local(child: ast.AST, env: dict[str, set[str]]) -> None:
    if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
        _add(env, child.target.id, type_names(child.annotation))
    elif isinstance(child, ast.Assign):
        created = _created(child.value)
        for target in child.targets:
            if isinstance(target, ast.Name):
                _add(env, target.id, created)


def function_env(node: ast.AST) -> dict[str, set[str]]:
    env: dict[str, set[str]] = {}
    if not isinstance(node, FUNCTION_NODES):
        return env
    args = node.args
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        _add(env, arg.arg, type_names(arg.annotation))
    for child in ast.walk(node):
        _record_local(child, env)
    return env


def _self_attribute(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "self":
        return node.attr
    return None


def _assigned_type(value: ast.AST, params: dict[str, set[str]]) -> set[str]:
    if isinstance(value, ast.Name):
        return params.get(value.id, set())
    return _created(value)


def _record_attribute(child: ast.AST, params: dict[str, set[str]], env: dict[str, set[str]]) -> None:
    if isinstance(child, ast.AnnAssign) and _self_attribute(child.target):
        _add(env, _self_attribute(child.target), type_names(child.annotation))
    elif isinstance(child, ast.Assign):
        types = _assigned_type(child.value, params)
        for attribute in filter(None, map(_self_attribute, child.targets)):
            _add(env, attribute, types)


def _method_assignments(method: ast.AST, env: dict[str, set[str]]) -> None:
    params = function_env(method)
    for child in ast.walk(method):
        _record_attribute(child, params, env)


def defines_member(class_node: ast.ClassDef | None, member: str) -> bool:
    if not isinstance(class_node, ast.ClassDef):
        return False
    for stmt in class_node.body:
        if isinstance(stmt, FUNCTION_NODES) and stmt.name == member:
            return True
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and member in {t.id for t in ast.walk(stmt) if isinstance(t, ast.Name) and isinstance(t.ctx, ast.Store)}:
            return True
    return False


def class_env(class_node: ast.ClassDef | None) -> dict[str, set[str]]:
    env: dict[str, set[str]] = {}
    if not isinstance(class_node, ast.ClassDef):
        return env
    for stmt in class_node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            _add(env, stmt.target.id, type_names(stmt.annotation))
        elif isinstance(stmt, FUNCTION_NODES):
            _method_assignments(stmt, env)
    return env


def class_identity(class_node: ast.ClassDef | None) -> set[str]:
    if not isinstance(class_node, ast.ClassDef):
        return set()
    return {class_node.name} | {_simple(dotted(base)) for base in class_node.bases} - {""}


def receiver_types(receiver: ast.AST, local: dict, attributes: dict, own: set[str]) -> set[str]:
    if isinstance(receiver, ast.Name):
        if receiver.id in _OWN:
            return own
        return local.get(receiver.id, set())
    attribute = _self_attribute(receiver)
    if attribute:
        return attributes.get(attribute, set())
    return set()


def member_uses(node: ast.AST, member: str, *, is_property: bool) -> list[tuple[int, ast.AST]]:
    uses = []
    for child in ast.walk(node):
        if is_property and isinstance(child, ast.Attribute) and child.attr == member and isinstance(child.ctx, ast.Load):
            uses.append((child.lineno, child.value))
        elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute) and child.func.attr == member:
            uses.append((child.lineno, child.func.value))
    return sorted(uses, key=lambda item: item[0])
