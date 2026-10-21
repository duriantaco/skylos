from __future__ import annotations

import ast
import sys


_REGISTRATION_METHOD_NAMES = {
    "add",
    "append",
    "connect",
    "listen",
    "register",
    "register_type_strategy",
    "setdefault",
}


_CONTAINER_FACTORIES = frozenset({"list", "set", "dict"})


def collect_local_registration_decorators(node: ast.Module) -> set[str]:
    decorators = set()
    for stmt in node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_registration_decorator(stmt):
                decorators.add(stmt.name)
    decorators |= _bound_registration_methods(node)
    decorators |= _imported_instances(node)
    return decorators


def _imported_instances(node: ast.Module) -> set[str]:
    opaque = set()
    for stmt in node.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if not _is_standard_library(alias.name):
                    opaque.add(alias.asname or alias.name.split(".", 1)[0])
        elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0 and stmt.module:
            if not _is_standard_library(stmt.module):
                for alias in stmt.names:
                    opaque.add(alias.asname or alias.name)
    assigned: dict[str, int] = {}
    for stmt in node.body:
        for target in _assigned_names(stmt):
            assigned[target] = assigned.get(target, 0) + 1
    instances = set()
    for stmt in node.body:
        target, value = _single_assignment(stmt)
        if target is None or assigned.get(target) != 1 or not isinstance(value, ast.Call):
            continue
        root = value.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in opaque:
            instances.add(target)
    return instances


def _is_standard_library(module: str) -> bool:
    return module.split(".", 1)[0] in sys.stdlib_module_names


def _assigned_names(stmt: ast.AST) -> list[str]:
    names = []
    for node in ast.walk(stmt):
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            names.append(node.id)
    return names


def _bound_registration_methods(node: ast.Module) -> set[str]:
    containers = set()
    assignments = []
    for stmt in node.body:
        target, value = _single_assignment(stmt)
        if target is None:
            continue
        if _is_empty_container(value):
            containers.add(target)
        assignments.append((target, value))
    bound = set()
    for target, value in assignments:
        if (
            isinstance(value, ast.Attribute)
            and value.attr in _REGISTRATION_METHOD_NAMES
            and isinstance(value.value, ast.Name)
            and value.value.id in containers
        ):
            bound.add(target)
    return bound


def _single_assignment(stmt: ast.AST) -> tuple[str | None, ast.AST | None]:
    if (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
    ):
        return stmt.targets[0].id, stmt.value
    if (
        isinstance(stmt, ast.AnnAssign)
        and isinstance(stmt.target, ast.Name)
        and stmt.value is not None
    ):
        return stmt.target.id, stmt.value
    return None, None


def _is_empty_container(value: ast.AST) -> bool:
    if isinstance(value, (ast.List, ast.Set, ast.Dict, ast.Tuple)):
        return True
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in _CONTAINER_FACTORIES
        and not value.args
        and not value.keywords
    )


def _is_registration_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    param_names = _positional_param_names(node)
    if not param_names:
        return False

    direct_param = param_names[0]
    if _function_registers_name(node, direct_param):
        return _function_returns_name(node, direct_param)

    returned_inner_names = _returned_local_function_names(node)
    if not returned_inner_names:
        return False

    for stmt in node.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if stmt.name not in returned_inner_names:
            continue
        nested_params = _positional_param_names(stmt)
        if not nested_params:
            continue
        registered_param = nested_params[0]
        if _function_registers_name(stmt, registered_param) and _function_returns_name(
            stmt, registered_param
        ):
            return True

    return False


def _positional_param_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = []
    args.extend(node.args.posonlyargs)
    args.extend(node.args.args)
    return [arg.arg for arg in args]


def _function_returns_name(
    node: ast.FunctionDef | ast.AsyncFunctionDef, name: str
) -> bool:
    for child in _iter_function_body_nodes(node):
        if isinstance(child, ast.Return) and isinstance(child.value, ast.Name):
            if child.value.id == name:
                return True
    return False


def _returned_local_function_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    local_functions = {
        stmt.name
        for stmt in node.body
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    returned = set()
    for stmt in node.body:
        if not isinstance(stmt, ast.Return):
            continue
        if isinstance(stmt.value, ast.Name) and stmt.value.id in local_functions:
            returned.add(stmt.value.id)
    return returned


def _function_registers_name(
    node: ast.FunctionDef | ast.AsyncFunctionDef, name: str
) -> bool:
    for child in _iter_function_body_nodes(node):
        if _is_registration_assignment(child, name):
            return True
        if _is_registration_call(child, name):
            return True
    return False


def _iter_function_body_nodes(node: ast.FunctionDef | ast.AsyncFunctionDef):
    stack = list(reversed(node.body))
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(current))))


def _is_registration_assignment(node: ast.AST, name: str) -> bool:
    if isinstance(node, ast.Assign):
        return _assignment_registers_name(node.targets, node.value, name)
    if isinstance(node, ast.AnnAssign):
        return _assignment_registers_name([node.target], node.value, name)
    return False


def _assignment_registers_name(
    targets: list[ast.expr], value: ast.AST | None, name: str
) -> bool:
    if value is None:
        return False
    if not _expr_mentions_name(value, name):
        return False
    return any(_is_registry_target(target) for target in targets)


def _is_registry_target(node: ast.AST) -> bool:
    return isinstance(node, (ast.Subscript, ast.Attribute))


def _is_registration_call(node: ast.AST, name: str) -> bool:
    if not isinstance(node, ast.Call):
        return False

    call_name = _call_name(node.func)
    simple_name = call_name.rsplit(".", 1)[-1]
    if simple_name not in _REGISTRATION_METHOD_NAMES:
        return False

    for arg in node.args:
        if _expr_mentions_name(arg, name):
            return True
    for keyword in node.keywords:
        if _expr_mentions_name(keyword.value, name):
            return True
    return False


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _expr_mentions_name(node: ast.AST, name: str) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id == name:
            return True
    return False
