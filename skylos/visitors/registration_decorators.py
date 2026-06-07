from __future__ import annotations

import ast


_REGISTRATION_METHOD_NAMES = {
    "add",
    "append",
    "connect",
    "listen",
    "register",
    "register_type_strategy",
    "setdefault",
}


def collect_local_registration_decorators(node: ast.Module) -> set[str]:
    decorators = set()
    for stmt in node.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if _is_registration_decorator(stmt):
            decorators.add(stmt.name)
    return decorators


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
