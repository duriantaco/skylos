"""Bounded callback forwarding into registry storage operations."""

from __future__ import annotations
import ast
from typing import Sequence
from skylos.deadcode.python_ast import ParsedPythonFile
from skylos.deadcode._registration_common import (
    _FUNCTION_NODES,
    _own_body_nodes,
    _is_signature_stub,
    _is_static,
)

_MAX_FORWARD_DEPTH = 4
_REGISTRY_CALL_NAMES = {
    "add",
    "append",
    "appendleft",
    "connect",
    "extend",
    "insert",
    "listen",
    "register",
    "setdefault",
    "subscribe",
}


class _MethodScope:
    __slots__ = ("class_methods", "module_functions", "function_modules")

    def __init__(self, class_methods, module_functions, function_modules=None):
        self.class_methods = class_methods
        self.module_functions = module_functions
        self.function_modules = function_modules or {}


def _wraps_arguments(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name):
        name = func.id
    else:
        name = getattr(func, "attr", "")
    return bool(name) and (name[0].isupper() or name == "partial")


def _carries(node: ast.AST | None, names: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in names
    if isinstance(node, ast.Call):
        if not _wraps_arguments(node):
            return False
        for arg in node.args:
            if _carries(arg, names):
                return True
        for keyword in node.keywords:
            if _carries(keyword.value, names):
                return True
        return False
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for element in node.elts:
            if _carries(element, names):
                return True
        return False
    if isinstance(node, ast.Dict):
        for value in node.values:
            if _carries(value, names):
                return True
        return False
    return False


class _RegistrationFlow:
    def __init__(self, method_index):
        self.method_index = method_index
        self.cache: dict[tuple[int, str, int, int], bool] = {}

    def callees(self, func: ast.AST, scope: _MethodScope, nested: dict, caller):
        if isinstance(func, ast.Name):
            module = scope.function_modules.get(caller, scope.module_functions)
            local = nested.get(func.id) or module.get(func.id)
            if local is not None:
                return [(local, 0, scope)]
            return []
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in {"self", "cls"}
        ):
            methods = []
            for method in scope.class_methods.get(func.attr, ()):
                if not _is_signature_stub(method):
                    methods.append((method, scope))
            targets = []
            for method, method_scope in methods:
                if _is_static(method):
                    offset = 0
                else:
                    offset = 1
                targets.append((method, offset, method_scope))
            return targets
        return []

    def registers(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        param: str,
        scope: _MethodScope,
        depth: int = _MAX_FORWARD_DEPTH,
    ) -> bool:
        key = (id(func), param, id(scope), depth)
        if key in self.cache:
            return self.cache[key]
        self.cache[key] = False
        result = self._registers(func, param, scope, depth)
        self.cache[key] = result
        return result

    def _registers(self, func, param, scope, depth) -> bool:
        body = list(_own_body_nodes(func))
        nested = {}
        for node in body:
            if isinstance(node, _FUNCTION_NODES):
                nested[node.name] = node
        aliases = {param}
        for _ in range(2):
            for node in body:
                if isinstance(node, ast.Assign) and _carries(node.value, aliases):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            aliases.add(target.id)
        for node in body:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if isinstance(node, ast.Assign):
                    targets = node.targets
                else:
                    targets = [node.target]
                if not _carries(node.value, aliases):
                    continue
                for target in targets:
                    if isinstance(target, ast.Subscript):
                        return True
                    if isinstance(target, ast.Attribute) and not (
                        target.attr.startswith("__") and target.attr.endswith("__")
                    ):
                        return True
            elif isinstance(node, ast.Call):
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in _REGISTRY_CALL_NAMES
                    and _carries(ast.Tuple(elts=list(node.args)), aliases)
                ):
                    return True
                if depth <= 0:
                    continue
                for callee, offset, callee_scope in self.callees(
                    node.func, scope, nested, func
                ):
                    params = []
                    for arg in (*callee.args.posonlyargs, *callee.args.args):
                        params.append(arg.arg)
                    keyword_params = set(params)
                    for arg in callee.args.kwonlyargs:
                        keyword_params.add(arg.arg)
                    for index, arg in enumerate(node.args):
                        if not (isinstance(arg, ast.Name) and arg.id in aliases):
                            continue
                        position = index + offset
                        if position < len(params) and self.registers(
                            callee, params[position], callee_scope, depth - 1
                        ):
                            return True
                    for keyword in node.keywords:
                        if (
                            keyword.arg in keyword_params
                            and isinstance(keyword.value, ast.Name)
                            and keyword.value.id in aliases
                            and self.registers(
                                callee, keyword.arg, callee_scope, depth - 1
                            )
                        ):
                            return True
        return False


def _method_index(parsed_files: Sequence[ParsedPythonFile]):
    index: dict[str, list[tuple[ast.AST, _MethodScope]]] = {}
    for parsed in parsed_files:
        module_functions = {}
        for stmt in parsed.tree.body:
            if isinstance(stmt, _FUNCTION_NODES):
                module_functions[stmt.name] = stmt
        for node in ast.walk(parsed.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            class_methods: dict[str, list[ast.AST]] = {}
            for stmt in node.body:
                if isinstance(stmt, _FUNCTION_NODES):
                    class_methods.setdefault(stmt.name, []).append(stmt)
            scope = _MethodScope(class_methods, module_functions)
            for name, methods in class_methods.items():
                for method in methods:
                    index.setdefault(name, []).append((method, scope))
    return index
