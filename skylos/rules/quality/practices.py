from __future__ import annotations

import ast
from pathlib import Path

from skylos.rules.base import SkylosRule


AUTH_MARKERS = (
    "auth",
    "login",
    "permission",
    "permit",
    "jwt",
    "token",
    "principal",
    "current_user",
    "require_user",
    "require_admin",
    "security",
)

MUTATING_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ROUTE_METHOD_NAMES = {
    "route",
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_route",
}
FASTAPI_ROUTE_METHODS = {
    "get",
    "post",
    "put",
    "patch",
    "delete",
    "api_route",
    "websocket",
}


def _basename(filename: str | None) -> str:
    return Path(filename or "").name


def _is_non_production_path(filename: str | None) -> bool:
    normalized = str(filename or "").replace("\\", "/").lower()
    parts = set(normalized.split("/"))
    base = Path(normalized).name
    return (
        "test" in parts
        or "tests" in parts
        or "corpus" in parts
        or base.startswith("test_")
        or base.endswith("_test.py")
    )


def _dotted_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    if isinstance(node, ast.Subscript):
        return _dotted_name(node.value)
    return ""


def _decorator_call(decorator: ast.AST) -> ast.Call | None:
    return decorator if isinstance(decorator, ast.Call) else None


def _decorator_name(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _dotted_name(decorator.func)
    return _dotted_name(decorator)


def _last_name_part(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower()


def _has_auth_marker(value: str) -> bool:
    lower = value.lower()
    return any(marker in lower for marker in AUTH_MARKERS)


def _string_values(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        values: list[str] = []
        for elt in node.elts:
            values.extend(_string_values(elt))
        return values
    return []


def _route_methods(decorator: ast.AST) -> tuple[str | None, set[str]]:
    name = _decorator_name(decorator)
    method_name = _last_name_part(name)
    if method_name not in ROUTE_METHOD_NAMES:
        return None, set()

    framework = "fastapi"
    if method_name == "route":
        framework = "flask"
    if name.startswith("app.") or name.startswith("blueprint."):
        if method_name == "route":
            framework = "flask"

    methods: set[str] = set()
    if method_name.upper() in MUTATING_HTTP_METHODS | {"GET"}:
        methods.add(method_name.upper())

    call = _decorator_call(decorator)
    if call is not None:
        for keyword in call.keywords:
            if keyword.arg == "methods":
                methods.update(value.upper() for value in _string_values(keyword.value))

    return framework, methods


def _is_fastapi_route(decorator: ast.AST) -> bool:
    name = _decorator_name(decorator)
    method_name = _last_name_part(name)
    if method_name not in FASTAPI_ROUTE_METHODS:
        return False
    return name.startswith(("app.", "router.", "api.", "server."))


def _call_uses_auth(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        name = _dotted_name(node.func)
        if _has_auth_marker(name):
            return True
        return any(_call_uses_auth(arg) for arg in node.args) or any(
            _call_uses_auth(keyword.value) for keyword in node.keywords
        )
    if isinstance(node, ast.Name):
        return _has_auth_marker(node.id)
    if isinstance(node, ast.Attribute):
        return _has_auth_marker(_dotted_name(node))
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_call_uses_auth(elt) for elt in node.elts)
    return False


def _decorator_has_response_contract(decorator: ast.AST) -> bool:
    call = _decorator_call(decorator)
    if call is None:
        return False
    return any(
        keyword.arg in {"response_model", "response_class"}
        and not (
            isinstance(keyword.value, ast.Constant) and keyword.value.value is None
        )
        for keyword in call.keywords
    )


def _route_has_auth_guard(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        name = _decorator_name(decorator)
        method_name = _last_name_part(name)
        if method_name not in ROUTE_METHOD_NAMES and _has_auth_marker(name):
            return True

        call = _decorator_call(decorator)
        if call is not None:
            for keyword in call.keywords:
                if keyword.arg in {"dependencies", "dependency_overrides"}:
                    if _call_uses_auth(keyword.value):
                        return True

    args = [
        *node.args.args,
        *node.args.posonlyargs,
        *node.args.kwonlyargs,
    ]
    defaults = [*node.args.defaults, *[d for d in node.args.kw_defaults if d]]
    for arg in args:
        if _has_auth_marker(arg.arg):
            return True
        if arg.annotation is not None and _has_auth_marker(
            _dotted_name(arg.annotation)
        ):
            return True
    return any(_call_uses_auth(default) for default in defaults)


def _is_public_function(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if node.name.startswith("_"):
        return False
    if node.name.startswith("__") and node.name.endswith("__"):
        return False
    return True


def _iter_public_functions(module: ast.Module):
    for stmt in module.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_public_function(stmt):
                yield stmt, stmt.name
        elif isinstance(stmt, ast.ClassDef) and not stmt.name.startswith("_"):
            for item in stmt.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if _is_public_function(item):
                        yield item, f"{stmt.name}.{item.name}"


def _module_has_typing_signal(module: ast.Module) -> bool:
    for node in ast.walk(module):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.returns is not None:
                return True
            args = [
                *node.args.args,
                *node.args.posonlyargs,
                *node.args.kwonlyargs,
            ]
            if node.args.vararg:
                args.append(node.args.vararg)
            if node.args.kwarg:
                args.append(node.args.kwarg)
            if any(arg.annotation is not None for arg in args):
                return True
        if isinstance(node, ast.AnnAssign):
            return True
        if isinstance(node, ast.ImportFrom) and node.module == "typing":
            return True
        if isinstance(node, ast.Import):
            if any(alias.name == "typing" for alias in node.names):
                return True
    return False


class TypeAnnotationPracticeRule(SkylosRule):
    rule_id = "SKY-T101"
    name = "Typed API Surface"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename")
        if _is_non_production_path(filename) or not _module_has_typing_signal(node):
            return None

        findings = []
        for function, display_name in _iter_public_functions(node):
            args = [
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            ]
            if function.args.vararg:
                args.append(function.args.vararg)
            if function.args.kwarg:
                args.append(function.args.kwarg)

            missing_params = [
                arg.arg
                for arg in args
                if arg.arg not in {"self", "cls"} and arg.annotation is None
            ]
            if missing_params:
                findings.append(
                    {
                        "rule_id": "SKY-T101",
                        "kind": "typing",
                        "severity": "LOW",
                        "type": "function",
                        "name": display_name,
                        "simple_name": function.name,
                        "value": ", ".join(missing_params),
                        "threshold": 0,
                        "message": (
                            f"Public function '{display_name}' has untyped parameters: "
                            f"{', '.join(missing_params)}."
                        ),
                        "file": filename,
                        "basename": _basename(filename),
                        "line": function.lineno,
                        "col": function.col_offset,
                    }
                )

            if function.returns is None:
                findings.append(
                    {
                        "rule_id": "SKY-T102",
                        "kind": "typing",
                        "severity": "LOW",
                        "type": "function",
                        "name": display_name,
                        "simple_name": function.name,
                        "value": "missing_return_annotation",
                        "threshold": 0,
                        "message": (
                            f"Public function '{display_name}' is missing a return type annotation."
                        ),
                        "file": filename,
                        "basename": _basename(filename),
                        "line": function.lineno,
                        "col": function.col_offset,
                    }
                )

        return findings or None


class FrameworkPracticeRule(SkylosRule):
    rule_id = "SKY-F101"
    name = "Framework Route Practices"

    def visit_node(self, node, context):
        if not isinstance(node, ast.Module):
            return None

        filename = context.get("filename")
        if _is_non_production_path(filename):
            return None

        findings = []
        for function in ast.walk(node):
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            route_decorators = [
                decorator
                for decorator in function.decorator_list
                if _route_methods(decorator)[0] is not None
            ]
            if not route_decorators:
                continue

            if any(_is_fastapi_route(decorator) for decorator in route_decorators):
                has_response_contract = function.returns is not None or any(
                    _decorator_has_response_contract(decorator)
                    for decorator in route_decorators
                )
                if not has_response_contract:
                    findings.append(
                        {
                            "rule_id": "SKY-F101",
                            "kind": "framework",
                            "severity": "LOW",
                            "type": "route",
                            "name": function.name,
                            "simple_name": function.name,
                            "value": "missing_response_contract",
                            "threshold": 0,
                            "message": (
                                f"FastAPI route '{function.name}' has no response_model, "
                                "response_class, or return annotation."
                            ),
                            "file": filename,
                            "basename": _basename(filename),
                            "line": function.lineno,
                            "col": function.col_offset,
                        }
                    )

            methods = set()
            for decorator in route_decorators:
                _, decorator_methods = _route_methods(decorator)
                methods.update(decorator_methods)

            if methods & MUTATING_HTTP_METHODS and not _route_has_auth_guard(function):
                findings.append(
                    {
                        "rule_id": "SKY-F102",
                        "kind": "framework_security",
                        "severity": "MEDIUM",
                        "type": "route",
                        "name": function.name,
                        "simple_name": function.name,
                        "value": ",".join(sorted(methods & MUTATING_HTTP_METHODS)),
                        "threshold": 0,
                        "message": (
                            f"Mutating route '{function.name}' has no obvious auth, "
                            "permission, security, or dependency guard."
                        ),
                        "file": filename,
                        "basename": _basename(filename),
                        "line": function.lineno,
                        "col": function.col_offset,
                    }
                )

        return findings or None
