from __future__ import annotations

import ast
import re


FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


_DENIAL_STATUS = frozenset({401, 403})


_DENIAL_EXCEPTIONS = frozenset({
    "PermissionError", "PermissionDenied", "Forbidden", "Unauthorized", "AuthenticationFailed",
    "NotAuthenticated", "HTTPForbidden", "HTTPUnauthorized", "NotAuthorized", "AccessDenied",
})


_STATUS_EXCEPTIONS = frozenset({"HTTPException", "HTTPError", "APIException", "StarletteHTTPException"})


_DEPENDENCY_WRAPPERS = frozenset({"Depends", "Security"})


def dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        if base is None:
            return None
        return base + "." + node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return None


_DENIAL_NAME = re.compile(r"_(401|403)(?:_|$)")


def _code_of(value: ast.AST) -> int | None:
    if isinstance(value, ast.Constant) and isinstance(value.value, int):
        return value.value
    match = _DENIAL_NAME.search(dotted(value) or "")
    if match:
        return int(match.group(1))
    return None


def _status_code(call: ast.Call) -> int | None:
    candidates = [k.value for k in call.keywords if k.arg in ("status_code", "code", "status")]
    candidates += call.args[:1]
    for value in candidates:
        code = _code_of(value)
        if code is not None:
            return code
    return None


def _raise_guard(node: ast.Raise) -> str | None:
    exc = node.exc
    if exc is None:
        return None
    name = (dotted(exc) or "").rsplit(".", 1)[-1]
    if name in _DENIAL_EXCEPTIONS:
        return f"inline {name} check"
    if name in _STATUS_EXCEPTIONS and isinstance(exc, ast.Call):
        code = _status_code(exc)
        if code in _DENIAL_STATUS:
            return f"inline {code} check"
    return None


def _call_guard(node: ast.Call) -> str | None:
    if (dotted(node.func) or "").rsplit(".", 1)[-1] != "abort":
        return None
    code = _status_code(node)
    if code in _DENIAL_STATUS:
        return f"inline {code} check"
    return None


def _rejection(node: ast.Raise) -> str | None:
    exc = node.exc
    if exc is None:
        return None
    name = (dotted(exc) or "").rsplit(".", 1)[-1]
    if not name:
        return None
    message = ""
    if isinstance(exc, ast.Call) and exc.args and isinstance(exc.args[0], ast.Constant) and isinstance(exc.args[0].value, str):
        message = exc.args[0].value[:60]
    return f"raise {name}('{message}')".replace("('')", "()")


def rejections_of(node: ast.AST) -> list[str]:
    if not isinstance(node, FUNCTION_NODES):
        return []
    return sorted(filter(None, (_rejection(n) for n in ast.walk(node) if isinstance(n, ast.Raise))))


def guards_of(node: ast.AST) -> list[str]:
    found = []
    for child in ast.walk(node):
        guard = None
        if isinstance(child, ast.Raise):
            guard = _raise_guard(child)
        elif isinstance(child, ast.Call):
            guard = _call_guard(child)
        if guard:
            found.append(guard)
    return sorted(found)


def _dependency_name(default: ast.AST) -> str | None:
    if not isinstance(default, ast.Call) or not default.args:
        return None
    if (dotted(default.func) or "").rsplit(".", 1)[-1] not in _DEPENDENCY_WRAPPERS:
        return None
    return dotted(default.args[0])


def dependencies_of(node: ast.AST) -> list[str]:
    if not isinstance(node, FUNCTION_NODES):
        return []
    defaults = [*node.args.defaults, *[d for d in node.args.kw_defaults if d is not None]]
    return sorted(name for name in map(_dependency_name, defaults) if name)


_DATACLASS_DECORATORS = frozenset({"dataclass", "define", "frozen", "mutable", "attrs"})


def _is_dataclass(node: ast.ClassDef) -> bool:
    return any((dotted(d) or "").rsplit(".", 1)[-1] in _DATACLASS_DECORATORS for d in node.decorator_list)


def _is_classvar(annotation: ast.AST) -> bool:
    return "ClassVar" in (dotted(annotation) or ast.unparse(annotation))


def _dataclass_fields(node: ast.ClassDef) -> tuple:
    fields = []
    for stmt in node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and not _is_classvar(stmt.annotation):
            fields.append(("positional", stmt.target.id, stmt.value is not None))
    return tuple(fields)


def class_attributes(node: ast.AST) -> dict[str, str]:
    if not isinstance(node, ast.ClassDef):
        return {}
    found = {}
    for stmt in node.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            found[stmt.targets[0].id] = ast.unparse(stmt.value)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            found[stmt.target.id] = ast.unparse(stmt.value)
    return found


def params_of(node: ast.AST) -> tuple:
    if isinstance(node, ast.ClassDef):
        if _is_dataclass(node):
            return _dataclass_fields(node)
        return ()
    if not isinstance(node, FUNCTION_NODES):
        return ()
    args = node.args
    positional = [*args.posonlyargs, *args.args]
    first_default = len(positional) - len(args.defaults)
    out = [("positional", a.arg, index >= first_default) for index, a in enumerate(positional)]
    if args.vararg is not None:
        out.append(("varargs", args.vararg.arg, True))
    out += [("keyword", a.arg, d is not None) for a, d in zip(args.kwonlyargs, args.kw_defaults)]
    if args.kwarg is not None:
        out.append(("varkw", args.kwarg.arg, True))
    return tuple(out)
