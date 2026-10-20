"""Source-only constructor, attribute and primitive-value resolution."""

from __future__ import annotations

import ast

from skylos.security.receiver_bindings import _Reference, _FUNCTIONS
from skylos.security.receiver_effects import _VALUE_TYPES, _VALUE_METHODS

_PATH_TYPES = {
    "Path",
    "PosixPath",
    "WindowsPath",
    "PurePath",
    "PurePosixPath",
    "PureWindowsPath",
}
_PATH_METHODS = {"open", "read_text", "read_bytes", "write_text", "write_bytes"}


def resolve_attribute(resolver, base, name, depth, active):
    if base is None or depth > resolver.MAX_DEPTH:
        return None
    if base.kind == "module":
        if base.module is not None:
            sentinel = base.module.tree
            fake = ast.Name(id=name)
            base.module.parents[fake] = sentinel
            return resolver._name(base.module, fake, name, depth + 1, active)
        if base.model == "pathlib" and name in _PATH_TYPES:
            return _Reference("class", f"pathlib.{name}", model="path")
        if base.model == "io" and name in {"StringIO", "BytesIO"}:
            return _Reference("class", f"io.{name}", model="stream")
        if base.model in {"io", "builtins"} and name == "open":
            return _Reference("builtin", f"{base.model}.open", model="open")
        if base.model == "sqlite3" and name == "connect":
            return _Reference(
                "builtin", "sqlite3.connect", model="sqlite_connection_factory"
            )
        imported = resolver._load(f"{base.name}.{name}")
        if imported is not None:
            return _Reference("module", imported.name, imported)
        return None
    if base.kind != "instance":
        return None
    if base.model in {"sqlite_connection", "sqlite_cursor"}:
        if name in {"execute", "executemany", "executescript"}:
            return _Reference(
                "method", f"{base.name}.{name}", receiver=base, model="database"
            )
        if name == "cursor" and base.model == "sqlite_connection":
            return _Reference(
                "method",
                "sqlite3.Connection.cursor",
                receiver=base,
                model="sqlite_cursor_factory",
            )
        return None
    if base.model == "path":
        if name in _PATH_METHODS:
            return _Reference(
                "method", f"{base.name}.{name}", receiver=base, model="path"
            )
        return None
    if base.model in _VALUE_TYPES and name in _VALUE_METHODS:
        return _Reference(
            "method", f"builtins.{base.model}.{name}", receiver=base, model="value"
        )
    if base.model == "stream" and name in {
        "read",
        "readinto",
        "write",
        "seek",
        "tell",
        "flush",
        "getvalue",
        "close",
    }:
        return _Reference("method", f"{base.name}.{name}", receiver=base, model="value")
    if base.module is None or not resolver._class_safe(base):
        return None
    methods = []
    for child in base.node.body:
        if isinstance(child, _FUNCTIONS) and child.name == name:
            methods.append(child)
    if methods:
        for child in ast.walk(base.node):
            if isinstance(child, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                if isinstance(child, ast.Assign):
                    targets = child.targets
                else:
                    targets = [child.target]
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                        and target.attr == name
                    ):
                        return None
    if len(methods) == 1 and not methods[0].decorator_list:
        return _Reference(
            "method", f"{base.name}.{name}", base.module, methods[0], base
        )
    if methods:
        return None
    # A field's concrete initializer can prove a list/string/owned instance.
    initializers = []
    writes = 0
    for child in ast.walk(base.node):
        if isinstance(child, ast.Attribute) and isinstance(
            child.ctx, (ast.Store, ast.Del)
        ):
            if (
                isinstance(child.value, ast.Name)
                and child.value.id == "self"
                and child.attr == name
            ):
                writes += 1
    if writes != 1:
        return None
    for child in base.node.body:
        if not isinstance(child, _FUNCTIONS) or child.name != "__init__":
            continue
        for statement in child.body:
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            if isinstance(statement, ast.Assign):
                targets = statement.targets
            else:
                targets = [statement.target]
            for target in targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and target.attr == name
                ):
                    initializers.append(statement.value)
    if len(initializers) == 1:
        return resolver._expr(base.module, initializers[0], depth + 1, active)
    return None


def resolve_expression(resolver, module, node, depth=0, active=frozenset()):
    if node is None or depth > resolver.MAX_DEPTH:
        return None
    if isinstance(node, ast.Name):
        return resolver._name(module, node, node.id, depth, active)
    if isinstance(node, ast.Attribute):
        return resolver._attribute(
            resolver._expr(module, node.value, depth + 1, active),
            node.attr,
            depth + 1,
            active,
        )
    if isinstance(node, ast.Call):
        callee = resolver._expr(module, node.func, depth + 1, active)
        if callee is None:
            return None
        if callee.model == "sqlite_connection_factory":
            return _Reference(
                "instance",
                "sqlite3.Connection",
                module,
                node,
                model="sqlite_connection",
            )
        if callee.model == "sqlite_cursor_factory":
            return _Reference(
                "instance", "sqlite3.Cursor", module, node, model="sqlite_cursor"
            )
        if callee.kind == "class":
            if callee.model is not None or resolver._class_safe(callee):
                return _Reference(
                    "instance",
                    callee.name,
                    callee.module,
                    callee.node,
                    model=callee.model,
                )
        if callee.kind in {"function", "method"} and isinstance(
            callee.node, _FUNCTIONS
        ):
            body = callee.node.body
            if len(body) == 1 and isinstance(body[0], ast.Return):
                marker = (str(callee.module.path), id(callee.node))
                if marker not in active:
                    return resolver._expr(
                        callee.module, body[0].value, depth + 1, active | {marker}
                    )
        return None
    if isinstance(node, ast.Constant):
        model = type(node.value).__name__
        if model in _VALUE_TYPES:
            return _Reference("instance", f"builtins.{model}", model=model)
    for cls, model in [
        (ast.List, "list"),
        (ast.Dict, "dict"),
        (ast.Set, "set"),
        (ast.Tuple, "tuple"),
    ]:
        if isinstance(node, cls):
            return _Reference("instance", f"builtins.{model}", model=model)
    return None
