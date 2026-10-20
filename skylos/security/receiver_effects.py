"""Conservative source-body effects; unknown Python dispatch is never safe proof."""

from __future__ import annotations

import ast

from skylos.security.receiver_bindings import _SCOPES, _FUNCTIONS

_VALUE_TYPES = {
    "str",
    "bytes",
    "bytearray",
    "list",
    "dict",
    "set",
    "tuple",
    "int",
    "float",
    "bool",
}
_VALUE_CALLS = {
    "len",
    "min",
    "max",
    "sum",
    "enumerate",
    "zip",
    "range",
    "sorted",
    "reversed",
    "isinstance",
    "issubclass",
    "abs",
    "round",
    "repr",
    "format",
    "print",
}
_VALUE_METHODS = {
    "append",
    "extend",
    "insert",
    "pop",
    "clear",
    "copy",
    "get",
    "keys",
    "values",
    "items",
    "update",
    "add",
    "discard",
    "remove",
    "join",
    "format",
    "replace",
    "split",
    "rsplit",
    "splitlines",
    "strip",
    "lstrip",
    "rstrip",
    "partition",
    "rpartition",
    "startswith",
    "endswith",
    "lower",
    "upper",
    "casefold",
    "encode",
    "decode",
    "count",
    "index",
    "find",
    "rfind",
    "isdigit",
    "isalpha",
    "isalnum",
}


def callable_effects(resolver, ref, active=frozenset()):
    if ref.model == "database":
        return {"filesystem": "none", "database": "sql_receiver"}, None
    if ref.model in {"sqlite_connection_factory", "sqlite_cursor_factory"}:
        return {"filesystem": "unknown", "database": "unknown"}, None
    if ref.model in {"value", *_VALUE_TYPES, "stream"}:
        return {"filesystem": "none", "database": "none"}, None
    if ref.model == "path":
        return {"filesystem": "path_receiver", "database": "unknown"}, None
    if ref.kind == "builtin":
        if ref.model == "open":
            return {"filesystem": "wrapped_path_argument", "database": "none"}, 0
        return {"filesystem": "none", "database": "none"}, None
    if ref.module is None or not isinstance(ref.node, _FUNCTIONS):
        return {"filesystem": "unknown", "database": "unknown"}, None
    key = (str(ref.module.path), id(ref.node))
    if key in resolver._effect_cache:
        return resolver._effect_cache[key]
    if key in active or len(active) >= resolver.MAX_DEPTH:
        return {"filesystem": "unknown", "database": "unknown"}, None
    effects = {"filesystem": "none", "database": "none"}
    path_params = set()
    args = [*ref.node.args.posonlyargs, *ref.node.args.args]
    if ref.kind == "method" and args:
        args = args[1:]
    params = []
    for arg in args:
        params.append(arg.arg)
    pending = list(ref.node.body)
    while pending:
        node = pending.pop()
        if isinstance(node, _SCOPES):
            # Defaults/decorators/class bodies execute when a nested
            # definition is created; unvisited syntax is not harmless.
            effects = {"filesystem": "unknown", "database": "unknown"}
            continue
        if isinstance(node, (ast.With, ast.AsyncWith, ast.Await, ast.YieldFrom)):
            effects = {"filesystem": "unknown", "database": "unknown"}
        if isinstance(node, ast.Attribute):
            if resolver._expr(ref.module, node) is None:
                effects = {"filesystem": "unknown", "database": "unknown"}
        if isinstance(node, ast.Subscript):
            container = resolver._expr(ref.module, node.value)
            if (
                container is None
                or container.model not in _VALUE_TYPES
                or not isinstance(node.slice, ast.Constant)
            ):
                effects = {"filesystem": "unknown", "database": "unknown"}
        if isinstance(node, (ast.BinOp, ast.UnaryOp, ast.Compare, ast.FormattedValue)):
            operands = []
            if isinstance(node, ast.BinOp):
                operands = [node.left, node.right]
            elif isinstance(node, ast.UnaryOp):
                operands = [node.operand]
            elif isinstance(node, ast.Compare):
                operands = [node.left, *node.comparators]
            else:
                operands = [node.value]
            for operand in operands:
                value = resolver._expr(ref.module, operand)
                if value is None or value.model not in _VALUE_TYPES:
                    effects = {"filesystem": "unknown", "database": "unknown"}
        if isinstance(
            node,
            (
                ast.If,
                ast.IfExp,
                ast.While,
                ast.BoolOp,
                ast.For,
                ast.AsyncFor,
                ast.comprehension,
            ),
        ):
            if isinstance(node, ast.BoolOp):
                operands = node.values
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                operands = [node.iter]
            else:
                operands = [node.test]
            for operand in operands:
                value = resolver._expr(ref.module, operand)
                if value is None or value.model not in _VALUE_TYPES:
                    effects = {"filesystem": "unknown", "database": "unknown"}
        if isinstance(node, ast.Call):
            callee = resolver._expr(ref.module, node.func)
            if callee is None:
                called = {"filesystem": "unknown", "database": "unknown"}
                index = None
            else:
                called, index = resolver._effects(callee, active | {key})
                if (
                    callee.model in {"value", *_VALUE_TYPES, "stream"}
                    or callee.kind == "builtin"
                ):
                    opaque_append = (
                        callee.name.endswith("list.append")
                        and len(node.args) == 1
                        and not node.keywords
                    )
                    if not opaque_append:
                        values = list(node.args)
                        for keyword in node.keywords:
                            values.append(keyword.value)
                        for value_node in values:
                            value = resolver._expr(ref.module, value_node)
                            if value is None or value.model not in _VALUE_TYPES:
                                if callee.model == "open":
                                    called = dict(called)
                                    called["database"] = "unknown"
                                else:
                                    called = {
                                        "filesystem": "unknown",
                                        "database": "unknown",
                                    }
                                break
            for category, value in called.items():
                if value != "none":
                    effects[category] = "unknown"
            if (
                called["filesystem"] == "wrapped_path_argument"
                and index is not None
                and index < len(node.args)
            ):
                actual = node.args[index]
                if isinstance(actual, ast.Name) and actual.id in params:
                    path_params.add(params.index(actual.id))
            pending.extend(ast.iter_child_nodes(node))
            continue
        pending.extend(ast.iter_child_nodes(node))
    path_index = None
    if len(path_params) == 1:
        path_index = path_params.pop()
        effects["filesystem"] = "wrapped_path_argument"
    result = effects, path_index
    resolver._effect_cache[key] = result
    return result
