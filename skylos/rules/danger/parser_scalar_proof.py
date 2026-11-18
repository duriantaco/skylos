"""Finite native scalar callbacks and deployment defaults for argparse.

These proofs certify data conversion, not arbitrary actions or parser hooks.
"""

from __future__ import annotations

import ast


class ParserContracts(frozenset):
    def __new__(cls, names=(), *, scalar_types=(), values=None, native=None):
        result = super().__new__(cls, names)
        result.scalar_types = frozenset(scalar_types)
        result.values = dict(values or {})
        result.native = native
        return result

    def narrowed(self, bound):
        return type(self)(
            self.difference(bound),
            scalar_types=self.scalar_types.difference(bound),
            values={k: v for k, v in self.values.items() if k not in bound},
            native=self.native,
        )


def _qualified(node, bindings):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    if node.id in bindings:
        base = bindings[node.id]
        return ".".join([base, *reversed(parts)]) if base else None
    return "builtins." + node.id if not parts else None


def scalar_callback(function, bindings, native):
    if not callable(native) or not isinstance(function, ast.FunctionDef):
        return False
    args = function.args
    parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
    if function.decorator_list or len(parameters) != 1 or args.vararg or args.kwarg:
        return False
    for annotation in [parameters[0].annotation, function.returns]:
        if annotation is not None and not (
            isinstance(annotation, ast.Name)
            and _qualified(annotation, bindings)
            in {"builtins.str", "builtins.int", "builtins.float", "builtins.bool"}
            and native(_qualified(annotation, bindings))
        ):
            return False
    locals_ = {parameters[0].arg}
    nodes = [part for statement in function.body for part in ast.walk(statement)]
    if len(nodes) > 256:
        return False
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(not isinstance(target, ast.Name) for target in targets):
                return False
            locals_.update(target.id for target in targets)
        if isinstance(node, ast.ExceptHandler) and node.name:
            locals_.add(node.name)
    allowed_calls = {
        "builtins.str",
        "builtins.int",
        "builtins.float",
        "builtins.bool",
        "builtins.ValueError",
        "builtins.TypeError",
        "argparse.ArgumentTypeError",
        "math.isfinite",
    }
    parents = {
        child: parent
        for statement in function.body
        for parent in ast.walk(statement)
        for child in ast.iter_child_nodes(parent)
    }
    for node in nodes:
        if isinstance(
            node,
            (
                ast.Global,
                ast.Nonlocal,
                ast.Import,
                ast.ImportFrom,
                ast.Lambda,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.With,
                ast.AsyncWith,
                ast.For,
                ast.While,
                ast.Yield,
                ast.YieldFrom,
                ast.Delete,
                ast.AugAssign,
                ast.Subscript,
                ast.NamedExpr,
            ),
        ):
            return False
        if isinstance(node, ast.Call):
            qualified = _qualified(node.func, bindings)
            if (
                qualified not in allowed_calls
                or node.keywords
                or any(isinstance(arg, ast.Starred) for arg in node.args)
                or isinstance(node.func, ast.Name)
                and node.func.id in locals_
                or not native(qualified)
            ):
                return False
        if isinstance(node, ast.Attribute):
            parent = parents.get(node)
            if not isinstance(parent, ast.Call) or parent.func is not node:
                return False
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            if node.id in locals_:
                continue
            if isinstance(parent, ast.Call) and parent.func is node:
                continue
            if isinstance(parent, ast.Attribute) and parent.value is node:
                continue
            if _qualified(node, bindings) not in {
                "builtins.ValueError",
                "builtins.TypeError",
            }:
                return False
            if not native(_qualified(node, bindings)):
                return False
    return any(
        isinstance(node, ast.Return) and node.value is not None for node in nodes
    )


def operator_default(node, bindings, values, native, depth=0):
    if depth > 8:
        return False
    if isinstance(node, ast.Constant):
        return type(node.value) in {str, int, float, bool, type(None)}
    if isinstance(node, ast.Tuple):
        return all(
            operator_default(item, bindings, values, native, depth + 1)
            for item in node.elts
        )
    if isinstance(node, ast.Name):
        value = values.get(node.id)
        return value is not None and operator_default(
            value, bindings, values, native, depth + 1
        )
    if not callable(native) or not isinstance(node, ast.Call) or node.keywords:
        return False
    qualified = _qualified(node.func, bindings)
    if qualified in {"os.getenv", "os.environ.get"}:
        return (
            1 <= len(node.args) <= 2
            and isinstance(node.args[0], ast.Constant)
            and type(node.args[0].value) is str
            and native(qualified)
            and all(
                operator_default(arg, bindings, values, native, depth + 1)
                for arg in node.args[1:]
            )
        )
    if qualified in {"builtins.str", "builtins.int", "builtins.float", "builtins.bool"}:
        return (
            len(node.args) == 1
            and native(qualified)
            and operator_default(node.args[0], bindings, values, native, depth + 1)
        )
    return False
