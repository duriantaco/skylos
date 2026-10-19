"""Shared syntax and import helpers for static registration evidence."""

from __future__ import annotations
import ast
from pathlib import Path
from skylos.deadcode._reachability_bindings import default_expressions

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def _resolved(path: Path, cache: dict[Path, str]) -> str:
    key = cache.get(path)
    if key is None:
        try:
            key = str(Path(path).resolve())
        except OSError:
            key = str(path)
        cache[path] = key
    return key


def _first_param(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    params = [*node.args.posonlyargs, *node.args.args]
    if params:
        return params[0].arg
    return None


def _own_body_nodes(node: ast.FunctionDef | ast.AsyncFunctionDef):
    stack = list(reversed(node.body))
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, (*_FUNCTION_NODES, ast.ClassDef, ast.Lambda)):
            continue
        stack.extend(reversed(list(ast.iter_child_nodes(current))))


def _package_base(module: str, path: Path, level: int) -> str | None:
    if module:
        parts = module.split(".")
    else:
        parts = []
    if path.name != "__init__.py":
        parts = parts[:-1]
    if level > 1:
        if level - 1 > len(parts):
            return None
        parts = parts[: len(parts) - (level - 1)]
    return ".".join(parts)


def _import_aliases(
    tree: ast.Module, module: str | None, path: Path
) -> tuple[dict[str, str], dict[str, str]]:
    """Module-level ``from X import N as A`` and ``import X as A`` bindings."""
    names: dict[str, str] = {}
    modules: dict[str, str] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.ImportFrom):
            source = stmt.module or ""
            if stmt.level:
                if module is None:
                    continue
                base = _package_base(module, path, stmt.level)
                if base is None:
                    continue
                if base and source:
                    source = f"{base}.{source}"
                elif base:
                    source = base
            if not source:
                continue
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                names[alias.asname or alias.name] = f"{source}.{alias.name}"
        elif isinstance(stmt, ast.Import):
            for alias in stmt.names:
                if alias.asname:
                    modules[alias.asname] = alias.name
                else:
                    head = alias.name.split(".", 1)[0]
                    modules[head] = head
    return names, modules


def _decorator_reference(
    decorator: ast.AST, names: dict[str, str], modules: dict[str, str], module: str
) -> tuple[str, str | None]:
    """(leaf name, qualified name if resolvable) for a decorator expression."""
    node = decorator
    while isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Name):
        if node.id in names:
            return node.id, names[node.id]
        if module:
            return node.id, f"{module}.{node.id}"
        return node.id, None
    if isinstance(node, ast.Attribute):
        parts = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            root = modules.get(current.id) or names.get(current.id)
            if root:
                return node.attr, ".".join([root, *reversed(parts)])
        return node.attr, None
    return "", None


def _is_signature_stub(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call):
            target = decorator.func
        else:
            target = decorator
        if isinstance(target, ast.Attribute):
            name = target.attr
        else:
            name = getattr(target, "id", "")
        if name == "overload":
            return True
    for stmt in node.body:
        if isinstance(stmt, ast.Pass):
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        return False
    return True


def _is_static(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Name) and decorator.id == "staticmethod":
            return True
    return False


def _executed_nodes(statements):
    """Potentially executed expressions, without deferred callable bodies."""
    pending = list(reversed(statements))
    while pending:
        node = pending.pop()
        yield node
        if isinstance(node, _FUNCTION_NODES):
            children = [*node.decorator_list, *default_expressions(node.args)]
        elif isinstance(node, ast.Lambda):
            children = default_expressions(node.args)
        elif isinstance(node, ast.GeneratorExp):
            children = [node.generators[0].iter]
        elif isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
            children = [node.test]
            if node.test.value:
                children.extend(node.body)
            else:
                children.extend(node.orelse)
        elif (
            isinstance(node, ast.While)
            and isinstance(node.test, ast.Constant)
            and not node.test.value
        ):
            children = [node.test, *node.orelse]
        else:
            children = list(ast.iter_child_nodes(node))
        pending.extend(reversed(children))


def _attribute_root(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Attribute):
        return None
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        current = current.value
    if isinstance(current, ast.Name):
        return current.id
    return None
