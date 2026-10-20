"""An imported proof provider must not escape to unknown mutation."""

import ast

from skylos.analysis.ast_cache import run_memo
from skylos.rules.danger.module_namespace import module_rebinding


def provider_namespace_stable(tree, module, member):
    """Reject an explicit replacement or escape of a constructor provider."""

    def evaluate():
        dynamic, rebound = module_rebinding(tree, module)
        if dynamic or member in rebound:
            return False
        imports = {}
        sensitive = {
            "sys.modules",
            "sys.meta_path",
            "sys.path",
            "sys.path_hooks",
            "sys.path_importer_cache",
            "builtins.__import__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in {"sys", "builtins"}:
                        imports[alias.asname or alias.name] = alias.name
            elif isinstance(node, ast.ImportFrom) and not node.level:
                if node.module in {"sys", "builtins"}:
                    for alias in node.names:
                        if f"{node.module}.{alias.name}" in sensitive:
                            return False
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                namespace = imports.get(node.value.id)
                if namespace is not None and f"{namespace}.{node.attr}" in sensitive:
                    return False
        return True

    return run_memo(("fixture-provider-namespace", id(tree), module, member), evaluate)


def binding_escapes(tree, name, *, allow_decorators=False):
    return run_memo(
        ("fixture-binding-escape", id(tree), name, allow_decorators),
        lambda: _binding_escapes(tree, name, allow_decorators),
    )


def _binding_escapes(tree, name, allow_decorators):
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Name)
            or not isinstance(node.ctx, ast.Load)
            or node.id != name
        ):
            continue
        expression = node
        parent = parents.get(expression)
        while isinstance(parent, ast.Attribute) and parent.value is expression:
            expression = parent
            parent = parents.get(expression)
        if isinstance(parent, ast.Call) and parent.func is expression:
            continue
        if (
            allow_decorators
            and isinstance(
                parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            and expression in parent.decorator_list
        ):
            continue
        current = expression
        annotation = False
        while current in parents:
            owner = parents[current]
            if isinstance(owner, ast.arg) and owner.annotation is current:
                annotation = True
                break
            if isinstance(owner, ast.AnnAssign) and owner.annotation is current:
                annotation = True
                break
            if (
                isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef))
                and owner.returns is current
            ):
                annotation = True
                break
            if isinstance(owner, (ast.stmt, ast.Call)):
                break
            current = owner
        if not annotation:
            return True
    return False
