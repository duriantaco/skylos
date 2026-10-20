"""Qualified API contracts for operation classification, never general safety.

A model refutes only a specific operation claim. Context propagation may run
user callbacks; recognizing it is not proof that it has no filesystem effects.
Owned source, rebinding, mutation and unresolved dispatch take precedence.
"""

from __future__ import annotations

import ast


CALL_OPERATION_MODELS = {
    "opentelemetry.propagate.extract": {
        "operation": "context_propagation",
        "not_operations": ("archive_extraction",),
        "source": "https://opentelemetry-python.readthedocs.io/en/latest/_modules/opentelemetry/propagate.html",
    },
}


def _import_always_bound(module, binding):
    """Accept optional imports only when failure cannot reach the caller."""
    parent = module.parents.get(binding)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return True
        if isinstance(parent, ast.Try):
            if parent.orelse or parent.finalbody or not parent.handlers:
                return False
            if binding not in parent.body:
                return False
            for handler in parent.handlers:
                if not handler.body or not isinstance(handler.body[-1], ast.Raise):
                    return False
            binding = parent
        else:
            return False
        parent = module.parents.get(parent)
    return False


def _external_name(resolver, node, depth=0, active=frozenset()):
    if depth > resolver.MAX_DEPTH:
        return None
    module = resolver.main
    if module.dynamic_namespace:
        return None
    if isinstance(node, ast.Attribute):
        base = _external_name(resolver, node.value, depth + 1, active)
        if base is not None:
            return f"{base}.{node.attr}"
        return None
    if not isinstance(node, ast.Name) or node.id in module.mutated:
        return None
    scope = module.scope(node)
    while True:
        bindings = module.bindings(scope).get(node.id, [])
        if bindings:
            if len(bindings) != 1:
                return None
            binding, value, conditional = bindings[0]
            if isinstance(binding, (ast.Import, ast.ImportFrom)):
                if conditional and not _import_always_bound(module, binding):
                    return None
                if isinstance(binding, ast.Import):
                    if value.asname:
                        return value.name
                    return value.name.split(".")[0]
                if binding.level or not binding.module:
                    return None
                return f"{binding.module}.{value.name}"
            if conditional or not isinstance(binding, (ast.Assign, ast.AnnAssign)):
                return None
            if id(binding) in active:
                return None
            return _external_name(resolver, value, depth + 1, active | {id(binding)})
        if scope is module.tree:
            return None
        scope = module.scope(scope)
        if isinstance(scope, ast.ClassDef):
            scope = module.scope(scope)


def _has_local_provider(resolver, qualified_name):
    """A model cannot override a source package, including namespace packages."""
    root_name = qualified_name.split(".")[0]
    for root in resolver.search_roots:
        for candidate in (root / root_name, root / f"{root_name}.py"):
            try:
                if candidate.exists() or candidate.is_symlink():
                    return True
            except OSError:
                return True
    return False


def _has_custom_import_provider(module):
    """Explicit import machinery access prevents external-provider proof.

    Even handing a registry or hook list to another function can change the
    provider. Source models do not assume an untouched import system then.
    This is specific to import machinery, not arbitrary dynamic loaders.
    """
    namespaces = {}
    sensitive = {
        "sys.modules",
        "sys.meta_path",
        "sys.path",
        "sys.path_hooks",
        "sys.path_importer_cache",
        "builtins.__import__",
    }
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"sys", "builtins"}:
                    namespaces[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and not node.level:
            if node.module in {"sys", "builtins"}:
                for alias in node.names:
                    qualified = f"{node.module}.{alias.name}"
                    if qualified in sensitive:
                        return True
    for node in ast.walk(module.tree):
        if not isinstance(node, ast.Attribute):
            continue
        if isinstance(node.value, ast.Name):
            namespace = namespaces.get(node.value.id)
            if namespace is not None and f"{namespace}.{node.attr}" in sensitive:
                return True
    return False


def resolve_operation_contract(resolver, node):
    """Return a documented model only for an unshadowed, stable API binding."""
    if _has_custom_import_provider(resolver.main):
        return None
    name = _external_name(resolver, node.func)
    model = CALL_OPERATION_MODELS.get(name)
    if model is None or _has_local_provider(resolver, name):
        return None
    # Qualified attribute arguments can escape a module just as simple-name
    # arguments do (for example monkeypatch.setattr(pkg.api, ...)).
    for call in ast.walk(resolver.main.tree):
        if not isinstance(call, ast.Call):
            continue
        arguments = list(call.args)
        for keyword in call.keywords:
            arguments.append(keyword.value)
        for argument in arguments:
            escaped = _external_name(resolver, argument)
            if escaped is not None:
                if name == escaped or name.startswith(f"{escaped}."):
                    return None
    return {
        "qualified_name": name,
        "operation": model["operation"],
        "not_operations": list(model["not_operations"]),
        "source": model["source"],
    }


def archive_receiver_evidence(resolver, node):
    """Resolve source effects first, retaining unknown archive parameters."""
    proof = resolver.resolve_call(node)
    proof["archive_operation"] = "unresolved"
    if proof.get("status") == "resolved":
        if proof.get("effects", {}).get("filesystem") == "none":
            proof["archive_operation"] = "refuted"
        # An owned implementation may delegate to an archive. Its body wins
        # over an external model even when those effects remain unresolved.
        return proof
    model = resolve_operation_contract(resolver, node)
    if model is not None and "archive_extraction" in model["not_operations"]:
        proof["archive_operation"] = "refuted"
        proof["operation_contract"] = model
        proof["qualified_name"] = model["qualified_name"]
        proof["steps"].append(
            {
                "kind": "qualified_api_contract",
                "file": str(resolver.path),
                "line": getattr(node, "lineno", None),
                "description": f"{model['qualified_name']} performs {model['operation']}; the model does not prove callback effects safe.",
            }
        )
    return proof
